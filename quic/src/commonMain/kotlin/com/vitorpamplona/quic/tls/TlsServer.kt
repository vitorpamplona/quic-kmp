/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.vitorpamplona.quic.tls

import com.vitorpamplona.crypto.curve25519.X25519
import com.vitorpamplona.crypto.curve25519.X25519KeyPair
import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.quic.QuicCodecException
import com.vitorpamplona.quic.QuicReader
import com.vitorpamplona.quic.QuicWriter
import com.vitorpamplona.quic.TlsAlertException
import kotlin.time.Clock

/**
 * TLS 1.3 server driven by QUIC's CRYPTO streams (RFC 8446, RFC 9001), the
 * counterpart of [TlsClient].
 *
 * Handles a full handshake (X25519, AES-128-GCM or ChaCha20-Poly1305,
 * certificate authentication through [signer]) and, when [ticketKeys] is set,
 * PSK resumption from tickets it issued, with 0-RTT if [maxEarlyDataSize] is
 * non-zero. Keys reach the QUIC layer through [secretsListener] exactly as on
 * the client: handshake keys after ServerHello, application keys after the
 * server Finished (the server may send 1-RTT from then on), early-data keys
 * when 0-RTT is accepted, and [TlsSecretsListener.onHandshakeComplete] once
 * the client's Finished verifies.
 *
 * A ClientHello that lists X25519 without sending a share for it gets a
 * HelloRetryRequest; one that doesn't list it fails with handshake_failure.
 * Not supported: client certificates.
 */
class TlsServer(
    /** Our QUIC transport parameters, sent in EncryptedExtensions. */
    val transportParameters: ByteArray,
    val secretsListener: TlsSecretsListener,
    val signer: TlsCertificateSigner,
    /**
     * Picks the application protocol from the client's offer (RFC 7301), or
     * null to refuse the connection with no_application_protocol.
     */
    val alpnSelector: (offered: List<ByteArray>) -> ByteArray?,
    /** Cipher suites we accept, most preferred first. */
    val cipherSuites: IntArray =
        intArrayOf(
            TlsConstants.CIPHER_TLS_AES_128_GCM_SHA256,
            TlsConstants.CIPHER_TLS_CHACHA20_POLY1305_SHA256,
        ),
    /** Enables session tickets and PSK resumption. */
    val ticketKeys: TlsSessionTicketKeys? = null,
    /** Ticket lifetime advertised in NewSessionTicket (RFC 8446 caps it at 7 days). */
    val ticketLifetimeSec: Long = 24L * 60L * 60L,
    /**
     * 0-RTT on resumed connections: RFC 9001 §4.6.1 requires 0xffffffff in
     * QUIC when early data is allowed at all; 0 disables it.
     */
    val maxEarlyDataSize: Long = 0L,
    /** The QUIC version tickets are bound to (RFC 9369 §5). */
    val quicVersion: () -> Int = { com.vitorpamplona.quic.packet.QuicVersion.V1 },
    val nowMillisSource: () -> Long = { Clock.System.now().toEpochMilliseconds() },
    /** Deterministic tests only. */
    val fixedKeyPair: X25519KeyPair? = null,
    /**
     * Sees the client's QUIC transport parameters from the ClientHello we
     * answer with a ServerHello (the second one after a HelloRetryRequest),
     * before that answer is built; a non-null result replaces
     * [transportParameters] in EncryptedExtensions. The QUIC layer uses it to
     * switch to a compatible version the client offered (RFC 9368 §2.3).
     */
    val onClientTransportParameters: ((ByteArray) -> ByteArray?)? = null,
) : TlsHandshake {
    enum class State { WAITING_CLIENT_HELLO, WAITING_CLIENT_FINISHED, CONNECTED, FAILED }

    var state: State = State.WAITING_CLIENT_HELLO
        private set

    /** The protocol picked by [alpnSelector]. */
    override var negotiatedAlpn: ByteArray? = null
        private set

    /** The client's QUIC transport parameters, from its ClientHello. */
    override var peerTransportParameters: ByteArray? = null
        private set

    /** The SNI host name the client asked for, if any. */
    var requestedServerName: String? = null
        private set

    /** The ClientHello random, for SSLKEYLOGFILE lines. */
    var clientRandom: ByteArray? = null
        private set

    /** True when the client resumed from one of our tickets. */
    var pskAccepted: Boolean = false
        private set

    /** True when we accepted the client's 0-RTT data. */
    override var earlyDataAccepted: Boolean = false
        private set

    private val outboundQueues =
        mapOf(
            TlsClient.Level.INITIAL to ArrayDeque<ByteArray>(),
            TlsClient.Level.HANDSHAKE to ArrayDeque<ByteArray>(),
            TlsClient.Level.APPLICATION to ArrayDeque<ByteArray>(),
        )
    private val inboundBuffers =
        mapOf(
            TlsClient.Level.INITIAL to ByteArrayBuilder(),
            TlsClient.Level.HANDSHAKE to ByteArrayBuilder(),
            TlsClient.Level.APPLICATION to ByteArrayBuilder(),
        )

    private val transcript = TlsTranscriptHash()
    private val keySchedule = TlsKeySchedule(transcript)
    private var negotiatedCipherSuite: Int = -1
    private var ticketNonce: Long = 0L
    private var sentTransportParameters: ByteArray = transportParameters

    /** We sent a HelloRetryRequest; the next ClientHello is the client's second. */
    private var helloRetried: Boolean = false

    override fun pollOutbound(level: TlsClient.Level): ByteArray? = outboundQueues[level]?.removeFirstOrNull()

    override fun pushHandshakeBytes(
        level: TlsClient.Level,
        bytes: ByteArray,
    ) {
        if (state == State.FAILED) throw QuicCodecException("TLS handshake already failed; ignoring further bytes at $level")
        val buf = inboundBuffers[level] ?: throw QuicCodecException("no buffer at level $level")
        buf.append(bytes)
        while (true) {
            val msg = buf.takeHandshakeMessage() ?: break
            try {
                handleMessage(level, msg)
            } catch (t: Throwable) {
                state = State.FAILED
                throw t
            }
        }
    }

    private fun handleMessage(
        level: TlsClient.Level,
        msg: ByteArray,
    ) {
        val type = msg[0].toInt() and 0xFF
        when (state) {
            State.WAITING_CLIENT_HELLO -> {
                if (type != TlsConstants.HS_CLIENT_HELLO || level != TlsClient.Level.INITIAL) {
                    throw TlsAlertException(TlsConstants.ALERT_UNEXPECTED_MESSAGE, "expected ClientHello at Initial, got type=$type at $level")
                }
                handleClientHello(msg)
            }

            State.WAITING_CLIENT_FINISHED -> {
                // RFC 9001 §8.3: QUIC clients never send EndOfEarlyData.
                if (type != TlsConstants.HS_FINISHED || level != TlsClient.Level.HANDSHAKE) {
                    throw TlsAlertException(TlsConstants.ALERT_UNEXPECTED_MESSAGE, "expected client Finished at Handshake, got type=$type at $level")
                }
                handleClientFinished(msg)
            }

            State.CONNECTED -> {
                // RFC 9001 §6: no TLS KeyUpdate over QUIC; nothing else is expected from a client.
                throw TlsAlertException(TlsConstants.ALERT_UNEXPECTED_MESSAGE, "unexpected post-handshake message type=$type")
            }

            State.FAILED -> {
                throw QuicCodecException("TLS handshake already failed")
            }
        }
    }

    private fun handleClientHello(msg: ByteArray) {
        val ch = ParsedClientHello.parse(msg)
        clientRandom = ch.random
        requestedServerName = ch.serverName

        if (TlsConstants.VERSION_TLS_1_3 !in ch.supportedVersions) {
            throw TlsAlertException(TlsConstants.ALERT_PROTOCOL_VERSION, "client does not offer TLS 1.3")
        }
        val tp = ch.quicTransportParameters ?: throw TlsAlertException(TlsConstants.ALERT_MISSING_EXTENSION, "ClientHello without quic_transport_parameters")
        peerTransportParameters = tp
        // RFC 9001 §8.1: ALPN is mandatory with QUIC.
        val alpn = alpnSelector(ch.alpns) ?: throw TlsAlertException(TlsConstants.ALERT_NO_APPLICATION_PROTOCOL, "no acceptable ALPN in ${ch.alpns.map { it.decodeToString() }}")
        negotiatedAlpn = alpn
        val suite =
            cipherSuites.firstOrNull { it in ch.cipherSuites }
                ?: throw TlsAlertException(TlsConstants.ALERT_HANDSHAKE_FAILURE, "no common cipher suite")
        negotiatedCipherSuite = suite
        val clientShare = ch.x25519KeyShare
        if (clientShare == null) {
            if (helloRetried) throw TlsAlertException(TlsConstants.ALERT_ILLEGAL_PARAMETER, "second ClientHello still has no X25519 key share")
            if (TlsConstants.GROUP_X25519 !in ch.supportedGroups) throw TlsAlertException(TlsConstants.ALERT_HANDSHAKE_FAILURE, "client does not support X25519")
            sendHelloRetryRequest(ch, msg, suite)
            return
        }
        // Only for the ClientHello we answer: a compatible version switch
        // (RFC 9368) together with a HelloRetryRequest left picoquic restarting
        // its handshake in the new version without the retry.
        onClientTransportParameters?.invoke(tp)?.let { sentTransportParameters = it }

        // RFC 8446 §4.2.11: try the offered ticket before deciding on a full handshake.
        // After a HelloRetryRequest the binder would cover the retry too; a full
        // handshake is simpler and always allowed, and 0-RTT is off (§4.2.10).
        val resumed = if (helloRetried) null else tryResume(ch, msg, suite, alpn)
        if (resumed != null) {
            pskAccepted = true
            keySchedule.deriveEarlyFromPsk(resumed.psk)
        } else {
            keySchedule.deriveEarly()
        }
        transcript.append(msg)

        if (resumed != null && ch.earlyData && maxEarlyDataSize > 0 && resumed.maxEarlyDataSize > 0 &&
            resumed.cipherSuite == suite && resumed.alpn?.contentEquals(alpn) == true &&
            resumed.quicVersion == quicVersion() && ticketKeys!!.claimEarlyData(ch.pskIdentity!!)
        ) {
            earlyDataAccepted = true
            keySchedule.deriveEarlyTraffic(transcript.snapshot())
            secretsListener.onEarlyDataKeysReady(suite, keySchedule.clientEarlyTrafficSecret!!)
        }

        val scheme =
            if (resumed == null) {
                signer.signatureSchemes.firstOrNull { it in ch.signatureAlgorithms }
                    ?: throw TlsAlertException(TlsConstants.ALERT_HANDSHAKE_FAILURE, "no common signature scheme")
            } else {
                0
            }

        val keyPair = fixedKeyPair ?: X25519.generateKeyPair()
        val shared = X25519.dh(keyPair.privateKey, clientShare)

        val sh = buildServerHello(ch.sessionId, suite, keyPair.publicKey, pskAccepted)
        transcript.append(sh)
        outboundQueues[TlsClient.Level.INITIAL]!!.addLast(sh)

        keySchedule.deriveHandshake(shared)
        keySchedule.deriveHandshakeTraffic()
        keySchedule.deriveMaster()
        secretsListener.onHandshakeKeysReady(suite, keySchedule.clientHandshakeSecret!!, keySchedule.serverHandshakeSecret!!)

        val hs = outboundQueues[TlsClient.Level.HANDSHAKE]!!
        val ee = buildEncryptedExtensions(alpn, earlyDataAccepted)
        transcript.append(ee)
        hs.addLast(ee)
        if (resumed == null) {
            val cert = buildCertificate()
            transcript.append(cert)
            hs.addLast(cert)
            val signature = signer.sign(scheme, serverCertificateVerifyContent(transcript.snapshot()))
            val cv =
                handshakeMessage(TlsConstants.HS_CERTIFICATE_VERIFY) {
                    writeUint16(scheme)
                    writeTlsOpaque2(signature)
                }
            transcript.append(cv)
            hs.addLast(cv)
        }
        val fin = handshakeMessage(TlsConstants.HS_FINISHED) { writeBytes(finishedVerifyData(keySchedule.serverHandshakeSecret!!, transcript.snapshot())) }
        transcript.append(fin)
        hs.addLast(fin)

        keySchedule.deriveApplicationTraffic()
        secretsListener.onApplicationKeysReady(suite, keySchedule.clientApplicationSecret!!, keySchedule.serverApplicationSecret!!)
        state = State.WAITING_CLIENT_FINISHED
    }

    /**
     * RFC 8446 §4.1.4: ask for an X25519 share. The transcript restarts as
     * message_hash(ClientHello1) followed by the HelloRetryRequest; the
     * client's second ClientHello comes on the same Initial CRYPTO stream.
     */
    private fun sendHelloRetryRequest(
        ch: ParsedClientHello,
        msg: ByteArray,
        suite: Int,
    ) {
        helloRetried = true
        // Both suites we offer hash with SHA-256.
        val ch1Hash = TlsRunningSha256().also { it.update(msg) }.snapshot()
        transcript.append(handshakeMessage(TlsConstants.HS_MESSAGE_HASH) { writeBytes(ch1Hash) })
        val hrr =
            handshakeMessage(TlsConstants.HS_SERVER_HELLO) {
                writeUint16(TlsConstants.LEGACY_VERSION_TLS_1_2)
                writeBytes(HELLO_RETRY_REQUEST_RANDOM)
                writeTlsOpaque1(ch.sessionId)
                writeUint16(suite)
                writeByte(0)
                withUint16Length {
                    writeUint16(TlsConstants.EXT_SUPPORTED_VERSIONS)
                    withUint16Length { writeUint16(TlsConstants.VERSION_TLS_1_3) }
                    writeUint16(TlsConstants.EXT_KEY_SHARE)
                    withUint16Length { writeUint16(TlsConstants.GROUP_X25519) }
                }
            }
        transcript.append(hrr)
        outboundQueues[TlsClient.Level.INITIAL]!!.addLast(hrr)
    }

    /** The ticket state when the client's offered PSK opens, binds and is still fresh; null for a full handshake. */
    private fun tryResume(
        ch: ParsedClientHello,
        msg: ByteArray,
        suite: Int,
        alpn: ByteArray,
    ): TlsSessionTicketState? {
        val keys = ticketKeys ?: return null
        val identity = ch.pskIdentity ?: return null
        val binder = ch.pskBinder ?: return null
        // We only issue psk_dhe_ke tickets (RFC 8446 §4.2.9).
        if (TlsConstants.PSK_MODE_DHE_KE !in ch.pskModes) return null
        val ticket = keys.open(identity) ?: return null
        val now = nowMillisSource()
        if (now - ticket.issuedAtMillis > ticket.lifetimeSec * 1000L || now < ticket.issuedAtMillis) return null
        // Both suites we support hash with SHA-256, so a ticket from either resumes either (§4.2.11).
        if (ticket.cipherSuite !in cipherSuites) return null
        if (ticket.alpn != null && !ticket.alpn.contentEquals(alpn)) return null
        // RFC 8446 §4.2.11.2: the binder covers the ClientHello up to the binders list.
        val early = TlsKeySchedule(TlsTranscriptHash()).also { it.deriveEarlyFromPsk(ticket.psk) }
        val binderKey = pskBinderFinishedKey(early.earlySecret!!)
        val partial = TlsRunningSha256().also { it.update(msg.copyOfRange(0, ch.bindersOffset)) }.snapshot()
        val mac =
            com.vitorpamplona.crypto.mac
                .MacInstance("HmacSHA256", binderKey)
        mac.update(partial)
        if (!mac.doFinal().contentEqualsConstantTime(binder)) {
            throw TlsAlertException(TlsConstants.ALERT_DECRYPT_ERROR, "PSK binder does not verify")
        }
        return ticket
    }

    private fun handleClientFinished(msg: ByteArray) {
        val r = QuicReader(msg, 4, msg.size)
        val verifyData = r.readBytes(msg.size - 4)
        val expected = finishedVerifyData(keySchedule.clientHandshakeSecret!!, transcript.snapshot())
        if (!expected.contentEqualsConstantTime(verifyData)) {
            throw TlsAlertException(TlsConstants.ALERT_DECRYPT_ERROR, "client Finished MAC mismatch")
        }
        transcript.append(msg)
        keySchedule.deriveResumption(transcript.snapshot())
        state = State.CONNECTED
        secretsListener.onHandshakeComplete()
        issueSessionTicket()
    }

    /** RFC 8446 §4.6.1: one NewSessionTicket after the handshake, when tickets are enabled. */
    private fun issueSessionTicket() {
        val keys = ticketKeys ?: return
        val rms = keySchedule.resumptionMasterSecret ?: return
        val nonce =
            QuicWriter()
                .also {
                    it.writeUint32((ticketNonce ushr 32).toInt())
                    it.writeUint32(ticketNonce.toInt())
                }.toByteArray()
        ticketNonce++
        val ageAdd = QuicReader(RandomInstance.bytes(4)).readUint32() and 0xFFFFFFFFL
        val state =
            TlsSessionTicketState(
                psk = resumptionPsk(rms, nonce),
                cipherSuite = negotiatedCipherSuite,
                issuedAtMillis = nowMillisSource(),
                ticketAgeAdd = ageAdd,
                lifetimeSec = ticketLifetimeSec,
                maxEarlyDataSize = maxEarlyDataSize,
                alpn = negotiatedAlpn,
                quicVersion = quicVersion(),
            )
        val ticket = keys.seal(state)
        val nst =
            handshakeMessage(TlsConstants.HS_NEW_SESSION_TICKET) {
                writeUint32(ticketLifetimeSec)
                writeUint32(ageAdd)
                writeTlsOpaque1(nonce)
                writeTlsOpaque2(ticket)
                withUint16Length {
                    if (maxEarlyDataSize > 0) {
                        writeUint16(TlsConstants.EXT_EARLY_DATA)
                        withUint16Length { writeUint32(maxEarlyDataSize) }
                    }
                }
            }
        outboundQueues[TlsClient.Level.APPLICATION]!!.addLast(nst)
    }

    private fun buildServerHello(
        sessionIdEcho: ByteArray,
        suite: Int,
        publicKey: ByteArray,
        psk: Boolean,
    ): ByteArray =
        handshakeMessage(TlsConstants.HS_SERVER_HELLO) {
            writeUint16(TlsConstants.LEGACY_VERSION_TLS_1_2)
            writeBytes(RandomInstance.bytes(32))
            writeTlsOpaque1(sessionIdEcho)
            writeUint16(suite)
            writeByte(0)
            withUint16Length {
                writeUint16(TlsConstants.EXT_SUPPORTED_VERSIONS)
                withUint16Length { writeUint16(TlsConstants.VERSION_TLS_1_3) }
                writeUint16(TlsConstants.EXT_KEY_SHARE)
                withUint16Length {
                    writeUint16(TlsConstants.GROUP_X25519)
                    writeTlsOpaque2(publicKey)
                }
                if (psk) {
                    writeUint16(TlsConstants.EXT_PRE_SHARED_KEY)
                    withUint16Length { writeUint16(0) }
                }
            }
        }

    private fun buildEncryptedExtensions(
        alpn: ByteArray,
        earlyData: Boolean,
    ): ByteArray =
        handshakeMessage(TlsConstants.HS_ENCRYPTED_EXTENSIONS) {
            withUint16Length {
                writeUint16(TlsConstants.EXT_ALPN)
                withUint16Length { withUint16Length { writeTlsOpaque1(alpn) } }
                writeUint16(TlsConstants.EXT_QUIC_TRANSPORT_PARAMETERS)
                writeTlsOpaque2(sentTransportParameters)
                if (earlyData) {
                    writeUint16(TlsConstants.EXT_EARLY_DATA)
                    writeUint16(0)
                }
            }
        }

    private fun buildCertificate(): ByteArray =
        handshakeMessage(TlsConstants.HS_CERTIFICATE) {
            writeTlsOpaque1(ByteArray(0))
            withUint24Length {
                for (der in signer.certificateChain) {
                    writeTlsOpaque3(der)
                    writeUint16(0)
                }
            }
        }

    private inline fun handshakeMessage(
        type: Int,
        body: QuicWriter.() -> Unit,
    ): ByteArray {
        val w = QuicWriter()
        w.writeByte(type)
        w.withUint24Length(body)
        return w.toByteArray()
    }
}

/** The parts of a ClientHello (RFC 8446 §4.1.2) a server acts on. */
internal class ParsedClientHello(
    val random: ByteArray,
    val sessionId: ByteArray,
    val cipherSuites: List<Int>,
    val supportedVersions: List<Int>,
    val x25519KeyShare: ByteArray?,
    val supportedGroups: List<Int>,
    val signatureAlgorithms: List<Int>,
    val alpns: List<ByteArray>,
    val serverName: String?,
    val quicTransportParameters: ByteArray?,
    val pskModes: List<Int>,
    val earlyData: Boolean,
    /** First PSK identity offered (we only ever issue one ticket per connection). */
    val pskIdentity: ByteArray?,
    val pskBinder: ByteArray?,
    /** Offset in the message where the PSK binders list starts: the binder covers everything before. */
    val bindersOffset: Int,
) {
    companion object {
        fun parse(msg: ByteArray): ParsedClientHello {
            try {
                val r = QuicReader(msg)
                r.readByte()
                val len = r.readUint24()
                if (len != msg.size - 4) throw QuicCodecException("ClientHello length $len != ${msg.size - 4}")
                if (r.readUint16() != TlsConstants.LEGACY_VERSION_TLS_1_2) throw QuicCodecException("ClientHello legacy_version")
                val random = r.readBytes(32)
                val sessionId = r.readTlsOpaque1()
                val suitesLen = r.readUint16()
                val suites = (0 until suitesLen / 2).map { r.readUint16() }
                val compression = r.readTlsOpaque1()
                if (!compression.contentEquals(byteArrayOf(0))) throw TlsAlertException(TlsConstants.ALERT_ILLEGAL_PARAMETER, "ClientHello compression methods")
                val extTotal = r.readUint16()
                val extEnd = r.position + extTotal
                var versions = emptyList<Int>()
                var share: ByteArray? = null
                var groups = emptyList<Int>()
                var sigAlgs = emptyList<Int>()
                var alpns = emptyList<ByteArray>()
                var sni: String? = null
                var tp: ByteArray? = null
                var pskModes = emptyList<Int>()
                var earlyData = false
                var pskIdentity: ByteArray? = null
                var pskBinder: ByteArray? = null
                var bindersOffset = msg.size
                while (r.position < extEnd) {
                    val type = r.readUint16()
                    val dataLen = r.readUint16()
                    val start = r.position
                    val e = QuicReader(msg, start, start + dataLen)
                    when (type) {
                        TlsConstants.EXT_SUPPORTED_VERSIONS -> {
                            val n = e.readByte()
                            versions = (0 until n / 2).map { e.readUint16() }
                        }

                        TlsConstants.EXT_KEY_SHARE -> {
                            val end = e.position + e.readUint16()
                            while (e.position < end) {
                                val group = e.readUint16()
                                val key = e.readTlsOpaque2()
                                if (group == TlsConstants.GROUP_X25519 && key.size == 32 && share == null) share = key
                            }
                        }

                        TlsConstants.EXT_SUPPORTED_GROUPS -> {
                            val n = e.readUint16()
                            groups = (0 until n / 2).map { e.readUint16() }
                        }

                        TlsConstants.EXT_SIGNATURE_ALGORITHMS -> {
                            val n = e.readUint16()
                            sigAlgs = (0 until n / 2).map { e.readUint16() }
                        }

                        TlsConstants.EXT_ALPN -> {
                            val end = e.position + e.readUint16()
                            val list = ArrayList<ByteArray>()
                            while (e.position < end) list += e.readTlsOpaque1()
                            alpns = list
                        }

                        TlsConstants.EXT_SERVER_NAME -> {
                            val end = e.position + e.readUint16()
                            while (e.position < end) {
                                val nameType = e.readByte()
                                val name = e.readTlsOpaque2()
                                if (nameType == TlsConstants.SERVER_NAME_TYPE_HOST_NAME) sni = name.decodeToString()
                            }
                        }

                        TlsConstants.EXT_QUIC_TRANSPORT_PARAMETERS -> {
                            tp = msg.copyOfRange(start, start + dataLen)
                        }

                        TlsConstants.EXT_PSK_KEY_EXCHANGE_MODES -> {
                            pskModes = e.readTlsOpaque1().map { it.toInt() and 0xFF }
                        }

                        TlsConstants.EXT_EARLY_DATA -> {
                            earlyData = true
                        }

                        TlsConstants.EXT_PRE_SHARED_KEY -> {
                            // RFC 8446 §4.2.11: must be the last extension.
                            if (start + dataLen != extEnd) throw TlsAlertException(TlsConstants.ALERT_ILLEGAL_PARAMETER, "pre_shared_key is not the last extension")
                            val idEnd = e.position + e.readUint16()
                            while (e.position < idEnd) {
                                val id = e.readTlsOpaque2()
                                e.readUint32()
                                if (pskIdentity == null) pskIdentity = id
                            }
                            bindersOffset = e.position
                            val bEnd = e.position + e.readUint16()
                            if (e.position < bEnd) pskBinder = e.readTlsOpaque1()
                        }
                    }
                    r.seek(start + dataLen)
                }
                return ParsedClientHello(
                    random,
                    sessionId,
                    suites,
                    versions,
                    share,
                    groups,
                    sigAlgs,
                    alpns,
                    sni,
                    tp,
                    pskModes,
                    earlyData,
                    pskIdentity,
                    pskBinder,
                    bindersOffset,
                )
            } catch (e: TlsAlertException) {
                throw e
            } catch (e: Exception) {
                throw TlsAlertException(TlsConstants.ALERT_DECODE_ERROR, "malformed ClientHello: ${e.message}")
            }
        }
    }
}
