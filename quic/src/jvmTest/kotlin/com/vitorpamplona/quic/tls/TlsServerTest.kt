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
import com.vitorpamplona.quic.QuicReader
import com.vitorpamplona.quic.QuicWriter
import com.vitorpamplona.quic.TlsAlertException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** [TlsServer] against our own [TlsClient], over in-memory CRYPTO streams. */
class TlsServerTest {
    private class Recorder : TlsSecretsListener {
        var handshake: Pair<ByteArray, ByteArray>? = null
        var application: Pair<ByteArray, ByteArray>? = null
        var early: ByteArray? = null
        var complete = false
        val tickets = mutableListOf<TlsResumptionState>()

        override fun onHandshakeKeysReady(
            cipherSuite: Int,
            clientSecret: ByteArray,
            serverSecret: ByteArray,
        ) {
            handshake = clientSecret to serverSecret
        }

        override fun onApplicationKeysReady(
            cipherSuite: Int,
            clientSecret: ByteArray,
            serverSecret: ByteArray,
        ) {
            application = clientSecret to serverSecret
        }

        override fun onEarlyDataKeysReady(
            cipherSuite: Int,
            clientEarlySecret: ByteArray,
        ) {
            early = clientEarlySecret
        }

        override fun onHandshakeComplete() {
            complete = true
        }

        override fun onNewSessionTicket(state: TlsResumptionState) {
            tickets += state
        }
    }

    private val ecSigner = JcaCertificateSigner.fromPem(TestCertificates.EC_CERT_PEM, TestCertificates.EC_KEY_PEM)
    private val alpnH3 = "h3".encodeToByteArray()

    private fun server(
        listener: Recorder,
        signer: TlsCertificateSigner = ecSigner,
        tickets: TlsSessionTicketKeys? = null,
        maxEarly: Long = 0L,
        alpn: (List<ByteArray>) -> ByteArray? = { offered -> offered.firstOrNull { it.contentEquals(alpnH3) } },
    ) = TlsServer(
        transportParameters = byteArrayOf(1, 2, 3),
        secretsListener = listener,
        signer = signer,
        alpnSelector = alpn,
        ticketKeys = tickets,
        maxEarlyDataSize = maxEarly,
    )

    private fun client(
        listener: Recorder,
        signer: TlsCertificateSigner = ecSigner,
        resumption: TlsResumptionState? = null,
    ) = TlsClient(
        serverName = "quic.test",
        transportParameters = byteArrayOf(9, 8, 7),
        secretsListener = listener,
        certificateValidator = PinnedCertificateValidator.ofDer(signer.certificateChain.first()),
        resumption = resumption,
    )

    /** Shuttle CRYPTO bytes until nothing moves. */
    private fun run(
        c: TlsClient,
        s: TlsServer,
    ) {
        c.start()
        repeat(10) {
            var moved = false
            for (level in TlsClient.Level.entries) {
                while (true) {
                    val b = c.pollOutbound(level) ?: break
                    s.pushHandshakeBytes(level, b)
                    moved = true
                }
                while (true) {
                    val b = s.pollOutbound(level) ?: break
                    c.pushHandshakeBytes(level, b)
                    moved = true
                }
            }
            if (!moved) return
        }
    }

    @Test
    fun full_handshake_with_an_ecdsa_certificate() {
        val cl = Recorder()
        val sl = Recorder()
        val c = client(cl)
        val s = server(sl)
        run(c, s)
        assertTrue(cl.complete && sl.complete)
        assertEquals(TlsServer.State.CONNECTED, s.state)
        assertContentEquals(cl.handshake!!.first, sl.handshake!!.first)
        assertContentEquals(cl.application!!.second, sl.application!!.second)
        assertContentEquals(alpnH3, c.negotiatedAlpn)
        assertContentEquals(byteArrayOf(1, 2, 3), c.peerTransportParameters)
        assertContentEquals(byteArrayOf(9, 8, 7), s.peerTransportParameters)
        assertEquals("quic.test", s.requestedServerName)
        assertFalse(s.pskAccepted)
    }

    @Test
    fun full_handshake_with_rsa_pss_and_pkcs1_keys() {
        for (keyPem in listOf(TestCertificates.RSA_KEY_PEM, TestCertificates.RSA_KEY_PKCS1_PEM)) {
            val signer = JcaCertificateSigner.fromPem(TestCertificates.RSA_CERT_PEM, keyPem)
            assertEquals(TlsConstants.SIG_RSA_PSS_RSAE_SHA256, signer.signatureSchemes.first())
            val cl = Recorder()
            val sl = Recorder()
            run(client(cl, signer), server(sl, signer))
            assertTrue(cl.complete && sl.complete)
        }
    }

    @Test
    fun resumption_skips_the_certificate_and_0rtt_is_accepted_once() {
        val tickets = TlsSessionTicketKeys()
        val cl = Recorder()
        run(client(cl), server(Recorder(), tickets = tickets, maxEarly = 0xFFFFFFFFL))
        val ticket = cl.tickets.single()
        assertEquals(0xFFFFFFFFL, ticket.maxEarlyDataSize)

        val cl2 = Recorder()
        val sl2 = Recorder()
        val s2 = server(sl2, tickets = tickets, maxEarly = 0xFFFFFFFFL)
        val c2 = client(cl2, resumption = ticket)
        run(c2, s2)
        assertTrue(cl2.complete && sl2.complete)
        assertTrue(s2.pskAccepted)
        assertTrue(s2.earlyDataAccepted)
        assertTrue(c2.earlyDataAccepted)
        assertContentEquals(cl2.early, sl2.early, "both sides derive the same 0-RTT secret")

        // The same ticket again: still resumes, but its 0-RTT is a replay.
        val sl3 = Recorder()
        val s3 = server(sl3, tickets = tickets, maxEarly = 0xFFFFFFFFL)
        val c3 = client(Recorder(), resumption = ticket)
        run(c3, s3)
        assertTrue(s3.pskAccepted)
        assertFalse(s3.earlyDataAccepted)
        assertNull(sl3.early)
    }

    @Test
    fun a_ticket_from_other_keys_falls_back_to_a_full_handshake() {
        val cl = Recorder()
        run(client(cl), server(Recorder(), tickets = TlsSessionTicketKeys()))
        val s = server(Recorder(), tickets = TlsSessionTicketKeys())
        val c = client(Recorder(), resumption = cl.tickets.single())
        run(c, s)
        assertFalse(s.pskAccepted)
        assertEquals(TlsServer.State.CONNECTED, s.state)
    }

    @Test
    fun no_common_alpn_is_refused() {
        val s = server(Recorder(), alpn = { null })
        val c = client(Recorder())
        val e = assertFailsWith<TlsAlertException> { run(c, s) }
        assertEquals(TlsConstants.ALERT_NO_APPLICATION_PROTOCOL, e.alertCode)
    }

    @Test
    fun session_ticket_state_round_trips() {
        val keys = TlsSessionTicketKeys()
        val state = TlsSessionTicketState(ByteArray(32) { it.toByte() }, 0x1301, 1_700_000_000_000L, 0xDEADBEEFL, 3600, 0xFFFFFFFFL, alpnH3, 1)
        val opened = assertNotNull(keys.open(keys.seal(state)))
        assertContentEquals(state.psk, opened.psk)
        assertEquals(state.issuedAtMillis, opened.issuedAtMillis)
        assertEquals(0xDEADBEEFL, opened.ticketAgeAdd)
        assertContentEquals(alpnH3, opened.alpn)
        val tampered = keys.seal(state).also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertNull(keys.open(tampered))
    }

    /** A hand-built ClientHello offering P-256 and X25519 in supported_groups, with one key share. */
    private fun clientHello(
        random: ByteArray,
        shareGroup: Int,
        share: ByteArray,
        groups: List<Int> = listOf(GROUP_SECP256R1, TlsConstants.GROUP_X25519),
        // Offers this ticket, with a binder over [binderPrefix] and the ClientHello (RFC 8446 §4.2.11.2).
        resume: TlsResumptionState? = null,
        binderPrefix: ByteArray = ByteArray(0),
    ): ByteArray {
        val w = QuicWriter()
        w.writeByte(TlsConstants.HS_CLIENT_HELLO)
        w.withUint24Length {
            writeUint16(TlsConstants.LEGACY_VERSION_TLS_1_2)
            writeBytes(random)
            writeTlsOpaque1(ByteArray(0))
            withUint16Length { writeUint16(TlsConstants.CIPHER_TLS_AES_128_GCM_SHA256) }
            writeTlsOpaque1(byteArrayOf(0))
            withUint16Length {
                writeUint16(TlsConstants.EXT_SUPPORTED_VERSIONS)
                withUint16Length { writeTlsOpaque1(byteArrayOf(0x03, 0x04)) }
                writeUint16(TlsConstants.EXT_SUPPORTED_GROUPS)
                withUint16Length { withUint16Length { groups.forEach { writeUint16(it) } } }
                writeUint16(TlsConstants.EXT_KEY_SHARE)
                withUint16Length {
                    withUint16Length {
                        writeUint16(shareGroup)
                        writeTlsOpaque2(share)
                    }
                }
                writeUint16(TlsConstants.EXT_SIGNATURE_ALGORITHMS)
                withUint16Length { withUint16Length { writeUint16(TlsConstants.SIG_ECDSA_SECP256R1_SHA256) } }
                writeUint16(TlsConstants.EXT_ALPN)
                withUint16Length { withUint16Length { writeTlsOpaque1(alpnH3) } }
                writeUint16(TlsConstants.EXT_QUIC_TRANSPORT_PARAMETERS)
                writeTlsOpaque2(byteArrayOf(9, 8, 7))
                if (resume != null) {
                    writeUint16(TlsConstants.EXT_PSK_KEY_EXCHANGE_MODES)
                    withUint16Length { writeTlsOpaque1(byteArrayOf(TlsConstants.PSK_MODE_DHE_KE.toByte())) }
                    // Must be last; the binder (32 zero bytes for now) is the final field.
                    writeUint16(TlsConstants.EXT_PRE_SHARED_KEY)
                    withUint16Length {
                        withUint16Length {
                            writeTlsOpaque2(resume.ticket)
                            writeUint32(0)
                        }
                        withUint16Length { writeTlsOpaque1(ByteArray(32)) }
                    }
                }
            }
        }
        val out = w.toByteArray()
        if (resume != null) {
            // Everything before the binders list: its 2-byte length, the binder's 1-byte length and 32 bytes.
            val partialEnd = out.size - 35
            val early = TlsKeySchedule(TlsTranscriptHash()).also { it.deriveEarlyFromPsk(resume.psk) }
            val partial =
                TlsRunningSha256()
                    .also {
                        it.update(binderPrefix)
                        it.update(out.copyOfRange(0, partialEnd))
                    }.snapshot()
            val mac =
                com.vitorpamplona.crypto.mac
                    .MacInstance("HmacSHA256", pskBinderFinishedKey(early.earlySecret!!))
            mac.update(partial)
            mac.doFinal().copyInto(out, out.size - 32)
        }
        return out
    }

    private fun serverHello(msg: ByteArray): TlsServerHello {
        assertEquals(TlsConstants.HS_SERVER_HELLO, msg[0].toInt() and 0xFF)
        return TlsServerHello.decodeBody(QuicReader(msg, 4, msg.size))
    }

    @Test
    fun a_client_hello_without_an_x25519_share_gets_a_hello_retry_request() {
        val sl = Recorder()
        val s = server(sl)
        val random = ByteArray(32) { it.toByte() }
        val ch1 = clientHello(random, GROUP_SECP256R1, ByteArray(65) { 4 })
        s.pushHandshakeBytes(TlsClient.Level.INITIAL, ch1)

        val hrr = assertNotNull(s.pollOutbound(TlsClient.Level.INITIAL))
        assertNull(s.pollOutbound(TlsClient.Level.HANDSHAKE), "nothing else until the second ClientHello")
        assertNull(sl.handshake)
        assertEquals(TlsServer.State.WAITING_CLIENT_HELLO, s.state)
        val retry = serverHello(hrr)
        assertContentEquals(HELLO_RETRY_REQUEST_RANDOM, retry.random)
        val keyShare = retry.extensions.single { it.type == TlsConstants.EXT_KEY_SHARE }
        assertEquals(TlsConstants.GROUP_X25519, QuicReader(keyShare.data).readUint16(), "selected_group")

        val keyPair = X25519.generateKeyPair()
        val ch2 = clientHello(random, TlsConstants.GROUP_X25519, keyPair.publicKey)
        s.pushHandshakeBytes(TlsClient.Level.INITIAL, ch2)
        val shBytes = assertNotNull(s.pollOutbound(TlsClient.Level.INITIAL))
        val sh = serverHello(shBytes)
        assertFalse(sh.random.contentEquals(HELLO_RETRY_REQUEST_RANDOM))
        assertEquals(TlsServer.State.WAITING_CLIENT_FINISHED, s.state)

        // RFC 8446 §4.4.1: the transcript replaces ClientHello1 with message_hash.
        val transcript = TlsTranscriptHash()
        val ch1Hash = TlsRunningSha256().also { it.update(ch1) }.snapshot()
        transcript.append(byteArrayOf(TlsConstants.HS_MESSAGE_HASH.toByte(), 0, 0, 32) + ch1Hash)
        transcript.append(hrr)
        transcript.append(ch2)
        transcript.append(shBytes)
        val expected = TlsKeySchedule(transcript)
        expected.deriveEarly()
        expected.deriveHandshake(X25519.dh(keyPair.privateKey, sh.serverKeyShareX25519))
        expected.deriveHandshakeTraffic()
        assertContentEquals(expected.clientHandshakeSecret, sl.handshake!!.first)
        assertContentEquals(expected.serverHandshakeSecret, sl.handshake!!.second)
    }

    @Test
    fun a_ticket_resumes_after_a_hello_retry_request() {
        // s2n-quic's ClientHello carries only a P-256 share, so it always gets a retry.
        val tickets = TlsSessionTicketKeys()
        val cl = Recorder()
        run(client(cl), server(Recorder(), tickets = tickets))
        val ticket = cl.tickets.single()

        val sl = Recorder()
        val s = server(sl, tickets = tickets)
        val random = ByteArray(32) { 7 }
        val ch1 = clientHello(random, GROUP_SECP256R1, ByteArray(65) { 4 }, resume = ticket)
        s.pushHandshakeBytes(TlsClient.Level.INITIAL, ch1)
        val hrr = assertNotNull(s.pollOutbound(TlsClient.Level.INITIAL))
        val ch1Hash = TlsRunningSha256().also { it.update(ch1) }.snapshot()
        val prefix = byteArrayOf(TlsConstants.HS_MESSAGE_HASH.toByte(), 0, 0, 32) + ch1Hash + hrr

        val ch2 = clientHello(random, TlsConstants.GROUP_X25519, X25519.generateKeyPair().publicKey, resume = ticket, binderPrefix = prefix)
        s.pushHandshakeBytes(TlsClient.Level.INITIAL, ch2)
        assertTrue(s.pskAccepted, "the binder over the retry verified")
        assertFalse(s.earlyDataAccepted)
        // EncryptedExtensions and Finished only: no Certificate on a resumption.
        val handshakeTypes = generateSequence { s.pollOutbound(TlsClient.Level.HANDSHAKE) }.map { it[0].toInt() and 0xFF }.toList()
        assertEquals(listOf(TlsConstants.HS_ENCRYPTED_EXTENSIONS, TlsConstants.HS_FINISHED), handshakeTypes)
    }

    @Test
    fun a_second_client_hello_still_without_an_x25519_share_is_refused() {
        val s = server(Recorder())
        val ch = clientHello(ByteArray(32), GROUP_SECP256R1, ByteArray(65) { 4 })
        s.pushHandshakeBytes(TlsClient.Level.INITIAL, ch)
        assertNotNull(s.pollOutbound(TlsClient.Level.INITIAL))
        val e = assertFailsWith<TlsAlertException> { s.pushHandshakeBytes(TlsClient.Level.INITIAL, ch) }
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, e.alertCode)
    }

    @Test
    fun a_client_without_x25519_in_its_groups_is_refused() {
        val s = server(Recorder())
        val ch = clientHello(ByteArray(32), GROUP_SECP256R1, ByteArray(65) { 4 }, groups = listOf(GROUP_SECP256R1))
        val e = assertFailsWith<TlsAlertException> { s.pushHandshakeBytes(TlsClient.Level.INITIAL, ch) }
        assertEquals(TlsConstants.ALERT_HANDSHAKE_FAILURE, e.alertCode)
    }

    private companion object {
        const val GROUP_SECP256R1 = 23
    }
}
