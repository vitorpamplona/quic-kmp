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
package com.vitorpamplona.quic.server

import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.quic.QuicLog
import com.vitorpamplona.quic.QuicReader
import com.vitorpamplona.quic.QuicWriter
import com.vitorpamplona.quic.SynchronizedObject
import com.vitorpamplona.quic.connection.ConnectionId
import com.vitorpamplona.quic.connection.QuicConnection
import com.vitorpamplona.quic.connection.QuicConnectionDriver
import com.vitorpamplona.quic.connection.QuicServerSetup
import com.vitorpamplona.quic.connection.defaultEpochMillis
import com.vitorpamplona.quic.connection.defaultMonotonicNowMillis
import com.vitorpamplona.quic.observability.QlogObserver
import com.vitorpamplona.quic.packet.LongHeaderType
import com.vitorpamplona.quic.packet.QuicVersion
import com.vitorpamplona.quic.packet.RetryPacket
import com.vitorpamplona.quic.synchronized
import com.vitorpamplona.quic.tls.PermissiveCertificateValidator
import com.vitorpamplona.quic.tls.TlsServer
import com.vitorpamplona.quic.transport.QuicDatagramSocket
import com.vitorpamplona.quic.transport.QuicServerTransport
import com.vitorpamplona.quic.transport.ReceivedDatagram
import com.vitorpamplona.quic.transport.UdpPeerAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

/** A connection a [QuicServer] accepted, with the driver that runs it. */
class QuicServerConnection internal constructor(
    val connection: QuicConnection,
    val driver: QuicConnectionDriver,
    private val socket: ServerPeerSocket,
) {
    /** The client's current address. */
    val peerAddress: UdpPeerAddress get() = connection.sendAddress ?: socket.peer

    /** The TLS server of this connection: SNI, ALPN, resumption, client random. */
    val tls: TlsServer get() = connection.tlsServer!!
}

/**
 * A QUIC server endpoint (RFC 9000) on one [QuicServerTransport]: it routes
 * datagrams to connections by destination connection ID, starts a
 * connection for each valid client Initial, answers unknown versions with
 * Version Negotiation (§6), sends Retry when [QuicServerConfig.requireRetry]
 * asks for address validation (§8.1.2), and answers short-header packets
 * for unknown connections with a stateless reset (§10.3).
 *
 * Each connection runs on its own [QuicConnectionDriver]; [accept] hands
 * them out as they arrive, before their handshake completes.
 */
class QuicServer(
    val config: QuicServerConfig,
    private val transport: QuicServerTransport,
    parentScope: CoroutineScope,
    private val nowMillis: () -> Long = defaultMonotonicNowMillis(),
    private val epochMillis: () -> Long = { defaultEpochMillis() },
) {
    private val job = SupervisorJob(parentScope.coroutineContext[Job])
    private val scope = CoroutineScope(parentScope.coroutineContext + job)
    private val lock = SynchronizedObject()
    private val routes = HashMap<ConnectionId, ServerPeerSocket>()
    private val accepted = Channel<QuicServerConnection>(Channel.UNLIMITED)
    private val tokens = AddressTokens()
    private val resetTokens = StatelessResetTokens()
    private var readJob: Job? = null

    /** Connections currently routed. */
    val connectionCount: Int get() = synchronized(lock) { routes.values.toSet().size }

    fun start() {
        readJob =
            scope.launch {
                try {
                    while (true) {
                        val datagram = transport.receive() ?: break
                        try {
                            onDatagram(datagram)
                        } catch (e: Exception) {
                            QuicLog.w(TAG) { "dropped a datagram from ${datagram.from}: ${e.message}" }
                        }
                    }
                } finally {
                    accepted.close()
                }
            }
    }

    /** The next accepted connection; null once the server is closed. */
    suspend fun accept(): QuicServerConnection? = accepted.receiveCatching().getOrNull()

    /** Close every connection and the transport. */
    fun close() {
        val sockets = synchronized(lock) { routes.values.toSet().also { routes.clear() } }
        for (s in sockets) s.owner?.driver?.close()
        transport.close()
        accepted.close()
    }

    private suspend fun onDatagram(d: ReceivedDatagram) {
        val bytes = d.payload
        if (bytes.isEmpty()) return
        val first = bytes[0].toInt() and 0xFF
        if ((first and 0x80) == 0) {
            if (bytes.size < 1 + config.connectionIdLength) return
            val dcid = ConnectionId(bytes.copyOfRange(1, 1 + config.connectionIdLength))
            val route = synchronized(lock) { routes[dcid] }
            if (route != null) {
                route.deliver(d)
            } else {
                sendStatelessReset(dcid, d)
            }
            return
        }
        val header = parseLongHeader(bytes) ?: return
        synchronized(lock) { routes[header.dcid] }?.let {
            it.deliver(d)
            return
        }
        // Only a client Initial can start a connection; the rest of a
        // connection we don't know (0-RTT racing ahead of its Initial, or
        // packets of one already gone) is dropped.
        if (header.version == QuicVersion.VERSION_NEGOTIATION) return
        if (header.version !in config.supportedVersions) {
            // RFC 9000 §6.1 / §14.1: only for datagrams a client Initial could be.
            if (bytes.size >= MIN_INITIAL_DATAGRAM) sendVersionNegotiation(header, d.from)
            return
        }
        if (LongHeaderType.fromWireBits((first ushr 4) and 0x03, header.version) != LongHeaderType.INITIAL) return
        // RFC 9000 §14.1: a server discards an Initial in a datagram under
        // 1200 bytes; §7.2: the client's first DCID has at least 8 bytes.
        if (bytes.size < MIN_INITIAL_DATAGRAM || header.dcid.length < 8 && header.token.isEmpty()) return
        val now = epochMillis()
        var retry: AddressTokens.Retry? = null
        var returning = false
        if (header.token.isNotEmpty()) {
            retry = tokens.openRetry(header.token, d.from, now)
            if (retry != null && retry.retrySourceConnectionId != header.dcid) retry = null
            // A token we can't open (stale, another address, someone else's)
            // gets the same treatment as none.
            if (retry == null) returning = tokens.openNewToken(header.token, d.from, now)
        }
        if (retry == null && !returning && config.requireRetry) {
            sendRetry(header, d.from, now)
            return
        }
        startConnection(header, d, retry, returning)
    }

    private fun startConnection(
        header: LongHeader,
        d: ReceivedDatagram,
        retry: AddressTokens.Retry?,
        returning: Boolean,
    ) {
        val localCid = ConnectionId.random(config.connectionIdLength)
        val odcid = retry?.originalDestinationConnectionId ?: header.dcid
        val socket = ServerPeerSocket(transport, d.from)
        var connRef: QuicConnection? = null
        val setup =
            QuicServerSetup(
                tlsServerFactory = { tp, listener ->
                    TlsServer(
                        transportParameters = tp,
                        secretsListener = listener,
                        signer = config.signer,
                        alpnSelector = config.alpnSelector,
                        cipherSuites = config.cipherSuites,
                        ticketKeys = config.ticketKeys,
                        maxEarlyDataSize = if (config.ticketKeys != null) config.maxEarlyDataSize else 0L,
                        quicVersion = { connRef?.currentVersion ?: header.version },
                        nowMillisSource = epochMillis,
                        onClientTransportParameters = { tp -> connRef?.chooseCompatibleVersion(tp) },
                    )
                },
                originalDestinationConnectionId = odcid,
                clientInitialDestinationConnectionId = header.dcid,
                clientSourceConnectionId = header.scid,
                localConnectionId = localCid,
                retrySourceConnectionId = retry?.retrySourceConnectionId,
                addressValidated = retry != null || returning,
                statelessResetTokenFor = resetTokens::tokenFor,
                supportedVersions = config.supportedVersions,
                onConnectionIdIssued = { cid -> synchronized(lock) { routes[cid] = socket } },
                onConnectionIdRetired = { cid -> synchronized(lock) { if (routes[cid] === socket) routes.remove(cid) } },
                peerAddress = d.from,
                newTokenFactory = if (config.issueNewTokens) ({ tokens.mintNewToken(d.from, epochMillis()) }) else null,
            )
        val conn =
            QuicConnection(
                serverName = "",
                config = config.connectionConfig,
                tlsCertificateValidator = PermissiveCertificateValidator(),
                nowMillis = nowMillis,
                epochMillis = epochMillis,
                alpnList = emptyList(),
                extraSecretsListener = config.secretsListenerFactory?.invoke(),
                cipherSuites = config.cipherSuites,
                initialVersion = header.version,
                qlogObserver = config.qlogObserverFactory?.invoke(odcid.bytes) ?: QlogObserver.NoOp,
                resumption = null,
                onResumptionTicket = null,
                addressValidationToken = null,
                onNewToken = null,
                serverSetup = setup,
            )
        connRef = conn
        val driver = QuicConnectionDriver(conn, socket, scope)
        val accepted = QuicServerConnection(conn, driver, socket)
        socket.owner = accepted
        synchronized(lock) {
            routes[header.dcid] = socket
            routes[localCid] = socket
        }
        conn.onTerminated = {
            synchronized(lock) { routes.entries.removeAll { it.value === socket } }
            driver.close()
        }
        driver.start()
        socket.deliver(d)
        this.accepted.trySend(accepted)
        QuicLog.d(TAG) { "accepted ${d.from} odcid=${odcid.toHex()} version=${QuicVersion.name(header.version)} retry=${retry != null}" }
    }

    /** RFC 9000 §17.2.1. */
    private suspend fun sendVersionNegotiation(
        header: LongHeader,
        to: UdpPeerAddress,
    ) {
        val w = QuicWriter()
        w.writeByte(0x80 or 0x40 or (RandomInstance.bytes(1)[0].toInt() and 0x3F))
        w.writeUint32(0)
        w.writeByte(header.scid.length)
        w.writeBytes(header.scid.bytes)
        w.writeByte(header.dcid.length)
        w.writeBytes(header.dcid.bytes)
        for (v in config.supportedVersions) w.writeUint32(v)
        // A reserved version (0x?a?a?a?a), so clients don't come to rely on the list's shape.
        w.writeUint32(((RandomInstance.bytes(4).fold(0) { a, b -> (a shl 8) or (b.toInt() and 0xFF) }) and 0xF0F0F0F0.toInt()) or 0x0A0A0A0A)
        transport.send(w.toByteArray(), to)
    }

    /** RFC 9000 §17.2.5: a Retry whose token carries the client's original DCID. */
    private suspend fun sendRetry(
        header: LongHeader,
        to: UdpPeerAddress,
        now: Long,
    ) {
        val retryScid = ConnectionId.random(config.connectionIdLength)
        val token = tokens.mintRetry(to, header.dcid, retryScid, now)
        val w = QuicWriter()
        w.writeByte(0xC0 or (LongHeaderType.RETRY.wireBits(header.version) shl 4) or (RandomInstance.bytes(1)[0].toInt() and 0x0F))
        w.writeUint32(header.version)
        w.writeByte(header.scid.length)
        w.writeBytes(header.scid.bytes)
        w.writeByte(retryScid.length)
        w.writeBytes(retryScid.bytes)
        w.writeBytes(token)
        val withoutTag = w.toByteArray()
        val tag = RetryPacket.computeIntegrityTag(withoutTag, header.dcid.bytes, header.version)
        transport.send(withoutTag + tag, to)
    }

    /**
     * RFC 9000 §10.3: tell a peer that lost track of us. Always smaller than
     * the packet that triggered it, so two endpoints can't loop.
     */
    private suspend fun sendStatelessReset(
        dcid: ConnectionId,
        d: ReceivedDatagram,
    ) {
        val size = minOf(d.payload.size - 1, STATELESS_RESET_SIZE)
        if (size < MIN_STATELESS_RESET_SIZE) return
        val packet = RandomInstance.bytes(size)
        packet[0] = ((packet[0].toInt() and 0x3F) or 0x40).toByte()
        resetTokens.tokenFor(dcid).copyInto(packet, size - 16)
        transport.send(packet, d.from)
    }

    internal class LongHeader(
        val version: Int,
        val dcid: ConnectionId,
        val scid: ConnectionId,
        /** An Initial's token; empty for other types. */
        val token: ByteArray,
    )

    private fun parseLongHeader(bytes: ByteArray): LongHeader? =
        try {
            val r = QuicReader(bytes, 1)
            val version = r.readUint32().toInt()
            val dcidLen = r.readByte()
            if (dcidLen > 20) return null
            val dcid = ConnectionId(r.readBytes(dcidLen))
            val scidLen = r.readByte()
            if (scidLen > 20) return null
            val scid = ConnectionId(r.readBytes(scidLen))
            val first = bytes[0].toInt() and 0xFF
            val token =
                if (version != QuicVersion.VERSION_NEGOTIATION &&
                    QuicVersion.isSupported(version) &&
                    LongHeaderType.fromWireBits((first ushr 4) and 0x03, version) == LongHeaderType.INITIAL
                ) {
                    val len = r.readVarint()
                    if (len < 0 || len > r.remaining) return null
                    r.readBytes(len.toInt())
                } else {
                    ByteArray(0)
                }
            LongHeader(version, dcid, scid, token)
        } catch (_: Exception) {
            null
        }

    companion object {
        private const val TAG = "QuicServer"
        private const val MIN_INITIAL_DATAGRAM = 1200
        private const val STATELESS_RESET_SIZE = 43
        private const val MIN_STATELESS_RESET_SIZE = 21
    }
}

/** A server's view of one client path: datagrams the endpoint routed here in, sends out the shared transport. */
internal class ServerPeerSocket(
    private val transport: QuicServerTransport,
    @kotlin.concurrent.Volatile var peer: UdpPeerAddress,
) : QuicDatagramSocket {
    var owner: QuicServerConnection? = null
    private val inbox = Channel<ReceivedDatagram>(INBOX_CAPACITY)
    private var datagrams = 0L
    private var bytes = 0L

    /** Queue a datagram for the connection; dropped like a full socket buffer would when it lags. */
    fun deliver(d: ReceivedDatagram) {
        inbox.trySend(d)
    }

    /** To where the connection last pointed us: it moves only with a new path's PATH_CHALLENGE. */
    override suspend fun send(payload: ByteArray): Int = transport.send(payload, owner?.connection?.sendAddress ?: peer)

    /**
     * The next datagram, after telling the connection where it came from
     * (the read loop parses it next, so the two can't interleave).
     */
    override suspend fun receive(): ByteArray? {
        val d = inbox.receiveCatching().getOrNull() ?: return null
        datagrams++
        bytes += d.payload.size
        owner?.connection?.datagramSource = d.from
        return d.payload
    }

    override fun close() {
        inbox.close()
    }

    override val receivedDatagramCount: Long get() = datagrams
    override val receivedByteCount: Long get() = bytes
    override val receiveBufferSizeBytes: Int get() = 0
    override val remoteIsIpv6: Boolean get() = peer.isIpv6

    companion object {
        private const val INBOX_CAPACITY = 1024
    }
}
