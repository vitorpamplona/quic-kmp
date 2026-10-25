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

import com.vitorpamplona.quic.connection.QuicConnection
import com.vitorpamplona.quic.connection.QuicConnectionConfig
import com.vitorpamplona.quic.connection.QuicConnectionDriver
import com.vitorpamplona.quic.packet.QuicVersion
import com.vitorpamplona.quic.tls.JcaCertificateSigner
import com.vitorpamplona.quic.tls.PinnedCertificateValidator
import com.vitorpamplona.quic.tls.TestCertificates
import com.vitorpamplona.quic.tls.TlsConstants
import com.vitorpamplona.quic.transport.QuicDatagramSocket
import com.vitorpamplona.quic.transport.QuicServerTransport
import com.vitorpamplona.quic.transport.ReceivedDatagram
import com.vitorpamplona.quic.transport.UdpPeerAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** [QuicServer] against client [QuicConnection]s, each on a real driver, over an in-memory network. */
class QuicServerTest {
    private val signer = JcaCertificateSigner.fromPem(TestCertificates.EC_CERT_PEM, TestCertificates.EC_KEY_PEM)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @AfterTest
    fun tearDown() = scope.cancel()

    /** The server's side of the network; [clientSocket] hands out the clients' sides. */
    private class Network : QuicServerTransport {
        val toServer = Channel<ReceivedDatagram>(Channel.UNLIMITED)
        val clients = HashMap<UdpPeerAddress, Channel<ByteArray>>()
        val sentToUnknown = Channel<Pair<UdpPeerAddress, ByteArray>>(Channel.UNLIMITED)

        /** Drop everything clients send, as if the path to the server went dark. */
        @Volatile
        var dropToServer = false

        /** Datagrams clients tried to send. */
        val clientSends =
            java.util.concurrent.atomic
                .AtomicInteger()

        override suspend fun receive(): ReceivedDatagram? = toServer.receiveCatching().getOrNull()

        override suspend fun send(
            payload: ByteArray,
            to: UdpPeerAddress,
        ): Int {
            val inbox = synchronized(clients) { clients[to] }
            if (inbox == null) sentToUnknown.trySend(to to payload) else inbox.trySend(payload)
            return payload.size
        }

        override fun close() {
            toServer.close()
        }

        /** A client's side; [Rebindable.address] can change like a NAT rebinding would. */
        inner class Rebindable(
            address: UdpPeerAddress,
        ) {
            val inbox = Channel<ByteArray>(Channel.UNLIMITED)

            @Volatile
            var address: UdpPeerAddress = address
                set(value) {
                    synchronized(clients) { clients[value] = inbox }
                    field = value
                }

            init {
                synchronized(clients) { clients[address] = inbox }
            }

            /** Once the first datagram is out, move here and drop the old mapping, like a NAT rebinding. */
            @Volatile
            var moveAfterFirstSend: UdpPeerAddress? = null

            fun afterSend() {
                val to = moveAfterFirstSend ?: return
                moveAfterFirstSend = null
                synchronized(clients) { clients.remove(address) }
                address = to
            }
        }

        fun clientSocket(address: UdpPeerAddress): QuicDatagramSocket = clientSocket(Rebindable(address))

        fun clientSocket(path: Rebindable): QuicDatagramSocket {
            val inbox = path.inbox
            return object : QuicDatagramSocket {
                override suspend fun send(payload: ByteArray): Int {
                    clientSends.incrementAndGet()
                    if (!dropToServer) toServer.trySend(ReceivedDatagram(payload, path.address))
                    path.afterSend()
                    return payload.size
                }

                override suspend fun receive(): ByteArray? = inbox.receiveCatching().getOrNull()

                override fun close() {
                    inbox.close()
                }

                override val receivedDatagramCount: Long = 0
                override val receivedByteCount: Long = 0
                override val receiveBufferSizeBytes: Int = 0
                override val remoteIsIpv6: Boolean = false
            }
        }
    }

    private fun server(
        network: Network,
        requireRetry: Boolean = false,
        versions: List<Int> = listOf(QuicVersion.V1),
        maxConnections: Int = 10_000,
    ) = QuicServer(
        QuicServerConfig(
            signer = signer,
            alpnSelector = { offered -> offered.firstOrNull { it.contentEquals(TlsConstants.ALPN_H3) } },
            requireRetry = requireRetry,
            supportedVersions = versions,
            maxConnections = maxConnections,
        ),
        network,
        scope,
    ).also { it.start() }

    private fun client(
        network: Network,
        port: Int,
        compatibleVersions: List<Int> = listOf(QuicVersion.V1),
        path: Network.Rebindable = network.Rebindable(UdpPeerAddress(byteArrayOf(10, 0, 0, 1), port)),
        token: ByteArray? = null,
        onNewToken: ((ByteArray) -> Unit)? = null,
        config: QuicConnectionConfig = QuicConnectionConfig(compatibleVersions = compatibleVersions),
    ): QuicConnection {
        val conn =
            QuicConnection(
                serverName = "quic.test",
                config = config,
                tlsCertificateValidator = PinnedCertificateValidator.ofDer(signer.certificateChain.first()),
                addressValidationToken = token,
                onNewToken = onNewToken,
            )
        QuicConnectionDriver(conn, network.clientSocket(path), scope).start()
        return conn
    }

    private suspend fun echoOnce(
        server: QuicServer,
        client: QuicConnection,
    ): QuicServerConnection {
        val accepted =
            try {
                withTimeout(5_000) { assertNotNull(server.accept()) }
            } catch (e: Exception) {
                throw AssertionError("no connection accepted; client ${client.status} ${client.closeReason}", e)
            }
        scope.launch {
            val stream = accepted.connection.awaitIncomingPeerStream() ?: return@launch
            val body = stream.incoming.toList().fold(ByteArray(0)) { a, b -> a + b }
            stream.send.enqueue("echo:".encodeToByteArray() + body)
            stream.send.finish()
            accepted.driver.wakeup()
        }
        try {
            withTimeout(5_000) { client.awaitHandshakeConfirmed() }
        } catch (e: Exception) {
            throw AssertionError(
                "handshake: client ${client.status} ${client.closeReason}; server ${accepted.connection.status} ${accepted.connection.closeReason}",
                e,
            )
        }
        val request = client.openBidiStream()
        request.send.enqueue("ping".encodeToByteArray())
        request.send.finish()
        val reply = withTimeout(5_000) { request.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }
        assertEquals("echo:ping", reply.decodeToString())
        return accepted
    }

    @Test
    fun `a client connects and gets its request echoed`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network)
            val client = client(network, 5000)
            echoOnce(server, client)
            assertEquals(1, server.connectionCount)
            server.close()
        }

    @Test
    fun `a server requiring Retry validates the client's address first`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network, requireRetry = true)
            val client = client(network, 5001)
            echoOnce(server, client)
        }

    @Test
    fun `a NEW_TOKEN from one connection lets the next skip Retry`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network, requireRetry = true)
            val token = kotlinx.coroutines.CompletableDeferred<ByteArray>()
            val first = echoOnce(server, client(network, 5005, onNewToken = { token.complete(it) }))
            assertNotNull(first.connection.serverSetup?.retrySourceConnectionId, "first connection went through Retry")
            val saved = withTimeout(5_000) { token.await() }
            // Same IP, another port: the token is bound to the address only.
            val second = echoOnce(server, client(network, 5006, token = saved))
            assertEquals(null, second.connection.serverSetup?.retrySourceConnectionId)
        }

    @Test
    fun `a client past the connection limit is refused`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network, maxConnections = 1)
            echoOnce(server, client(network, 5009))
            val refused = client(network, 5010)
            val failure = runCatching { withTimeout(5_000) { refused.awaitHandshake() } }.exceptionOrNull()
            assertNotNull(failure)
            // A peer's CONNECTION_CLOSE puts the client in draining (RFC 9000 §10.2.2).
            assertTrue(refused.status == QuicConnection.Status.DRAINING || refused.status == QuicConnection.Status.CLOSED)
            assertTrue(refused.closeReason?.contains("connection limit") == true, "closed with: ${refused.closeReason}")
            assertEquals(1, server.connectionCount)
        }

    @Test
    fun `keep-alive into a dead path sends a few probes, not a flood`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network)
            val client = client(network, 5011, config = QuicConnectionConfig(keepAliveIntervalMillis = 100, maxIdleTimeoutMillis = 2_000))
            echoOnce(server, client)
            network.dropToServer = true
            val before = network.clientSends.get()
            kotlinx.coroutines.delay(1_500)
            val sent = network.clientSends.get() - before
            assertTrue(sent in 1..60, "client sent $sent datagrams in 1.5 s into a dead path")
        }

    @Test
    fun `several clients are told apart by connection ID`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network)
            repeat(3) { i -> echoOnce(server, client(network, 6000 + i)) }
            assertEquals(3, server.connectionCount)
        }

    @Test
    fun `an unsupported version gets Version Negotiation and the client moves to v2`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network, versions = listOf(QuicVersion.V2))
            val client = client(network, 5002, compatibleVersions = listOf(QuicVersion.V1, QuicVersion.V2))
            echoOnce(server, client)
            assertEquals(QuicVersion.V2, client.currentVersion)
        }

    @Test
    fun `a client that starts in v1 and offers v2 is switched to v2 without Version Negotiation`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network, versions = listOf(QuicVersion.V2, QuicVersion.V1))
            val client = client(network, 5003, compatibleVersions = listOf(QuicVersion.V1, QuicVersion.V2))
            echoOnce(server, client)
            assertEquals(QuicVersion.V2, client.currentVersion)
            assertTrue(network.sentToUnknown.isEmpty)
        }

    @Test
    fun `a client whose address changes during the handshake is answered at the new one`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network)
            val first = UdpPeerAddress(byteArrayOf(10, 0, 0, 1), 5010)
            val moved = UdpPeerAddress(byteArrayOf(10, 0, 0, 1), 6010)
            val path = network.Rebindable(first)
            // Our first flight goes to the old port and is lost; the client's
            // retransmitted Initial comes from the new one.
            path.moveAfterFirstSend = moved
            val client = client(network, 5010, path = path)
            val accepted = echoOnce(server, client)
            assertEquals(moved, accepted.peerAddress)
        }

    @Test
    fun `a client that rebinds to a new address is challenged there and followed`() =
        runBlocking<Unit> {
            val network = Network()
            val server = server(network)
            val first = UdpPeerAddress(byteArrayOf(10, 0, 0, 1), 5004)
            val path = network.Rebindable(first)
            val client = client(network, 5004, path = path)
            val accepted = echoOnce(server, client)
            assertEquals(first, accepted.peerAddress)

            val moved = UdpPeerAddress(byteArrayOf(10, 0, 0, 2), 6004)
            path.address = moved
            val request = client.openBidiStream()
            request.send.enqueue("after".encodeToByteArray())
            request.send.finish()
            val serverSide = withTimeout(5_000) { assertNotNull(accepted.connection.awaitIncomingPeerStream()) }
            val body = withTimeout(5_000) { serverSide.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }
            assertEquals("after", body.decodeToString())
            serverSide.send.enqueue("ok".encodeToByteArray())
            serverSide.send.finish()
            accepted.driver.wakeup()
            val reply = withTimeout(5_000) { request.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }
            assertEquals("ok", reply.decodeToString())
            assertEquals(moved, accepted.peerAddress)
            withTimeout(5_000) { while (accepted.connection.peerMigration != null) kotlinx.coroutines.delay(10) }
        }

    @Test
    fun `a client moves to the server's preferred address and is challenged there`() =
        runBlocking<Unit> {
            val main = Network()
            val preferred = Network()
            val preferredAddress = UdpPeerAddress(byteArrayOf(10, 9, 9, 9), 4443)
            val server =
                QuicServer(
                    QuicServerConfig(
                        signer = signer,
                        alpnSelector = { offered -> offered.firstOrNull { it.contentEquals(TlsConstants.ALPN_H3) } },
                        preferredAddress = ServerPreferredAddress(ipv4 = preferredAddress),
                    ),
                    main,
                    scope,
                    preferredAddressTransport = preferred,
                ).also { it.start() }
            val conn =
                QuicConnection(
                    serverName = "quic.test",
                    config = QuicConnectionConfig(),
                    tlsCertificateValidator = PinnedCertificateValidator.ofDer(signer.certificateChain.first()),
                )
            var opened: Pair<String, Int>? = null
            QuicConnectionDriver(
                conn,
                main.clientSocket(UdpPeerAddress(byteArrayOf(10, 0, 0, 1), 5007)),
                scope,
                socketFactory = { host, port ->
                    opened = host to port
                    preferred.clientSocket(UdpPeerAddress(byteArrayOf(10, 0, 0, 1), 5008))
                },
            ).start()
            val accepted = echoOnce(server, conn)
            withTimeout(5_000) { while (!conn.migratedToPreferredAddress) kotlinx.coroutines.delay(10) }
            assertEquals("10.9.9.9" to 4443, opened)
            // Our PATH_RESPONSE to the client's probe carried a PATH_CHALLENGE, so its
            // address on that path is validated before it moves there (RFC 9000 §8.2).
            withTimeout(5_000) { while (accepted.connection.validatedServerPaths.isEmpty()) kotlinx.coroutines.delay(10) }
            // The next request rides the preferred path, and the server follows it there.
            val request = conn.openBidiStream()
            request.send.enqueue("moved".encodeToByteArray())
            request.send.finish()
            val serverSide = withTimeout(5_000) { assertNotNull(accepted.connection.awaitIncomingPeerStream()) }
            assertEquals("moved", withTimeout(5_000) { serverSide.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }.decodeToString())
            serverSide.send.enqueue("ok".encodeToByteArray())
            serverSide.send.finish()
            accepted.driver.wakeup()
            assertEquals("ok", withTimeout(5_000) { request.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }.decodeToString())
            assertEquals(1, accepted.connection.sendPath?.local)
            withTimeout(5_000) { while (accepted.connection.peerMigration != null) kotlinx.coroutines.delay(10) }
        }

    @Test
    fun `a short header packet for an unknown connection gets a smaller stateless reset`() =
        runBlocking<Unit> {
            val network = Network()
            server(network)
            val from = UdpPeerAddress(byteArrayOf(10, 0, 0, 9), 7000)
            val dcid = ByteArray(8) { (it + 1).toByte() }
            val packet = byteArrayOf(0x40) + dcid + ByteArray(60)
            network.toServer.send(ReceivedDatagram(packet, from))
            val (to, reset) = withTimeout(2_000) { network.sentToUnknown.receive() }
            assertEquals(from, to)
            assertTrue(reset.size < packet.size && reset.size >= 21)
            assertEquals(0x40, reset[0].toInt() and 0xC0)
        }
}
