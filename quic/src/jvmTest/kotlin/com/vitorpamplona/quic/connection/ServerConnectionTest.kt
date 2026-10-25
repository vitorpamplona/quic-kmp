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
package com.vitorpamplona.quic.connection

import com.vitorpamplona.quic.tls.JcaCertificateSigner
import com.vitorpamplona.quic.tls.PinnedCertificateValidator
import com.vitorpamplona.quic.tls.TestCertificates
import com.vitorpamplona.quic.tls.TlsConstants
import com.vitorpamplona.quic.tls.TlsServer
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** A client [QuicConnection] against a server-side one, datagrams shuttled in memory. */
class ServerConnectionTest {
    private val signer = JcaCertificateSigner.fromPem(TestCertificates.EC_CERT_PEM, TestCertificates.EC_KEY_PEM)

    private var now = 1_000L

    private fun client() =
        QuicConnection(
            serverName = "quic.test",
            config = QuicConnectionConfig(),
            tlsCertificateValidator = PinnedCertificateValidator.ofDer(signer.certificateChain.first()),
            nowMillis = { now },
        )

    private fun serverFor(client: QuicConnection): QuicConnection =
        QuicConnection(
            serverName = "",
            config = QuicConnectionConfig(),
            tlsCertificateValidator = PinnedCertificateValidator.ofDer(signer.certificateChain.first()),
            nowMillis = { now },
            epochMillis = { now },
            alpnList = listOf(TlsConstants.ALPN_H3),
            extraSecretsListener = null,
            cipherSuites = intArrayOf(TlsConstants.CIPHER_TLS_AES_128_GCM_SHA256),
            initialVersion = client.currentVersion,
            qlogObserver = com.vitorpamplona.quic.observability.QlogObserver.NoOp,
            resumption = null,
            onResumptionTicket = null,
            addressValidationToken = null,
            onNewToken = null,
            serverSetup =
                QuicServerSetup(
                    tlsServerFactory = { tp, listener ->
                        TlsServer(
                            transportParameters = tp,
                            secretsListener = listener,
                            signer = signer,
                            alpnSelector = { offered -> offered.firstOrNull { it.contentEquals(TlsConstants.ALPN_H3) } },
                        )
                    },
                    originalDestinationConnectionId = client.destinationConnectionId,
                    clientInitialDestinationConnectionId = client.destinationConnectionId,
                    clientSourceConnectionId = client.sourceConnectionId,
                    localConnectionId = ConnectionId.random(8),
                    statelessResetTokenFor = { ByteArray(16) { i -> (it.bytes[0] + i).toByte() } },
                    peerAddress = clientAddress,
                ),
        )

    private val clientAddress =
        com.vitorpamplona.quic.transport
            .UdpPeerAddress(byteArrayOf(10, 0, 0, 1), 5000)

    private class Counts {
        var toServer = 0L
        var toClient = 0L
    }

    /** Move datagrams both ways until neither side has anything to say, letting delayed ACKs fire. */
    private fun pump(
        client: QuicConnection,
        server: QuicConnection,
        counts: Counts = Counts(),
    ) {
        var quietRounds = 0
        while (quietRounds < 3) {
            var moved = false
            while (true) {
                val d = drainOutbound(client, now) ?: break
                counts.toServer += d.size
                feedDatagram(server, d, now)
                moved = true
            }
            while (true) {
                val d = drainOutbound(server, now) ?: break
                counts.toClient += d.size
                feedDatagram(client, d, now)
                moved = true
            }
            now += 30
            if (moved) quietRounds = 0 else quietRounds++
        }
    }

    @Test
    fun `client and server complete the handshake and confirm it`() {
        val client = client()
        client.start()
        val server = serverFor(client)
        val counts = Counts()
        pump(client, server, counts)

        assertEquals(QuicConnection.Status.CONNECTED, client.status)
        assertEquals(QuicConnection.Status.CONNECTED, server.status)
        assertTrue(client.handshakeConfirmed, "client never got HANDSHAKE_DONE")
        assertTrue(server.handshakeConfirmed)
        assertTrue(server.isServer)
        assertNotNull(client.peerTransportParameters)
        assertNotNull(server.peerTransportParameters)
        // The client adopted the server's chosen connection ID.
        assertEquals(server.sourceConnectionId, client.destinationConnectionId)
        assertTrue(server.initial.keysDiscarded && server.handshake.keysDiscarded)
    }

    @Test
    fun `a request on a client stream gets the server's answer`() =
        runBlocking {
            val client = client()
            client.start()
            val server = serverFor(client)
            pump(client, server)

            val request = client.openBidiStream()
            request.send.enqueue("GET /index.html\r\n".encodeToByteArray())
            request.send.finish()
            pump(client, server)

            val accepted = assertNotNull(server.pollIncomingPeerStream())
            assertEquals(request.streamId, accepted.streamId)
            val body = withTimeout(2_000) { accepted.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }
            assertEquals("GET /index.html\r\n", body.decodeToString())

            val response = ByteArray(50_000) { (it % 251).toByte() }
            accepted.send.enqueue(response)
            accepted.send.finish()
            pump(client, server)
            val got = withTimeout(2_000) { request.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }
            assertTrue(response.contentEquals(got), "response came back ${got.size} bytes")
        }

    @Test
    fun `the server opens its own streams with server-initiated ids`() =
        runBlocking {
            val client = client()
            client.start()
            val server = serverFor(client)
            pump(client, server)

            val push = server.openUniStream()
            assertEquals(3L, push.streamId)
            push.send.enqueue("hi".encodeToByteArray())
            push.send.finish()
            pump(client, server)
            val incoming = assertNotNull(client.pollIncomingPeerStream())
            assertEquals(3L, incoming.streamId)
            assertEquals("hi", withTimeout(2_000) { incoming.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }.decodeToString())
        }

    @Test
    fun `the spin bit flips once per round trip`() {
        val client = client()
        client.start()
        val server = serverFor(client)
        pump(client, server)
        client.spinEnabled = true
        server.spinEnabled = true
        client.spinValue = false
        server.spinValue = false
        val seen = ArrayList<Boolean>()
        repeat(4) {
            client.pendingPing = true
            val toServer = assertNotNull(drainOutbound(client, now))
            seen += (toServer[0].toInt() and 0x20) != 0
            feedDatagram(server, toServer, now)
            // The server echoes what it saw; the client answers with the inverse.
            assertEquals(seen.last(), server.spinValue)
            server.pendingPing = true
            feedDatagram(client, assertNotNull(drainOutbound(server, now)), now)
            now += 30
        }
        assertEquals(listOf(false, true, false, true), seen)
    }

    @Test
    fun `a replayed packet from another address does not move the server`() =
        runBlocking {
            val client = client()
            client.start()
            val server = serverFor(client)
            pump(client, server)
            val stream = client.openBidiStream()
            stream.send.enqueue("x".encodeToByteArray())
            val datagram = assertNotNull(drainOutbound(client, now))
            server.datagramPath = ServerPath(0, clientAddress)
            feedDatagram(server, datagram, now)
            // An attacker replays it from elsewhere: not a higher packet number, so no move.
            server.datagramPath =
                ServerPath(
                    0,
                    com.vitorpamplona.quic.transport
                        .UdpPeerAddress(byteArrayOf(10, 6, 6, 6), 666),
                )
            feedDatagram(server, datagram, now)
            assertEquals(null, server.peerMigration)
            assertEquals(clientAddress, server.sendAddress)
        }

    @Test
    fun `an unvalidated server sends at most three times what it received`() {
        val client = client()
        client.start()
        val server = serverFor(client)
        // Only the client's first flight reaches the server; nothing goes back.
        var received = 0L
        while (true) {
            val d = drainOutbound(client, now) ?: break
            received += d.size
            feedDatagram(server, d, now)
        }
        var sent = 0L
        repeat(10) {
            while (true) {
                val d = drainOutbound(server, now) ?: break
                sent += d.size
            }
            now += 1_000
        }
        assertTrue(sent > 0)
        assertTrue(sent <= 3 * received, "server sent $sent bytes for $received received")
    }
}
