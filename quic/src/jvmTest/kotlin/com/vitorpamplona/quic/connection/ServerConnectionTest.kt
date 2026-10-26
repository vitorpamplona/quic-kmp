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
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A client [QuicConnection] against a server-side one, datagrams shuttled in memory. */
class ServerConnectionTest {
    private val signer = JcaCertificateSigner.fromPem(TestCertificates.EC_CERT_PEM, TestCertificates.EC_KEY_PEM)

    private var now = 1_000L

    private fun client(signer: JcaCertificateSigner = this.signer) =
        QuicConnection(
            serverName = "quic.test",
            config = QuicConnectionConfig(),
            tlsCertificateValidator = PinnedCertificateValidator.ofDer(signer.certificateChain.first()),
            nowMillis = { now },
        )

    private fun serverFor(
        client: QuicConnection,
        signer: JcaCertificateSigner = this.signer,
    ): QuicConnection =
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
                // Coalesced levels never make a datagram bigger than the minimum PMTU.
                if (!server.handshakeConfirmed) assertTrue(d.size <= 1200, "server handshake datagram of ${d.size} bytes")
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

    @Test
    fun `a handshake probe repeats an ACK that was lost`() {
        // picoquic in handshakeloss: most of its flight and our only Handshake ACK
        // were lost, and its own packets after that were ACK-only, so it learned
        // what arrived only if our probes carried the ACK again.
        val rsa = JcaCertificateSigner.fromPem(TestCertificates.RSA_CERT_PEM, TestCertificates.RSA_KEY_PEM)
        val client = client(rsa)
        client.start()
        val server = serverFor(client, rsa)
        while (true) feedDatagram(server, drainOutbound(client, now) ?: break, now)
        // The RSA certificate makes the server's flight two datagrams; only the first arrives.
        feedDatagram(client, assertNotNull(drainOutbound(server, now)), now)
        assertNotNull(drainOutbound(server, now), "the flight spans more than one datagram")
        while (true) drainOutbound(server, now) ?: break
        assertTrue(client.application.sendProtection == null, "the client is still waiting for the rest")
        // The client's ACKs for what arrived are lost.
        while (true) drainOutbound(client, now) ?: break
        assertNull(server.handshake.largestAckedPn)

        now += 1_000
        client.pendingPing = true
        while (true) feedDatagram(server, drainOutbound(client, now) ?: break, now)
        assertNotNull(server.handshake.largestAckedPn, "the client's probe acknowledged the server's Handshake packet")
    }

    @Test
    fun `a ClientHello sent again after our flight was acknowledged gets the whole flight again`() {
        // picoquic in the v2 test: switched to v2 by our first Initial, it
        // ACKed that packet but started its handshake over, sending its
        // ClientHello again; with our ServerHello ACKed, we only ACKed back.
        val client = client()
        client.start()
        val server = serverFor(client)
        while (true) feedDatagram(server, drainOutbound(client, now) ?: break, now)
        // Our flight goes out and is lost, but the client ACKs the Initial (picoquic's ACK of what it dropped).
        while (true) drainOutbound(server, now) ?: break
        server.initial.cryptoSend.markAcked(0L, server.initial.cryptoSend.nextOffset)
        server.initial.clearSentPackets()
        assertNull(drainOutbound(server, now), "nothing left to send")

        // The ClientHello again, from offset 0, in a new packet.
        now += 300
        client.requeueAllInflightCrypto(EncryptionLevel.INITIAL)
        while (true) feedDatagram(server, drainOutbound(client, now) ?: break, now)
        pump(client, server)
        assertTrue(client.handshakeConfirmed, "the resent flight completed the handshake")
        assertTrue(server.handshakeConfirmed)
    }

    @Test
    fun `a request that arrives before the client's Finished is read once the Finished does`() =
        runBlocking {
            // lsquic in handshakeloss: its Finished was lost, the request it sent
            // right after was dropped, and its own retransmit came too late.
            val client = client()
            client.start()
            val server = serverFor(client)
            while (true) feedDatagram(server, drainOutbound(client, now) ?: break, now)
            while (true) feedDatagram(client, drainOutbound(server, now) ?: break, now)
            val finishedFlight = mutableListOf<ByteArray>()
            while (true) finishedFlight += drainOutbound(client, now) ?: break
            assertNotNull(client.application.sendProtection, "the client has 1-RTT keys")

            val request = client.openBidiStream()
            request.send.enqueue("GET /index.html\r\n".encodeToByteArray())
            request.send.finish()
            while (true) feedDatagram(server, drainOutbound(client, now) ?: break, now)
            assertTrue(!server.handshakeComplete, "the server still waits for the Finished")
            assertNull(server.pollIncomingPeerStream())

            for (d in finishedFlight) feedDatagram(server, d, now)
            assertTrue(server.handshakeComplete)
            val accepted = assertNotNull(server.pollIncomingPeerStream(), "the kept request was read")
            val body = withTimeout(2_000) { accepted.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }
            assertEquals("GET /index.html\r\n", body.decodeToString())
        }

    @Test
    fun `a PTO probe carries HANDSHAKE_DONE again until the client acknowledges it`() =
        runBlocking {
            // ngtcp2 in handshakecorruption: our HANDSHAKE_DONE was lost twice, the
            // probes were bare PINGs, and the client never confirmed its handshake.
            val client = client()
            client.start()
            val server = serverFor(client)
            while (true) feedDatagram(server, drainOutbound(client, now) ?: break, now)
            while (true) feedDatagram(client, drainOutbound(server, now) ?: break, now)
            while (true) feedDatagram(server, drainOutbound(client, now) ?: break, now)
            assertTrue(server.handshakeConfirmed)
            // Everything the server sends now, HANDSHAKE_DONE included, is lost.
            while (true) drainOutbound(server, now) ?: break
            assertTrue(!client.handshakeConfirmed)

            now += 1_000
            handlePtoFired(server)
            while (true) feedDatagram(client, drainOutbound(server, now) ?: break, now)
            assertTrue(client.handshakeConfirmed, "the probe carried HANDSHAKE_DONE")
        }
}
