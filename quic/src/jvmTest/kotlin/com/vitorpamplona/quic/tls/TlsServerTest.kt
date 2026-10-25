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
}
