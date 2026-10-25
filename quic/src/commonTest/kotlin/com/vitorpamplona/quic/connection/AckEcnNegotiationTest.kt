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

import com.vitorpamplona.quic.frame.AckEcnCounts
import com.vitorpamplona.quic.frame.AckFrame
import com.vitorpamplona.quic.frame.PingFrame
import com.vitorpamplona.quic.frame.decodeFrames
import com.vitorpamplona.quic.frame.encodeFrames
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Our 1-RTT ACKs carry (always zero) ECN counts only once the peer's ACKs
 * carry counts: nginx closes the connection with INTERNAL_ERROR on the first
 * ACK_ECN it receives, and never sends one itself.
 */
class AckEcnNegotiationTest {
    /** Two PINGs from the peer make an ACK due; returns the ACK we send for them. */
    private fun ackForTwoPings(
        client: QuicConnection,
        pipe: InMemoryQuicPipe,
    ): AckFrame {
        repeat(2) { feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(PingFrame))!!, nowMillis = 0L) }
        var ack: AckFrame? = null
        while (true) {
            val out = drainOutbound(client, nowMillis = 0L) ?: break
            pipe
                .decryptClientApplicationFrames(out)
                ?.filterIsInstance<AckFrame>()
                ?.firstOrNull()
                ?.let { ack = it }
        }
        return assertNotNull(ack, "an ACK went out")
    }

    @Test
    fun `ACKs are plain until the peer sends ECN counts`() {
        val (client, pipe) = newConnectedClient()
        assertNull(ackForTwoPings(client, pipe).ecnCounts)

        val largest = client.application.pnSpace.nextPacketNumber - 1L
        val peerAck = AckFrame(largestAcknowledged = largest, ackDelay = 0L, firstAckRange = largest, ecnCounts = AckEcnCounts(ect0 = 3L, ect1 = 0L, ce = 0L))
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(peerAck))!!, nowMillis = 0L)

        assertNotNull(ackForTwoPings(client, pipe).ecnCounts)
    }

    @Test
    fun `ACK_ECN counts survive decoding`() {
        // They were read and dropped, so a peer's rising CE count never reached congestion control.
        val counts = AckEcnCounts(ect0 = 7L, ect1 = 1L, ce = 2L)
        val decoded = decodeFrames(encodeFrames(listOf(AckFrame(largestAcknowledged = 9L, ackDelay = 0L, firstAckRange = 3L, ecnCounts = counts)))).single() as AckFrame
        assertEquals(counts, decoded.ecnCounts)
    }
}
