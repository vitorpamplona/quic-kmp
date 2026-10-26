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

import com.vitorpamplona.quic.frame.AckFrame
import com.vitorpamplona.quic.frame.PingFrame
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * RFC 9002 §6.2.1: the PTO period counts from the latest ack-eliciting send.
 * It used to restart on every pass of the send loop, and a stream write wakes
 * the loop: an app writing every few milliseconds into a full congestion
 * window on a dead path never saw a probe.
 */
class PtoDeadlineTest {
    /** Sends what's queued at [sentAt] and has the peer ACK all of it at [ackedAt]. */
    private fun sendAndAck(
        client: QuicConnection,
        pipe: InMemoryQuicPipe,
        sentAt: Long,
        ackedAt: Long,
    ) {
        while (true) pipe.decryptClientApplicationFrames(drainOutbound(client, nowMillis = sentAt) ?: break)
        val largest = client.application.pnSpace.nextPacketNumber - 1L
        val ack = AckFrame(largestAcknowledged = largest, ackDelay = 0L, firstAckRange = largest)
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(ack))!!, nowMillis = ackedAt)
    }

    @Test
    fun `waking up later does not postpone the PTO`() =
        runBlocking {
            val (client, pipe) = newConnectedClient()
            // An RTT sample of about 200 ms, so the PTO period is measurable.
            client.openUniStream().send.enqueue("rtt".encodeToByteArray())
            sendAndAck(client, pipe, sentAt = 0L, ackedAt = 200L)

            client.openUniStream().send.enqueue("hello".encodeToByteArray())
            assertNotNull(drainOutbound(client, nowMillis = 1_000L))
            val atSend = client.ptoDelayMillis(1_000L)
            assertTrue(atSend in 200L until 60_000L, "armed with data in flight: $atSend")
            assertEquals(atSend - 100L, client.ptoDelayMillis(1_100L), "100 ms later, 100 ms closer")
            assertEquals(0L, client.ptoDelayMillis(1_000L + atSend + 50L), "past the deadline it is due now")
        }

    @Test
    fun `a PTO of silence after an ACK-only packet gets one probe and not two`() =
        runBlocking {
            val (client, pipe) = newConnectedClient()
            sendAndAck(client, pipe, sentAt = 0L, ackedAt = 0L)
            repeat(2) { feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(PingFrame))!!, nowMillis = 0L) }
            assertNotNull(drainOutbound(client, nowMillis = 0L))
            assertTrue(client.lastAppPacketAckOnly)
            handlePtoFired(client)
            assertEquals(1, client.pendingProbePackets)
        }
}
