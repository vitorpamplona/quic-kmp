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
import com.vitorpamplona.quic.frame.StreamFrame
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The writer stops sending stream data at the congestion window and resumes on ACK. */
class CongestionGatingTest {
    @Test
    fun stream_data_stops_at_the_window_and_resumes_after_an_ack() {
        val (client, pipe) = newConnectedClient(maxData = 4L * 1024 * 1024, maxStreamData = 4L * 1024 * 1024)
        val stream = runBlocking { client.openBidiStream() }
        stream.send.enqueue(ByteArray(200_000))
        var now = 0L
        var sentBytes = 0L
        repeat(200) {
            // Advance time so the pacer never limits: only the window can.
            now += 1000
            val d = drainOutbound(client, now) ?: return@repeat
            val frames = pipe.decryptClientApplicationFrames(d) ?: return@repeat
            sentBytes += frames.filterIsInstance<StreamFrame>().sumOf { it.data.size }
        }
        val window = client.congestion.congestionWindow
        assertTrue(client.congestionBlocked(), "blocked after filling the window")
        assertTrue(sentBytes in (window - 2400)..window, "sent $sentBytes of a $window-byte window")
        assertTrue(client.bytesInFlight() >= window)

        // ACK everything sent: the window grows (slow start) and data flows again.
        val largest =
            client.application.sentPackets.keys
                .max()
        val ack = pipe.buildServerApplicationDatagram(listOf(AckFrame(largestAcknowledged = largest, ackDelay = 0, firstAckRange = largest)))
        assertNotNull(ack)
        feedDatagram(client, ack, now + 10)
        assertEquals(0L, client.bytesInFlight())
        assertTrue(client.congestion.congestionWindow > window, "slow start grew the window")
        val next = drainOutbound(client, now + 2000)
        assertNotNull(next)
        assertTrue(pipe.decryptClientApplicationFrames(next)!!.any { it is StreamFrame })
    }
}
