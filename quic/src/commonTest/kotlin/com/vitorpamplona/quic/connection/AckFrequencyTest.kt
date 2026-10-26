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
import com.vitorpamplona.quic.frame.AckFrequencyFrame
import com.vitorpamplona.quic.frame.ImmediateAckFrame
import com.vitorpamplona.quic.frame.PingFrame
import com.vitorpamplona.quic.frame.decodeFrames
import com.vitorpamplona.quic.frame.encodeFrames
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** draft-ietf-quic-ack-frequency: min_ack_delay, ACK_FREQUENCY and IMMEDIATE_ACK as the receiver. */
class AckFrequencyTest {
    @Test
    fun min_ack_delay_round_trips_and_is_advertised() {
        val tp = TransportParameters(minAckDelayMicros = 1_000L)
        assertEquals(1_000L, TransportParameters.decode(tp.encode()).minAckDelayMicros)
        val frames = listOf(AckFrequencyFrame(3, 9, 50_000, 0), ImmediateAckFrame())
        val decoded = decodeFrames(encodeFrames(frames))
        val af = decoded[0] as AckFrequencyFrame
        assertEquals(listOf(3L, 9L, 50_000L, 0L), listOf(af.sequenceNumber, af.ackElicitingThreshold, af.requestedMaxAckDelayMicros, af.reorderingThreshold))
        assertTrue(decoded[1] is ImmediateAckFrame)
    }

    /** Feed one 1-RTT PING packet; true when the client's next drain carries an ACK. */
    private fun pingAndAckDue(
        client: QuicConnection,
        pipe: InMemoryQuicPipe,
        now: Long,
        extra: List<com.vitorpamplona.quic.frame.Frame> = emptyList(),
    ): Boolean {
        feedDatagram(client, pipe.buildServerApplicationDatagram(extra + PingFrame)!!, now)
        val out = drainOutbound(client, now) ?: return false
        return pipe.decryptClientApplicationFrames(out)?.any { it is AckFrame } == true
    }

    @Test
    fun ack_frequency_raises_the_threshold_and_immediate_ack_overrides_it() {
        val (client, pipe) = newConnectedClient()
        while (drainOutbound(client, 0L) != null) Unit
        // Threshold 9: acknowledge every tenth ack-eliciting packet; 1 s delay.
        assertTrue(!pingAndAckDue(client, pipe, 1, listOf(AckFrequencyFrame(0, 9, 1_000_000, 0))))
        for (i in 2..9) assertTrue(!pingAndAckDue(client, pipe, i.toLong()), "packet $i")
        assertTrue(pingAndAckDue(client, pipe, 10), "tenth packet")
        assertEquals(1_000L, client.localMaxAckDelayMillis)
        // IMMEDIATE_ACK: right away.
        assertTrue(pingAndAckDue(client, pipe, 11, listOf(ImmediateAckFrame())))
        // A stale sequence number changes nothing.
        assertTrue(!pingAndAckDue(client, pipe, 12, listOf(AckFrequencyFrame(0, 0, 1_000, 1))))
    }

    @Test
    fun a_delay_below_min_ack_delay_is_a_protocol_violation() {
        val (client, pipe) = newConnectedClient()
        feedDatagram(client, assertNotNull(pipe.buildServerApplicationDatagram(listOf(AckFrequencyFrame(0, 1, 10, 1)))), 1)
        assertEquals(QuicConnection.Status.CLOSED, client.status)
        assertEquals(com.vitorpamplona.quic.frame.QuicTransportError.PROTOCOL_VIOLATION, client.closeErrorCode)
    }
}
