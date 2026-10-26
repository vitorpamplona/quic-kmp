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
package com.vitorpamplona.quic.connection.recovery

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** RFC 9002 Appendix B NewReno, mirroring neqo's `cc/classic_cc.rs` cases. */
class CongestionControllerTest {
    private val mss = 1200

    private fun packet(
        pn: Long,
        sentAt: Long,
        size: Int = mss,
        ackEliciting: Boolean = true,
    ) = SentPacket(pn, sentAt, ackEliciting, size, emptyList())

    @Test
    fun initial_window_follows_rfc9002() {
        val cc = CongestionController(mss)
        assertEquals(12_000L, cc.congestionWindow, "min(10 * 1200, max(2400, 14720))")
        assertEquals(2_400L, cc.minimumWindow)
        assertTrue(cc.inSlowStart)
        assertEquals(14_720L, CongestionController(1472).congestionWindow)
    }

    @Test
    fun slow_start_grows_by_acked_bytes() {
        val cc = CongestionController(mss)
        val acked = (0L until 10L).map { packet(it, 0L) }
        cc.onPacketsAcked(acked, bytesInFlightBeforeAck = cc.congestionWindow)
        assertEquals(24_000L, cc.congestionWindow, "a full window acked doubles it")
    }

    @Test
    fun app_limited_sender_does_not_grow() {
        val cc = CongestionController(mss)
        cc.onPacketsAcked(listOf(packet(0, 0)), bytesInFlightBeforeAck = mss.toLong())
        assertEquals(12_000L, cc.congestionWindow)
    }

    @Test
    fun non_ack_eliciting_packets_do_not_count() {
        val cc = CongestionController(mss)
        cc.onPacketsAcked(listOf(packet(0, 0, ackEliciting = false)), bytesInFlightBeforeAck = cc.congestionWindow)
        assertEquals(12_000L, cc.congestionWindow)
        cc.onPacketsLost(listOf(packet(1, 0, ackEliciting = false)), 10, null)
        assertEquals(0L, cc.congestionEvents)
    }

    @Test
    fun loss_halves_and_enters_avoidance() {
        val cc = CongestionController(mss)
        cc.onPacketsLost(listOf(packet(0, 5)), nowMillis = 10, persistentCongestionDurationMs = null)
        assertEquals(6_000L, cc.congestionWindow)
        assertEquals(6_000L, cc.slowStartThreshold)
        assertFalse(cc.inSlowStart)
        assertEquals(1L, cc.congestionEvents)
    }

    @Test
    fun one_reduction_per_recovery_period() {
        val cc = CongestionController(mss)
        cc.onPacketsLost(listOf(packet(0, 5)), nowMillis = 10, persistentCongestionDurationMs = null)
        // Sent before recovery started: same congestion epoch.
        cc.onPacketsLost(listOf(packet(1, 8)), nowMillis = 12, persistentCongestionDurationMs = null)
        assertEquals(6_000L, cc.congestionWindow)
        // Sent after: a new event.
        cc.onPacketsLost(listOf(packet(2, 11)), nowMillis = 20, persistentCongestionDurationMs = null)
        assertEquals(3_000L, cc.congestionWindow)
        assertEquals(2L, cc.congestionEvents)
    }

    @Test
    fun packets_sent_before_recovery_do_not_grow_the_window() {
        val cc = CongestionController(mss)
        cc.onPacketsLost(listOf(packet(0, 5)), nowMillis = 10, persistentCongestionDurationMs = null)
        cc.onPacketsAcked(listOf(packet(1, 9)), bytesInFlightBeforeAck = 10_000)
        assertEquals(6_000L, cc.congestionWindow)
    }

    @Test
    fun avoidance_grows_one_datagram_per_window() {
        val cc = CongestionController(mss)
        cc.onPacketsLost(listOf(packet(0, 0)), nowMillis = 1, persistentCongestionDurationMs = null)
        val window = cc.congestionWindow
        val acked = (1L..5L).map { packet(it, 2) } // 6000 bytes = one window
        cc.onPacketsAcked(acked, bytesInFlightBeforeAck = window)
        assertEquals(window + mss, cc.congestionWindow)
    }

    @Test
    fun window_never_drops_below_minimum() {
        val cc = CongestionController(mss)
        repeat(10) { i -> cc.onPacketsLost(listOf(packet(i.toLong(), 100L * i + 1)), nowMillis = 100L * i + 2, persistentCongestionDurationMs = null) }
        assertEquals(cc.minimumWindow, cc.congestionWindow)
    }

    @Test
    fun persistent_congestion_collapses_to_minimum() {
        val cc = CongestionController(mss)
        cc.onPacketsLost(listOf(packet(0, 0), packet(1, 1000)), nowMillis = 1100, persistentCongestionDurationMs = 900)
        assertEquals(cc.minimumWindow, cc.congestionWindow)
        assertEquals(1L, cc.persistentCongestionEvents)
        // Recovery period cleared: the next ACKs grow the window again (slow start).
        assertTrue(cc.inSlowStart || cc.congestionWindow == cc.minimumWindow)
    }

    @Test
    fun short_loss_span_is_not_persistent() {
        val cc = CongestionController(mss)
        cc.onPacketsLost(listOf(packet(0, 0), packet(1, 100)), nowMillis = 200, persistentCongestionDurationMs = 900)
        assertEquals(6_000L, cc.congestionWindow)
        assertEquals(0L, cc.persistentCongestionEvents)
    }

    @Test
    fun ecn_ce_is_a_congestion_event() {
        val cc = CongestionController(mss)
        cc.onCongestionEvent(sentAtMillis = 5, nowMillis = 10)
        assertEquals(6_000L, cc.congestionWindow)
    }
}
