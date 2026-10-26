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
import kotlin.test.assertTrue

/** RFC 9438 CUBIC in [CongestionController]. */
class CubicCongestionTest {
    private val mss = 1200

    private fun packet(
        pn: Long,
        sentAt: Long,
    ) = SentPacket(pn, sentAt, true, mss, emptyList())

    private fun cubic() = CongestionController(mss, CongestionAlgorithm.CUBIC)

    /** Ack one full window's worth of datagrams sent after [sentAfter], at [now], with the window full. */
    private fun ackWindow(
        cc: CongestionController,
        sentAfter: Long,
        now: Long,
        rtt: Long,
    ) {
        val n = (cc.congestionWindow / mss).toInt()
        cc.onPacketsAcked((0 until n).map { packet(it.toLong(), sentAfter + 1) }, cc.congestionWindow, now, rtt)
    }

    @Test
    fun congestion_keeps_seventy_percent_of_the_window() {
        val cc = cubic()
        cc.onPacketsLost(listOf(packet(0, 5)), nowMillis = 10, persistentCongestionDurationMs = null)
        assertEquals((12_000 * 0.7).toLong(), cc.congestionWindow)
        assertEquals(cc.congestionWindow, cc.slowStartThreshold)
        // NewReno halves.
        val reno = CongestionController(mss)
        reno.onPacketsLost(listOf(packet(0, 5)), nowMillis = 10, persistentCongestionDurationMs = null)
        assertEquals(6_000L, reno.congestionWindow)
    }

    @Test
    fun the_window_climbs_back_to_where_loss_happened_then_probes_past_it() {
        val cc = cubic()
        // Grow to 100 datagrams in slow start, then lose.
        while (cc.congestionWindow < 100L * mss) ackWindow(cc, 0, 1, 50)
        val before = cc.congestionWindow
        cc.onPacketsLost(listOf(packet(0, 2)), nowMillis = 1_000, persistentCongestionDurationMs = null)
        val reduced = cc.congestionWindow
        // K = cbrt(W_max * (1 - beta) / C) seconds: about 4.2 s for 100+ datagrams.
        var now = 1_000L
        var sawConcave = false
        while (now < 1_000L + 4_000L) {
            now += 50
            ackWindow(cc, 1_000, now, 50)
            if (cc.congestionWindow in (reduced + 1) until before) sawConcave = true
        }
        assertTrue(sawConcave)
        assertTrue(cc.congestionWindow <= before * 102 / 100, "still near the plateau: ${cc.congestionWindow} vs $before")
        while (now < 1_000L + 8_000L) {
            now += 50
            ackWindow(cc, 1_000, now, 50)
        }
        assertTrue(cc.congestionWindow > before * 11 / 10, "probing past the old plateau: ${cc.congestionWindow} vs $before")
    }

    @Test
    fun a_second_loss_below_the_plateau_lowers_it() {
        val cc = cubic()
        while (cc.congestionWindow < 100L * mss) ackWindow(cc, 0, 1, 50)
        cc.onPacketsLost(listOf(packet(0, 2)), nowMillis = 1_000, persistentCongestionDurationMs = null)
        val afterFirst = cc.congestionWindow
        cc.onPacketsLost(listOf(packet(1, 1_500)), nowMillis = 2_000, persistentCongestionDurationMs = null)
        assertEquals((afterFirst * 0.7).toLong(), cc.congestionWindow)
        // Fast convergence: the plateau is now (1 + beta) / 2 of the window at the
        // second loss, so the window gets back there sooner than to the first one.
        var now = 2_000L
        repeat(60) {
            now += 50
            ackWindow(cc, 2_000, now, 50)
        }
        assertTrue(cc.congestionWindow >= afterFirst * 85 / 100, "${cc.congestionWindow} vs $afterFirst")
    }

    @Test
    fun small_windows_follow_the_reno_friendly_estimate() {
        // RFC 9438 §4.3: with a small window and short RTT the cubic curve is
        // slow (here it would still be under 9 datagrams after 0.4 s), so the
        // window follows W_est, which grows alpha = 3 * 0.3 / 1.7 ≈ 0.53
        // datagrams per round trip — Reno's average rate given beta 0.7.
        val cc = cubic()
        cc.onPacketsLost(listOf(packet(0, 5)), nowMillis = 10, persistentCongestionDurationMs = null)
        val reduced = cc.congestionWindow
        var now = 10L
        repeat(20) {
            now += 20
            ackWindow(cc, 10, now, 20)
        }
        val grown = (cc.congestionWindow - reduced) / mss.toDouble()
        assertTrue(grown in 9.0..11.5, "grew $grown datagrams in 20 round trips")
    }
}
