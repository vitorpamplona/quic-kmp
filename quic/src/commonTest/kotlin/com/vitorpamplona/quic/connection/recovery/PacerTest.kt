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

class PacerTest {
    @Test
    fun allows_an_initial_burst_then_paces() {
        val pacer = Pacer(1200)
        val cwnd = 12_000L
        val rtt = 100L
        repeat(10) {
            assertEquals(0L, pacer.delayMillis(0, 1200, cwnd, rtt), "burst of ten")
            pacer.onSent(1200)
        }
        val wait = pacer.delayMillis(0, 1200, cwnd, rtt)
        assertTrue(wait > 0, "eleventh datagram waits")
        // 1.25 * 12000 / 100 = 150 bytes/ms → 1200 bytes take 8 ms.
        assertEquals(8L, wait)
        assertEquals(0L, pacer.delayMillis(8, 1200, cwnd, rtt))
    }

    @Test
    fun rate_scales_with_the_window() {
        val pacer = Pacer(1200)
        repeat(10) { pacer.onSent(1200) }
        val slow = pacer.delayMillis(0, 1200, 12_000, 100)
        val fast = Pacer(1200).also { p -> repeat(10) { p.onSent(1200) } }.delayMillis(0, 1200, 120_000, 100)
        assertTrue(fast < slow)
    }

    @Test
    fun idle_time_refills_up_to_the_burst_cap() {
        val pacer = Pacer(1200)
        repeat(10) { pacer.onSent(1200) }
        pacer.delayMillis(0, 1200, 12_000, 100)
        // A long idle period refills, but only to the burst capacity.
        assertEquals(0L, pacer.delayMillis(10_000, 1200, 12_000, 100))
        repeat(10) { pacer.onSent(1200) }
        assertTrue(pacer.delayMillis(10_000, 1200, 12_000, 100) > 0)
    }
}
