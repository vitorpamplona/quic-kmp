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
package com.vitorpamplona.quic.recovery

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** RFC 9000 §13.2.1–§13.2.2 delayed acknowledgments. */
class DelayedAckTest {
    private val maxAckDelay = 25L

    @Test
    fun one_packet_waits_for_max_ack_delay() {
        val t = AckTracker()
        t.receivedPacket(0, ackEliciting = true, receivedAtMillis = 100)
        assertFalse(t.ackDue(110, maxAckDelay))
        assertEquals(125L, t.ackDeadlineMillis(maxAckDelay))
        assertTrue(t.ackDue(125, maxAckDelay))
    }

    @Test
    fun second_ack_eliciting_packet_makes_it_due() {
        val t = AckTracker()
        t.receivedPacket(0, ackEliciting = true, receivedAtMillis = 100)
        t.receivedPacket(1, ackEliciting = true, receivedAtMillis = 101)
        assertTrue(t.ackDue(101, maxAckDelay))
    }

    @Test
    fun reordering_is_acknowledged_at_once() {
        val t = AckTracker()
        t.receivedPacket(0, ackEliciting = true, receivedAtMillis = 100)
        assertNotNull(t.buildAckFrame(100))
        t.receivedPacket(2, ackEliciting = true, receivedAtMillis = 101) // gap: 1 missing
        assertTrue(t.ackDue(101, maxAckDelay))
    }

    @Test
    fun building_an_ack_resets_the_counters() {
        val t = AckTracker()
        t.receivedPacket(0, ackEliciting = true, receivedAtMillis = 100)
        t.receivedPacket(1, ackEliciting = true, receivedAtMillis = 100)
        assertNotNull(t.buildAckFrame(100))
        assertFalse(t.ackDue(100, maxAckDelay))
        assertNull(t.ackDeadlineMillis(maxAckDelay))
        t.receivedPacket(2, ackEliciting = true, receivedAtMillis = 200)
        assertFalse(t.ackDue(201, maxAckDelay), "in-order single packet starts a fresh delay")
    }

    @Test
    fun non_ack_eliciting_packets_never_make_an_ack_due() {
        val t = AckTracker()
        t.receivedPacket(0, ackEliciting = false, receivedAtMillis = 0)
        t.receivedPacket(1, ackEliciting = false, receivedAtMillis = 0)
        assertFalse(t.ackDue(1_000, maxAckDelay))
        assertNull(t.ackDeadlineMillis(maxAckDelay))
    }
}
