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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** RFC 8899 / RFC 9000 §14.3 path MTU discovery. */
class PmtuDiscoveryTest {
    @Test
    fun first_probe_tries_the_ceiling_and_success_raises_the_size() {
        val d = PmtuDiscovery(1452)
        assertEquals(1452, d.probeDue(0))
        d.onProbeSent(1452)
        assertEquals(0, d.probeDue(0), "one probe at a time")
        d.onProbeAcked(1452)
        assertEquals(1452, d.currentSize)
        assertTrue(d.searchComplete)
        assertEquals(0, d.probeDue(0))
    }

    @Test
    fun three_losses_lower_the_ceiling_and_the_search_bisects() {
        val d = PmtuDiscovery(1452)
        repeat(PmtuDiscovery.MAX_PROBES) {
            val size = d.probeDue(0)
            assertEquals(1452, size)
            d.onProbeSent(size)
            d.onProbeLost(size)
        }
        assertEquals(1451, d.ceiling)
        val next = d.probeDue(0)
        assertEquals((1200 + 1451 + 1) / 2, next)
        d.onProbeSent(next)
        d.onProbeAcked(next)
        assertEquals(next, d.currentSize)
        assertTrue(d.probeDue(0) > next)
    }

    @Test
    fun black_hole_falls_back_to_the_base_size() {
        val d = PmtuDiscovery(1452)
        d.onProbeSent(d.probeDue(0))
        d.onProbeAcked(1452)
        assertTrue(d.onBlackHoleSuspected(10))
        assertEquals(PmtuDiscovery.BASE_SIZE, d.currentSize)
        assertEquals(0, d.probeDue(11), "search waits for the raise timer")
        assertTrue(d.probeDue(10 + PmtuDiscovery.RAISE_TIMER_MILLIS) > 0)
    }

    @Test
    fun connection_probes_in_a_lull_and_grows_its_packets() {
        val (client, pipe) = newConnectedClient()
        // Everything owed goes out first; then, idle, the probe.
        var probe: ByteArray? = null
        repeat(5) { if (probe == null) drainOutbound(client, 10L)?.let { d -> if (d.size > 1300) probe = d } }
        val datagram = assertNotNull(probe, "a probe goes out once there's nothing else to send")
        assertEquals(client.pmtud.ceiling, datagram.size, "probe is exactly the size under test")
        assertTrue(pipe.decryptClientApplicationFrames(datagram)!!.any { it is PingFrame })
        val probePn =
            client.application.sentPackets.values
                .single { it.mtuProbeSize > 0 }
                .packetNumber
        val ack = pipe.buildServerApplicationDatagram(listOf(AckFrame(probePn, 0, 0)))!!
        feedDatagram(client, ack, 20L)
        assertEquals(datagram.size, client.pmtud.currentSize)
    }

    @Test
    fun a_lost_probe_is_not_congestion() {
        val (client, pipe) = newConnectedClient()
        var probe: ByteArray? = null
        repeat(5) { if (probe == null) drainOutbound(client, 10L)?.let { d -> if (d.size > 1300) probe = d } }
        assertNotNull(probe)
        val window = client.congestion.congestionWindow
        val probePn =
            client.application.sentPackets.values
                .single { it.mtuProbeSize > 0 }
                .packetNumber
        // Send three more packets and ACK them so the probe is declared lost by packet threshold.
        val stream = kotlinx.coroutines.runBlocking { client.openBidiStream() }
        stream.send.enqueue(ByteArray(3_000))
        var now = 2_000L
        repeat(4) {
            drainOutbound(client, now)
            now += 10
        }
        val largest =
            client.application.sentPackets.keys
                .max()
        // Everything but the probe: [probePn+1, largest] and [0, probePn-1].
        val ack =
            AckFrame(
                largest,
                0,
                largest - probePn - 1,
                listOf(
                    com.vitorpamplona.quic.frame
                        .AckRange(0, probePn - 1),
                ),
            )
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(ack))!!, now)
        assertTrue(
            client.application.sentPackets.values
                .none { it.mtuProbeSize > 0 },
            "probe declared lost",
        )
        assertEquals(0L, client.congestion.congestionEvents, "a lost probe doesn't shrink the window")
        assertTrue(client.congestion.congestionWindow >= window)
    }
}
