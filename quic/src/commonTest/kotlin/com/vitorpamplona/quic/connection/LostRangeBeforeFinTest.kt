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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A packet lost before the one carrying the FIN: the peer ACKs the FIN first,
 * and the stream must stay around until the lost bytes are resent and ACK'd.
 * Found against quic-go's HTTP/3 client, which waited forever for 1416 bytes
 * of a 512 KB response that our server had dropped along with the stream.
 */
class LostRangeBeforeFinTest {
    @Test
    fun `a stream whose FIN is acked first keeps its lost bytes`() =
        runBlocking {
            val (client, pipe) = newConnectedClient()
            drainAndAckEverything(client, pipe)

            val stream = client.openUniStream()
            val payload = ByteArray(6_000) { it.toByte() }
            stream.send.enqueue(payload)
            stream.send.finish()

            val sent = mutableListOf<Long>()
            while (true) {
                val out = drainOutbound(client, nowMillis = 0L) ?: break
                pipe.decryptClientApplicationFrames(out)
                sent += client.application.pnSpace.nextPacketNumber - 1L
            }
            assertTrue(sent.size >= 5, "the payload spans several packets (sent=$sent)")

            // Only the last packet (the FIN) arrives; packet-threshold loss
            // declares the oldest ones lost.
            ack(client, pipe, largest = sent.last(), firstRange = 0L)
            assertTrue(stream.send.finAcked)
            assertFalse(stream.send.fullyAcked)
            assertFalse(stream.isFullyRetired, "lost bytes still need their retransmit")

            val resent = mutableListOf<StreamFrame>()
            while (true) {
                val out = drainOutbound(client, nowMillis = 0L) ?: break
                pipe.decryptClientApplicationFrames(out)!!.filterIsInstance<StreamFrame>().filterTo(resent) { it.streamId == stream.streamId }
            }
            assertTrue(resent.isNotEmpty(), "the lost range is retransmitted")
            assertEquals(0L, resent.minOf { it.offset }, "starting with the first lost byte")
            assertTrue(client.streamsListLocked().contains(stream), "the stream isn't retired yet")

            drainAndAckEverything(client, pipe)
            assertTrue(stream.send.fullyAcked)
            assertTrue(stream.isFullyRetired)
        }

    @Test
    fun `a closed stream with no credit left still resends a lost range`() =
        runBlocking {
            // The quic-go failures: a response stream whose request was FIN'd
            // (so the stream counts as closed once our FIN goes out), sending
            // exactly its credit. The lost range must still go out.
            val payload = ByteArray(6_000) { it.toByte() }
            val (client, pipe) = newConnectedClient(maxStreamData = payload.size.toLong())
            drainAndAckEverything(client, pipe)

            val stream = client.openBidiStream()
            val peerFin = pipe.buildServerApplicationDatagram(listOf(StreamFrame(stream.streamId, 0L, "request".encodeToByteArray(), fin = true)))!!
            feedDatagram(client, peerFin, nowMillis = 0L)
            stream.send.enqueue(payload)
            stream.send.finish()

            val sent = mutableListOf<Long>()
            while (true) {
                val out = drainOutbound(client, nowMillis = 0L) ?: break
                pipe.decryptClientApplicationFrames(out)
                sent += client.application.pnSpace.nextPacketNumber - 1L
            }
            assertTrue(stream.isClosed)
            assertEquals(stream.sendCredit, stream.send.sentOffset, "the stream used all its credit")

            ack(client, pipe, largest = sent.last(), firstRange = 0L)
            assertTrue(stream.send.hasRetransmit)

            val resent = mutableListOf<StreamFrame>()
            while (true) {
                val out = drainOutbound(client, nowMillis = 0L) ?: break
                pipe.decryptClientApplicationFrames(out)!!.filterIsInstance<StreamFrame>().filterTo(resent) { it.streamId == stream.streamId }
            }
            assertTrue(resent.isNotEmpty(), "the lost range is retransmitted")
            assertEquals(0L, resent.minOf { it.offset })
            assertFalse(stream.send.hasRetransmit)
        }

    @Test
    fun `an idle connection does not arm the PTO`() =
        runBlocking {
            val (client, pipe) = newConnectedClient()
            drainAndAckEverything(client, pipe)
            assertFalse(client.ptoArmed(), "nothing ack-eliciting in flight after the handshake is confirmed")

            val stream = client.openUniStream()
            stream.send.enqueue("hello".encodeToByteArray())
            while (true) {
                val out = drainOutbound(client, nowMillis = 0L) ?: break
                pipe.decryptClientApplicationFrames(out)
            }
            assertTrue(client.ptoArmed(), "a STREAM frame in flight arms it")

            drainAndAckEverything(client, pipe)
            assertFalse(client.ptoArmed())
        }

    @Test
    fun `after sending only ACKs one PING follows a PTO of silence`() =
        runBlocking {
            // A receiver that only ACKs goes silent if the peer's packets stop
            // arriving (a NAT rebinding drops them); the PING is what tells the
            // peer our new address (our client against haproxy's rebind tests).
            val (client, pipe) = newConnectedClient()
            drainAndAckEverything(client, pipe)
            repeat(2) { feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(com.vitorpamplona.quic.frame.PingFrame))!!, nowMillis = 0L) }
            val ackOnly = pipe.decryptClientApplicationFrames(assertNotNull(drainOutbound(client, nowMillis = 0L)))!!
            assertTrue(ackOnly.all { it is AckFrame }, "an ACK-only packet: $ackOnly")
            assertTrue(client.ptoArmed(), "an ACK-only packet keeps the PTO timer running")

            handlePtoFired(client)
            val probe = pipe.decryptClientApplicationFrames(assertNotNull(drainOutbound(client, nowMillis = 1_000L)))!!
            assertTrue(probe.any { it is com.vitorpamplona.quic.frame.PingFrame }, "the PTO sent a PING: $probe")
            drainAndAckEverything(client, pipe)
            assertFalse(client.ptoArmed(), "quiet once the PING is acknowledged")
        }

    private fun drainAndAckEverything(
        client: QuicConnection,
        pipe: InMemoryQuicPipe,
    ) {
        while (true) {
            val out = drainOutbound(client, nowMillis = 0L) ?: break
            pipe.decryptClientApplicationFrames(out)
        }
        val largest = client.application.pnSpace.nextPacketNumber - 1L
        if (largest >= 0L) ack(client, pipe, largest, firstRange = largest)
    }

    private fun ack(
        client: QuicConnection,
        pipe: InMemoryQuicPipe,
        largest: Long,
        firstRange: Long,
    ) {
        val packet = pipe.buildServerApplicationDatagram(listOf(AckFrame(largestAcknowledged = largest, ackDelay = 0L, firstAckRange = firstRange)))!!
        feedDatagram(client, packet, nowMillis = 0L)
    }
}
