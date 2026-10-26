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

import com.vitorpamplona.quic.frame.DataBlockedFrame
import com.vitorpamplona.quic.frame.MaxStreamDataFrame
import com.vitorpamplona.quic.frame.PingFrame
import com.vitorpamplona.quic.frame.QuicTransportError
import com.vitorpamplona.quic.frame.StreamDataBlockedFrame
import com.vitorpamplona.quic.frame.StreamFrame
import com.vitorpamplona.quic.frame.StreamsBlockedFrame
import com.vitorpamplona.quic.frame.decodeFrames
import com.vitorpamplona.quic.frame.encodeFrames
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BlockedFramesTest {
    @Test
    fun blocked_frames_round_trip() {
        val frames = listOf(DataBlockedFrame(10), StreamDataBlockedFrame(4, 20), StreamsBlockedFrame(true, 3), StreamsBlockedFrame(false, 5))
        val decoded = decodeFrames(encodeFrames(frames))
        assertEquals(10L, (decoded[0] as DataBlockedFrame).maximumData)
        assertEquals(20L, (decoded[1] as StreamDataBlockedFrame).maximumStreamData)
        assertTrue((decoded[2] as StreamsBlockedFrame).bidi)
        assertEquals(5L, (decoded[3] as StreamsBlockedFrame).maximumStreams)
    }

    @Test
    fun a_lone_blocked_frame_is_acknowledged() {
        val (client, pipe) = newConnectedClient()
        while (drainOutbound(client, 0L) != null) { /* clear */ }
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(DataBlockedFrame(1_000), StreamDataBlockedFrame(1, 100)))!!, 0L)
        assertNotNull(drainOutbound(client, QuicConnectionConfig().maxAckDelay), "BLOCKED frames are ack-eliciting")
    }

    @Test
    fun stream_blocked_on_peer_credit_says_so_once() {
        val (client, pipe) = newConnectedClient(maxStreamData = 1_000)
        val stream = runBlocking { client.openBidiStream() }
        stream.send.enqueue(ByteArray(5_000))
        val sent = mutableListOf<com.vitorpamplona.quic.frame.Frame>()
        var now = 0L
        repeat(10) {
            now += 100
            drainOutbound(client, now)?.let { pipe.decryptClientApplicationFrames(it)?.let(sent::addAll) }
        }
        assertEquals(1_000, sent.filterIsInstance<StreamFrame>().sumOf { it.data.size }, "stops at the peer's 1000-byte limit")
        val blocked = sent.filterIsInstance<StreamDataBlockedFrame>()
        assertEquals(1, blocked.size, "reported once per limit: $sent")
        assertEquals(stream.streamId, blocked.single().streamId)
        assertEquals(1_000L, blocked.single().maximumStreamData)

        // New credit, blocked again at the new limit: reported again.
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(MaxStreamDataFrame(stream.streamId, 2_000)))!!, now)
        sent.clear()
        repeat(10) {
            now += 100
            drainOutbound(client, now)?.let { pipe.decryptClientApplicationFrames(it)?.let(sent::addAll) }
        }
        assertEquals(2_000L, sent.filterIsInstance<StreamDataBlockedFrame>().single().maximumStreamData)
    }

    @Test
    fun stream_frame_in_an_initial_packet_is_a_protocol_violation() {
        val client = newHandshakingClient()
        val pipe = InMemoryQuicPipe(client, client.destinationConnectionId.bytes)
        feedDatagram(client, pipe.buildServerInitialDatagram(listOf(StreamFrame(1, 0, ByteArray(1), false, true))), 0L)
        assertEquals(QuicConnection.Status.CLOSED, client.status)
        assertEquals(QuicTransportError.PROTOCOL_VIOLATION, client.closeErrorCode)
    }

    @Test
    fun only_the_first_server_initial_scid_is_adopted() {
        val client = newHandshakingClient()
        val pipe = InMemoryQuicPipe(client, client.destinationConnectionId.bytes)
        val first = ConnectionId.random(8)
        feedDatagram(client, pipe.buildServerInitialDatagram(listOf(PingFrame), scid = first), 0L)
        assertEquals(first, client.destinationConnectionId)
        val other = ConnectionId.random(8)
        feedDatagram(client, pipe.buildServerInitialDatagram(listOf(PingFrame), scid = other), 0L)
        assertEquals(first, client.destinationConnectionId, "a later Initial with another SCID is dropped")
        assertEquals(QuicConnection.Status.HANDSHAKING, client.status)
    }

    @Test
    fun hitting_the_stream_limit_sends_streams_blocked() {
        val (client, pipe) = newConnectedClient(maxStreamsBidi = 1)
        while (drainOutbound(client, 0L) != null) { /* clear */ }
        runBlocking { client.openBidiStream() }
        repeat(2) { assertTrue(runCatching { runBlocking { client.openBidiStream() } }.isFailure) }
        val frames = drainOutbound(client, 0L)?.let { pipe.decryptClientApplicationFrames(it) }.orEmpty()
        val blocked = frames.filterIsInstance<StreamsBlockedFrame>()
        assertEquals(1, blocked.size, "once per limit: $frames")
        assertTrue(blocked.single().bidi)
        assertEquals(1L, blocked.single().maximumStreams)
    }

    private fun newHandshakingClient() =
        QuicConnection(
            serverName = "example.test",
            config = QuicConnectionConfig(),
            tlsCertificateValidator =
                com.vitorpamplona.quic.tls
                    .PermissiveCertificateValidator(),
        ).also { it.start() }
}
