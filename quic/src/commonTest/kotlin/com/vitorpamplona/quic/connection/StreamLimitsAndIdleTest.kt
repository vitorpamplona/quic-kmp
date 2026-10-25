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

import com.vitorpamplona.quic.frame.QuicTransportError
import com.vitorpamplona.quic.frame.StreamFrame
import com.vitorpamplona.quic.stream.StreamId
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Stream limits, credit for unread streams and the idle timer. */
class StreamLimitsAndIdleTest {
    @Test
    fun a_peer_opening_past_our_stream_limit_is_a_stream_limit_error() {
        val (client, pipe) = newConnectedClient()
        val past = StreamId.build(StreamId.Kind.SERVER_UNI, client.advertisedMaxStreamsUni)
        feedDatagram(client, assertNotNull(pipe.buildServerApplicationDatagram(listOf(StreamFrame(past, 0, byteArrayOf(1), fin = false)))), 1)
        assertEquals(QuicConnection.Status.CLOSED, client.status)
        assertEquals(QuicTransportError.STREAM_LIMIT_ERROR, client.closeErrorCode)
    }

    @Test
    fun a_finished_stream_keeps_its_credit_until_it_is_read() =
        runBlocking {
            val (client, pipe) = newConnectedClient()
            val id = StreamId.build(StreamId.Kind.SERVER_UNI, 0)
            feedDatagram(client, assertNotNull(pipe.buildServerApplicationDatagram(listOf(StreamFrame(id, 0, ByteArray(500), fin = true)))), 1)
            val stream = assertNotNull(client.streamByIdLocked(id))
            client.retireFullyDoneStreamsLocked()
            assertNotNull(client.streamByIdLocked(id), "unread: not retired")
            assertEquals(0L, client.retiredStreamsRecvBytes)
            assertEquals(500, stream.incoming.toList().sumOf { it.size })
            client.retireFullyDoneStreamsLocked()
            assertNull(client.streamByIdLocked(id), "read to the end: retired")
            assertEquals(500L, client.retiredStreamsRecvBytes)
        }

    @Test
    fun only_the_first_ack_eliciting_send_after_a_receive_restarts_the_idle_timer() {
        val (client, pipe) = newConnectedClient()
        client.noteReceived(1_000)
        client.noteAckElicitingSent(2_000)
        assertEquals(2_000L, client.lastActivityMs)
        client.noteAckElicitingSent(30_000)
        assertEquals(2_000L, client.lastActivityMs, "a PTO probe into silence must not keep the connection alive")
        val timeout = assertNotNull(client.effectiveIdleTimeoutMs())
        assertTrue(client.isIdleTimedOut(2_000 + timeout))
        feedDatagram(client, assertNotNull(pipe.buildServerApplicationDatagram(listOf(com.vitorpamplona.quic.frame.PingFrame))), 40_000)
        assertEquals(40_000L, client.lastActivityMs)
    }
}
