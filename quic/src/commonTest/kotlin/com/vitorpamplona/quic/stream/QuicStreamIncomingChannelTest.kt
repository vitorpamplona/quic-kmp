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
package com.vitorpamplona.quic.stream

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Bounds-checking on the per-stream `incomingChannel`.
 *
 * Audit-2 finding: a slow consumer paired with an unbounded channel was a
 * memory-pin vector — the parser would happily forward gigabytes of inbound
 * STREAM bytes that nothing ever read. The fix capped the channel at 64
 * chunks; the producer-side [QuicStream.deliverIncoming] uses `trySend`, so
 * a saturated channel quietly drops the offending chunk.
 *
 * The defence-in-depth layer is the connection-level receive-limit check in
 * the parser ([com.vitorpamplona.quic.connection.QuicConnectionParser] line
 * ~184) which closes the connection before a hostile peer can stream past
 * the advertised limit. These tests exercise the channel cap directly so a
 * regression that bumps the capacity (or removes it) gets caught even if
 * the receive-limit path moves.
 */
class QuicStreamIncomingChannelTest {
    @Test
    fun deliver_incoming_buffers_chunks_until_collector_drains_them() {
        // Baseline: chunks delivered before any collector starts MUST still
        // surface to the collector — the channel must buffer up to its cap.
        runBlocking {
            val stream = QuicStream(streamId = 0L, direction = QuicStream.Direction.BIDIRECTIONAL)

            // Push three small chunks before any collector is around.
            stream.deliverIncoming(byteArrayOf(0x10))
            stream.deliverIncoming(byteArrayOf(0x20))
            stream.deliverIncoming(byteArrayOf(0x30))
            stream.closeIncoming()

            val received = mutableListOf<ByteArray>()
            stream.incoming.collect { received += it }

            assertEquals(3, received.size)
            assertContentEquals(byteArrayOf(0x10), received[0])
            assertContentEquals(byteArrayOf(0x20), received[1])
            assertContentEquals(byteArrayOf(0x30), received[2])
        }
    }

    @Test
    fun deliver_incoming_never_blocks_or_drops_and_consumption_is_counted() {
        // The producer runs on the connection lock, so it must never block.
        // The channel doesn't bound what it holds — flow control does, by
        // only crediting what the collector consumed — so nothing is dropped.
        runBlocking {
            val stream = QuicStream(streamId = 0L, direction = QuicStream.Direction.BIDIRECTIONAL)
            val ok =
                withTimeoutOrNull(2_000L) {
                    repeat(1024) { i -> assertTrue(stream.deliverIncoming(byteArrayOf(i.toByte(), 0))) }
                    true
                }
            assertEquals(true, ok, "deliverIncoming must not block — a blocked producer would deadlock the parser")
            assertEquals(0L, stream.consumedBytes)
            stream.closeIncoming()
            val collected = mutableListOf<ByteArray>()
            stream.incoming.collect { collected += it }
            assertEquals(1024, collected.size)
            assertEquals(2048L, stream.consumedBytes)
            assertTrue(!stream.overflowed)
        }
    }

    @Test
    fun deliver_incoming_skips_empty_chunks() {
        // The parser issues a STREAM frame even when its data is zero-length
        // (FIN-only frames). deliverIncoming MUST NOT push an empty chunk —
        // otherwise the consumer sees a bogus "empty data event" between real
        // bytes. The closeIncoming path is the FIN signal.
        runBlocking {
            val stream = QuicStream(streamId = 0L, direction = QuicStream.Direction.BIDIRECTIONAL)
            stream.deliverIncoming(ByteArray(0))
            stream.deliverIncoming(byteArrayOf(0x42))
            stream.closeIncoming()

            val first = withTimeoutOrNull(2_000L) { stream.incoming.first() }
            assertNotNull(first)
            assertContentEquals(byteArrayOf(0x42), first, "first emitted chunk must be the non-empty one")
        }
    }

    @Test
    fun close_incoming_terminates_collector_immediately_when_buffer_is_empty() {
        runBlocking {
            val stream = QuicStream(streamId = 0L, direction = QuicStream.Direction.BIDIRECTIONAL)
            stream.closeIncoming()
            val collected = mutableListOf<ByteArray>()
            // collect must terminate, not hang. The withTimeoutOrNull guards
            // a regression that would, e.g., switch from `consumeAsFlow` to
            // a flow that never closes when the channel does.
            val finished =
                withTimeoutOrNull(2_000L) {
                    stream.incoming.collect { collected += it }
                    true
                }
            assertEquals(true, finished)
            assertEquals(0, collected.size)
        }
    }
}
