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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A FIN sent on its own, after the data went out: a writer that calls
 * `finish()` after its last `enqueue` drained. Its zero-length range was
 * never matched by an ACK or a loss, so the stream never settled and every
 * PTO resent the FIN.
 */
class SendBufferFinOnlyTest {
    private fun dataThenFinOnly(bestEffort: Boolean = false): SendBuffer {
        val buf = SendBuffer(bestEffort = bestEffort)
        buf.enqueue(ByteArray(4) { it.toByte() })
        assertEquals(4, assertNotNull(buf.takeChunk(100)).data.size)
        buf.markAcked(0L, 4L)
        buf.finish()
        val fin = assertNotNull(buf.takeChunk(100))
        assertTrue(fin.fin && fin.data.isEmpty() && fin.offset == 4L, "a FIN-only chunk at offset 4")
        return buf
    }

    @Test
    fun `an ACK of a FIN-only chunk settles the stream`() {
        val buf = dataThenFinOnly()
        buf.markAcked(4L, 0L)
        assertTrue(buf.finAcked)
        assertTrue(buf.fullyAcked)
        buf.requeueAllInflight()
        assertNull(buf.takeChunk(100), "nothing left to resend")
    }

    @Test
    fun `a lost FIN-only chunk is resent once and its ACK settles the stream`() {
        val buf = dataThenFinOnly()
        buf.markLost(4L, 0L, fin = true)
        val again = assertNotNull(buf.takeChunk(100))
        assertTrue(again.fin && again.offset == 4L)
        assertNull(buf.takeChunk(100), "one FIN, not two")
        buf.markAcked(4L, 0L)
        assertTrue(buf.fullyAcked)
    }

    @Test
    fun `a best-effort stream whose FIN is lost still settles`() {
        // The moq-lite group streams: a lost FIN is not resent, and the stream must not stay tracked forever.
        val buf = dataThenFinOnly(bestEffort = true)
        buf.markLost(4L, 0L, fin = true)
        assertNull(buf.takeChunk(100))
        assertTrue(buf.fullyAcked, "nothing more will be sent")

        val viaPto = dataThenFinOnly(bestEffort = true)
        viaPto.requeueAllInflight()
        assertTrue(viaPto.fullyAcked)
        assertFalse(viaPto.hasRetransmit)
    }
}
