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

import com.vitorpamplona.quic.frame.ConnectionCloseFrame
import com.vitorpamplona.quic.frame.MaxStreamsFrame
import com.vitorpamplona.quic.frame.QuicTransportError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * RFC 9000 §10.2: an error the client detects ends the connection with a
 * CONNECTION_CLOSE carrying the error code, not by going silent.
 */
class LocalErrorCloseTest {
    @Test
    fun protocol_error_leaves_a_transport_close_to_send() {
        val (client, pipe) = newConnectedClient()
        val hostile = pipe.buildServerApplicationDatagram(listOf(MaxStreamsFrame(bidi = true, maxStreams = (1L shl 60) + 1)))!!
        feedDatagram(client, hostile, 0L)
        assertEquals(QuicConnection.Status.CLOSED, client.status)
        assertEquals(QuicTransportError.STREAM_LIMIT_ERROR, client.closeErrorCode)
        val datagram = client.takeFinalCloseDatagram()
        assertNotNull(datagram)
        val close = pipe.decryptClientApplicationFrames(datagram)!!.filterIsInstance<ConnectionCloseFrame>().single()
        assertEquals(QuicTransportError.STREAM_LIMIT_ERROR, close.errorCode)
        assertNotNull(close.frameType, "a transport error uses the 0x1c form")
        assertNull(client.takeFinalCloseDatagram(), "sent once")
        assertNull(drainOutbound(client, 0L), "nothing else after CLOSED")
    }

    @Test
    fun silent_closes_send_nothing() {
        val (client, _) = newConnectedClient()
        client.markClosedExternally("idle timeout")
        assertNull(client.takeFinalCloseDatagram())
    }
}
