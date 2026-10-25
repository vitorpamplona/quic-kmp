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
package com.vitorpamplona.quic.transport

/**
 * One peer's datagram path, as the connection driver sees it: a [UdpSocket]
 * connected to a server, or a server endpoint's view of one client.
 */
interface QuicDatagramSocket {
    /** Send one datagram to the peer. Returns the number of bytes written. */
    suspend fun send(payload: ByteArray): Int

    /** The next datagram from the peer; null once closed. */
    suspend fun receive(): ByteArray?

    /** Close the path. After close, [receive] returns null and [send] throws. */
    fun close()

    /** Lifetime count of datagrams [receive] returned. Diagnostic-only. */
    val receivedDatagramCount: Long

    /** Sum of payload bytes [receive] returned. */
    val receivedByteCount: Long

    /** The kernel's receive buffer size, when there is one socket per path; 0 otherwise. */
    val receiveBufferSizeBytes: Int

    /** True when the peer address is IPv6. */
    val remoteIsIpv6: Boolean
}
