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

/** A UDP peer: its IP address as raw bytes (4 for IPv4, 16 for IPv6) and port. */
class UdpPeerAddress(
    val ip: ByteArray,
    val port: Int,
) {
    init {
        require(ip.size == 4 || ip.size == 16) { "IP address must be 4 or 16 bytes, was ${ip.size}" }
    }

    val isIpv6: Boolean get() = ip.size == 16

    override fun equals(other: Any?): Boolean = other is UdpPeerAddress && port == other.port && ip.contentEquals(other.ip)

    override fun hashCode(): Int = 31 * ip.contentHashCode() + port

    override fun toString(): String =
        if (ip.size == 4) {
            ip.joinToString(".") { (it.toInt() and 0xFF).toString() } + ":$port"
        } else {
            "[" + (0 until 8).joinToString(":") { i -> (((ip[2 * i].toInt() and 0xFF) shl 8) or (ip[2 * i + 1].toInt() and 0xFF)).toString(16) } + "]:$port"
        }
}

/** One datagram a server received, and who sent it. */
class ReceivedDatagram(
    val payload: ByteArray,
    val from: UdpPeerAddress,
)

/** What a [com.vitorpamplona.quic.server.QuicServer] listens and answers on: one unconnected socket, or a test double. */
interface QuicServerTransport {
    /** The next datagram from any peer; null once closed. */
    suspend fun receive(): ReceivedDatagram?

    /** Send one datagram to [to]. Returns the number of bytes written. */
    suspend fun send(
        payload: ByteArray,
        to: UdpPeerAddress,
    ): Int

    fun close()
}

/** An unconnected UDP socket bound to a local port, for a QUIC server. */
expect class UdpServerSocket : QuicServerTransport {
    override suspend fun receive(): ReceivedDatagram?

    override suspend fun send(
        payload: ByteArray,
        to: UdpPeerAddress,
    ): Int

    override fun close()

    /** The port the socket is bound to. */
    val localPort: Int

    companion object {
        /**
         * Bind to [host]:[port]; a null [host] binds every local address, and
         * port 0 picks a free one. Throws on bind failure.
         */
        suspend fun bind(
            host: String?,
            port: Int,
        ): UdpServerSocket
    }
}
