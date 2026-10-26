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

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardSocketOptions
import java.nio.ByteBuffer
import java.nio.channels.ClosedChannelException
import java.nio.channels.DatagramChannel
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * JVM/Android server socket: one blocking, unconnected [DatagramChannel],
 * with a dedicated receive thread and a dedicated send thread for the same
 * reasons [UdpSocket] has them. Every connection of a server shares it.
 */
actual class UdpServerSocket private constructor(
    private val channel: DatagramChannel,
) : QuicServerTransport {
    private val closed = AtomicBoolean(false)
    private val recvExecutor = Executors.newSingleThreadExecutor { r -> Thread(r, "quic-server-recv").apply { isDaemon = true } }
    private val sendExecutor = Executors.newSingleThreadExecutor { r -> Thread(r, "quic-server-send").apply { isDaemon = true } }
    private val recvDispatcher: ExecutorCoroutineDispatcher = recvExecutor.asCoroutineDispatcher()
    private val sendDispatcher: ExecutorCoroutineDispatcher = sendExecutor.asCoroutineDispatcher()
    private val readBuf = ByteBuffer.allocate(2048)

    actual val localPort: Int
        get() = (channel.localAddress as InetSocketAddress).port

    actual override suspend fun receive(): ReceivedDatagram? {
        if (closed.get()) return null
        return withContext(recvDispatcher) {
            while (!closed.get()) {
                try {
                    readBuf.clear()
                    val from = channel.receive(readBuf) as? InetSocketAddress ?: return@withContext null
                    readBuf.flip()
                    val out = ByteArray(readBuf.remaining())
                    readBuf.get(out)
                    return@withContext ReceivedDatagram(out, peerOf(from))
                } catch (_: ClosedChannelException) {
                    return@withContext null
                } catch (_: java.net.PortUnreachableException) {
                    // An ICMP error from an earlier send; keep listening.
                }
            }
            null
        }
    }

    actual override suspend fun send(
        payload: ByteArray,
        to: UdpPeerAddress,
    ): Int {
        if (closed.get()) throw ClosedChannelException()
        return withContext(sendDispatcher) {
            if (closed.get()) throw ClosedChannelException()
            try {
                channel.send(ByteBuffer.wrap(payload), InetSocketAddress(InetAddress.getByAddress(to.ip), to.port))
            } catch (e: java.io.IOException) {
                // EMSGSIZE (a PMTU probe past the path MTU) or an unreachable
                // peer: drop it like the network would.
                if (e is ClosedChannelException) throw e
                0
            }
        }
    }

    actual override fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { channel.close() }
            recvExecutor.shutdownNow()
            sendExecutor.shutdownNow()
        }
    }

    actual companion object {
        private const val ECT0_TOS_BITS: Int = 0x02

        /** IPv4-mapped IPv6 addresses (a dual-stack socket's view of IPv4 peers) as plain IPv4. */
        private fun peerOf(address: InetSocketAddress): UdpPeerAddress {
            val raw = address.address.address
            val v4Mapped =
                raw.size == 16 && (0 until 10).all { raw[it] == 0.toByte() } && raw[10] == 0xFF.toByte() && raw[11] == 0xFF.toByte()
            return UdpPeerAddress(if (v4Mapped) raw.copyOfRange(12, 16) else raw, address.port)
        }

        actual suspend fun bind(
            host: String?,
            port: Int,
        ): UdpServerSocket =
            withContext(Dispatchers.IO) {
                val channel = DatagramChannel.open()
                channel.configureBlocking(true)
                runCatching { channel.setOption(StandardSocketOptions.SO_RCVBUF, 4 * 1024 * 1024) }
                runCatching { channel.setOption(StandardSocketOptions.SO_SNDBUF, 4 * 1024 * 1024) }
                runCatching { channel.setOption(StandardSocketOptions.IP_TOS, ECT0_TOS_BITS) }
                runCatching {
                    val option =
                        Class
                            .forName("jdk.net.ExtendedSocketOptions")
                            .getField("IP_DONTFRAGMENT")
                            .get(null)
                    @Suppress("UNCHECKED_CAST")
                    channel.setOption(option as java.net.SocketOption<Boolean>, true)
                }
                channel.bind(if (host == null) InetSocketAddress(port) else InetSocketAddress(InetAddress.getByName(host), port))
                UdpServerSocket(channel)
            }
    }
}
