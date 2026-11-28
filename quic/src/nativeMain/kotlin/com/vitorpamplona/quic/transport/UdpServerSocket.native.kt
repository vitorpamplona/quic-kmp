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

import com.vitorpamplona.quic.transport.UdpSocket.Companion.RECEIVE_POLL_SLICE_MS
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import platform.posix.AF_INET6
import platform.posix.EAGAIN
import platform.posix.ECONNREFUSED
import platform.posix.EINTR
import platform.posix.EWOULDBLOCK
import platform.posix.IPPROTO_IP
import platform.posix.IPPROTO_IPV6
import platform.posix.IPPROTO_UDP
import platform.posix.IPV6_TCLASS
import platform.posix.IPV6_V6ONLY
import platform.posix.IP_TOS
import platform.posix.SOCK_DGRAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_RCVBUF
import platform.posix.SO_SNDBUF
import platform.posix.bind
import platform.posix.pipe
import platform.posix.recvfrom
import platform.posix.sendto
import platform.posix.sockaddr_storage
import platform.posix.socket
import platform.posix.socklen_tVar
import platform.posix.write
import kotlin.concurrent.AtomicInt
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.Cleaner
import kotlin.native.ref.createCleaner
import platform.posix.close as closeFd

/**
 * The server's one unconnected UDP socket on POSIX, as the JVM's: every connection of a server
 * shares it, IPv4 peers on a dual-stack wildcard bind are reported as plain IPv4, and a send to a
 * peer that is gone is a lost datagram. A receive waits in `poll` and ends at once on [close].
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
actual class UdpServerSocket private constructor(
    private val fd: Int,
    private val family: Int,
    private val wakeRead: Int,
    private val wakeWrite: Int,
) : QuicServerTransport {
    private val closed = AtomicInt(0)
    private val readBuf = ByteArray(2048)

    @Suppress("unused")
    private val pipeCleaner: Cleaner =
        createCleaner(intArrayOf(wakeRead, wakeWrite)) { fds -> fds.forEach { closeFd(it) } }

    private val isClosed get() = closed.value != 0

    actual val localPort: Int get() = PosixUdp.localPort(fd)

    actual override suspend fun receive(): ReceivedDatagram? {
        if (isClosed) return null
        return withContext(Dispatchers.IO) {
            while (!isClosed) {
                var err = 0
                val datagram =
                    memScoped {
                        val from = alloc<sockaddr_storage>()
                        val length = alloc<socklen_tVar>()
                        length.value = sizeOf<sockaddr_storage>().convert()
                        val read = readBuf.usePinned { recvfrom(fd, it.addressOf(0), readBuf.size.convert(), 0, from.ptr.reinterpret(), length.ptr) }
                        if (read >= 0) {
                            PosixUdp.peerOf(from.ptr.reinterpret())?.let { ReceivedDatagram(readBuf.copyOf(read.toInt()), it) }
                        } else {
                            err = PosixUdp.lastErrno()
                            null
                        }
                    }
                if (datagram != null) return@withContext datagram
                when (err) {
                    // Waits in slices, so a cancelled receive ends within one even with no datagram or close.
                    EAGAIN, EWOULDBLOCK ->
                        when (PosixUdp.await(fd, wakeRead, forWrite = false, timeoutMs = RECEIVE_POLL_SLICE_MS)) {
                            PosixUdp.Wait.WOKEN -> return@withContext null
                            PosixUdp.Wait.TIMED_OUT -> ensureActive()
                            PosixUdp.Wait.READY -> Unit
                        }
                    // 0: a datagram from a family this socket cannot name; skipped.
                    EINTR, ECONNREFUSED, 0 -> continue
                    else -> if (isClosed) return@withContext null else throw UdpSocketException("recvfrom failed: ${PosixUdp.errorText(err)}", err)
                }
            }
            null
        }
    }

    actual override suspend fun send(
        payload: ByteArray,
        to: UdpPeerAddress,
    ): Int {
        if (isClosed) throw UdpSocketException("Socket closed")
        return withContext(Dispatchers.IO) {
            if (isClosed) throw UdpSocketException("Socket closed")
            val sent =
                PosixUdp.withSockaddr(to, family) { address, length ->
                    payload.usePinned { sendto(fd, if (payload.isEmpty()) null else it.addressOf(0), payload.size.convert(), 0, address, length.convert()) }
                }
            // A full buffer, an unreachable peer, an oversized datagram: lost, as the network would lose it.
            if (sent < 0) 0 else sent.toInt()
        }
    }

    actual override fun close() {
        if (closed.compareAndSet(0, 1)) {
            byteArrayOf(1).usePinned { write(wakeWrite, it.addressOf(0), 1.convert()) }
            closeFd(fd)
        }
    }

    actual companion object {
        private const val ECT0_TOS_BITS: Int = 0x02
        private const val BUFFER_REQUEST: Int = 4 * 1024 * 1024

        actual suspend fun bind(
            host: String?,
            port: Int,
        ): UdpServerSocket =
            withContext(Dispatchers.IO) {
                // No host: the IPv6 wildcard, dual-stack, which takes IPv4 peers too.
                val local = PosixUdp.resolve(host ?: "::", port, passive = true)
                val fd = socket(local.family, SOCK_DGRAM, IPPROTO_UDP)
                if (fd < 0) throw UdpSocketException("socket failed: ${PosixUdp.errorText(PosixUdp.lastErrno())}", PosixUdp.lastErrno())
                try {
                    PosixUdp.setIntOption(fd, SOL_SOCKET, SO_RCVBUF, BUFFER_REQUEST)
                    PosixUdp.setIntOption(fd, SOL_SOCKET, SO_SNDBUF, BUFFER_REQUEST)
                    if (local.family == AF_INET6) {
                        if (host == null) PosixUdp.setIntOption(fd, IPPROTO_IPV6, IPV6_V6ONLY, 0)
                        PosixUdp.setIntOption(fd, IPPROTO_IPV6, IPV6_TCLASS, ECT0_TOS_BITS)
                    } else {
                        PosixUdp.setIntOption(fd, IPPROTO_IP, IP_TOS, ECT0_TOS_BITS)
                    }
                    val rc = PosixUdp.withSockaddr(local.bytes) { address, length -> bind(fd, address, length.convert()) }
                    if (rc != 0) throw UdpSocketException("bind to ${host ?: "*"}:$port failed: ${PosixUdp.errorText(PosixUdp.lastErrno())}", PosixUdp.lastErrno())
                    PosixUdp.setNonBlocking(fd)
                    val wake = IntArray(2)
                    if (wake.usePinned { pipe(it.addressOf(0)) } != 0) throw UdpSocketException("pipe failed", PosixUdp.lastErrno())
                    PosixUdp.setNonBlocking(wake[0])
                    UdpServerSocket(fd, local.family, wake[0], wake[1])
                } catch (e: Throwable) {
                    closeFd(fd)
                    throw e
                }
            }
    }
}
