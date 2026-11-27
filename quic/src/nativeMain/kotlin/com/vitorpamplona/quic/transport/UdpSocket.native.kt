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

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import platform.posix.AF_INET6
import platform.posix.EAGAIN
import platform.posix.ECONNREFUSED
import platform.posix.EINTR
import platform.posix.EMSGSIZE
import platform.posix.EWOULDBLOCK
import platform.posix.IPPROTO_IP
import platform.posix.IPPROTO_IPV6
import platform.posix.IPPROTO_UDP
import platform.posix.IPV6_TCLASS
import platform.posix.IP_TOS
import platform.posix.SOCK_DGRAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_RCVBUF
import platform.posix.connect
import platform.posix.pipe
import platform.posix.recv
import platform.posix.send
import platform.posix.socket
import platform.posix.write
import kotlin.concurrent.AtomicInt
import kotlin.concurrent.AtomicLong
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.Cleaner
import kotlin.native.ref.createCleaner
import platform.posix.close as closeFd

/**
 * A connected UDP socket on POSIX (iOS, and Linux for the tests), the counterpart of the JVM's
 * DatagramChannel one: bound to an ephemeral port, connected to one peer so the kernel drops
 * datagrams from anyone else, a 4 MiB receive buffer, and outgoing datagrams marked ECT(0).
 *
 * The socket is non-blocking. [receive] waits in `poll` on [Dispatchers.IO] for the socket or for
 * [close]'s wake-up byte on a pipe, so a close always ends a parked receive at once. An ICMP port
 * unreachable (ECONNREFUSED on a connected socket) ends nothing, as on the JVM: anyone on the path
 * can forge one, so it is a lost datagram, and the idle timeout or the peer's CONNECTION_CLOSE
 * decides (RFC 9000 §10).
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
actual class UdpSocket private constructor(
    private val fd: Int,
    private val ipv6: Boolean,
    private val wakeRead: Int,
    private val wakeWrite: Int,
) : QuicDatagramSocket {
    private val closed = AtomicInt(0)
    private val receivedDatagrams = AtomicLong(0L)
    private val receivedBytes = AtomicLong(0L)

    // Only the receive loop touches it, by contract, as on the JVM.
    private val readBuf = ByteArray(RECEIVE_BUFFER_BYTES)

    // The pipe outlives close() while a receive may still be polling it; it goes with the object.
    @Suppress("unused")
    private val pipeCleaner: Cleaner =
        createCleaner(intArrayOf(wakeRead, wakeWrite)) { fds -> fds.forEach { closeFd(it) } }

    actual val localPort: Int get() = PosixUdp.localPort(fd)

    actual override val receivedDatagramCount: Long get() = receivedDatagrams.value

    actual override val receivedByteCount: Long get() = receivedBytes.value

    actual override val receiveBufferSizeBytes: Int get() = PosixUdp.intOption(fd, SO_RCVBUF)

    actual override val remoteIsIpv6: Boolean get() = ipv6

    private val isClosed get() = closed.value != 0

    actual override suspend fun send(payload: ByteArray): Int {
        if (isClosed) throw UdpSocketException("Socket closed")
        return withContext(Dispatchers.IO) {
            while (true) {
                if (isClosed) throw UdpSocketException("Socket closed")
                val sent =
                    if (payload.isEmpty()) {
                        send(fd, null, 0.convert(), 0)
                    } else {
                        payload.usePinned { send(fd, it.addressOf(0), payload.size.convert(), 0) }
                    }
                if (sent >= 0) return@withContext sent.toInt()
                when (val err = PosixUdp.lastErrno()) {
                    EINTR -> continue
                    // A full send buffer: wait (briefly) until the kernel takes more.
                    EAGAIN, EWOULDBLOCK -> PosixUdp.await(fd, wakeRead, forWrite = true, timeoutMs = SEND_WAIT_MS)
                    // An earlier ICMP port unreachable, reported on this call: a lost datagram.
                    ECONNREFUSED -> return@withContext 0
                    // Larger than the path MTU the kernel knows: dropped, as the network would.
                    EMSGSIZE -> return@withContext 0
                    else -> throw UdpSocketException("send failed: ${PosixUdp.errorText(err)}", err)
                }
            }
            @Suppress("UNREACHABLE_CODE")
            0
        }
    }

    actual override suspend fun receive(): ByteArray? {
        if (isClosed) return null
        return withContext(Dispatchers.IO) {
            while (!isClosed) {
                val read = readBuf.usePinned { recv(fd, it.addressOf(0), readBuf.size.convert(), 0) }
                if (read >= 0) {
                    val out = readBuf.copyOf(read.toInt())
                    receivedDatagrams.incrementAndGet()
                    receivedBytes.addAndGet(out.size.toLong())
                    return@withContext out
                }
                when (val err = PosixUdp.lastErrno()) {
                    // Waits in slices, so a cancelled receive ends within one even with no datagram or close.
                    EAGAIN, EWOULDBLOCK ->
                        when (PosixUdp.await(fd, wakeRead, forWrite = false, timeoutMs = RECEIVE_POLL_SLICE_MS)) {
                            PosixUdp.Wait.WOKEN -> return@withContext null
                            PosixUdp.Wait.TIMED_OUT -> ensureActive()
                            PosixUdp.Wait.READY -> Unit
                        }
                    EINTR, ECONNREFUSED -> continue
                    else -> if (isClosed) return@withContext null else throw UdpSocketException("recv failed: ${PosixUdp.errorText(err)}", err)
                }
            }
            null
        }
    }

    actual override fun close() {
        if (closed.compareAndSet(0, 1)) {
            // Wakes a receive parked in poll, then lets the socket go.
            byteArrayOf(1).usePinned { write(wakeWrite, it.addressOf(0), 1.convert()) }
            closeFd(fd)
        }
    }

    actual companion object {
        /** ECT(0), RFC 3168 §5: the low two bits of the TOS / Traffic Class byte set to `10`. */
        private const val ECT0_TOS_BITS: Int = 0x02

        /** 4 MiB: room for a relay's burst of MoQ groups after the handshake, as on the JVM. */
        private const val RECEIVE_BUFFER_REQUEST: Int = 4 * 1024 * 1024

        /** Above the ~1500-byte datagrams QUIC sends; larger ones are malformed anyway. */
        private const val RECEIVE_BUFFER_BYTES: Int = 2048

        private const val SEND_WAIT_MS: Int = 50

        /** How long one poll of a receive waits before checking for cancellation. */
        internal const val RECEIVE_POLL_SLICE_MS: Int = 100

        actual suspend fun connect(
            host: String,
            port: Int,
        ): UdpSocket =
            withContext(Dispatchers.IO) {
                val remote = PosixUdp.resolve(host, port)
                val fd = socket(remote.family, SOCK_DGRAM, IPPROTO_UDP)
                if (fd < 0) throw UdpSocketException("socket failed: ${PosixUdp.errorText(PosixUdp.lastErrno())}", PosixUdp.lastErrno())
                try {
                    PosixUdp.setIntOption(fd, SOL_SOCKET, SO_RCVBUF, RECEIVE_BUFFER_REQUEST)
                    val ipv6 = remote.family == AF_INET6
                    // Best effort: without it the connection is simply not ECN-capable, which is also spec-compliant.
                    if (ipv6) {
                        PosixUdp.setIntOption(fd, IPPROTO_IPV6, IPV6_TCLASS, ECT0_TOS_BITS)
                    } else {
                        PosixUdp.setIntOption(fd, IPPROTO_IP, IP_TOS, ECT0_TOS_BITS)
                    }
                    // connect() makes the kernel drop datagrams from anyone but the peer, before
                    // they cost an AEAD open (RFC 9000 §9 hardening), and picks the ephemeral port.
                    val rc = PosixUdp.withSockaddr(remote.bytes) { address, length -> connect(fd, address, length.convert()) }
                    if (rc != 0) throw UdpSocketException("Failed to connect to $host: ${PosixUdp.errorText(PosixUdp.lastErrno())}", PosixUdp.lastErrno())
                    PosixUdp.setNonBlocking(fd)
                    val wake = IntArray(2)
                    val piped = wake.usePinned { pipe(it.addressOf(0)) }
                    if (piped != 0) throw UdpSocketException("pipe failed: ${PosixUdp.errorText(PosixUdp.lastErrno())}", PosixUdp.lastErrno())
                    PosixUdp.setNonBlocking(wake[0])
                    UdpSocket(fd, ipv6, wake[0], wake[1])
                } catch (e: Throwable) {
                    closeFd(fd)
                    throw e
                }
            }
    }
}
