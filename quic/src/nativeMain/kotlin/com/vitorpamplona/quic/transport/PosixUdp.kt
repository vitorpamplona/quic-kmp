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

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.allocPointerTo
import kotlinx.cinterop.convert
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.AF_UNSPEC
import platform.posix.AI_PASSIVE
import platform.posix.F_GETFL
import platform.posix.F_SETFL
import platform.posix.O_NONBLOCK
import platform.posix.POLLIN
import platform.posix.POLLOUT
import platform.posix.SOCK_DGRAM
import platform.posix.SOL_SOCKET
import platform.posix.addrinfo
import platform.posix.errno
import platform.posix.fcntl
import platform.posix.freeaddrinfo
import platform.posix.gai_strerror
import platform.posix.getaddrinfo
import platform.posix.getsockname
import platform.posix.getsockopt
import platform.posix.memset
import platform.posix.poll
import platform.posix.pollfd
import platform.posix.setsockopt
import platform.posix.sockaddr
import platform.posix.sockaddr_in
import platform.posix.sockaddr_in6
import platform.posix.sockaddr_storage
import platform.posix.socklen_tVar
import platform.posix.strerror

/** A socket call failed. [errno] is the POSIX error number, 0 when the failure was not a syscall's. */
class UdpSocketException(
    message: String,
    val errno: Int = 0,
) : Exception(message)

/** A resolved socket address: its family and the raw `sockaddr` bytes to hand back to the kernel. */
internal class SocketAddressBytes(
    val family: Int,
    val bytes: ByteArray,
)

/**
 * The POSIX socket calls the QUIC sockets share, written once for Linux and Darwin: the two lay
 * out `sockaddr` differently (BSD's has a length byte), so every address is read and written
 * through the struct fields, never by offset, and every width goes through [convert].
 */
@OptIn(ExperimentalForeignApi::class)
internal object PosixUdp {
    fun lastErrno(): Int = errno

    fun errorText(code: Int): String = strerror(code)?.toKString() ?: "errno $code"

    /** The first address [host]:[port] resolves to for UDP; [passive] for a server's wildcard bind. */
    fun resolve(
        host: String?,
        port: Int,
        passive: Boolean = false,
    ): SocketAddressBytes =
        memScoped {
            val hints = alloc<addrinfo>()
            memset(hints.ptr, 0, sizeOf<addrinfo>().convert())
            hints.ai_family = AF_UNSPEC
            hints.ai_socktype = SOCK_DGRAM
            if (passive) hints.ai_flags = AI_PASSIVE
            val result = allocPointerTo<addrinfo>()
            val rc = getaddrinfo(host, port.toString(), hints.ptr, result.ptr)
            if (rc != 0) throw UdpSocketException("Unable to resolve host \"$host\": ${gai_strerror(rc)?.toKString()}")
            try {
                val info = result.value?.pointed ?: throw UdpSocketException("No address for \"$host\"")
                val address = info.ai_addr ?: throw UdpSocketException("No address for \"$host\"")
                SocketAddressBytes(info.ai_family, address.reinterpret<ByteVar>().readBytes(info.ai_addrlen.convert()))
            } finally {
                freeaddrinfo(result.value)
            }
        }

    fun setNonBlocking(fd: Int) {
        val flags = fcntl(fd, F_GETFL, 0)
        if (flags < 0 || fcntl(fd, F_SETFL, flags or O_NONBLOCK) < 0) throw UdpSocketException("fcntl(O_NONBLOCK) failed: ${errorText(errno)}", errno)
    }

    /** Sets an int socket option, ignoring a refusal (they are all best effort here). */
    fun setIntOption(
        fd: Int,
        level: Int,
        option: Int,
        value: Int,
    ): Boolean =
        memScoped {
            val v = alloc<IntVar>()
            v.value = value
            setsockopt(fd, level, option, v.ptr, sizeOf<IntVar>().convert()) == 0
        }

    fun intOption(
        fd: Int,
        option: Int,
    ): Int =
        memScoped {
            val v = alloc<IntVar>()
            val len = alloc<socklen_tVar>()
            len.value = sizeOf<IntVar>().convert()
            if (getsockopt(fd, SOL_SOCKET, option, v.ptr, len.ptr) == 0) v.value else 0
        }

    /** The port the kernel bound [fd] to. */
    fun localPort(fd: Int): Int =
        memScoped {
            val storage = alloc<sockaddr_storage>()
            val len = alloc<socklen_tVar>()
            len.value = sizeOf<sockaddr_storage>().convert()
            if (getsockname(fd, storage.ptr.reinterpret(), len.ptr) != 0) return@memScoped 0
            peerOf(storage.ptr.reinterpret())?.port ?: 0
        }

    /** What [await] saw: the socket ready, the wake-up byte of a close, or neither before the timeout. */
    enum class Wait { READY, WOKEN, TIMED_OUT }

    /**
     * Waits until [fd] is readable ([forWrite] false) or writable, or [wakeFd] is readable, for at
     * most [timeoutMs] (-1 waits forever).
     */
    fun await(
        fd: Int,
        wakeFd: Int,
        forWrite: Boolean,
        timeoutMs: Int,
    ): Wait =
        memScoped {
            val fds = allocArray<pollfd>(2)
            fds[0].fd = fd
            fds[0].events = (if (forWrite) POLLOUT else POLLIN).convert()
            fds[0].revents = 0
            fds[1].fd = wakeFd
            fds[1].events = POLLIN.convert()
            fds[1].revents = 0
            val ready = poll(fds, 2.convert(), timeoutMs)
            when {
                fds[1].revents.toInt() != 0 -> Wait.WOKEN
                ready == 0 -> Wait.TIMED_OUT
                else -> Wait.READY
            }
        }

    /** The address in [address] (an AF_INET or AF_INET6 sockaddr), an IPv4-mapped IPv6 one read as IPv4. */
    fun peerOf(address: CPointer<sockaddr>): UdpPeerAddress? =
        when (address.pointed.sa_family.toInt()) {
            AF_INET -> {
                val v4 = address.reinterpret<sockaddr_in>().pointed
                val ip =
                    v4.sin_addr.ptr
                        .reinterpret<ByteVar>()
                        .readBytes(4)
                UdpPeerAddress(ip, fromNetworkOrder(v4.sin_port.toInt()))
            }
            AF_INET6 -> {
                val v6 = address.reinterpret<sockaddr_in6>().pointed
                val ip =
                    v6.sin6_addr.ptr
                        .reinterpret<ByteVar>()
                        .readBytes(16)
                val port = fromNetworkOrder(v6.sin6_port.toInt())
                if (isV4Mapped(ip)) UdpPeerAddress(ip.copyOfRange(12, 16), port) else UdpPeerAddress(ip, port)
            }
            else -> null
        }

    /**
     * Writes [peer] as a sockaddr of [family] (the socket's own: a dual-stack IPv6 socket reaches an
     * IPv4 peer at its mapped address) and runs [block] with it and its length.
     */
    fun <T> withSockaddr(
        peer: UdpPeerAddress,
        family: Int,
        block: (CPointer<sockaddr>, Int) -> T,
    ): T =
        memScoped {
            if (family == AF_INET6) {
                val v6 = alloc<sockaddr_in6>()
                memset(v6.ptr, 0, sizeOf<sockaddr_in6>().convert())
                v6.sin6_family = AF_INET6.convert()
                v6.sin6_port = toNetworkOrder(peer.port).convert()
                val ip = if (peer.isIpv6) peer.ip else V4_MAPPED_PREFIX + peer.ip
                val dst = v6.sin6_addr.ptr.reinterpret<ByteVar>()
                for (i in 0 until 16) dst[i] = ip[i]
                block(v6.ptr.reinterpret(), sizeOf<sockaddr_in6>().toInt())
            } else {
                require(!peer.isIpv6) { "An IPv4 socket cannot reach $peer" }
                val v4 = alloc<sockaddr_in>()
                memset(v4.ptr, 0, sizeOf<sockaddr_in>().convert())
                v4.sin_family = AF_INET.convert()
                v4.sin_port = toNetworkOrder(peer.port).convert()
                val dst = v4.sin_addr.ptr.reinterpret<ByteVar>()
                for (i in 0 until 4) dst[i] = peer.ip[i]
                block(v4.ptr.reinterpret(), sizeOf<sockaddr_in>().toInt())
            }
        }

    /** [bytes] (from [resolve]) as a sockaddr for [block]. */
    fun <T> withSockaddr(
        bytes: ByteArray,
        block: (CPointer<sockaddr>, Int) -> T,
    ): T = bytes.usePinned { block(it.addressOf(0).reinterpret(), bytes.size) }

    private val V4_MAPPED_PREFIX = ByteArray(10) + byteArrayOf(-1, -1)

    private fun isV4Mapped(ip: ByteArray): Boolean {
        for (i in 0 until 10) if (ip[i] != 0.toByte()) return false
        return ip[10] == (-1).toByte() && ip[11] == (-1).toByte()
    }

    // Both targets (arm64, x86_64) are little-endian; the port goes out big-endian.
    fun toNetworkOrder(port: Int): Int = ((port and 0xFF) shl 8) or ((port shr 8) and 0xFF)

    fun fromNetworkOrder(raw: Int): Int = ((raw and 0xFF) shl 8) or ((raw shr 8) and 0xFF)
}
