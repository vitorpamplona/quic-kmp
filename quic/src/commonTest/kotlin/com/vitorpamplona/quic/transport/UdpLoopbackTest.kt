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

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The client and server UDP sockets against each other over loopback, on every target: the JVM's
 * DatagramChannel ones and the POSIX ones iOS runs (checked here on Linux).
 */
class UdpLoopbackTest {
    @Test
    fun `a datagram goes out and its answer comes back`() =
        runBlocking {
            val server = UdpServerSocket.bind("127.0.0.1", 0)
            val client = UdpSocket.connect("127.0.0.1", server.localPort)
            try {
                assertTrue(client.localPort > 0, "the client is bound to an ephemeral port")
                assertTrue(!client.remoteIsIpv6)

                val hello = ByteArray(1200) { it.toByte() }
                assertEquals(hello.size, client.send(hello))

                val received = withTimeout(5_000) { server.receive() }!!
                assertContentEquals(hello, received.payload)
                assertEquals(client.localPort, received.from.port)
                assertContentEquals(byteArrayOf(127, 0, 0, 1), received.from.ip)

                val answer = "pong".encodeToByteArray()
                server.send(answer, received.from)
                assertContentEquals(answer, withTimeout(5_000) { client.receive() })
                assertEquals(1L, client.receivedDatagramCount)
                assertEquals(answer.size.toLong(), client.receivedByteCount)
            } finally {
                client.close()
                server.close()
            }
        }

    @Test
    fun `close ends a parked receive`() =
        runBlocking {
            val server = UdpServerSocket.bind("127.0.0.1", 0)
            val client = UdpSocket.connect("127.0.0.1", server.localPort)
            val clientRead = async { client.receive() }
            val serverRead = async { server.receive() }
            delay(200)
            client.close()
            server.close()
            assertNull(withTimeout(5_000) { clientRead.await() })
            assertNull(withTimeout(5_000) { serverRead.await() })
        }

    @Test
    fun `after close receive returns null and send fails`() =
        runBlocking {
            val server = UdpServerSocket.bind("127.0.0.1", 0)
            val client = UdpSocket.connect("127.0.0.1", server.localPort)
            server.close()
            client.close()
            assertNull(client.receive())
            assertFails { client.send(byteArrayOf(1)) }
            Unit
        }

    @Test
    fun `an unreachable port ends neither send nor receive`() =
        runBlocking {
            // A port nobody listens on: the kernel answers with ICMP port unreachable.
            val gone = UdpServerSocket.bind("127.0.0.1", 0)
            val port = gone.localPort
            gone.close()
            val client = UdpSocket.connect("127.0.0.1", port)
            val read = async { client.receive() }
            try {
                repeat(3) {
                    client.send(byteArrayOf(1, 2, 3))
                    delay(50)
                }
                // Still open: the receive waits rather than ending, as for a lost datagram.
                delay(300)
                assertTrue(read.isActive, "an ICMP error must not end the receive")
                assertEquals(0L, client.receivedDatagramCount)
            } finally {
                // A close, not a cancel, ends a parked receive on every target.
                client.close()
            }
            assertNull(withTimeout(5_000) { read.await() })
        }
}
