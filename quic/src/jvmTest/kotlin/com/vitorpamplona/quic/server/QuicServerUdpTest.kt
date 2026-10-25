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
package com.vitorpamplona.quic.server

import com.vitorpamplona.quic.connection.QuicConnection
import com.vitorpamplona.quic.connection.QuicConnectionConfig
import com.vitorpamplona.quic.connection.QuicConnectionDriver
import com.vitorpamplona.quic.tls.JcaCertificateSigner
import com.vitorpamplona.quic.tls.PinnedCertificateValidator
import com.vitorpamplona.quic.tls.TestCertificates
import com.vitorpamplona.quic.tls.TlsConstants
import com.vitorpamplona.quic.transport.UdpServerSocket
import com.vitorpamplona.quic.transport.UdpSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull

/** [QuicServer] on a real [UdpServerSocket], with a client on a real [UdpSocket], over loopback. */
class QuicServerUdpTest {
    private val signer = JcaCertificateSigner.fromPem(TestCertificates.EC_CERT_PEM, TestCertificates.EC_KEY_PEM)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @AfterTest
    fun tearDown() = scope.cancel()

    @Test
    fun `a client downloads a megabyte over loopback UDP`() =
        runBlocking<Unit> {
            val socket = UdpServerSocket.bind("127.0.0.1", 0)
            val server =
                QuicServer(
                    QuicServerConfig(
                        signer = signer,
                        alpnSelector = { offered -> offered.firstOrNull { it.contentEquals(TlsConstants.ALPN_H3) } },
                    ),
                    socket,
                    scope,
                )
            server.start()
            val body = ByteArray(1 shl 20) { (it * 31).toByte() }
            scope.launch {
                val accepted = server.accept() ?: return@launch
                val stream = accepted.connection.awaitIncomingPeerStream() ?: return@launch
                stream.incoming.toList()
                stream.send.enqueue(body)
                stream.send.finish()
                accepted.driver.wakeup()
            }
            val conn =
                QuicConnection(
                    serverName = "quic.test",
                    config = QuicConnectionConfig(),
                    tlsCertificateValidator = PinnedCertificateValidator.ofDer(signer.certificateChain.first()),
                )
            val driver = QuicConnectionDriver(conn, UdpSocket.connect("127.0.0.1", socket.localPort), scope)
            driver.start()
            withTimeout(10_000) { conn.awaitHandshakeConfirmed() }
            val request = conn.openBidiStream()
            request.send.enqueue("GET /\r\n".encodeToByteArray())
            request.send.finish()
            driver.wakeup()
            val got = withTimeout(20_000) { request.incoming.toList() }.fold(ByteArray(0)) { a, b -> a + b }
            assertContentEquals(body, got)
            assertNotNull(conn.peerTransportParameters)
            driver.close()
            // Teardown is asynchronous; let it close the socket before the scope goes.
            driver.closeTeardownJob?.join()
            server.close()
        }
}
