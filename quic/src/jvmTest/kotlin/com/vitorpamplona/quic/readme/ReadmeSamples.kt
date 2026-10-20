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
package com.vitorpamplona.quic.readme

// The code samples in README.md, compiled with the tests so an API change that would break the
// README breaks the build instead. Nothing here runs; keep it in sync when editing the README.

import com.vitorpamplona.quic.connection.QuicConnection
import com.vitorpamplona.quic.connection.QuicConnectionConfig
import com.vitorpamplona.quic.connection.QuicConnectionDriver
import com.vitorpamplona.quic.http3.Http3Frame
import com.vitorpamplona.quic.http3.Http3FrameReader
import com.vitorpamplona.quic.http3.Http3StreamType
import com.vitorpamplona.quic.http3.buildClientWebTransportSettings
import com.vitorpamplona.quic.qpack.QpackDecoder
import com.vitorpamplona.quic.tls.JdkCertificateValidator
import com.vitorpamplona.quic.tls.PinnedCertificateValidator
import com.vitorpamplona.quic.tls.TlsResumptionState
import com.vitorpamplona.quic.transport.UdpSocket
import com.vitorpamplona.quic.webtransport.QuicWebTransportSessionState
import com.vitorpamplona.quic.webtransport.buildExtendedConnectHeaders
import com.vitorpamplona.quic.webtransport.encodeHeadersFrame
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.transform
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout

suspend fun quickStart() {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    val socket = UdpSocket.connect("example.com", 443)
    val connection =
        QuicConnection(
            serverName = "example.com",
            config = QuicConnectionConfig(),
            tlsCertificateValidator = JdkCertificateValidator(),
            alpnList = listOf("my-protocol".encodeToByteArray()),
        )
    val driver = QuicConnectionDriver(connection, socket, scope)
    driver.start()

    try {
        withTimeout(10_000) { connection.awaitHandshake() }
        check(connection.status == QuicConnection.Status.CONNECTED)

        val stream = connection.openBidiStream()
        stream.send.enqueue("hello".encodeToByteArray())
        stream.send.finish()
        driver.wakeup()

        stream.incoming.collect { chunk -> println(chunk.decodeToString()) }
    } finally {
        driver.close()
    }
}

suspend fun peerStreamsAndDatagrams(
    connection: QuicConnection,
    driver: QuicConnectionDriver,
    scope: CoroutineScope,
) {
    scope.launch {
        while (true) {
            val stream = connection.awaitIncomingPeerStream() ?: break
            launch { stream.incoming.collect { chunk -> println(chunk.size) } }
        }
    }

    connection.queueDatagram(byteArrayOf(1, 2, 3))
    driver.wakeup()
    val datagram: ByteArray? = connection.awaitIncomingDatagram()
}

fun pinned() {
    val validator = PinnedCertificateValidator.ofSha256Hex("5E:FF:3A:...")
}

fun resumption(cached: TlsResumptionState?) {
    val ticketCache = mutableMapOf<String, TlsResumptionState>()
    val connection =
        QuicConnection(
            serverName = "example.com",
            config = QuicConnectionConfig(),
            tlsCertificateValidator = JdkCertificateValidator(),
            resumption = ticketCache["example.com"],
            onResumptionTicket = { ticketCache["example.com"] = it },
        )
}

suspend fun webTransport(
    connection: QuicConnection,
    driver: QuicConnectionDriver,
): QuicWebTransportSessionState {
    // HTTP/3 control stream with SETTINGS that enable WebTransport.
    val control = connection.openUniStream()
    control.send.enqueue(byteArrayOf(Http3StreamType.CONTROL.toByte()) + buildClientWebTransportSettings().encodeFrame())

    // Extended CONNECT (RFC 9220) on a request stream.
    val request = connection.openBidiStream()
    request.send.enqueue(encodeHeadersFrame(buildExtendedConnectHeaders("example.com:443", "/moq", bearerToken = null)))
    driver.wakeup()

    // Read frames until the response HEADERS, then check :status.
    val reader = Http3FrameReader()
    val status =
        request.incoming
            .transform { chunk ->
                reader.push(chunk)
                while (true) emit(reader.next() ?: break)
            }.filterIsInstance<Http3Frame.Headers>()
            .map { headers ->
                QpackDecoder()
                    .decodeFieldSection(headers.qpackPayload)
                    .first { it.first == ":status" }
                    .second
                    .toInt()
            }.first()
    check(status in 200..299) { "CONNECT rejected: $status" }

    val session = QuicWebTransportSessionState(connection, driver, request.streamId)

    val out = session.openUniStream()
    out.send.enqueue("hi".encodeToByteArray())
    driver.wakeup()

    session.sendDatagram(byteArrayOf(42))

    CoroutineScope(Dispatchers.IO).launch {
        session.incomingStrippedStreams.collect { stream ->
            stream.data.collect { chunk -> println(chunk.size) }
        }
    }

    session.close(errorCode = 0, reason = "bye")
    return QuicWebTransportSessionState(connection, driver, request.streamId)
}
