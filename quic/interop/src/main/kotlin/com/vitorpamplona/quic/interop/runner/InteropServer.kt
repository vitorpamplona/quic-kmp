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
package com.vitorpamplona.quic.interop.runner

import com.vitorpamplona.quic.QuicWriter
import com.vitorpamplona.quic.connection.QuicConnectionConfig
import com.vitorpamplona.quic.http3.Http3Frame
import com.vitorpamplona.quic.http3.Http3FrameReader
import com.vitorpamplona.quic.http3.Http3FrameType
import com.vitorpamplona.quic.http3.Http3Settings
import com.vitorpamplona.quic.http3.Http3StreamType
import com.vitorpamplona.quic.packet.QuicVersion
import com.vitorpamplona.quic.qpack.QpackDecoder
import com.vitorpamplona.quic.qpack.QpackEncoder
import com.vitorpamplona.quic.server.QuicServer
import com.vitorpamplona.quic.server.QuicServerConfig
import com.vitorpamplona.quic.server.QuicServerConnection
import com.vitorpamplona.quic.stream.QuicStream
import com.vitorpamplona.quic.stream.StreamId
import com.vitorpamplona.quic.tls.JcaCertificateSigner
import com.vitorpamplona.quic.tls.TlsConstants
import com.vitorpamplona.quic.tls.TlsSessionTicketKeys
import com.vitorpamplona.quic.transport.UdpServerSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.File

private const val ALPN_HQ = "hq-interop"
private const val H3_DATA_FRAME_SIZE = 64 * 1024

/** Testcases the server plays (https://github.com/quic-interop/quic-interop-runner, `testcases_quic.py`). */
private val SERVER_TESTCASES =
    setOf(
        "handshake",
        "transfer",
        "longrtt",
        "chacha20",
        "multiplexing",
        "retry",
        "resumption",
        "zerortt",
        "http3",
        "blackhole",
        "keyupdate",
        "ecn",
        "amplificationlimit",
        "handshakeloss",
        "transferloss",
        "handshakecorruption",
        "transfercorruption",
        "ipv6",
        "goodput",
        "crosstraffic",
    )

/**
 * The runner's server role: serve `/www` over hq-interop (HTTP/0.9) or, for
 * `http3`, HTTP/3, on UDP 443 with the certificate in `/certs`. Runs until
 * the runner stops the container. Returns 127 for testcases it doesn't play.
 */
fun runInteropServer(testcase: String): Int {
    if (testcase !in SERVER_TESTCASES) {
        System.err.println("server: testcase '$testcase' not supported")
        return 127
    }
    val certs = File(System.getenv("CERTS")?.takeIf { it.isNotBlank() } ?: "/certs")
    val www = File(System.getenv("WWW")?.takeIf { it.isNotBlank() } ?: "/www").canonicalFile
    val port = System.getenv("PORT")?.toIntOrNull() ?: 443
    val signer = JcaCertificateSigner.fromPem(File(certs, "cert.pem").readText(), File(certs, "priv.key").readText())
    val keyLogFile = System.getenv("SSLKEYLOGFILE")?.takeIf { it.isNotBlank() }?.let(::File)
    val qlogDir =
        System
            .getenv("QLOGDIR")
            ?.takeIf { it.isNotBlank() }
            ?.let(::File)
            ?.also { it.mkdirs() }
    // The testcase's protocol first, but serve whichever of the two the client offers.
    val hq = ALPN_HQ.encodeToByteArray()
    val preferred = if (testcase == "http3") listOf(TlsConstants.ALPN_H3, hq) else listOf(hq, TlsConstants.ALPN_H3)

    val config =
        QuicServerConfig(
            signer = signer,
            alpnSelector = { offered -> preferred.firstOrNull { p -> offered.any { it.contentEquals(p) } } },
            connectionConfig = QuicConnectionConfig(),
            supportedVersions = listOf(QuicVersion.V1, QuicVersion.V2),
            requireRetry = testcase == "retry",
            ticketKeys = TlsSessionTicketKeys(),
            maxEarlyDataSize = if (testcase == "zerortt") 0xffffffffL else 0L,
            cipherSuites =
                intArrayOf(
                    TlsConstants.CIPHER_TLS_AES_128_GCM_SHA256,
                    TlsConstants.CIPHER_TLS_CHACHA20_POLY1305_SHA256,
                ),
            secretsListenerFactory = keyLogFile?.let { file -> { KeyLogListener(SslKeyLogger(file)) } },
            qlogObserverFactory = qlogDir?.let { dir -> { odcid -> QlogWriter(File(dir, "server-${odcid.toHex()}.sqlog"), odcid.toHex()) } },
        )

    return runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val socket = UdpServerSocket.bind(null, port)
        val server = QuicServer(config, socket, scope)
        server.start()
        System.err.println("server: $testcase on UDP ${socket.localPort}, serving $www, alpn=${preferred.joinToString { it.decodeToString() }}")
        while (true) {
            val accepted = server.accept() ?: break
            scope.launch { serveConnection(accepted, www, scope) }
        }
        0
    }
}

private suspend fun serveConnection(
    accepted: QuicServerConnection,
    www: File,
    scope: CoroutineScope,
) {
    val conn = accepted.connection
    try {
        conn.awaitHandshake()
    } catch (e: Exception) {
        System.err.println("server: handshake with ${accepted.peerAddress} failed: ${e.message}")
        (conn.qlogObserver as? java.io.Closeable)?.close()
        return
    }
    // The secrets are labelled by the client random, known once the ClientHello arrived.
    (conn.extraSecretsListener as? KeyLogListener)?.let { kl -> accepted.tls.clientRandom?.let { kl.logger.flush(it) } }
    val http3 = conn.tlsServer?.negotiatedAlpn?.contentEquals(TlsConstants.ALPN_H3) == true
    if (http3) openHttp3ServerStreams(accepted)
    while (true) {
        val stream = conn.awaitIncomingPeerStream() ?: break
        if (StreamId.isUnidirectional(stream.streamId)) {
            // The client's control and QPACK streams: we keep no dynamic table.
            scope.launch { stream.incoming.collect { } }
            continue
        }
        scope.launch {
            try {
                if (http3) serveHttp3Request(accepted, stream, www) else serveHqRequest(accepted, stream, www)
            } catch (e: Exception) {
                System.err.println("server: stream ${stream.streamId} failed: ${e.message}")
            }
        }
    }
    (conn.qlogObserver as? java.io.Closeable)?.close()
}

/** HTTP/0.9: `GET /path\r\n`, answered with the file's bytes and FIN. */
private suspend fun serveHqRequest(
    accepted: QuicServerConnection,
    stream: QuicStream,
    www: File,
) {
    val request = readAll(stream).decodeToString()
    val path =
        request
            .trim()
            .removePrefix("GET")
            .trim()
            .substringBefore(' ')
    val body = fileFor(www, path)?.readBytes() ?: ByteArray(0)
    stream.send.enqueue(body)
    stream.send.finish()
    accepted.driver.wakeup()
}

/** RFC 9114: a HEADERS frame with `:path` in, HEADERS (`:status`) and DATA out. */
private suspend fun serveHttp3Request(
    accepted: QuicServerConnection,
    stream: QuicStream,
    www: File,
) {
    val reader = Http3FrameReader()
    var path: String? = null
    stream.incoming.collect { chunk ->
        reader.push(chunk)
        while (true) {
            val frame = reader.next() ?: break
            if (frame is Http3Frame.Headers && path == null) {
                path = QpackDecoder().decodeFieldSection(frame.qpackPayload).firstOrNull { it.first == ":path" }?.second
            }
        }
    }
    val file = path?.let { fileFor(www, it) }
    val status = if (file != null) "200" else "404"
    val body = file?.readBytes() ?: ByteArray(0)
    val headers = QpackEncoder().encodeFieldSection(listOf(":status" to status, "content-length" to body.size.toString()))
    val w = QuicWriter()
    w.writeVarint(Http3FrameType.HEADERS)
    w.writeVarint(headers.size.toLong())
    w.writeBytes(headers)
    stream.send.enqueue(w.toByteArray())
    // DATA frames of at most 64 KB, so a client needn't buffer a whole file to parse one.
    var off = 0
    while (off < body.size) {
        val n = minOf(H3_DATA_FRAME_SIZE, body.size - off)
        val header = QuicWriter()
        header.writeVarint(Http3FrameType.DATA)
        header.writeVarint(n.toLong())
        stream.send.enqueue(header.toByteArray())
        stream.send.enqueue(body.copyOfRange(off, off + n))
        off += n
    }
    stream.send.finish()
    accepted.driver.wakeup()
}

/** RFC 9114 §6.2.1: our control stream (with SETTINGS) and the two QPACK streams. */
private suspend fun openHttp3ServerStreams(accepted: QuicServerConnection) {
    val conn = accepted.connection
    for (type in listOf(Http3StreamType.CONTROL, Http3StreamType.QPACK_ENCODER, Http3StreamType.QPACK_DECODER)) {
        val s = conn.openUniStream()
        val w = QuicWriter()
        w.writeVarint(type)
        if (type == Http3StreamType.CONTROL) w.writeBytes(Http3Settings(emptyMap()).encodeFrame())
        s.send.enqueue(w.toByteArray())
    }
    accepted.driver.wakeup()
}

private suspend fun readAll(stream: QuicStream): ByteArray {
    val parts = ArrayList<ByteArray>()
    stream.incoming.collect { parts += it }
    val out = ByteArray(parts.sumOf { it.size })
    var off = 0
    for (p in parts) {
        p.copyInto(out, off)
        off += p.size
    }
    return out
}

/** The file under [www] that [path] names, or null when there is none or the path climbs out. */
private fun fileFor(
    www: File,
    path: String,
): File? {
    val file = File(www, path.removePrefix("/")).canonicalFile
    if (!file.path.startsWith(www.path + File.separator) || !file.isFile) return null
    return file
}

/** The keylog listener of one server connection, so it can be flushed once the client random is known. */
private class KeyLogListener(
    val logger: SslKeyLogger,
) : com.vitorpamplona.quic.tls.TlsSecretsListener by logger.listener
