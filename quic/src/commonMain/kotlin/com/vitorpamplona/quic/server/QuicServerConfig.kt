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

import com.vitorpamplona.quic.connection.QuicConnectionConfig
import com.vitorpamplona.quic.observability.QlogObserver
import com.vitorpamplona.quic.packet.QuicVersion
import com.vitorpamplona.quic.tls.TlsCertificateSigner
import com.vitorpamplona.quic.tls.TlsConstants
import com.vitorpamplona.quic.tls.TlsSecretsListener
import com.vitorpamplona.quic.tls.TlsSessionTicketKeys

/** How a [QuicServer] accepts and runs connections. */
class QuicServerConfig(
    /** The certificate chain and key the server proves itself with. */
    val signer: TlsCertificateSigner,
    /** Picks the application protocol from the client's offer, or null to refuse it (RFC 7301). */
    val alpnSelector: (offered: List<ByteArray>) -> ByteArray?,
    /** Transport settings every accepted connection runs with. */
    val connectionConfig: QuicConnectionConfig = QuicConnectionConfig(),
    /** Versions accepted, most preferred first; anything else gets Version Negotiation. */
    val supportedVersions: List<Int> = listOf(QuicVersion.V1),
    /** Answer every new Initial without a valid token with a Retry (RFC 9000 §8.1.2). */
    val requireRetry: Boolean = false,
    /** Give each client a NEW_TOKEN token, so its next connection skips address validation (RFC 9000 §8.1.3). */
    val issueNewTokens: Boolean = true,
    /** Enables session tickets and resumption. */
    val ticketKeys: TlsSessionTicketKeys? = null,
    /** 0xffffffff accepts 0-RTT on resumed connections (RFC 9001 §4.6.1); 0 refuses it. Needs [ticketKeys]. */
    val maxEarlyDataSize: Long = 0L,
    /** Cipher suites accepted, most preferred first. */
    val cipherSuites: IntArray =
        intArrayOf(
            TlsConstants.CIPHER_TLS_AES_128_GCM_SHA256,
            TlsConstants.CIPHER_TLS_CHACHA20_POLY1305_SHA256,
        ),
    /** Length of the connection IDs the server picks; short headers are routed on it. */
    val connectionIdLength: Int = 8,
    /** A qlog observer per connection, keyed by the client's original DCID. */
    val qlogObserverFactory: ((originalDestinationConnectionId: ByteArray) -> QlogObserver)? = null,
    /** A secrets listener per connection, e.g. an SSLKEYLOGFILE writer. */
    val secretsListenerFactory: (() -> TlsSecretsListener?)? = null,
) {
    init {
        require(connectionIdLength in 8..20) { "connectionIdLength must be 8..20" }
        require(supportedVersions.isNotEmpty() && supportedVersions.all { QuicVersion.isSupported(it) }) {
            "supportedVersions must be non-empty and only list versions this library speaks"
        }
    }
}
