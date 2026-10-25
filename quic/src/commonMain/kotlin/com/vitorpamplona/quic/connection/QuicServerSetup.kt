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
package com.vitorpamplona.quic.connection

import com.vitorpamplona.quic.tls.TlsHandshake
import com.vitorpamplona.quic.tls.TlsSecretsListener

/**
 * What a server-side [QuicConnection] needs from the endpoint that accepted
 * the client's first Initial: the connection IDs both sides chose, the TLS
 * server, and hooks that keep the endpoint's CID routing table current.
 */
internal class QuicServerSetup(
    /** Builds the TLS server from our encoded transport parameters. */
    val tlsServerFactory: (transportParameters: ByteArray, listener: TlsSecretsListener) -> TlsHandshake,
    /** The DCID of the client's first Initial, before any Retry (RFC 9000 §7.3). */
    val originalDestinationConnectionId: ConnectionId,
    /** The DCID of the Initial this connection answers; Initial keys derive from it. */
    val clientInitialDestinationConnectionId: ConnectionId,
    /** The SCID of the client's Initial: our DCID. */
    val clientSourceConnectionId: ConnectionId,
    /** The SCID we put in our packets. */
    val localConnectionId: ConnectionId,
    /** The SCID of the Retry we sent, when the connection went through one. */
    val retrySourceConnectionId: ConnectionId? = null,
    /** True when a Retry or NEW_TOKEN token already validated the client's address (RFC 9000 §8.1). */
    val addressValidated: Boolean = false,
    /** The stateless reset token for one of our connection IDs (RFC 9000 §10.3.2). */
    val statelessResetTokenFor: (ConnectionId) -> ByteArray,
    /** The versions the server speaks, for its version_information (RFC 9368 §3). */
    val supportedVersions: List<Int> = listOf(com.vitorpamplona.quic.packet.QuicVersion.V1),
    /** Called when we issue a new connection ID, so the endpoint routes it to us. */
    val onConnectionIdIssued: (ConnectionId) -> Unit = {},
    /** Called when the peer retires one of our connection IDs. */
    val onConnectionIdRetired: (ConnectionId) -> Unit = {},
    /** Where the client's first Initial came from. */
    val peerAddress: com.vitorpamplona.quic.transport.UdpPeerAddress? = null,
)
