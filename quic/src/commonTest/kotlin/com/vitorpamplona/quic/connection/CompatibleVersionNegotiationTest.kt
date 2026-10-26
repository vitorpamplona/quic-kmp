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

import com.vitorpamplona.quic.frame.QuicTransportError
import com.vitorpamplona.quic.packet.LongHeaderPacket
import com.vitorpamplona.quic.packet.LongHeaderType
import com.vitorpamplona.quic.packet.QuicVersion
import com.vitorpamplona.quic.tls.InProcessTlsServer
import com.vitorpamplona.quic.tls.PermissiveCertificateValidator
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * RFC 9368 compatible version negotiation with QUIC v2 (RFC 9369): the client
 * opens in v1, offers v2 in `version_information`, and a server that prefers v2
 * answers in it.
 */
class CompatibleVersionNegotiationTest {
    private fun newClient(compatible: List<Int>) =
        QuicConnection(
            serverName = "example.test",
            config = QuicConnectionConfig(compatibleVersions = compatible),
            tlsCertificateValidator = PermissiveCertificateValidator(),
        )

    private fun serverTls(
        client: QuicConnection,
        serverScid: ConnectionId,
        versionInformation: VersionInformation?,
    ) = InProcessTlsServer(
        transportParameters =
            TransportParameters(
                initialMaxData = 1_000_000,
                initialMaxStreamDataBidiLocal = 100_000,
                initialMaxStreamDataBidiRemote = 100_000,
                initialMaxStreamDataUni = 100_000,
                initialMaxStreamsBidi = 16,
                initialMaxStreamsUni = 16,
                initialSourceConnectionId = serverScid.bytes,
                originalDestinationConnectionId = client.destinationConnectionId.bytes,
                versionInformation = versionInformation,
            ).encode(),
    )

    @Test
    fun client_advertises_its_compatible_versions() {
        val client = newClient(listOf(QuicVersion.V2, QuicVersion.V1))
        val tp = TransportParameters.decode(client.tls.transportParameters)
        assertEquals(VersionInformation(QuicVersion.V1, listOf(QuicVersion.V2, QuicVersion.V1)), tp.versionInformation)
    }

    @Test
    fun default_config_offers_only_v1() {
        val client = newClient(QuicConnectionConfig().compatibleVersions)
        val tp = TransportParameters.decode(client.tls.transportParameters)
        assertEquals(VersionInformation(QuicVersion.V1, listOf(QuicVersion.V1)), tp.versionInformation)
    }

    @Test
    fun server_switches_the_connection_to_v2() {
        val client = newClient(listOf(QuicVersion.V2, QuicVersion.V1))
        client.start()
        val pipe = InMemoryQuicPipe(client, client.destinationConnectionId.bytes, serverVersion = QuicVersion.V2)
        pipe.drive()
        assertEquals(QuicConnection.Status.CONNECTED, client.status, "closed: ${client.closeReason}")
        assertTrue(client.compatibleVersionSwitched, "sent ${pipe.clientLongHeaders} version ${client.currentVersion}")
        assertEquals(QuicVersion.V2, client.currentVersion)
        assertEquals(LongHeaderType.INITIAL to QuicVersion.V1, pipe.clientLongHeaders.first(), "first Initial goes out in v1")
        // The client's next flight (Initial ACK + Handshake Finished) is all v2.
        val finished = drainOutbound(client, 0L)
        assertNotNull(finished)
        val headers = mutableListOf<LongHeaderPacket.PeekedHeader>()
        var offset = 0
        while (offset < finished.size && (finished[offset].toInt() and 0x80) != 0) {
            val header = LongHeaderPacket.peekHeader(finished, offset)
            assertNotNull(header)
            headers += header
            offset += header.totalLength
        }
        assertTrue(headers.any { it.type == LongHeaderType.HANDSHAKE }, "flight: $headers")
        assertTrue(headers.all { it.version == QuicVersion.V2 }, "flight: $headers")
    }

    @Test
    fun client_ignores_a_version_it_did_not_offer() {
        val client = newClient(listOf(QuicVersion.V1))
        client.start()
        val pipe = InMemoryQuicPipe(client, client.destinationConnectionId.bytes, serverVersion = QuicVersion.V2)
        pipe.drive()
        assertFalse(client.compatibleVersionSwitched)
        assertEquals(QuicVersion.V1, client.currentVersion)
        assertEquals(QuicConnection.Status.HANDSHAKING, client.status, "a v2 answer to a v1-only client is dropped")
    }

    @Test
    fun server_chosen_version_must_match_the_switch() {
        val client = newClient(listOf(QuicVersion.V2, QuicVersion.V1))
        client.start()
        val scid = ConnectionId.random(8)
        val pipe =
            InMemoryQuicPipe(
                client,
                client.destinationConnectionId.bytes,
                serverScid = scid,
                serverVersion = QuicVersion.V2,
                tlsServer = serverTls(client, scid, VersionInformation(QuicVersion.V1, listOf(QuicVersion.V1))),
            )
        pipe.drive()
        assertEquals(QuicConnection.Status.CLOSED, client.status)
        assertEquals(QuicTransportError.VERSION_NEGOTIATION_ERROR, client.closeErrorCode)
    }

    @Test
    fun switch_without_version_information_is_rejected() {
        val client = newClient(listOf(QuicVersion.V2, QuicVersion.V1))
        client.start()
        val scid = ConnectionId.random(8)
        val pipe =
            InMemoryQuicPipe(
                client,
                client.destinationConnectionId.bytes,
                serverScid = scid,
                serverVersion = QuicVersion.V2,
                tlsServer = serverTls(client, scid, null),
            )
        pipe.drive()
        assertEquals(QuicConnection.Status.CLOSED, client.status)
        assertEquals(QuicTransportError.VERSION_NEGOTIATION_ERROR, client.closeErrorCode)
    }

    @Test
    fun forged_chosen_version_without_a_switch_is_rejected() {
        val client = newClient(listOf(QuicVersion.V2, QuicVersion.V1))
        client.start()
        val scid = ConnectionId.random(8)
        val pipe =
            InMemoryQuicPipe(
                client,
                client.destinationConnectionId.bytes,
                serverScid = scid,
                tlsServer = serverTls(client, scid, VersionInformation(QuicVersion.V2, listOf(QuicVersion.V1, QuicVersion.V2))),
            )
        pipe.drive()
        assertEquals(QuicConnection.Status.CLOSED, client.status)
        assertEquals(QuicTransportError.VERSION_NEGOTIATION_ERROR, client.closeErrorCode)
    }

    @Test
    fun v1_server_with_matching_version_information_connects() {
        val client = newClient(listOf(QuicVersion.V2, QuicVersion.V1))
        client.start()
        val scid = ConnectionId.random(8)
        val pipe =
            InMemoryQuicPipe(
                client,
                client.destinationConnectionId.bytes,
                serverScid = scid,
                tlsServer = serverTls(client, scid, VersionInformation(QuicVersion.V1, listOf(QuicVersion.V1, QuicVersion.V2))),
            )
        pipe.drive()
        assertEquals(QuicConnection.Status.CONNECTED, client.status, "closed: ${client.closeReason}")
        assertEquals(QuicVersion.V1, client.currentVersion)
    }

    @Test
    fun malformed_version_information_is_a_transport_parameter_error() {
        val bad = TransportParameters(unknown = mapOf(TransportParameterId.VERSION_INFORMATION to ByteArray(6))).encode()
        val failure = runCatching { TransportParameters.decode(bad) }.exceptionOrNull()
        assertNotNull(failure)
        val zero = TransportParameters(unknown = mapOf(TransportParameterId.VERSION_INFORMATION to ByteArray(8))).encode()
        assertNotNull(runCatching { TransportParameters.decode(zero) }.exceptionOrNull())
    }
}
