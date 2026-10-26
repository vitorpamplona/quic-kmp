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

import com.vitorpamplona.quic.frame.PathChallengeFrame
import com.vitorpamplona.quic.frame.PathResponseFrame
import com.vitorpamplona.quic.frame.PingFrame
import com.vitorpamplona.quic.frame.RetireConnectionIdFrame
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * RFC 9000 §9.6 migration to the server's preferred address: validate the new
 * path with PATH_CHALLENGE first, then move every packet there with the
 * preferred address's connection ID.
 */
class PreferredAddressMigrationTest {
    private val paCid = ConnectionId.random(8)

    private fun preferredAddress(
        v4: ByteArray = byteArrayOf(193.toByte(), 167.toByte(), 100, 100),
        v4Port: Int = 4433,
        v6: ByteArray = ByteArray(16),
        v6Port: Int = 0,
    ) = PreferredAddress(v4, v4Port, v6, v6Port, paCid.bytes, ByteArray(16) { 7 })

    @Test
    fun transport_parameter_round_trips() {
        val v6 =
            ByteArray(16).also {
                it[0] = 0xfd.toByte()
                it[15] = 1
            }
        val pa = preferredAddress(v6 = v6, v6Port = 443)
        val decoded = TransportParameters.decode(TransportParameters(preferredAddress = pa).encode()).preferredAddress
        assertNotNull(decoded)
        assertEquals("193.167.100.100", decoded.ipv4Host)
        assertEquals(4433, decoded.ipv4Port)
        assertEquals("fd00:0:0:0:0:0:0:1", decoded.ipv6Host)
        assertContentEquals(paCid.bytes, decoded.connectionId)
    }

    @Test
    fun zero_length_connection_id_is_rejected() {
        val bad = PreferredAddress(ByteArray(4), 0, ByteArray(16), 0, ByteArray(0), ByteArray(16))
        assertNotNull(runCatching { TransportParameters.decode(TransportParameters(preferredAddress = bad).encode()) }.exceptionOrNull())
    }

    @Test
    fun probe_validates_then_migrates() {
        val (client, pipe) = newConnectedClient(preferredAddress = preferredAddress())
        val originalDcid = client.destinationConnectionId
        assertNull(drainProbe(client, 0L), "nothing on the probe path before the probe exists")
        drainOutbound(client, 0L)
        val probe = client.pathProbe
        assertNotNull(probe, "handshake confirmed + preferred_address → probe")
        assertEquals("193.167.100.100", probe.host)
        assertEquals(4433, probe.port)
        assertEquals(PathProbe.State.AWAITING_SOCKET, probe.state)
        assertNull(drainProbe(client, 0L), "no datagram before the driver opened the socket")

        probe.onSocketReady()
        val datagram = drainProbe(client, 0L)
        assertNotNull(datagram)
        assertTrue(datagram.size >= 1200, "PATH_CHALLENGE datagrams are expanded to 1200 bytes, got ${datagram.size}")
        assertContentEquals(paCid.bytes, datagram.copyOfRange(1, 1 + paCid.length), "probe uses the preferred address's CID")
        val frames = pipe.decryptClientApplicationFrames(datagram)
        assertNotNull(frames)
        val challenge = frames.filterIsInstance<PathChallengeFrame>().single()
        assertTrue(frames.all { it is PathChallengeFrame || it is com.vitorpamplona.quic.frame.PaddingFrame }, "only probing frames: $frames")
        assertNull(drainProbe(client, 1L), "the next challenge waits for the retransmit timer")
        assertEquals(originalDcid, client.destinationConnectionId, "active path untouched while validating")

        // The server's PATH_RESPONSE validates the path.
        val response = pipe.buildServerApplicationDatagram(listOf(PathResponseFrame(challenge.data)))!!
        feedDatagram(client, response, 2L, NetworkPath.PROBE)
        assertEquals(PathProbe.State.VALIDATED, probe.state)
        assertTrue(client.migratedToPreferredAddress)
        assertEquals(paCid, client.destinationConnectionId)

        // Next packet (on the new path) retires the old CID and is non-probing.
        val next = drainOutbound(client, 3L)
        assertNotNull(next)
        assertContentEquals(paCid.bytes, next.copyOfRange(1, 1 + paCid.length))
        val nextFrames = pipe.decryptClientApplicationFrames(next)
        assertNotNull(nextFrames)
        assertEquals(0L, nextFrames.filterIsInstance<RetireConnectionIdFrame>().single().sequenceNumber)
        assertTrue(nextFrames.any { it is PingFrame })
    }

    @Test
    fun server_challenge_on_the_probe_path_is_answered_there() {
        val (client, pipe) = newConnectedClient(preferredAddress = preferredAddress())
        drainOutbound(client, 0L)
        val probe = client.pathProbe!!
        probe.onSocketReady()
        drainProbe(client, 0L)
        val serverChallenge = ByteArray(8) { (it + 1).toByte() }
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(PathChallengeFrame(serverChallenge)))!!, 1L, NetworkPath.PROBE)
        val onProbe = pipe.decryptClientApplicationFrames(drainProbe(client, 1L)!!)!!
        assertContentEquals(serverChallenge, onProbe.filterIsInstance<PathResponseFrame>().single().data)
        val onActive = drainOutbound(client, 1L)?.let { pipe.decryptClientApplicationFrames(it) }.orEmpty()
        assertTrue(onActive.none { it is PathResponseFrame }, "the response belongs to the probe path")
    }

    @Test
    fun server_challenge_still_unanswered_when_the_probe_validates_is_answered_on_the_new_path() {
        // lsquic: its PATH_CHALLENGE on the probed path came 3 ms before its
        // PATH_RESPONSE; the answer queued on the probe was dropped once the
        // probe validated, and lsquic never moved its sending to the new path.
        val (client, pipe) = newConnectedClient(preferredAddress = preferredAddress())
        drainOutbound(client, 0L)
        val probe = client.pathProbe!!
        probe.onSocketReady()
        val ourChallenge = pipe.decryptClientApplicationFrames(drainProbe(client, 0L)!!)!!.filterIsInstance<PathChallengeFrame>().single()
        val serverChallenge = ByteArray(8) { (it + 1).toByte() }
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(PathChallengeFrame(serverChallenge)))!!, 1L, NetworkPath.PROBE)
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(PathResponseFrame(ourChallenge.data)))!!, 1L, NetworkPath.PROBE)
        assertEquals(PathProbe.State.VALIDATED, probe.state)
        val frames = pipe.decryptClientApplicationFrames(assertNotNull(drainOutbound(client, 2L)))!!
        assertContentEquals(serverChallenge, frames.filterIsInstance<PathResponseFrame>().single().data)
    }

    @Test
    fun unanswered_probe_times_out_and_the_connection_stays() {
        val (client, _) = newConnectedClient(preferredAddress = preferredAddress())
        val originalDcid = client.destinationConnectionId
        drainOutbound(client, 0L)
        val probe = client.pathProbe!!
        probe.onSocketReady()
        drainProbe(client, 0L)
        drainOutbound(client, probe.timeoutMillis + 1)
        assertEquals(PathProbe.State.FAILED, probe.state)
        assertFalse(client.migratedToPreferredAddress)
        assertEquals(originalDcid, client.destinationConnectionId)
        assertEquals(QuicConnection.Status.CONNECTED, client.status)
    }

    @Test
    fun ipv6_path_picks_the_ipv6_preferred_address() {
        val v6 =
            ByteArray(16).also {
                it[0] = 0xfd.toByte()
                it[15] = 0x64
            }
        val (client, _) = newConnectedClient(preferredAddress = preferredAddress(v6 = v6, v6Port = 443))
        client.activePathIsIpv6 = true
        drainOutbound(client, 0L)
        assertEquals("fd00:0:0:0:0:0:0:64", client.pathProbe!!.host)
    }

    @Test
    fun migration_can_be_turned_off() {
        val (client, _) = newConnectedClient(preferredAddress = preferredAddress(), migrateToPreferredAddress = false)
        drainOutbound(client, 0L)
        assertNull(client.pathProbe)
    }

    @Test
    fun no_probe_before_the_handshake_is_confirmed() {
        val (client, _) = newConnectedClient(preferredAddress = preferredAddress(), deliverHandshakeDone = false)
        drainOutbound(client, 0L)
        assertNull(client.pathProbe)
    }
}
