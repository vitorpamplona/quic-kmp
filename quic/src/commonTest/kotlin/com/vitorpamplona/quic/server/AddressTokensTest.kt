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

import com.vitorpamplona.quic.connection.ConnectionId
import com.vitorpamplona.quic.transport.UdpPeerAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** RFC 9000 §8.1.3 address-validation tokens and §10.3.2 stateless reset tokens. */
class AddressTokensTest {
    private val peer = UdpPeerAddress(byteArrayOf(10, 0, 0, 1), 5000)
    private val odcid = ConnectionId(ByteArray(8) { 1 })
    private val rscid = ConnectionId(ByteArray(8) { 2 })

    @Test
    fun a_retry_token_opens_for_the_same_address_while_fresh() {
        val tokens = AddressTokens()
        val token = tokens.mintRetry(peer, odcid, rscid, nowMillis = 1_000)
        val opened = assertNotNull(tokens.openRetry(token, peer, nowMillis = 2_000))
        assertEquals(odcid, opened.originalDestinationConnectionId)
        assertEquals(rscid, opened.retrySourceConnectionId)
        assertNull(tokens.openRetry(token, peer, nowMillis = 1_000 + AddressTokens.RETRY_TOKEN_LIFETIME_MS + 1), "stale")
        assertNull(tokens.openRetry(token, UdpPeerAddress(peer.ip, 5001), nowMillis = 2_000), "another port")
        assertNull(tokens.openRetry(token, peer, nowMillis = 999), "from the future")
        assertNull(AddressTokens().openRetry(token, peer, nowMillis = 2_000), "another server's key")
        val tampered = token.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertNull(tokens.openRetry(tampered, peer, nowMillis = 2_000))
    }

    @Test
    fun a_new_token_is_bound_to_the_ip_not_the_port() {
        val tokens = AddressTokens()
        val token = tokens.mintNewToken(peer, nowMillis = 0)
        assertTrue(tokens.openNewToken(token, UdpPeerAddress(peer.ip, 6000), nowMillis = 60_000))
        assertFalse(tokens.openNewToken(token, UdpPeerAddress(byteArrayOf(10, 0, 0, 2), 5000), nowMillis = 60_000))
        assertFalse(tokens.openNewToken(token, peer, nowMillis = AddressTokens.NEW_TOKEN_LIFETIME_MS + 1))
    }

    @Test
    fun the_two_kinds_do_not_stand_in_for_each_other() {
        val tokens = AddressTokens()
        assertFalse(tokens.openNewToken(tokens.mintRetry(peer, odcid, rscid, 0), peer, 0))
        assertNull(tokens.openRetry(tokens.mintNewToken(peer, 0), peer, 0))
    }

    @Test
    fun stateless_reset_tokens_are_stable_per_connection_id_and_key() {
        val a = StatelessResetTokens()
        assertEquals(16, a.tokenFor(odcid).size)
        assertTrue(a.tokenFor(odcid).contentEquals(a.tokenFor(ConnectionId(odcid.bytes.copyOf()))))
        assertFalse(a.tokenFor(odcid).contentEquals(a.tokenFor(rscid)))
        assertNotEquals(a.tokenFor(odcid).toList(), StatelessResetTokens().tokenFor(odcid).toList())
    }
}
