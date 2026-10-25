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

import com.vitorpamplona.crypto.mac.MacInstance
import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.quic.QuicReader
import com.vitorpamplona.quic.QuicWriter
import com.vitorpamplona.quic.connection.ConnectionId
import com.vitorpamplona.quic.crypto.Aes128Gcm
import com.vitorpamplona.quic.transport.UdpPeerAddress

/**
 * Address-validation tokens (RFC 9000 §8.1.3), sealed with a per-server
 * AES-128-GCM key and bound to the client's address. A Retry token also
 * carries the connection IDs the server must echo in its transport
 * parameters, so the server keeps no state between the Retry and the
 * client's next Initial.
 */
internal class AddressTokens(
    private val key: ByteArray = RandomInstance.bytes(16),
) {
    class Retry(
        val originalDestinationConnectionId: ConnectionId,
        val retrySourceConnectionId: ConnectionId,
    )

    fun mintRetry(
        peer: UdpPeerAddress,
        originalDestinationConnectionId: ConnectionId,
        retrySourceConnectionId: ConnectionId,
        nowMillis: Long,
    ): ByteArray {
        val w = QuicWriter()
        w.writeByte(KIND_RETRY)
        w.writeUint32((nowMillis ushr 32).toInt())
        w.writeUint32(nowMillis.toInt())
        w.writeByte(originalDestinationConnectionId.length)
        w.writeBytes(originalDestinationConnectionId.bytes)
        w.writeByte(retrySourceConnectionId.length)
        w.writeBytes(retrySourceConnectionId.bytes)
        val nonce = RandomInstance.bytes(12)
        return byteArrayOf(KIND_RETRY.toByte()) + nonce + Aes128Gcm.seal(key, nonce, aad(peer), w.toByteArray())
    }

    /** The Retry token's contents when it opens, came from [peer], and is fresh; else null. */
    fun openRetry(
        token: ByteArray,
        peer: UdpPeerAddress,
        nowMillis: Long,
    ): Retry? {
        if (!isRetryToken(token) || token.size < 1 + 12 + 16 + 11) return null
        val plain = Aes128Gcm.open(key, token.copyOfRange(1, 13), aad(peer), token.copyOfRange(13, token.size)) ?: return null
        return try {
            val r = QuicReader(plain)
            if (r.readByte() != KIND_RETRY) return null
            val issuedAt = (r.readUint32() shl 32) or (r.readUint32() and 0xFFFFFFFFL)
            if (nowMillis < issuedAt || nowMillis - issuedAt > RETRY_TOKEN_LIFETIME_MS) return null
            val odcid = ConnectionId(r.readBytes(r.readByte()))
            val rscid = ConnectionId(r.readBytes(r.readByte()))
            Retry(odcid, rscid)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * A token for a future connection from the same client (RFC 9000 §8.1.3),
     * bound to its IP address only: its port will differ next time.
     */
    fun mintNewToken(
        peer: UdpPeerAddress,
        nowMillis: Long,
    ): ByteArray {
        val w = QuicWriter()
        w.writeByte(KIND_NEW_TOKEN)
        w.writeUint32((nowMillis ushr 32).toInt())
        w.writeUint32(nowMillis.toInt())
        val nonce = RandomInstance.bytes(12)
        return byteArrayOf(KIND_NEW_TOKEN.toByte()) + nonce + Aes128Gcm.seal(key, nonce, peer.ip, w.toByteArray())
    }

    /** True when [token] is one of our NEW_TOKEN tokens for [peer]'s IP, and still fresh. */
    fun openNewToken(
        token: ByteArray,
        peer: UdpPeerAddress,
        nowMillis: Long,
    ): Boolean {
        if (token.isEmpty() || token[0] != KIND_NEW_TOKEN.toByte() || token.size < 1 + 12 + 16 + 9) return false
        val plain = Aes128Gcm.open(key, token.copyOfRange(1, 13), peer.ip, token.copyOfRange(13, token.size)) ?: return false
        return try {
            val r = QuicReader(plain)
            if (r.readByte() != KIND_NEW_TOKEN) return false
            val issuedAt = (r.readUint32() shl 32) or (r.readUint32() and 0xFFFFFFFFL)
            nowMillis >= issuedAt && nowMillis - issuedAt <= NEW_TOKEN_LIFETIME_MS
        } catch (_: Exception) {
            false
        }
    }

    /**
     * True when [token] says it's one of our Retry tokens. Its first byte is
     * the kind in the clear, so a Retry token that no longer opens can be
     * told from a NEW_TOKEN one (RFC 9000 §8.1.2: the client won't take a
     * second Retry, so a bad Retry token ends the attempt instead).
     */
    fun isRetryToken(token: ByteArray): Boolean = token.isNotEmpty() && token[0] == KIND_RETRY.toByte()

    private fun aad(peer: UdpPeerAddress): ByteArray = peer.ip + byteArrayOf((peer.port ushr 8).toByte(), peer.port.toByte())

    companion object {
        private const val KIND_RETRY = 1
        private const val KIND_NEW_TOKEN = 2

        /** How long a NEW_TOKEN token lets a returning client skip address validation. */
        const val NEW_TOKEN_LIFETIME_MS = 24L * 60L * 60L * 1000L

        /** A Retry token only has to outlive one round trip. */
        const val RETRY_TOKEN_LIFETIME_MS = 10_000L
    }
}

/** Stateless reset tokens (RFC 9000 §10.3.2): an HMAC of the connection ID under a per-server key. */
internal class StatelessResetTokens(
    private val key: ByteArray = RandomInstance.bytes(32),
) {
    fun tokenFor(cid: ConnectionId): ByteArray {
        val mac = MacInstance("HmacSHA256", key)
        mac.update(cid.bytes)
        return mac.doFinal().copyOfRange(0, 16)
    }
}
