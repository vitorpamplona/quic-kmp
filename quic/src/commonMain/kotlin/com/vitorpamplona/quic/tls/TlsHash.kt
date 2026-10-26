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
package com.vitorpamplona.quic.tls

import com.vitorpamplona.crypto.digest.DigestInstance
import com.vitorpamplona.crypto.kdf.Hkdf
import com.vitorpamplona.crypto.mac.MacInstance

/**
 * The hash a TLS 1.3 cipher suite runs its transcript and key schedule on
 * (RFC 8446 §7.1): SHA-256 for TLS_AES_128_GCM_SHA256 and
 * TLS_CHACHA20_POLY1305_SHA256, SHA-384 for TLS_AES_256_GCM_SHA384. Every
 * secret, binder and Finished MAC is [length] bytes long.
 */
class TlsHash private constructor(
    val digestAlgorithm: String,
    val hmacAlgorithm: String,
    val length: Int,
) {
    val hkdf: Hkdf = Hkdf(hmacAlgorithm)

    /** Hash of the empty string: the context of Derive-Secret(secret, "derived", ""). */
    internal val emptyHash: ByteArray = DigestInstance(digestAlgorithm).digest()

    internal fun newDigest(): DigestInstance = DigestInstance(digestAlgorithm)

    fun digest(vararg parts: ByteArray): ByteArray {
        val d = newDigest()
        for (p in parts) d.update(p)
        return d.digest()
    }

    fun hmac(
        key: ByteArray,
        data: ByteArray,
    ): ByteArray {
        val mac = MacInstance(hmacAlgorithm, key)
        mac.update(data)
        return mac.doFinal()
    }

    /** RFC 8446 §7.1 Derive-Secret(secret, label, transcriptHash). */
    fun deriveSecret(
        secret: ByteArray,
        label: String,
        transcriptHash: ByteArray,
    ): ByteArray = hkdf.expandLabel(secret, label, transcriptHash, length)

    /** RFC 8446 §7.1 HKDF-Expand-Label(secret, label, "", length). */
    fun expandLabel(
        secret: ByteArray,
        label: String,
        length: Int,
    ): ByteArray = hkdf.expandLabel(secret, label, ByteArray(0), length)

    override fun toString(): String = digestAlgorithm

    companion object {
        val SHA256: TlsHash = TlsHash("SHA-256", "HmacSHA256", 32)
        val SHA384: TlsHash = TlsHash("SHA-384", "HmacSHA384", 48)

        fun forCipherSuite(cipherSuite: Int): TlsHash = if (cipherSuite == TlsConstants.CIPHER_TLS_AES_256_GCM_SHA384) SHA384 else SHA256

        /** The hash a secret was derived with, read from its length (secrets are Hash.length bytes). */
        fun forSecret(secret: ByteArray): TlsHash =
            when (secret.size) {
                32 -> SHA256
                48 -> SHA384
                else -> throw IllegalArgumentException("a TLS 1.3 secret is 32 or 48 bytes, not ${secret.size}")
            }
    }
}
