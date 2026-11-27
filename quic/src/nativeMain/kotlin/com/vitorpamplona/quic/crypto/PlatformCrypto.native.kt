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
package com.vitorpamplona.quic.crypto

import com.vitorpamplona.crypto.aes.AESCBC
import com.vitorpamplona.crypto.aes.AESGCM
import com.vitorpamplona.crypto.chacha.ChaCha20Core

private val ZERO_IV = ByteArray(16)

/**
 * One AES block for header protection: a one-block CBC encryption under a zero IV is that block's
 * ECB encryption, so it is the first 16 bytes of crypto-kmp's AES-CBC output (CommonCrypto on
 * Apple, constant-time Kotlin elsewhere); the padding block after it is dropped.
 */
actual val PlatformAesOneBlock: AesOneBlockEncrypt =
    object : AesOneBlockEncrypt {
        override fun encrypt(
            key: ByteArray,
            block: ByteArray,
        ): ByteArray = AESCBC(key, ZERO_IV).encrypt(block.copyOf(16)).copyOf(16)

        override fun encryptInto(
            key: ByteArray,
            src: ByteArray,
            srcOffset: Int,
            dst: ByteArray,
            dstOffset: Int,
        ) {
            AESCBC(key, ZERO_IV).encrypt(src.copyOfRange(srcOffset, srcOffset + 16)).copyInto(dst, dstOffset, 0, 16)
        }
    }

/** The ChaCha20 block of RFC 8439, as the JVM uses, from crypto-kmp. */
actual val PlatformChaCha20Block: ChaCha20BlockEncrypt =
    ChaCha20BlockEncrypt { key, nonce, counter, plaintext ->
        ChaCha20Core.chaCha20Xor(plaintext, key, nonce, counter)
    }

actual fun bestAes128GcmAead(key: ByteArray): Aead = Aes128Gcm

actual fun bestAes256GcmAead(key: ByteArray): Aead = Aes256Gcm

actual fun bestChaCha20Poly1305Aead(key: ByteArray): Aead = ChaCha20Poly1305Aead

/** AES-256-GCM over crypto-kmp's AESGCM (CommonCrypto on Apple), for TLS_AES_256_GCM_SHA384. */
internal object Aes256Gcm : Aead() {
    override val keyLength = 32
    override val nonceLength = 12
    override val tagLength = 16

    // RFC 9001 §B.1: the same limits as AEAD_AES_128_GCM.
    override val confidentialityLimit: Long = 1L shl 23
    override val integrityLimit: Long = 1L shl 52

    override fun seal(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        require(key.size == keyLength) { "AES-256-GCM key must be 32 bytes" }
        require(nonce.size == nonceLength) { "AES-256-GCM nonce must be 12 bytes" }
        return AESGCM(key, nonce).encrypt(plaintext, aad)
    }

    override fun open(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray? {
        require(key.size == keyLength) { "AES-256-GCM key must be 32 bytes" }
        require(nonce.size == nonceLength) { "AES-256-GCM nonce must be 12 bytes" }
        return try {
            AESGCM(key, nonce).decrypt(ciphertext, aad)
        } catch (_: Throwable) {
            null
        }
    }
}
