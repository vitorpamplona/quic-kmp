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
import com.vitorpamplona.quic.QuicWriter

/**
 * Running hash over the concatenated handshake messages, per RFC 8446 §4.4.1.
 *
 * The transcript order is:
 *   ClientHello
 *   ServerHello
 *   EncryptedExtensions
 *   Certificate
 *   CertificateVerify
 *   server Finished
 *   client Finished
 *
 * Each message is appended with its 4-byte handshake header included.
 *
 * The hash is the negotiated cipher suite's, which a client learns only from
 * the ServerHello: until [select] picks it the messages are kept, and [peek]
 * hashes them under any hash. Once selected, each [snapshot] copies the
 * running digest and finishes the copy, so later [append] calls keep
 * extending the same hash. A platform digest that can't be copied (a few
 * Android 8–9 Conscrypt builds) falls back to hashing the kept messages at
 * each snapshot.
 */
class TlsTranscriptHash {
    /** The transcript's hash: SHA-256 until [select] says otherwise. */
    var hash: TlsHash = TlsHash.SHA256
        private set

    private var digest: DigestInstance? = null

    /** The messages so far; null once a copyable digest runs. */
    private var messages: MutableList<ByteArray>? = ArrayList()

    fun append(messageBytes: ByteArray) {
        digest?.update(messageBytes)
        messages?.add(messageBytes)
    }

    /** Fix the transcript's hash. Selecting again is a no-op for the same hash and an error for another. */
    fun select(hash: TlsHash) {
        if (digest != null) {
            check(hash === this.hash) { "transcript already hashed with ${this.hash}, not $hash" }
            return
        }
        this.hash = hash
        val d = hash.newDigest()
        val copyable =
            try {
                d.copy()
                true
            } catch (_: IllegalStateException) {
                false
            }
        messages?.forEach { d.update(it) }
        digest = d
        if (copyable) messages = null
    }

    /** The current transcript hash; selects the default hash if none was. */
    fun snapshot(): ByteArray {
        if (digest == null) select(hash)
        return peek(hash)
    }

    /**
     * Hash of the transcript followed by [extra], without appending it: a PSK
     * binder's input, or before the hash is selected the client's view of
     * its own ClientHello under the ticket's hash.
     */
    fun peek(
        hash: TlsHash,
        extra: ByteArray = ByteArray(0),
    ): ByteArray {
        val d = digest
        val kept = messages
        if (d != null) check(hash === this.hash) { "transcript hashed with ${this.hash}, not $hash" }
        if (d != null && kept == null) {
            val copy = d.copy()
            copy.update(extra)
            return copy.digest()
        }
        return hash.digest(*kept!!.toTypedArray(), extra)
    }

    /**
     * RFC 8446 §4.4.1: after a HelloRetryRequest the first ClientHello is
     * replaced by message_hash(Hash(ClientHello1)), under the retry's cipher
     * suite [hash], which this selects.
     */
    fun replaceWithMessageHash(hash: TlsHash) {
        check(digest == null) { "message_hash replaces the ClientHello before the hash is selected" }
        val kept = messages!!
        val clientHello1 = hash.digest(*kept.toTypedArray())
        kept.clear()
        kept.add(messageHash(clientHello1))
        select(hash)
    }

    companion object {
        /** The synthetic handshake message standing in for a ClientHello hashed to [clientHelloHash]. */
        fun messageHash(clientHelloHash: ByteArray): ByteArray {
            val w = QuicWriter()
            w.writeByte(TlsConstants.HS_MESSAGE_HASH)
            w.withUint24Length { writeBytes(clientHelloHash) }
            return w.toByteArray()
        }
    }
}
