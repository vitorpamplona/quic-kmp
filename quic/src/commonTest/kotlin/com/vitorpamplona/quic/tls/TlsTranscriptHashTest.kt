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

import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.crypto.sha2.sha384
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * Regression coverage for [TlsTranscriptHash] after the switch from the
 * O(n²) "concatenate-and-rehash on every snapshot" implementation to an
 * incremental digest, and its choice of hash (SHA-256, or SHA-384 for
 * TLS_AES_256_GCM_SHA384) once the cipher suite is known.
 *
 * The contract that production TLS code depends on:
 *
 *   1. snapshot() bytes equal the SHA-256 of all appended bytes in order.
 *   2. Multiple snapshots taken at the same point yield identical bytes.
 *   3. snapshot() must NOT consume the running hash — further append() calls
 *      keep extending the same digest. This is the non-obvious bit: a naive
 *      `digest.digest()` finalizes and resets, so without the clone trick a
 *      handshake-mid snapshot would silently corrupt later snapshots.
 *   4. Output is always 32 bytes, until SHA-384 is selected.
 */
class TlsTranscriptHashTest {
    @Test
    fun snapshot_matches_sha256_of_concatenated_bytes() {
        val transcript = TlsTranscriptHash()
        val msg1 = byteArrayOf(1, 2, 3, 4)
        val msg2 = byteArrayOf(5, 6, 7, 8, 9)
        transcript.append(msg1)
        transcript.append(msg2)

        val expected = sha256(msg1 + msg2)
        assertContentEquals(expected, transcript.snapshot())
    }

    @Test
    fun empty_transcript_hashes_empty_input() {
        val transcript = TlsTranscriptHash()
        assertContentEquals(sha256(ByteArray(0)), transcript.snapshot())
    }

    @Test
    fun output_is_always_32_bytes() {
        val transcript = TlsTranscriptHash()
        assertEquals(32, transcript.snapshot().size)
        transcript.append(byteArrayOf(0x42))
        assertEquals(32, transcript.snapshot().size)
    }

    @Test
    fun snapshot_does_not_consume_running_state() {
        // The bug we're guarding against: `MessageDigest.digest()` finalizes
        // and resets. If the implementation accidentally uses that instead of
        // cloning, the second snapshot would hash only the post-snapshot
        // bytes, not the full transcript. TLS 1.3 takes ≥3 snapshots per
        // handshake, so this would corrupt every later key.
        val transcript = TlsTranscriptHash()
        val ch = byteArrayOf(0x01, 0x00, 0x00, 0x04, 0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val sh = byteArrayOf(0x02, 0x00, 0x00, 0x04, 0xCA.toByte(), 0xFE.toByte(), 0xBA.toByte(), 0xBE.toByte())
        val ee = byteArrayOf(0x08, 0x00, 0x00, 0x02, 0x00, 0x00)

        transcript.append(ch)
        transcript.append(sh)
        val handshakeSnapshot = transcript.snapshot()

        transcript.append(ee)
        val applicationSnapshot = transcript.snapshot()

        // Both must be SHA-256 of their respective prefixes.
        assertContentEquals(sha256(ch + sh), handshakeSnapshot)
        assertContentEquals(sha256(ch + sh + ee), applicationSnapshot)
    }

    @Test
    fun two_snapshots_at_same_position_match() {
        val transcript = TlsTranscriptHash()
        transcript.append(byteArrayOf(0x10, 0x20, 0x30))
        val a = transcript.snapshot()
        val b = transcript.snapshot()
        assertContentEquals(a, b)
    }

    @Test
    fun snapshots_at_different_positions_differ() {
        // Sanity: bumping the transcript should produce a new hash. Catches
        // an implementation that accidentally caches and returns a stale
        // snapshot.
        val transcript = TlsTranscriptHash()
        transcript.append(byteArrayOf(0x00))
        val before = transcript.snapshot()
        transcript.append(byteArrayOf(0x01))
        val after = transcript.snapshot()
        assertFalse(before.contentEquals(after))
    }

    @Test
    fun the_hash_is_chosen_after_the_first_messages() {
        // A client hashes its ClientHello before the ServerHello names the suite.
        val transcript = TlsTranscriptHash()
        val ch = byteArrayOf(1, 0, 0, 1, 7)
        val sh = byteArrayOf(2, 0, 0, 1, 9)
        transcript.append(ch)
        assertContentEquals(sha384(ch), transcript.peek(TlsHash.SHA384))
        assertContentEquals(sha256(ch + sh), transcript.peek(TlsHash.SHA256, sh), "peek hashes extra bytes without appending them")
        transcript.select(TlsHash.SHA384)
        transcript.append(sh)
        val snapshot = transcript.snapshot()
        assertEquals(48, snapshot.size)
        assertContentEquals(sha384(ch + sh), snapshot)
        assertContentEquals(sha384(ch + sh + ch), transcript.peek(TlsHash.SHA384, ch))
        assertContentEquals(snapshot, transcript.snapshot(), "peek did not append")
    }

    @Test
    fun a_retry_replaces_the_client_hello_with_message_hash() {
        // RFC 8446 §4.4.1: message_hash = 254, 00 00 Hash.length, Hash(ClientHello1).
        val transcript = TlsTranscriptHash()
        val ch1 = byteArrayOf(1, 0, 0, 2, 5, 6)
        val hrr = byteArrayOf(2, 0, 0, 1, 3)
        transcript.append(ch1)
        transcript.replaceWithMessageHash(TlsHash.SHA384)
        transcript.append(hrr)
        val messageHash = byteArrayOf(254.toByte(), 0, 0, 48) + sha384(ch1)
        assertContentEquals(sha384(messageHash + hrr), transcript.snapshot())
    }
}
