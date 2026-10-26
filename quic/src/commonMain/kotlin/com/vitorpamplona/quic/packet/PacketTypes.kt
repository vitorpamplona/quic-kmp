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
package com.vitorpamplona.quic.packet

import com.vitorpamplona.quic.connection.PacketNumberSpace

/**
 * Long-header packet types per RFC 9000 §17.2. [code] is the QUIC v1 wire value of
 * the two type bits; QUIC v2 (RFC 9369 §3.2) rotates them, so code that reads or
 * writes a header goes through [wireBits] / [fromWireBits] with the packet's version.
 */
enum class LongHeaderType(
    val code: Int,
    val space: PacketNumberSpace,
    private val v2Code: Int,
) {
    INITIAL(0x00, PacketNumberSpace.INITIAL, 0x01),
    ZERO_RTT(0x01, PacketNumberSpace.APPLICATION, 0x02),
    HANDSHAKE(0x02, PacketNumberSpace.HANDSHAKE, 0x03),
    RETRY(0x03, PacketNumberSpace.INITIAL, 0x00), // retry has no PN space, INITIAL is a placeholder
    ;

    /** The two type bits this packet type carries in a long header of [version]. */
    fun wireBits(version: Int): Int = if (version == QuicVersion.V2) v2Code else code

    companion object {
        fun fromTypeBits(bits: Int): LongHeaderType = entries.firstOrNull { it.code == bits } ?: error("unknown long-header type bits: $bits")

        /** Decode the two type bits of a long header carrying [version]. */
        fun fromWireBits(
            bits: Int,
            version: Int,
        ): LongHeaderType =
            if (version == QuicVersion.V2) {
                entries.firstOrNull { it.v2Code == bits } ?: error("unknown long-header type bits: $bits")
            } else {
                fromTypeBits(bits)
            }
    }
}

/** QUIC versions we recognise. */
object QuicVersion {
    const val V1: Int = 0x00000001

    /** RFC 9369 QUIC version 2. Same wire image as v1 apart from the version-specific salts, labels and type bits. */
    const val V2: Int = 0x6b3343cf
    const val VERSION_NEGOTIATION: Int = 0x00000000

    /** Versions this stack can speak, in our order of preference for Version Negotiation. */
    val SUPPORTED: List<Int> = listOf(V1, V2)

    fun isSupported(version: Int): Boolean = version == V1 || version == V2

    /** HKDF label prefix for packet-protection keys (RFC 9001 §5.1, RFC 9369 §3.3.2). */
    internal fun labelPrefix(version: Int): String = if (version == V2) "quicv2" else "quic"

    /** The 1-RTT key-update label (RFC 9001 §6.1, RFC 9369 §3.3.2). */
    internal fun keyUpdateLabel(version: Int): String = labelPrefix(version) + " ku"

    /** qlog / log rendering: `v1`, `v2`, or the hex value. */
    fun name(version: Int): String =
        when (version) {
            V1 -> "v1"
            V2 -> "v2"
            else -> "0x" + version.toUInt().toString(16)
        }

    /**
     * RFC 9000 §6 / interop runner convention: a "force VN" version
     * number that no QUIC server is allowed to support. Sending this
     * in the first Initial guarantees the server replies with a
     * Version Negotiation packet listing the versions it actually
     * supports. The interop runner's `versionnegotiation` testcase
     * uses this to drive the client through the VN code path.
     *
     * Value 0x1a2a3a4a is conventional for this purpose; any
     * non-spec-assigned 32-bit value would work equally well.
     */
    const val FORCE_VERSION_NEGOTIATION: Int = 0x1a2a3a4a
}
