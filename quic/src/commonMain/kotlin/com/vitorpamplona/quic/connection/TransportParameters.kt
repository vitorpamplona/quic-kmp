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

import com.vitorpamplona.quic.QuicCodecException
import com.vitorpamplona.quic.QuicReader
import com.vitorpamplona.quic.QuicWriter
import com.vitorpamplona.quic.Varint

/**
 * QUIC transport parameter identifiers per RFC 9000 §18.2 + RFC 9221 (datagrams).
 *
 * Each parameter is carried as `(id varint)(length varint)(value)`.
 */
object TransportParameterId {
    const val ORIGINAL_DESTINATION_CONNECTION_ID: Long = 0x00
    const val MAX_IDLE_TIMEOUT: Long = 0x01
    const val STATELESS_RESET_TOKEN: Long = 0x02
    const val MAX_UDP_PAYLOAD_SIZE: Long = 0x03
    const val INITIAL_MAX_DATA: Long = 0x04
    const val INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: Long = 0x05
    const val INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: Long = 0x06
    const val INITIAL_MAX_STREAM_DATA_UNI: Long = 0x07
    const val INITIAL_MAX_STREAMS_BIDI: Long = 0x08
    const val INITIAL_MAX_STREAMS_UNI: Long = 0x09
    const val ACK_DELAY_EXPONENT: Long = 0x0a
    const val MAX_ACK_DELAY: Long = 0x0b
    const val DISABLE_ACTIVE_MIGRATION: Long = 0x0c
    const val PREFERRED_ADDRESS: Long = 0x0d
    const val ACTIVE_CONNECTION_ID_LIMIT: Long = 0x0e
    const val INITIAL_SOURCE_CONNECTION_ID: Long = 0x0f
    const val RETRY_SOURCE_CONNECTION_ID: Long = 0x10

    /** RFC 9221 — `max_datagram_frame_size`. */
    const val MAX_DATAGRAM_FRAME_SIZE: Long = 0x20

    /** RFC 9368 §3 — `version_information`. */
    const val VERSION_INFORMATION: Long = 0x11

    /** draft-ietf-quic-ack-frequency §3: the smallest ACK delay we can do, in microseconds. */
    const val MIN_ACK_DELAY: Long = 0xff04de1bL
}

/**
 * RFC 9000 §18.2 `preferred_address`: a server address (per family) the client
 * may migrate to once the handshake is confirmed, plus the connection ID
 * (sequence number 1, §5.1.1) and stateless-reset token to use there.
 */
class PreferredAddress(
    val ipv4Address: ByteArray,
    val ipv4Port: Int,
    val ipv6Address: ByteArray,
    val ipv6Port: Int,
    val connectionId: ByteArray,
    val statelessResetToken: ByteArray,
) {
    /** Dotted-quad IPv4 address, or null when the server offered none (all-zero address or port). */
    val ipv4Host: String?
        get() =
            if (ipv4Port == 0 || ipv4Address.all { it == 0.toByte() }) {
                null
            } else {
                ipv4Address.joinToString(".") { (it.toInt() and 0xFF).toString() }
            }

    /** Colon-hex IPv6 address, or null when the server offered none. */
    val ipv6Host: String?
        get() =
            if (ipv6Port == 0 || ipv6Address.all { it == 0.toByte() }) {
                null
            } else {
                (0 until 8).joinToString(":") { i ->
                    (((ipv6Address[2 * i].toInt() and 0xFF) shl 8) or (ipv6Address[2 * i + 1].toInt() and 0xFF)).toString(16)
                }
            }

    fun encode(): ByteArray {
        val w = QuicWriter()
        w.writeBytes(ipv4Address)
        w.writeUint16(ipv4Port)
        w.writeBytes(ipv6Address)
        w.writeUint16(ipv6Port)
        w.writeByte(connectionId.size)
        w.writeBytes(connectionId)
        w.writeBytes(statelessResetToken)
        return w.toByteArray()
    }

    companion object {
        fun decode(bytes: ByteArray): PreferredAddress {
            val r = QuicReader(bytes)
            val v4 = r.readBytes(4)
            val v4Port = r.readUint16()
            val v6 = r.readBytes(16)
            val v6Port = r.readUint16()
            val cidLen = r.readByte()
            // §18.2: a server that uses zero-length connection IDs MUST NOT send a preferred address.
            if (cidLen !in 1..20) throw QuicCodecException("preferred_address connection ID length $cidLen")
            val cid = r.readBytes(cidLen)
            val token = r.readBytes(16)
            if (r.hasMore()) throw QuicCodecException("preferred_address has ${r.remaining} trailing bytes")
            return PreferredAddress(v4, v4Port, v6, v6Port, cid, token)
        }
    }
}

/**
 * RFC 9368 §3 Version Information: the version the sender chose for the
 * connection, plus the versions it offers (client) or has fully deployed
 * (server).
 */
data class VersionInformation(
    val chosenVersion: Int,
    val availableVersions: List<Int>,
) {
    fun encode(): ByteArray {
        val w = QuicWriter()
        w.writeUint32(chosenVersion)
        for (v in availableVersions) w.writeUint32(v)
        return w.toByteArray()
    }

    companion object {
        /**
         * RFC 9368 §4: a length that isn't a positive multiple of four, or a zero
         * version anywhere, is a parsing failure (TRANSPORT_PARAMETER_ERROR).
         */
        fun decode(bytes: ByteArray): VersionInformation {
            if (bytes.isEmpty() || bytes.size % 4 != 0) {
                throw QuicCodecException("version_information length ${bytes.size} is not a positive multiple of 4")
            }
            val r = QuicReader(bytes)
            val chosen = r.readUint32().toInt()
            val available = ArrayList<Int>(bytes.size / 4 - 1)
            while (r.hasMore()) available += r.readUint32().toInt()
            if (chosen == 0 || available.any { it == 0 }) {
                throw QuicCodecException("version_information carries version 0")
            }
            return VersionInformation(chosen, available)
        }
    }
}

/**
 * RFC 9000 §18.2 default values for parameters that are NOT advertised
 * by the peer. Surfacing them as constants so the parser / writer can
 * use them as the "peer didn't tell us" fallback without each call site
 * hard-coding the numeric default.
 */
object TransportParameterDefaults {
    /** §18.2: default `ack_delay_exponent` is 3 if not advertised. */
    const val ACK_DELAY_EXPONENT: Long = 3L

    /** §18.2: default `max_ack_delay` is 25 ms if not advertised. */
    const val MAX_ACK_DELAY_MS: Long = 25L

    /** §18.2: default `active_connection_id_limit` is 2 if not advertised. */
    const val ACTIVE_CONNECTION_ID_LIMIT: Long = 2L
}

/**
 * QUIC transport parameters as exchanged inside the TLS QUIC transport_params
 * extension.
 *
 * Only the parameters we actually advertise / interpret are surfaced as named
 * fields. Unknown parameters are kept in [unknown] to be re-emitted verbatim
 * if needed (we don't currently echo).
 */
data class TransportParameters(
    val initialMaxData: Long? = null,
    val initialMaxStreamDataBidiLocal: Long? = null,
    val initialMaxStreamDataBidiRemote: Long? = null,
    val initialMaxStreamDataUni: Long? = null,
    val initialMaxStreamsBidi: Long? = null,
    val initialMaxStreamsUni: Long? = null,
    val maxIdleTimeoutMillis: Long? = null,
    val maxUdpPayloadSize: Long? = null,
    val ackDelayExponent: Long? = null,
    val maxAckDelay: Long? = null,
    val activeConnectionIdLimit: Long? = null,
    val disableActiveMigration: Boolean = false,
    val initialSourceConnectionId: ByteArray? = null,
    val originalDestinationConnectionId: ByteArray? = null,
    val retrySourceConnectionId: ByteArray? = null,
    val statelessResetToken: ByteArray? = null,
    val maxDatagramFrameSize: Long? = null,
    val unknown: Map<Long, ByteArray> = emptyMap(),
    val versionInformation: VersionInformation? = null,
    val preferredAddress: PreferredAddress? = null,
    /** draft-ietf-quic-ack-frequency `min_ack_delay`, microseconds; non-null means ACK_FREQUENCY is welcome. */
    val minAckDelayMicros: Long? = null,
) {
    fun encode(): ByteArray {
        val w = QuicWriter()

        fun writeVarintParam(
            id: Long,
            value: Long,
        ) {
            w.writeVarint(id)
            w.writeVarint(Varint.size(value).toLong())
            w.writeVarint(value)
        }

        fun writeBytesParam(
            id: Long,
            value: ByteArray,
        ) {
            w.writeVarint(id)
            w.writeVarint(value.size.toLong())
            w.writeBytes(value)
        }

        fun writeFlagParam(id: Long) {
            w.writeVarint(id)
            w.writeVarint(0L)
        }

        initialMaxData?.let { writeVarintParam(TransportParameterId.INITIAL_MAX_DATA, it) }
        initialMaxStreamDataBidiLocal?.let { writeVarintParam(TransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, it) }
        initialMaxStreamDataBidiRemote?.let { writeVarintParam(TransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, it) }
        initialMaxStreamDataUni?.let { writeVarintParam(TransportParameterId.INITIAL_MAX_STREAM_DATA_UNI, it) }
        initialMaxStreamsBidi?.let { writeVarintParam(TransportParameterId.INITIAL_MAX_STREAMS_BIDI, it) }
        initialMaxStreamsUni?.let { writeVarintParam(TransportParameterId.INITIAL_MAX_STREAMS_UNI, it) }
        maxIdleTimeoutMillis?.let { writeVarintParam(TransportParameterId.MAX_IDLE_TIMEOUT, it) }
        maxUdpPayloadSize?.let { writeVarintParam(TransportParameterId.MAX_UDP_PAYLOAD_SIZE, it) }
        ackDelayExponent?.let { writeVarintParam(TransportParameterId.ACK_DELAY_EXPONENT, it) }
        maxAckDelay?.let { writeVarintParam(TransportParameterId.MAX_ACK_DELAY, it) }
        activeConnectionIdLimit?.let { writeVarintParam(TransportParameterId.ACTIVE_CONNECTION_ID_LIMIT, it) }
        if (disableActiveMigration) writeFlagParam(TransportParameterId.DISABLE_ACTIVE_MIGRATION)
        initialSourceConnectionId?.let { writeBytesParam(TransportParameterId.INITIAL_SOURCE_CONNECTION_ID, it) }
        originalDestinationConnectionId?.let { writeBytesParam(TransportParameterId.ORIGINAL_DESTINATION_CONNECTION_ID, it) }
        retrySourceConnectionId?.let { writeBytesParam(TransportParameterId.RETRY_SOURCE_CONNECTION_ID, it) }
        statelessResetToken?.let { writeBytesParam(TransportParameterId.STATELESS_RESET_TOKEN, it) }
        maxDatagramFrameSize?.let { writeVarintParam(TransportParameterId.MAX_DATAGRAM_FRAME_SIZE, it) }
        versionInformation?.let { writeBytesParam(TransportParameterId.VERSION_INFORMATION, it.encode()) }
        preferredAddress?.let { writeBytesParam(TransportParameterId.PREFERRED_ADDRESS, it.encode()) }
        minAckDelayMicros?.let { writeVarintParam(TransportParameterId.MIN_ACK_DELAY, it) }
        for ((id, bytes) in unknown) writeBytesParam(id, bytes)

        return w.toByteArray()
    }

    companion object {
        fun decode(bytes: ByteArray): TransportParameters {
            val r = QuicReader(bytes)
            var initialMaxData: Long? = null
            var initialMaxStreamDataBidiLocal: Long? = null
            var initialMaxStreamDataBidiRemote: Long? = null
            var initialMaxStreamDataUni: Long? = null
            var initialMaxStreamsBidi: Long? = null
            var initialMaxStreamsUni: Long? = null
            var maxIdleTimeoutMillis: Long? = null
            var maxUdpPayloadSize: Long? = null
            var ackDelayExponent: Long? = null
            var maxAckDelay: Long? = null
            var minAckDelayMicros: Long? = null
            var activeConnectionIdLimit: Long? = null
            var disableActiveMigration = false
            var initialSourceConnectionId: ByteArray? = null
            var originalDestinationConnectionId: ByteArray? = null
            var retrySourceConnectionId: ByteArray? = null
            var statelessResetToken: ByteArray? = null
            var maxDatagramFrameSize: Long? = null
            var versionInformation: VersionInformation? = null
            var preferredAddress: PreferredAddress? = null
            val unknown = mutableMapOf<Long, ByteArray>()

            while (r.hasMore()) {
                val id = r.readVarint()
                val len = r.readVarint().toInt()
                val sub = QuicReader(r.readBytes(len))
                when (id) {
                    TransportParameterId.INITIAL_MAX_DATA -> initialMaxData = sub.readVarint()
                    TransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL -> initialMaxStreamDataBidiLocal = sub.readVarint()
                    TransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE -> initialMaxStreamDataBidiRemote = sub.readVarint()
                    TransportParameterId.INITIAL_MAX_STREAM_DATA_UNI -> initialMaxStreamDataUni = sub.readVarint()
                    TransportParameterId.INITIAL_MAX_STREAMS_BIDI -> initialMaxStreamsBidi = sub.readVarint()
                    TransportParameterId.INITIAL_MAX_STREAMS_UNI -> initialMaxStreamsUni = sub.readVarint()
                    TransportParameterId.MAX_IDLE_TIMEOUT -> maxIdleTimeoutMillis = sub.readVarint()
                    TransportParameterId.MAX_UDP_PAYLOAD_SIZE -> maxUdpPayloadSize = sub.readVarint()
                    TransportParameterId.ACK_DELAY_EXPONENT -> ackDelayExponent = sub.readVarint()
                    TransportParameterId.MAX_ACK_DELAY -> maxAckDelay = sub.readVarint()
                    TransportParameterId.ACTIVE_CONNECTION_ID_LIMIT -> activeConnectionIdLimit = sub.readVarint()
                    TransportParameterId.DISABLE_ACTIVE_MIGRATION -> disableActiveMigration = true
                    TransportParameterId.INITIAL_SOURCE_CONNECTION_ID -> initialSourceConnectionId = sub.src.copyOfRange(0, len)
                    TransportParameterId.ORIGINAL_DESTINATION_CONNECTION_ID -> originalDestinationConnectionId = sub.src.copyOfRange(0, len)
                    TransportParameterId.RETRY_SOURCE_CONNECTION_ID -> retrySourceConnectionId = sub.src.copyOfRange(0, len)
                    TransportParameterId.STATELESS_RESET_TOKEN -> statelessResetToken = sub.src.copyOfRange(0, len)
                    TransportParameterId.MAX_DATAGRAM_FRAME_SIZE -> maxDatagramFrameSize = sub.readVarint()
                    TransportParameterId.VERSION_INFORMATION -> versionInformation = VersionInformation.decode(sub.src.copyOfRange(0, len))
                    TransportParameterId.PREFERRED_ADDRESS -> preferredAddress = PreferredAddress.decode(sub.src.copyOfRange(0, len))
                    TransportParameterId.MIN_ACK_DELAY -> minAckDelayMicros = sub.readVarint()
                    else -> unknown[id] = sub.src.copyOfRange(0, len)
                }
            }
            return TransportParameters(
                initialMaxData = initialMaxData,
                initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal,
                initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote,
                initialMaxStreamDataUni = initialMaxStreamDataUni,
                initialMaxStreamsBidi = initialMaxStreamsBidi,
                initialMaxStreamsUni = initialMaxStreamsUni,
                maxIdleTimeoutMillis = maxIdleTimeoutMillis,
                maxUdpPayloadSize = maxUdpPayloadSize,
                ackDelayExponent = ackDelayExponent,
                maxAckDelay = maxAckDelay,
                minAckDelayMicros = minAckDelayMicros,
                activeConnectionIdLimit = activeConnectionIdLimit,
                disableActiveMigration = disableActiveMigration,
                initialSourceConnectionId = initialSourceConnectionId,
                originalDestinationConnectionId = originalDestinationConnectionId,
                retrySourceConnectionId = retrySourceConnectionId,
                statelessResetToken = statelessResetToken,
                maxDatagramFrameSize = maxDatagramFrameSize,
                unknown = unknown,
                versionInformation = versionInformation,
                preferredAddress = preferredAddress,
            )
        }
    }
}
