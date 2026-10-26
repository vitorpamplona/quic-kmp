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

import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.quic.QuicReader
import com.vitorpamplona.quic.QuicWriter
import com.vitorpamplona.quic.crypto.Aes128Gcm

/**
 * A server's certificate chain and the private key behind its leaf, as the
 * TLS server needs them: the chain goes into the Certificate message and
 * [sign] produces the CertificateVerify signature (RFC 8446 §4.4.2-§4.4.3).
 *
 * The JVM/Android implementation is `JcaCertificateSigner`, which loads PEM
 * files and signs through the platform's JCA.
 */
interface TlsCertificateSigner {
    /** DER-encoded certificates, leaf first. */
    val certificateChain: List<ByteArray>

    /** Signature schemes this key can produce (RFC 8446 §4.2.3), most preferred first. */
    val signatureSchemes: List<Int>

    /** Sign [content] with [scheme], one of [signatureSchemes]. */
    fun sign(
        scheme: Int,
        content: ByteArray,
    ): ByteArray
}

/** RFC 8446 §4.4.3: what a server's CertificateVerify signs. */
fun serverCertificateVerifyContent(transcriptHash: ByteArray): ByteArray {
    val context = "TLS 1.3, server CertificateVerify".encodeToByteArray()
    val out = ByteArray(64 + context.size + 1 + transcriptHash.size)
    for (i in 0 until 64) out[i] = 0x20
    context.copyInto(out, 64)
    out[64 + context.size] = 0x00
    transcriptHash.copyInto(out, 64 + context.size + 1)
    return out
}

/**
 * What a server needs to resume a session from a ticket it issued: the
 * ticket is this state sealed under the server's [TlsSessionTicketKeys].
 */
class TlsSessionTicketState(
    val psk: ByteArray,
    val cipherSuite: Int,
    val issuedAtMillis: Long,
    val ticketAgeAdd: Long,
    val lifetimeSec: Long,
    val maxEarlyDataSize: Long,
    val alpn: ByteArray?,
    /** The QUIC version of the connection that issued it (RFC 9369 §5: tickets are version-bound). */
    val quicVersion: Int,
) {
    fun encode(): ByteArray {
        val w = QuicWriter()
        w.writeByte(FORMAT)
        w.writeTlsOpaque1(psk)
        w.writeUint16(cipherSuite)
        w.writeUint32((issuedAtMillis ushr 32).toInt())
        w.writeUint32(issuedAtMillis.toInt())
        w.writeUint32(ticketAgeAdd.toInt())
        w.writeUint32(lifetimeSec.toInt())
        w.writeUint32(maxEarlyDataSize.toInt())
        w.writeTlsOpaque1(alpn ?: ByteArray(0))
        w.writeUint32(quicVersion)
        return w.toByteArray()
    }

    companion object {
        private const val FORMAT = 1

        fun decode(bytes: ByteArray): TlsSessionTicketState? =
            runCatching {
                val r = QuicReader(bytes)
                if (r.readByte() != FORMAT) return null
                val psk = r.readTlsOpaque1()
                val cs = r.readUint16()
                val hi = r.readUint32() and 0xFFFFFFFFL
                val lo = r.readUint32() and 0xFFFFFFFFL
                val ageAdd = r.readUint32() and 0xFFFFFFFFL
                val lifetime = r.readUint32() and 0xFFFFFFFFL
                val maxEarly = r.readUint32() and 0xFFFFFFFFL
                val alpn = r.readTlsOpaque1().takeIf { it.isNotEmpty() }
                val version = r.readUint32().toInt()
                TlsSessionTicketState(psk, cs, (hi shl 32) or lo, ageAdd, lifetime, maxEarly, alpn, version)
            }.getOrNull()
    }
}

/**
 * Seals and opens session tickets (RFC 8446 §4.6.1) with AES-128-GCM under a
 * server-held key, and remembers which tickets already carried 0-RTT so a
 * replayed ClientHello can't get its early data accepted twice (§8.1,
 * single-use tickets). Share one instance across a server's connections.
 */
class TlsSessionTicketKeys(
    private val key: ByteArray = RandomInstance.bytes(16),
    /** Most recent 0-RTT tickets remembered for replay protection. */
    private val replayWindow: Int = 4096,
) {
    private val earlyDataTickets = LinkedHashSet<String>()
    private val lock = com.vitorpamplona.quic.SynchronizedObject()

    fun seal(state: TlsSessionTicketState): ByteArray {
        val nonce = RandomInstance.bytes(12)
        val sealed = Aes128Gcm.seal(key, nonce, TICKET_AAD, state.encode())
        return nonce + sealed
    }

    fun open(ticket: ByteArray): TlsSessionTicketState? {
        if (ticket.size < 12 + 16) return null
        val plain = Aes128Gcm.open(key, ticket.copyOfRange(0, 12), TICKET_AAD, ticket.copyOfRange(12, ticket.size)) ?: return null
        return TlsSessionTicketState.decode(plain)
    }

    /** True the first time [ticket] asks for 0-RTT; false on any replay. */
    fun claimEarlyData(ticket: ByteArray): Boolean {
        val id = ticket.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
        return com.vitorpamplona.quic.synchronized(lock) {
            if (!earlyDataTickets.add(id)) return@synchronized false
            while (earlyDataTickets.size > replayWindow) earlyDataTickets.remove(earlyDataTickets.first())
            true
        }
    }

    private companion object {
        val TICKET_AAD = "quic-kmp ticket".encodeToByteArray()
    }
}
