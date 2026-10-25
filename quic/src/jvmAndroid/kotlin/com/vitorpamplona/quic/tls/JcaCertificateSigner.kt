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

import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * [TlsCertificateSigner] backed by the platform JCA: ECDSA (P-256, P-384),
 * RSA-PSS and Ed25519 (Android 13+) private keys.
 *
 * [fromPem] reads the usual server files: a certificate chain (leaf first) and
 * a private key in PKCS#8 (`BEGIN PRIVATE KEY`), SEC1 (`BEGIN EC PRIVATE KEY`,
 * what `openssl ecparam -genkey` writes) or PKCS#1 (`BEGIN RSA PRIVATE KEY`).
 */
class JcaCertificateSigner(
    private val privateKey: PrivateKey,
    override val certificateChain: List<ByteArray>,
) : TlsCertificateSigner {
    override val signatureSchemes: List<Int> =
        when {
            privateKey is ECPrivateKey -> {
                when (privateKey.params.order.bitLength()) {
                    256 -> listOf(TlsConstants.SIG_ECDSA_SECP256R1_SHA256)
                    384 -> listOf(TlsConstants.SIG_ECDSA_SECP384R1_SHA384)
                    else -> emptyList()
                }
            }

            privateKey is RSAPrivateKey -> {
                listOf(TlsConstants.SIG_RSA_PSS_RSAE_SHA256, TlsConstants.SIG_RSA_PSS_RSAE_SHA384, TlsConstants.SIG_RSA_PSS_RSAE_SHA512)
            }

            privateKey.algorithm == "Ed25519" || privateKey.algorithm == "EdDSA" -> {
                listOf(TlsConstants.SIG_ED25519)
            }

            else -> {
                emptyList()
            }
        }

    init {
        require(certificateChain.isNotEmpty()) { "certificate chain is empty" }
        require(signatureSchemes.isNotEmpty()) { "unsupported private key type ${privateKey.algorithm}" }
    }

    override fun sign(
        scheme: Int,
        content: ByteArray,
    ): ByteArray = CertificateVerifySignature.sign(privateKey, scheme, content)

    companion object {
        fun fromPem(
            certificatePem: String,
            privateKeyPem: String,
        ): JcaCertificateSigner {
            val certs = pemBlocks(certificatePem).filter { it.first == "CERTIFICATE" }.map { it.second }
            val (label, der) =
                pemBlocks(privateKeyPem).firstOrNull { it.first.endsWith("PRIVATE KEY") }
                    ?: throw IllegalArgumentException("no private key in PEM")
            val pkcs8 =
                when (label) {
                    "PRIVATE KEY" -> der
                    "EC PRIVATE KEY" -> sec1ToPkcs8(der)
                    "RSA PRIVATE KEY" -> pkcs1ToPkcs8(der)
                    else -> throw IllegalArgumentException("unsupported key PEM '$label'")
                }
            return JcaCertificateSigner(loadPkcs8(pkcs8), certs)
        }

        private fun loadPkcs8(der: ByteArray): PrivateKey {
            val spec = PKCS8EncodedKeySpec(der)
            for (alg in listOf("EC", "RSA", "Ed25519")) {
                runCatching { return KeyFactory.getInstance(alg).generatePrivate(spec) }
            }
            throw IllegalArgumentException("private key is not EC, RSA or Ed25519")
        }

        private fun pemBlocks(pem: String): List<Pair<String, ByteArray>> {
            val out = ArrayList<Pair<String, ByteArray>>()
            val re = Regex("-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \\1-----", RegexOption.DOT_MATCHES_ALL)
            for (m in re.findAll(pem)) {
                out += m.groupValues[1] to Base64.getMimeDecoder().decode(m.groupValues[2].trim())
            }
            return out
        }

        // OIDs, DER-encoded without tag/length.
        private val OID_EC_PUBLIC_KEY = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01)
        private val OID_RSA_ENCRYPTION = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x01, 0x01)

        /** RFC 5915 SEC1 ECPrivateKey → PKCS#8, taking the curve from its [0] parameters. */
        private fun sec1ToPkcs8(sec1: ByteArray): ByteArray {
            val curve = findCurveOid(sec1) ?: throw IllegalArgumentException("SEC1 key without curve parameters")
            val algId = der(0x30, der(0x06, OID_EC_PUBLIC_KEY) + der(0x06, curve))
            return der(0x30, der(0x02, byteArrayOf(0)) + algId + der(0x04, sec1))
        }

        /** RFC 8017 RSAPrivateKey → PKCS#8. */
        private fun pkcs1ToPkcs8(pkcs1: ByteArray): ByteArray {
            val algId = der(0x30, der(0x06, OID_RSA_ENCRYPTION) + byteArrayOf(0x05, 0x00))
            return der(0x30, der(0x02, byteArrayOf(0)) + algId + der(0x04, pkcs1))
        }

        /** The OID inside the `[0] parameters` element of a SEC1 ECPrivateKey. */
        private fun findCurveOid(sec1: ByteArray): ByteArray? {
            var pos = 0
            val (_, seqStart) = readHeader(sec1, pos)
            pos = seqStart
            while (pos < sec1.size) {
                val tag = sec1[pos].toInt() and 0xFF
                val (len, valueStart) = readHeader(sec1, pos)
                if (tag == 0xA0) {
                    val (oidLen, oidStart) = readHeader(sec1, valueStart)
                    return sec1.copyOfRange(oidStart, oidStart + oidLen)
                }
                pos = valueStart + len
            }
            return null
        }

        /** (length, offset of value) for the DER element at [pos]. */
        private fun readHeader(
            der: ByteArray,
            pos: Int,
        ): Pair<Int, Int> {
            val first = der[pos + 1].toInt() and 0xFF
            if (first < 0x80) return first to pos + 2
            val n = first and 0x7F
            var len = 0
            for (i in 0 until n) len = (len shl 8) or (der[pos + 2 + i].toInt() and 0xFF)
            return len to pos + 2 + n
        }

        private fun der(
            tag: Int,
            value: ByteArray,
        ): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(tag)
            val len = value.size
            when {
                len < 0x80 -> {
                    out.write(len)
                }

                len < 0x100 -> {
                    out.write(0x81)
                    out.write(len)
                }

                else -> {
                    out.write(0x82)
                    out.write(len ushr 8)
                    out.write(len and 0xFF)
                }
            }
            out.write(value)
            return out.toByteArray()
        }
    }
}
