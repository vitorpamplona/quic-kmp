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

import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.quic.QuicCodecException
import kotlinx.cinterop.COpaquePointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFArrayCreate
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFErrorCopyDescription
import platform.CoreFoundation.CFErrorRef
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.CFStringGetCString
import platform.CoreFoundation.CFStringGetLength
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFStringEncodingUTF8
import platform.CoreFoundation.kCFTypeArrayCallBacks
import platform.Security.SecCertificateCreateWithData
import platform.Security.SecKeyAlgorithm
import platform.Security.SecKeyRef
import platform.Security.SecKeyVerifySignature
import platform.Security.SecPolicyCreateSSL
import platform.Security.SecTrustCopyKey
import platform.Security.SecTrustCreateWithCertificates
import platform.Security.SecTrustEvaluateWithError
import platform.Security.SecTrustRefVar
import platform.Security.errSecSuccess
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA256
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA384
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA256
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA384
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA512

/**
 * The server's certificate checked against the device's trust store, as JdkCertificateValidator
 * does on the JVM: Apple's Security framework validates the chain under the SSL policy for
 * [validateChain]'s host (which also matches the host against the leaf's names, IP literals
 * included), and the TLS 1.3 CertificateVerify is checked against the leaf's key with SecKey.
 * Ed25519 leaves, which SecKey does not take, are checked with crypto-kmp's Ed25519.
 *
 * One validator per connection: [verifySignature] reads the key [validateChain] kept.
 */
@OptIn(ExperimentalForeignApi::class)
class AppleCertificateValidator : CertificateValidator {
    private var leafKey: SecKeyRef? = null
    private var leafEd25519: ByteArray? = null

    override fun validateChain(
        chain: List<ByteArray>,
        expectedHost: String,
    ) {
        if (chain.isEmpty()) throw QuicCodecException("server sent empty certificate chain")
        val certificates =
            chain.map { der ->
                val data = der.toCFData() ?: throw QuicCodecException("certificate chain parse failed")
                val certificate = SecCertificateCreateWithData(kCFAllocatorDefault, data)
                CFRelease(data)
                certificate ?: throw QuicCodecException("certificate chain parse failed: not a DER certificate")
            }
        val host = CFStringCreateWithCString(kCFAllocatorDefault, expectedHost, kCFStringEncodingUTF8)
        val policy = SecPolicyCreateSSL(true, host)
        try {
            memScoped {
                val values = allocArray<COpaquePointerVar>(certificates.size)
                certificates.forEachIndexed { i, certificate -> values[i] = certificate }
                val array = CFArrayCreate(kCFAllocatorDefault, values, certificates.size.convert(), kCFTypeArrayCallBacks.ptr)
                val trust = alloc<SecTrustRefVar>()
                val status = SecTrustCreateWithCertificates(array, policy, trust.ptr)
                array?.let { CFRelease(it) }
                if (status != errSecSuccess) throw QuicCodecException("certificate chain validation failed: SecTrust status $status")
                val trustRef = trust.value ?: throw QuicCodecException("certificate chain validation failed")
                try {
                    val error = alloc<CFErrorRefVar>()
                    if (!SecTrustEvaluateWithError(trustRef, error.ptr)) {
                        val reason = error.value?.let { describe(it) } ?: "untrusted"
                        error.value?.let { CFRelease(it) }
                        throw QuicCodecException("certificate chain validation failed: $reason")
                    }
                    leafKey = SecTrustCopyKey(trustRef)
                    if (leafKey == null) leafEd25519 = ed25519PublicKeyOf(chain[0])
                } finally {
                    CFRelease(trustRef)
                }
            }
        } finally {
            certificates.forEach { CFRelease(it) }
            policy?.let { CFRelease(it) }
            host?.let { CFRelease(it) }
        }
    }

    override fun verifySignature(
        signatureAlgorithm: Int,
        signature: ByteArray,
        transcriptHash: ByteArray,
    ) {
        val signed = certificateVerifyContent(transcriptHash)
        if (signatureAlgorithm == TlsConstants.SIG_ED25519) {
            val key = leafEd25519 ?: throw QuicCodecException("CertificateVerify: Ed25519 signature from a non-Ed25519 certificate")
            if (!Ed25519.verify(signed, signature, key)) throw QuicCodecException("CertificateVerify signature did not verify")
            return
        }
        val key = leafKey ?: throw QuicCodecException("CertificateVerify before Certificate")
        val algorithm = secKeyAlgorithmFor(signatureAlgorithm)
        val data = signed.toCFData()
        val sig = signature.toCFData()
        try {
            val ok =
                memScoped {
                    val error = alloc<CFErrorRefVar>()
                    SecKeyVerifySignature(key, algorithm, data, sig, error.ptr).also { error.value?.let { CFRelease(it) } }
                }
            if (!ok) throw QuicCodecException("CertificateVerify signature did not verify")
        } finally {
            data?.let { CFRelease(it) }
            sig?.let { CFRelease(it) }
            CFRelease(key)
            leafKey = null
        }
    }

    /**
     * RFC 8446 §4.2.3's schemes for a CertificateVerify. rsa_pkcs1_* are forbidden there, so they
     * are refused, as on the JVM.
     */
    private fun secKeyAlgorithmFor(algorithm: Int): SecKeyAlgorithm? =
        when (algorithm) {
            TlsConstants.SIG_ECDSA_SECP256R1_SHA256 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA256
            TlsConstants.SIG_ECDSA_SECP384R1_SHA384 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA384
            TlsConstants.SIG_RSA_PSS_RSAE_SHA256 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA256
            TlsConstants.SIG_RSA_PSS_RSAE_SHA384 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA384
            TlsConstants.SIG_RSA_PSS_RSAE_SHA512 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA512
            else -> throw QuicCodecException("CertificateVerify: unsupported signature scheme 0x${algorithm.toString(16)}")
        }

    private fun describe(error: CFErrorRef): String {
        val text = CFErrorCopyDescription(error) ?: return "untrusted"
        return try {
            val length = CFStringGetLength(text).toInt() * 4 + 1
            val buffer = ByteArray(length)
            buffer.usePinned { CFStringGetCString(text, it.addressOf(0), length.convert(), kCFStringEncodingUTF8) }
            buffer.decodeToString().substringBefore('\u0000')
        } finally {
            CFRelease(text)
        }
    }
}

/** RFC 8446 §4.4.3: 64 spaces, the context string, a zero byte, then the transcript hash. */
internal fun certificateVerifyContent(transcriptHash: ByteArray): ByteArray {
    val context = "TLS 1.3, server CertificateVerify".encodeToByteArray()
    val content = ByteArray(64 + context.size + 1 + transcriptHash.size)
    for (i in 0 until 64) content[i] = 0x20
    context.copyInto(content, 64)
    content[64 + context.size] = 0x00
    transcriptHash.copyInto(content, 64 + context.size + 1)
    return content
}

/** An Ed25519 leaf's raw public key: its SubjectPublicKeyInfo is this fixed prefix and 32 bytes. */
internal fun ed25519PublicKeyOf(der: ByteArray): ByteArray? {
    val prefix = byteArrayOf(0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00)
    for (start in 0..der.size - prefix.size - 32) {
        var match = true
        for (i in prefix.indices) {
            if (der[start + i] != prefix[i]) {
                match = false
                break
            }
        }
        if (match) return der.copyOfRange(start + prefix.size, start + prefix.size + 32)
    }
    return null
}

@OptIn(ExperimentalForeignApi::class)
private fun ByteArray.toCFData(): CFDataRef? = usePinned { CFDataCreate(kCFAllocatorDefault, it.addressOf(0).reinterpret(), size.convert()) }

@OptIn(ExperimentalForeignApi::class)
actual fun systemCertificateValidator(): CertificateValidator = AppleCertificateValidator()
