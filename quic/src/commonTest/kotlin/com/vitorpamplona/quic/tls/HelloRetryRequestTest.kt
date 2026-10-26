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

import com.vitorpamplona.quic.QuicReader
import com.vitorpamplona.quic.QuicWriter
import com.vitorpamplona.quic.TlsAlertException
import kotlin.test.Test
import kotlin.test.assertFailsWith

/**
 * RFC 8446 §4.1.4 — HelloRetryRequest is a ServerHello whose `random` equals
 * the SHA-256 of the ASCII string "HelloRetryRequest". Our ClientHello
 * carries an X25519 share and lists X25519 and P-256; a server may ask for a
 * P-256 share or a cookie, and gets a second ClientHello. A retry that
 * changes nothing, or a second one, is refused (mapped by the QUIC layer to
 * CRYPTO_ERROR `0x100 + alert` per RFC 9001 §4.8).
 */
class HelloRetryRequestTest {
    private fun startedClient(): Pair<TlsClient, ByteArray> {
        val tls =
            TlsClient(
                serverName = "example.test",
                transportParameters = ByteArray(0),
                secretsListener = NoopSecretsListener,
                certificateValidator = PermissiveCertificateValidator(),
            )
        tls.start()
        return tls to tls.pollOutbound(TlsClient.Level.INITIAL)!!
    }

    @Test
    fun a_retry_for_the_group_we_already_sent_is_refused() {
        val (tls, _) = startedClient()
        val ex =
            assertFailsWith<TlsAlertException> {
                tls.pushHandshakeBytes(TlsClient.Level.INITIAL, buildHelloRetryRequest(TlsConstants.GROUP_X25519))
            }
        kotlin.test.assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, ex.alertCode)
    }

    @Test
    fun a_retry_for_p256_gets_a_second_client_hello_with_a_p256_share() {
        val (tls, ch1Bytes) = startedClient()
        val ch1 = ParsedClientHello.parse(ch1Bytes)
        kotlin.test.assertEquals(listOf(TlsConstants.GROUP_X25519, TlsConstants.GROUP_SECP256R1), ch1.supportedGroups)
        kotlin.test.assertNotNull(ch1.x25519KeyShare)

        tls.pushHandshakeBytes(TlsClient.Level.INITIAL, buildHelloRetryRequest(TlsConstants.GROUP_SECP256R1, cookie = byteArrayOf(0, 3, 7, 7, 7)))
        val ch2Bytes = kotlin.test.assertNotNull(tls.pollOutbound(TlsClient.Level.INITIAL))
        val ch2 = ParsedClientHello.parse(ch2Bytes)
        kotlin.test.assertContentEquals(ch1.random, ch2.random, "same random")
        kotlin.test.assertNull(ch2.x25519KeyShare)
        kotlin.test.assertEquals(65, ch2.p256KeyShare?.size)
        kotlin.test.assertEquals(TlsClient.State.WAITING_SERVER_HELLO, tls.state)

        val cookie = TlsExtension.decodeList(QuicReader(ch2Bytes, 4 + 2 + 32 + 1 + 2 + ch1.cipherSuites.size * 2 + 2, ch2Bytes.size)).single { it.type == TlsConstants.EXT_COOKIE }
        kotlin.test.assertContentEquals(byteArrayOf(0, 3, 7, 7, 7), cookie.data, "the cookie is echoed")
    }

    @Test
    fun a_retry_with_an_extension_it_may_not_carry_is_refused() {
        val (tls, _) = startedClient()
        val ex =
            assertFailsWith<TlsAlertException> {
                tls.pushHandshakeBytes(TlsClient.Level.INITIAL, buildHelloRetryRequest(TlsConstants.GROUP_SECP256R1, extraExtension = TlsConstants.EXT_PRE_SHARED_KEY))
            }
        kotlin.test.assertEquals(TlsConstants.ALERT_UNSUPPORTED_EXTENSION, ex.alertCode)
    }

    @Test
    fun a_retry_with_an_empty_cookie_is_refused() {
        val (tls, _) = startedClient()
        val ex =
            assertFailsWith<TlsAlertException> {
                tls.pushHandshakeBytes(TlsClient.Level.INITIAL, buildHelloRetryRequest(TlsConstants.GROUP_SECP256R1, cookie = byteArrayOf(0, 0)))
            }
        kotlin.test.assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.alertCode)
    }

    @Test
    fun a_second_retry_is_refused() {
        val (tls, _) = startedClient()
        tls.pushHandshakeBytes(TlsClient.Level.INITIAL, buildHelloRetryRequest(TlsConstants.GROUP_SECP256R1))
        val ex =
            assertFailsWith<TlsAlertException> {
                tls.pushHandshakeBytes(TlsClient.Level.INITIAL, buildHelloRetryRequest(TlsConstants.GROUP_SECP256R1))
            }
        kotlin.test.assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, ex.alertCode)
    }

    /**
     * Build a minimal HRR: handshake type 2 (ServerHello), with the magic
     * SHA-256("HelloRetryRequest") random, asking for [group] and echoing [cookie].
     */
    private fun buildHelloRetryRequest(
        group: Int,
        cookie: ByteArray? = null,
        extraExtension: Int? = null,
    ): ByteArray {
        val helloRetryRequestRandom =
            byteArrayOf(
                0xCF.toByte(),
                0x21.toByte(),
                0xAD.toByte(),
                0x74.toByte(),
                0xE5.toByte(),
                0x9A.toByte(),
                0x61.toByte(),
                0x11.toByte(),
                0xBE.toByte(),
                0x1D.toByte(),
                0x8C.toByte(),
                0x02.toByte(),
                0x1E.toByte(),
                0x65.toByte(),
                0xB8.toByte(),
                0x91.toByte(),
                0xC2.toByte(),
                0xA2.toByte(),
                0x11.toByte(),
                0x16.toByte(),
                0x7A.toByte(),
                0xBB.toByte(),
                0x8C.toByte(),
                0x5E.toByte(),
                0x07.toByte(),
                0x9E.toByte(),
                0x09.toByte(),
                0xE2.toByte(),
                0xC8.toByte(),
                0xA8.toByte(),
                0x33.toByte(),
                0x9C.toByte(),
            )
        val w = QuicWriter()
        w.writeByte(TlsConstants.HS_SERVER_HELLO)
        w.withUint24Length {
            writeUint16(TlsConstants.LEGACY_VERSION_TLS_1_2)
            writeBytes(helloRetryRequestRandom)
            writeByte(0) // legacy_session_id_echo: empty
            writeUint16(TlsConstants.CIPHER_TLS_AES_128_GCM_SHA256)
            writeByte(0) // null compression
            withUint16Length {
                // supported_versions = TLS 1.3
                writeUint16(TlsConstants.EXT_SUPPORTED_VERSIONS)
                withUint16Length { writeUint16(TlsConstants.VERSION_TLS_1_3) }
                writeUint16(TlsConstants.EXT_KEY_SHARE)
                withUint16Length { writeUint16(group) }
                if (cookie != null) {
                    writeUint16(TlsConstants.EXT_COOKIE)
                    writeTlsOpaque2(cookie)
                }
                if (extraExtension != null) {
                    writeUint16(extraExtension)
                    withUint16Length { writeUint16(0) }
                }
            }
        }
        return w.toByteArray()
    }

    private object NoopSecretsListener : TlsSecretsListener {
        override fun onHandshakeKeysReady(
            cipherSuite: Int,
            clientSecret: ByteArray,
            serverSecret: ByteArray,
        ) = Unit

        override fun onApplicationKeysReady(
            cipherSuite: Int,
            clientSecret: ByteArray,
            serverSecret: ByteArray,
        ) = Unit

        override fun onHandshakeComplete() = Unit
    }
}
