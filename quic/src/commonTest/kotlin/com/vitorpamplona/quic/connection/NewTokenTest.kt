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

import com.vitorpamplona.quic.crypto.Aes128Gcm
import com.vitorpamplona.quic.crypto.AesEcbHeaderProtection
import com.vitorpamplona.quic.crypto.InitialSecrets
import com.vitorpamplona.quic.crypto.PlatformAesOneBlock
import com.vitorpamplona.quic.frame.NewTokenFrame
import com.vitorpamplona.quic.frame.QuicTransportError
import com.vitorpamplona.quic.packet.LongHeaderPacket
import com.vitorpamplona.quic.tls.PermissiveCertificateValidator
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** RFC 9000 §8.1.3 address-validation tokens from NEW_TOKEN. */
class NewTokenTest {
    @Test
    fun saved_token_goes_in_the_first_initial() {
        val token = byteArrayOf(1, 2, 3, 4, 5)
        val client =
            QuicConnection(
                serverName = "example.test",
                config = QuicConnectionConfig(),
                tlsCertificateValidator = PermissiveCertificateValidator(),
                addressValidationToken = token,
            )
        client.start()
        val datagram = drainOutbound(client, 0L)
        assertNotNull(datagram)
        val keys = InitialSecrets.derive(client.destinationConnectionId.bytes)
        val parsed =
            LongHeaderPacket.parseAndDecrypt(
                datagram,
                0,
                Aes128Gcm,
                keys.clientKey,
                keys.clientIv,
                AesEcbHeaderProtection(PlatformAesOneBlock),
                keys.clientHp,
                -1L,
            )
        assertNotNull(parsed)
        assertContentEquals(token, parsed.packet.token)
    }

    @Test
    fun new_token_frames_reach_the_callback() {
        val received = mutableListOf<ByteArray>()
        val (client, pipe) = newConnectedClient(onNewToken = { received += it })
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(NewTokenFrame(byteArrayOf(9, 9))))!!, 0L)
        assertEquals(QuicConnection.Status.CONNECTED, client.status)
        assertContentEquals(byteArrayOf(9, 9), received.single())
    }

    @Test
    fun empty_new_token_is_a_frame_encoding_error() {
        val (client, pipe) = newConnectedClient()
        feedDatagram(client, pipe.buildServerApplicationDatagram(listOf(NewTokenFrame(ByteArray(0))))!!, 0L)
        assertEquals(QuicTransportError.FRAME_ENCODING_ERROR, client.closeErrorCode)
    }
}
