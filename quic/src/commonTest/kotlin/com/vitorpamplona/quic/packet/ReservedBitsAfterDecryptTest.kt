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

import com.vitorpamplona.quic.connection.ConnectionId
import com.vitorpamplona.quic.crypto.Aes128Gcm
import com.vitorpamplona.quic.crypto.AesEcbHeaderProtection
import com.vitorpamplona.quic.crypto.InitialSecrets
import com.vitorpamplona.quic.crypto.PlatformAesOneBlock
import kotlin.test.Test
import kotlin.test.assertNull

/**
 * RFC 9000 §17.2 / §17.3.1: the reserved bits count only once packet
 * protection is removed. A packet opened with the wrong keys (one from
 * before a version switch, a key phase being tried, a forgery) unmasks to
 * noise there and must be dropped, not close the connection. Our server
 * closed aioquic's v2 connection that way on a leftover v1 packet.
 */
class ReservedBitsAfterDecryptTest {
    private val dcid = ConnectionId("8394c8f03e515708".hexToByteArray())
    private val scid = ConnectionId("01020304".hexToByteArray())
    private val keys = InitialSecrets.derive(dcid.bytes)
    private val hp = AesEcbHeaderProtection(PlatformAesOneBlock)

    @Test
    fun `long header packets under other keys are dropped whatever their reserved bits unmask to`() {
        for (pn in 0L until 32L) {
            val wire =
                LongHeaderPacket.build(
                    plain = LongHeaderPlaintextPacket(type = LongHeaderType.INITIAL, dcid = dcid, scid = scid, packetNumber = pn, payload = ByteArray(40)),
                    aead = Aes128Gcm,
                    key = keys.clientKey,
                    iv = keys.clientIv,
                    hp = hp,
                    hpKey = keys.clientHp,
                    largestAckedInSpace = -1L,
                )
            // The server's keys are the wrong ones for a client packet.
            val parsed =
                LongHeaderPacket.parseAndDecrypt(
                    bytes = wire,
                    offset = 0,
                    aead = Aes128Gcm,
                    key = keys.serverKey,
                    iv = keys.serverIv,
                    hp = hp,
                    hpKey = keys.serverHp,
                    largestReceivedInSpace = -1L,
                )
            assertNull(parsed)
        }
    }

    @Test
    fun `short header packets under other keys are dropped whatever their reserved bits unmask to`() {
        for (pn in 0L until 32L) {
            val wire =
                ShortHeaderPacket.build(
                    plain = ShortHeaderPlaintextPacket(dcid = dcid, packetNumber = pn, payload = ByteArray(40)),
                    aead = Aes128Gcm,
                    key = keys.clientKey,
                    iv = keys.clientIv,
                    hp = hp,
                    hpKey = keys.clientHp,
                    largestAckedInSpace = -1L,
                )
            val parsed =
                ShortHeaderPacket.parseAndDecrypt(
                    bytes = wire,
                    offset = 0,
                    dcidLen = dcid.length,
                    aead = Aes128Gcm,
                    key = keys.serverKey,
                    iv = keys.serverIv,
                    hp = hp,
                    hpKey = keys.serverHp,
                    largestReceivedInSpace = -1L,
                )
            assertNull(parsed)
        }
    }
}
