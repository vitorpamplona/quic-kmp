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

import com.vitorpamplona.quic.tls.PermissiveCertificateValidator
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TransportParameterGreaseTest {
    private fun localParameters(grease: Boolean) =
        TransportParameters.decode(
            QuicConnection(
                serverName = "example.test",
                config = QuicConnectionConfig(greaseTransportParameters = grease),
                tlsCertificateValidator = PermissiveCertificateValidator(),
            ).tls.transportParameters,
        )

    @Test
    fun one_reserved_parameter_is_advertised() {
        val unknown = localParameters(grease = true).unknown
        assertEquals(1, unknown.size)
        val (id, value) = unknown.entries.single()
        assertEquals(27L, id % 31L, "reserved ids are 31 * N + 27")
        assertTrue(value.isNotEmpty())
    }

    @Test
    fun grease_can_be_turned_off() {
        assertTrue(localParameters(grease = false).unknown.isEmpty())
    }
}
