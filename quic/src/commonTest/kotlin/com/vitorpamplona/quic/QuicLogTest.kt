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
package com.vitorpamplona.quic

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame

class QuicLogTest {
    @AfterTest
    fun clearSink() {
        QuicLog.sink = null
    }

    @Test
    fun `without a sink nothing is logged and the message is never built`() {
        QuicLog.sink = null
        var built = false
        QuicLog.d("Test") {
            built = true
            "unused"
        }
        QuicLog.w("Test", IllegalStateException()) {
            built = true
            "unused"
        }
        assertFalse(built)
    }

    @Test
    fun `a sink receives the level tag message and throwable`() {
        val lines = mutableListOf<String>()
        var caught: Throwable? = null
        QuicLog.sink =
            QuicLog.Sink { level, tag, message, throwable ->
                lines += "$level $tag $message"
                if (throwable != null) caught = throwable
            }
        val error = IllegalStateException("boom")
        QuicLog.d("Writer") { "one" }
        QuicLog.i("Writer") { "two" }
        QuicLog.w("Tls") { "three" }
        QuicLog.e("Tls", error) { "four" }
        assertEquals(listOf("DEBUG Writer one", "INFO Writer two", "WARN Tls three", "ERROR Tls four"), lines)
        assertSame(error, caught)
    }
}
