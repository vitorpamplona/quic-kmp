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
package com.vitorpamplona.quic.transport

// Placeholder actual for the -PquicNativeCheck target; see ../Synchronized.kt.

actual class UdpSocket {
    actual suspend fun send(payload: ByteArray): Int = throw NotImplementedError("native check stub")

    actual suspend fun receive(): ByteArray? = throw NotImplementedError("native check stub")

    actual fun close(): Unit = throw NotImplementedError("native check stub")

    actual val localPort: Int get() = throw NotImplementedError("native check stub")

    actual val receivedDatagramCount: Long get() = throw NotImplementedError("native check stub")

    actual val receivedByteCount: Long get() = throw NotImplementedError("native check stub")

    actual val receiveBufferSizeBytes: Int get() = throw NotImplementedError("native check stub")

    actual companion object {
        actual suspend fun connect(
            host: String,
            port: Int,
        ): UdpSocket = throw NotImplementedError("native check stub")
    }
}
