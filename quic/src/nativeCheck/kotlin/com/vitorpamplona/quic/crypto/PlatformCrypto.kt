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
package com.vitorpamplona.quic.crypto

// Placeholder actuals for the -PquicNativeCheck target; see ../Synchronized.kt.

actual val PlatformAesOneBlock: AesOneBlockEncrypt
    get() = throw NotImplementedError("native check stub")

actual val PlatformChaCha20Block: ChaCha20BlockEncrypt
    get() = throw NotImplementedError("native check stub")

actual fun bestAes128GcmAead(key: ByteArray): Aead = throw NotImplementedError("native check stub")

actual fun bestAes256GcmAead(key: ByteArray): Aead = throw NotImplementedError("native check stub")

actual fun bestChaCha20Poly1305Aead(key: ByteArray): Aead = throw NotImplementedError("native check stub")
