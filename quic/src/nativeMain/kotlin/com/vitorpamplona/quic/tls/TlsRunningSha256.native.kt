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

import com.vitorpamplona.crypto.sha2.sha256

/**
 * The transcript kept as bytes and hashed whole at each [snapshot], the JVM's own fallback: a
 * TLS 1.3 handshake transcript is a few kilobytes and is sampled three times, so the re-hash costs
 * microseconds.
 */
actual class TlsRunningSha256 actual constructor() {
    private var transcript = ByteArray(INITIAL_CAPACITY)
    private var size = 0

    actual fun update(bytes: ByteArray) {
        if (size + bytes.size > transcript.size) transcript = transcript.copyOf(maxOf(transcript.size * 2, size + bytes.size))
        bytes.copyInto(transcript, size)
        size += bytes.size
    }

    actual fun snapshot(): ByteArray = sha256(transcript.copyOf(size))

    private companion object {
        const val INITIAL_CAPACITY = 4096
    }
}
