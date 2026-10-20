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

/**
 * A lock for short critical sections that never suspend: the close-state
 * transitions in [com.vitorpamplona.quic.connection.QuicConnection] and the
 * byte bookkeeping in [com.vitorpamplona.quic.stream.SendBuffer].
 *
 * The same shape as kotlinx-atomicfu's `SynchronizedObject`. On the JVM it is
 * a plain object used as a monitor, so the generated code is the
 * `synchronized` block it replaced.
 */
internal expect class SynchronizedObject()

/**
 * Runs [block] while holding [lock]. Inline, so [block] may return from the
 * enclosing function, as `kotlin.synchronized` allows.
 */
internal expect inline fun <T> synchronized(
    lock: SynchronizedObject,
    block: () -> T,
): T
