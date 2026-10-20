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

import kotlin.concurrent.Volatile

/**
 * quic's logging hook. The library picks no logger for its users: it logs nothing until an app
 * sets [sink], and until then a call costs one volatile read and its message lambda never runs.
 *
 * Route the lines into your own logger once, at startup:
 *
 * ```kotlin
 * QuicLog.sink =
 *     QuicLog.Sink { level, tag, message, throwable ->
 *         when (level) {
 *             QuicLog.Level.DEBUG -> Log.d(tag, message, throwable)
 *             QuicLog.Level.INFO -> Log.i(tag, message, throwable)
 *             QuicLog.Level.WARN -> Log.w(tag, message, throwable)
 *             QuicLog.Level.ERROR -> Log.e(tag, message, throwable)
 *         }
 *     }
 * ```
 *
 * A logger with its own level filter should also override [Sink.isLoggable], so a message it
 * would drop is never built.
 */
object QuicLog {
    enum class Level { DEBUG, INFO, WARN, ERROR }

    fun interface Sink {
        fun log(
            level: Level,
            tag: String,
            message: String,
            throwable: Throwable?,
        )

        /** False skips the line before its message lambda runs. */
        fun isLoggable(level: Level): Boolean = true
    }

    /** Where log lines go; null (the default) drops them unbuilt. */
    @Volatile
    var sink: Sink? = null

    inline fun d(
        tag: String,
        message: () -> String,
    ) {
        val sink = sink ?: return
        if (sink.isLoggable(Level.DEBUG)) sink.log(Level.DEBUG, tag, message(), null)
    }

    inline fun i(
        tag: String,
        message: () -> String,
    ) {
        val sink = sink ?: return
        if (sink.isLoggable(Level.INFO)) sink.log(Level.INFO, tag, message(), null)
    }

    inline fun w(
        tag: String,
        throwable: Throwable? = null,
        message: () -> String,
    ) {
        val sink = sink ?: return
        if (sink.isLoggable(Level.WARN)) sink.log(Level.WARN, tag, message(), throwable)
    }

    inline fun e(
        tag: String,
        throwable: Throwable? = null,
        message: () -> String,
    ) {
        val sink = sink ?: return
        if (sink.isLoggable(Level.ERROR)) sink.log(Level.ERROR, tag, message(), throwable)
    }
}
