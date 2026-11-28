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

import kotlinx.cinterop.Arena
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.ptr
import platform.posix.PTHREAD_MUTEX_RECURSIVE
import platform.posix.pthread_mutex_destroy
import platform.posix.pthread_mutex_init
import platform.posix.pthread_mutex_lock
import platform.posix.pthread_mutex_t
import platform.posix.pthread_mutex_unlock
import platform.posix.pthread_mutexattr_destroy
import platform.posix.pthread_mutexattr_init
import platform.posix.pthread_mutexattr_settype
import platform.posix.pthread_mutexattr_t
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.Cleaner
import kotlin.native.ref.createCleaner

/**
 * A recursive pthread mutex, so a thread that already holds the lock may take it again, as a JVM
 * monitor allows. Its memory is freed when the object is collected.
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
internal actual class SynchronizedObject actual constructor() {
    private val arena = Arena()
    private val mutex: pthread_mutex_t = arena.alloc()

    init {
        val attr: pthread_mutexattr_t = arena.alloc()
        pthread_mutexattr_init(attr.ptr)
        pthread_mutexattr_settype(attr.ptr, PTHREAD_MUTEX_RECURSIVE.toInt())
        pthread_mutex_init(mutex.ptr, attr.ptr)
        pthread_mutexattr_destroy(attr.ptr)
    }

    @Suppress("unused")
    private val cleaner: Cleaner = createCleaner(MutexHandle(arena, mutex)) { it.free() }

    fun lock() {
        pthread_mutex_lock(mutex.ptr)
    }

    fun unlock() {
        pthread_mutex_unlock(mutex.ptr)
    }

    private class MutexHandle(
        val arena: Arena,
        val mutex: pthread_mutex_t,
    ) {
        fun free() {
            pthread_mutex_destroy(mutex.ptr)
            arena.clear()
        }
    }
}

internal actual inline fun <T> synchronized(
    lock: SynchronizedObject,
    block: () -> T,
): T {
    lock.lock()
    try {
        return block()
    } finally {
        lock.unlock()
    }
}
