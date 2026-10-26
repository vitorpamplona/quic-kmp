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

/**
 * Datagram Packetization Layer PMTU Discovery (RFC 8899, RFC 9000 §14.3).
 *
 * Every QUIC path carries 1200-byte datagrams ([BASE_SIZE]); larger ones are
 * earned by probing: a PING padded to the candidate size that, once
 * acknowledged, proves the path carries it. The search is a binary search
 * between the largest acknowledged size and [ceiling] (our and the peer's
 * `max_udp_payload_size`). [MAX_PROBES] losses at a size lower the ceiling
 * below it. Probe losses are not congestion signals (RFC 8899 §4.4).
 *
 * A path that starts dropping full-size packets (a black hole: persistent
 * congestion or repeated PTOs while above the base) falls back to
 * [BASE_SIZE] and searches again after [RAISE_TIMER_MILLIS], as does a
 * finished search, in case the path grew.
 *
 * Caller of any mutation must hold [QuicConnection.streamsLock].
 */
class PmtuDiscovery(
    /** Largest datagram we or the peer accept (`max_udp_payload_size`), capped to what a probe can be. */
    initialCeiling: Int = BASE_SIZE,
) {
    /** Largest datagram size validated on the current path; what the writer fills packets to. */
    var currentSize: Int = BASE_SIZE
        private set

    var ceiling: Int = initialCeiling.coerceAtLeast(BASE_SIZE)
        private set

    private var configuredCeiling: Int = ceiling

    /** Size of the probe in flight, or 0 when none. */
    var probeInFlight: Int = 0
        private set

    private var probeSize: Int = 0
    private var failuresAtProbeSize: Int = 0

    /** No search before this time (search finished, or fell back on a black hole). */
    private var nextSearchAtMillis: Long = 0L

    /** Diagnostic: number of probes sent. */
    var probesSent: Int = 0
        private set

    /** Re-arm the ceiling once both sides' limits are known. */
    fun setCeiling(size: Int) {
        configuredCeiling = size.coerceAtLeast(BASE_SIZE)
        ceiling = configuredCeiling
        if (currentSize > ceiling) currentSize = ceiling
    }

    /** True when the search space is exhausted: what's left between floor and ceiling isn't worth a probe. */
    val searchComplete: Boolean get() = ceiling - currentSize < MIN_STEP

    /**
     * The size to probe now, or 0 when no probe is due. Starts with the
     * ceiling (the common case on Ethernet-sized paths is one probe), then
     * bisects downward after failures.
     */
    fun probeDue(nowMillis: Long): Int {
        if (probeInFlight != 0 || nowMillis < nextSearchAtMillis) return 0
        if (searchComplete) {
            // Done; look again later in case the path's MTU grew.
            nextSearchAtMillis = nowMillis + RAISE_TIMER_MILLIS
            ceiling = configuredCeiling
            return 0
        }
        if (probeSize == 0 || probeSize <= currentSize || probeSize > ceiling) {
            probeSize = if (failuresAtProbeSize == 0 && probesSent == 0) ceiling else (currentSize + ceiling + 1) / 2
            failuresAtProbeSize = 0
        }
        return probeSize
    }

    fun onProbeSent(size: Int) {
        probeInFlight = size
        probesSent++
    }

    fun onProbeAcked(size: Int) {
        if (size == probeInFlight) probeInFlight = 0
        if (size > currentSize) currentSize = size
        probeSize = 0
        failuresAtProbeSize = 0
    }

    fun onProbeLost(size: Int) {
        if (size == probeInFlight) probeInFlight = 0
        if (size != probeSize) return
        failuresAtProbeSize++
        if (failuresAtProbeSize >= MAX_PROBES) {
            ceiling = size - 1
            probeSize = 0
            failuresAtProbeSize = 0
        }
    }

    /** A new path (RFC 9000 §14.3): back to the base size, searching again from scratch. */
    fun resetForNewPath() {
        currentSize = BASE_SIZE
        ceiling = configuredCeiling
        probeSize = 0
        failuresAtProbeSize = 0
        probeInFlight = 0
        nextSearchAtMillis = 0L
    }

    /** Full-size packets stop arriving: assume the larger size is a black hole (RFC 8899 §4.3). */
    fun onBlackHoleSuspected(nowMillis: Long): Boolean {
        if (currentSize == BASE_SIZE) return false
        ceiling = currentSize - 1
        currentSize = BASE_SIZE
        probeSize = 0
        failuresAtProbeSize = 0
        probeInFlight = 0
        nextSearchAtMillis = nowMillis + RAISE_TIMER_MILLIS
        return true
    }

    companion object {
        /** RFC 9000 §14: every QUIC path carries 1200-byte UDP payloads. */
        const val BASE_SIZE: Int = 1200

        /** RFC 8899 §5.1.2 MAX_PROBES. */
        const val MAX_PROBES: Int = 3

        /** Stop bisecting once the remaining range is smaller than this. */
        const val MIN_STEP: Int = 20

        /** RFC 8899 §5.1.1 PMTU_RAISE_TIMER (600 s). */
        const val RAISE_TIMER_MILLIS: Long = 600_000L

        /** A probe can't usefully exceed an Ethernet-path UDP payload (1500 - 20 - 8). */
        const val MAX_PROBE_SIZE: Int = 1472
    }
}
