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
package com.vitorpamplona.quic.connection.recovery

/**
 * RFC 9002 §7 / Appendix B NewReno congestion control: slow start, congestion
 * avoidance, one window reduction per recovery period, persistent congestion,
 * and the ECN-CE response.
 *
 * Bytes in flight live on the packet-number spaces
 * ([com.vitorpamplona.quic.connection.LevelState.bytesInFlight]) so that
 * discarding keys or resetting a space for Retry drops them with the packets;
 * callers pass the connection total in.
 */
class CongestionController(
    val maxDatagramSize: Int = DEFAULT_MAX_DATAGRAM_SIZE,
) {
    /** RFC 9002 §7.2: min(10 * max_datagram_size, max(2 * max_datagram_size, 14720)). */
    val initialWindow: Long = minOf(10L * maxDatagramSize, maxOf(2L * maxDatagramSize, 14_720L))

    /** RFC 9002 §7.2: kMinimumWindow = 2 * max_datagram_size. */
    val minimumWindow: Long = 2L * maxDatagramSize

    var congestionWindow: Long = initialWindow
        private set

    var slowStartThreshold: Long = Long.MAX_VALUE
        private set

    val inSlowStart: Boolean get() = congestionWindow < slowStartThreshold

    /** Diagnostic: congestion events (loss or CE) that reduced the window. */
    var congestionEvents: Long = 0L
        private set

    /** Diagnostic: times persistent congestion collapsed the window. */
    var persistentCongestionEvents: Long = 0L
        private set

    /** RFC 9002 §B.2 congestion_recovery_start_time; null outside recovery. */
    private var recoveryStartTimeMs: Long? = null

    /** Back to slow start from the initial window: a new path's capacity is unknown (RFC 9000 §9.4). */
    fun reset() {
        congestionWindow = initialWindow
        slowStartThreshold = Long.MAX_VALUE
        recoveryStartTimeMs = null
    }

    /** Congestion-avoidance byte counter: the window grows one datagram per window's worth acked. */
    private var bytesAckedInAvoidance: Long = 0L

    /** RFC 9002 §B.5: packets sent before the recovery period began don't grow the window. */
    fun inRecovery(sentAtMillis: Long): Boolean = recoveryStartTimeMs?.let { sentAtMillis <= it } ?: false

    /** Room left in the window given [bytesInFlight]; zero or negative means blocked. */
    fun availableWindow(bytesInFlight: Long): Long = congestionWindow - bytesInFlight

    /**
     * RFC 9002 §B.5 OnPacketsAcked. [bytesInFlightBeforeAck] is the total
     * before these packets left flight: §7.8 says an application-limited sender
     * (one that wasn't using its window) must not grow it.
     */
    fun onPacketsAcked(
        acked: List<SentPacket>,
        bytesInFlightBeforeAck: Long,
    ) {
        val appLimited = bytesInFlightBeforeAck + maxDatagramSize < congestionWindow
        for (packet in acked) {
            if (!packet.ackEliciting) continue
            if (inRecovery(packet.sentAtMillis)) continue
            if (appLimited) continue
            if (inSlowStart) {
                congestionWindow += packet.sizeBytes
            } else {
                bytesAckedInAvoidance += packet.sizeBytes
                if (bytesAckedInAvoidance >= congestionWindow) {
                    bytesAckedInAvoidance -= congestionWindow
                    congestionWindow += maxDatagramSize
                }
            }
        }
    }

    /**
     * RFC 9002 §B.6 OnCongestionEvent, for a loss or an ECN-CE report about a
     * packet sent at [sentAtMillis]. Reduces the window at most once per
     * round trip: events about packets sent before the current recovery period
     * began are part of it.
     */
    fun onCongestionEvent(
        sentAtMillis: Long,
        nowMillis: Long,
    ) {
        if (inRecovery(sentAtMillis)) return
        recoveryStartTimeMs = nowMillis
        slowStartThreshold = maxOf(congestionWindow / 2, minimumWindow)
        congestionWindow = slowStartThreshold
        bytesAckedInAvoidance = 0L
        congestionEvents++
    }

    /**
     * RFC 9002 §B.8 OnPacketsLost. [persistentCongestionDurationMs] is
     * `(smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay) *
     * kPersistentCongestionThreshold`, or null before the first RTT sample
     * (§7.6.2: persistent congestion needs one).
     */
    fun onPacketsLost(
        lost: List<SentPacket>,
        nowMillis: Long,
        persistentCongestionDurationMs: Long?,
    ) {
        var earliest = Long.MAX_VALUE
        var latest = Long.MIN_VALUE
        var inFlightLost = 0
        for (packet in lost) {
            if (!packet.ackEliciting) continue
            inFlightLost++
            if (packet.sentAtMillis < earliest) earliest = packet.sentAtMillis
            if (packet.sentAtMillis > latest) latest = packet.sentAtMillis
        }
        if (inFlightLost == 0) return
        onCongestionEvent(latest, nowMillis)
        // §7.6.2, simplified: two or more ack-eliciting packets lost across a
        // span longer than the persistent-congestion duration, all declared in
        // one batch (so nothing between them was acknowledged).
        if (persistentCongestionDurationMs != null && inFlightLost >= 2 && latest - earliest > persistentCongestionDurationMs) {
            congestionWindow = minimumWindow
            recoveryStartTimeMs = null
            bytesAckedInAvoidance = 0L
            persistentCongestionEvents++
        }
    }

    companion object {
        /** RFC 9000 §14: every endpoint can send 1200-byte datagrams. */
        const val DEFAULT_MAX_DATAGRAM_SIZE: Int = 1200

        /** RFC 9002 §7.6.1 kPersistentCongestionThreshold. */
        const val PERSISTENT_CONGESTION_THRESHOLD: Long = 3L
    }
}

/**
 * RFC 9002 §7.7 pacer: a token bucket refilled at `N * cwnd / smoothed_rtt`
 * (N = 1.25, so pacing never starves the window), holding a burst of about
 * [TARGET_BURST_MILLIS] worth of the rate, between [MIN_BURST_PACKETS] and
 * [MAX_BURST_PACKETS] datagrams. Millisecond clock, like the rest of the stack:
 * the burst floor keeps one-millisecond granularity from capping the rate.
 */
class Pacer(
    private val maxDatagramSize: Int = CongestionController.DEFAULT_MAX_DATAGRAM_SIZE,
) {
    private var tokens: Long = MIN_BURST_PACKETS * maxDatagramSize.toLong()
    private var lastRefillMs: Long = Long.MIN_VALUE

    private fun capacity(
        congestionWindow: Long,
        smoothedRttMs: Long,
    ): Long {
        val rtt = smoothedRttMs.coerceAtLeast(1L)
        val burst = congestionWindow * TARGET_BURST_MILLIS / rtt
        return burst.coerceIn(MIN_BURST_PACKETS * maxDatagramSize.toLong(), MAX_BURST_PACKETS * maxDatagramSize.toLong())
    }

    private fun refill(
        nowMillis: Long,
        congestionWindow: Long,
        smoothedRttMs: Long,
    ) {
        val cap = capacity(congestionWindow, smoothedRttMs)
        if (lastRefillMs != Long.MIN_VALUE && nowMillis > lastRefillMs) {
            val rtt = smoothedRttMs.coerceAtLeast(1L)
            // rate = 1.25 * cwnd / rtt bytes per millisecond.
            val earned = (nowMillis - lastRefillMs) * congestionWindow * 5 / (4 * rtt)
            tokens = (tokens + earned).coerceAtMost(cap)
        } else {
            tokens = tokens.coerceAtMost(cap)
        }
        if (nowMillis > lastRefillMs) lastRefillMs = nowMillis
    }

    /** Milliseconds until a datagram of [size] bytes may go out; 0 means now. */
    fun delayMillis(
        nowMillis: Long,
        size: Int,
        congestionWindow: Long,
        smoothedRttMs: Long,
    ): Long {
        refill(nowMillis, congestionWindow, smoothedRttMs)
        if (tokens >= size) return 0L
        val rtt = smoothedRttMs.coerceAtLeast(1L)
        val ratePerMs = (congestionWindow * 5 / (4 * rtt)).coerceAtLeast(1L)
        return ((size - tokens) + ratePerMs - 1) / ratePerMs
    }

    /** Charge a sent ack-eliciting datagram against the bucket. */
    fun onSent(size: Int) {
        tokens -= size
    }

    companion object {
        const val TARGET_BURST_MILLIS: Long = 2L
        const val MIN_BURST_PACKETS: Long = 10L
        const val MAX_BURST_PACKETS: Long = 256L
    }
}
