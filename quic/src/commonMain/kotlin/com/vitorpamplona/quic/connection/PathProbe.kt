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

import com.vitorpamplona.crypto.random.RandomInstance

/**
 * Which network path a datagram arrived on. A connection normally has one
 * ([ACTIVE]); while it validates a server's preferred address it also has a
 * [PROBE] path, and right after migrating, stragglers can still arrive on the
 * old path ([RETIRED]).
 */
enum class NetworkPath { ACTIVE, PROBE, RETIRED }

/**
 * RFC 9000 §9.6 migration to the server's preferred address, client side.
 *
 * The probe path is validated before any non-probing packet uses it (§9.6.2,
 * §21.5.3): the writer sends PATH_CHALLENGE datagrams there ([pendingChallenge]),
 * expanded to 1200 bytes (§8.2.1), and answers the server's own PATH_CHALLENGEs
 * received there ([pendingResponses], §8.2.2: the response goes out on the path
 * the challenge arrived on). A PATH_RESPONSE echoing any challenge we sent
 * validates the path and the connection moves to it.
 *
 * Caller of any mutation must hold [QuicConnection.streamsLock].
 */
class PathProbe(
    /** Address to probe, as a numeric host string the platform socket resolves without DNS. */
    val host: String,
    val port: Int,
    /** The preferred address's connection ID (sequence number 1). */
    val connectionId: ConnectionId,
    val connectionIdSequence: Long,
    val startedAtMillis: Long,
    /** Give up when no PATH_RESPONSE has arrived this long after the first challenge. */
    val timeoutMillis: Long,
    private val challengePayloadFactory: () -> ByteArray = { RandomInstance.bytes(8) },
) {
    enum class State {
        /** Waiting for the driver to open a socket toward [host]. */
        AWAITING_SOCKET,

        /** Challenges are going out on the probe path. */
        PROBING,

        /** A PATH_RESPONSE matched: the connection now sends to [host]. */
        VALIDATED,

        /** No response within [timeoutMillis] (or the socket couldn't open). */
        FAILED,
    }

    @kotlin.concurrent.Volatile
    var state: State = State.AWAITING_SOCKET
        internal set

    /** Every challenge payload sent so far; a response to any of them validates the path. */
    private val sentChallenges = ArrayList<ByteArray>()

    /** PATH_RESPONSE payloads owed on the probe path. */
    internal val pendingResponses: ArrayDeque<ByteArray> = ArrayDeque()

    private var lastChallengeAtMillis: Long = Long.MIN_VALUE

    /** Number of challenges sent; diagnostic. */
    val challengesSent: Int get() = sentChallenges.size

    /** The driver opened the probe socket. */
    internal fun onSocketReady() {
        if (state == State.AWAITING_SOCKET) state = State.PROBING
    }

    /**
     * The next challenge to send, or null if the last one went out less than
     * [retransmitMillis] ago. Re-sending at the PTO cadence covers a lost
     * challenge or response without loss-recovery state on this path.
     */
    internal fun pendingChallenge(
        nowMillis: Long,
        retransmitMillis: Long,
    ): ByteArray? {
        if (state != State.PROBING) return null
        if (lastChallengeAtMillis != Long.MIN_VALUE && nowMillis - lastChallengeAtMillis < retransmitMillis) return null
        if (sentChallenges.size >= MAX_CHALLENGES) return null
        val payload = challengePayloadFactory()
        require(payload.size == 8) { "challenge payload supplier must return 8 bytes" }
        sentChallenges += payload
        lastChallengeAtMillis = nowMillis
        return payload
    }

    /** Milliseconds until the next challenge is due, or null when none will be. */
    internal fun millisUntilNextChallenge(
        nowMillis: Long,
        retransmitMillis: Long,
    ): Long? {
        if (state != State.PROBING || sentChallenges.size >= MAX_CHALLENGES) return null
        if (lastChallengeAtMillis == Long.MIN_VALUE) return 0L
        return (lastChallengeAtMillis + retransmitMillis - nowMillis).coerceAtLeast(0L)
    }

    /** True when [payload] answers one of our challenges. */
    internal fun matches(payload: ByteArray): Boolean = sentChallenges.any { it.contentEquals(payload) }

    internal fun isTimedOut(nowMillis: Long): Boolean = nowMillis - startedAtMillis >= timeoutMillis

    companion object {
        /** Cap on challenges per probe, so a dead address costs a bounded number of datagrams. */
        const val MAX_CHALLENGES: Int = 8

        /**
         * RFC 9000 §8.2.4 suggests a validation timeout of at least
         * max(3 * PTO, 6 * kInitialRtt); kInitialRtt is 333 ms.
         */
        const val MIN_TIMEOUT_MILLIS: Long = 2_000L
    }
}
