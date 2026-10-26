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

import com.vitorpamplona.quic.transport.QuicDatagramSocket
import com.vitorpamplona.quic.transport.UdpSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Owns the UDP socket and runs the read + send loops for a [QuicConnection].
 *
 * Synchronization (post lock-split refactor 2026-05-08): the driver no
 * longer takes a single connection-wide lock around feed/drain. Instead
 * [feedDatagram] and [drainOutbound] internally acquire `streamsLock`
 * for the precise critical sections they touch — leaving app
 * coroutines (`openBidiStream`, etc.) free to run in parallel with the
 * I/O loops. Per-stream and per-level buffers serialize through their
 * leaf `synchronized(this)` blocks.
 *
 * The send loop is woken by a `Channel<Unit>(CONFLATED)` rather than a
 * polling timer — no idle CPU. App writes ([QuicConnection.queueDatagram]
 * and [QuicConnection.openBidiStream]/[com.vitorpamplona.quic.stream.SendBuffer.enqueue])
 * call [wakeup] to nudge the send loop.
 */
@OptIn(ExperimentalAtomicApi::class)
class QuicConnectionDriver(
    val connection: QuicConnection,
    socket: QuicDatagramSocket,
    private val parentScope: CoroutineScope,
    /**
     * Opens the extra socket a preferred-address migration (RFC 9000 §9.6)
     * needs toward the server's new address. Tests substitute their own.
     */
    private val socketFactory: suspend (host: String, port: Int) -> QuicDatagramSocket = { host, port -> UdpSocket.connect(host, port) },
) {
    /** A client connection over a connected [UdpSocket]. */
    constructor(
        connection: QuicConnection,
        socket: UdpSocket,
        parentScope: CoroutineScope,
        socketFactory: suspend (host: String, port: Int) -> UdpSocket = { host, port -> UdpSocket.connect(host, port) },
    ) : this(connection, socket as QuicDatagramSocket, parentScope, socketFactory)

    /** The socket the connection sends on. Swapped to [probeSocket] when a preferred-address probe validates. */
    @kotlin.concurrent.Volatile
    private var activeSocket: QuicDatagramSocket = socket

    /** Socket toward the preferred address while its path is being validated. */
    @kotlin.concurrent.Volatile
    private var probeSocket: QuicDatagramSocket? = null

    /** Sockets of paths we left; still read for stragglers, closed with the driver. */
    private val retiredSockets = ArrayList<QuicDatagramSocket>()
    private var probeSocketRequested = false

    /**
     * Single time source: defer to the connection's [QuicConnection.nowMillis]
     * (monotonic by default). Pre-fix the driver had its own
     * `System.currentTimeMillis()` default which silently disagreed with the
     * connection's wallclock-derived clock; under NTP step the two could
     * report different values for the SAME logical "now", leading to RTT
     * samples computed against drifted timestamps.
     */
    private val nowMillis: () -> Long get() = connection.nowMillis
    private val job = SupervisorJob(parentScope.coroutineContext[Job])
    private val scope = CoroutineScope(parentScope.coroutineContext + job + Dispatchers.IO)
    private val sendWakeup = Channel<Unit>(Channel.CONFLATED)

    // Track the read + send loop jobs so close() can join them cleanly
    // (waiting for the in-flight datagram to finish flushing) instead of
    // racing them with scope.cancel().
    private var readJob: Job? = null
    private var sendJob: Job? = null

    /**
     * Test-only handle on the driver's [SupervisorJob]. Used by the
     * session-lifecycle leak test in
     * [com.vitorpamplona.quic.connection.QuicConnectionDriverLifecycleTest]
     * to assert that a closed driver reports `isCompleted = true` once
     * its read/send loops have unwound — the inverse of "the driver
     * leaked a coroutine past close()".
     *
     * Production code MUST NOT touch this — the driver lifecycle is
     * managed end-to-end by [start] / [close].
     */
    internal val driverJob: Job get() = job

    /**
     * Test-only handle on the in-flight teardown coroutine. Returns null
     * before [close] has been called; once close runs, the returned Job
     * lets the test `join()` until teardown is complete (cancel + socket
     * close + read/send join). Pre-existing close() returned immediately
     * and provided no synchronous "teardown is done" signal — tests had
     * to poll `connection.status == CLOSED` and trust that the rest of
     * the cleanup eventually settled.
     */
    internal val closeTeardownJob: Job? get() = closeJob.load()

    /**
     * Round-5 concurrency #5: close() guard. A second concurrent invocation
     * (e.g. session close + read-loop death close racing) used to launch a
     * parallel teardown that called scope.cancel() and socket.close() while
     * the first close was mid-joinAll. We memoize the teardown Job so the
     * second caller awaits the first's completion instead.
     *
     * Lock-free CAS replaces the previous `synchronized(this)` double-checked
     * init: the close path is single-shot ("first writer wins"), which is
     * exactly what `compareAndSet` expresses.
     */
    private val closeJob: AtomicReference<Job?> = AtomicReference(null)

    fun start() {
        connection.sendWakeup = ::wakeup
        connection.start()
        // Wire the diagnostic UDP-stats supplier so
        // QuicConnection.flowControlSnapshot can surface
        // kernel-delivered datagram counters alongside the QUIC
        // flow-control fields.
        connection.udpStatsSupplier = {
            val socket = activeSocket
            UdpSocketStats(
                receivedDatagrams = socket.receivedDatagramCount,
                receivedBytes = socket.receivedByteCount,
                receiveBufferSizeBytes = socket.receiveBufferSizeBytes,
            )
        }
        connection.activePathIsIpv6 = runCatching { activeSocket.remoteIsIpv6 }.getOrDefault(false)
        val initialSocket = activeSocket
        readJob = scope.launch { readLoop(initialSocket) }
        sendJob = scope.launch { sendLoop() }
        // Initial nudge so the ClientHello goes out immediately.
        sendWakeup.trySend(Unit)
    }

    /** Nudge the send loop. Safe to call from any coroutine. */
    fun wakeup() {
        sendWakeup.trySend(Unit)
    }

    /** Which path [socket] currently carries. */
    private fun pathOf(socket: QuicDatagramSocket): NetworkPath =
        when {
            socket === activeSocket -> NetworkPath.ACTIVE
            socket === probeSocket -> NetworkPath.PROBE
            else -> NetworkPath.RETIRED
        }

    private suspend fun readLoop(socket: QuicDatagramSocket) {
        try {
            while (connection.status != QuicConnection.Status.CLOSED) {
                val datagram = socket.receive() ?: break
                // Phase 1 of the lock-split refactor: parser holds
                // streamsLock for a single datagram-feed pass.
                connection.streamsLock.withLock {
                    feedDatagram(connection, datagram, nowMillis(), pathOf(socket))
                }
                // Inbound data may have produced new outbound (acks, crypto, etc.).
                wakeup()
            }
        } finally {
            // If the read loop exits while the handshake is still pending,
            // unblock anyone awaiting the handshake — otherwise awaitHandshake()
            // suspends forever. Only the active path's socket closing ends the
            // connection; a probe or retired socket going away doesn't.
            if (socket === activeSocket) {
                connection.markClosedExternally("read loop exited (socket closed or peer closed)")
            }
            wakeup() // let the send loop notice CLOSED and exit
        }
    }

    /**
     * Drive the preferred-address probe (RFC 9000 §9.6) from the send loop:
     * open its socket when the connection asks for one, swap to it once the
     * path validated, drop it if validation failed, and flush its datagrams.
     */
    private suspend fun servicePathProbe() {
        if (connection.isServer) {
            val send = connection.sendOnServerPath ?: return
            while (true) {
                val (path, datagram) = connection.streamsLock.withLock { drainServerProbeResponse(connection, nowMillis()) } ?: break
                runCatching { send(path, datagram) }
            }
            return
        }
        val probe = connection.pathProbe ?: return
        when (probe.state) {
            PathProbe.State.AWAITING_SOCKET -> {
                if (probeSocketRequested) return
                probeSocketRequested = true
                scope.launch {
                    val opened =
                        try {
                            socketFactory(probe.host, probe.port)
                        } catch (t: Throwable) {
                            connection.streamsLock.withLock {
                                connection.failPathProbeLocked("socket: ${t.message ?: t::class.simpleName}")
                            }
                            return@launch
                        }
                    probeSocket = opened
                    launch { readLoop(opened) }
                    connection.streamsLock.withLock { probe.onSocketReady() }
                    wakeup()
                }
            }

            PathProbe.State.PROBING -> {
                val socket = probeSocket ?: return
                while (true) {
                    val out = connection.streamsLock.withLock { drainProbe(connection, nowMillis()) } ?: break
                    // A send failure on the probe path just means the probe fails by timeout.
                    runCatching { socket.send(out) }
                }
            }

            PathProbe.State.VALIDATED -> {
                connection.streamsLock.withLock { adoptValidatedProbeSocketLocked() }
            }

            PathProbe.State.FAILED -> {
                probeSocket?.let {
                    probeSocket = null
                    it.close()
                }
            }
        }
    }

    /**
     * Once the probe validated, make its socket the one we send on. Called
     * under [QuicConnection.streamsLock] right before each datagram is built,
     * so a packet built after validation (the new connection ID, PATH_RESPONSEs
     * owed on the new path) never goes out on the old socket.
     */
    private fun adoptValidatedProbeSocketLocked() {
        if (connection.pathProbe?.state != PathProbe.State.VALIDATED) return
        val socket = probeSocket ?: return
        retiredSockets += activeSocket
        activeSocket = socket
        probeSocket = null
        connection.activePathIsIpv6 = runCatching { socket.remoteIsIpv6 }.getOrDefault(false)
    }

    private suspend fun sendLoop() {
        // RFC 9002 §6.2 Probe Timeout. Once handshake is complete and
        // we have an RTT estimate, the PTO duration is
        // `smoothed_rtt + max(4*rttvar, 1ms) + max_ack_delay`,
        // doubled by `1 shl consecutivePtoCount` per §6.2.2. Before
        // the first RTT sample we fall back to a 1 s conservative
        // floor (the same prior-shipping behavior, kept for
        // handshake-timeout safety on lossy paths).
        //
        // Mirror the read loop's symmetry: any uncaught throw inside
        // the loop (most common: `socket.send` raising once the OS
        // tears down the UDP socket — typical on Android when the
        // app backgrounds and the kernel reclaims the FD ~30 s
        // later) MUST flip the connection to CLOSED so the
        // higher-level reconnect orchestration in
        // [com.vitorpamplona.nestsclient.connectReconnectingNestsListener]
        // observes a Failed terminal state and fires a fresh
        // handshake. Pre-fix, the throw escaped silently into the
        // SupervisorJob, the read loop kept blocking on
        // `socket.receive()` (which doesn't throw — it returns null
        // on close, but the OS may not surface that for many
        // seconds), and the connection sat in HANDSHAKING / CONNECTED
        // long after the socket was dead — invisibly wedged.
        try {
            sendLoopBody()
        } catch (ce: kotlinx.coroutines.CancellationException) {
            // Cooperative cancel from close() / scope.cancel(). Don't
            // mark closed here — close() is already driving the
            // teardown and would race with our markClosedExternally.
            throw ce
        } catch (t: Throwable) {
            connection.markClosedExternally("send loop exited: ${t::class.simpleName}: ${t.message}")
        }
    }

    private suspend fun sendLoopBody() {
        try {
            sendLoopUntilClosed()
        } finally {
            // A locally detected error closed the connection: tell the peer.
            connection.takeFinalCloseDatagram()?.let { runCatching { activeSocket.send(it) } }
        }
    }

    private suspend fun sendLoopUntilClosed() {
        // When the last keep-alive PING was queued. The idle clock only moves on
        // the first send after a receive, so keep-alive keeps its own.
        var lastKeepAliveMs = Long.MIN_VALUE
        while (connection.status != QuicConnection.Status.CLOSED) {
            // Swap paths before building: once a probe validates, the next
            // packets must already go to the preferred address.
            servicePathProbe()
            // Phase 1 of the lock-split refactor: the writer holds
            // streamsLock for the build, releases it for the actual
            // socket.send() so a slow socket doesn't stall app
            // coroutines (open/close streams, queue datagrams).
            while (true) {
                var socket = activeSocket
                val out =
                    connection.streamsLock.withLock {
                        adoptValidatedProbeSocketLocked()
                        socket = activeSocket
                        drainOutbound(connection, nowMillis())
                    } ?: break
                socket.send(out)
                // RFC 9002 §6.2.4 probe budget: when the PTO timer
                // fired we set `pendingProbePackets = 2`; consume one
                // slot per probe-bearing datagram. If budget remains,
                // re-requeue inflight CRYPTO / STREAM bytes so the
                // next drainOutbound iteration has payload to probe
                // with. The loop's own break-on-null then terminates
                // naturally if there's nothing left to requeue (e.g.
                // a connection with no inflight data — the first
                // probe is a bare PING, the second slot harmlessly
                // expires with no follow-up datagram).
                //
                // Decrementing AFTER socket.send (not before) ensures
                // a non-PTO drain — wakeup-driven, no probe budget
                // outstanding — leaves the field at 0 untouched. The
                // post-decrement check uses `> 0` (not `>= 0`) so
                // we only requeue while another probe is still owed.
                if (connection.pendingProbePackets > 0) {
                    connection.pendingProbePackets--
                    if (connection.pendingProbePackets > 0) {
                        // Two cooperating signals for the next probe:
                        //   (a) requeue inflight CRYPTO / STREAM data so a
                        //       payload-bearing probe can fire (preferred —
                        //       a CRYPTO retransmit also covers the
                        //       ack-eliciting requirement);
                        //   (b) re-arm `pendingPing` for the no-data fallback
                        //       (CRYPTO already ACK'd or never in flight, e.g.
                        //       handshake-confirmed connections idling
                        //       between transfers). Without (b), the writer
                        //       suppresses the second probe entirely because
                        //       `pendingPing` is one-shot — the first probe
                        //       cleared it. The writer's own
                        //       `collectHandshakeLevelFrames` still
                        //       suppresses the PING when a CRYPTO frame
                        //       lands in the same packet, so this never
                        //       wastes a frame on top of a retransmit.
                        requeueInflightForProbe(connection)
                        connection.pendingPing = true
                    }
                }
            }
            // Defence-in-depth: if the inner loop exited with budget
            // still unconsumed (e.g. drainOutbound returned null on
            // the very first iteration because nothing was inflight
            // — only `pendingPing` would have been set, and it can
            // be cleared by the writer without an outbound emission
            // when no level has send keys), zero it out so the next
            // wakeup-driven drain doesn't accidentally re-requeue.
            connection.pendingProbePackets = 0
            // RFC 9002 §6.2.1: the PTO period counts from the latest
            // ack-eliciting send (QuicConnection.ptoDelayMillis), not from
            // this wakeup, so wakeups that send nothing don't postpone it.
            val ptoArmed = connection.ptoArmed()
            val ptoMillis = connection.ptoDelayMillis(nowMillis())
            // RFC 9002 §6.1.2 timer-driven loss detection: take the
            // earliest of (PTO deadline, next-loss-time across levels).
            // Without this, tail loss waits for the PTO instead of the
            // shorter `9/8 * max_rtt` time threshold — visible to the
            // user as a recovery delay equal to the PTO minus that
            // threshold (often ~5x worse than necessary on lossy
            // links). A null nextLossTime contributes nothing.
            val nowForLossTimer = nowMillis()
            val nextLossDelta =
                listOfNotNull(
                    connection.initial.nextLossTimeMs,
                    connection.handshake.nextLossTimeMs,
                    connection.application.nextLossTimeMs,
                ).minOrNull()?.let { (it - nowForLossTimer).coerceAtLeast(0L) }
            // RFC 9000 §10.1 idle-timeout deadline. Null when neither
            // endpoint advertised a non-zero `max_idle_timeout`. We
            // fold the remaining time into the same `withTimeoutOrNull`
            // sleep so an idle connection wakes exactly at expiry
            // instead of polling.
            val idleTimeoutMs = connection.effectiveIdleTimeoutMs()
            val idleDelta =
                idleTimeoutMs?.let {
                    (connection.lastActivityMs + it - nowForLossTimer).coerceAtLeast(0L)
                }
            // RFC 9000 §10.2.2 draining-period deadline. Set when
            // peer's CONNECTION_CLOSE arrives; we hold in DRAINING
            // until 3 * PTO elapses, then transition to CLOSED.
            val drainingDelta =
                connection.drainingDeadlineMs?.let {
                    (it - nowForLossTimer).coerceAtLeast(0L)
                }
            // A probe re-sends its challenge on its own timer and gives up at its deadline.
            servicePathProbe()
            val probeDelta =
                connection.pathProbe?.let { probe ->
                    val now = nowMillis()
                    when (probe.state) {
                        PathProbe.State.PROBING -> {
                            minOf(
                                probe.millisUntilNextChallenge(now, connection.pathProbeRetransmitMillis()) ?: Long.MAX_VALUE,
                                (probe.startedAtMillis + probe.timeoutMillis - now).coerceAtLeast(0L),
                            )
                        }

                        PathProbe.State.AWAITING_SOCKET -> {
                            (probe.startedAtMillis + probe.timeoutMillis - now).coerceAtLeast(0L)
                        }

                        else -> {
                            null
                        }
                    }
                }
            // RFC 9002 §7.7: the pacer held payload back; come back when it
            // releases the next datagram. (Window-blocked sends wait for an ACK,
            // which wakes us, or the PTO.)
            val pacingDelta =
                connection.pacingDelayMillis(nowForLossTimer).takeIf { it > 0L && !connection.congestionBlocked() }
            // Keep-alive: a PING once the connection has been quiet this long.
            val keepAliveMs = connection.config.keepAliveIntervalMillis
            val keepAliveDelta =
                if (keepAliveMs > 0L && connection.handshakeConfirmed && connection.status == QuicConnection.Status.CONNECTED) {
                    (maxOf(connection.lastActivityMs, lastKeepAliveMs) + keepAliveMs - nowForLossTimer).coerceAtLeast(0L)
                } else {
                    null
                }
            // RFC 9000 §13.2.1: a delayed application ACK falls due at max_ack_delay.
            val ackDelta =
                connection.application.ackTracker
                    .ackDeadlineMillis(connection.localMaxAckDelayMillis)
                    ?.let { (it - nowForLossTimer).coerceAtLeast(0L) }
                    // Only while a drain could send it: not when draining, nor
                    // while an amplification limit holds everything back
                    // (else an overdue ACK spins this loop).
                    ?.takeIf { connection.application.sendProtection != null && connection.canSendAck() }
            val sleepMillis =
                minOf(
                    ptoMillis,
                    nextLossDelta ?: Long.MAX_VALUE,
                    idleDelta ?: Long.MAX_VALUE,
                    drainingDelta ?: Long.MAX_VALUE,
                    probeDelta ?: Long.MAX_VALUE,
                    pacingDelta ?: Long.MAX_VALUE,
                    ackDelta ?: Long.MAX_VALUE,
                    keepAliveDelta ?: Long.MAX_VALUE,
                )
            // Suspend until either: a wakeup arrives, or the timer expires.
            val woke =
                withTimeoutOrNull(sleepMillis) {
                    sendWakeup.receive()
                    Unit
                }
            if (woke == null) {
                // Distinguish draining-deadline / idle-timeout /
                // loss-timer / PTO expiry. RFC 9000 §10.2.2: the
                // draining period transitions to fully CLOSED once
                // 3 * PTO has elapsed since the peer's
                // CONNECTION_CLOSE — gives the peer's last
                // retransmits a chance to converge before we discard
                // state. Idle-timeout fires per §10.2.1 ("silently
                // closes — discarding the connection state without
                // sending a CONNECTION_CLOSE frame"). A loss-timer
                // wake just runs `detectAndRemoveLost`. A PTO wake
                // additionally bumps the consecutive-PTO counter and
                // arms the probe budget.
                if (connection.isDrainingExpired(nowMillis())) {
                    connection.markClosedExternally("draining period elapsed")
                    continue
                }
                if (idleTimeoutMs != null && connection.isIdleTimedOut(nowMillis())) {
                    connection.markClosedExternally(
                        "idle timeout ($idleTimeoutMs ms with no activity)",
                    )
                    continue
                }
                if (keepAliveDelta != null && keepAliveDelta < ptoMillis && (nextLossDelta == null || keepAliveDelta < nextLossDelta) &&
                    nowMillis() - maxOf(connection.lastActivityMs, lastKeepAliveMs) >= keepAliveMs
                ) {
                    lastKeepAliveMs = nowMillis()
                    connection.pendingPing = true
                    continue
                }
                // The pacer's or the ACK timer woke us: just drain again.
                val softDelta = minOf(pacingDelta ?: Long.MAX_VALUE, ackDelta ?: Long.MAX_VALUE)
                if (softDelta < ptoMillis && (nextLossDelta == null || softDelta < nextLossDelta)) {
                    continue
                }
                // The probe timer woke us: its work happens at the top of the loop.
                if (probeDelta != null && probeDelta < ptoMillis && (nextLossDelta == null || probeDelta < nextLossDelta)) {
                    connection.streamsLock.withLock { connection.checkPathProbeTimeoutLocked(nowMillis()) }
                    continue
                }
                val pickedLossTimer = nextLossDelta != null && nextLossDelta < ptoMillis
                if (pickedLossTimer) {
                    handleLossTimerFired(connection)
                } else if (ptoArmed) {
                    handlePtoFired(connection)
                }
            }
        }
    }

    /**
     * RFC 9002 §6.1.2 timer-driven loss detection. Re-runs
     * `detectAndRemoveLost` across each encryption level; any newly
     * time-threshold-lost packets dispatch their tokens to the
     * pending retransmit queues, and the next drain emits them.
     * Cheaper than [handlePtoFired] because no probe budget /
     * exponential backoff is needed — the peer ACKs that fix the
     * loss state arrive on their normal cadence.
     */
    private suspend fun handleLossTimerFired(conn: QuicConnection) {
        // Under streamsLock like the parser's ACK path: both walk and remove from the same plain
        // HashMap of sent packets, and onTokensLost requires the lock.
        conn.streamsLock.withLock {
            val nowMs = conn.nowMillis()
            runLossDetectionForLevel(conn, conn.initial, EncryptionLevel.INITIAL, nowMs)
            runLossDetectionForLevel(conn, conn.handshake, EncryptionLevel.HANDSHAKE, nowMs)
            runLossDetectionForLevel(conn, conn.application, EncryptionLevel.APPLICATION, nowMs)
        }
    }

    private fun runLossDetectionForLevel(
        conn: QuicConnection,
        state: LevelState,
        level: EncryptionLevel,
        nowMs: Long,
    ) {
        val largest = state.largestAckedPn ?: return
        val result = conn.lossDetection.detectAndRemoveLost(state.sentPackets, largest, nowMs)
        for (lostPacket in result.lost) {
            conn.onTokensLost(lostPacket.tokens)
        }
        conn.onPacketsLostLocked(state, result.lost, nowMs)
        if (result.lost.isNotEmpty()) {
            conn.qlogObserver.onLossDetected(level, result.lost.map { it.packetNumber })
        }
        state.nextLossTimeMs = result.nextLossTimeMs
    }

    /**
     * Cleanly tear down the driver. Runs on [parentScope] so the caller (which
     * may itself live inside the driver's [scope]) isn't cancelled before its
     * own teardown completes.
     *
     * Sequence:
     *  1. Mark the connection CLOSING so the writer starts emitting
     *     CONNECTION_CLOSE on the next drain.
     *  2. Wake the send loop and wait up to [CLOSE_FLUSH_TIMEOUT_MILLIS] for it
     *     to flush that packet — yield() alone is not enough because the send
     *     loop may be parked on Channel.receive on a different IO worker
     *     thread; only an explicit join+wakeup sequence guarantees the close
     *     bytes hit the socket.
     *  3. Force the loops out of their `while (status != CLOSED)` guards by
     *     transitioning to CLOSED, then cancel the scope and close the socket.
     *
     * The earlier yield()-based version raced: scope.cancel() could fire
     * while sendLoop was mid-`socket.send()`, occasionally producing partial
     * datagrams or skipping the CONNECTION_CLOSE entirely.
     */
    fun close() {
        // Round-5 #5: idempotent close. Memoize the teardown launch so a
        // second concurrent caller (which is common: session.close() and
        // read-loop death both race to close()) awaits the same Job rather
        // than launching a parallel teardown.
        if (closeJob.load() != null) return
        // Build the teardown coroutine LAZY so we can race-test the CAS
        // without paying for a launched-and-cancelled Job on the loser.
        val teardown =
            parentScope.launch(start = kotlinx.coroutines.CoroutineStart.LAZY) {
                connection.close(0L, "")
                wakeup()
                val send = sendJob
                // Bounded wait for the send loop to flush CONNECTION_CLOSE.
                // Event-driven via [QuicConnection.closingDrainSignal] —
                // both `drainOutbound` (after building the close datagram)
                // and `markClosedExternally` (forced transition) complete
                // the deferred. Replaces an earlier 1 ms polling loop.
                // The timeout is the upper bound on how long close() blocks
                // if the writer is wedged.
                withTimeoutOrNull(CLOSE_FLUSH_TIMEOUT_MILLIS) {
                    connection.closingDrainSignal.await()
                }
                // Now flip to CLOSED so both loops exit their while-guards.
                connection.markClosedExternally("driver close requested")
                wakeup()
                // Wait for both loops to actually exit — joinAll won't
                // return until the in-flight socket.send() completes.
                withTimeoutOrNull(CLOSE_FLUSH_TIMEOUT_MILLIS) {
                    listOfNotNull(readJob, send).joinAll()
                }
                // Final teardown — cancel guarantees both jobs are done
                // before we close the sockets.
                scope.cancel()
                activeSocket.close()
                probeSocket?.close()
                retiredSockets.forEach { it.close() }
            }
        if (closeJob.compareAndSet(null, teardown)) {
            teardown.start()
        } else {
            // A concurrent close() already installed the teardown Job; drop
            // ours without ever starting it. The winner's Job runs, this
            // call is a no-op (matching the original idempotent contract).
            teardown.cancel()
        }
    }

    companion object {
        /** Upper bound on close() flush wait. Each phase (drain + join) gets up to this much. */
        private const val CLOSE_FLUSH_TIMEOUT_MILLIS = 250L
    }
}

/**
 * Spec-correct response to a PTO timer firing (RFC 9002 §6.2.4). The probe
 * packet MUST be ack-eliciting at the encryption level with unacknowledged
 * data, and SHOULD retransmit the lost data rather than emit a bare PING —
 * so we requeue inflight CRYPTO bytes at every active pre-application
 * level (Initial AND Handshake), and the next [drainOutbound] emits a
 * CRYPTO frame at the original offset. `requeueAllInflight` is a no-op
 * when nothing is inflight, so calling this for already-ACKed or
 * already-discarded levels is harmless.
 *
 * `pendingPing` stays set as a fallback. `collectHandshakeLevelFrames`
 * suppresses the PING when CRYPTO is in the same frame list, so we
 * don't waste a frame on top of the retransmit.
 *
 * Why every active pre-application level, not just the highest: there's a
 * window between 1-RTT keys becoming installed (server's Finished arrives,
 * client derives application keys) and the handshake being confirmed
 * (server's HANDSHAKE_DONE arrives). In that window our own Finished is
 * still in flight at Handshake level, and the application-space loss
 * detection that ACK-only PINGs rely on doesn't cover it. If our Finished
 * is dropped, the server keeps retransmitting handshake CRYPTO forever
 * trying to elicit our missing ACK-eliciting handshake-level packet,
 * never confirms the handshake, never sends HANDSHAKE_DONE. Surfaced by
 * `handshakeloss` against aioquic at 30% drop rate (multiconnect iter 12
 * stuck at t=52s with zero handshake_done events; pre-fix
 * `handlePtoFired` gated the requeue on `application.sendProtection ==
 * null` and skipped Handshake CRYPTO retransmit once 1-RTT keys existed).
 *
 * Why aioquic interop demands this: aioquic strictly rejects pre-
 * handshake Initials that contain no CRYPTO frame
 * (`CONNECTION_CLOSE 0x0 "Packet contains no CRYPTO frame"`). A
 * bare-PING probe before the ClientHello is acknowledged is fatal.
 *
 * Extracted from [QuicConnectionDriver.sendLoop]'s PTO branch into a
 * top-level helper so the unit test in
 * [com.vitorpamplona.quic.connection.PtoCryptoRetransmitTest]
 * can invoke the EXACT logic the live driver does, without standing
 * up a UDP socket. Earlier shapes simulated the steps inline in the
 * test, which let the driver-side wiring regress twice
 * (commits c0d7b6031, then again in the lock-split refactor) without
 * any test breaking.
 *
 * Concurrency: `pendingPing` and `consecutivePtoCount` are `@Volatile`.
 * [QuicConnection.requeueAllInflightCrypto] delegates to
 * [com.vitorpamplona.quic.stream.SendBuffer.requeueAllInflight] which
 * is `synchronized(this)` internally, so it's safe to call without
 * an external lock — even concurrent with the writer's `takeChunk`.
 * If the parser concurrently runs `discardKeys` on the same level,
 * `requeueAllInflight` operates on the buffer reference we captured
 * (or the fresh one — both are valid) and is at worst a no-op.
 */
internal suspend fun handlePtoFired(conn: QuicConnection) {
    // RFC 9002 §6.2.2: the consecutive-PTO count advances by exactly
    // ONE per PTO timer expiry, so the §6.2.1 backoff is
    // `pto_base * 2^count` per firing. Pre-2026-05-08 we incremented
    // THREE times per firing — here + inside [requeueInflightForProbe]
    // + again from the send loop's between-probe re-requeue (RFC
    // §6.2.4 two-packet probe budget) — turning the backoff into
    // `2^(3*N)` — 1×, 8×, 64× per PTO instead of 1×, 2×, 4×.
    // Quic-go's `amplificationlimit` testcase exposed this: after the
    // sim drops client packets 2-7, we couldn't get a probe to the
    // server within its 5 s amp-limited idle timeout because PTO #3
    // didn't fire until ~11 s post-handshake.
    //
    // Increment FIRST so [requeueInflightForProbe]'s threshold check
    // (RFC 9000 §9 — trigger migration after PATH_PROBE_PTO_THRESHOLD
    // consecutive PTOs) sees the post-increment value, matching the
    // constant's natural reading: "after N consecutive PTOs with no
    // progress, trigger migration on the Nth PTO firing".
    conn.consecutivePtoCount = (conn.consecutivePtoCount + 1).coerceAtMost(6)
    // The next period counts from now even if no probe can go out (an
    // amplification limit), so the loop doesn't spin on an expired deadline.
    conn.ptoReferenceMs = conn.nowMillis()
    // Nothing in flight (the quiet after an ACK-only packet): one PING is
    // enough, not the usual two probes.
    val nothingInFlight = conn.initial.bytesInFlight == 0L && conn.handshake.bytesInFlight == 0L && conn.application.bytesInFlight == 0L
    // Repeated PTOs after growing the packet size: suspect a PMTU black hole.
    if (conn.consecutivePtoCount >= PMTU_BLACK_HOLE_PTO_COUNT) conn.pmtud.onBlackHoleSuspected(conn.nowMillis())
    conn.pendingPing = true
    requeueInflightForProbe(conn)
    // RFC 9002 §6.2.4: the spec allows up to 2 ack-eliciting packets
    // per PTO. The first probe falls out of the next drain naturally
    // (we just requeued); the send loop watches [pendingProbePackets]
    // and re-requeues for the second probe. Set AFTER the requeue so
    // a concurrent reader of the field doesn't see "budget set,
    // nothing requeued yet" — the requeue is what makes the budget
    // meaningful.
    conn.pendingProbePackets = if (nothingInFlight) 1 else 2
}

/**
 * Move any sent-but-not-ACK'd CRYPTO / STREAM bytes back onto the
 * retransmit queue at every active encryption level so the next
 * [drainOutbound] re-emits them. Used by both [handlePtoFired] (the
 * initial PTO requeue) and the send loop's RFC 9002 §6.2.4 probe
 * budget (the re-requeue between the first and second probe
 * datagram). Idempotent on levels with nothing inflight, so calling
 * it for already-ACKed or already-discarded levels is harmless.
 *
 * The level walk mirrors [handlePtoFired]'s original inline
 * sequence: Handshake first (most-recent CRYPTO), then Initial
 * (oldest), then Application (1-RTT STREAM data + post-handshake
 * CRYPTO). The application branch holds [QuicConnection.streamsLock]
 * because [QuicConnection.requeueAllInflightStreamData] iterates
 * `streamsList`, which `openBidiStream` mutates under the same lock.
 */
internal suspend fun requeueInflightForProbe(conn: QuicConnection) {
    if (conn.handshake.sendProtection != null && !conn.handshake.keysDiscarded) {
        conn.requeueAllInflightCrypto(EncryptionLevel.HANDSHAKE)
    }
    if (conn.initial.sendProtection != null && !conn.initial.keysDiscarded) {
        conn.requeueAllInflightCrypto(EncryptionLevel.INITIAL)
    }
    // [conn.consecutivePtoCount] is incremented exactly once per PTO
    // firing inside [handlePtoFired]; the path-validation threshold
    // check below reads the already-incremented value. Pre-2026-05-08
    // this function ALSO incremented the count, and the send loop's
    // between-probe re-requeue called this function again — turning
    // one PTO into +3 to the count. The amplificationlimit interop
    // testcase against quic-go flushed this: PTO #3 didn't fire until
    // ~11 s post-handshake, well past the 5 s amp-limited idle
    // timeout. See [handlePtoFired] kdoc for the full mechanism.
    // Once 1-RTT keys are installed, PTO must also retransmit application
    // data — STREAM bytes that were sent but never ACK'd. Without this,
    // a single corrupted/lost 1-RTT packet (especially the first one
    // carrying our HTTP/3 init streams + the GET request) is unrecoverable
    // because loss detection only runs after the peer ACKs something
    // and we have nothing else for the peer to ACK. Iterating streamsList
    // requires streamsLock — `openBidiStream` and friends mutate it under
    // the same lock, so unlocked iteration races with stream creation.
    if (conn.application.sendProtection != null) {
        // RFC 9002 §6.2.4: a probe carries data in flight. HANDSHAKE_DONE
        // gates the client's handshake confirmation: until it arrives
        // ngtcp2's client probes only with Handshake packets, which a
        // server that has dropped its Handshake keys can't read, and never
        // resends its request.
        conn.streamsLock.withLock {
            if (conn.isServer && conn.handshakeConfirmed && !conn.handshakeDoneAcked) conn.pendingHandshakeDone = true
            conn.requeueAllInflightStreamData()
            conn.requeueAllInflightCrypto(EncryptionLevel.APPLICATION)
            // RFC 9000 §9 client-initiated path validation. After
            // [PATH_PROBE_PTO_THRESHOLD] consecutive PTOs without
            // any inbound ACK we suspect the path is dead (NAT
            // rebind, route flap, dead peer). If the peer has
            // issued spare CIDs via NEW_CONNECTION_ID, rotate to
            // one and emit a PATH_CHALLENGE on the new DCID. The
            // validator only triggers on the FIRST crossing of
            // the threshold per validation cycle — the
            // [PathValidator] internally rejects re-entry while
            // [PathValidationState.Validating] holds.
            //
            // Also check the §8.2.4 budget on any in-flight
            // validation: 3*PTO since the challenge went out
            // without a matching response means the new path is
            // also dead — abandon and let the next PTO try with
            // another CID (or surface the failure to the higher
            // layer).
            //
            // Bug-5 fix: use [conn.nowMillis] so a test-injected
            // virtual clock takes effect. The pre-fix shape called
            // [Clock.System.now()] directly, ignoring the
            // connection's clock supplier and breaking timing
            // assertions in unit tests.
            val nowMillis = conn.nowMillis()
            val maxAckDelayMs = conn.peerTransportParameters?.maxAckDelay ?: 0L
            val ptoBaseMs = conn.lossDetection.ptoBaseMs(maxAckDelayMs).coerceAtLeast(1L)
            conn.checkPathValidationTimeoutLocked(nowMillis)
            if (conn.consecutivePtoCount >= PATH_PROBE_PTO_THRESHOLD) {
                conn.triggerPathMigrationLocked(nowMillis = nowMillis, currentPtoMillis = ptoBaseMs)
            }
        }
    }
}

/**
 * RFC 9000 §9 / §10.1.2 — number of consecutive PTOs we tolerate on
 * the active path before assuming it's dead and probing a new one.
 * The QUIC RFC doesn't pin a specific value (the spec only says "an
 * endpoint that has previously discovered a particular path
 * works"); 2 matches Firefox neqo's `PATH_PROBE_PTO_THRESHOLD`
 * default and Chrome's behavior. Picking 1 is too aggressive
 * (single dropped packet trips a rotation); 4+ is too late (user
 * notices the silence).
 *
 * The check in [handlePtoFired] runs AFTER the consecutive-PTO
 * counter is incremented, so the threshold value is the count of
 * PTOs that fired without an inbound ACK arriving in between.
 * With value 2 migration triggers on the 2nd consecutive PTO.
 *
 * Once the threshold is crossed, [handlePtoFired] calls into
 * [QuicConnection.triggerPathMigrationLocked] which is itself
 * idempotent — a second crossing while validation is already in
 * flight is a no-op.
 */
internal const val PATH_PROBE_PTO_THRESHOLD: Int = 2

/** Consecutive PTOs after which full-size packets are presumed to vanish (RFC 8899 §4.3). */
internal const val PMTU_BLACK_HOLE_PTO_COUNT: Int = 3
