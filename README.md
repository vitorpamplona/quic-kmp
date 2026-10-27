# QUIC for Kotlin Multiplatform

[![GitHub downloads](https://img.shields.io/github/downloads/vitorpamplona/quic-kmp/total?label=Downloads&labelColor=27303D&color=0D1117&logo=github&logoColor=FFFFFF&style=flat)](https://github.com/vitorpamplona/quic-kmp/releases)
[![Last Version](https://img.shields.io/github/release/vitorpamplona/quic-kmp.svg?maxAge=3600&label=Stable&labelColor=06599d&color=043b69)](https://github.com/vitorpamplona/quic-kmp/releases/latest)
[![Maven Central](https://img.shields.io/maven-central/v/com.vitorpamplona.quic/quic?label=Maven%20Central&labelColor=27303D&color=0877d2)](https://central.sonatype.com/artifact/com.vitorpamplona.quic/quic)
[![JitPack snapshots](https://img.shields.io/badge/snapshots-JitPack-27303D?labelColor=27303D&color=0877d2)](https://jitpack.io/#vitorpamplona/quic-kmp)
[![CI](https://img.shields.io/github/actions/workflow/status/vitorpamplona/quic-kmp/build.yml?labelColor=27303D)](https://github.com/vitorpamplona/quic-kmp/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/github/license/vitorpamplona/quic-kmp?labelColor=27303D&color=0877d2)](LICENSE)

A pure-Kotlin **QUIC** client and server (v1 and v2) with **HTTP/3**, **QPACK** and
**WebTransport** building blocks, for the JVM and Android. No JNI, no BouncyCastle, no native QUIC library: the TLS 1.3 handshake,
packet protection, loss recovery, flow control and stream machinery are all Kotlin. The platform's
JCA does AES-GCM, ChaCha20-Poly1305 and certificate validation.

It was written for [Amethyst](https://github.com/vitorpamplona/amethyst)'s audio rooms (MoQ over
WebTransport), because no Android-compatible Java QUIC library existed, and it carries Amethyst's
audio rooms and Marmot agent streams in production.

## Features

| Area | What you get |
|---|---|
| QUIC v1 (RFC 9000) | Client and server. Bidirectional and unidirectional streams with flow control, version negotiation, Retry, connection IDs (`NEW_CONNECTION_ID` / `RETIRE_CONNECTION_ID`), path validation, NAT rebinding, preferred addresses (the client moves to one; the server offers one), stateless reset, `NEW_TOKEN`, ECN on 1-RTT, path MTU discovery (RFC 8899), latency spin bit, keep-alive |
| QUIC v2 (RFC 9369, RFC 9368) | Both versions, and compatible version negotiation from v1 to v2 on either side |
| TLS 1.3 for QUIC (RFC 8446, RFC 9001) | X25519 and P-256 (secp256r1) key exchange, with HelloRetryRequest on both sides (the client sends an X25519 share and lists both; the server asks for a share it can use); `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`; RSA-PSS, ECDSA and Ed25519 certificates (Ed25519 needs Android 13+); 1-RTT key update (both directions); session resumption and 0-RTT, as client and as server (session tickets, PSK binders, single-use 0-RTT tickets) |
| Recovery (RFC 9002) | RTT estimation, packet- and time-threshold loss detection, PTO, per-frame retransmission, CUBIC (RFC 9438) or NewReno congestion control with pacing, persistent congestion and ECN-CE response, delayed ACKs, the ACK frequency extension (draft-ietf-quic-ack-frequency) as receiver |
| Datagrams (RFC 9221) | Send and receive unreliable `DATAGRAM` frames |
| HTTP/3 (RFC 9114) | Frame reader (optionally streaming DATA bodies) and writer, `SETTINGS`, control and request streams, `GOAWAY` |
| QPACK (RFC 9204) | Static table and Huffman. The encoder sends literals; the decoder also reads dynamic-table references |
| WebTransport over HTTP/3 | Extended CONNECT, session streams, capsules (`WT_CLOSE_SESSION`), HTTP datagrams |
| Debugging | qlog events (`QlogObserver`, viewable in [qvis](https://qvis.quictools.info/)) and TLS secrets for Wireshark (`TlsSecretsListener`) |

Interop is tested against the implementations in the
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner), both as client and as
server (see [Interop matrix](#interop-matrix)).

### Not supported

- Key-exchange groups other than X25519 and P-256 (P-384, P-521, FFDHE, hybrid post-quantum
  groups such as X25519MLKEM768).
- HTTP/3 server push and QPACK dynamic-table inserts on the encoder.
- Client certificates on the server.
- **Targets other than JVM and Android.** The protocol code in `commonMain` is platform-neutral
  (CI compiles it as common code), but the UDP socket, packet ciphers, TLS transcript hash, lock
  and certificate validation exist only for the JVM so far.

## Install

The library is on Maven Central:

```kotlin
dependencies {
    implementation("com.vitorpamplona.quic:quic:<version>")
}
```

| Requirement | |
|---|---|
| JVM | Java 21 |
| Android | minSdk 26 |
| Kotlin coroutines | the API is `suspend` and `Flow` based |

The crypto primitives (HKDF, HMAC, SHA-256, SHA-384, AES-GCM, ChaCha20-Poly1305, X25519, P-256, secure random)
come from [crypto-kmp](https://github.com/vitorpamplona/crypto-kmp)
(`com.vitorpamplona.crypto:crypto`), which depends on nothing but the Kotlin stdlib. Its
`X25519KeyPair` appears in `TlsClient`'s API, so it comes along as an `api` dependency.

## Quick start

A connection needs three things: a `UdpSocket`, a `QuicConnection` (the protocol state) and a
`QuicConnectionDriver`, which runs the read and send loops on the scope you give it.

```kotlin
val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

val socket = UdpSocket.connect("example.com", 443)
val connection =
    QuicConnection(
        serverName = "example.com",
        config = QuicConnectionConfig(),
        tlsCertificateValidator = JdkCertificateValidator(),
        alpnList = listOf("my-protocol".encodeToByteArray()),
    )
val driver = QuicConnectionDriver(connection, socket, scope)
driver.start()

try {
    withTimeout(10_000) { connection.awaitHandshake() }
    check(connection.status == QuicConnection.Status.CONNECTED)

    val stream = connection.openBidiStream()
    stream.send.enqueue("hello".encodeToByteArray())
    stream.send.finish()
    driver.wakeup()

    stream.incoming.collect { chunk -> println(chunk.decodeToString()) }
} finally {
    driver.close()
}
```

Things to know:

- **Call `driver.wakeup()` after you write.** `send.enqueue` only buffers. The wake-up tells the
  send loop there is something to send.
- **`awaitHandshake()` has no deadline of its own.** A server that drops your packets, or fails
  TLS without sending an alert, leaves it waiting, so wrap it in `withTimeout`.
- **`alpnList` defaults to `h3`.** Pass your own protocol identifiers for anything else, and
  read the one the server picked from `connection.tls.negotiatedAlpn`.
- **`driver.close()` sends `CONNECTION_CLOSE`** and stops both loops. Use
  `connection.close(errorCode, reason)` to close with an application error code.

## Streams and datagrams

Peer-initiated streams arrive through `awaitIncomingPeerStream()`, which returns `null` once the
connection closes. **Always consume them.** A stream's receive window only moves as you read
`incoming`, so a stream nobody reads stalls the peer once its window is used up, and unread
streams hold back the connection-level window too. An HTTP/3 server opens three of these (control
and the two QPACK streams) as soon as you connect.

```kotlin
scope.launch {
    while (true) {
        val stream = connection.awaitIncomingPeerStream() ?: break
        launch { stream.incoming.collect { chunk -> println(chunk.size) } }
    }
}
```

You can send datagrams once the server has advertised support for them. Receiving is on by
default (`QuicConnectionConfig.maxDatagramFrameSize`):

```kotlin
connection.queueDatagram(byteArrayOf(1, 2, 3))
driver.wakeup()

val datagram: ByteArray? = connection.awaitIncomingDatagram() // null once closed
```

`openUniStream(bestEffort = true)` gives a unidirectional stream whose lost data is not
retransmitted. That suits real-time media, where a late frame is worthless.

## Certificate validation

`tlsCertificateValidator` is required, so a choice is always explicit:

| Validator | Use it for |
|---|---|
| `JdkCertificateValidator()` | The normal case: the system trust store, hostname and IP-literal checks |
| `PinnedCertificateValidator.ofSha256Hex("5E:FF:3A:...")` | Self-signed or private servers: accepts only certificates with these SHA-256 fingerprints (`openssl x509 -fingerprint -sha256` output pastes in as-is). `ofDer(...)` takes the certificates themselves |
| `PermissiveCertificateValidator()` | Tests and local development only. It accepts anything |

You can implement `CertificateValidator` for other policies.

## Session resumption and 0-RTT

Keep the tickets the server issues and hand one back on the next connection to the same server
to resume the TLS session:

```kotlin
val ticketCache = mutableMapOf<String, TlsResumptionState>()

val connection =
    QuicConnection(
        serverName = "example.com",
        config = QuicConnectionConfig(),
        tlsCertificateValidator = JdkCertificateValidator(),
        resumption = ticketCache["example.com"],
        onResumptionTicket = { ticketCache["example.com"] = it },
    )
```

When the ticket allows early data, stream data you write before `awaitHandshake()` returns goes
out as 0-RTT. If the server rejects early data, that data is resent once the handshake
completes; if it rejects the ticket, you get a full handshake. A ticket is only offered for the
same ALPN. 0-RTT data can be replayed by an attacker, so send only requests that are safe to
repeat.

## HTTP/3 and WebTransport

The library has the HTTP/3 and WebTransport pieces, not a turnkey HTTP client. You open the
control stream, send the request, and read the response with the frame and QPACK codecs, then
hand the session to `QuicWebTransportSessionState`. A WebTransport session looks like this
(connect with the default `h3` ALPN):

```kotlin
// HTTP/3 control stream, with SETTINGS that enable WebTransport.
val control = connection.openUniStream()
control.send.enqueue(byteArrayOf(Http3StreamType.CONTROL.toByte()) + buildClientWebTransportSettings().encodeFrame())

// Extended CONNECT (RFC 9220) on a request stream.
val request = connection.openBidiStream()
request.send.enqueue(encodeHeadersFrame(buildExtendedConnectHeaders("example.com:443", "/moq", bearerToken = null)))
driver.wakeup()

// Read frames until the response HEADERS, then check :status.
val reader = Http3FrameReader()
val status =
    request.incoming
        .transform { chunk ->
            reader.push(chunk)
            while (true) emit(reader.next() ?: break)
        }.filterIsInstance<Http3Frame.Headers>()
        .map { headers ->
            QpackDecoder()
                .decodeFieldSection(headers.qpackPayload)
                .first { it.first == ":status" }
                .second
                .toInt()
        }.first()
check(status in 200..299) { "CONNECT rejected: $status" }

val session = QuicWebTransportSessionState(connection, driver, request.streamId)
```

The session drains the server's control and QPACK streams for you and surfaces only the
WebTransport streams that belong to it:

```kotlin
val out = session.openUniStream()
out.send.enqueue("hi".encodeToByteArray())
driver.wakeup()

session.sendDatagram(byteArrayOf(42))

scope.launch {
    session.incomingStrippedStreams.collect { stream ->
        stream.data.collect { chunk -> println(chunk.size) }
    }
}

session.close(errorCode = 0, reason = "bye")
```

`buildExtendedConnectHeaders` takes extra headers, for example `wt-available-protocols` to offer
WebTransport sub-protocols. Amethyst's
[`QuicWebTransportFactory`](https://github.com/vitorpamplona/amethyst/blob/main/nestsClient/src/jvmAndroid/kotlin/com/vitorpamplona/nestsclient/transport/QuicWebTransportFactory.kt)
is a complete client built this way, with timeouts and error reporting.

## Server

`QuicServer` accepts connections on one UDP socket: it routes packets by connection ID, answers
unknown versions with Version Negotiation, can require a Retry round trip to validate client
addresses, and sends stateless resets for connections it doesn't know.

```kotlin
val server =
    QuicServer(
        QuicServerConfig(
            signer = JcaCertificateSigner.fromPem(certPem, keyPem),
            alpnSelector = { offered -> offered.firstOrNull { it.contentEquals("h3".encodeToByteArray()) } },
            supportedVersions = listOf(QuicVersion.V1, QuicVersion.V2),
            ticketKeys = TlsSessionTicketKeys(), // resumption; add maxEarlyDataSize = 0xffffffff for 0-RTT
        ),
        UdpServerSocket.bind(host = null, port = 443),
        scope,
    )
server.start()
while (true) {
    val accepted = server.accept() ?: break
    scope.launch {
        accepted.connection.awaitHandshake()
        while (true) {
            val stream = accepted.connection.awaitIncomingPeerStream() ?: break
            // read stream.incoming, answer on stream.send, then accepted.driver.wakeup()
        }
    }
}
```

`JcaCertificateSigner` loads PKCS#8, SEC1 and PKCS#1 keys for ECDSA, RSA and Ed25519
certificates. The interop endpoint's
[`InteropServer`](interop/src/main/kotlin/com/vitorpamplona/interop/runner/InteropServer.kt)
is a complete hq-interop and HTTP/3 file server built this way.

## Configuration

`QuicConnectionConfig` holds the transport parameters this client advertises. The defaults suit a
long-lived connection with many streams:

| Parameter | Default |
|---|---|
| `initialMaxData` | 16 MiB per connection |
| `initialMaxStreamDataBidiLocal` / `BidiRemote` / `Uni` | 1 MiB per stream |
| `initialMaxStreamsBidi` / `initialMaxStreamsUni` | 100 / 10,000 (both extend as streams close) |
| `maxIdleTimeoutMillis` | 30 s |
| `maxDatagramFrameSize` | 1200 bytes, the largest datagram the peer may send (0: none) |
| `congestionControl` | `CUBIC` (`NEW_RENO` also available) |
| `compatibleVersions` | `[V1]`; add `V2` to offer QUIC v2 (RFC 9368) |
| `spinBit`, `ackFrequency`, `greaseTransportParameters`, `migrateToPreferredAddress` | on |
| `keepAliveIntervalMillis` | 0 (off) |

## Debugging

- **qlog.** Pass a `QlogObserver` as `qlogObserver` to get every packet, frame and recovery
  event. The interop runner's
  [`QlogWriter`](interop/src/main/kotlin/com/vitorpamplona/interop/runner/QlogWriter.kt)
  writes them as a `.sqlog` file that qvis opens.
- **Wireshark.** Pass a `TlsSecretsListener` as `extraSecretsListener` and write the secrets in
  `SSLKEYLOGFILE` format to decrypt a capture.
- **Logs.** The library logs nothing until you set `QuicLog.sink`. Point it at your logger once,
  at startup:

  ```kotlin
  QuicLog.sink =
      QuicLog.Sink { level, tag, message, throwable ->
          println("[$level] $tag: $message")
          throwable?.printStackTrace()
      }
  ```

  If your logger filters by level, override `Sink.isLoggable` too, so a line it would drop is
  never built. Set `writerDebugEnabled = true` (in `com.vitorpamplona.quic.connection`) as well for the
  writer's per-packet traces.

## Versioning

Releases follow [semantic versioning](https://semver.org/): a breaking change to the public API
bumps the major version. Each release is tagged `v<version>` and listed on the
[releases page](https://github.com/vitorpamplona/quic-kmp/releases).

## Developer Setup

Make sure to have the following pre-requisites installed:
1. Java 21
2. Android Studio or IntelliJ Idea CE

Create a `local.properties` file that points to your Android SDK. If you are using Android Studio,
the IDE performs this step for you.

```bash
echo "sdk.dir=/Users/<your user>/Library/Android/sdk" > local.properties
```

Install the git hooks (formatting check on commit; formatting and the full test suite, as in CI,
on push):

```bash
./gradlew installGitHook
```

## Building

```bash
./gradlew assemble
```

## Testing

```bash
./gradlew :quic:jvmTest :quic:testAndroidHostTest :quic-interop:test
```

Opt-in long runs: `-PquicSoakSeconds=1800` turns on the audio-rooms soak test, and
`./gradlew :quic:interop -PinteropHost=127.0.0.1 -PinteropPort=4433` drives a live QUIC server.
`scripts/run-picoquic.sh` starts a local picoquic to point it at.

## Interop matrix

`interop/` packages the client and server as a
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) endpoint image and runs
it against other implementations:

```bash
interop/run-matrix.sh -s aioquic -t handshake,chacha20   # our client, aioquic's server
interop/run-matrix.sh -c quic-go -t handshake,retry      # our server, quic-go's client
```

It needs Docker, and it clones the runner next to this repo on first use. Run one peer at a time:
the runner is not safe to run concurrently. On a host whose kernel has no IPv6 (some sandboxes and
CI VMs), `interop/no-ipv6/patch-runner.sh` adapts the runner checkout; the `ipv6` testcase
and IPv6 preferred addresses can't pass there.

Results from 2026-10-26, in such a sandbox, against every implementation in the runner, both as
client and as server: apart from `ipv6`, every testcase both sides support passes, except where
the other implementation or the sandbox is at fault (a few loss and corruption tests fail now and
then when a run loses every copy of a packet). The tables, and the reason for each failure, are
in [`plans/2026-10-25-feature-parity.md`](plans/2026-10-25-feature-parity.md).

Design notes behind the stack and the interop work live in `plans/` and `interop/plans/`.

## Publishing

Install GnuPG and generate a key:

```bash
gpg --gen-key
```

Run `gpg --list-keys` to show your GPG keys.

Distribute the public key:

```bash
gpg --keyserver keyserver.ubuntu.com --send-keys <pubkey>
```

Export your private key to a file

```bash
gpg --export-secret-keys > ~/.gnupg/secring.gpg
```

Generate a User Token on MavenCentral

To publish from local, and add the following fields to your ~/.gradle/gradle.properties file:

```properties
mavenCentralUsername=<maven user>
mavenCentralPassword=<maven password>
signing.keyId=<gpg key id>
signing.password=<gpg key passphrase>
signing.secretKeyRingFile=<yourhome>/.gnupg/secring.gpg
```

Then run

```bash
./gradlew :quic:publishAllPublicationsToMavenCentral --no-configuration-cache
```

To publish from GitHub Actions, export your private key as a base64 string:

```bash
gpg --export-secret-keys --armor <key-id> ~/.gnupg/secring.gpg | grep -v '\-\-' | grep -v '^=.' | tr -d '\n'
```

and add the following secrets to your GitHub secrets:

```properties
SONATYPE_USERNAME=<maven user>
SONATYPE_PASSWORD=<maven password>
SIGNING_PRIVATE_KEY=<base64versionOfTheFile>
SIGNING_PASSWORD=<gpg key passphrase>
```

Then tag the release version starting with `v`. Tag `v1.0.0` publishes version `1.0.0`:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

## Contributing

Issues can be logged on [GitHub issues](https://github.com/vitorpamplona/quic-kmp/issues). [Pull requests](https://github.com/vitorpamplona/quic-kmp/pulls) are very welcome.

By contributing to this repository, you agree to license your work under the MIT license. Any work contributed where you are not the original author must contain its license header with the original author(s) and source.

# MIT License

See [LICENSE](LICENSE).
