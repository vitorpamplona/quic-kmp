# QUIC for Kotlin Multiplatform

A from-scratch, pure-Kotlin QUIC v1 (RFC 9000/9001/9002) client with HTTP/3 (RFC 9114), QPACK
(RFC 9204) and WebTransport over HTTP/3. No JNI, no BouncyCastle: the TLS 1.3 handshake, packet
protection, loss recovery and stream machinery are all Kotlin, with the platform's JCA providing
AES-GCM/ChaCha20 and certificate validation.

It was built for [Amethyst](https://github.com/vitorpamplona/amethyst)'s audio rooms (MoQ over
WebTransport) because no Android-compatible Java QUIC library existed. Amethyst still uses it in
production for its audio rooms and Marmot agent streams.

Targets: **JVM** and **Android** (minSdk 26). The crypto primitives (HKDF, HMAC, SHA-256,
AES-GCM, ChaCha20-Poly1305, X25519, secure random) come from
[Quartz](https://central.sonatype.com/artifact/com.vitorpamplona.quartz/quartz).

## Install

```kotlin
dependencies {
    implementation("com.vitorpamplona.quic:quic:<version>")
}
```

## Usage

Open a connection, wait for the handshake, then open streams:

```kotlin
val socket = UdpSocket.connect("example.com", 443)
val connection =
    QuicConnection(
        serverName = "example.com",
        config = QuicConnectionConfig(),
        tlsCertificateValidator = JdkCertificateValidator(),
        alpnList = listOf("h3".encodeToByteArray()),
    )
val driver = QuicConnectionDriver(connection, socket, scope)
driver.start()

connection.awaitHandshake()

val stream = connection.openBidiStream()
stream.send.enqueue("hello".encodeToByteArray())
stream.send.finish()
driver.wakeup()

stream.incoming.collect { chunk -> /* bytes from the peer */ }

driver.close()
```

Certificate validators live in `com.vitorpamplona.quic.tls`: `JdkCertificateValidator` (system
trust store), `PinnedCertificateValidator` (SHA-256 fingerprint pinning) and
`PermissiveCertificateValidator` (tests and local development only).

Debug output goes through Quartz's `Log` (`com.vitorpamplona.quartz.utils.Log`).

## Developer Setup

Make sure to have the following pre-requisites installed:
1. Java 21
2. Android Studio or IntelliJ Idea CE

Create a `local.properties` file that points to your Android SDK. If you are using Android Studio,
the IDE performs this step for you.

```bash
echo "sdk.dir=/Users/<your user>/Library/Android/sdk" > local.properties
```

Install the git hooks (spotless on commit, tests on push):

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
`quic/scripts/run-picoquic.sh` starts a local picoquic to point it at.

## Interop matrix

`quic/interop/` packages the client as a
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) endpoint image and runs
it against other implementations:

```bash
quic/interop/run-matrix.sh -s aioquic -t handshake,chacha20
```

Design notes behind the stack and the interop work live in `quic/plans/` and `quic/interop/plans/`.

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

Then tag the release version starting with `v`. Tag `v0.1.0` publishes version `0.1.0`:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Contributing

Issues can be logged on [GitHub issues](https://github.com/vitorpamplona/quic-kmp/issues). [Pull requests](https://github.com/vitorpamplona/quic-kmp/pulls) are very welcome.

By contributing to this repository, you agree to license your work under the MIT license. Any work contributed where you are not the original author must contain its license header with the original author(s) and source.

# MIT License

See [LICENSE](LICENSE).
