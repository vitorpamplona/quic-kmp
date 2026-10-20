# quic-kmp

A from-scratch, pure-Kotlin QUIC v1 + HTTP/3 + QPACK + WebTransport client, published to Maven
Central as `com.vitorpamplona.quic:quic`. It started inside
[Amethyst](https://github.com/vitorpamplona/amethyst) (as `:quic`), which is still its main
consumer: `nestsClient` (audio rooms over MoQ/WebTransport) and `marmotQuic` (Marmot agent
streams) build on it.

## Layout

- `quic/` — the library. `commonMain` holds the protocol (connection, recovery, frames, packets,
  TLS 1.3 state machine, HTTP/3, QPACK, WebTransport); `jvmAndroid` holds the JCA AEADs, the
  certificate validators and the UDP socket. Targets: `jvm` and `android` only.
- `quic/interop/` — `:quic-interop`, the [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
  endpoint (JVM app + Docker image). Never published.
- `quic/plans/`, `quic/interop/plans/` — design notes, `YYYY-MM-DD-<slug>.md`.

## Rules

- Crypto primitives and the secure random source come from Quartz (`com.vitorpamplona.quartz`).
  Don't reimplement them here; if one is missing, add it to Quartz.
- `commonMain` stays free of new JVM-only APIs, so more targets can be added later.
- The public API is consumed by Amethyst from a pinned version. A breaking change needs a version
  bump and a matching change in Amethyst's `nestsClient` / `marmotQuic`.
- Log through Quartz's `Log` with the lambda overload (`Log.d(TAG) { "…$x" }`).
- Before pushing: `./gradlew spotlessApply` and
  `./gradlew :quic:jvmTest :quic:testAndroidHostTest :quic-interop:test`.
  Changes that can affect wire bytes, congestion control or the TLS state machine should also run
  the interop matrix (`quic/interop/run-matrix.sh`, one peer at a time).
- Commits: conventional commits (`feat:`, `fix:`, …). Never `--no-verify`.

## Releasing

Bump `VERSION_NAME` in `gradle.properties`, then push a `v<version>` tag. The
`create-release.yml` workflow tests, publishes to Maven Central and opens the GitHub release.
See `README.md` → Publishing for the signing secrets it needs.
