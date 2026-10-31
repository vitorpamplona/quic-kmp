# quic-kmp

A from-scratch, pure-Kotlin QUIC (v1 and v2) client and server with HTTP/3, QPACK and WebTransport,
published to Maven Central as `com.vitorpamplona.quic:quic`. It started inside
[Amethyst](https://github.com/vitorpamplona/amethyst) (as `:quic`). Its consumers are Amethyst's
`nestsClient` (audio rooms over MoQ/WebTransport) and marmot-kmp's `marmot-quic` (Marmot agent
streams over raw QUIC, its own ALPNs). Neither protocol belongs here: MoQ stays in `nestsClient`,
Marmot's binding in marmot-kmp.

## Layout

- `quic/` — the library. `commonMain` holds the protocol (connection, recovery, frames, packets,
  TLS 1.3 state machine, HTTP/3, QPACK, WebTransport); `jvmAndroid` holds the JCA AEADs, the
  certificate validators and the UDP socket. Targets: `jvm` and `android` only.
- `interop/` — `:quic-interop`, the [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
  endpoint (JVM app + Docker image). Never published.
- `plans/`, `interop/plans/` — design notes, `YYYY-MM-DD-<slug>.md`.

## Rules

- Crypto primitives and the secure random source come from
  [crypto-kmp](https://github.com/vitorpamplona/crypto-kmp) (`com.vitorpamplona.crypto`). Don't
  reimplement them here; if one is missing, add it there. To change both together, build against
  a local checkout with `-PcryptoKmpDir=../crypto-kmp`.
- `commonMain` and `commonTest` stay free of JVM-only APIs, so more targets can be added. CI and the
  pre-push hook compile both for a native target with
  `./gradlew -PquicNativeCheck :quic:compileTestKotlinLinuxX64`; plain `jvm`/`android` builds don't
  catch a JVM call there. That target's actuals in `quic/src/nativeCheck/` only throw: they exist so
  the check compiles, never run them. For a lock, use `com.vitorpamplona.quic.synchronized` with a
  `SynchronizedObject`, not `kotlin.synchronized`; for `@Volatile`, import `kotlin.concurrent.Volatile`;
  in tests use `assertTrue`, not `assert`, and write backticked test names with letters, digits,
  spaces, `-` and `_` only (Kotlin/Native rejects `()`, `,`, `.`, `:`, `/`, `#` and others). JVM-only tests go in `jvmTest`. The platform layer (UDP
  socket, ciphers, TLS transcript hash, lock, certificate validators) has JVM actuals only.
- Releases follow semantic versioning from 1.0.0: a breaking change to the public API bumps the
  major version. Amethyst and marmot-kmp pin a version, so a breaking change also needs a matching
  change in Amethyst's `nestsClient` and marmot-kmp's `marmot-quic`. crypto-kmp is pinned in `gradle/libs.versions.toml`.
- Log through `QuicLog` (`QuicLog.d(TAG) { "…$x" }`): the library logs nothing until the app sets
  `QuicLog.sink`. Read wall-clock time from `kotlin.time.Clock` or an injected source.
- Before pushing: `./gradlew spotlessApply` and
  `./gradlew :quic:jvmTest :quic:testAndroidHostTest :quic-interop:test` (the pre-push hook runs
  these plus the `commonMain` check).
  Changes that can affect wire bytes, congestion control or the TLS state machine should also run
  the interop matrix (`interop/run-matrix.sh`, one peer at a time).
- Commits: conventional commits (`feat:`, `fix:`, …). Never `--no-verify`.

## Remotes and pull requests

The repo is on GitHub, `github.com/vitorpamplona/quic-kmp`, which holds the canonical `main`, and on
nostr as a NIP-34 repository,
`nostr://npub1gcxzte5zlkncx26j68ez60fzkvtkm9e0vrwdcvsjakxf9mu9qewqlfnj5z/relay.ngit.dev/quic-kmp`: a
push to that remote goes to its GRASP git servers and to GitHub. A PR can go out either way: a
GitHub PR (`gh`), or a nostr proposal (`ngit`, a `pr/…` branch, reviewed on
[gitworkshop.dev](https://gitworkshop.dev/npub1gcxzte5zlkncx26j68ez60fzkvtkm9e0vrwdcvsjakxf9mu9qewqlfnj5z/relay.ngit.dev/quic-kmp)).
Remote names vary per clone, so identify them by URL. Open a PR only when the human you work for
asks, and before opening, revising or merging one by either path, use the `ngit-pr` skill.

## Releasing

Bump `VERSION_NAME` in `gradle.properties`, then push a `v<version>` tag. The
`create-release.yml` workflow tests, publishes to Maven Central and opens the GitHub release.
See `README.md` → Publishing for the signing secrets it needs.
