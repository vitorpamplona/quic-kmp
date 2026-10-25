# Feature parity with other QUIC stacks

> **Status:** done for what's listed under "Added"; interop results below — 2026-10-25.

## Why

`:quic` started as the client Amethyst needed. Measured against the stacks in the
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) (quic-go, quinn,
ngtcp2, picoquic, quiche, msquic, neqo, mvfst, lsquic, s2n-quic, aioquic, xquic, kwik, …) it was
missing a server role, congestion control, QUIC v2, PMTU discovery and a handful of smaller
transport features, and it could only be tested from one side of the matrix.

## Added

| Area | What | Where |
|---|---|---|
| QUIC v2 | RFC 9369 keys, labels, Retry and packet types; RFC 9368 compatible version negotiation, client and server | `packet/PacketTypes.kt`, `QuicConnection` |
| Server | TLS 1.3 server (PSK, tickets, 0-RTT), server `QuicConnection`, `QuicServer` endpoint (VN, Retry, stateless reset, CID routing), NAT rebinding, preferred address, NEW_TOKEN, connection limit, interop server | `quic/plans/2026-10-25-server-role.md` |
| Congestion control | NewReno and CUBIC (default), pacing, persistent congestion, ECN-CE | `recovery/CongestionController.kt` |
| Path MTU | DPLPMTUD (RFC 8899) with black-hole fallback | `PmtuDiscovery.kt` |
| ACKs | Delayed ACKs (RFC 9000 §13.2), ACK frequency extension as receiver | `recovery/AckTracker.kt` |
| Migration | Client moves to a server's preferred address; servers follow a moved client and limit what they send to it until validated | `PathProbe.kt`, `QuicConnection` |
| Smaller | Immediate close on local errors, BLOCKED frames, §7.2 DCID adoption, §12.4 frame/packet-type checks, NEW_TOKEN, transport-parameter grease, keep-alive, latency spin bit, streaming HTTP/3 DATA | |

Fixed on the way, found by testing against our own server: stream credit followed arrival
instead of consumption (a fast sender overflowed the app channel and killed the connection),
`extraSecretsListener` never received traffic secrets (SSLKEYLOGFILE was empty), 1-RTT CRYPTO
was never sent, and `original_destination_connection_id` was checked against the DCID from
before Version Negotiation.

## Not done

- `TLS_AES_256_GCM_SHA384` and P-256 key shares (so HelloRetryRequest): crypto-kmp has neither
  SHA-384 nor P-256 yet.
- Client certificates; HTTP/3 server push; QPACK dynamic-table inserts; multipath.
- The sending side of the ACK frequency extension.
- Reading ECN marks on receive: the JVM can't see the TOS byte, so ACK_ECN counts are zero and
  peers turn ECN off after validation.

## Interop environment notes

Runs here used a sandbox without kernel IPv6; `quic/interop/no-ipv6/patch-runner.sh` adapts the
runner. Consequences:

- `ipv6` can't pass, and `connectionmigration` fails wherever the server needs an IPv6 preferred
  address (neqo, picoquic, ngtcp2).
- The host's tshark (4.2.2) can't decrypt 1-RTT packets from ngtcp2, which starts its packet
  numbers at a random large value; the rebind checks then can't see the PATH_CHALLENGE that is
  there (checked by decrypting the packets by hand, and with tshark 4.6.6).
- quiche's rebind tests time out against our client: the packets quiche sent just as the NAT
  rebound are lost, our ACKs (sent on the new path) report the gap, but quiche's log never
  declares those packets lost, so the data is never resent and the transfer waits forever. Per-path
  loss detection is the likely cause; unconfirmed.
