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
| Server | TLS 1.3 server (PSK, tickets, 0-RTT, HelloRetryRequest), server `QuicConnection`, `QuicServer` endpoint (VN, Retry, stateless reset, CID routing), NAT rebinding, preferred address, NEW_TOKEN, connection limit, interop server | `quic/plans/2026-10-25-server-role.md` |
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

Found by the server sweep, and affecting the client as well:

- Lost STREAM data was never resent on a "closed" stream (our FIN sent, the peer's FIN received),
  which is every server response once its last byte is out. A stream was also retired once its
  FIN was acknowledged, even with an earlier range still lost. quic-go's HTTP/3 and handshakeloss
  clients waited forever for the missing bytes.
- A lost range was capped by flow-control credit like new data, so a stream that had used its
  whole window could deadlock waiting for credit the peer withholds until the gap fills.
- The PTO timer ran with nothing in flight, so an idle connection sent a PING every PTO. That
  timer had also been flushing stream writes made without `driver.wakeup()`; writes now wake the
  send loop themselves.
- The reserved header bits were checked before the AEAD, so about three in four undecryptable
  packets (corrupted, forged, or left over from before a version switch) closed the connection
  instead of being dropped.
- An ICMP port unreachable made the client socket's `receive()` throw, which killed the read loop
  with an uncaught exception (an app crash on Android) whenever the server's port closed.
- Every 1-RTT ACK was an ACK_ECN with zero counts. nginx closes the connection with
  INTERNAL_ERROR on the first ACK_ECN it gets, so our client never finished a transfer from nginx.
  ACKs now carry counts only once the peer's ACKs do. ACK_ECN counts were also decoded and
  dropped, so the ECN-CE congestion response never saw a real count.
- A PATH_CHALLENGE that arrived with the PATH_RESPONSE validating our preferred-address probe
  was never answered.

- A resent NEW_CONNECTION_ID for a connection ID we had already retired put it back in the pool,
  and quinn answered our next packet on it with a stateless reset.
- Handshake ACKs were sent once: with that ACK lost and the peer's packets ACK-only, picoquic
  never learned its certificate was lost. Ack-eliciting Initial/Handshake packets now repeat it.
- A server PATH_CHALLENGE that arrived on our preferred-address probe just before its
  PATH_RESPONSE went unanswered, and lsquic never moved its sending to the new path.
- A receiver that sent only ACKs went silent when the peer's packets stopped arriving (after a
  NAT rebinding), so the peer never learned its new address. A PTO of silence after an ACK-only
  packet now sends one PING.

Server-only: a client whose NAT rebound before the handshake finished was never answered again;
with a HelloRetryRequest the server switched versions before the retry (picoquic then restarted its
handshake) and skipped PSK resumption on ClientHello2 (s2n-quic, xquic, kwik lead with P-256
shares); and a path the client probed (our preferred address) is now challenged and validated
before the client moves there.

## Not done

- `TLS_AES_256_GCM_SHA384` and P-256 key shares: crypto-kmp has neither SHA-384 nor P-256 yet.
  A client that lists X25519 gets a HelloRetryRequest (which rules out its 0-RTT: xquic, kwik);
  one that offers only P-256 can't connect (kwik's HTTP/3 client).
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
  rebound are lost, our ACKs (sent on the new path) report the gap, but quiche never declares
  those packets lost, so the data is never resent and the transfer waits forever. ngtcp2's and
  quic-go's clients fail the same tests against quiche here.

## Interop results: our server against the runner's clients

2026-10-25, final image (`server-*.json` plus reruns of tests fixed during the sweep). `ok` passed,
`FAIL` failed, `-` unsupported by the client.

| client | handshake | transfer | longrtt | chacha20 | multiplexing | retry | resumption | zerortt | http3 | blackhole | keyupdate | ecn | amplificationlimit | handshakeloss | transferloss | handshakecorruption | transfercorruption | ipv6 | v2 | rebind-port | rebind-addr | connectionmigration |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aioquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| go-x-net | ok | ok | ok | - | ok | - | - | - | - | ok | ok | - | ok | - | ok | - | ok | FAIL | - | ok | ok | FAIL |
| kwik | ok | ok | ok | ok | ok | ok | ok | FAIL | FAIL | ok | ok | - | FAIL | ok | ok | ok | ok | FAIL | ok | ok | ok | FAIL |
| lsquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| msquic | ok | ok | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | FAIL | FAIL | FAIL |
| mvfst | ok | ok | ok | - | ok | - | - | FAIL | ok | ok | - | - | ok | FAIL | ok | FAIL | ok | FAIL | - | FAIL | FAIL | FAIL |
| neqo | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | FAIL | FAIL | FAIL |
| ngtcp2 | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| picoquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| quic-go | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | FAIL | FAIL | FAIL |
| quiche | ok | ok | ok | - | FAIL | ok | ok | ok | ok | ok | - | - | ok | ok | ok | ok | ok | FAIL | - | ok | ok | FAIL |
| quinn | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| s2n-quic | ok | ok | ok | - | ok | ok | ok | - | ok | ok | - | ok | ok | ok | ok | ok | ok | FAIL | - | ok | ok | FAIL |
| xquic | ok | ok | ok | ok | - | ok | ok | FAIL | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | ok | ok | FAIL |

What the failures are (other than `ipv6`, which this sandbox can't run):

- quinn: its client drops every reply as from an "unrecognized peer" under the IPv6 shim this
  sandbox needs (it fails the same way against quic-go's server).
- rebind-port / rebind-addr with quic-go, msquic, mvfst, neqo: these clients use zero-length
  connection IDs, and the host's tshark 4.2.2 can't follow such a connection to its new 4-tuple, so
  it can't see the PATH_CHALLENGE. Our qlog shows it in the first packet on the new path, and the
  client answers it. Clients with connection IDs (aioquic, picoquic, ngtcp2, quiche, lsquic,
  s2n-quic, xquic, kwik, go-x-net) pass.
- connectionmigration with quic-go, msquic, mvfst, neqo, quiche, s2n-quic, xquic, kwik, go-x-net:
  we offer the preferred address; these clients don't move to it (or, for neqo, tshark loses the
  zero-length-CID connection again).
- zerortt with xquic and kwik: their first ClientHello carries only a P-256 share, and the
  HelloRetryRequest rejects 0-RTT. With msquic: its PMTU probes' padding counts as 1-RTT data and
  tips the runner's size check (5130 of 5000 bytes); the 0-RTT data was accepted. With mvfst: its
  client script sent nothing.
- kwik http3 / amplificationlimit: its HTTP/3 client offers only P-256; amplificationlimit ends
  with kwik closing on CRYPTO_BUFFER_EXCEEDED after the retry (kwik's log is empty; unexplained).
- quiche multiplexing: quiche's HTTP/0.9 client wrote 3 bytes of 37 requests while its congestion
  window was shut and never sent the rest.
- mvfst handshakeloss / handshakecorruption: its client downloads everything on one connection
  where the test wants one per file.

## Interop results: our client against the runner's servers

2026-10-25, final image (`client-*.json` plus reruns of tests fixed during the sweep).

| server | handshake | transfer | longrtt | chacha20 | multiplexing | retry | resumption | zerortt | http3 | blackhole | keyupdate | ecn | amplificationlimit | handshakeloss | transferloss | handshakecorruption | transfercorruption | ipv6 | v2 | rebind-port | rebind-addr | connectionmigration |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aioquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | - |
| go-x-net | ok | ok | ok | - | ok | - | - | - | - | ok | ok | - | ok | - | ok | - | ok | FAIL | - | FAIL | FAIL | - |
| haproxy | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | FAIL | FAIL | - |
| kwik | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | - |
| lsquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| msquic | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | - |
| mvfst | ok | ok | ok | - | ok | - | ok | ok | ok | ok | ok | - | FAIL | ok | ok | ok | ok | FAIL | - | ok | ok | - |
| neqo | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | FAIL |
| nginx | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - |
| ngtcp2 | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | FAIL | FAIL | FAIL |
| picoquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | FAIL |
| quic-go | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - |
| quiche | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | FAIL | FAIL | - |
| quinn | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - |
| s2n-quic | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | - | ok | ok | FAIL |
| xquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - |

What the failures are (other than `ipv6`):

- ngtcp2 rebind-port / rebind-addr: the host's tshark can't decrypt ngtcp2's 1-RTT packets (see
  above); connectionmigration with ngtcp2, picoquic, neqo: their preferred address is IPv6.
- quiche rebind-port / rebind-addr: quiche never resends what it lost as the NAT rebound (above);
  ngtcp2's and quic-go's clients fail the same way.
- haproxy rebind-port / rebind-addr: haproxy keeps sending to the old address although our
  packets (PINGs included) come from the new one; ngtcp2's and quic-go's clients fail the same
  tests, and its resumption test too (ours passed on a rerun).
- go-x-net rebind-port / rebind-addr: go-x-net never sends to our new address.
- mvfst amplificationlimit: mvfst's server sends more than three times what it received.
- s2n-quic connectionmigration: s2n-quic offers no preferred address.

