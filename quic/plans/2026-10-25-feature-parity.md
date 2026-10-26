# Feature parity with other QUIC stacks

> **Status:** done for what's listed under "Added"; interop results below — 2026-10-26.

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
| TLS | `TLS_AES_256_GCM_SHA384` (the transcript and key schedule run on the suite's hash), P-256 key exchange beside X25519, HelloRetryRequest on the client | `tls/TlsHash.kt`, `TlsClient`, `TlsServer` |
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

Found by the sweep after adding P-256 and AES-256-GCM, server-only:

- picoquic, moved to v2 by our first Initial, ACKs that packet but starts its handshake over and
  sends its ClientHello again. With our ServerHello ACKed we only ACKed back; a ClientHello
  repeated from the start now gets the whole flight again, as ngtcp2's server does. (Its
  P-256-only ClientHello used to get a HelloRetryRequest first, which hid this.)
- 1-RTT packets that arrive before the client's Finished were dropped, so a request sent right
  after a lost Finished waited on the client's own retransmit timer (lsquic). The server now keeps
  up to 32 of them (RFC 9001 §5.7) and reads them once the handshake completes.
- Before its handshake completed, the server probed with 1-RTT PINGs, whose 1-RTT ACKs it can't
  read yet; it now probes in the Handshake space.
- HANDSHAKE_DONE was resent only once declared lost, and probes were bare PINGs: with both
  copies lost, ngtcp2's client never confirmed its handshake and never resent its request. Probes
  now carry HANDSHAKE_DONE until the client ACKs it.

## Not done

- Key-exchange groups other than X25519 and P-256 (P-384, P-521, FFDHE, hybrid post-quantum
  groups).
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
- In the rebind tests the NAT first moves 1 s after the simulator starts. Our JVM client's first
  Initial reaches the server at about 0.88 s, and kwik's server takes about 200 ms to answer, so
  its answer goes to the old port; kwik's server keeps answering there and the handshake never
  finishes. Whether those two tests pass against kwik depends on that race.
- The loss and corruption tests are random: a run can lose every copy of one packet. Results
  below are from single runs, with the repeats noted.

## Interop results: our server against the runner's clients

2026-10-26, final image (TLS with P-256 and AES-256-GCM, and the server fixes above): the full
sweep (`server-*.json`), then every test those fixes touch run again against every client.
`ok` passed, `FAIL` failed, `-` unsupported by the client.

| client | handshake | transfer | longrtt | chacha20 | multiplexing | retry | resumption | zerortt | http3 | blackhole | keyupdate | ecn | amplificationlimit | handshakeloss | transferloss | handshakecorruption | transfercorruption | ipv6 | v2 | rebind-port | rebind-addr | connectionmigration |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aioquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| go-x-net | ok | ok | ok | - | ok | - | - | - | - | ok | ok | - | ok | - | ok | - | ok | FAIL | - | ok | ok | FAIL |
| kwik | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | FAIL |
| lsquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| msquic | ok | ok | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | FAIL | FAIL | FAIL |
| mvfst | ok | ok | ok | - | ok | - | - | FAIL | ok | ok | - | - | ok | FAIL | ok | FAIL | ok | FAIL | - | FAIL | FAIL | FAIL |
| neqo | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | FAIL | FAIL | FAIL |
| ngtcp2 | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| picoquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| quic-go | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | FAIL | FAIL | FAIL |
| quiche | ok | ok | ok | - | FAIL | ok | ok | ok | ok | ok | - | - | ok | ok | ok | FAIL | ok | FAIL | - | ok | ok | FAIL |
| quinn | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| s2n-quic | ok | ok | ok | - | ok | ok | ok | - | ok | ok | - | ok | ok | ok | ok | ok | ok | FAIL | - | ok | ok | FAIL |
| xquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | ok | ok | FAIL |

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
- zerortt with msquic: its PMTU probes' padding counts as 1-RTT data and tips the runner's size
  check (5130 of 5000 bytes); the 0-RTT data was accepted. With mvfst: its client script sent
  nothing.
- quiche multiplexing: quiche's HTTP/0.9 client wrote 3 bytes of 37 requests while its congestion
  window was shut and never sent the rest.
- quiche handshakecorruption (fails about one run in two): quiche's ClientHello spans two
  Initials. When the second is corrupted and so are all our ACKs back, quiche's probes resend only
  the first half, and that connection never gets past its ClientHello.
- mvfst handshakeloss / handshakecorruption: its client downloads everything on one connection
  where the test wants one per file.
- Passed here but not every time: lsquic handshakeloss (four of five runs; the failing one lost
  every copy of lsquic's Finished for 30 s).

The P-256 change fixed kwik's zerortt, http3 and amplificationlimit and xquic's zerortt, which
had all failed because their ClientHello carries only a P-256 share.

## Interop results: our client against the runner's servers

2026-10-26 sweep (`client-*.json`; lsquic's and msquic's last three tests and mvfst's run again
after a full disk), plus reruns of tests that failed once.

| server | handshake | transfer | longrtt | chacha20 | multiplexing | retry | resumption | zerortt | http3 | blackhole | keyupdate | ecn | amplificationlimit | handshakeloss | transferloss | handshakecorruption | transfercorruption | ipv6 | v2 | rebind-port | rebind-addr | connectionmigration |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aioquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | - |
| go-x-net | ok | ok | ok | - | ok | - | - | - | - | ok | ok | - | ok | - | ok | - | ok | FAIL | - | FAIL | FAIL | - |
| haproxy | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | FAIL | FAIL | - |
| kwik | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | FAIL | FAIL | - |
| lsquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | ok |
| msquic | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | - | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | - |
| neqo | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | FAIL |
| nginx | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - |
| ngtcp2 | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | FAIL | FAIL | FAIL |
| picoquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | ok | ok | ok | FAIL |
| quic-go | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - |
| quiche | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | FAIL | FAIL | - |
| quinn | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - |
| s2n-quic | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | ok | ok | ok | ok | FAIL | - | ok | ok | FAIL |
| xquic | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | - | ok | ok | ok | ok | ok | FAIL | - | ok | ok | - |
| mvfst | ok | ok | ok | - | ok | - | ok | ok | ok | ok | ok | - | FAIL | ok | ok | ok | ok | FAIL | - | ok | ok | - |

What the failures are (other than `ipv6`):

- ngtcp2 rebind-port / rebind-addr: the host's tshark can't decrypt ngtcp2's 1-RTT packets (see
  above); connectionmigration with ngtcp2, picoquic, neqo: their preferred address is IPv6.
- quiche rebind-port / rebind-addr: quiche never resends what it lost as the NAT rebound (above);
  ngtcp2's and quic-go's clients fail the same way.
- haproxy rebind-port / rebind-addr: haproxy keeps sending to the old address although our
  packets (PINGs included) come from the new one; ngtcp2's and quic-go's clients fail the same
  tests.
- go-x-net rebind-port / rebind-addr: go-x-net never sends to our new address.
- kwik rebind-port / rebind-addr: the race with the first rebind described above.
- mvfst amplificationlimit: mvfst's server sends more than three times what it received.
- s2n-quic connectionmigration: s2n-quic offers no preferred address.
- Passed on a rerun: nginx rebind-addr (nginx answered a packet from the new address with a
  stateless reset once), quinn handshakecorruption.
