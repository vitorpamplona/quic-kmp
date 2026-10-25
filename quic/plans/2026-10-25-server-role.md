# Server role for `:quic`

> **Status:** S1–S5 done, S6 partly (compatible version negotiation done; NEW_TOKEN issuance
> and a server preferred address not yet) — 2026-10-25.

## Why

Every other implementation in the quic-interop-runner matrix plays both
roles. `:quic` is client-only, so half the matrix (our server against every
client) can't run, and anything built on the library (relays, test servers,
loopback tests) has to bring another stack. Most of the transport — packets,
frames, streams, flow control, recovery, congestion control, key update,
path validation — is already role-neutral; what's missing is the TLS server,
the role-specific transport rules, and an endpoint that accepts connections.

## Shape

One `QuicConnection` class, with a role. The client constructor stays as it
is; a server connection is built by the endpoint. Role-specific behaviour:

| Area | Client (today) | Server |
|---|---|---|
| TLS | `TlsClient` | `TlsServer`: ClientHello parsing, ServerHello/EE/Certificate/CertificateVerify/Finished, PSK + 0-RTT acceptance, NewSessionTicket |
| Initial keys | send with client keys | send with server keys; derived from the client's first DCID |
| Stream IDs | even = ours | odd = ours |
| Transport parameters | validates the server's (ODCID, ISCID, retry SCID) | validates the client's (ISCID; forbids server-only parameters); sends ODCID, retry SCID, stateless-reset token, preferred address |
| Address validation | n/a | anti-amplification (3x) until a Handshake packet or a valid token; Retry |
| Key discard | Initial on first Handshake sent; Handshake on HANDSHAKE_DONE | Initial on first Handshake received; Handshake when the handshake completes |
| HANDSHAKE_DONE | receives | sends |
| 0-RTT | sends | receives (0-RTT keys from the TLS server) |
| Migration | to the server's preferred address | validates new client addresses (PATH_CHALLENGE), rotates DCID |
| NEW_TOKEN | keeps tokens | issues tokens |

`QuicServer` (the endpoint) owns one UDP socket: routes datagrams to
connections by DCID, creates a connection on a valid Initial, answers
unsupported versions with Version Negotiation, sends Retry when address
validation is required, sends stateless resets for unknown short-header
packets, and keeps the CID → connection map current as connections issue and
retire IDs. Each connection runs on the existing `QuicConnectionDriver`
through a per-connection datagram transport that sends to the peer's current
address.

## Phases

1. **S1 — TLS server.** `TlsServer` in `commonMain/tls`, a
   `TlsCertificateSigner` interface with a JCA implementation in `jvmAndroid`
   (ECDSA P-256/P-384, RSA-PSS, Ed25519; PEM loading for PKCS#8, SEC1 and
   PKCS#1 keys), session tickets sealed with AES-GCM, PSK binder checks,
   0-RTT acceptance with a single-use ticket register. Tested against
   `TlsClient` in memory.
2. **S2 — Role plumbing in `QuicConnection`.** Role flag; key directions;
   stream parity; transport-parameter rules; server-side key discard;
   HANDSHAKE_DONE; anti-amplification; 0-RTT receive; Initial padding for
   ack-eliciting server Initials. Tested client ↔ server fully in memory.
3. **S3 — Endpoint.** `QuicServer` + a JVM unconnected UDP socket: demux,
   connection creation, Version Negotiation, Retry tokens, stateless reset,
   CID registry. Loopback UDP tests.
4. **S4 — Server-side path handling.** Detect a client address change,
   validate the new path, rotate DCID, apply amplification limits there;
   advertise a preferred address when configured.
5. **S5 — Interop server.** HTTP/0.9 (`hq-interop`) and HTTP/3 file server
   in `:quic-interop`, `ROLE=server` in `run_endpoint.sh`; run our server
   against every runner client.
6. **S6 — Extras.** Compatible version negotiation to v2 on the server,
   NEW_TOKEN issuance, ECN.

## Where it landed

- `QuicConnection` takes an internal `QuicServerSetup`; the public constructor is still the
  client's. `handshakeTls` is a `TlsHandshake` (`TlsClient` or `TlsServer`); `tls` stays the
  client's.
- `QuicServer` + `QuicServerTransport` (`UdpServerSocket` on JVM/Android). The driver runs on a
  `QuicDatagramSocket`, which `UdpSocket` and the server's per-client `ServerPeerSocket` implement.
- Rebinding: the address a server sends to (`sendAddress`) only moves in the writer, with the
  packet that carries the new path's PATH_CHALLENGE, so nothing built for the old path goes to
  the new one. An unanswered challenge moves it back after 3 PTO.
- Not yet: amplification limits on a migrated-to path, NEW_TOKEN issuance, a server preferred
  address, a cap on concurrent connections or handshakes.

Found on the way and fixed for the client too: stream credit followed arrival rather than
consumption (a fast sender overflowed the 64-chunk app channel and the connection died), 1-RTT
CRYPTO was never sent, `extraSecretsListener` never saw traffic secrets (SSLKEYLOGFILE was empty),
and the client checked `original_destination_connection_id` against its pre-Version-Negotiation
DCID.

## Out of scope

- HelloRetryRequest beyond what interop needs (X25519 is the only group).
- Client certificates.
- Multiple listening sockets / SO_REUSEPORT load balancing.
