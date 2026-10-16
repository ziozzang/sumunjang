# Persistent binary decision protocol v1

[한국어](ko/PROTOCOL.md) · [Documentation index](README.md)

The HTTP API remains the management/evidence interface. The optional binary
listener handles ordinary IP decisions with the same policy, rules and GeoIP
context, without JSON. Plaintext is restricted to literal loopback; remote native
listeners require mTLS and still authenticate the collector token. Enable with:

```sh
sumunjang --decision-listen 127.0.0.1:9081
hangang --guard-url http://127.0.0.1:9080 --guard-decision-tcp 127.0.0.1:9081
```

Supply matching collector tokens through `HANGANG_GUARD_COLLECTOR_TOKEN`.
Native Hangang uses up to 64 concurrent reusable connections. Idle sockets are retired after 25 seconds, before
the service 30 second idle deadline. Requests carrying a
honeypot/scanner signal still use the authenticated HTTP decision endpoint. The
same default no-cache, optional 1–5 s cache, timeout and failure policy apply. A
broken/malformed connection is discarded; no silent HTTP transport fallback.

## Authentication

Client writes `HGD1` (4 ASCII bytes), token length (u16 big-endian), then exactly that
many token bytes (16–4096). Server verifies collector credential and returns
`HGA1`; invalid authentication closes the connection. Admin tokens are rejected.
Authentication deadline 5 s, idle read deadline 30 s, write deadline 5 s; at most 256
concurrent binary connections. Shutdown cancels existing sockets.

## Query frame — 24 bytes

| Offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 1 | Version 1 |
| 1 | 1 | IP family 4 or 6 |
| 2 | 2 | Reserved, must be zero |
| 4 | 4 | Correlation id, u32 big-endian |
| 8 | 16 | IPv6 bytes; IPv4 uses first 4 bytes and 12 zero bytes |

## Response frame — 24 bytes

| Offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 1 | Version 1 |
| 1 | 1 | Action 0 allow, 1 deny |
| 2 | 1 | Mode 0 observe, 1 enforce |
| 3 | 1 | Reserved zero |
| 4 | 4 | Echoed correlation id, u32 big-endian |
| 8 | 8 | Policy revision, u64 big-endian |
| 16 | 4 | Decision TTL milliseconds, u32 big-endian, 0–5000 |
| 20 | 4 | Reserved zero |

Stream framing is fixed-size; queries may be pipelined and responses remain in
order. The service batches up to 256 frames per read and combines response writes.
It retains a partial frame across reads. Invalid versions/families/padding close
connection. Native client validates all response fields/correlation, and the
single request timeout includes pool wait, connect, auth, read/write. TTL is
measured from query start, so transport latency cannot extend decision validity.
No reason strings, GeoIP names, scores or credentials occur in decision frames;
operator inspection uses admin APIs instead.

## Native remote mTLS listener

The server accepts `--decision-tls-cert`, `--decision-tls-key` and
`--decision-client-ca` together with `--decision-listen`. Outside loopback the
TLS configuration is mandatory; `0.0.0.0` can bind the authenticated endpoint.
PEM material must be a regular file, is capped at 1 MiB per file and is checked
before serving (including `--check`). The server trusts only the explicit
client CA, requires ALPN `hgd1` and disables TLS early data. Collector-token
authentication remains mandatory after TLS; mTLS does not grant admin access.

TLS handshakes are bounded to 3 seconds within the existing 256-connection
limit. Connections expire after 300 seconds. Idle reads retain the 30-second
bound, but a partial 24-byte frame must finish within 5 seconds; trickling
bytes cannot restart its deadline. Pipelined replies and immutable in-memory
decisions keep their existing semantics and avoid database queries.

Hangang remote HGD1 client configuration and actual cross-process deployment
qualification are follow-up work. HTTP management/evidence listeners are
unchanged by these native TLS flags; use the existing local broker or a
separately authenticated TLS ingress for remote HTTP access. This change does
not establish replica membership or measured full-stack TLS throughput.

## Decision evidence is not carried by HGD1

The 24-byte frames above are unchanged. Matched rule IDs, ASN, country and
reason codes are available only through the additive gRPC
`include_evidence` flag and HTTP `/v1/decision` `"evidence": true`; see
[gRPC](GRPC.md) and [audit and explain](AUDIT_EXPLAIN.md).

The native mTLS listener picks up rotated certificate, key and client-CA files
without restart (`--tls-reload-seconds`); see [operations](OPERATIONS.md).
