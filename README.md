# Sumunjang (수문장)

[한국어](README.ko.md) · [Documentation](docs/README.md)

Sumunjang is the component name of `hangang-guard`. The primary executable is `sumunjang`; a `hangang-guard` compatibility executable
and signed legacy asset pair remain available for existing installations. Repository
URLs, protocol magic and credential environment variables remain compatible. Pumgye owns service/user/IP
authorization; Sumunjang supplies network admission and risk evidence.

A Rust security decision service and one backbone component of Hangang's
zero-trust architecture. **Hangang queries guard on every request by default**;
optional decision caching is restricted to **1–5 seconds**. A guard `allow`
decision does not authenticate a user or device or bypass Hangang authentication.
Hopae manages users/principals; guard manages IP/network policy and risk, without
duplicating user accounts or sessions.

Guard aggregates explicitly configured honeypot/scanner signals, maintains block
candidates, and supports reviewed IP/CIDR blocks, allowlists, expiration and
optional automatic IP blocking. The default policy is `observe`. Decisions run
in memory; SQLite persists policy and bounded aggregates. The authenticated admin
API and embedded dashboard form the control plane; Hangang enforces decisions.

## Build and run

Rust 1.96 or later is required.

```sh
cargo build --release
export HANGANG_GUARD_COLLECTOR_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export HANGANG_GUARD_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
./target/release/sumunjang --listen 127.0.0.1:9080 --database ./guard.sqlite3
```

The tokens must differ and each contain at least 16 bytes. Persist the same
collector credential in guard and Hangang deployment environments; protect the
environment file with mode `0600`. Never commit credentials.

The dashboard is at `http://127.0.0.1:9080/`. It keeps the administrator token only
in browser memory. Use an HTTPS reverse proxy or SSH tunnel for remote access.

## Native Hangang integration

Use a Hangang build containing native guard support. See its
[guard integration documentation](https://github.com/ziozzang/hangang/blob/main/docs/GUARD.md).

```sh
# Run with the same HANGANG_GUARD_COLLECTOR_TOKEN as guard.
hangang --config hangang.json --listen 127.0.0.1:8080 \
  --guard-url http://127.0.0.1:9080 \
  --guard-honeypot-path /trap \
  --guard-scanner-path /.git/config
```

Defaults: `--guard-mode query`, no cache, 100 ms query timeout. If guard is
unavailable, `--guard-failure-mode deny` returns 503. Explicit `allow` continues
with existing Hangang policies on a guard failure. Optional caching uses
`--guard-cache-ms 1000` through `5000`; requests carrying detection signals always
reach guard. Policy changes may take up to that TTL to affect cached requests.
`--guard-mode snapshot` selects a separate local snapshot mode with different
failure semantics; read [operations](docs/OPERATIONS.md) before choosing it.

## API and trust boundary

Collector token: `POST /v1/decision`, `POST /v1/events`, `GET /v1/snapshot`.
Admin token: policy, blocks, candidates, rules, GeoIP and inspection endpoints.
All API authentication uses `Authorization: Bearer …`. `/healthz` provides a
minimal unauthenticated health check. See [design and HTTP API](docs/DESIGN.md)
and [rules and inspection API](docs/RULES.md).

Hangang resolves client IP at its trusted-proxy boundary; arbitrary
`X-Forwarded-For` values are not trusted. Requests denied by guard do not renew
attack evidence. Allowlisting exempts only guard blocking, not other security or
authentication checks. GeoIP, ASN and scores are signals for policy evaluation;
they do not establish user or device identity.

## Performance, GeoIP and dynamic rules

IP/CIDR/ASN pools use compressed radix trees. Ordinary decisions read immutable
policy without locks, SQLite queries, aggregate locks or blocking workers. An
optional persistent binary TCP transport authenticates once per connection and
uses 24-byte frames.

```sh
sumunjang --decision-listen 127.0.0.1:9081 \
  --geoip-database /path/country-or-city.mmdb \
  --geoip-asn-database /path/asn.mmdb
hangang --guard-url http://127.0.0.1:9080 --guard-decision-tcp 127.0.0.1:9081
```

The plaintext binary listener is **loopback-only**. Use secured HTTP transport for
remote decisions. The dashboard supports IP/CIDR inspection, GeoIP/ASN, risk
scores, suspicion stages, allowlists, policy editing and JSON/Lua rules. Embedded
Lua 5.4 runs only when validating/applying configuration, never on each request.
Validation and activation are separate operations.

See [rules, scoring and GeoIP](docs/RULES.md), [binary protocol](docs/PROTOCOL.md),
[tool research](docs/TOOL_RESEARCH.md) and [measured performance](docs/PERFORMANCE.md).
The measurements qualify local decision transport, not a production capacity SLA.

## Verification

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
# Also build Hangang in the integration checkout: cargo build --bin hangang
python3 tools/e2e.py --hangang-bin ../hangang-guard-integration/target/debug/hangang
```

E2E starts and stops real processes using temporary databases, ports and tokens.
It does not modify running gateway configuration. [Validation](docs/VALIDATION.md)
records completed checks and outstanding production qualification.

## Scope and next steps

Implemented: per-request decisions, optional short cache, IPv4/IPv6 CIDRs,
bounded weighted-window aggregation, reviewed approval/unblocking, policy changes,
SQLite restoration, offline ASN prefix catalogs and GeoIP MMDB, IP/CIDR inspection,
embedded Lua/JSON rules, admin dashboard and native Hangang HTTP/TCP integration.

ASN is classification metadata; ASN-wide automatic blocking is not enabled.
Online ASN updates, authenticated attack-pattern feeds, reviewed ASN impact
analysis, online GeoIP refresh and prompt-based LLM inspection remain in the
[backlog](TODO.md). See [operations](docs/OPERATIONS.md) for rollout and recovery,
and [design](docs/DESIGN.md) for the delivery procedure.

## Signed updates

[Update trust model and lifecycle](docs/UPDATES.md)

[Policy-change audit, explain/what-if and decision evidence](docs/AUDIT_EXPLAIN.md):
`GET /v1/audit`, `POST /v1/explain`, `POST /v1/explain/batch`, gRPC/HTTP evidence.

Use [Guard in the native Hangang console](docs/CONSOLE.md) with delegated host authentication and a pinned package.

Additional [gRPC decisions](docs/GRPC.md) reuse the shared server runtime; building requires `protoc`.

Native HGD1 uses the pinned hangang-runtime 0.1.2 connection owner, also used
by management HTTPS. The 256-connection quota, zero shutdown drain, loopback
restriction without TLS, mTLS/ALPN checks and native decision semantics remain
unchanged. Connection tasks are owned and cancelled with the listener; supervised
listener inheritance remains Sumunjang owned and requires its actual HUP gate.

## v0.3.5 release preparation

Network gRPC replies recheck captured policy and required GeoIP owners before
returning. Owner replacement yields unavailable with zero TTL, including same
numeric policy revisions. Debug/static transport and actual Pumgye observation
fixtures passed. Newly versioned static assets require qualification before
signed publication. These replies remain observations, not distributed leases.
GitHub Actions remains disabled.

[v0.3.5](https://github.com/ziozzang/sumunjang/releases/tag/v0.3.5) is now
published at `cd9d8413cf6e71d82a386484a8aa82ee21405f92`. Exact newly versioned static three-authority endpoint
qualification, source regression/Clippy and release boundary checks passed.
All downloaded assets matched originals; pinned signatures, version/target/URL
bindings and static ELF were independently verified. Internal adoption and
Kubernetes combined-endpoint qualification remain subsequent gates.

### 0.3.5 Internal adoption — 2026-10-15

Internal deployment passed pinned signature/version/target verification, live
configuration preflight, private consistent backup, unchanged policy, actual
HGD1 mTLS and supervised HUP/worker replacement. Existing observe mode remains.
The installed server and updater target are static musl; no enforcement grants
were added. Unified Hangang console HTTPS remains available.

Native Kubernetes authority: [setup, source ownership and readiness](docs/KUBERNETES_AUTHORITY.md).
