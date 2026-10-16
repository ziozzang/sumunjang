# Operations

[한국어](ko/OPERATIONS.md) · [Documentation index](README.md)

## Rollout

1. Issue distinct collector/admin tokens and protect environment files with mode `0600`.
2. Run guard on loopback in `observe` mode with a writable database directory.
3. Validate per-request decisions and failure handling using a separate Hangang instance.
4. Add native guard flags when upgrading the production gateway; retain `observe`.
5. Review actual honeypot paths and trusted administration IPs/CIDRs. Do not count a generic 403 as attack evidence.
6. Review candidates, false positives and decision latency before enabling `enforce` with manual approval.
7. Enable automatic blocking only for bounded exact-IP policies. Do not automate ASN-wide blocking.

The existing Docker gateway uses `/docker/hangang/gateway` as its data volume.
Integration verification uses separate ports and temporary configuration. That
verification does not restart production containers, replace images or enable live blocking.

Guard is a security decision backbone component. An allow decision or allowlist
entry never authenticates a user/device; Hangang authentication remains required.
Hopae owns user/principal management; guard does not duplicate accounts or
sessions. The admin control plane changes policy; Hangang is the enforcement point.

## Failure and recovery

- Query mode defaults to 503 on guard failure, timeout or malformed responses.
  Guard availability therefore affects gateway availability on protected paths.
- `--guard-failure-mode allow` permits admission past the guard check on failure;
  existing Hangang authentication still runs. Choose this explicitly where availability takes priority.
- Caching defaults off. Enabled TTL is 1–5 seconds and is never extended indefinitely on failure.
- Snapshot mode retains the last good policy until expiration, then stops guard
  blocking. Its failure semantics differ from query mode; select it explicitly.
- SQLite policy changes commit transactionally before a success response.
  Aggregates and automatic decisions checkpoint every 5 seconds and on graceful
  shutdown, so a crash can lose recent aggregates. Account for WAL/SHM files;
  use the SQLite backup API or back up while stopped.
- Ordinary queries read an immutable ArcSwap view and do not wait for admin fsync
  or aggregate locks. New policy publishes after durable commit. Evidence queries
  and administrator inspection use a separate serialized path. Measure latency
  and memory with real rule counts before large deployments and tune timeouts.

## Resource limits

Maximum tracked IPs: 10,000; per-IP aggregate buckets: 64; block entries: 100,000;
conservative JSON policy budget: 4,000,000 bytes; HTTP body: 4 MiB; event batch:
256; default concurrent HTTP requests: 4,096 (configurable); binary connections:
256; blocking work: 1,024. Byte budgets may apply before entry-count limits.
Windows longer than 64 seconds conservatively discard partial evidence at bucket
boundaries. Raw request logs, bodies and credentials are not retained.

## ASN catalog

Load operator-supplied prefixes with `--asn-catalog path.json`:
`[{"network":"192.0.2.0/24","asn":64500}]`. Do not enable online automatic refresh
until the provider, update schedule and verification policy are established.
ASN enriches IP candidate classification; it alone does not justify broad blocking.

## Rollback

Switching policy to `observe` releases guard blocks on the next query or within
cache TTL. If query fail-deny is active because guard is unavailable, recover
guard or change Hangang flags and restart it. Remove `--guard-url` to disable the
native integration. Existing Hangang zero-trust authentication and defenses remain independent.

## Dynamic rules and GeoIP

Use the dashboard's IP/CIDR inspection, JSON/Lua rules and GeoIP tabs. Read
[rules and score semantics](RULES.md), validate without activation, then apply.
Lua source currently lives in the browser draft; the service persists compiled,
validated JSON RuleSets. Version Lua scripts separately. Review disabled states,
action explanations and cache TTL effects.

Guard verifies configured local MMDB files and atomically reloads them, retaining
the last good catalog on failure. Guard Country/City/ASN support is separate from
existing Hangang GeoIP support. Configured country/ASN rules affect remote
decisions. Snapshot v1 cannot carry dynamic rules; use query mode.

State-changing evidence queries have different throughput from ordinary read-only
decisions. Measure immutable-view rebuild cost if automatic blocking is frequent.
Do not assume 100k ordinary decisions/sec and 100k raw attack events/sec fit the
same resource budget.

## Durable bootstrap policy

Use `--bootstrap-policy /config/bootstrap.json` to seed a new database only. Once a checkpoint exists, its policy is authoritative and the bootstrap file is not read, including after supervised HUP. This is suitable for restartable deployments. `--policy` continues to explicitly reload policy at each start; the two options are mutually exclusive. Bootstrap input is bounded to 1 MiB. Invalid stored state fails startup rather than falling back to bootstrap.

## Management mTLS

`--management-tls` serves the management listener over mandatory client-certificate HTTPS using the configured decision TLS identity/CA. Decision TLS settings and their native listener are required. Collector/admin token roles still apply; a certificate does not grant policy write access. The shared HTTP/1.1 runtime bounds connections, handshake/header reads and shutdown drain. Supervised mode retains the management listener during HUP. Plain management remains available for explicitly loopback deployments. Do not expose plaintext management as a remote Service.

## TLS certificate rotation (hot reload) and probes

The decision TLS material (`--decision-tls-cert`, `--decision-tls-key`,
`--decision-client-ca`) serves the HGD1 mTLS listener, the gRPC listener and,
with `--management-tls`, the management HTTPS listener. Sumunjang polls the three
files every `--tls-reload-seconds` (default 10; 0 disables) by content digest —
no inotify, so Kubernetes Secret volume updates (atomic `..data` symlink swaps by
cert-manager/kubelet) are detected. On a change it reads the files once, builds
new rustls configurations for all three listeners (same policy: mandatory
client certificates from the explicit CA, safe protocol versions, no early data,
listener ALPN) and swaps them atomically. New handshakes use the new material;
established connections keep their session until they close (HGD1/management
connections are capped at 300 s). Logs show
`tls: reloaded certificate material; leaf sha256 <fingerprint>`.

Invalid new material — unparsable PEM, a key that does not match the
certificate, an empty CA, files over 1 MiB, missing files mid-rotation — is
refused and the previous configuration keeps serving. `GET /v1/status` → `tls`
reports `leaf_sha256`, `loaded_at`, `reloads_total`, `reload_failures_total`,
`consecutive_failures`, `last_error` and `last_failure_at`; alert on a growing
`reload_failures_total` or nonzero `consecutive_failures`. The same bad material
is logged once and retried only when the files change again.

TLS for gRPC is now terminated by Sumunjang (per-handshake current material, 3 s
handshake bound, 2,048 connections, ALPN `h2`, client certificate required)
before tonic, with the previous HTTP/2 bounds unchanged.

Outbound clients already re-read their CA files on every use: the native
Kubernetes authority reads its `ca` file on each collection (every 500 ms), the
read-only policy source rebuilds its client when the CA bytes change, and signed
update checks read `--update-ca` per check. No restart is needed after rotating
those CA files.

**Probes.** Use `--readiness-listen IP:port` (plain HTTP, probe-only, no admin
routes) with `httpGet /readyz` for readiness and `/healthz` for liveness instead
of TCP probes. `/readyz` returns 503 while the native Kubernetes source is not
fresh or while the most recent durable checkpoint failed; TLS reload failures do
not make the pod unready because the previous valid material keeps serving. The
main listener exposes the same `/readyz`. See
`deploy/sumunjang-native-authority-deployment.yaml`.
