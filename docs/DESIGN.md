# hangang-guard design and delivery procedure

[한국어](ko/DESIGN.md) · [Documentation index](README.md)

Status: accepted implementation baseline, 2026-10-12. Project name: hangang-guard.
The existing directory remains hangang-safe to preserve the current workspace.

## Purpose and boundaries
A Rust IP/network policy and risk service, one component of the zero-trust backbone,
consumes authenticated security signals from Hangang, keeps
bounded per-IP evidence, creates block candidates (BCL), and provides per-request
remote decisions and optional expiring policy snapshots. Hangang is a first-class
zero-trust decision client: by default each request calls the guard asynchronously.
Guard decisions use memory, with no database, ASN-provider or LLM query. Optional
short-lived decision caching and snapshot enforcement are explicit modes.
Hopae manages users/principals; guard does not duplicate user accounts or sessions.
A guard allow decision does not authenticate a user or device.
Existing authentication, zero-trust, allow/deny and request defenses remain in
force independently. A guard allowlist only exempts an IP from guard blocking.

## Procedure
1. Inspect native Hangang admission, trusted-proxy IP resolution, events and auth.
2. Record architecture, threat model, API and resource limits before coding.
3. Implement core and service as independent units through sub-agents; implement
   Hangang integration in a separate worktree to preserve existing dirty edits.
4. Review contracts and failure behavior, run unit and real HTTP integration tests.
5. Exercise a local proxy + guard + origin in observe and enforce modes.
6. Commit and push a new guard repository and a Hangang feature branch. Production
   observation is attempted only if the running deployment and config are located;
   do not silently enable live blocking or restart an unrelated deployment.
7. Document delivered scope and remaining work, notify operator at completion.

## Threat model and decisions
- Only bearer-authenticated collectors can submit evidence or retrieve snapshots.
  Operator mutations use a distinct admin credential. Bind loopback by default;
  remote exposure requires a TLS reverse proxy or private secured transport.
- Resolve IP at Hangang's trusted-proxy boundary; never accept arbitrary XFF.
- No bodies, cookies, credentials, full URLs or query strings cross the protocol.
  Signals are typed: honeypot, scanner, auth_failure, invalid_request. Requests
  rejected by guard itself cannot generate fresh attack evidence.
- Observe is the default. Candidate creation and automatic IP blocking are distinct.
  Exact IP blocks may be automated only when explicitly enabled in enforce mode.
  A lone generic HTTP 403 is not evidence. Honeypot paths must be explicitly set.
- Allowlist wins over guard blocks, including broader CIDRs; it never bypasses
  Hangang authentication. CIDRs use canonical network addresses, IPv4-mapped IPv6
  is normalized, and expiration is checked locally on every lookup.
- ASN association is enrichment, not proof of maliciousness. Offline supplied ASN
  prefix catalogs are supported first; ASN-wide decisions require explicit manual
  approval. No LLM has authority to modify allowlists or expand blocks.
- Policies are full, bounded snapshots swapped atomically only after validation.
  In explicit snapshot mode a failed poll preserves the previous snapshot until
  valid_until, then guard enforcement fails open. Query mode defaults to a 100 ms
  timeout and fail-deny (503), with explicit fail-allow available. Existing Hangang
  defenses remain active. A restarted
  guard may reset revision; generated_at + validity govern freshness, not a
  permanently monotonic in-process revision requirement.
- Input/event/candidate/block/rule/prefix counts and body sizes are bounded.
  Overflow is visible in counters; guard cannot backpressure proxy requests.
  Durable storage holds policy and compact candidate aggregates, never all logs.
- Checkpoints are SQLite transactions. Admin success requires durable policy
  persistence; candidate counts may lose at most one checkpoint interval on crash.
  The policy-change audit row commits in the same transaction, so a change
  cannot become durable without its audit record (AUDIT_EXPLAIN.md).

## Resource and performance goals
Default maximum tracked IPs: 10,000; maximum block entries: 100,000; event batch:
256; maximum HTTP body/snapshot: 4 MiB; native event queue: 4,096; decision refresh:
2 seconds; snapshot validity: 30 seconds. Candidate window default 60 seconds;
block lifetime 15 minutes. Bounded counters expose dropped events and capacity
rejections. The initial prefix index used bounded IPv4/IPv6 hash probes; the current
implementation uses compressed radix trees. Numeric limits are budgets, not
measured capacity claims.
Remote query is the default and must be measured under load. Optional decision
cache defaults off; when enabled its configured TTL must be 1–5 seconds. It has bounded IP capacity, and TTL is the minimum of configured
TTL and server ttl_ms (server max 5 seconds). A revision change clears old cached
decisions when observed; changes may remain stale for the bounded TTL. Signals
never use cached decisions because every evidence event must reach the guard.
No raw log retention. SQLite policy/aggregate checkpoint defaults to 5 seconds.

## Wire protocol v1
JSON; times are UTC Unix seconds. Networks are canonical CIDR strings. Unknown
kinds or invalid networks are rejected. Authentication uses Authorization: Bearer.

Collector endpoints:
- POST /v1/decision -> {version: 1, revision, action: allow|deny, mode, reason,
  ttl_ms}; body {source_id: string, ip: IP string, kind?: EventKind}. Check current
  allow/block policy before ingesting an optional signal, so requests already
  denied by guard do not renew evidence/TTL. The decision then reflects any
  newly created block. In observe mode always allow. No request URLs or credentials.
- POST /v1/events -> {accepted: N}; body {source_id: string, events: [Event]}.
  Event = {ip: IP string, kind: honeypot|scanner|auth_failure|invalid_request,
  observed_at: integer}. Timestamps must be near receiver time; counting/window
  expiration uses receiver time. Batches max 256, source ID max 64 bytes.
- GET /v1/snapshot -> Snapshot.

Snapshot = {version: 1, revision: integer, generated_at: integer,
valid_until: integer, mode: observe|enforce, allow: [CIDR], blocks: [Block]}.
Block = {network: CIDR, expires_at: integer, reason: string}.
Snapshot lifetime <= 300 seconds; reason <= 128 bytes. Duplicate canonical block
networks are rejected by clients; expired individual blocks never enforce.

Admin endpoints (admin bearer only):
- GET /v1/status: health, capacity and counters, no secrets.
- GET /v1/candidates: bounded IP aggregates including ASN if known and eligible
  flag. Only aggregates at/above threshold are BCL candidates eligible for approval.
- GET/PUT /v1/policy: Policy.
- GET /v1/blocks: active Block array; POST /v1/blocks: Block;
  DELETE /v1/blocks: {network: CIDR}.
- POST /v1/candidates/approve: {ip: IP string}; approve an exact-IP block.
- GET /v1/audit, POST /v1/audit/query: policy-change audit (filters, cursor).
- POST /v1/explain, POST /v1/explain/batch, GET /v1/reasons: explain/what-if on
  the live evaluation path and the reason catalog. See AUDIT_EXPLAIN.md.
- GET /v1/history, GET/POST/DELETE /v1/allowlist, GET /v1/rules/document,
  GET /v1/asn/catalog: console Network APIs. See CONSOLE_NETWORK_API.md.
- Dashboard /: static HTML, credential entered in browser memory only; no local
  storage, embedded token, external scripts or unsanitized evidence HTML.

Policy = {mode, auto_block, window_secs, threshold, block_ttl_secs,
allow: [CIDR], weights: {honeypot, scanner, auth_failure, invalid_request}}.
Defaults: observe, false, 60, 10, 900, [], weights 10/5/1/2. Integers must be
bounded; zero weights disable a signal. Configure authentication tokens through
environment variables, not checked-in JSON or command-line arguments.

## Components
- guard-core: typed contract, validation, bounded weighted-window candidates,
  exact-IP approval, manual CIDR blocks, allow precedence, offline ASN enrichment,
  snapshot construction and prefix index. No network/DB dependencies.
- guard-server (binary hangang-guard): authenticated bounded HTTP API, embedded
  management dashboard, SQLite state/checkpoints, graceful shutdown and config.
- native Hangang guard module: opt-in CLI config; async snapshot polling/event
  batching, bounded try_send, prefix index + ArcSwap, admission at resolved IP,
  explicit honeypot/scanner path signals. Default query mode uses per-request
  /v1/decision; optional bounded IP cache defaults off, optional snapshot mode
  available. Disabled has no background network work.

## Research and extension decisions
CrowdSec separates detection/decisions from remediation, and its bouncers cache
and retrieve decision streams: https://docs.crowdsec.net/docs/concepts/ and
https://docs.crowdsec.net/docs/local_api/bouncers/ . Adopt the separation, but do
not advertise CrowdSec compatibility without implementing that protocol.
Future phases: authenticated/signed pattern feeds with provenance and rollback;
ASN/GeoIP background refresh with last-good catalogs; reviewed ASN proposals and
impact estimates; fleet identities, audit history, distributed sync and retention.
The initial plan retained GeoIP in Hangang; the current extension below also
supports local GeoIP in guard. External feeds and
LLM suggestions are optional extensions, not prerequisites for local protection.

## Verification gates
Core: weighted thresholds/windows, allow precedence, mapped IPv6, expiration,
capacity, restart restoration, IPv4/IPv6 prefix matching and invalid policies.
Service: auth separation, bounded bodies/batches, persistence/restart, mutations,
observe/enforce snapshots, safe dashboard rendering and API errors.
Hangang: trusted client IP, offline cached enforcement, expiry/observe bypass,
malformed snapshot retention, bounded export and no self-reinforcing evidence.
End-to-end: each-request remote query (cache off), explicit honeypot -> candidate
-> reviewed approval -> native 403; query outage -> configured 503 or fail-allow;
allowlist -> origin succeeds; explicit snapshot outage -> expiry -> origin succeeds.

## Prompt-based LLM request inspection backlog
User-requested investigation: configurable prompt policies may inspect request
patterns through an LLM. Compare synchronous per-request decisions and asynchronous
aggregate analysis; retain explicit latency/cost budgets and 1–5 second optional
cache semantics. Define minimal redacted inputs, structured output validation,
untrusted request/prompt-injection isolation, provider/prompt versioning, timeout
and outage behavior, deterministic policy gates, shadow evaluation and operator
review. This is a design backlog item, not an implemented runtime dependency.
The detailed checklist is recorded in TODO.md.

## Performance phase — IP pools, operator UI and protocol
User requirement: design and qualify 10,000–100,000 decisions/second, including
protocol-level optimization when necessary. The earlier Python sample is not
sufficient qualification. Use compact radix indexes for IPv4/IPv6 allow, block
and ASN pools. Publish immutable decision views atomically; ordinary decisions
must avoid the engine mutex, SQLite, spawn_blocking, string IP parsing and generic
JSON intermediate values. Evidence ingestion and durable administration retain
a separate serialized control path. Query remains default, optional cache 1–5 s.

Add an optional loopback-only authenticated persistent binary decision listener
with fixed-size frames and bounded connections/idle deadlines; HTTP remains for
API, evidence, remote secured access and management. Native Hangang should be able
to select this transport without changing evidence or failure semantics.

Qualification uses release builds, a Rust multi-connection load generator,
explicit concurrency/pipeline sizes, empty/enforce and large IPv4/IPv6 pools,
match/miss mixes, latencies, errors, CPU/RSS and sustained runs. Distinguish isolated
index throughput, decision-service transport throughput and full native proxy
throughput. Publish measured results and limits, never infer a production SLA.
Operator UI gets structured policy editing, separate allow/block/candidate views,
search/sort/pagination, expiration and clear errors; it must handle thousands of
entries without creating thousands of DOM nodes or replacing unsaved inputs.

## Current GeoIP/rules extension
The initial GeoIP deferral above is superseded by operator-provided offline MMDB
support in guard. Country/City/ASN lookup, IP/CIDR scores and suspicion stages,
compiled JSON/Lua rules, dry-run validation and durable atomic policy publication
are now implemented. See RULES.md for exact precedence/limits and TOOL_RESEARCH.md
for the primary-source comparison. Scripts compile on administration, never per
query. Policy default remains observe and every-query remote admission remains
default; rules requiring GeoIP use local immutable readers. Snapshot v1 rejects
nonempty dynamic rules instead of publishing an incomplete policy.
