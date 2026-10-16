# ASN prefix bundles and ASN block proposals

[한국어](ko/ASN_PROPOSALS.md) · [Documentation index](README.md)

Original requirements steps 4–6: retrieve the prefix pool of an ASN, analyse the
impact of blocking it, and decide the reviewed block scope. ASN is classification
metadata, never proof of maliciousness: **nothing ever activates an ASN-wide
block automatically.**

## Signed ASN prefix bundles

Payload `sumunjang.asn-bundle.v1`:

```json
{"format":"sumunjang.asn-bundle.v1","version":42,"created_at":1792200000,
 "source":"licensed-provider-2026-10","provenance":{"dataset":"...","generator":"..."},
 "prefixes":[{"network":"198.51.100.0/24","asn":64500}, ...]}
```

- Signed with Ed25519 in a domain-separated envelope (`"<domain>\0" || payload`,
  domain `sumunjang.asn-bundle.v1`) by the offline helper
  `guard-release-sign --asn-bundle payload.json seed.key bundle.json`. Use a
  dedicated bundle key, distinct from the release key; Sumunjang trusts
  `HANGANG_GUARD_ASN_BUNDLE_KEY` (base64 public key). A release-manifest
  signature can never verify as a bundle.
- Bounds: envelope ≤ 32 MiB, ≤ 100,000 prefixes (engine catalog bound), source ≤
  256 bytes, ≤ 16 provenance fields.
- Install paths: offline `sumunjang --import-asn-bundle FILE --database …`
  (no listeners; the service must have checkpointed once), `PUT /v1/asn/bundle`
  (envelope body; the console broker limits bodies to 1 MiB, so use the CLI or
  URL for large bundles), and the optional scheduled fetch
  `--asn-bundle-url https://…` (HTTPS only, no redirects, 30 s timeout,
  `--asn-bundle-ca`, `--asn-bundle-interval-seconds` 300–86,400, default 3,600;
  there is no default URL) or `POST /v1/asn/refresh`.
- Versions are monotonic: an equal version with the same digest is a no-op, an
  older one is refused (use rollback), and a rolled-back version is refused
  until a newer version is published.
- Each install returns and audits (`asn.bundle.install`) a diff report: prefixes
  before/after, added, removed, reassigned, samples and the most changed ASNs.
  Bundle rows, the checkpoint and the audit row commit in one transaction;
  failures keep the last-good catalog.
- `POST /v1/asn/bundle/rollback {"expected_version", "reason"}` reinstalls the
  last-good previous bundle (two are kept) and marks the current version
  `rolled_back` (`asn.bundle.rollback`).
- `GET /v1/asn/bundle`: current bundle (version, source, provenance, sha256,
  prefixes), history, key and fetch status (attempts, failures, last error).
- The installed bundle is reloaded at startup and takes precedence over the
  legacy unsigned `--asn-catalog`. Native Kubernetes ownership refuses bundle
  writes (its catalog comes from the source).

## ASN block proposals

`POST /v1/asn/proposals`:

```json
{"asn": 64500, "scope": {"kind": "asn" | "prefixes" | "aggregates", "prefixes": [...]},
 "reason": "botnet C2 hosting", "expires_at": 1792459200}
```

- `asn`: every catalog prefix of the ASN. `prefixes`: listed networks inside the
  ASN's catalog prefixes. `aggregates`: IPv4 /24 and IPv6 /48 networks inside the
  ASN that contain tracked evidence addresses (clipped to narrower catalog
  prefixes), plus listed /24 or /48 aggregates. At most 4,096 networks after
  removing nested ones. Errors are located (`/asn`, `/scope/prefixes/3`,
  `/reason`, `/expires_at`). A reason is required; expiry is within 30 days.
- `POST /v1/asn/preview` returns the same impact for a scope without storing
  anything.

**Impact analysis** (stored with the proposal, refreshed by `analyze`): network
list; estimated IPv4 addresses and IPv6 /64s; tracked evidence addresses in scope
with per-signal totals and the top addresses; in-memory history (addresses,
score, events); a decision preview on a never-published view with the proposal's
blocks — current mode (allow→deny, already denied, unchanged) and enforce — with
samples, so observe deployments see what enforcement would do; collisions with
allowlist entries (allowlisted addresses stay allowed), network zones and
existing blocks; warnings (observe mode, allowlist/zone overlaps, very large
networks). Hangang decision-log aggregate counts can be attached with
`annotate` (`decision_log`: at most 16 integer counts; pseudonymized source,
counts only).

**Lifecycle** — `POST /v1/asn/proposals/{id}` with
`{"action", "expected_revision", "reason"?, "decision_log"?}`:

| Action | From → to | Notes |
| --- | --- | --- |
| `submit` | draft → pending | recomputes and **freezes** the network list |
| `analyze` | draft, pending, approved | refreshes the impact (networks stay frozen after submit) |
| `annotate` | any open state | attaches decision-log counts |
| `approve` | pending → approved | distinct approvers, never the proposer; `--asn-proposal-approvals` (1–3, default 1) |
| `reject` | pending/approved → rejected | reason required |
| `activate` | approved → active | explicit only; blocks exactly the reviewed networks with source `asn_proposal`, expiry `min(expires_at, now + 7 days)`; networks already blocked longer are skipped |
| `withdraw` | any open state → withdrawn | removes only this proposal's blocks |
| (system) | → expired | at `expires_at`, or when the activated blocks expire |

Each proposal has a revision; a stale `expected_revision` returns 409 with
`current_revision`. Every transition is audited (`asn.proposal.*`) in the same
transaction as the proposal row (and the checkpoint for activate/withdraw). The
two-person rule compares verified actors: with the shared admin credential the
proposer and approver are the same identity, so use delegated console actors.
Blocks from proposals decide with `sumunjang.deny.block_asn`; the allowlist still
wins. At most 1,000 open proposals; old closed ones are pruned. `GET
/v1/asn/proposals` lists summaries; `GET /v1/asn/proposals/{id}` returns the
proposal with impact and history.

## Console routes (package 0.2.0, broker contract v2)

Plain: `asn/bundle` GET, `asn/bundle` PUT (mutation), `asn/bundle/rollback` POST
(mutation), `asn/refresh` POST (mutation), `asn/preview` POST, `asn/proposals`
GET, `asn/proposals` POST (mutation). Patterns: `asn/proposals/*` GET and
`asn/proposals/*` POST (mutation). The package now declares `api_version: 2`
(40 routes + 2 patterns) and needs a Hangang console with broker route patterns.
