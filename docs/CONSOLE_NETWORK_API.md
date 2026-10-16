# Console Network APIs

[한국어](ko/CONSOLE_NETWORK_API.md) · [Documentation index](README.md)

Additive, backward-compatible owner APIs used by the rebuilt console Network
pages. All require the **admin** bearer credential; writes are audited
([audit and explain](AUDIT_EXPLAIN.md)). Console package 0.1.6 declares the
broker routes listed at the end.

## Per-address signal history

`GET /v1/history?ip=&since=&until=` or `POST /v1/history/query`
`{"ip", "since"?, "until"?}` (Unix seconds; default: the retention window up to
now). Accepted evidence events are folded into per-minute buckets per address:
weighted score added in that minute (weights at ingestion time) and per-signal
counts. Response (`sumunjang.history.v1`): `buckets` (`start`, `score`,
`signals`), `totals`, the current evidence `window` (`signal_score`,
`threshold`, `window_secs`) and `stats` (addresses, buckets, caps, dropped).

Bounds: retention `--history-hours` (default 6, 1–48); at most 10,000 addresses
and 262,144 minute buckets in total (≈ 16 MiB worst case); overflow is counted in
`stats.dropped`, never grown. Only counts are kept — no paths, sources or request
logs. History is memory-only observation: it survives policy changes (which reset
the evidence window) and is lost on restart. Events refused because the address
is allowlisted or already denied are not counted, as before.

## Candidates

`GET /v1/candidates` entries add `signals` (`honeypot`, `scanner`,
`auth_failure`, `invalid_request` counts within the window) and `country`
(GeoIP, `null` without a country database). Aggregates restored from checkpoints
written before this change report zero per-signal counts for their old buckets.

## Block provenance

`GET /v1/blocks` and the candidate approval reply add `source` (`manual`,
`approved`, `auto`, `kubernetes`, `unknown` for blocks created before provenance
was recorded), `created_at` and `created_by` (verified delegated console actor
name, otherwise `admin-credential`). Provenance is recorded by Sumunjang, cannot
be supplied in `POST /v1/blocks` (an `origin` field is rejected), is persisted
in the checkpoint and is not part of snapshots or HGD1. Reason codes
(`sumunjang.deny.block_*`) now use the source; only `unknown` blocks fall back to
the fixed reason strings. Kubernetes source blocks use
`sumunjang.deny.block_source`.

## Rules compare-and-set and Lua source

`GET /v1/rules/document` → `{revision, rules, source: "json"|"lua", script}`.
`script` is the retained Lua source (≤ 32 KiB, persisted) when the active rules
were applied from Lua, so the editor can reload it; a JSON write clears it.

- `PUT /v1/rules` with `{"expected_revision", "rules", "reason"?}` publishes only
  if the rules revision still matches and returns the new document; otherwise
  409 `{"error", "current_revision"}` without changes.
- `PUT /v1/rules/lua` accepts optional `expected_revision` and `reason`; with a
  revision it returns the document, otherwise the RuleSet as before.
- **Deprecated:** bare-RuleSet `PUT /v1/rules` and Lua writes without
  `expected_revision` remain unconditional (lost-update risk) for existing
  clients. The rules revision changes on every rules write and on restart.

## Change reasons

Optional `reason` (≤ 256 bytes, no control characters) on `DELETE /v1/blocks`,
`POST /v1/candidates/approve`, rules and Lua writes, allowlist writes and the
policy document; `POST /v1/blocks` records the block's own `reason`. The reason
is stored in the audit row.

## Offline ASN catalog

`GET /v1/asn/catalog?asn=&limit=&cursor=` or `POST /v1/asn/catalog/query`.
Lists the offline `--asn-catalog` (or Kubernetes source) prefixes sorted by ASN
and network, grouped per ASN: `entries: [{asn, prefixes: [...]}]`,
`total_prefixes`, `total_asns`, `next_cursor`. `limit` counts prefix rows
(1–1,000, default 200); cursors are stable keys. MMDB ASN databases cannot be
enumerated and are not listed. ASN proposals remain out of scope.

## Allowlist entries

`GET /v1/allowlist` → `{revision, entries: [{network, expires_at, reason,
created_at, created_by, expired}]}`. `revision` is the policy document revision.

- `POST /v1/allowlist` `{"expected_revision", "network", "expires_at"?,
  "reason"?}` adds an entry or updates its metadata.
- `DELETE /v1/allowlist` `{"expected_revision", "network", "reason"?}` removes it.
- Stale revisions return 409 with `current_revision`. Audit actions
  `allowlist.add` / `allowlist.remove`.

Metadata lives in the policy as additive `allow_meta` (keyed by canonical
network; omitted when empty), so the policy document stays compatible. A policy
write that omits `allow_meta` keeps the metadata of entries that remain, so older
editors cannot silently turn a temporary entry into a permanent one. An expired
entry stops matching on the next lookup (no allocation on the decision path),
is reported with `expired: true` until removed and is omitted from snapshots;
a snapshot client may still honour it until its snapshot expires (≤ 30 s). As
with any policy write, allowlist writes reset the evidence window.

## Console package 0.1.6 routes

Added: `rules/document` GET, `history/query` POST, `asn/catalog/query` POST,
`allowlist` GET, `allowlist` POST (mutation), `allowlist` DELETE (mutation).
The GET variants with query strings are for direct API clients; the broker
forwards no query strings. The package now declares 31 of the broker's 32 routes.
