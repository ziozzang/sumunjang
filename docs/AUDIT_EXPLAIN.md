# Policy-change audit, explain and decision evidence

[한국어](ko/AUDIT_EXPLAIN.md) · [Documentation index](README.md)

Owner APIs required by the unified console (zero-trust ADR 0020) and decision
events (ADR 0019): a durable audit of policy changes, an explain/what-if API on
the live evaluation path, and additive decision evidence for gRPC and HTTP
decisions. All endpoints below require the **admin** bearer credential unless
stated otherwise. HGD1 frames are unchanged.

## Policy-change audit

Every administrative mutation writes one audit row:

| Action | Endpoint / source |
| --- | --- |
| `policy.replace` | `PUT /v1/policy` (legacy) |
| `policy.document.replace` | `PUT /v1/policy/document` (optional `reason`, ≤ 256 bytes) |
| `blocks.add`, `blocks.remove` | `POST`/`DELETE /v1/blocks` |
| `candidates.approve` | `POST /v1/candidates/approve` |
| `rules.replace`, `rules.lua.replace` | `PUT /v1/rules`, `PUT /v1/rules/lua` (Lua compile failures are refusals) |
| `geoip.reload` | `POST /v1/geoip/reload` |
| `update.check` | `POST /v1/update/check` |
| `kubernetes.authority.publish` | native `--kubernetes-authority` publication whose content changed |
| `startup.import` | `--policy`, `--bootstrap-policy`, `--asn-catalog` changing stored state at startup |

A row contains: opaque `id`, `time`/`time_ms`, `actor` (`kind`, `id`, `name`,
`issuer`, `client_ip`, `request_sha256`), `action`, `target` (policy, rules, a
network, an IP, `resourceVersion=…`), `result` (`committed`, `refused`,
`uncertain`), `revision_before`/`revision_after` (decision revision, the
`revision` of decision replies), `policy_revision` (policy document revision),
`before_digest`/`after_digest` (`sha256:` of the affected policy, rules, block
set, GeoIP metadata or full published state), a bounded human-readable
`summary` (for example `mode observe -> enforce; allow +1: 192.0.2.0/24` or
`rules 3 -> 4; added deny-cn; changed asn-allow`), `reason` and `error`. Rows
never contain credentials, Lua source or request bodies. Mutation responses carry
the row ID in `x-sumunjang-audit-id`.

**Fail closed.** Committed rows are inserted in the same SQLite transaction as the
policy checkpoint. If the audit insert fails, the transaction rolls back, the
request fails with 500 and the published policy, decision view and checkpoint
stay unchanged. GeoIP reload commits its row before swapping the in-memory
catalog (503 and old catalog on audit failure). `update.check` touches a file
outside SQLite, so it first records `uncertain`, then finalizes to `committed`
or `refused`; a crash in between leaves `uncertain`, which is truthful. A failed
`COMMIT` is recorded as `uncertain` under the same ID (the insert fails if the
original row did commit). Refusals (validation errors, stale revisions, Lua
errors, exclusive Kubernetes owner, disabled updates) are recorded best-effort in
their own transaction: nothing changed, so a failure there does not alter the
refusal. Requests rejected before decoding (authentication, malformed JSON) and
event-driven automatic blocks are not policy-change audit rows; candidates and
the Hangang host journal own those records. Unchanged Kubernetes republications
(every 500 ms) are not recorded.

**Retention.** `--audit-max-rows` (default 100,000; 1,000–10,000,000) and
`--audit-retention-days` (default 365; 1–3,650). Every insert and every
five-second checkpoint removes the oldest rows beyond either bound; reads also
exclude rows past the age bound. Row IDs (`seq`) are never reused, so cursors
remain stable while old rows are pruned.

**Actor.** By default the actor is the shared admin credential
(`kind: credential`). When the Hangang console binding sets
`"delegate_actor": true` (and `"delegation_authority": "hangang"`) with the Guard
admin credential as `token_env` (≥ 32 bytes), the broker signs every dispatched
call (`x-hopae-delegation`, `x-hopae-delegation-mac`: HMAC-SHA-256 under that
credential). Sumunjang verifies signature, method, path, body SHA-256, ±10 s
freshness and a single-use nonce, then records `kind: delegated`, the console
account ID/name, `issuer: hangang` and the administrator's client IP. A present
but invalid, stale, replayed or mismatched assertion returns 401; it is never
downgraded to the credential actor. `request_sha256` equals the host plugin
journal's body digest for correlation.

### Query

`GET /v1/audit?since=&until=&actor=&action=&result=&target=&limit=&cursor=` and
`POST /v1/audit/query` with the same fields as JSON (the console broker forwards
no query strings). `since` (inclusive) and `until` (exclusive) are Unix seconds;
`action` is exact or a prefix ending in `.*` (`blocks.*`); `limit` is 1–200
(default 50). Results are newest first:

```json
{"schema":"sumunjang.audit.v1","entries":[{"id":"…","time":1760600000,"actor":{"kind":"delegated","id":7,"name":"operator","issuer":"hangang"},
  "action":"policy.document.replace","target":"policy","result":"committed","revision_before":41,"revision_after":42,
  "before_digest":"sha256:…","after_digest":"sha256:…","summary":"mode observe -> enforce","message_key":"sumunjang.audit.result.committed"}],
 "next_cursor":"a118","retention":{"max_rows":100000,"max_days":365,"retained_rows":118,"oldest_retained_ms":1760000000000}}
```

Pass `next_cursor` as `cursor` for the next page; `null` means no more rows.
Invalid filters return 400; a database failure returns 503 (never an empty page).

## Explain and what-if

`POST /v1/explain`:

```json
{"ip":"203.0.113.7",
 "candidate":{"policy":{…},"rules":{…}},       // optional; or "script": Lua instead of "rules"
 "evidence":{"honeypot":2,"scanner":0,"auth_failure":0,"invalid_request":0,"include_observed":true},
 "geo":{"country":"KR","asn":64500},            // optional simulated metadata
 "at":1760600000}                               // optional simulated time, ±30 days
```

The decision is computed by `DecisionView::evaluate`, the same function every
live transport uses (`query_ip_context` is that function with the zero-sized
`NoTrace` sink). Explain passes a bounded `VecTrace`; geo metadata reaches rule
evaluation under the live rule (only when the evaluated rules require it). With a
`candidate`, a never-published view is built from the candidate mode/allowlist
and/or rules plus the published blocks and ASN catalog. Candidates are validated
exactly as publication would (`Policy::validate`, snapshot budget,
`RuleSet::validate`, the Lua sandbox for `script`) and are never stored,
published or audited as a change.

The response (`schema: sumunjang.explain.v1`) contains `decision` (identical in
shape to `/v1/decision`), `verdict` (`allow`, `deny`, `observe`), `reason_code`,
`params`, `matched_rules`, ordered `stages` and `trace_truncated`:

| Stage | Content |
| --- | --- |
| `mode` | `observe` ends evaluation (Guard allows); `enforce` continues |
| `allowlist` | match and matched prefix; a match ends evaluation |
| `geo` | country, ASN and ASN source (`geoip`, `catalog`) used by rules; `simulated` |
| `rules` | configured count, every matching active rule (id, action, priority, score, winner), matched-but-expired rules, winner |
| `blocklist` | most specific active block (network, reason, expiry, remaining) and covering expired blocks |
| `outcome` | deciding stage and final reason code |
| `score` | informational: observed + simulated signal score, static rule score, threshold, suspicion |
| `auto_block` | informational: whether automatic blocking would add a block and the projected deny |

Stages that were not reached are omitted. In observe mode `enforce_preview`
holds the same evaluation as enforce. `evaluated` labels `source`
(`published`/`candidate`), `revision`, `policy_revision`, `candidate_digest`,
`rules_source` (`json`, `lua`, `published`), `source_available` and
`stored: false`; `simulated` labels time, geo and evidence.

Invalid input returns 400 with JSON Pointer paths, for example
`{"error":"invalid explain request","errors":[{"path":"/candidate/rules/rules/0/network","message":"invalid IP address syntax"}]}`.
Serde type/unknown-field errors, every policy/rule diagnostic and Lua failures
(`/candidate/script`) are located this way.

`POST /v1/explain/batch` with `{"ips":[…≤1024], "candidate":{…}, "at":…}`
returns per-address `published` (and `candidate`) action, verdict, reason code,
rules and block, a `changed` flag and a `summary`
(`total`, `changed`, `allow_to_deny`, `deny_to_allow`, `reason_changed`). Without
a candidate it reports the published decisions only.

Explain and batch requests are reads: they consume the bounded worker pool, are
admin-only and are not written to the policy-change audit (the Hangang host and
console own simulation audit, ADR 0019).

## Reason codes and messages

`GET /v1/reasons` returns the registered codes (decision, stage, audit) and the
English/Korean catalogs (`crates/guard-core/messages/{en,ko}.json`). Message keys
equal the codes; messages use `{name}` placeholders filled from `params`.
Decision codes: `sumunjang.observe.mode`, `sumunjang.allow.allowlist`,
`sumunjang.allow.rule`, `sumunjang.allow.default`, `sumunjang.deny.rule`,
`sumunjang.deny.block_manual`, `sumunjang.deny.block_approved`,
`sumunjang.deny.block_automatic`, `sumunjang.unavailable.revision_floor`,
`sumunjang.unavailable.owner_replaced`, `sumunjang.unavailable.source`. Tests
require identical key sets and placeholders in both languages; adding a code
requires both messages.

## Decision evidence (gRPC and HTTP)

gRPC: set `NetworkRequest.include_evidence = true` (field 4) to receive
`NetworkReply.evidence` (field 6). See [gRPC](GRPC.md). HTTP: add
`"evidence": true` to the `POST /v1/decision` body (collector credential) to
receive an additional `evidence` object:

```json
{"version":1,"revision":418,"action":"allow","mode":"enforce","reason":null,"ttl_ms":5000,
 "evidence":{"schema":"sumunjang.evidence.v1","verdict":"allow","mode":"enforce","reason_code":"sumunjang.allow.rule",
   "deciding_stage":"rule","rules":["asn-allow-corp"],"rules_truncated":false,"block":null,"asn":64500,"country":"KR",
   "revision":418,"enforce":{"action":"allow","reason_code":"sumunjang.allow.rule"}}}
```

Without the flag the reply is byte-for-byte unchanged. Older servers reject the
unknown field (`deny_unknown_fields`); clients should enable it only after the
server is upgraded. Rule IDs (≤ 8, winner first) are the matching active rules;
`enforce` reports what enforcement of the same published view decides, which is
informative while the policy is observed. ASN/country come from rule metadata or
a GeoIP/offline-catalog lookup. `block` is a network address: consumers that
export events must pseudonymize it like other addresses (ADR 0019).

## Hot path

The evaluation function is generic over a `Tracer`. Production instantiates it
with `NoTrace` (zero-sized, `#[inline(always)]` empty method), so HGD1, HTTP and
gRPC decisions contain no trace code and do not allocate.
`crates/guard-core/tests/no_alloc.rs` installs a counting global allocator and
asserts zero allocations across observe/enforce, allowlist, rule, expired rule,
observe rule, block, expired block, automatic block, IPv4/IPv6/mapped and default
paths, for both `NoTrace` and the fixed-size `Evidence` sink, and checks
traced/untraced parity. Server tests compare `/v1/explain` with `/v1/decision`
for 293 addresses in each mode.
