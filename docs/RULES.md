# Dynamic rules, scoring and GeoIP

[한국어](ko/RULES.md) · [Documentation index](README.md)

JSON and embedded Lua both compile into one typed, persisted RuleSet. An admin
can validate without activation, then atomically apply while queries continue
reading the last committed immutable policy view. Lua only executes on rule
configuration, never per-request. Existing Hangang auth still follows guard allow.

## Schema and precedence

```json
{
  "version": 1,
  "rules": [
    {"id":"network-watch","priority":10,"network":"192.0.2.0/24",
     "action":"observe","score":5,"description":"review this test pool"},
    {"id":"country-deny","priority":20,"countries":["GB"],
     "action":"deny","score":10}
  ]
}
```

Rule optional fields: `network`, `countries`, `asns`, `expires_at` (Unix seconds),
`description`, `priority` (default 0), `score` (default 0). At least one condition
must exist. Conditions across fields are AND; country/ASN lists are OR within
that field. Missing GeoIP does not match a rule requiring that metadata.
Maximum 256 rules, unique ASCII ids ≤ 64 bytes, description ≤ 256 bytes, score ≤ 1,000,000,
country/ASN list ≤ 256 each. Countries normalize to uppercase; networks normalize to
canonical CIDR. Rules are indexed via compressed CIDR trie and fixed 256 bit masks.

Guard allowlist always wins. In enforce mode highest priority matching rule wins,
with equal priorities ordered by id ascending. `allow` permits guard admission,
`deny` blocks, `observe` leaves the existing manual/automatic IP block decision in
place. Lower priority action rules do not override the winner. All matching rule
scores sum for inspection, independent of winning action. In observe mode every
guard decision allows, while evidence and rule scores remain visible.

Country/ASN rules are explicit operator choices, not automatic reputation facts.
Rule scores alone do not create automatic block records; automatic IP blocking
uses the configured event-weight threshold. This prevents a static pool tag from
quietly becoming a broad automatic ban. Geo/rule inspection is an admin path.

## Lua embedding

Equivalent Lua configuration:

```lua
local ranges = { "192.0.2.0/24", "2001:db8::/48" }
local rules = {}
for i, network in ipairs(ranges) do
  rules[i] = { id = "watch-" .. i, network = network,
               priority = 10, action = "observe", score = 5 }
end
return { version = 1, rules = rules }
```

Script ≤ 32 KiB, Lua memory ≤ 4 MiB, approximately 100,000 instruction budget and a 50 ms hook
budget. Only text chunks and selected string/math/table/UTF8 libraries are
available. No `os`, `io`, `package`, `debug`, `require`, dynamic chunk loading,
filesystem, network or process API. The Lua hook is an execution budget, not an OS
process isolation boundary. Only authenticated administrators configure scripts.
Compile in a blocking worker; invalid scripts cannot change active policy.

API (admin token):
- `GET/PUT /v1/rules` reads/applies JSON RuleSet.
- `POST /v1/rules/validate` with exactly one of `{rules: RuleSet}` or `{script: ...}`
  returns `{valid: true, rules: RuleSet}` without modifying policy.
- `PUT /v1/rules/lua` with `{script: ...}` compiles and durably applies.

Snapshots v1 do not carry dynamic rules. `/v1/snapshot` returns 501 when rules are
nonempty to prevent a silently incomplete policy. Use HTTP or binary query mode
for dynamic rules. A previously running snapshot client retains its old snapshot
until expiry then fails open: do not mix snapshot rollout with dynamic rule
activation. Decision caches may remain stale for their explicit 1–5 s TTL, including
GeoIP reload. Zero cache obtains the current published policy on every query.

## IP and CIDR scores

`POST /v1/lookup {ip}` returns GeoIP plus `inspection` with decision, total score,
signal score, static rule score, matched rule ids and suspicion.

Stages: `normal`=0; `watch`=positive but below policy threshold; `suspicious`=at
least threshold but below 3×threshold; `high`=at least 3×threshold; `blocked`=current
policy denies. Stages describe current evidence, not the probability of an attack.
Signal scores decay with the bounded window; no raw request logs are retained.

`POST /v1/networks/inspect {network}` returns unique tracked IPs, evidence count,
signal score sum, largest IP signal score, and static rule score for network-only
rules covering the **entire queried CIDR**. Partial subnetwork and GeoIP-based rules
cannot establish a baseline for the whole CIDR. Scoring does not trigger automatic
CIDR or ASN-wide blocking. Review both aggregate size and per-IP values.

## GeoIP

Configure local immutable databases with `--geoip-database` (Country/City,
including DBIP-Country-Lite) and `--geoip-asn-database` (GeoIP2/GeoLite2-ASN). Each
file ≤ 128 MiB, verified MMDB structure/type, regular opened file and bounded reads.
Future build timestamps beyond 5 min are rejected. Missing/malformed records return
unknown fields. Metadata reports type/build epoch/size, never private file paths.

`POST /v1/geoip/reload` reloads only startup-configured paths atomically; a failure
preserves the last good catalog. Update DB files through your licensed provider,
then reload. No online provider is called during admission. Country/ASN fields
are decoded on decisions only when a rule requires them; detailed city/location
metadata is decoded on admin lookup. Geographic accuracy varies; accuracy radius
is displayed when available and never interpreted as exact personal location.

When ASN MMDB metadata is missing, configured offline `--asn-catalog` prefixes
provide ASN rule context. Explicit MMDB ASN takes precedence. Admin inspection
reports the effective ASN, and the dashboard displays that fallback.

## Explain and candidate rules

`POST /v1/explain` traces one address through mode, allowlist, geo/ASN, every
matching and expired rule, the block lookup and the final reason code, for the
published rules or a candidate `rules`/`script` that is validated like
`PUT /v1/rules`/`PUT /v1/rules/lua` but never stored. `POST /v1/explain/batch`
counts how a candidate changes up to 1,024 addresses. See
[audit and explain](AUDIT_EXPLAIN.md).
