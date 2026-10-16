# Network zones

[한국어](ko/NETWORK_ZONES.md) · [Documentation index](README.md)

Sumunjang owns named network zones (zero-trust ADR 0021 "network zones",
ADR 0022 `NetworkZone`). A zone is a named set of IPv4/IPv6 prefixes. Zones label
addresses — in decision evidence, explain and the snapshot Pumgye imports for
zone conditions and ceilings. They never change a Sumunjang admission decision.

## Model and bounds

`{"id", "display_name"?, "description"?, "owner"?, "prefixes": [CIDR, …]}`

- `id`: `[A-Za-z0-9_.:-]{1,128}` (the Pumgye zone name, for example
  `corp` or the converter's `legacy.<service>.<n>` proposals).
- `display_name` ≤ 128, `owner` (team/contact text) ≤ 128, `description` ≤ 512
  bytes, no control characters.
- `prefixes`: 1 or more, canonicalized (host bits cleared, IPv4-mapped IPv6 →
  IPv4), sorted, no duplicates within a zone; a prefix may belong to several
  zones.
- At most **64 zones and 65,536 prefixes** in total, the Pumgye contract bounds,
  so every snapshot is importable.
- `updated_at` / `updated_by` are stamped by the server (body values ignored).
- ASN and country members are not part of the Pumgye contract and are not
  supported; use JSON/Lua rules for ASN/country conditions.

The zone set has a monotonic `revision` (contract `revision`), persisted in the
checkpoint with the zones; every successful change increments it.

## Admin API (admin credential)

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/zones` | `{schema, revision, limits, zones: [Zone…]}` |
| `POST /v1/zones` | `{"expected_revision": N, "zone": {…}, "reason"?}` creates or replaces; `{"expected_revision": N, "remove": "<id>", "reason"?}` removes (for broker clients) |
| `DELETE /v1/zones` | `{"expected_revision": N, "id", "reason"?}` removes |
| `GET /v1/zones/snapshot` | Pumgye contract snapshot (below) |
| `POST /v1/zones/lookup` | `{"ip"}` → `{ip, revision, zones: [ids]}` |

Writes compare against the zone revision: a stale `expected_revision` returns
409 with `current_revision` and changes nothing. Invalid zones return 400 with
JSON Pointer paths (`/zone/id`, `/zone/prefixes/3`). Writes are audited as
`zones.upsert` / `zones.remove` with a diff summary, digests and the reason, in
the checkpoint transaction (fail closed). Under exclusive Kubernetes ownership
zone writes are refused (409); lookup and reads remain available.

## Pumgye snapshot contract

`GET /v1/zones/snapshot` returns exactly the body defined in Pumgye
`docs/MODEL_V2.md` ("Sumunjang zone contract"):

```json
{"revision": 7, "zones": {"corp": {"prefixes": ["10.0.0.0/8"]},
                          "office": {"prefixes": ["192.0.2.0/24"]}}}
```

Names and prefixes already satisfy the contract (name pattern, canonical
prefixes, ≤ 64 zones, ≤ 65,536 prefixes). Headers `x-sumunjang-zone-revision`
and `x-sumunjang-zone-digest` (`sha256:` of the body) let an operator or importer
verify what was published. Pumgye imports it as
`"zones": {"source": "sumunjang", "revision": N, …}` through its own CAS
publication. The snapshot is versioned but **not signed**: signed fetch by
Pumgye is ADR 0021 P1 (PPG2/HGD); until then transfer it over the admin channel.

## Evidence and explain

- Membership compiles into one radix tree of 64-bit zone masks published with
  each decision view. A lookup walks one path and never allocates
  (`crates/guard-core/tests/no_alloc.rs`). It runs outside the decision function,
  so decisions without evidence pay nothing.
- `POST /v1/explain` adds an informational `zone` stage (second, after `mode`):
  zone ids, `zone_revision`, code `sumunjang.stage.zone.match` / `.none`.
  Batch results include `zones`.
- HTTP `/v1/decision` evidence adds `zones` (≤ 8, id order), `zones_truncated`
  and `zone_revision`. gRPC `NetworkEvidence` adds `zone_ids` (10),
  `zone_ids_truncated` (11) and `zone_revision` (12); zone ids are trimmed so the
  reply stays within the 1 KiB encode bound. HGD1 is unchanged.

## Kubernetes

The native `SumunjangPolicy` source does not carry zones, and the ADR 0022
`NetworkZone`/`NetworkControl` structural CRDs are not implemented: mapping them
needs a new informer source, ownership rules for mixed native/admin zones and a
migration tool, so it is not a trivial change. In Kubernetes-owned mode zones are
read-only (whatever the checkpoint holds).

## Console

Package 0.1.7 declares `zones` (GET) and `zones` (POST, mutation). Snapshot and
lookup are not broker routes (the broker allows 32 routes, now all used); the
console gets membership from explain and evidence.
