# Metrics

[한국어](ko/METRICS.md) · [Documentation index](README.md)

`GET /metrics` serves Prometheus text exposition 0.0.4 on the main management
listener (`--listen`). It follows the zero-trust OBSERVABILITY guidance: low
cardinality, bounded label values only, never addresses, subjects, URLs, rule
ids or zone names.

## Access

- Served over **HTTPS with mandatory client certificates** when
  `--management-tls` is set (the same reloadable decision TLS material); plain
  HTTP otherwise (loopback/sidecar use only).
- Authorization: `Authorization: Bearer <HANGANG_GUARD_METRICS_TOKEN>` — an
  optional, read-only credential (16–4,096 bytes, distinct from collector and
  admin) that grants nothing else — or the admin credential. The collector
  credential is refused.
- Not exposed on `--readiness-listen`, which stays a probe-only, unauthenticated
  plain-HTTP listener.

## Hot path

Decision counters and latency histograms are fixed arrays of atomics indexed by
transport, mode and reason code (`guard_core::metrics`); recording is a few
relaxed atomic additions and never allocates (covered by
`crates/guard-core/tests/no_alloc.rs`). Gauges are computed only on scrape.

## Series

| Metric | Type | Labels |
| --- | --- | --- |
| `sumunjang_decisions_total` | counter | `transport` (http, hgd1, grpc), `mode`, `outcome` (allow, deny), `reason` (`sumunjang.*` decision code) |
| `sumunjang_decisions_unavailable_total` | counter | `transport`, `reason` (`sumunjang.unavailable.*`) |
| `sumunjang_decision_duration_seconds` | histogram | `transport` (5 µs … 100 ms buckets) |
| `sumunjang_evidence_accepted_total`, `sumunjang_evidence_dropped_capacity_total`, `sumunjang_evidence_batches_rejected_total`, `sumunjang_block_capacity_rejections_total` | counter | — |
| `sumunjang_candidates`, `sumunjang_blocks{source}`, `sumunjang_allowlist_entries{state}`, `sumunjang_zones`, `sumunjang_zone_prefixes`, `sumunjang_zone_revision`, `sumunjang_rules`, `sumunjang_rules_from_lua`, `sumunjang_asn_catalog_prefixes`, `sumunjang_policy_enforce`, `sumunjang_decision_revision` | gauge | `source` (unknown, manual, approved, auto, kubernetes), `state` (active, expired) |
| `sumunjang_rules_compile_failures_total` | counter | `kind` (lua, json) |
| `sumunjang_admin_changes_total` | counter | `result` (committed, refused, uncertain) |
| `sumunjang_checkpoints_total` | counter | `result` (success, failure) |
| `sumunjang_checkpoint_last_success_timestamp_seconds`, `sumunjang_checkpoint_age_seconds`, `sumunjang_ready` | gauge | — |
| `sumunjang_tls_enabled`, `sumunjang_tls_reload_consecutive_failures`, `sumunjang_tls_leaf_expiry_seconds` | gauge | — |
| `sumunjang_tls_reloads_total`, `sumunjang_tls_reload_failures_total` | counter | — |
| `sumunjang_history_addresses`, `sumunjang_history_buckets` / `sumunjang_history_dropped_total` | gauge / counter | — |
| `sumunjang_kubernetes_authority_enabled`, `_available`, `_remaining_seconds`, `sumunjang_kubernetes_diagnostic_source_fresh` | gauge | — |
| `sumunjang_geoip_database_loaded` | gauge | `role` (country, asn) |
| `sumunjang_build_info` | gauge | `version` |

HTTP decisions that ingest evidence are counted with the pre-ingest outcome; an
automatic block created by that event shows in the reply and from the next
decision on. HGD1 records per frame; gRPC records in the reply path, including
unavailable fences.

Suggested alerts: `sumunjang_ready == 0`; `sumunjang_checkpoint_age_seconds > 60`;
`increase(sumunjang_tls_reload_failures_total[15m]) > 0`;
`sumunjang_tls_leaf_expiry_seconds < 7*86400`;
`sumunjang_kubernetes_authority_available == 0` when enabled; rising
`sumunjang_evidence_dropped_capacity_total` or `sumunjang_history_dropped_total`;
p99 of `sumunjang_decision_duration_seconds` per transport.

## Helm / ServiceMonitor

The packaged chart expects HTTPS. Run the management listener on the pod network
with mTLS (`--listen=0.0.0.0:9080 --management-tls` plus the decision TLS flags;
the template in `deploy/` binds loopback and must be changed for scraping) and
provide Prometheus a client certificate from the same client CA and the metrics
token:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
spec:
  endpoints:
    - port: management-mtls          # Service port -> 9080
      scheme: https
      path: /metrics
      bearerTokenSecret: {name: sumunjang-api-tokens, key: metrics}
      tlsConfig:
        serverName: sumunjang.<namespace>.svc
        ca: {secret: {name: sumunjang-tls, key: ca.crt}}
        cert: {secret: {name: prometheus-sumunjang-client, key: tls.crt}}
        keySecret: {name: prometheus-sumunjang-client, key: tls.key}
```

Keep the readiness probe on `--readiness-listen` (`/readyz`, `/healthz`).
