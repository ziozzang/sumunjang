# 지표(Metrics)

[English](../METRICS.md) · [문서 목록](README.md)

`GET /metrics`는 주 관리 리스너(`--listen`)에서 Prometheus 텍스트 형식 0.0.4를
제공한다. 제로트러스트 OBSERVABILITY 지침에 따라 카디널리티가 낮고 제한된 라벨 값만
쓰며 주소·주체·URL·룰 ID·존 이름은 절대 라벨로 쓰지 않는다.

## 접근

- `--management-tls`가 있으면 클라이언트 인증서가 필수인 **HTTPS**로 제공한다(같은
  재적재 가능한 판정 TLS 자료). 없으면 일반 HTTP이며 루프백/사이드카 용도로만 쓴다.
- 인가: `Authorization: Bearer <HANGANG_GUARD_METRICS_TOKEN>`(선택 사항인 읽기 전용
  자격, 16–4,096바이트, collector·관리자 자격과 달라야 하며 다른 권한 없음) 또는 관리자
  자격. collector 자격은 거부한다.
- `--readiness-listen`에는 노출하지 않는다. 이 리스너는 인증 없는 프로브 전용 일반
  HTTP로 유지한다.

## 실시간 경로

판정 카운터와 지연 히스토그램은 전송·모드·사유 코드로 색인한 고정 원자 배열
(`guard_core::metrics`)이다. 기록은 relaxed 원자 덧셈 몇 번이며 할당하지 않는다
(`crates/guard-core/tests/no_alloc.rs`). 게이지는 수집(scrape) 때만 계산한다.

## 시계열

| 지표 | 형식 | 라벨 |
| --- | --- | --- |
| `sumunjang_decisions_total` | counter | `transport`(http, hgd1, grpc), `mode`, `outcome`(allow, deny), `reason`(`sumunjang.*` 판정 코드) |
| `sumunjang_decisions_unavailable_total` | counter | `transport`, `reason`(`sumunjang.unavailable.*`) |
| `sumunjang_decision_duration_seconds` | histogram | `transport`(5µs–100ms 버킷) |
| `sumunjang_evidence_accepted_total`, `sumunjang_evidence_dropped_capacity_total`, `sumunjang_evidence_batches_rejected_total`, `sumunjang_block_capacity_rejections_total` | counter | — |
| `sumunjang_candidates`, `sumunjang_blocks{source}`, `sumunjang_allowlist_entries{state}`, `sumunjang_zones`, `sumunjang_zone_prefixes`, `sumunjang_zone_revision`, `sumunjang_rules`, `sumunjang_rules_from_lua`, `sumunjang_asn_catalog_prefixes`, `sumunjang_policy_enforce`, `sumunjang_decision_revision` | gauge | `source`(unknown, manual, approved, auto, kubernetes), `state`(active, expired) |
| `sumunjang_rules_compile_failures_total` | counter | `kind`(lua, json) |
| `sumunjang_admin_changes_total` | counter | `result`(committed, refused, uncertain) |
| `sumunjang_checkpoints_total` | counter | `result`(success, failure) |
| `sumunjang_checkpoint_last_success_timestamp_seconds`, `sumunjang_checkpoint_age_seconds`, `sumunjang_ready` | gauge | — |
| `sumunjang_tls_enabled`, `sumunjang_tls_reload_consecutive_failures`, `sumunjang_tls_leaf_expiry_seconds` | gauge | — |
| `sumunjang_tls_reloads_total`, `sumunjang_tls_reload_failures_total` | counter | — |
| `sumunjang_history_addresses`, `sumunjang_history_buckets` / `sumunjang_history_dropped_total` | gauge / counter | — |
| `sumunjang_kubernetes_authority_enabled`, `_available`, `_remaining_seconds`, `sumunjang_kubernetes_diagnostic_source_fresh` | gauge | — |
| `sumunjang_geoip_database_loaded` | gauge | `role`(country, asn) |
| `sumunjang_build_info` | gauge | `version` |

근거를 수집하는 HTTP 판정은 수집 전 결과로 센다. 그 이벤트로 생긴 자동 차단은 응답과
다음 판정부터 반영된다. HGD1은 프레임마다, gRPC는 사용 불가 확인을 포함해 응답 경로에서
기록한다.

권장 경보: `sumunjang_ready == 0`, `sumunjang_checkpoint_age_seconds > 60`,
`increase(sumunjang_tls_reload_failures_total[15m]) > 0`,
`sumunjang_tls_leaf_expiry_seconds < 7*86400`, 활성화 시
`sumunjang_kubernetes_authority_available == 0`, 증가하는
`sumunjang_evidence_dropped_capacity_total`·`sumunjang_history_dropped_total`, 전송별
`sumunjang_decision_duration_seconds` p99.

## Helm / ServiceMonitor

패키지 차트는 HTTPS를 기대한다. 관리 리스너를 pod 네트워크에서 mTLS로 실행하고
(`--listen=0.0.0.0:9080 --management-tls`와 판정 TLS 플래그. `deploy/` 템플릿은
루프백에 바인딩하므로 수집하려면 바꿔야 한다) Prometheus에 같은 클라이언트 CA로 발급한
클라이언트 인증서와 metrics 토큰을 준다. 예시는 [영문 문서](../METRICS.md)의
ServiceMonitor를 참고한다(`scheme: https`, `bearerTokenSecret`, `tlsConfig`의 CA·
클라이언트 인증서·키). 준비 상태 프로브는 `--readiness-listen`(`/readyz`, `/healthz`)에
둔다.
