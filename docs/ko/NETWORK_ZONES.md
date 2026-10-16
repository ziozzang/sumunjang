# 네트워크 존

[English](../NETWORK_ZONES.md) · [문서 목록](README.md)

수문장은 이름 있는 네트워크 존을 소유한다(제로트러스트 ADR 0021 "network zones",
ADR 0022 `NetworkZone`). 존은 이름이 붙은 IPv4/IPv6 접두어 집합이다. 존은 판정 근거,
explain, 그리고 Pumgye가 존 조건·상한에 쓰려고 가져가는 스냅샷에서 주소에 붙는
라벨이며, 수문장의 접근 판정을 바꾸지 않는다.

## 모델과 한도

`{"id", "display_name"?, "description"?, "owner"?, "prefixes": [CIDR, …]}`

- `id`: `[A-Za-z0-9_.:-]{1,128}`(Pumgye 존 이름. 예: `corp`, 변환기의
  `legacy.<service>.<n>` 제안).
- `display_name` 128, `owner`(팀/연락처) 128, `description` 512바이트 이하, 제어
  문자 없음.
- `prefixes`: 1개 이상. 정규화(호스트 비트 제거, IPv4 매핑 IPv6 → IPv4)·정렬하며
  존 안 중복은 거부한다. 한 접두어가 여러 존에 속할 수 있다.
- 전체 **존 64개, 접두어 65,536개** 이하(Pumgye 계약 한도). 따라서 모든 스냅샷을
  가져갈 수 있다.
- `updated_at`/`updated_by`는 서버가 기록한다(본문 값 무시).
- ASN·국가 구성원은 Pumgye 계약에 없어서 지원하지 않는다. ASN/국가 조건은 JSON/Lua
  룰을 쓴다.

존 집합에는 단조 증가 `revision`(계약의 `revision`)이 있고 존과 함께 체크포인트에
저장되며 성공한 변경마다 1 증가한다.

## 관리 API(관리자 자격)

| 엔드포인트 | 용도 |
| --- | --- |
| `GET /v1/zones` | `{schema, revision, limits, zones: [Zone…]}` |
| `POST /v1/zones` | `{"expected_revision": N, "zone": {…}, "reason"?}` 생성·교체, `{"expected_revision": N, "remove": "<id>", "reason"?}` 삭제(브로커 클라이언트용) |
| `DELETE /v1/zones` | `{"expected_revision": N, "id", "reason"?}` 삭제 |
| `GET /v1/zones/snapshot` | Pumgye 계약 스냅샷(아래) |
| `POST /v1/zones/lookup` | `{"ip"}` → `{ip, revision, zones: [ids]}` |

쓰기는 존 리비전과 비교한다. 오래된 `expected_revision`은 변경 없이
`current_revision`과 함께 409. 잘못된 존은 JSON Pointer 경로(`/zone/id`,
`/zone/prefixes/3`)와 함께 400. 쓰기는 `zones.upsert`/`zones.remove`로 차이 요약·
해시·사유와 함께 체크포인트 트랜잭션에서 감사된다(실패 시 차단). Kubernetes 독점
소유 상태에서는 존 쓰기를 거부(409)하며 조회는 가능하다.

## Pumgye 스냅샷 계약

`GET /v1/zones/snapshot`은 Pumgye `docs/MODEL_V2.md`("Sumunjang zone contract")가 정한
본문을 그대로 반환한다.

```json
{"revision": 7, "zones": {"corp": {"prefixes": ["10.0.0.0/8"]},
                          "office": {"prefixes": ["192.0.2.0/24"]}}}
```

이름과 접두어는 이미 계약(이름 패턴, 정규 접두어, 존 64개·접두어 65,536개 이하)을
만족한다. `x-sumunjang-zone-revision`, `x-sumunjang-zone-digest`(본문 `sha256:`)
헤더로 게시 내용을 확인할 수 있다. Pumgye는 이를 자체 CAS 게시로
`"zones": {"source": "sumunjang", "revision": N, …}`에 가져간다. 스냅샷은 버전이
있지만 **서명되지 않는다**. Pumgye의 서명 조회는 ADR 0021 P1(PPG2/HGD)이며 그전에는
관리 채널로 전달한다.

## 근거와 explain

- 존 소속은 판정 뷰와 함께 게시되는 64비트 존 마스크 radix 트리 하나로 컴파일된다.
  조회는 경로 하나만 따라가며 할당이 없다(`crates/guard-core/tests/no_alloc.rs`).
  판정 함수 밖에서 실행되므로 근거를 요청하지 않는 판정은 비용이 없다.
- `POST /v1/explain`은 참고용 `zone` 단계(`mode` 다음 두 번째)를 추가한다: 존 ID,
  `zone_revision`, 코드 `sumunjang.stage.zone.match`/`.none`. batch 결과에도 `zones`가
  있다.
- HTTP `/v1/decision` 근거에 `zones`(최대 8개, ID 순), `zones_truncated`,
  `zone_revision`이 추가된다. gRPC `NetworkEvidence`에 `zone_ids`(10),
  `zone_ids_truncated`(11), `zone_revision`(12)이 추가되며 응답이 1KiB 인코딩 한계를
  넘지 않도록 존 ID를 줄인다. HGD1은 바뀌지 않는다.

## Kubernetes

네이티브 `SumunjangPolicy` 원천은 존을 담지 않고 ADR 0022 `NetworkZone`/
`NetworkControl` 구조 CRD도 구현하지 않았다. 새 informer 원천, 네이티브/관리 존 혼재
소유 규칙, 이전 도구가 필요해 간단한 변경이 아니다. Kubernetes 소유 모드에서 존은
읽기 전용(체크포인트 내용)이다.

## 콘솔

패키지 0.1.7은 `zones`(GET)와 `zones`(POST, 변경)를 선언한다. 스냅샷과 조회는 브로커
경로가 아니다(브로커 한도 32개를 모두 사용). 콘솔은 존 소속을 explain과 근거에서
얻는다.
