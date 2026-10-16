# 콘솔 네트워크 API

[English](../CONSOLE_NETWORK_API.md) · [문서 목록](README.md)

재구성된 콘솔 네트워크 화면이 쓰는 추가형·하위 호환 소유자 API다. 모두 **관리자**
Bearer 자격이 필요하고 쓰기는 감사된다([감사·explain](AUDIT_EXPLAIN.md)). 콘솔
패키지 0.1.6이 마지막에 나열한 브로커 경로를 선언한다.

## 주소별 신호 이력

`GET /v1/history?ip=&since=&until=` 또는 `POST /v1/history/query`
`{"ip", "since"?, "until"?}`(Unix 초, 기본은 보존 구간 전체). 수용된 근거 이벤트를
주소별 분 단위 버킷으로 합산한다. 버킷에는 그 분에 더해진 가중 점수(수집 시점 가중치)와
신호별 횟수가 있다. 응답(`sumunjang.history.v1`): `buckets`(`start`, `score`,
`signals`), `totals`, 현재 근거 `window`(`signal_score`, `threshold`,
`window_secs`), `stats`(주소·버킷 수, 한도, 누락).

한도: 보존 `--history-hours`(기본 6, 1–48), 주소 최대 10,000개, 전체 분 버킷 최대
262,144개(최악 약 16MiB). 넘치면 `stats.dropped`에 세고 늘리지 않는다. 횟수만 보관하며
경로·출처·요청 로그는 없다. 이력은 메모리 관찰값이다. 정책 변경(근거 창 초기화) 후에도
유지되지만 재시작 시 사라진다. 허용 목록이거나 이미 거부된 주소의 이벤트는 기존처럼
세지 않는다.

## 후보

`GET /v1/candidates` 항목에 창 내 신호별 횟수 `signals`(`honeypot`, `scanner`,
`auth_failure`, `invalid_request`)와 GeoIP `country`(국가 DB가 없으면 `null`)가
추가된다. 변경 전 체크포인트에서 복원된 오래된 버킷의 신호별 횟수는 0이다.

## 차단 출처

`GET /v1/blocks`와 후보 승인 응답에 `source`(`manual`, `approved`, `auto`,
`kubernetes`, 출처 기록 전 차단은 `unknown`), `created_at`, `created_by`(검증된 위임
콘솔 행위자 이름, 없으면 `admin-credential`)가 추가된다. 출처는 수문장이 기록하며
`POST /v1/blocks`로 지정할 수 없고(`origin` 필드는 거부), 체크포인트에 저장되며
스냅샷·HGD1에는 포함되지 않는다. 사유 코드(`sumunjang.deny.block_*`)는 이제 출처로
정하고 `unknown`만 고정 사유 문자열로 대체 판단한다. Kubernetes 원천 차단은
`sumunjang.deny.block_source`다.

## 룰 CAS와 Lua 원문

`GET /v1/rules/document` → `{revision, rules, source: "json"|"lua", script}`.
`script`는 현재 룰이 Lua에서 적용된 경우 보관한 Lua 원문(32KiB 이하, 저장됨)이며
편집기가 다시 불러올 수 있다. JSON 쓰기는 원문을 지운다.

- `PUT /v1/rules`에 `{"expected_revision", "rules", "reason"?}`를 보내면 룰 리비전이
  일치할 때만 게시하고 새 문서를 반환한다. 불일치면 변경 없이 409
  `{"error", "current_revision"}`.
- `PUT /v1/rules/lua`는 선택 `expected_revision`, `reason`을 받는다. 리비전이 있으면
  문서를, 없으면 기존처럼 RuleSet을 반환한다.
- **사용 중단 예정:** 리비전 없는 bare RuleSet `PUT /v1/rules`와 Lua 쓰기는 기존
  클라이언트를 위해 무조건 쓰기로 남는다(갱신 유실 위험). 룰 리비전은 모든 룰 쓰기와
  재시작 시 바뀐다.

## 변경 사유

`DELETE /v1/blocks`, `POST /v1/candidates/approve`, 룰·Lua 쓰기, 허용 목록 쓰기,
정책 문서에 선택 `reason`(256바이트 이하, 제어 문자 없음)을 받는다.
`POST /v1/blocks`는 차단 자체의 `reason`을 기록한다. 사유는 감사 행에 저장된다.

## 오프라인 ASN 카탈로그

`GET /v1/asn/catalog?asn=&limit=&cursor=` 또는 `POST /v1/asn/catalog/query`.
오프라인 `--asn-catalog`(또는 Kubernetes 원천) 접두어를 ASN·네트워크 순으로 정렬해
ASN별로 묶어 반환한다: `entries: [{asn, prefixes: [...]}]`, `total_prefixes`,
`total_asns`, `next_cursor`. `limit`은 접두어 행 수(1–1,000, 기본 200)이고 커서는
안정적인 키다. MMDB ASN DB는 열거할 수 없어 포함하지 않는다. ASN 제안은 범위 밖이다.

## 허용 목록 항목

`GET /v1/allowlist` → `{revision, entries: [{network, expires_at, reason,
created_at, created_by, expired}]}`. `revision`은 정책 문서 리비전이다.

- `POST /v1/allowlist` `{"expected_revision", "network", "expires_at"?,
  "reason"?}`는 항목을 추가하거나 메타데이터를 갱신한다.
- `DELETE /v1/allowlist` `{"expected_revision", "network", "reason"?}`는 삭제한다.
- 오래된 리비전은 `current_revision`과 함께 409. 감사 동작은 `allowlist.add`,
  `allowlist.remove`.

메타데이터는 정책의 추가 필드 `allow_meta`(정규화 네트워크 키, 비면 생략)에 있어
정책 문서와 호환된다. `allow_meta`를 생략한 정책 쓰기는 남아 있는 항목의 메타데이터를
유지하므로, 이전 편집기가 임시 항목을 영구 항목으로 바꾸지 못한다. 만료된 항목은 다음
조회부터 일치하지 않고(판정 경로 할당 없음), 삭제 전까지 `expired: true`로 표시되며
스냅샷에서 빠진다. 스냅샷 클라이언트는 스냅샷 만료(30초 이하)까지 따를 수 있다. 다른
정책 쓰기처럼 허용 목록 쓰기도 근거 창을 초기화한다.

## 콘솔 패키지 0.1.6 경로

추가: `rules/document` GET, `history/query` POST, `asn/catalog/query` POST,
`allowlist` GET, `allowlist` POST(변경), `allowlist` DELETE(변경). 쿼리 문자열 GET은
직접 API 클라이언트용이며 브로커는 쿼리 문자열을 전달하지 않는다. 패키지는 브로커 한도
32개 중 31개 경로를 선언한다.
