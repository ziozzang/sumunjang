# ASN 접두어 번들과 ASN 차단 제안

[English](../ASN_PROPOSALS.md) · [문서 목록](README.md)

원래 요구사항 4–6단계: ASN의 접두어 풀을 가져오고, 차단 영향을 분석하고, 검토된 차단
범위를 결정한다. ASN은 분류 메타데이터이며 악성의 증거가 아니다. **ASN 전체 차단은
절대 자동으로 활성화되지 않는다.**

## 서명된 ASN 접두어 번들

페이로드 `sumunjang.asn-bundle.v1`: `format`, `version`(단조 증가), `created_at`,
`source`, `provenance`, `prefixes`(`{network, asn}`).

- 오프라인 도구 `guard-release-sign --asn-bundle payload.json seed.key bundle.json`이
  도메인 분리 엔벨로프(`"<domain>\0" || payload`, 도메인 `sumunjang.asn-bundle.v1`)에
  Ed25519로 서명한다. 릴리즈 키와 다른 전용 번들 키를 쓰며 수문장은
  `HANGANG_GUARD_ASN_BUNDLE_KEY`(base64 공개키)를 신뢰한다. 릴리즈 매니페스트 서명은
  번들로 검증될 수 없다.
- 한도: 엔벨로프 32MiB, 접두어 100,000개(엔진 카탈로그 한도), source 256바이트,
  provenance 16개.
- 설치 경로: 오프라인 `sumunjang --import-asn-bundle FILE --database …`(리스너 없음,
  서비스가 한 번 체크포인트한 뒤), `PUT /v1/asn/bundle`(본문은 엔벨로프. 콘솔 브로커
  본문 한도가 1MiB라 큰 번들은 CLI나 URL 사용), 선택적 주기 조회 `--asn-bundle-url
  https://…`(HTTPS만, 리다이렉트 없음, 30초 제한, `--asn-bundle-ca`,
  `--asn-bundle-interval-seconds` 300–86,400, 기본 3,600. 기본 URL 없음)과
  `POST /v1/asn/refresh`.
- 버전은 단조 증가한다. 같은 버전·같은 해시는 변경 없음, 더 오래된 버전은 거부(롤백
  사용), 롤백된 버전은 더 새 버전이 게시될 때까지 거부한다.
- 설치마다 차이 보고서(전후 접두어 수, 추가·삭제·재할당, 표본, 가장 많이 바뀐 ASN)를
  반환하고 `asn.bundle.install`로 감사한다. 번들 행·체크포인트·감사 행은 한
  트랜잭션이며 실패하면 마지막 정상 카탈로그를 유지한다.
- `POST /v1/asn/bundle/rollback {"expected_version", "reason"}`은 마지막 정상 이전
  번들(2개 보관)을 다시 설치하고 현재 버전을 `rolled_back`으로 표시한다
  (`asn.bundle.rollback`).
- `GET /v1/asn/bundle`: 현재 번들(버전·출처·provenance·sha256·접두어 수), 이력, 키·조회
  상태(시도·실패·마지막 오류).
- 설치된 번들은 시작 시 다시 적재되며 서명 없는 기존 `--asn-catalog`보다 우선한다.
  네이티브 Kubernetes 소유 모드는 번들 쓰기를 거부한다.

## ASN 차단 제안

`POST /v1/asn/proposals`: `{"asn", "scope": {"kind": "asn"|"prefixes"|"aggregates",
"prefixes": [...]}, "reason", "expires_at"}`

- `asn`: ASN의 모든 카탈로그 접두어. `prefixes`: ASN 카탈로그 접두어 안의 지정
  네트워크. `aggregates`: 추적 중인 근거 주소가 있는 ASN 안의 IPv4 /24·IPv6 /48
  (더 좁은 카탈로그 접두어로 자름)과 지정한 /24·/48. 중첩 제거 후 최대 4,096개. 오류는
  위치를 표시한다(`/asn`, `/scope/prefixes/3`, `/reason`, `/expires_at`). 사유 필수,
  만료는 30일 이내.
- `POST /v1/asn/preview`는 저장 없이 같은 영향 분석을 반환한다.

**영향 분석**(제안에 저장, `analyze`로 갱신): 네트워크 목록, 추정 IPv4 주소 수와 IPv6
/64 수, 범위 안 추적 근거 주소와 신호별 합계·상위 주소, 메모리 이력(주소·점수·이벤트),
제안 차단을 더한 게시되지 않는 뷰의 판정 미리보기(현재 모드: 허용→거부, 이미 거부,
변화 없음 / 집행 모드)와 표본 — 관찰 배포에서도 집행 결과를 볼 수 있다 — 허용 목록
(허용 주소는 계속 허용)·네트워크 존·기존 차단과의 충돌, 경고(관찰 모드, 허용 목록/존
겹침, 매우 큰 네트워크). 한강 판정 로그 집계 수는 `annotate`로 붙인다(`decision_log`:
정수 카운트 최대 16개, 가명화된 원천, 개수만).

**수명주기** — `POST /v1/asn/proposals/{id}` `{"action", "expected_revision",
"reason"?, "decision_log"?}`:

| 동작 | 상태 변화 | 비고 |
| --- | --- | --- |
| `submit` | draft → pending | 네트워크 목록을 다시 계산해 **고정** |
| `analyze` | draft, pending, approved | 영향 갱신(제출 후 네트워크는 고정) |
| `annotate` | 열린 상태 | 판정 로그 집계 첨부 |
| `approve` | pending → approved | 제안자가 아닌 서로 다른 승인자, `--asn-proposal-approvals`(1–3, 기본 1) |
| `reject` | pending/approved → rejected | 사유 필수 |
| `activate` | approved → active | 명시적 동작만. 검토된 네트워크만 source `asn_proposal`로 차단, 만료는 `min(expires_at, 지금+7일)`. 더 길게 차단된 네트워크는 건너뜀 |
| `withdraw` | 열린 상태 → withdrawn | 이 제안의 차단만 제거 |
| (시스템) | → expired | `expires_at` 도래 또는 활성 차단 만료 시 |

제안마다 리비전이 있고 오래된 `expected_revision`은 `current_revision`과 함께 409.
모든 전이는 제안 행(활성화·철회는 체크포인트도)과 같은 트랜잭션에서
`asn.proposal.*`로 감사된다. 2인 규칙은 검증된 행위자를 비교하므로 공유 관리자 자격으로는
제안자와 승인자가 같은 신원이 된다. 위임된 콘솔 행위자를 써야 한다. 제안 차단의 사유
코드는 `sumunjang.deny.block_asn`이며 허용 목록이 여전히 우선한다. 열린 제안은 최대
1,000개이고 오래된 종료 제안은 정리한다. `GET /v1/asn/proposals`는 요약 목록, `GET
/v1/asn/proposals/{id}`는 영향과 이력을 포함한 제안을 반환한다.

## 콘솔 경로(패키지 0.2.0, 브로커 계약 v2)

일반: `asn/bundle` GET, `asn/bundle` PUT(변경), `asn/bundle/rollback` POST(변경),
`asn/refresh` POST(변경), `asn/preview` POST, `asn/proposals` GET, `asn/proposals`
POST(변경). 패턴: `asn/proposals/*` GET, `asn/proposals/*` POST(변경). 패키지는 이제
`api_version: 2`(경로 40개 + 패턴 2개)이며 브로커 경로 패턴을 지원하는 한강 콘솔이
필요하다.
