# 정책 변경 감사, 설명(explain)과 판정 근거

[English](../AUDIT_EXPLAIN.md) · [문서 목록](README.md)

통합 콘솔(제로트러스트 ADR 0020)과 판정 이벤트(ADR 0019)에 필요한 소유자 API다.
정책 변경의 지속 감사, 실제 판정 경로를 그대로 쓰는 explain/what-if API,
gRPC·HTTP 판정에 추가되는 근거(evidence)를 제공한다. 별도 표시가 없으면 모두
**관리자** Bearer 자격이 필요하다. HGD1 프레임은 바뀌지 않는다.

## 정책 변경 감사

모든 관리 변경은 감사 행 하나를 남긴다.

| 동작 | 엔드포인트/원천 |
| --- | --- |
| `policy.replace` | `PUT /v1/policy` (기존) |
| `policy.document.replace` | `PUT /v1/policy/document` (선택 `reason`, 256바이트 이하) |
| `blocks.add`, `blocks.remove` | `POST`/`DELETE /v1/blocks` |
| `candidates.approve` | `POST /v1/candidates/approve` |
| `rules.replace`, `rules.lua.replace` | `PUT /v1/rules`, `PUT /v1/rules/lua` (Lua 컴파일 실패는 거부로 기록) |
| `geoip.reload` | `POST /v1/geoip/reload` |
| `update.check` | `POST /v1/update/check` |
| `allowlist.add`, `allowlist.remove` | `POST`/`DELETE /v1/allowlist` |
| `allowlist.expire` | 오래 만료된 허용 항목 자동 삭제(행위자 `system`) |
| `zones.upsert`, `zones.remove` | `POST`/`DELETE /v1/zones` |
| `kubernetes.authority.publish` | 내용이 바뀐 네이티브 `--kubernetes-authority` 게시 |
| `startup.import` | 시작 시 `--policy`, `--bootstrap-policy`, `--asn-catalog`가 저장 상태를 바꾼 경우 |

행 필드: 불투명 `id`, `time`/`time_ms`, `actor`(`kind`, `id`, `name`, `issuer`,
`client_ip`, `request_sha256`), `action`, `target`(policy, rules, 네트워크, IP,
`resourceVersion=…`), `result`(`committed`, `refused`, `uncertain`),
`revision_before`/`revision_after`(판정 응답의 `revision`과 같은 판정 리비전),
`policy_revision`(정책 문서 리비전), `before_digest`/`after_digest`(대상 정책·룰·
차단 목록·GeoIP 메타데이터·전체 게시 상태의 `sha256:`), 길이가 제한된 사람이 읽는
`summary`(예: `mode observe -> enforce; allow +1: 192.0.2.0/24`), `reason`, `error`.
자격 증명·Lua 원문·요청 본문은 저장하지 않는다. 변경 응답의
`x-sumunjang-audit-id` 헤더에 행 ID가 담긴다.

**실패 시 차단(fail closed).** 반영 행은 정책 체크포인트와 같은 SQLite 트랜잭션에
기록한다. 감사 기록이 실패하면 트랜잭션이 롤백되어 500을 반환하고 게시 정책·판정
뷰·체크포인트는 그대로다. GeoIP 재적재는 메모리 카탈로그 교체 전에 행을 기록하며
실패 시 503과 기존 카탈로그를 유지한다. `update.check`는 SQLite 밖 파일을 만들기
때문에 먼저 `uncertain`을 기록하고 결과에 따라 `committed`/`refused`로 확정한다.
그 사이에 프로세스가 죽으면 `uncertain`이 남으며 이는 사실 그대로다. `COMMIT` 실패는
같은 ID의 `uncertain` 행으로 기록한다(원래 행이 실제로 반영됐다면 중복으로 실패).
거부(검증 오류, 오래된 리비전, Lua 오류, Kubernetes 독점 소유자, 업데이트 비활성)는
별도 트랜잭션으로 최선 노력 기록한다. 아무것도 바뀌지 않았으므로 그 기록 실패가
거부 결과를 바꾸지 않는다. 디코딩 전 거부(인증 실패, 잘못된 JSON)와 이벤트 기반
자동 차단은 정책 변경 감사 대상이 아니며 후보 목록과 한강 호스트 저널이 담당한다.
내용 변화 없는 Kubernetes 재게시(500ms 주기)는 기록하지 않는다.

**보존.** `--audit-max-rows`(기본 100,000, 1,000–10,000,000)와
`--audit-retention-days`(기본 365, 1–3,650). 기록 시와 5초 체크포인트마다 둘 중 먼저
넘는 한도의 가장 오래된 행을 지우고, 조회도 기간을 넘은 행을 제외한다. 행 순번은
재사용하지 않으므로 오래된 행이 지워져도 커서가 안정적이다.

**행위자.** 기본 행위자는 공유 관리자 자격(`kind: credential`)이다. 한강 콘솔
바인딩에 `"delegate_actor": true`(및 `"delegation_authority": "hangang"`)를 두고
Guard 관리자 자격(32바이트 이상)을 `token_env`로 지정하면 브로커가 모든 호출에
`x-hopae-delegation`, `x-hopae-delegation-mac`(해당 자격을 키로 한 HMAC-SHA-256)을
서명한다. 수문장은 서명·메서드·경로·본문 SHA-256·±10초 신선도·1회용 nonce를 검증하고
`kind: delegated`, 콘솔 계정 ID/이름, `issuer: hangang`, 관리자 클라이언트 IP를
기록한다. 잘못되었거나 만료·재사용·불일치한 단언은 401이며 자격 행위자로 낮춰
처리하지 않는다. `request_sha256`은 호스트 플러그인 저널의 본문 해시와 같아 상호
연결에 쓴다.

### 조회

`GET /v1/audit?since=&until=&actor=&action=&result=&target=&limit=&cursor=` 또는
같은 필드를 JSON으로 받는 `POST /v1/audit/query`(콘솔 브로커는 쿼리 문자열을
전달하지 않는다). `since`(포함)·`until`(제외)은 Unix 초, `action`은 정확히 일치하거나
`.*`로 끝나는 접두어(`blocks.*`), `limit`은 1–200(기본 50). 최신순이며 응답의
`next_cursor`를 다음 요청의 `cursor`로 넘긴다. `null`이면 끝이다. 잘못된 필터는 400,
저장소 장애는 빈 페이지가 아니라 503이다.

## Explain과 what-if

`POST /v1/explain` 본문: `ip`, 선택 `candidate`(`policy`, `rules` 또는 Lua
`script`), 선택 모의 근거 `evidence`(`honeypot`, `scanner`, `auth_failure`,
`invalid_request`, `include_observed`), 선택 모의 `geo`(`country`, `asn`), 선택 모의
시각 `at`(±30일).

판정은 모든 실시간 전송이 쓰는 `DecisionView::evaluate`로 계산한다
(`query_ip_context`는 크기 0인 `NoTrace` 싱크를 쓴 같은 함수다). explain은 제한된
`VecTrace`를 넘기며 GeoIP 메타데이터 전달 규칙도 실시간과 같다(평가 룰이 필요로 할
때만). `candidate`가 있으면 후보 모드/허용 목록·룰과 게시된 차단·ASN 카탈로그로
게시되지 않는 뷰를 만든다. 후보는 게시와 똑같이 검증하며(`Policy::validate`,
스냅샷 예산, `RuleSet::validate`, `script`의 Lua 샌드박스) 저장·게시·변경 감사하지
않는다.

응답(`schema: sumunjang.explain.v1`)은 `/v1/decision`과 같은 형태의 `decision`,
`verdict`(`allow`, `deny`, `observe`), `reason_code`, `params`, `matched_rules`,
순서가 있는 `stages`, `trace_truncated`를 담는다.

| 단계 | 내용 |
| --- | --- |
| `mode` | `observe`면 평가 종료(Guard 허용), `enforce`면 계속 |
| `allowlist` | 일치 여부와 일치한 접두어, 일치하면 종료 |
| `geo` | 룰이 쓴 국가·ASN·ASN 출처(`geoip`, `catalog`), `simulated` |
| `rules` | 구성 수, 일치한 활성 룰 전체(id, 동작, 우선순위, 점수, 승자), 일치했지만 만료된 룰, 승자 |
| `blocklist` | 가장 구체적인 활성 차단(네트워크, 사유, 만료, 남은 시간)과 포함하는 만료 차단 |
| `outcome` | 결정 단계와 최종 사유 코드 |
| `score` | 참고용: 관측+모의 신호 점수, 정적 룰 점수, 임계값, 위험 단계 |
| `auto_block` | 참고용: 자동 차단이 차단을 추가하는지와 예상 거부 |

도달하지 않은 단계는 생략한다. 관찰 모드에서는 `enforce_preview`에 같은 평가의
집행 결과를 담는다. `evaluated`는 `source`(`published`/`candidate`), `revision`,
`policy_revision`, `candidate_digest`, `rules_source`(`json`, `lua`, `published`),
`source_available`, `stored: false`를, `simulated`는 시각·GeoIP·근거 모의 여부를
표시한다.

잘못된 입력은 JSON Pointer 경로와 함께 400을 반환한다. 예:
`{"error":"invalid explain request","errors":[{"path":"/candidate/rules/rules/0/network","message":"…"}]}`.
serde 형식·미지정 필드 오류, 모든 정책/룰 진단, Lua 실패(`/candidate/script`)가 이렇게
위치를 표시한다.

`POST /v1/explain/batch`(`{"ips":[…최대 1024], "candidate":{…}, "at":…}`)는 주소별
`published`(및 `candidate`) 동작·판정·사유 코드·룰·차단, `changed`, 그리고
`summary`(`total`, `changed`, `allow_to_deny`, `deny_to_allow`, `reason_changed`)를
반환한다. 후보가 없으면 게시 판정만 반환한다.

explain과 batch는 읽기 요청이다. 제한된 작업자 풀을 쓰고 관리자 전용이며 정책 변경
감사에는 기록하지 않는다(모의 실행 감사는 한강 호스트·콘솔 담당, ADR 0019).

## 사유 코드와 메시지

`GET /v1/reasons`는 등록 코드(판정, 단계, 감사)와 영어/한국어 카탈로그
(`crates/guard-core/messages/{en,ko}.json`)를 반환한다. 메시지 키는 코드와 같고
`{name}` 자리표시자는 `params`로 채운다. 판정 코드: `sumunjang.observe.mode`,
`sumunjang.allow.allowlist`, `sumunjang.allow.rule`, `sumunjang.allow.default`,
`sumunjang.deny.rule`, `sumunjang.deny.block_manual`, `sumunjang.deny.block_approved`,
`sumunjang.deny.block_automatic`, `sumunjang.deny.block_source`, `sumunjang.unavailable.revision_floor`,
`sumunjang.unavailable.owner_replaced`, `sumunjang.unavailable.source`. 테스트가 두
언어의 키 집합과 자리표시자가 같은지 확인하며, 코드를 추가하려면 두 메시지가 모두
필요하다.

## 판정 근거(gRPC·HTTP)

gRPC는 `NetworkRequest.include_evidence = true`(필드 4)로 `NetworkReply.evidence`
(필드 6)를 받는다([gRPC](GRPC.md) 참고). HTTP는 `POST /v1/decision`(collector 자격)
본문에 `"evidence": true`를 넣으면 `evidence` 객체가 추가된다. 플래그가 없으면
응답은 이전과 같다. 이전 서버는 알 수 없는 필드를 거부하므로 서버 업그레이드 후에
켜야 한다. 룰 ID(최대 8개, 승자 먼저)는 일치한 활성 룰이고, `enforce`는 같은 게시
뷰를 집행했을 때의 결과로 관찰 중인 정책에 유용하다. ASN/국가는 룰 메타데이터 또는
GeoIP/오프라인 카탈로그 조회 결과다. `block`은 네트워크 주소이므로 이벤트를 내보내는
쪽은 다른 주소처럼 가명화해야 한다(ADR 0019).

## 실시간 경로

평가 함수는 `Tracer`에 대해 제네릭이다. 운영 경로는 `NoTrace`(크기 0,
`#[inline(always)]` 빈 메서드)로 인스턴스화하므로 HGD1·HTTP·gRPC 판정에 추적 코드나
할당이 없다. `crates/guard-core/tests/no_alloc.rs`는 할당 계수 전역 할당자를 설치해
관찰/집행, 허용 목록, 룰, 만료 룰, 관찰 룰, 차단, 만료 차단, 자동 차단, IPv4/IPv6/매핑
주소와 기본 경로에서 `NoTrace`와 고정 크기 `Evidence` 싱크의 할당이 0임을 확인하고
추적/비추적 동등성을 검사한다. 서버 테스트는 두 모드 각각 293개 주소에서
`/v1/explain`과 `/v1/decision`을 비교한다.
