# hangang-guard 설계와 작업 절차

[English](../DESIGN.md) · [문서 목록](README.md)

상태: 2026-10-12 승인된 구현 기준. 이름은 hangang-guard이며 기존 작업 공간
보호를 위해 디렉터리 hangang-safe를 유지합니다.

## 목적과 경계

Rust IP/네트워크 정책 및 위험 판단 서비스로 제로트러스트 백본의 구성 요소입니다.
인증된 Hangang 신호를 받아 제한된 IP별 증거와 차단 후보(BCL)를 관리하고 요청별
원격 판단 및 선택적 만료 snapshot을 제공합니다. Hangang은 기본적으로 모든 요청에서
guard를 비동기 질의합니다. 판단은 메모리에서 수행하며 DB/ASN 제공자/LLM을 호출하지
않습니다. 짧은 캐시와 snapshot 집행은 명시적 선택입니다. Hopae는 사용자/주체를
관리하며 guard는 계정/세션 관리를 중복 구현하지 않습니다. Guard 허용은 사용자나
장치를 인증하지 않습니다. 기존 Hangang 인증·허용/차단·방어 기능은 독립적으로
유지합니다. Guard 허용 목록은 guard 차단만 면제합니다.

## 절차

1. Hangang 입장 판단, 신뢰 프록시 IP 판별, 이벤트, 인증 구조를 조사합니다.
2. 구현 전 구조·위협 모델·API·자원 한계를 문서화합니다.
3. 코어와 서비스를 독립 단위로 서브 에이전트에 맡기며 Hangang은 별도 worktree로 기존 변경을 보호합니다.
4. 계약과 실패 동작을 검토하고 단위/실제 HTTP 통합 검증을 수행합니다.
5. 로컬 proxy+guard+origin을 observe/enforce에서 검증합니다.
6. Guard 저장소와 Hangang 기능 브랜치를 커밋/푸시합니다. 실제 배포와 설정을 확인한 경우에만 운영 관찰을 수행하며 별도 배포 재시작이나 live blocking을 임의로 활성화하지 않습니다.
7. 구현 범위와 남은 작업을 기록하고 완료 시 운영자에게 알립니다.

## 위협 모델과 정책

- Collector bearer 인증만 증거 제출/snapshot 조회를 허용합니다. 관리자 변경은 별도 토큰입니다. 기본 loopback이며 원격에는 TLS reverse proxy 또는 보호된 사설 전송이 필요합니다.
- Hangang 신뢰 프록시 경계에서 IP를 판별하며 임의 XFF는 신뢰하지 않습니다.
- Body/cookie/인증 정보/전체 URL/query string은 프로토콜로 전달하지 않습니다. 신호는 honeypot/scanner/auth_failure/invalid_request이며 guard가 차단한 요청은 새 증거를 생성하지 않습니다.
- 기본 observe. 후보 생성과 자동 차단은 별개이며 enforce에서 명시적으로 켠 정확한 IP 차단만 자동화합니다. 일반 403은 증거가 아니며 허니팟 경로는 명시적으로 설정합니다.
- 허용 목록은 더 넓은 CIDR 차단보다 우선하되 인증은 우회하지 않습니다. Canonical CIDR 및 IPv4-mapped IPv6 정규화, 매 조회 만료 확인을 적용합니다.
- ASN은 분류 정보이며 악성 증거가 아닙니다. 운영자 제공 오프라인 prefix catalog를 지원하고 ASN 전체 차단은 명시적 수동 승인이 필요합니다. LLM은 허용 목록 변경/범위 확대 권한이 없습니다.
- 정책은 검증된 bounded 전체 view를 원자 교체합니다. Snapshot poll 실패 시 valid_until까지 마지막 정상 정책을 유지한 뒤 fail-open합니다. Query 기본 timeout은 100ms, fail-deny 503이며 명시적 fail-allow를 선택할 수 있습니다. 기존 방어는 유지합니다. 재시작하면 revision이 초기화될 수 있어 generated_at/유효 기간으로 신선도를 판단합니다.
- 입력/이벤트/후보/차단/룰/prefix/body는 제한합니다. Overflow는 카운터에 표시하고 이벤트 전송 때문에 proxy를 대기시키지 않습니다. 영속 저장에는 정책과 압축 집계만 저장합니다.
- Checkpoint는 SQLite transaction입니다. 관리자 성공은 영속 정책 저장 이후이며 crash 시 집계는 최대 checkpoint 간격만큼 유실될 수 있습니다. 정책 변경 감사 행은 같은 transaction에서 반영되므로 감사 기록 없이 변경이 영속되지 않습니다(AUDIT_EXPLAIN.md).

## 자원·성능 목표

기본 tracked IP 10,000; block 100,000; event batch 256; HTTP body/snapshot 4MiB;
네이티브 event queue 4,096; snapshot refresh 2초/validity 30초; 후보 window 60초;
block lifetime 15분입니다. Drop/capacity 카운터를 제공합니다. 초기 prefix index는
IPv4/IPv6 bounded hash probe였고 현재는 압축 radix tree입니다. 이 수치는 예산이며
실측 성능 보장이 아닙니다. 원격 query가 기본이며 부하 검증이 필요합니다.
캐시는 기본 꺼짐이고 활성 시 1~5초, 제한된 IP 용량, configured TTL과 server ttl_ms
중 작은 값입니다(서버 최대 5초). Revision 변경 관측 시 캐시를 비우며 정책 변경은
TTL 동안 지연될 수 있습니다. 증거 요청은 캐시를 사용하지 않습니다. 원시 로그는
보관하지 않으며 SQLite checkpoint는 기본 5초입니다.

## HTTP 프로토콜 v1

JSON, UTC Unix 초, canonical CIDR을 사용합니다. 알 수 없는 kind/잘못된 network는
거부하고 `Authorization: Bearer` 인증을 사용합니다.

Collector API:

- `POST /v1/decision`: 입력 `{source_id, ip, kind?}`; 출력 `{version:1, revision, action:allow|deny, mode, reason, ttl_ms}`. 선택적 신호 집계 전에 현재 정책을 검사하여 이미 차단된 요청이 증거/TTL을 갱신하지 못합니다. 새 차단은 응답에 반영하며 observe는 허용합니다. URL/인증 정보는 없습니다.
- `POST /v1/events`: 입력 `{source_id, events:[{ip, kind, observed_at}]}`; 출력 `{accepted:N}`. Kind는 위 네 가지입니다. Timestamp는 수신 시각과 가까워야 하며 window는 수신 시각으로 계산합니다. Batch 256, source ID 64바이트 이하입니다.
- `GET /v1/snapshot`: 아래 Snapshot 반환.

Snapshot: `{version:1, revision, generated_at, valid_until, mode:observe|enforce,
allow:[CIDR], blocks:[{network, expires_at, reason}]}`. 유효 기간 최대 300초,
reason 128바이트 이하. 클라이언트는 canonical 중복 block을 거부하며 만료 block은
집행하지 않습니다.

Admin API:

- `GET /v1/status`: 비밀 없는 health/capacity/counter.
- `GET /v1/candidates`: ASN과 eligible을 포함한 제한된 IP 집계; 임계값 이상만 승인 가능한 BCL 후보입니다.
- `GET/PUT /v1/policy`: 정책 조회/변경.
- `GET /v1/blocks`: 활성 block 목록; `POST /v1/blocks`: block 추가; `DELETE /v1/blocks`: `{network}` 삭제.
- `POST /v1/candidates/approve`: `{ip}`로 정확한 IP 차단 승인.
- `GET /v1/audit`, `POST /v1/audit/query`: 정책 변경 감사(필터, 커서).
- `POST /v1/explain`, `POST /v1/explain/batch`, `GET /v1/reasons`: 실시간 평가 경로의 explain/what-if와 사유 카탈로그. AUDIT_EXPLAIN.md 참고.
- `/`: 정적 대시보드; 토큰은 브라우저 메모리만 사용하고 local storage/내장 토큰/외부 스크립트/비정제 evidence HTML은 없습니다.

Policy: `{mode, auto_block, window_secs, threshold, block_ttl_secs, allow,
weights:{honeypot, scanner, auth_failure, invalid_request}}`. 기본 observe/false/
60/10/900/빈 allow/가중치 10·5·1·2입니다. 정수에 상한이 있고 0 가중치는 신호를
끕니다. 토큰은 환경 변수로 설정하고 JSON/CLI 인자로 저장하지 않습니다.

## 구성 요소

- guard-core: 계약·검증·제한된 weighted-window 후보·정확한 IP 승인·CIDR block·허용 우선순위·오프라인 ASN·snapshot·prefix index. 네트워크/DB 의존성이 없습니다.
- guard-server(hangang-guard): 인증된 bounded HTTP API·내장 대시보드·SQLite/checkpoint·graceful shutdown·설정.
- Hangang 네이티브 모듈: opt-in CLI, 비동기 snapshot poll/event batch, bounded try_send, prefix index+ArcSwap, 판별된 IP admission, 명시적 honeypot/scanner 경로. 기본 요청별 query와 선택적 bounded 1~5초 캐시, 별도 snapshot 모드. 비활성 시 백그라운드 통신이 없습니다.

## 조사와 후속 확장

CrowdSec의 탐지/판단과 remediation 분리 및 bouncer stream/cache 방식을 참고합니다:
[개념](https://docs.crowdsec.net/docs/concepts/),
[bouncer](https://docs.crowdsec.net/docs/local_api/bouncers/).
분리를 채택하되 호환 프로토콜을 구현하기 전 호환성을 주장하지 않습니다.
후속: 인증/서명 feed와 provenance/rollback, ASN/GeoIP background last-good 갱신,
검토된 ASN 제안/영향 분석, fleet identity/audit/distributed sync/retention.
초기에는 GeoIP를 Hangang에 남기는 계획이었고 아래 확장으로 guard도 지원합니다.
외부 feed/LLM은 선택적 확장이며 로컬 방어의 전제 조건이 아닙니다.

## 검증 기준

Core: 가중치/window/허용 우선순위/mapped IPv6/만료/capacity/복구/prefix/invalid policy.
Service: 토큰 분리/body·batch 상한/영속성·변경/observe·enforce/safe HTML/API error.
Hangang: trusted IP/cache·snapshot 만료/잘못된 snapshot 유지/bounded export/자기 증거 갱신 방지.
E2E: 캐시 없는 요청별 query, honeypot→후보→승인→403, 장애→503 또는 fail-allow,
allowlist→origin 통과, snapshot 장애→만료→origin 통과.

## 프롬프트 기반 LLM 검사

운영자 프롬프트로 요청 패턴을 분석하는 기능을 검토합니다. 요청별 동기 판단과
집계 비동기 분석, 지연/비용/1~5초 캐시, 최소 마스킹 입력, 구조화 출력 검증,
비신뢰 요청/prompt injection 격리, provider/prompt 버전, timeout·장애,
deterministic gate/shadow/운영자 검토를 설계합니다. 구현 의존성이 아닌 backlog이며
상세 체크리스트는 [TODO.ko.md](../../TODO.ko.md)에 있습니다.

## 성능 확장: IP pool·관리 화면·프로토콜

10,000~100,000 판단/초를 설계·검증하고 필요 시 프로토콜도 최적화합니다. 초기 Python
샘플만으로는 부족합니다. IPv4/IPv6 allow/block/ASN 압축 radix index와 불변 view를
사용하여 일반 판단에서 engine mutex/SQLite/spawn_blocking/IP 문자열 parse/generic
JSON allocation을 제거합니다. 증거 집계와 영속 관리는 별도 직렬 경로입니다.

고정 프레임, 인증된 영구 연결, 제한된 연결/idle을 가진 선택적 loopback binary
리스너를 추가합니다. HTTP는 관리/증거/보안 원격 전송용입니다. 네이티브 전송 선택이
증거와 실패 의미를 바꾸지 않아야 합니다.

Release와 Rust 다중 연결 부하 생성기, concurrency/pipeline, empty/enforce 및 대규모
IPv4/IPv6 pool, hit/miss, latency/error/CPU/RSS/지속 부하를 검증합니다. Index microbench,
서비스 transport, 전체 proxy 성능을 구분하고 생산 SLA로 확대 해석하지 않습니다.
관리 UI는 policy/allow/block/candidate 분리, 검색/정렬/page/만료/error를 지원하며
수천 항목 때문에 수천 DOM을 만들거나 미저장 입력을 지우지 않아야 합니다.

## 현재 GeoIP/룰 확장

초기 GeoIP 보류 계획은 운영자 제공 오프라인 MMDB 지원으로 변경되었습니다.
Country/City/ASN, IP/CIDR score·stage, JSON/Lua compile, dry-run, durable atomic publish를
구현했습니다. 정확한 우선순위/제한은 [RULES.md](RULES.md), 공식 비교는
[TOOL_RESEARCH.md](TOOL_RESEARCH.md)를 참조하세요. 스크립트는 관리 시만 실행합니다.
정책 기본 observe, 요청별 query 기본을 유지하고 로컬 불변 GeoIP reader를 사용합니다.
Snapshot v1은 비어 있지 않은 동적 룰을 거부하여 불완전 정책 배포를 방지합니다.
