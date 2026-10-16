# Hangang 콘솔 통합

[English](../CONSOLE.md) · [문서](README.md)

Guard는 검토된 콘솔 패키지로 Hangang 사이드바에 들어갑니다.
`python3 tools/build_console_plugin.py`로 plugins/guard를 생성하고 manifest SHA-256을
Hangang --admin-plugins에 고정합니다. 기존 관리자 권한을 쓰는 hangang-console 어댑터도
사용할 수 있으며 Guard에 별도 계정/비밀번호 DB를 만들지 않습니다.

후보·차단/허용 풀·정책·IP/CIDR 점수·GeoIP·JSON/Lua 룰·DB 재적재·지표·서명 업데이트
기능을 기존 화면에서 재사용합니다. 자체 토큰 입력은 제거하고 host가 등록된 API 호출을
인증합니다. Guard 관리자 키는 서버 broker 환경에만 있으며 collector·decision API는
관리 allowlist에서 제외합니다.

활성 관리자만 수락하고 전달 및 응답 공개 전 권한을 재확인합니다. 요청/응답을 제한하고
변경 의도·결과·작업자·본문 해시를 영속 감사로 기록합니다. viewer는 거부합니다.
계정/세션 회수는 Hangang, 네트워크 정책/상태는 Guard 소유입니다. 이미 수락된 백엔드
변경을 전역 원자적으로 회수하지는 않습니다.

패키지는 신뢰된 동일 출처 코드이며 sandbox가 아닙니다. 시작 시 파일 해시/권한을 검사하고
불변 사본을 사용합니다. 변경은 새 pin과 재시작으로 반영합니다. 브라우저 discovery에는
키나 백엔드 주소를 주지 않습니다. 파일/설정/감사를 보호하고 공개 평문 어댑터는 TLS와
접근 제어 뒤에 둡니다.

Hangang 테마·언어·탐색 수명주기를 따릅니다. 화면을 숨기면 polling을 멈추고 로그아웃 시
늦은 작업도 폐기합니다. 화면 간 이동 시 정책 초안은 유지합니다. 장애는 표시하며 변경을
자동 재시도하지 않습니다. 재현 가능한 패키지·host 보안·실제 브라우저 및 프로세스 관리
작업을 검증합니다. 이 통합만으로 온톨로지나 펜테스트 자동화가 구현되는 것은 아닙니다.
설정은 Hangang docs/CONSOLE_PLUGINS.md, 향후 자동화는 zerotrust 설계를 참고하세요.

정책은 `GET /v1/policy/document`의 `{revision, policy}`를 읽고
`PUT /v1/policy/document`에 `{expected_revision, policy}`로 저장합니다.
revision은 JSON 본문에 있어 Hangang broker의 조건부 헤더 전달에 의존하지 않습니다.
비교·검증·영속 저장·게시는 같은 엔진 쓰기 잠금 안에서 처리합니다. 충돌은 상태 변경 없이
HTTP 409를 반환하며 화면은 초안을 유지합니다. 명시적으로 저장된 정책을 다시 불러와
변경을 조정해야 합니다. 허용 목록도 처음 읽은 revision으로 저장합니다. 모든 정책
교체(기존 API 포함)는 revision을 바꾸며 일반 관측은 바꾸지 않습니다. revision
(`<lineage>:<sequence>`)은 체크포인트에 저장되어 재시작 후에도 유지되므로 정책·허용
목록 CAS가 불필요하게 충돌하지 않습니다. 난수 lineage는 DB에 속해 다른 서버나 새 DB의
revision과 일치하지 않습니다. 오래된 체크포인트를 복원하면 순번도 되돌아가므로 복원 후
다시 불러오세요. 이전 버전 체크포인트는 한 번 새 lineage로 시작합니다.

기존 `GET/PUT /v1/policy`는 bare Policy 형식과 무조건 저장 동작을 유지합니다.
기존 native client는 document API로 이전하기 전까지 동시 수정 유실 위험이 남습니다.
백엔드를 먼저 배포하고 새 패키지를 검토한 뒤 host manifest pin을 갱신하세요. 새 UI는
구형 백엔드에서 기존 쓰기로 후퇴하지 않고 실패합니다. 관리자 권한 및 정책 원천 소유권은
바뀌지 않습니다.

정책·허용 목록 저장 중에는 요청과 후속 조회가 끝날 때까지 초안 입력을 잠급니다.
정상 저장 응답을 받으면 새 revision을 즉시 보관합니다. 이후 상태 조회만 실패하면
“저장 완료, 현재 상태 새로고침 실패”로 표시합니다. 통신 실패·모호한 서버 오류·잘못된
저장 응답은 초안을 유지하고 두 저장 버튼을 잠급니다. 명시적으로 최신 저장 정책을
다시 읽는 데 성공해야 잠금이 풀립니다. 다시 불러오기는 초안을 교체하므로 조정에
필요한 변경은 먼저 복사하세요. 409도 초안을 유지하며 자동 재시도하지 않습니다.

## 감사·explain 경로(패키지 0.1.5)

패키지 0.1.5는 읽기 전용 브로커 경로 `audit`(GET), `audit/query`, `explain`,
`explain/batch`(POST, `mutation: false`), `reasons`(GET)를 선언한다. 자산과 UI는
바뀌지 않았다. 백엔드를 먼저 배포한 뒤 새 manifest를 검토하고 다시 고정한다.
브로커는 쿼리 문자열을 전달하지 않으므로 콘솔의 감사 필터·커서는
`POST audit/query`를 쓴다. 공유 자격 대신 콘솔 관리자를 기록하려면 Guard 바인딩에
`"delegate_actor": true`, `"delegation_authority": "hangang"`을 두고 Guard 관리자
자격(32바이트 이상)을 `token_env`로 지정한다. 수문장은 서명된 행위자 단언을
검증하며 잘못된 단언은 거부한다. [감사·explain](AUDIT_EXPLAIN.md) 참고.

## 네트워크 API 경로(패키지 0.1.6)

패키지 0.1.6은 `rules/document`(GET), `history/query`·`asn/catalog/query`(POST, 읽기
전용), `allowlist`(GET, POST·DELETE는 변경)를 추가한다. 룰·허용 목록은 CAS 쓰기를
권장한다. [콘솔 네트워크 API](CONSOLE_NETWORK_API.md) 참고.

## 존 경로(패키지 0.1.7)

패키지 0.1.7은 `zones`(GET)와 `zones`(POST, 변경: 생성·교체 또는 삭제)를 추가하고
중복인 `audit` GET 경로를 뺐다(`audit/query` 사용). 브로커 경로 한도 32개를 모두
사용하므로 더 추가하려면 브로커 계약 변경(ADR 0020 플러그인 계약 v2)이 필요하다.
[네트워크 존](NETWORK_ZONES.md) 참고.
