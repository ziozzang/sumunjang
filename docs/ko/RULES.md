# 동적 룰, 점수와 GeoIP

[English](../RULES.md) · [문서 목록](README.md)

JSON과 내장 Lua는 동일한 타입의 영속 RuleSet으로 컴파일됩니다. 활성화 없이
검증한 뒤 원자적으로 적용할 수 있고, 진행 중인 질의는 마지막 커밋 정책을 읽습니다.
Lua는 룰 설정 시에만 실행합니다. Guard 허용 이후에도 Hangang 인증을 수행합니다.

## 스키마와 우선순위

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

선택 필드: `network`, `countries`, `asns`, `expires_at`(Unix 초), `description`,
`priority`(기본 0), `score`(기본 0). 최소 하나의 조건이 필요합니다. 필드 간 조건은
AND, country/ASN 목록 내부는 OR입니다. 필요한 GeoIP 정보가 없으면 매칭하지 않습니다.
최대 256개 룰, 고유 ASCII id 64바이트 이하, 설명 256바이트 이하, 점수 1,000,000 이하,
국가/ASN 목록 각각 256개 이하입니다. 국가 코드는 대문자, network는 canonical CIDR로
정규화합니다. 압축 CIDR trie와 고정 256비트 마스크로 인덱싱합니다.

Guard 허용 목록이 항상 우선합니다. enforce에서는 매칭한 룰 중 priority가 가장
높은 룰이 선택되고 동률은 id 오름차순입니다. `allow`는 guard를 통과하고 `deny`는
차단하며 `observe`는 기존 수동/자동 IP 차단 판단을 유지합니다. 낮은 우선순위 룰은
선택된 action을 덮어쓰지 않습니다. 모든 매칭 룰 점수는 action과 별도로 합산합니다.
observe 모드는 모든 판단을 허용하되 증거와 점수를 유지합니다.

국가/ASN 룰은 운영자의 명시적 선택입니다. 룰 점수만으로 자동 차단 레코드를 만들지
않으며 자동 IP 차단은 이벤트 가중치 임계값을 사용합니다. 정적 태그가 광역 자동
차단으로 바뀌지 않습니다. GeoIP/룰 상세 조회는 관리자 경로입니다.

## Lua 내장

```lua
local ranges = { "192.0.2.0/24", "2001:db8::/48" }
local rules = {}
for i, network in ipairs(ranges) do
  rules[i] = { id = "watch-" .. i, network = network,
               priority = 10, action = "observe", score = 5 }
end
return { version = 1, rules = rules }
```

스크립트 32KiB, Lua 메모리 4MiB, 약 100,000 명령어 및 50ms hook budget입니다.
텍스트 chunk와 일부 string/math/table/UTF8 라이브러리만 제공합니다. `os`, `io`,
`package`, `debug`, `require`, 동적 chunk 로드, 파일/네트워크/프로세스 API는 없습니다.
Hook은 실행 예산이며 OS 프로세스 격리를 대신하지 않습니다. 인증된 관리자만
스크립트를 설정합니다. blocking worker에서 컴파일하며 잘못된 스크립트는 활성
정책을 변경하지 않습니다.

관리자 API:

- `GET/PUT /v1/rules`: JSON RuleSet 조회/적용.
- `POST /v1/rules/validate`: `{rules: RuleSet}` 또는 `{script: ...}` 중 하나를 받아
  정책 변경 없이 `{valid: true, rules: RuleSet}` 반환.
- `PUT /v1/rules/lua`: `{script: ...}` 컴파일 및 영속 적용.

Snapshot v1은 동적 룰을 전달하지 않습니다. 룰이 있으면 `/v1/snapshot`은 501을
반환하여 불완전한 정책 배포를 막습니다. HTTP 또는 바이너리 query 모드를 사용하세요.
기존 snapshot 클라이언트는 만료까지 이전 정책을 유지하고 이후 fail-open하므로
snapshot 배포와 동적 룰 활성화를 섞지 마세요. 캐시가 있으면 GeoIP reload를 포함한
변경은 명시적 1~5초 TTL만큼 지연될 수 있습니다. 캐시가 없으면 매 질의가 현재 정책을 읽습니다.

## IP/CIDR 점수

`POST /v1/lookup {ip}`는 GeoIP와 `inspection`(판단, 총점, 신호 점수, 정적 룰 점수,
매칭 id, 의심 단계)을 반환합니다. 단계: `normal`=0; `watch`=양수이지만 임계값 미만;
`suspicious`=임계값 이상 3배 미만; `high`=임계값 3배 이상; `blocked`=현재 정책이 차단.
단계는 현재 증거를 설명하며 공격 확률이 아닙니다. 신호 점수는 제한된 시간창에 따라
감쇠하고 원시 요청 로그는 보관하지 않습니다.

`POST /v1/networks/inspect {network}`는 고유 tracked IP 수, 증거 수, 신호 점수 합계,
최대 IP 점수 및 **전체 조회 CIDR**을 덮는 network-only 룰의 정적 점수를 반환합니다.
부분 하위망/GeoIP 룰은 전체 CIDR 기준 점수를 확정하지 못합니다. 점수로 CIDR/ASN
전체를 자동 차단하지 않습니다. 집계 규모와 IP별 값을 함께 검토하세요.

## GeoIP

`--geoip-database`는 로컬 Country/City(DBIP-Country-Lite 포함),
`--geoip-asn-database`는 GeoIP2/GeoLite2-ASN을 사용합니다. 파일당 128MiB 이하,
MMDB 구조/타입 검증, 열린 일반 파일과 제한된 읽기를 적용합니다. 현재보다 5분 이상
미래인 build timestamp는 거부합니다. 누락/잘못된 레코드는 unknown입니다. 메타데이터는
타입/build epoch/크기만 표시하고 비공개 경로는 노출하지 않습니다.

`POST /v1/geoip/reload`는 시작 시 설정한 경로만 원자적으로 다시 읽고 실패하면
마지막 정상 DB를 유지합니다. 라이선스 제공자를 통해 파일을 갱신한 다음 reload합니다.
입장 판단 중 온라인 제공자 호출은 없습니다. 국가/ASN은 룰이 필요할 때만 decode하고
도시/위치 상세는 관리자 조회에서 decode합니다. accuracy radius는 제공 시 표시하되
정확한 개인 위치로 해석하지 않습니다.

MMDB ASN이 누락되면 오프라인 `--asn-catalog` prefix를 사용합니다. 명시적 MMDB
ASN이 우선합니다. 관리자 조회와 화면에는 실제 적용 ASN 및 fallback을 표시합니다.

## Explain과 후보 룰

`POST /v1/explain`은 한 주소의 모드·허용 목록·GeoIP/ASN·일치/만료 룰·차단 조회·최종
사유 코드를 게시 룰 또는 후보 `rules`/`script`에 대해 추적한다. 후보는
`PUT /v1/rules`/`PUT /v1/rules/lua`와 같이 검증하지만 저장하지 않는다.
`POST /v1/explain/batch`는 후보가 최대 1,024개 주소의 판정을 얼마나 바꾸는지
센다. [감사·explain](AUDIT_EXPLAIN.md) 참고.
