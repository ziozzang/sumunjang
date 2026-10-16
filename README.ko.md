# 수문장 (Sumunjang)

[English](README.md)

`hangang-guard`의 컴포넌트 이름은 수문장입니다. 기본 실행 파일은 `sumunjang`이며 기존 설치를 위한 `hangang-guard` 호환 실행 파일과
서명된 기존 자산도 제공합니다. 저장소 URL·프로토콜·자격 증명 환경변수는 유지합니다. 품계가 서비스/사용자/IP 권한을 관리하고
수문장은 네트워크 접근·위험 근거를 제공합니다.

제로트러스트 백본 구성 요소로 Hangang의 IP/네트워크 정책과 위험 판단을 담당하는 Rust 서비스입니다.
Hopae는 사용자/주체를 관리합니다. Guard는 계정이나 세션 관리를 중복 구현하지 않으며
허용 판단으로 사용자나 장치를 인증하지 않습니다. **기본 연동은 매
요청마다 guard 질의**이며, 선택적으로 **1~5초 캐시**를 사용할 수 있습니다.
Guard 허용은 기존 Hangang 인증을 우회하지 않습니다.

명시적으로 지정한 허니팟·스캐너 경로의 신호를 집계하고, 임계값을 넘는 IP를
차단 후보로 관리합니다. 기본은 `observe` 모드입니다. 검토한 IP/CIDR 차단,
허용 목록, 만료, 자동 IP 차단을 API와 내장 대시보드에서 관리합니다.
판단은 메모리에서 처리하고 SQLite에는 정책과 제한된 집계만 저장합니다.

## 실행

Rust 1.96 이상이 필요합니다.

```sh
cargo build --release
export HANGANG_GUARD_COLLECTOR_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export HANGANG_GUARD_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
./target/release/sumunjang --listen 127.0.0.1:9080 --database ./guard.sqlite3
```

두 토큰은 서로 달라야 하며 각각 최소 16바이트입니다. 실제 배포에서는 같은
collector 토큰을 guard와 Hangang에 지속적으로 공급하고, 환경 파일은 권한
`0600`으로 보호하세요. 저장소에 인증 정보를 넣지 마세요.

대시보드는 `http://127.0.0.1:9080/`입니다. 관리자 토큰은 브라우저 메모리에서만
사용합니다. 원격 접근에는 HTTPS 역방향 프록시나 SSH 터널을 사용하세요.

## Hangang 네이티브 연동

네이티브 guard 지원을 포함한 Hangang 빌드가 필요합니다.

```sh
# guard와 동일한 HANGANG_GUARD_COLLECTOR_TOKEN 환경에서 실행
hangang --config hangang.json --listen 127.0.0.1:8080 \
  --guard-url http://127.0.0.1:9080 \
  --guard-honeypot-path /trap \
  --guard-scanner-path /.git/config
```

기본은 `--guard-mode query`, 캐시 없음, 질의 타임아웃 100ms입니다. Guard
불통 시 기본은 `--guard-failure-mode deny`로 503을 반환합니다. 명시적으로
`allow`를 선택하면 guard 장애 시 기존 Hangang 정책으로 계속 처리합니다.
선택적 캐시는 `--guard-cache-ms 1000`부터 `5000`까지이며 탐지 신호가 있는
요청은 항상 guard에 전달합니다. 캐시를 켜면 정책 변경 반영에 최대 해당 TTL이
걸릴 수 있습니다. `--guard-mode snapshot`은 별도 선택 가능한 로컬 정책
스냅샷 방식입니다. 상세 연동은 Hangang의 `docs/GUARD.md`를 참고하세요.

## API

Collector 토큰: `POST /v1/decision`, `POST /v1/events`, `GET /v1/snapshot`.
Admin 토큰: `GET /v1/status`, `GET /v1/candidates`, `GET/PUT /v1/policy`,
`GET/POST/DELETE /v1/blocks`, `POST /v1/candidates/approve`.
모든 API 인증은 `Authorization: Bearer …`입니다. `/healthz`는 인증 없는
최소 상태 확인 경로입니다. [프로토콜·설계](docs/ko/DESIGN.md)를 참고하세요.

IP는 Hangang이 신뢰 프록시 경계에서 판별합니다. 임의의 X-Forwarded-For를
그대로 믿지 않습니다. Guard 차단 요청은 증거를 갱신하지 않습니다. 허용
목록은 guard 차단만 면제하고 다른 인증·보안 정책을 면제하지 않습니다.

## 성능·GeoIP·동적 룰

IP/CIDR/ASN pool은 압축 radix tree로 조회합니다. 일반 질의는 불변 정책을
잠금 없이 읽고 SQLite·집계 잠금·blocking worker를 거치지 않습니다. 선택적
바이너리 TCP 리스너는 평문 loopback 전용입니다. 원격 질의는 보안 HTTP 전송을 사용합니다.
TCP 연동은 연결당 한 번 인증하고 24바이트 프레임을 사용합니다.

```sh
sumunjang --decision-listen 127.0.0.1:9081 \
  --geoip-database /path/country-or-city.mmdb \
  --geoip-asn-database /path/asn.mmdb
hangang --guard-url http://127.0.0.1:9080 --guard-decision-tcp 127.0.0.1:9081
```

관리 화면에서 IP/CIDR 조회, GeoIP·ASN, 점수·의심 단계, 허용 목록, 정책과
JSON/Lua 룰을 관리합니다. Lua는 서비스에 내장되며 룰 적용 시 검증·컴파일하고,
요청마다 실행하지 않습니다. 룰 검증은 활성화와 분리되어 있습니다.

[룰·점수·GeoIP](docs/ko/RULES.md), [바이너리 프로토콜](docs/ko/PROTOCOL.md),
[도구 조사](docs/ko/TOOL_RESEARCH.md), [성능 검증](docs/ko/PERFORMANCE.md)을 참고하세요.

## 검증

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
# Hangang 연동 worktree에서도 cargo build --bin hangang 실행 후
python3 tools/e2e.py --hangang-bin ../hangang-guard-integration/target/debug/hangang
```

E2E는 임시 DB·별도 포트·임시 토큰으로 실제 프로세스를 실행하고 종료합니다.
운영 서버 설정을 변경하지 않습니다.

## 범위와 다음 단계

지원: 요청별 질의, 짧은 선택적 캐시, IPv4/IPv6 CIDR, 가중치 기반 제한된
시간창 집계, 수동 후보 승인·차단 해제, 정책 변경, SQLite 복구, 오프라인
ASN prefix catalog·GeoIP MMDB, IP/CIDR risk 조회, 내장 Lua/JSON 동적 룰,
관리자 대시보드, Hangang 네이티브 HTTP/TCP 연동.

ASN 정보는 분류를 위한 보조 자료입니다. ASN 전체 차단은 자동화하지 않습니다.
온라인 ASN 풀 갱신, 서명된 공격 패턴 피드, ASN 차단 제안의 영향 분석,
GeoIP 온라인 갱신·세부 운영 정책, LLM 검토 보조는 다음 단계입니다. 운영 적용 순서와 한계는
[운영 문서](docs/ko/OPERATIONS.md), 작업 절차는 [설계](docs/ko/DESIGN.md)에 있습니다.

## 서명 업데이트

[업데이트 신뢰 모델과 lifecycle](docs/ko/UPDATES.md)

[정책 변경 감사·explain/what-if·판정 근거](docs/ko/AUDIT_EXPLAIN.md):
`GET /v1/audit`, `POST /v1/explain`, `POST /v1/explain/batch`, gRPC/HTTP 근거.

[Hangang 네이티브 Guard 메뉴](docs/ko/CONSOLE.md)는 host 인증 위임과 해시가 고정된 패키지를 사용합니다.

추가 [gRPC 판정](docs/ko/GRPC.md)은 공용 서버 런타임을 사용하며 빌드에 `protoc`가 필요합니다.

네이티브 HGD1은 고정한 hangang-runtime 0.1.2의 연결 소유권 기반을 사용하며
관리 HTTPS와 공유합니다. 연결 256개·종료 드레인 0·TLS 없는 루프백 제한·
mTLS/ALPN·판정 의미는 유지합니다. 연결 태스크는 리스너와 함께 취소합니다.
감독 실행의 리스너 상속은 수문장이 소유하며 실제 HUP 검증을 별도로 수행합니다.

## v0.3.5 릴리스 준비

네트워크 gRPC 응답 직전에 캡처 정책·필요한 GeoIP 소유자를 재확인합니다. 같은 숫자
리비전의 교체도 unavailable·TTL 0을 반환합니다. debug/정적 전송·실제 품계 관측
검사가 통과했으며 새 버전 정적 자산도 서명 게시 전에 검증합니다. 분산 lease는
아니며 Actions는 비활성입니다.

[v0.3.5](https://github.com/ziozzang/sumunjang/releases/tag/v0.3.5)를
`cd9d8413cf6e71d82a386484a8aa82ee21405f92`에서 게시했습니다. 정확한 새 버전 정적 세 권위 endpoint·소스 회귀/
Clippy·릴리스 경계 검사를 통과했습니다. 재다운로드 자산은 원본과 일치하고 고정
서명·버전/대상/URL 바인딩·정적 ELF를 독립 검증했습니다. 내부 적용과 K8s 통합
endpoint 검증은 다음 단계로 남아 있습니다.

### 0.3.5 내부 적용 — 2026-10-15

고정 서명/버전/대상·실제 설정 사전 검사·비공개 일관된 백업·정책 유지·실제
HGD1 mTLS·감독 HUP/worker 교체를 통과해 내부에 적용했습니다. 기존 observe
모드를 유지하고 강제 허용을 추가하지 않았습니다. 설치 서버와 updater 대상은
정적 musl이며 통합 한강 관리자 HTTPS도 정상입니다.

Kubernetes 네이티브 정책 원천: [설정, 원천 소유권과 readiness](docs/ko/KUBERNETES_AUTHORITY.md).
