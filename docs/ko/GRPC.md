# gRPC 네트워크 판정

생성된 protobuf 디코딩 전에 호출자를 먼저 인증한다. Bearer는 최초
메타데이터에 있어야 하며 trailer에만 있는 자격은 본문을 읽지 않고 거부한다.
네이티브 핸들러 검사와 2,048바이트 메시지 제한도 유지한다. 리스너의 모든 연결이
공유하는 디코딩 전 예산은 `min(max_http_requests, 256)`개 서비스 future이며,
핸들러 수용량과 별도다. 포화 시 본문을 읽기 전에 즉시 거부한다. 공용 런타임은
압축하지 않은 unary 프레임 하나만 허용하며 실제 DATA를 접두부 포함 2,053바이트로
제한한다. 분할 입력을 지원하고 추가 프레임·잘림·초과 바이트는 거부한다. protobuf
자체 파서는 추가하지 않고 기존 Prost와 메시지별 제한을 유지한다.

기본 수용량에서 동시 인코딩 입력은 최대 513.25KiB(256 × 2,053바이트)다.
이는 전송 데이터 계획 한계이며 프로세스 메모리 한계는 아니다. 디코딩 객체·HTTP/2
버퍼·응답 본문은 별도 비용이다. permit은 디코딩부터 핸들러 완료·취소까지 유지하며,
응답 배출을 포함하거나 동기 CPU 작업을 선점하지 않는다.

[English](../GRPC.md)

`--grpc-listen IP:port`로 HGD1과 함께 `hangang.sumunjang.v1.Network/Check`를 제공한다.
`--decision-listen`, `--decision-tls-cert`, `--decision-tls-key`,
`--decision-client-ca`도 설정해야 한다. 루프백에서도 클라이언트 인증서가 필수다.
단일 `authorization: Bearer <collector 자격>`을 사용하며 관리자 자격은 거부한다.

요청은 요청 ID, IPv4 4바이트 또는 IPv6 16바이트, 최소 리비전을 포함한다.
응답은 허용·거부·사용 불가 및 관찰·집행 모드를 구분한다. 최소 리비전에 못 미치면
사용 불가와 TTL 0을 반환한다. HGD1과 동일한 메모리·GeoIP 판정이며 SQL을 질의하지 않는다.
K8s 수집은 여전히 진단용이고 NetworkPolicy 집행 완료를 의미하지 않는다.

공용 런타임이 연결 2,048개, 연결당 스트림·동시 요청 64개, 헤더 8KiB,
TLS 파일 1MiB, 요청 시간 1초를 제한한다. 메시지 입력·출력 제한은 2/1KiB이며
압축은 활성화하지 않는다. gRPC 판정 처리량 제한은 HTTP와 별도다.

Linux 감독 실행에서 HUP 시 리스너를 인계한다. 클라이언트 재연결은 필요할 수 있다.
빌드에는 protoc가 필요하고 grpcio·grpcio-tools가 있는 별도 Python 환경에서
`python tools/grpc_smoke.py --binary target/debug/sumunjang`으로 실제 전송을 검증한다.
인증서·자격 거부, 입력 제한, 네이티브 일치, 정책 변경 및 HUP 인계를 확인했다.
실제 K8s gRPC 배포·한강 gRPC 클라이언트·릴리즈는 미완료다.

## 최종 스냅샷 검사 (미릴리스)

Check는 판정 전에 정확한 불변 정책 view와 필요한 경우 GeoIP 카탈로그를 캡처합니다.
응답 직전에 Arc 동일성을 재확인하며 같은 숫자 리비전의 정책 교체·GeoIP 교체도
후보를 버리고 unavailable/미지정 모드/TTL 0을 반환합니다. TTL은 최대 5초입니다.
두 소유자 교체와 기존 호출자/수용량/리비전 하한 검사를 수행합니다. 로컬 응답 경계이며
서명 네트워크 receipt나 분산 소유권 lease가 아닙니다. 품계 receipt/permit 연결은 별도입니다.

## 판정 근거(추가 필드)

`NetworkRequest.include_evidence`(필드 4)를 켜면 `NetworkReply.evidence`(필드 6,
`NetworkEvidence`)를 받는다. 안정적인 `reason_code`(`sumunjang.*`, 카탈로그는
`GET /v1/reasons`), `deciding_stage`(observe, allowlist, rule, block, default),
우선순위 순 최대 8개의 일치 활성 `rule_ids`와 `rule_ids_truncated`, `block_network`,
`asn`(0은 불명), `country`(빈 값은 불명), 같은 게시 뷰를 집행으로 평가한
`enforce_verdict`/`enforce_reason_code`를 담는다. 판정·모드·리비전(ADR 0019 이벤트의
정책 리비전)·TTL은 같은 소유자 확인을 거친 기존 실시간 평가 그대로다. 사용 불가
응답에서는 `sumunjang.unavailable.revision_floor`, `.owner_replaced`, `.source`
사유 코드만 담는다. 플래그가 없으면 응답이 바뀌지 않아 기존 클라이언트에 영향이
없고, 필드 번호는 새로 추가되며 재사용하지 않는다. 가장 큰 근거 응답도 1KiB 인코딩
한계 안이다(테스트). 관찰 모드에서는 두 번 평가하며 할당 없는 고정 크기 `Evidence`
싱크를 쓴다. 플래그 없는 요청은 `NoTrace` 경로를 유지한다. HGD1은 바뀌지 않고 근거를
싣지 않는다. 차단 네트워크는 주소이므로 이벤트 내보내기 측에서 가명화해야 한다.
[감사·explain](AUDIT_EXPLAIN.md) 참고.

존 근거: `NetworkEvidence.zone_ids`(10), `zone_ids_truncated`(11),
`zone_revision`(12)은 주소를 포함하는 네트워크 존을 나열한다(최대 8개, 1KiB 인코딩
한계에 맞게 줄임). [네트워크 존](NETWORK_ZONES.md) 참고.

TLS 자료는 재시작 없이 재적재된다. gRPC TLS는 같은 한도로 tonic 앞에서 수문장이
종료한다. [운영](OPERATIONS.md) 참고.

위험 구간: `NetworkEvidence.risk_score`(13)는 근거 신호 점수와 일치 룰 점수의 합을
근거 임계값의 3배(`high` 시작점)에 대한 백분율로 계산해 10 단위로 내림하고 100에서 자른
값이다. `risk_stage`(14, `RiskStage`: normal, watch, suspicious, high, blocked)는
`/v1/lookup`의 위험 단계다(실시간 판정이 거부면 `blocked`). 점수 0과
`RISK_STAGE_UNSPECIFIED`는 근거 저장소가 사용 중이었다는 뜻이며 응답은 기다리지 않는다.
계산은 할당 없이 집계를 읽고(no_alloc 확인) 응답은 1KiB 인코딩 한계 안이다.
