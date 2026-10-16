# 영구 연결 바이너리 판단 프로토콜 v1

[English](../PROTOCOL.md) · [문서 목록](README.md)

HTTP API는 관리와 증거 제출에 사용합니다. 선택적 바이너리 리스너는 JSON 없이
동일한 정책·룰·GeoIP 문맥으로 일반 IP 판단을 처리합니다. 평문은 literal loopback으로
제한하고 원격 네이티브 리스너에는 mTLS와 collector token 인증을 함께 요구합니다.

```sh
sumunjang --decision-listen 127.0.0.1:9081
hangang --guard-url http://127.0.0.1:9080 --guard-decision-tcp 127.0.0.1:9081
```

양쪽에 동일한 `HANGANG_GUARD_COLLECTOR_TOKEN`을 공급합니다. Hangang은 최대
64개 연결을 재사용하고 서버의 30초 idle 제한보다 이른 25초에 idle 연결을 종료합니다.
허니팟/스캐너 신호가 있는 요청은 인증된 HTTP 판단 API를 사용합니다. 기본 캐시 없음,
선택적 1~5초 캐시, timeout과 실패 정책은 동일합니다. 잘못된 연결은 폐기하며
HTTP 전송으로 자동 전환하지 않습니다.

## 인증

클라이언트는 `HGD1`(ASCII 4바이트), 토큰 길이(u16 big-endian), 정확히 그 길이의
토큰(16~4096바이트)을 전송합니다. 서버는 collector 인증 후 `HGA1`을 반환합니다.
인증 실패 시 연결을 닫고 admin 토큰은 거부합니다. 인증 5초, idle 읽기 30초,
쓰기 5초 제한을 적용하며 동시 연결은 최대 256개입니다. 종료 시 기존 소켓도 취소합니다.

## 요청 프레임 — 24바이트

| 오프셋 | 길이 | 의미 |
| --- | ---: | --- |
| 0 | 1 | 버전 1 |
| 1 | 1 | IP family 4 또는 6 |
| 2 | 2 | 예약, 반드시 0 |
| 4 | 4 | correlation id, u32 big-endian |
| 8 | 16 | IPv6 주소; IPv4는 앞 4바이트 주소와 뒤 12바이트 0 |

## 응답 프레임 — 24바이트

| 오프셋 | 길이 | 의미 |
| --- | ---: | --- |
| 0 | 1 | 버전 1 |
| 1 | 1 | action: 0 allow, 1 deny |
| 2 | 1 | mode: 0 observe, 1 enforce |
| 3 | 1 | 예약 0 |
| 4 | 4 | 요청 correlation id, u32 big-endian |
| 8 | 8 | 정책 revision, u64 big-endian |
| 16 | 4 | 판단 TTL 밀리초, u32 big-endian, 0~5000 |
| 20 | 4 | 예약 0 |

고정 길이 스트림 프레임이며 요청 pipelining을 지원하고 응답 순서를 유지합니다.
서비스는 읽기당 최대 256프레임을 배치하고 응답 쓰기를 묶습니다. 부분 프레임은
다음 읽기로 이어집니다. 잘못된 버전/family/padding은 연결을 닫습니다. 네이티브
클라이언트는 모든 필드와 correlation을 검증하며 단일 요청 timeout에 pool 대기,
연결, 인증, 읽기/쓰기가 포함됩니다. TTL은 질의 시작부터 측정하여 전송 지연이
유효 시간을 늘리지 못합니다. 이유·GeoIP 이름·점수·인증 정보는 판단 프레임에
포함하지 않으며 관리자 API에서 조회합니다.

## 네이티브 원격 mTLS 리스너

서버는 `--decision-listen`과 함께 `--decision-tls-cert`·`--decision-tls-key`·
`--decision-client-ca`를 받습니다. 루프백 밖에서는 TLS 설정이 필수이며
`0.0.0.0`에 인증된 endpoint를 열 수 있습니다. PEM은 일반 파일이어야 하고
파일별 1 MiB로 제한하며 서비스 시작 전에 검증합니다(`--check` 포함). 서버는
명시적인 client CA만 신뢰하고 ALPN `hgd1`을 요구하며 TLS early data를 끕니다.
TLS 이후에도 collector token 인증은 필수이고 mTLS가 관리자 권한을 부여하지 않습니다.

기존 최대 256개 연결 안에서 TLS 핸드셰이크를 3초로 제한합니다. 연결은 300초 후
종료합니다. Idle 읽기는 30초로 유지하되 부분적인 24바이트 프레임은 5초 안에
완성해야 하고 조금씩 보내도 기한이 초기화되지 않습니다. 파이프라인 응답과
불변 인메모리 판단은 기존 의미를 유지하고 DB 질의를 하지 않습니다.

Hangang 원격 HGD1 client 설정과 실제 두 프로세스 배포 검증은 후속 작업입니다.
네이티브 TLS 옵션은 HTTP 관리/근거 리스너를 변경하지 않습니다. 원격 HTTP는 기존
로컬 broker 또는 별도로 인증되는 TLS ingress를 사용합니다. 이 변경으로 복제 서버
membership이나 전체 스택 TLS 처리량이 검증된 것은 아닙니다.

## HGD1은 판정 근거를 싣지 않음

위 24바이트 프레임은 바뀌지 않는다. 일치 룰 ID·ASN·국가·사유 코드는 추가된 gRPC
`include_evidence` 플래그와 HTTP `/v1/decision`의 `"evidence": true`로만 제공한다.
[gRPC](GRPC.md)와 [감사·explain](AUDIT_EXPLAIN.md) 참고.
