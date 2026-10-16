# 운영 절차

[English](../OPERATIONS.md)

## 적용 단계
1. Collector/admin 토큰을 분리 발급하고 환경 파일 권한을 0600으로 설정한다.
2. Guard를 loopback에서 observe로 실행하고 DB 디렉터리에 쓰기 권한을 준다.
3. 별도 Hangang 인스턴스에서 요청별 질의·장애 처리를 검증한다.
4. 운영 gateway 업그레이드 시 native guard 플래그를 추가하고 observe를 유지한다.
5. 실제 허니팟 경로와 정상 관리 IP/CIDR을 검토한다. 일반 403을 공격으로 세지 않는다.
6. 후보·오탐과 질의 지연을 확인한 뒤 enforce 및 수동 승인부터 시작한다.
7. 자동 차단은 제한된 IP 정책에서 켠다. ASN-wide 자동 차단은 사용하지 않는다.

기존 운영 Docker gateway는 `/docker/hangang/gateway`를 데이터 볼륨으로 사용한다.
이번 작업의 통합 테스트는 별도 포트와 임시 설정에서 수행한다. 운영 컨테이너
재시작·이미지 교체·강제 차단 활성화는 이 초기 검증에 포함하지 않는다.

Guard는 제로트러스트 백본의 IP/네트워크 정책 및 위험 판단 구성 요소입니다. Hopae가
사용자/주체를 관리하며 guard는 계정/세션을 중복 관리하지 않습니다. Guard 허용은
사용자나 장치를 인증하지 않습니다. 관리 API가 정책을 변경하고 Hangang이 집행합니다.

## 장애와 복구
- Query 기본은 guard 장애/타임아웃/잘못된 응답 시503이다. 인증이 중요한
  경로에 적합하지만 guard 가용성이 gateway 가용성에 영향을 준다.
- `--guard-failure-mode allow`는 장애 시 guard 검사를 허용하되 기존 인증은
  계속 수행한다. 장애 가용성이 우선인 경로에 선택한다.
- 캐시는 기본 비활성화. 활성 TTL은1~5초이고 장애 시 무기한 연장하지 않는다.
- Snapshot 모드는 마지막 정상 정책을 만료까지 유지하고 이후 guard 차단을
  중지한다. Query와는 장애 의미가 다르므로 명시적으로 선택한다.
- SQLite 정책 변경은 성공 응답 전에 트랜잭션으로 저장한다. 집계와 자동
  판단은5초 checkpoint 및 정상 종료 시 저장하므로 crash 때 최근 집계를 잃을
  수 있다. WAL/SHM을 고려해 SQLite backup API 또는 정지 상태에서 백업한다.
- 일반 질의는 불변 ArcSwap view를 읽으므로 관리자 fsync·집계 잠금을 기다리지
  않는다. 새 정책은 durable commit 후 publish한다. 증거를 동반한 질의와
  관리자 조회는 별도 직렬화 경로를 쓰며 대규모 운영 전
  실제 rule 수로 지연·메모리를 측정하고 타임아웃을 조정한다.

## 자원 제한
Tracked IP 최대10,000, IP별 집계 bucket 최대64, block 최대100,000,
정책 snapshot 보수적 JSON budget4,000,000바이트, HTTP body4MiB,
배치256, 서버 HTTP 요청 동시 수 기본4,096(설정 가능), binary 연결 최대256,
blocking 작업 상한1,024. 숫자 제한보다 byte budget이 먼저 적용될
수 있다. 시간창이64초보다 크면 bucket 경계의 부분 증거를 보수적으로 버린다.
원시 요청 로그나 body/토큰은 저장하지 않는다.

## ASN catalog

`--asn-catalog path.json`으로 운영자가 제공한 prefix 목록을 로드한다.
형식은 `[{"network":"192.0.2.0/24","asn":64500}]`이다. 정확한 ASN 제공자,
갱신 주기와 검증 방식이 정해지기 전에는 온라인 자동 갱신을 활성화하지 않는다.
ASN은 IP 후보 목록에 표시하는 분류 정보이고 광역 차단의 근거로 단독 사용하지 않는다.

## 되돌리기

Guard 정책을 observe로 바꾸면 다음 질의 또는 캐시 TTL 이내에 guard 차단이
해제된다. Guard 장애로 query fail-deny가 동작할 때는 guard 복구 또는 Hangang
플래그 변경/재시작이 필요하다. Native 기능 전체 해제는 `--guard-url`을 제거한다.
기존 Hangang zero-trust 인증과 방어 기능은 독립적으로 유지된다.

## 최신 동적 룰·GeoIP 적용

관리 화면의 IP/CIDR 위험 조회, JSON/Lua 규칙 탭과 GeoIP 탭을 사용한다.
[룰·점수 의미](RULES.md)를 읽고 dry-run 검증 후 적용한다. Lua 원본은 현재
브라우저 초안이며 서버는 검증·컴파일한 JSON RuleSet을 영속화한다. 원본 Lua
스크립트는 별도로 버전 관리한다. 비활성·동작 설명과 cache TTL 영향을 확인한다.
GeoIP는 구성한 로컬 MMDB를 verify 후 atomic reload하며 실패 시 last-good 유지.
기존 Hangang GeoIP 기능과 별개로 guard도 Country/City/ASN을 처리한다.
운영자가 country/ASN 룰을 설정하면 실제 remote decision에 반영된다.
Dynamic RuleSet은 snapshot v1로 전송하지 않으므로 query mode를 사용한다.

상태를 바꾸는 증거 질의의 처리량은 ordinary read-only 결정과 다르다. 신규
자동 차단이 매우 빈번하면 불변 view 재생성 비용을 측정해야 한다. 정상질의
목표100k QPS와 원시공격로그100k ingest/sec를 동일한 자원 예산으로 가정하지 않는다.

## 영속 초기 정책

`--bootstrap-policy /config/bootstrap.json`은 체크포인트가 없는 새 DB에만 초기 정책을 적용합니다. 체크포인트가 있으면 감독 실행 HUP 후에도 DB 정책을 사용하고 초기 파일을 읽지 않습니다. 재시작 가능한 배포에 사용합니다. 기존 `--policy`는 매 시작마다 명시적으로 정책을 다시 읽으며 두 옵션은 동시에 쓸 수 없습니다. 초기 입력은 1MiB로 제한합니다. 저장 상태가 잘못되면 초기 정책으로 우회하지 않고 시작을 실패합니다.

## 관리 mTLS

`--management-tls`는 판정 TLS 인증서·키·CA로 관리 리스너에 필수 클라이언트 인증서 HTTPS를 제공합니다. 판정 TLS 설정과 네이티브 리스너도 필요합니다. 수집자/관리자 토큰 역할은 계속 검사하며 인증서만으로 정책 쓰기를 허용하지 않습니다. 공용 HTTP/1.1 런타임이 연결·핸드셰이크·헤더·종료 시간을 제한합니다. 감독 실행 HUP에서도 리스너를 인계합니다. 명시적인 루프백 배포의 평문 관리는 유지하며 원격 Service로 노출하지 않습니다.

## TLS 인증서 교체(무중단 재적재)와 프로브

판정 TLS 자료(`--decision-tls-cert`, `--decision-tls-key`, `--decision-client-ca`)는
HGD1 mTLS 리스너, gRPC 리스너, `--management-tls` 사용 시 관리 HTTPS 리스너에 쓰인다.
수문장은 세 파일을 `--tls-reload-seconds`(기본 10, 0이면 비활성)마다 내용 해시로
확인한다. inotify를 쓰지 않으므로 cert-manager/kubelet의 Secret 볼륨 갱신(원자적
`..data` 심볼릭 링크 교체)도 감지한다. 변경되면 파일을 한 번에 읽어 세 리스너의 rustls
설정을 같은 정책(명시 CA의 클라이언트 인증서 필수, 안전한 프로토콜 버전, early data
없음, 리스너별 ALPN)으로 새로 만들고 원자적으로 교체한다. 새 핸드셰이크는 새 자료를
쓰고 기존 연결은 닫힐 때까지 세션을 유지한다(HGD1·관리 연결은 최대 300초). 로그에
`tls: reloaded certificate material; leaf sha256 <지문>`이 남는다.

잘못된 새 자료(해석 불가 PEM, 인증서와 맞지 않는 키, 빈 CA, 1MiB 초과, 교체 중 파일
없음)는 거부하고 이전 설정으로 계속 서비스한다. `GET /v1/status`의 `tls`는
`leaf_sha256`, `loaded_at`, `reloads_total`, `reload_failures_total`,
`consecutive_failures`, `last_error`, `last_failure_at`을 보고한다.
`reload_failures_total` 증가나 0이 아닌 `consecutive_failures`에 경보를 설정한다. 같은
잘못된 자료는 한 번만 기록하고 파일이 다시 바뀔 때 재시도한다.

gRPC TLS는 이제 tonic 앞에서 수문장이 종료한다(핸드셰이크마다 현재 자료, 3초 제한,
연결 2,048개, ALPN `h2`, 클라이언트 인증서 필수). 기존 HTTP/2 한도는 같다.

외부로 나가는 클라이언트는 이미 사용할 때마다 CA 파일을 다시 읽는다. 네이티브
Kubernetes 권위는 수집(500ms)마다 `ca` 파일을 읽고, 읽기 전용 정책 원천은 CA 바이트가
바뀌면 클라이언트를 다시 만들며, 서명 업데이트 확인은 확인마다 `--update-ca`를 읽는다.
이 CA 파일 교체에는 재시작이 필요 없다.

**프로브.** TCP 프로브 대신 `--readiness-listen IP:port`(일반 HTTP, 프로브 전용, 관리
경로 없음)에서 준비 상태는 `httpGet /readyz`, 생존은 `/healthz`를 쓴다. `/readyz`는
네이티브 Kubernetes 원천이 최신이 아니거나 최근 영속 체크포인트가 실패한 동안 503을
반환한다. 이전 유효 자료로 계속 서비스하므로 TLS 재적재 실패는 준비 상태에 영향을
주지 않는다. 주 리스너도 같은 `/readyz`를 제공한다.
`deploy/sumunjang-native-authority-deployment.yaml` 참고.
