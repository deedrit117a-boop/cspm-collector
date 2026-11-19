# 가정과 열린 이슈

기준일: 2026-10-21 · 명세 `2026.10.21-696a804e` (Prowler 5.46.0) · 이 문서는 "아는 것"과 "모르는 것"을 구분해 적습니다.

## 1. 무엇을 검증했고 무엇을 검증하지 못했나

| 영역 | 검증한 것 | 검증하지 못한 것 |
|---|---|---|
| AWS API 호출 | moto에서 동작, botocore 서비스 모델로 API 이름, 필수 파라미터, 응답 필드명 검증 | **실제 AWS 응답.** 특히 moto가 구현하지 않은 호출(Access Analyzer, Account 연락처, Glacier 정책, CodeCommit, Direct Connect, FMS, Lightsail, Roles Anywhere, WAF Classic, CloudFront OAI 등)은 에러 행으로 기록되는 것만 확인 |
| MongoDB | mongomock으로 upsert, 해시 비교, 이력, 소프트 삭제, 분할 저장, 인덱스 생성 호출 | **실제 서버.** unique 인덱스 충돌, 서버 버전별 필드명 규칙, 대량 쓰기 성능, 16MB 근처 문서 |
| Akamai | 가짜 응답으로 수집 로직, 재시도, 속도 제한, 자격증명 로딩 | **실제 Akamai API.** 응답 필드와 경로는 공식 문서와 PAPI 규격에 대한 이해에 의존 |
| 성능 | 없음 | 목표(계정 10개 × 리전 5개, Tier 1, 10분 이내) 측정 못 함 |
| 자격증명 갱신 | moto에서 만료를 흉내 내 재호출 확인 | 실제 1시간 이상 실행 |
| 비밀 마스킹 | 단위/통합 테스트로 "원문이 DB 어디에도 없음" 확인 | 정규식이 못 잡는 비밀 형태 |

**첫 실행은 반드시 작은 범위(계정 하나, 리전 하나, 서비스 몇 개)에서 시작하고 `collect status`로 확인하세요.**

### 실제 개발 환경에서 확인된 것 (2026-10-21)

dev 계정(`ap-northeast-2`)에서 `sqs,sns`를 실제 AWS와 개발 MongoDB(4.2.14, 샤드 클러스터)로 수집해 확인했습니다.
- 수집, 저장, 인덱스 생성, 컬렉션 이름 변경(`rename-collections`), 변경 감지(두 번째 실행부터 `unchanged`)가 동작했습니다.
- **발견한 문제**: SQS가 같은 정책의 `Principal.Service` 배열 순서를 호출마다 바꿔 돌려줘 "변경"으로 잡혔습니다. 정책 문서를 순서 무시로 비교하도록 고쳤습니다. 다른 서비스에도 비슷한 순서 불안정이 있을 수 있으므로, **새 서비스를 처음 켤 때는 같은 범위를 두 번 연속 실행해 두 번째가 전부 `unchanged`인지 확인**하세요.
- 해시 방식을 바꾼 첫 실행에서는 정책이 든 문서가 한 번씩 `updated`와 `history`로 기록됩니다(이후 안정).
- **활성 서비스 93개 전체 실행(계정 1개, 리전 1개)**: 3분 38초, API 호출 약 6,500회, 4,300여 건 수집. 가장 오래 걸린 서비스는 S3(191개 버킷 × 15개 호출, 3분 05초)와 IAM(역할 290개, 1분 20초), CloudFront(배포별 상세, 1분 08초)입니다. 서비스는 서로 병렬이라 전체 시간은 가장 느린 서비스(S3)가 정합니다. 원래 목표(10계정 × 5리전, Tier 1, 10분)에 대한 직접 측정은 아직 없지만, 리전 서비스는 몇 초씩이라 S3와 IAM 같은 계정 단위 서비스가 계정당 시간을 좌우할 것으로 보입니다.
- 같은 범위를 두 번 연속 실행하는 방식으로 찾아 고친 불안정: SQS 정책 배열 순서, IAM 마지막 사용 시각, 라우팅 테이블 연결 순서, RDS 복구 가능 시점, SSM 핑, Trusted Advisor. 그 외 서비스는 연속 실행에서 변경이 없었습니다(남은 변경은 계정에서 실제로 일어난 EC2 리소스 변화).
- 사내 TLS 검사 프록시(Zscaler) 때문에 전역 엔드포인트(Route 53, CloudFront, WAF Classic) 호출이 인증서 오류로 실패했습니다. OS 신뢰 루트를 합친 번들(`collect export-ca-bundle`)로 해결했습니다. 다른 환경의 프록시에서도 같은 조치가 필요합니다.
- 비밀 저장 점검(저장된 4,476건 검사): 가려진 값 43개, 가려지지 않은 비밀 의심 문자열은 IAM 액세스 키 **ID**(비밀 키가 아님)와 Trusted Advisor 설명 문구 1건뿐이었습니다. 실제 비밀은 발견되지 않았습니다.
- 아직 확인하지 못한 것: 삭제 처리(`deleted_at`)의 실서비스 동작, 여러 계정/리전 동시 수집, 실패 경로 일부, Akamai.

## 2. 설계 가정

| 가정 | 이유 / 영향 |
|---|---|
| 동시성은 boto3 + 스레드 풀 | 측정이 아니라 판단. 병목이 확인되면 재검토 |
| 비밀 필드명 | 환경변수 등 "값"을 가리고 이름은 남김. 이름 자체에 비밀이 있으면 노출 |
| `arn:aws` 파티션 | DynamoDB, S3, Route53 ARN을 만드는 곳이 있어 중국/GovCloud는 미지원 |
| 필드명 이스케이프 | `.`와 `$` 시작을 전각 문자로 바꿈. 복원은 데이터에 그 전각 문자가 원래 없다는 가정 (`mongo.escape_keys: false`로 끌 수 있음, 서버 5.0 이상일 때) |
| 글로벌 서비스는 `region: "global"` | iam, s3, route53, cloudfront, organizations, shield, fms, account, waf_global, wafv2_cloudfront, globalaccelerator, trustedadvisor. S3 버킷의 실제 리전은 `resource_region` |
| WAFv2 CloudFront 스코프는 별도 서비스 | `wafv2_cloudfront`(us-east-1 한 번). 룰 엔진은 `wafv2`와 함께 조회해야 함. WAF Classic 글로벌도 `waf_global` |
| CloudTrail `includeShadowTrails=false` | 멀티 리전 트레일이 홈 리전에만 나타남. 조직 트레일이 멤버 계정에서 어떻게 보이는지 미확인 |
| 스냅샷/이미지는 본인 소유만 | EC2 `OwnerIds/Owners: self`. RDS/Redshift/DocDB/Neptune 스냅샷은 `manual`만 (자동 스냅샷은 공유 불가이고 양이 많음) |
| RDS 파라미터 그룹은 `Source=user` | 변경한 값만. 기본값 약 400개는 수집하지 않음 |
| Access Analyzer 결과는 `ACTIVE`만 | |
| ACM `Includes.keyTypes` 명시 | 생략하면 RSA 1024/2048만 반환되므로 7개 키 타입을 명시 |
| Tier 분류 | Prowler 룰 5개 이상 = Tier 2, 그 미만 = Tier 3 (Tier 1은 CIS가 걸린 서비스와 흐름도 핵심 체인). 임의 규칙 |
| 읽기 전용 허용 이름 | `describe_/list_/get_/batch_get_` + `generate_credential_report`. 예외: `head_bucket`, `lookup_events`, `filter_log_events`, `search_tables`, `generate_service_last_accessed_details`는 옵트인 필수 (현재 명세는 `lookup_events` 등을 호출하지 않음) |
| 에러 코드 매핑 | `error_map.yaml`은 Prowler 소스와 AWS 문서 기준의 초안. 실계정에서 새 코드를 만나면 `ERROR`로 기록되므로 보고 추가 |

## 3. 열린 이슈 (우선순위 순)

| # | 이슈 | 현재 동작 | 제안 |
|---|---|---|---|
| 1 | **실계정, 실DB 검증** | 위 표 참고 | 작은 범위로 시험 실행 후 `collect status`로 에러 행 분석, `error_map.yaml`과 명세 보정 |
| 2 | ~~리전별 미지원 서비스 호출~~ (해결) | botocore 리전 정보로 호출 전에 건너뛰고 `NOT_SUPPORTED`로 기록 | botocore가 오래되면 새 리전/서비스를 건너뛸 수 있으니 주기적으로 업데이트 |
| 3 | `--smart-region` 일부 해결 | 실행 전에 자동으로 거르지는 않음. 대신 어카운트 화면의 "사용 리전 탐지"(단건/일괄)가 무료 읽기 호출(EC2, SQS, SNS, Lambda, DynamoDB 목록 1건씩)로 리소스가 있는 리전을 찾아 리전 칸을 채워 줍니다. 조회 권한이 막힌 리전은 "확인 못함"으로 따로 보여 주고 자동으로 빼지 않습니다 | 위 서비스만 쓰는 리전이 아니면 놓침. Resource Explorer/Tagging API 연동은 아직 없음 |
| 4 | `--incremental` 미구현 | 항상 전체 수집 | 대상 ARN 목록을 받는 훅 인터페이스, CloudTrail/EventBridge 이벤트 수신부는 별도 |
| 5 | Organizations에서 계정 목록 자동 조회 미구현 | 계정은 설정 파일에서만 읽음 | `list_accounts`로 계정을 만들고 AssumeRole 이름 규칙을 설정으로 |
| 6 | Akamai AppSec "모드(Alert/Deny)" 미수집 | 정책 원본 응답만 저장 | 공식 API 문서로 경로 확인 후 추가. `selected-hostnames` 경로도 확인 필요(틀리면 해당 호출만 ERROR) |
| 7 | Akamai `validateRules=false`, 429 `Retry-After`, 응답 필드 | 가정대로 동작 | 첫 실행에서 `collect akamai-check`와 `collect status`로 확인 |
| 8 | 서비스별 토큰 버킷 설정 미연결 | boto3 적응형 재시도 + 앱 수준 백오프만 | `concurrency`처럼 서비스별 초당 호출 수를 설정으로 노출 (`core/ratelimit.py`는 이미 있음) |
| 9 | Route53 대형 존 | 존의 모든 레코드를 메모리에 모은 뒤 저장 | 수십만 건이면 스트리밍 저장으로 변경 |
| 10 | `resource_history` 보존 정책 없음 | 계속 쌓임 | TTL 인덱스 또는 보존 기간 설정 |
| 11 | 명세 커버리지 점검 도구 없음 | `build-spec` 결과를 `git diff`로 수동 비교 | "Prowler가 호출하지만 overrides에 없는 API" 목록을 내는 명령 |
| 12 | Firehose 스트림 100개 제한 | `ExclusiveStartDeliveryStreamName` 페이징 미지원 | 전용 수집기에서 페이징 |
| 13 | 옵트인으로 뺀 대용량 항목 | 기본 수집 안 함 | 룰이 필요로 하면 옵트인: ECR 이미지, SageMaker 잡, Route53 헬스체크 상태. 아예 뺀 것: Backup 복구 지점, CloudFormation 템플릿 본문, Athena 쿼리 이력, Glue `search_tables` |
| 14 | 룰↔API 매핑 미저장 | 서비스 단위로만 연결 | 룰 평가 단계에서 필요하면 `rules` 컬렉션과 `rule_requirements`를 별도로 |
| 15 | ~~스케줄링 없음~~ (웹 페이지로 해결) | `collect web`의 스케줄러가 항목별 주기로 실행 | 서버를 상시 구동해야 함(서비스/컨테이너로 등록). 단일 워커라 전체 수집 중 다른 항목은 대기 |
| 16 | `describe_regions` 옵트인 리전 포함 여부 | 항상 포함 | 설정으로 노출 (`AccountSession.enabled_regions(include_opt_in=...)`는 이미 있음) |
| 17 | 개발 환경의 `pymongo<4.11` 고정 | mongomock 호환 때문 | mongomock이 새 pymongo를 지원하면 해제하거나 실제 MongoDB 컨테이너 테스트로 전환 |
| 18 | ~~실행 중인 수집을 취소할 수 없음~~ (해결) | 실행 중이면 새 작업을 시작하지 않고(이미 도는 작업은 끝까지), 대기 중이면 목록에서 뺍니다. 취소된 실행은 `CANCELLED`이고 삭제 표시(sweep)를 하지 않습니다 | 어카운트 단위 중지, 실행 중인 호출 즉시 중단은 없음 |
| 19 | ~~큰 실행 전 확인 없음~~ (해결) | 수동 실행의 예상 작업이 500개를 넘으면 서버가 409로 확인을 요구하고 화면이 확인 창을 띄웁니다(`BIG_RUN_TASKS`). 리전을 비운 어카운트는 17개로 어림합니다. 자동 수집은 확인 없이 실행 | 임계값을 설정으로 노출 |
| 20 | ~~같은 서비스는 어카운트와 무관하게 한 번에 한 실행~~ (해결) | 중복 판정이 (항목, 어카운트) 단위입니다. 어카운트 A의 sqs가 실행 중이어도 B의 sqs는 시작되고, 겹치는 어카운트가 있으면 비어 있는 어카운트만 새 실행으로 만듭니다. Akamai는 하나의 단위 | 실행 자체는 여전히 한 번에 하나(단일 워커) |
| 21 | 접근 제어는 localhost뿐 | 화면 사용자는 서버의 어떤 AWS 프로필이든 어카운트에 지정할 수 있음(권한 상승 가능) | 인증을 켠 뒤에는 허용 프로필 목록(allowlist)과 역할 분리(조회/관리) |
| 22 | ~~어카운트 연결 점검 없음~~ (해결) | 어카운트별 `연결 확인`과 일괄 점검 표가 있습니다 | — |
| 23 | 개인 SSO 프로필에 의존 | SSO 로그인이 만료되면 수집이 어카운트마다 실패. 서버 상시 운영에는 부적합 | 서버 실행 Role + `role_arn` 방식으로 전환, 만료 감지와 알림 |
| 24 | ~~스캔 문서에 어카운트별 결과 저장~~ (해결) | 어카운트별 결과는 `scan_accounts` 컬렉션(스캔 x 어카운트당 문서 하나)에 저장하고 스캔 문서에는 넣지 않습니다. 이전 버전 스캔은 `summary.accounts`를 그대로 읽습니다 | 오래된 스캔의 `summary.accounts`를 옮기는 도구는 없음 |
| 25 | 서버가 `127.0.0.1`에만 바인드 | Windows에서 `localhost`가 IPv6(::1)를 먼저 시도하는 클라이언트는 연결마다 약 2초 지연 | 안내 문구에 `127.0.0.1` 사용 또는 IPv6도 바인드 |

## 4. 알려진 동작과 주의점

- **상세 호출 일시 실패 → 해시 변동**: 상세 호출(`config._details`)이 잠깐 실패하면 그 리소스가 "변경"으로 보여 `resource_history`에 한 건 늘 수 있습니다. `config._errors`로 구분합니다.
- **빈 스캔**: 필터가 아무것도 선택하지 않으면 스캔이 `FAILED`입니다 (`--retry-failed`로 다시 할 일이 없을 때만 `COMPLETED`).
- **수집 Role의 권한 범위**: 비밀이 섞인 설정을 읽을 수 있습니다. 읽기는 하되 마스킹 후 저장합니다. Role과 DB 접근 권한을 제한하세요.
- **moto 테스트의 한계**: 모듈 단위로 moto 상태를 공유하는 통합 테스트가 있어, 격리가 필요한 테스트는 별도 모듈에 있습니다.
- **웹 페이지**: 접근 제어는 localhost 전용이 기본입니다(서버로 옮길 때 `CSPM_WEB_TOKEN` 또는 `--user-header` 필요). 실행은 한 번에 하나이고(대기열), 실행 취소는 새 작업 시작을 막는 방식입니다. 서버 프로세스가 죽으면 30분 이상 갱신 없는 `RUNNING` 스캔은 `INTERRUPTED`로 정리됩니다. 웹 도입 전 스캔은 "실행 주체"가 비어 있습니다.
- **성능 점검(웹 화면)**: 화면이 몇 초마다 부르는 `/api/items`는 항목마다 설정을 DB에서 다시 읽어 요청당 DB 조회가 약 190회였습니다(718ms). 한 번만 읽도록 고쳐 28ms가 되었습니다. 목록 API는 스캔 문서의 큰 필드(서비스/어카운트별 결과)를 읽지 않습니다.
- **CSV 주입**: 어카운트/그룹 이름이 `=`, `+`, `-`, `@`로 시작하면 엑셀이 수식으로 실행할 수 있어 입력 단계에서 거부합니다.
