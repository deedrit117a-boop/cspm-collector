# cspm-collector

AWS와 Akamai의 설정을 **읽기 전용 API로만** 수집해 MongoDB에 원본 그대로 저장하는 수집기입니다.
점검(룰 평가), 그래프(nodes/edges) 생성, UI는 이 프로젝트의 범위가 아닙니다. 그 단계가 사용할 수 있도록
원본을 정확하게, 변경 이력과 함께, 빠르게 저장하는 것까지가 이 프로젝트가 하는 일입니다.

| 항목 | 현재 상태 |
|---|---|
| AWS 서비스 | 93개 활성 (Tier 1 35 / Tier 2 19 / Tier 3 39), 460개 API 호출 정의 |
| Akamai | PAPI(속성, 호스트, 룰 트리, Origin 요약), AppSec, Network Lists, Edge DNS(선택) |
| 명세 기준 | Prowler 5.46.0 (`rules_master.json` 563개 룰, 77개 서비스) |
| 저장소 | MongoDB. 기본 DB 이름 `cspm` (기존 DB와 분리) |
| 테스트 | 210개, 코드 커버리지 97%. **moto, mongomock, 가짜 Akamai 응답으로만** 검증했고 실제 AWS/MongoDB/Akamai로는 아직 검증하지 않았습니다 ([한계와 열린 이슈](docs/assumptions-and-open-issues.md)) |

## 구조

```
                    +-------------------------------+
 config.yaml  --->  |  collect run (cli/main.py)    |
 collect_spec.yaml  |  core/scan.py  (오케스트레이터) |
                    +---------------+---------------+
                                    | (계정, 리전, 서비스) 태스크, 계정/서비스별 동시성 제한
              +---------------------+----------------------+
              v                                            v
   core/workers.py (스레드 풀)                      akamai/collector.py
        |                                            |  EdgeGrid + 속도 제한 + 429 백오프
        v                                            |
   collectors/  generic | ec2 | s3 | iam | route53   |
                ecs | eks | dynamodb | ...           |
        |  core/call.py: 페이지네이션, 재시도, 에러 분류
        |  collectors/masking.py: 저장 전 민감정보 마스킹
        v                                            v
   +--------------------------------------------------------+
   | storage/store.py  해시 비교 upsert, 이력, 소프트 삭제    |
   +---------------------------+----------------------------+
                               v
   MongoDB (DB cspm): scans | collection_status | resources | resource_history | resource_chunks
                      account_settings | akamai_raw | cspm_meta
```

핵심 원칙

1. **수집은 한 번, 원본 그대로.** API 응답에서 `ResponseMetadata`만 제거하고, 날짜/바이트 같은 BSON 비호환 값만 변환합니다.
2. **"없음"과 "조회 못 함"을 구분합니다.** 모든 `(스캔, 계정, 리전, 서비스, API)`마다 `collection_status`에 상태를 남깁니다. 리소스가 0개여도 `SUCCESS`, `resource_count: 0`입니다.
3. **실패한 범위의 데이터는 절대 지우지 않습니다.** 삭제 처리(`deleted_at`)는 완전히 수집된 범위에서만 합니다.
4. **읽기 전용.** 명세 검증이 `describe_/list_/get_/batch_get_` 외의 API 이름을 막고, IAM 정책도 명세에서 생성합니다.
5. **민감정보는 저장하지 않습니다.** 환경변수, UserData, Connection 속성 등은 마스킹하고 탐지 위치/유형만 남깁니다.

### 동시성 방식 (boto3 + 스레드 풀)

`aioboto3`가 아니라 `boto3` + `ThreadPoolExecutor`를 씁니다. 호출 대부분이 네트워크 대기라 스레드로 충분히 겹치고,
moto 테스트와 호환되며, 서비스마다 하위 호출이 많은 구조에서 코드가 단순합니다. 다만 두 방식을 직접 측정해
비교한 것은 아닙니다(설계상 판단). 병목은 `collect run` 끝에 출력되는 "가장 느린 서비스/API Top 10"으로 확인합니다.

## 설치

Python 3.11 이상.

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"      # Windows. Linux/macOS는 .venv/bin/python
```

개발 의존성의 `pymongo<4.11` 제약은 mongomock과의 호환성 때문입니다(테스트 전용). 운영에는 적용되지 않습니다.

## 설정

`config.example.yaml`을 `config.yaml`로 복사해 채웁니다 (`config.yaml`은 git에서 제외됩니다).
**비밀값은 파일에 쓰지 않고 환경변수로 넣습니다.**

```yaml
mongo:
  database: cspm                 # MONGO_URI / MONGO_DATABASE 환경변수가 우선
  collection_prefix: ""          # 예: "000_cspm_" -> 000_cspm_resources, 000_cspm_scans ... (MONGO_COLLECTION_PREFIX가 우선)
accounts:
  - account_id: "123456789012"
    role_arn: arn:aws:iam::123456789012:role/CspmReadOnly
    external_id_env: CSPM_EXTERNAL_ID_PROD   # ExternalId 값이 든 "환경변수 이름"
    regions: [ap-northeast-2, us-east-1]     # 생략하면 활성화된 모든 리전
concurrency: {total: 32, per_account: 8, per_service: 4}
akamai:
  - name: main
    edgerc: ~/.edgerc            # 또는 env_prefix: AKAMAI_MAIN
```

**사용 리전 탐지(비용 없음)**: 어카운트 편집 창의 "사용 리전 탐지" 버튼은 활성화된 리전마다 EC2(네트워크 인터페이스, 기본이 아닌 VPC, 인스턴스), SQS, SNS, Lambda, DynamoDB 목록을 1건씩만 읽어 실제로 리소스가 있는 리전을 찾고, 결과를 리전 칸에 넣을 수 있게 합니다(읽기 전용 호출, Cost Explorer 미사용). 조회 권한이 막힌 리전은 "확인 못함"으로 따로 보여 주고 자동으로 빼지 않습니다. 위 서비스만 쓰는 리전이 아니면 놓칠 수 있으니 그런 리전은 직접 추가하세요.

**스스로 점검하는 기능** (`config.yaml`의 최상위 설정, 모두 기본 켜짐)
- `preflight_check: true`: 웹에서 실행하기 전에 그 실행의 어카운트를 연결 확인하고, 접속할 수 없는 어카운트(SSO 로그인 필요, Role 거부, 다른 어카운트 등)는 이유와 해결 방법을 붙여 실행에서 뺍니다. 나머지는 그대로 수집합니다. 2분 안의 정상 결과는 다시 확인하지 않습니다.
- `auto_retry: true`: 실행이 일부 실패하면 일시적 실패(타임아웃, 스로틀링, 오류)만 모아 자동으로 한 번 더 실행합니다. 권한 거부나 열 수 없던 어카운트는 다시 하지 않고, 재시도를 다시 재시도하지 않습니다. 실행 이력에 "자동 재시도"로 표시됩니다.
- `region_check_days: 7`: 이 기간마다 전체 어카운트의 사용 리전을 다시 탐지해, `regions`에 적지 않은 리전에서 리소스가 발견되면 대시보드의 "리전 변화" 카드와 메뉴 배지로 알립니다(0이면 끔, AWS 로그인이 되어 있어야 함).
- **수집 건강도** 화면: 어카운트별 최근 수집(칸 하나가 한 번)과 성공률, 평균 시간, 주의(연속 실패, 평소의 2배 이상 느려짐, 항목 건수 70% 이하로 감소)를 보여 줍니다. 건수 비교는 완료된 일반 실행끼리만 합니다.
- **작업량 추천** (`core/resources.py`): 수집 항목 화면에서 항목을 고르면 이 PC의 CPU 코어 수, 가용 메모리, 지금 CPU 사용률을 읽어 동시 실행 설정(동시 작업, 어카운트당, 항목당, 상세 호출)을 추천하고, 작업이 한 번에 너무 많으면 "어카운트 N개씩 M번"으로 나눠 실행하도록 권합니다. 예상 시간은 이전 큰 수집의 속도로 계산하고(기록이 없으면 작업당 2.5초 가정), 작업이 500개를 넘는 수동 실행에는 확인 창에 같은 추천이 나옵니다. 추천은 현재 설정보다 낮추는 방향으로만 제안하고(AWS 호출 제한이 또 하나의 한계), 나눠 실행하면 같은 결과를 더 낮은 부하로 순서대로 얻습니다(`POST /api/runs`의 `batch_size`). 작업당 메모리 50MB, 코어당 작업 6개 같은 값은 가정이라 `core/resources.py` 상수로 두었고 실제 수집 뒤 조정합니다.
- **관계 인덱스(`edges`)**: 수집하면서 리소스 사이의 관계(보안 그룹, 로드밸런서와 대상 그룹, 웹 ACL이 보호하는 대상과 참조하는 IP 집합, CloudFront·Route 53·Akamai의 호스트명과 오리진, Akamai 정책이 쓰는 네트워크 리스트와 커스텀 룰)를 `edges` 컬렉션에 한 건씩 저장합니다. 출발 리소스의 `_id`(`src_key`)와 도착 리소스의 `_id`(`dst_key`)로 이어지고, `hostname`/`ip`는 시스템을 잇는 가상 노드입니다. 추출 규칙은 `core/edges.py`, 형태와 쿼리 예시는 `docs/CSPM_개발_반영_요청.md`.
- **조치 필요** (수집 건강도의 첫 탭, `GET /api/health/actions`, `web/actions.py`): 지금 수집할 수 없는 어카운트를 이유별로 묶어 "할 일"과 함께 보여 줍니다. 연결 확인의 실패와 가장 최근 수집에서 어카운트를 열지 못한 행 중 더 새로운 쪽을 쓰고, 그 뒤 정상으로 끝난 수집이나 연결 확인이 있으면 목록에서 사라집니다. 아래에는 가장 최근 수집의 `ACCESS_DENIED`를 어카운트·항목별로 묶어(IAM 정책 미적용이나 SCP의 흔한 신호) 보여 줍니다. 어카운트 화면 위에도 짧은 요약이 있고 "이 어카운트만 보기"로 표를 거를 수 있으며, 상단 경고에 "조치 필요 N"이 나옵니다.
- **관계 인덱스 상태** (수집 건강도의 마지막 탭, `GET /api/health/edges`): `edges`의 현재 관계 수, 마지막 갱신 시각(3일 넘으면 경고), 도착 리소스가 저장되지 않은 관계 수(호스트명·IP 제외), 관계(`rel`)별 건수.
- **Akamai 저장 현황** (Akamai 화면, `GET /api/akamai/summary`): 종류별 문서 수와 가장 최근 수집, 이 계약에서 받을 수 없는 종류(`NOT_SUPPORTED`)를 보여 줍니다.
- **배치 수집 표시**: `batch_size`로 나눈 실행은 `scans.options.trigger.batch = {n, of, id}`를 가지고, 실행 이력에 "배치 n/of" 칩과 "몇 번째 배치가 끝났고 어느 것이 수집 중·대기인지" 보여 주는 상자가 나옵니다.
- **어카운트 화면**: 리전을 칩으로 보여 주고(설정에 없는 리전이 발견되면 "새 리전" 칩이 사용 리전 탐지를 엽니다), 열(이름·계정 ID·환경·연결) 정렬과 "수집 결과: 조치 필요" 필터가 있고, 50개씩 나눠 "더 보기"로 펼칩니다. 정렬은 브라우저에 기억합니다.
- **한 화면에서 끝내기**: 어카운트 이름, 수집(실행), 리소스를 어디서 누르든 오른쪽 **서랍**이 열리고(`Esc`로 닫고 ← 로 이전 화면), 보던 페이지는 그대로입니다. 어카운트 서랍에서는 연결 확인·다시 확인, 해결 방법, 사용 리전 탐지와 "탐지 결과로 리전 바꾸기", 최근 수집, 편집을 하고, 수집 서랍에서는 어카운트별 결과와 취소를, 리소스 서랍에서는 설정 원본(`GET /api/resources/detail`), 태그, 바뀐 시각별 차이를 봅니다. 상단 경고 칩("조치 필요", "수집 주의" 등)은 이동 대신 "확인이 필요한 것" 서랍을 엽니다.
- **하단 실행 현황 막대**: 어느 페이지에서나 수집 진행(작업 수, 배치 n/m, 수집 중인 어카운트, 대기 수), 상세 보기, 취소가 보이고, 끝나면 "결과 보기"가 2분 동안 나옵니다. 연결 확인과 사용 리전 탐지의 진행도 같은 막대에 나옵니다. 접은 상태는 브라우저가 기억합니다.
- **빠른 이동**: `Ctrl+K`(또는 `/`)로 어카운트, 최근 수집, 화면, 수집 항목, 작업(지금 수집, 전체 연결 확인, 어카운트 추가)을 찾아 바로 엽니다. 방향키와 Enter로 고릅니다.
- **보던 상태 기억**: 변경 내역·어카운트·수집 항목의 검색과 필터, 건강도 탭을 페이지를 옮기거나 새로 고쳐도 유지합니다(브라우저 `localStorage`, "필터 해제"로 지움).
- **설정 진단 점검 항목 반영**(사내 점검서 중 수집기 웹에 해당하는 항목만): 접근 통제(기본 loopback만, 호스트 허용 목록, 그 밖의 주소는 토큰·SSO 프록시 필수), 인증 실패 제한(틀린 토큰 5회면 15분 잠금, `429`와 `auth_locked` 감사 기록), 보안 헤더(CSP·`X-Frame-Options`·`nosniff`·`Referrer-Policy` 등, 외부 호스트 로드 없음), `/api/*` 응답 캐시 금지, 서버 배너(`Server:`) 숨김, 변경 이력(감사 로그, 기본 365일 보관), 시간은 UTC 저장·KST 표시. 해당 없음: 세션 만료(로그인 세션 없음), 계정·패스워드 정책(토큰 방식, 값은 환경변수로만), SNMP·NAT·DMZ. 위 항목이 서버 OS·Docker 쪽(방화벽, 계정, 파일 권한, 컨테이너 사용자 등)에 걸리는 부분은 배포 환경에서 따로 지켜야 합니다.
- **접근성**: 본문 건너뛰기 링크, 메뉴의 현재 페이지(`aria-current`), 탭의 방향키 이동과 `aria-selected`, 변경 내역 줄의 키보드 조작, 이름 없는 입력칸과 대화 상자·표 머리글의 이름, 움직임 줄이기 설정을 따릅니다. 폭 720px 이하에서는 메뉴가 한 줄로 가로 스크롤되고, 다크 모드는 시스템 설정을 따릅니다.
- **데이터 신선도**: 수집 건강도 화면의 두 번째 표입니다. 항목마다 API 호출이 하나도 실패하지 않은 마지막 수집을 찾아, 기준일(3/7/14/30일) 넘게 성공하지 못한 항목을 어카운트별로 보여 줍니다.
- **변경 없는 상세 호출 건너뛰기** (`incremental_details: true`, `full_refresh_days: 7`): 목록 응답에 "마지막 변경 시각"이 있는 항목(스펙의 `change_marker`: Lambda `LastModified`, CloudFront `LastModifiedTime`)은 그 값이 저장된 복사본과 같으면 리소스마다 부르는 상세 API(get_function, get_policy 등)를 다시 부르지 않고 저장된 값을 씁니다. 마지막으로 전부 읽은 시각(`resources.detail_checked_at`)이 `full_refresh_days`보다 오래됐거나 이전 호출에 오류가 있었거나 삭제됐던 리소스는 항상 전부 읽습니다. 재시도 실행은 쓰지 않습니다. 건너뛴 수는 `scan_accounts.services.<항목>.reused`에 남습니다. 다른 항목에 쓰려면 `spec/overrides/<서비스>.yaml`의 목록 API에 `change_marker: <필드>`를 적고 `collect assemble-spec`을 실행하세요. 목록 응답의 그 필드가 정말 상세 변경 때마다 바뀌는 항목에만 쓰세요.
- **응답 형식 변화 감지**: 정상으로 끝난 수집마다 항목(서비스·리소스 종류)별 필드 이름을 지난번과 비교해, 리소스가 5개 이상인 항목에서 전체가 가진 필드가 사라지거나 새로 생기면 `scans.summary.shape_changes`에 남기고 수집 건강도의 "응답 형식 변화" 탭과 상단 경고에 보여 줍니다(`core/shape.py`, 기억하는 형태는 `runtime`의 `shape:<서비스>:<종류>` 문서). 값은 보지 않고 이름만 봅니다. 일부 리전·어카운트만 수집한 실행(지난번의 절반 미만)은 비교하지 않습니다.
- **변경 내역** 화면(`GET /api/changes`, `/api/changes/detail`): `resource_history`와 `resources`로 신규, 변경, 삭제를 시간순으로 보여 주고, 변경은 줄을 누르면 바뀐 필드(이전 → 지금)를 보여 줍니다. 마지막 사용 시각처럼 수집 때마다 바뀌는 값은 비교에서 뺍니다. 각 어카운트·항목의 첫 수집(1시간 안)은 "신규"로 세지 않습니다.
- **Organizations에서 어카운트 가져오기**(어카운트 화면): 서버의 AWS 자격증명(조직 관리 계정)으로 `organizations:DescribeOrganization`, `ListAccounts`만 읽어 어카운트 목록을 보여 주고, 고른 어카운트를 같은 이름의 Role(`arn:aws:iam::<ID>:role/<Role 이름>`)로 수집하도록 한꺼번에 등록합니다(이미 등록된 어카운트는 건드리지 않음, 활성 상태만). 이 권한은 수집용 IAM 정책(`iam/policy-*.json`)에 들어 있지 않으니, 이 기능을 쓰는 자격증명에만 따로 주세요(읽기 전용).
- **알림**(설정 화면, 기본 꺼짐): 수집 실패·일부 실패, 사전 점검에서 어카운트 제외, 새 주의, 응답 형식 변화를 채팅 웹훅(`{"text": ...}` JSON, Slack·Teams 호환)으로 보냅니다. 웹훅 주소는 비밀이라 DB나 화면에 두지 않고 서버 환경변수(이름은 `notify_webhook_env`, 기본 `CSPM_NOTIFY_WEBHOOK`)에서만 읽습니다. 자동 재시도가 대기 중인 실행은 알리지 않고 재시도의 결과를 알립니다.
- **데이터 보관 기간**(설정 화면, 기본 꺼짐): 수집 기록(scans·collection_status·scan_accounts, 최근 20번은 항상 유지), 변경 이력(`resource_history`), 삭제된 리소스(`deleted_at`이 오래된 resources·akamai_raw·edges), 화면 변경 이력(audit)의 보관 일수(7~3650, 비우면 무기한)를 정하고, 켜면 스케줄러가 하루에 한 번 지웁니다. 지금도 수집에서 보이는 리소스는 지우지 않습니다. "지금 정리"는 지울 양을 확인 창에서 보여 준 뒤에만 합니다.
- Akamai 응답 점검: 기대한 최상위 필드가 없는 응답은 "빈 결과"가 아니라 `UNEXPECTED_RESPONSE` 오류로 기록하고 그 종류의 삭제 표시를 막습니다. 정책별 커스텀 룰 사용(`appsec_policy_custom_rules`)도 수집합니다.

- `collection_prefix`는 컬렉션 이름 앞에 붙는 문자열입니다. 기존 컬렉션이 많은 DB에서 구분하기 쉽게 하거나(정렬상 맨 위로 오게 하는 등)
  이름 충돌을 피하려고 씁니다. 이미 만든 컬렉션의 접두사를 바꾸려면 `collect rename-collections --from-prefix <현재> --to-prefix <새로>`
  (데이터와 인덱스 유지, 이 수집기가 만든 컬렉션만 대상, 대상 이름이 이미 있으면 아무것도 바꾸지 않음) 후 설정을 맞추세요.
- `role_arn`이 없으면 현재 자격증명(환경변수, 프로파일)을 그대로 씁니다. 로컬 시험용입니다.
- AssumeRole 자격증명은 만료 전에 자동 갱신됩니다.
- MongoDB 접속 문자열은 `MONGO_URI`로 넣는 것을 권장합니다.

## 실행

```bash
collect validate-spec                    # 명세 검증 (스키마, 읽기 전용, botocore 모델과 필드명 대조)
collect akamai-check --config config.yaml  # Akamai 자격증명 점검 (PAPI 그룹 조회 1회)
collect ensure-indexes --config config.yaml
collect run --config config.yaml --services s3,iam      # 작게 시작
collect run --config config.yaml                        # 활성 서비스 전체 + Akamai
collect status <scan_id> --config config.yaml           # 스캔 요약과 SUCCESS가 아닌 상태 행
collect run --config config.yaml --retry-failed <scan_id>   # 실패한 범위만 다시
```

`collect run` 옵션

| 옵션 | 설명 |
|---|---|
| `--services a,b` | 서비스 제한. `akamai`를 넣으면 Akamai만/함께 실행 |
| `--tier 1` | 해당 티어만 (Akamai는 Tier 1로 취급) |
| `--regions`, `--accounts` | 리전, 계정 제한 (`--accounts`에는 Akamai 계정 이름도 가능) |
| `--collect-userdata` | EC2/시작 구성 UserData를 비밀 탐지에 사용 (내용은 어떤 경우에도 저장하지 않음) |
| `--opt-in <flag>` | 무거운 호출 켜기: `--collect-ecr-images`, `--collect-sagemaker-jobs`, `--collect-health-check-status` 등 |
| `--retry-failed <scan_id>` | 그 스캔에서 실패한 (계정, 리전, 서비스)만 재수집. 계정 연결이 실패했다면 계정 전체, Akamai는 계정 단위 |

종료 코드: 스캔이 `FAILED`면 1, 그 외 0 (`PARTIAL`도 0). 입력 오류는 2.

### 처음 실제 계정에서 돌려볼 때

1. `collect validate-spec`, `collect iam-policy`로 만든 정책을 Role에 붙입니다 ([IAM](#읽기-전용-iam-정책)).
2. **빈 DB 이름**(`cspm`)으로 `collect ensure-indexes`. 같은 이름의 컬렉션이 있는 DB는 거부합니다.
3. 계정 하나, 리전 하나, 서비스 몇 개(`--accounts`, `--regions`, `--services s3,iam,kms`)로 먼저 실행합니다.
4. `collect status <scan_id>`로 `SUCCESS`가 아닌 행을 확인합니다. `ACCESS_DENIED`는 정책 누락, `NOT_SUPPORTED`는 리전 미지원이 대부분입니다.
5. 같은 명령을 한 번 더 실행해 `unchanged`가 대부분인지(변경 감지가 안정적인지) 봅니다.

## 저장되는 데이터

| 컬렉션 | 내용 |
|---|---|
| `scans` | `scan_id`, 상태(`RUNNING/COMPLETED/PARTIAL/FAILED`), 계정, `spec_version`, `prowler_version`, 옵션, 요약 |
| `collection_status` | `(scan_id, account_id, region, service, api)`별 상태, 에러 코드, `resource_count`, 소요 시간 |
| `resources` | AWS 리소스. `_id`는 `sha1(계정\|리전\|서비스\|타입\|ID)`. 아래 참고 |
| `resource_history` | 변경 전 버전 (`resource_key`, `config`, `changed_at`, `version_scan_id`) |
| `resource_chunks` | 12MB를 넘는 `config`를 나눠 저장한 조각 (`Store.get_config()`가 복원) |
| `account_settings` | `(scan_id, account_id, region, setting)`별 계정/리전 설정과 `<서비스>_enablement` |
| `akamai_raw` | Akamai 문서 (`property_version`, `appsec_*`, `network_list`, `dns_*` 등). `appsec_ip_geo_firewall`(정책별 차단/허용 네트워크 리스트와 Geo), `appsec_bypass_network_lists`(설정별 우회 리스트), `appsec_custom_rule`(커스텀 룰 조건)로 어떤 정책이 어떤 리스트를 쓰는지 알 수 있습니다 |
| `cspm_meta` | 이 DB를 우리가 만들었다는 표식 (다른 컬렉션과의 충돌 방지) |

`resources` 문서의 주요 필드

```
account_id, region ("global"이면 계정 단위 서비스), service, resource_type, resource_id, arn, tags [{key,value}],
config            API 응답 원본. 상세 호출 결과는 config._details.<API>, 실패는 config._errors.<API>
config_hash       config+tags의 SHA-256 (키 순서와 무관). 같으면 last_seen/scan_id만 갱신
first_seen, last_seen, scan_id, deleted_at (소프트 삭제), key_escaped
secret_findings   [{location, type[, line]}]  비밀 탐지 결과 (내용 없음)
parent, <상위 필드>  하위 리소스(리스너, 룰, 레코드 등)가 가리키는 상위 리소스
```

- **상태값**: `SUCCESS`, `ACCESS_DENIED`, `NOT_ENABLED`, `NOT_SUPPORTED`, `THROTTLED_GIVEUP`, `TIMEOUT`, `ERROR`, `SKIPPED`.
  에러 코드 → 상태 매핑은 [error_map.yaml](src/cspm_collector/core/error_map.yaml)에서 고칩니다 (코드 수정 불필요).
  "설정 없음"(예: `NoSuchBucketPolicy`)은 에러가 아니라 `config: null` + `SUCCESS`입니다.
- **S3와 IAM 같은 계정 단위 서비스**는 `region: "global"`이고, 실제 버킷 리전은 `resource_region`에 있습니다.
- **Route53 레코드**는 레코드당 문서 하나입니다 (`<존ID>|<이름>|<타입>[|<SetIdentifier>]`).
- **필드명의 `.`와 `$`로 시작하는 키**(IAM 조건 키 등)는 전각 문자로 이스케이프해 저장합니다 (`mongo.escape_keys`, 기본 켬).
- **Akamai 조인 키**: `akamai_raw`의 `hostnames`, `edge_hostnames`, `origin_hostnames`는 소문자·마침표 제거로 정규화한 배열이고
  멀티키 인덱스가 있습니다. 예: `db.akamai_raw.find({edge_hostnames: "www.example.com.edgekey.net"})`.

### 변경 감지, 삭제, 재시도

- 스캔마다 `config_hash`를 비교해 **바뀐 것만** `config`를 갱신하고 이전 버전을 `resource_history`에 남깁니다.
  정책 문서(`Statement`가 있는 JSON, 문자열이든 객체든)는 배열 순서를 무시하고 비교합니다. AWS가 같은 정책을
  호출마다 다른 순서로 돌려주는 경우가 실제로 있었기 때문입니다 (예: SQS `Principal.Service`). 저장되는 `config`는 원본 그대로입니다.
- 스캔 종료 후, 이번 스캔에서 **완전히 읽은 범위**에서 보이지 않은 리소스에 `deleted_at`을 기록합니다. API 하나라도 실패한
  리소스 타입, `SKIPPED`, 접근 거부된 범위는 삭제하지 않습니다. 다시 나타나면 `deleted_at`이 해제됩니다.
- 상세 호출 하나가 일시적으로 실패하면 그 리소스의 `config`가 바뀐 것으로 보여 이력이 늘 수 있습니다
  (`config._errors`에 코드가 남아 구분됩니다).
- **설정이 아닌데 계속 바뀌는 값**은 변경 감지에서 제외합니다 ([storage/volatile.py](src/cspm_collector/storage/volatile.py)).
  IAM 역할/사용자의 "마지막 사용" 시각, RDS 복구 가능 시점, SSM 에이전트 핑, Trusted Advisor 결과가 해당합니다.
  이 값들은 이력 없이 **매 스캔 최신 값으로 갱신**되고, 순서가 호출마다 달라지는 목록(예: 라우팅 테이블 `Associations`)은 순서를 무시하고 비교합니다.
  새 서비스를 처음 켤 때 같은 범위를 두 번 연속 실행해 두 번째가 전부 `unchanged`가 아니면, 바뀌는 필드를 찾아 이 파일에 추가하세요.
- **서비스가 없는 리전**은 호출하지 않고 `NOT_SUPPORTED`로 기록합니다(botocore 엔드포인트 정보 기준, `skip_unsupported_regions`로 끌 수 있음).
  호출해 보면 연결 재시도 때문에 서비스당 1~2분이 걸립니다.

## 명세 (`spec/collect_spec.yaml`)

무엇을 수집할지는 코드가 아니라 명세가 정합니다. 흐름은 다음과 같습니다.

```
Prowler 소스 + rules_master.json --(collect build-spec)--> spec/collect_spec.generated.yaml   (참고용 초안)
spec/overrides/<서비스>.yaml (사람이 검토한 정의) --(collect assemble-spec)--> spec/collect_spec.yaml  (실행에 쓰는 명세)
```

`build-spec`은 Prowler 서비스 소스를 AST로 분석해 호출하는 boto3 API를 뽑지만, 하위 호출 연결과 ID 필드는 추측입니다.
그래서 **검토한 서비스만 `overrides/`에 두고 그것만 활성화**합니다. 검토 안 된 서비스는 `enabled: false`로 남습니다.

서비스 항목: `service`, `client`(boto3 이름), `scope`(`regional`/`global`), `tier`, `collector`, `enabled`,
`enablement_api`(리전별 활성화 판정에 쓰는 API), `api_region`(글로벌 서비스의 호출 리전), `apis[]`.

API 항목

| 필드 | 의미 |
|---|---|
| `api` | boto3 메서드 이름 (읽기 전용만 허용). 같은 API를 두 번 부르면 `alias`로 구분 |
| `client` | 서비스 기본 클라이언트와 다를 때 (예: `logs`, `s3control`, `bedrock-agent`) |
| `paginate`, `parameters` | 페이지네이션 사용, 고정 파라미터 (`{account_id}`, `{region}` 치환 가능) |
| `result_path` | 응답에서 리소스 목록 위치 (`Key`, `A.B`, `A[].B`). 없으면 응답 전체가 하나의 리소스 |
| `resource_type`, `id_field`, `arn_field` | 리소스 종류, ID, ARN 필드. `id_field: "a+b"`는 비어 있지 않은 값을 `\|`로 연결 |
| `depends_on` | `{api: <상위 API 키>, params: {요청파라미터: 상위항목필드}}`. 상위 항목마다 한 번씩 호출 |
| `as_resource` | 하위 응답의 항목을 상세가 아니라 **독립 문서**로 저장 (`inherit`, `scope_id_to_parent`와 함께) |
| `setting` | 리소스가 아니라 `account_settings`에 저장 |
| `tags_from`, `arn_from` | 상세 응답에서 태그/ARN을 꺼냄 (`list_tags.Tags`, `describe_cluster.cluster.arn`) |
| `mask` | 저장 전 가릴 값. `value:`, `b64:`, `map:`, `pairs:`, `smap:`, `spairs:` ([민감정보](#민감정보-처리)) |
| `opt_in_flag` | 이 플래그가 있을 때만 호출. 없으면 `SKIPPED`로 기록 |

`collect validate-spec`은 API가 botocore에 있는지, 필수 파라미터가 빠지지 않았는지, `result_path`/`id_field`/`arn_field`/
`depends_on` 필드가 실제 출력 구조에 있는지(오타 방지)를 검사합니다. 오류가 있으면 `collect run`이 시작되지 않습니다.

### 새 서비스를 추가하려면

1. `spec/overrides/<서비스>.yaml`을 만듭니다. 예:

   ```yaml
   service: timestream
   client: timestream-write
   scope: regional
   tier: 3
   apis:
     - {api: list_databases, result_path: Databases, resource_type: database, id_field: DatabaseName, arn_field: Arn}
     - {api: list_tables, resource_type: database, depends_on: {api: list_databases, params: {DatabaseName: DatabaseName}}}
   ```
2. `collect assemble-spec && collect validate-spec`. 오류 메시지가 틀린 필드를 알려줍니다.
3. `collect iam-policy --out-dir iam`으로 정책을 다시 만들어 Role에 반영합니다 (`tests/test_iam_policy.py`가 커밋된 정책과 명세의 일치를 검사).
4. 응답에 **비밀이 들어올 수 있으면** `mask`를 정의합니다. 그렇지 않은 서비스는 명세만으로 끝납니다.

명세만으로 안 되는 경우(두 상위 값이 함께 필요한 호출, 응답에 없는 값을 만들어야 하는 호출, 비동기 폴링)에만
`src/cspm_collector/collectors/`에 `GenericCollector`를 상속한 클래스를 만들고 `@register("이름")`으로 등록한 뒤
`collectors/__init__.py`에 import를 추가하고 명세에서 `collector: 이름`으로 지정합니다.
훅: `client_for`, `prepare_entries`, `enrich`, `sanitize_item`, `sanitize_detail`, `arn_for`, `tags_for`, `after_roots`.
예시는 `iam.py`(자격 증명 보고서 폴링), `s3.py`(버킷 리전별 클라이언트), `misc.py`(ECS/EKS 하위 문서)입니다.
수집기가 스스로 호출하는 API는 `spec/iam_policy.py`의 `HELPER_CALLS`에도 적어야 합니다 (테스트가 누락을 잡습니다).

### Prowler 버전이 올라가면

```bash
collect build-spec --prowler-root <prowler가 있는 폴더> --rules rules_master.json   # 새 collect_spec.generated.yaml
git diff spec/collect_spec.generated.yaml                                             # 새로 호출하는 API 확인
# 필요한 서비스/API를 spec/overrides/에 반영한 뒤
collect assemble-spec && collect validate-spec && collect iam-policy --out-dir iam
```

`scans.prowler_version`과 `spec_version`(소스 해시 포함)이 스캔마다 기록되어, 어떤 명세로 수집했는지 추적할 수 있습니다.

## 민감정보 처리

수집 Role은 비밀이 섞인 설정을 **읽을 수 있습니다** (Lambda 환경변수, ECS 태스크 정의, Glue Connection 등).
수집기는 이를 저장 전에 가리고 로그에도 남기지 않지만, Role과 MongoDB 접근 권한은 그만큼 민감하게 다루세요.

| 규칙 | 동작 |
|---|---|
| `value:` / `b64:` | 값 전체를 `***MASKED***`로 (b64는 디코드해 탐지 후) |
| `map:` / `pairs:` | 환경변수 맵/목록의 **값만** 가리고 이름은 남김 |
| `smap:` / `spairs:` | 비밀처럼 보이는 항목만 가림 (Glue 잡 인자, CloudFormation 파라미터·출력 등) |

적용 대상: EC2/시작 구성 UserData, Lambda 환경변수와 코드 다운로드 URL, ECS·CodeBuild·Batch·SageMaker·App Runner·Beanstalk 환경변수,
Glue Connection, Amplify 인증 정보, Direct Connect BGP 키, Step Functions 정의, SSM 문서 내용, SageMaker 수명주기 스크립트 등.
탐지 결과는 `secret_findings`에 `{location, type, line}`으로만 남습니다. 탐지는 정규식 기반이라 모든 비밀을 잡지는 못합니다.

**CloudFront 경로별 라우팅**: 관계 인덱스의 CloudFront → 오리진 선(`rel: origin`)의 `attrs`에 `origin_id`, `default`, `paths`(그 오리진으로 가는 경로 패턴, 기본 동작은 `*`), `behaviors[]`(`viewer_protocol`, `methods`, `cache_policy_id`), 오리진 그룹을 거치면 `origin_group`과 `failover_role`이 들어갑니다. CSPM 쪽 전달용 정리는 `CSPM_전달_ECS_CloudFront.md`에 있습니다.

**ECS 서비스·태스크**: `ecs`를 수집하면 클러스터, 태스크 정의에 더해 서비스(`resource_type: service`)와 **실행 중인 태스크**(`resource_type: task`, 클러스터별 `list_tasks` → 100개씩 `describe_tasks`, 태그 포함)가 따로 저장됩니다(`parent`는 클러스터). 태스크의 환경변수 오버라이드(`overrides.containerOverrides[].environment`) 값은 가립니다. 태스크 문서에는 읽기 쉽게 꺼낸 값도 최상위에 붙습니다: `service_name`(`group`이 `service:이름`일 때), `launch_type`, `container_instance_arn`, `ec2_instance_id`, `private_ips`(컨테이너 `networkInterfaces[].privateIpv4Address`). 포트 매핑(`networkBindings`)은 `config.containers[]`에 그대로 있습니다. **컨테이너 인스턴스**(`resource_type: container_instance`, EC2 시작 유형 클러스터만)도 따로 저장하고 `ec2_instance_id`를 최상위에 둡니다. 태스크는 이 값으로 EC2 서버와 이어지며, 관계 인덱스(`edges`)에는 태스크 → `belongs_to_service`(서비스), `runs_on_instance`(EC2 인스턴스), `runs_on_container_instance`, `has_private_ip`, `in_cluster`가 들어갑니다. 서비스 ARN은 새 형식(`service/<클러스터>/<서비스>`)으로 만들므로 옛 형식 서비스는 `dst_key`가 비어 보일 수 있습니다. 멈춘 태스크는 AWS에서 약 1시간만 보이므로 수집하지 않습니다. 목록 호출이 실패하면 저장된 태스크는 삭제 처리하지 않습니다. IAM에 `ecs:ListTasks`, `ecs:DescribeTasks`, `ecs:ListContainerInstances`, `ecs:DescribeContainerInstances`가 필요하므로 `iam/policy-1.json`을 Role에 다시 반영하세요. EKS Pod는 AWS API로 읽을 수 없어 수집하지 않습니다.
Secrets Manager의 비밀 **값**과 SSM 파라미터 값은 읽지 않습니다 (명세에 해당 API가 없습니다).

## 읽기 전용 IAM 정책

```bash
collect iam-policy --out-dir iam      # 현재 명세가 필요로 하는 동작만 (약 425개, 정책 3개로 분할)
```

관리형 정책 크기 제한(6144자) 때문에 `iam/policy-1.json` ~ `policy-3.json`으로 나뉩니다. 세 개를 같은 Role에 붙입니다.
`s3:Get*` 같은 와일드카드를 쓰지 않아 `s3:GetObject`, `secretsmanager:GetSecretValue`, `ssm:GetParameter`는 포함되지 않습니다.
주의: `apigateway:GET`은 API Gateway 전체 읽기이므로 필요하면 `Resource`를 좁히세요. `lambda:GetFunction`은 코드 다운로드 임시 URL을
돌려주지만 수집기는 이를 가리고 내려받지 않습니다.

대상 계정의 Role 신뢰 정책 예시 (수집기를 실행하는 쪽 계정/Role을 신뢰):

```json
{"Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::<수집기 계정>:role/<수집기 실행 Role>"},
  "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:ExternalId": "<ExternalId>"}}}]}
```

수집기 실행 Role에는 각 대상 Role에 대한 `sts:AssumeRole`이 필요합니다. Akamai는 읽기 전용 API Client(PAPI, Edge DNS, AppSec, Network Lists)를 쓰세요.

## Akamai

- 인증: EdgeGrid. `.edgerc`(`edgerc`, `section`) 또는 환경변수(`env_prefix: AKAMAI_MAIN`이면 `AKAMAI_MAIN_HOST`, `_CLIENT_TOKEN`, `_CLIENT_SECRET`, `_ACCESS_TOKEN`).
  계정 전환 키는 `account_switch_key_env`에 환경변수 이름으로 지정합니다. 키는 오류 메시지와 로그에 나오지 않습니다.
- 수집: 그룹/계약 → 속성 → 운영/스테이징 활성 버전의 호스트명과 룰 트리(원본 전체 + `origins[]` 요약).
  `origins[]`는 호스트, 포트, Host 헤더 전달 방식, 룰 경로, 상위 룰부터 누적한 조건을 담습니다. 변수 Origin(`{{user.…}}`)은 `is_variable`로 표시합니다.
  AppSec(설정, 보안 정책, 매치 타깃, 선택된 호스트명), Network Lists, Edge DNS(`collect.edge_dns: true`일 때).
- 속도: PAPI 공식 문서의 기본 한도는 계정당 분당 100회입니다. 기본 `requests_per_second: 1.5`이고 429/5xx는 `Retry-After`를 따르거나
  5초부터 시도마다 10초씩 늘려 재시도합니다. 속성이 많으면 수 분 이상 걸립니다.
- AWS와의 연결 키: Akamai Origin ↔ ELB `DNSName`/CloudFront 별칭/EIP, Route53 CNAME(`edgekey.net`) ↔ `edge_hostnames`.

## 웹 관리 페이지 (`collect web`)

```bash
collect web --config config.yaml --port 8765      # http://localhost:8765
```

- 화면은 좌측 메뉴로 나뉩니다(디자인은 팀의 FortiGate 도구를 따름): **대시보드**(환영 배너, 요약 카드, 실행 현황, 최근 실행, 환경별 분포, 빠른 작업) /
  **수집**(수집 항목, Akamai, 항목 그룹, 실행 이력, 변경 내역, 수집 건강도: 조치 필요·최근 수집 결과·데이터 신선도·응답 형식 변화·관계 인덱스) / **어카운트**(어카운트·연결 확인, 어카운트 그룹) / **시스템**(설정: 동시 실행·데이터 보관 기간·알림, 화면 변경 이력). 수집 메뉴에는 **변경 내역**(수집한 리소스의 신규·변경·삭제)이 있습니다.
  주소의 `#/items`처럼 메뉴마다 고유 주소가 있고 마지막으로 본 메뉴를 기억합니다. 메뉴 옆 배지는 실행 상태, 연결 실패 수, 그룹 수를 보여 줍니다. 좁은 화면에서는 메뉴가 위로 올라갑니다.
- 항목(서비스) 체크, 항목별 자동 수집 주기, `지금 수집`, 동시 실행 수 변경, 실행 이력(수집 건수, 시작/끝, 걸린 시간)을 한 화면에서 다룹니다. 화면은 `web/static/index.html` 한 파일이며 FastAPI가 제공합니다.
- 주기: 분 단위(5–1440분 간격), 매일, 매주(요일 복수 선택), 매달(일자, 말일 보정). 시간대는 `timezone`(기본 Asia/Seoul)입니다.
  서버가 꺼져 있던 동안 놓친 주기는 켜질 때 한 번만 실행합니다. 같은 시각에 도래한 항목은 한 번의 실행으로 묶습니다.
- **그룹**: 항목 그룹(예: "메시징" = sqs, sns, kms)과 어카운트 그룹을 만들고, 이름 변경, 멤버 추가/제거, 삭제를 할 수 있습니다. 항목 그룹은 "지금 수집"과 표 선택에 쓰고,
  어카운트 그룹은 수집 대상으로 씁니다. 설정 파일의 어카운트에 `env: dev` 라벨을 붙이면 "dev 전체" 그룹이 자동으로 생기고 라벨 변경을 따라갑니다.
- **수집 대상 어카운트**: "지금 수집"은 화면 위쪽의 대상(전체/그룹/개별)을 따르고, 자동 수집은 항목마다 "편집"에서 대상을 정합니다. 스케줄이 그룹을 대상으로 하면 실행 시점의 그룹 멤버를 씁니다.
  그룹이 삭제되었거나 비어 있으면 전체 어카운트로 넓히지 않고 그 실행을 건너뛰며 사유를 남깁니다. Akamai는 어카운트 선택과 상관없이 항상 설정된 Akamai 계정 전체를 수집합니다.
  어카운트는 두 곳에서 옵니다. 설정 파일(`accounts`)의 어카운트는 화면에서 고칠 수 없고, 화면의 `+ 어카운트 추가`로 넣은 어카운트(ID, 이름, env, 수집 Role ARN, ExternalId 환경변수 *이름*, 리전)는
  DB의 `settings` 컬렉션에 저장되어 서버를 다시 시작하지 않아도 다음 수집부터 적용됩니다. 설정 파일은 다시 쓰지 않습니다(주석 보존, 여러 서버가 같은 목록을 보도록).
  같은 ID가 양쪽에 있으면 설정 파일이 우선합니다. 삭제하면 어카운트 그룹에서도 빠지며, 수집된 데이터는 지우지 않습니다.
  **어카운트별 AWS 프로필**: 어카운트에 `profile`(이 PC의 `~/.aws/config`에 있는 SSO 프로필 이름)을 지정하면 그 프로필의 자격증명으로 해당 어카운트에 직접 들어가 수집합니다.
  어카운트마다 SSO 프로필이 이미 있으면 Role을 따로 만들 필요가 없고 `aws sso login` 한 번(같은 SSO 세션)으로 모두 유효해집니다. `role_arn`과 같이 쓰면 그 프로필로 Role을 맡습니다.
  저장할 때 프로필이 이 서버에 있는지 확인하고(`GET /api/profiles`), CSV 가져오기의 "이름이 같은 AWS 프로필 사용" 옵션을 켜면 프로필 열이 빈 줄에 같은 이름의 프로필을 자동으로 지정합니다.
  서버를 운영 서버로 옮기면 개인 SSO 프로필 대신 서버의 실행 Role을 쓰도록 `profile`을 비우고 `role_arn`을 사용하세요.
  **자격증명 확인**: 수집 전에 `sts:GetCallerIdentity`로 쓰려는 자격증명이 설정된 어카운트의 것인지 확인하고, 다르면 그 어카운트는 `AccountMismatch` 오류로 건너뜁니다
  (Role 없이 추가한 어카운트가 서버의 현재 어카운트 데이터를 다른 어카운트 ID로 저장하는 사고를 막습니다. `verify_account_identity: false`로 끌 수 있습니다).
  Role ARN의 어카운트 번호가 ID와 같은지, 리전 이름 형식, ExternalId가 값이 아닌 환경변수 이름인지 검사합니다. 비밀 값은 화면에서 입력하지 않습니다.
- **CSV 가져오기/내보내기**: 어카운트(`account_id,name,env,role_arn,external_id_env,regions`)와 그룹(`kind,name,members,action`)을 CSV로 한꺼번에 등록·수정할 수 있습니다.
  쉼표/탭/세미콜론 구분과 엑셀(UTF-8, BOM)을 지원하고, `regions`와 `members`는 공백이나 `;`로 구분합니다. "검사"로 줄별 결과(추가/수정/오류)를 먼저 보고, 한 줄이라도 오류가 있으면 아무것도 저장하지 않습니다.
  그룹의 `action`은 `set`(기본: 없으면 만들고 있으면 멤버 교체), `add`, `remove`, `delete`이며 줄 순서대로 적용됩니다. config.yaml의 어카운트와 env 자동 그룹은 CSV로 바꿀 수 없습니다.
  **엑셀로 저장한 CSV**: 엑셀은 12자리 계정 ID를 `1.24249E+11`처럼 바꾸고 앞의 0을 지웁니다. 11자리 이하 숫자는 12자리로 0을 채우고(role_arn 안의 ID도 같이), 과학 표기는 role_arn 안의 ID와 맞으면 그 값으로 복구합니다(검사 결과에 "복구" 표시).
  맞지 않는 값은 고치지 않고 오류로 남깁니다. 이미 config.yaml에 있는 어카운트의 줄은 오류가 아니라 "건너뜀"입니다.
  "CSV 내보내기"로 받은 파일을 고쳐 다시 가져오면 수정이 됩니다. 한 번에 500줄, 200KB까지입니다.
- **연결 확인**: "어카운트 목록"의 `전체 연결 확인`(또는 `보이는 것만 확인`, 줄의 `확인 안 함` 버튼)은 수집과 같은 방식으로 어카운트에 접속해 `sts:GetCallerIdentity`로 실제 어카운트를 확인합니다(읽기 전용, Role이 있으면 AssumeRole 포함, 8개씩 동시에, 71개에 약 40초).
  결과는 어카운트마다 `연결` 열에 표시되고(정상 / 프로필 없음 / SSO 로그인 필요 / 자격증명 만료 / ExternalId 환경변수 없음 / Role을 맡을 수 없음 / 다른 어카운트 / 네트워크 오류), 배지를 누르면 원인, 해결 방법, 접속된 신원 ARN이 나옵니다.
  상단 칩이나 `연결` 필터로 실패한 이유별로 모아 볼 수 있고, 최근 결과는 DB(`runtime`)에 저장되어 새로고침하거나 다른 서버에서도 보입니다. 비밀 값은 저장하지 않습니다.
  SSO 프로필들은 토큰 캐시 파일을 함께 쓰므로, 동시에 열 때 Windows에서 파일이 잠기면(`PermissionError`) 자동으로 다시 시도합니다.
- **서버 버전 확인**: 화면 파일은 열 때마다 새로 읽지만 서버는 시작할 때의 코드로 계속 돕니다. 코드를 바꾼 뒤 서버를 다시 시작하지 않으면 새 화면이 없는 기능을 호출해 `Method Not Allowed`/`Not Found`가 납니다.
  화면은 서버가 알려 주는 `api_level`을 보고, 서버가 이전 버전이면 화면 위쪽에 "서버가 이전 버전입니다" 안내를 띄우고 해당 오류도 "서버를 다시 시작하세요"로 바꿔 보여 줍니다(`web/app.py`의 `API_LEVEL`과 `index.html`의 `NEED_API`는 테스트가 같은지 검사합니다).
- **수집 항목 화면**은 순서대로 읽도록 만들었습니다: ① "수집 대상 어카운트" 카드(큰 글씨로 현재 대상과 개수, `전체`/`dev 전체` 같은 빠른 선택 버튼, 대상 중 연결 실패가 있으면 경고) → ② 항목 선택(표는 항목 / 자동 수집 / 다음 실행 / 마지막 수집 / 상태 / 버튼으로 단순화, 선택한 줄은 파랗게 표시, 예상 작업 수는 현재 대상 어카운트 기준) → ③ 화면 아래에 고정된 작업 줄(선택 개수, 대상, 예상 작업, `선택 항목 지금 수집`).
- **어카운트별 수집 로그**: 실행 이력의 `상세`는 요약 카드(어카운트 수, 문제 있는 어카운트, 작업, API 호출, 시간) 아래에 어카운트마다 한 줄(상태, 수집 수, 작업, 시간, API 성공/문제/건너뜀)을 보여 주고, 줄을 누르면 그 어카운트의 수집 항목별 결과와 **문제 로그**(상태, 호출, 리전, 전체 메시지)가 펼쳐집니다. `문제 있는 어카운트만` 필터와 `모두 펼치기/접기`가 있고, 어카운트당 로그는 80건까지 보여 줍니다(건수는 실제 값). 어카운트별 수집 수를 저장하기 전의 옛 실행도 기록된 로그로 어카운트별 표를 다시 만들어 보여 줍니다(수집 수와 시간은 "—").
- **실행 중 진행 상황**(실행 이력): 진행 중인 실행은 목록의 상태 아래에 진행 막대와 "작업 33 / 36 (92%) · 어카운트 1 / 3 완료"가 나옵니다. `상세`를 열면 위쪽에 진행 상자(지금 수집 중인 항목 포함)가 나오고, 어카운트마다 상태(대기 / 수집 중 / 완료)와 `진행` 열(그 어카운트의 작업 `10 / 12`)이 보입니다.
  줄을 누르면 항목별로 `완료 / 수집 중 / 대기`와 리전 진행(`1 / 2 리전`)이 나옵니다. 몇 초마다 자동으로 새로 고쳐지고, `아직 끝나지 않은 어카운트만` 필터가 있습니다. 작업 하나는 어카운트 × 리전 × 수집 항목 한 칸이며 끝나는 순간 기록되므로, 한창 수집 중인 큰 항목(iam, s3 등)은 끝나기 전까지 "대기"로 보일 수 있어, 그 항목이 실행 중으로 표시된 동안은 일하는 어카운트에서 "수집 중"으로 표시합니다.
- **어카운트별 결과**: 여러 어카운트를 한 번에 수집하면 실행 이력의 `상세`에 어카운트마다 한 줄(상태, 작업, 수집 수, 걸린 시간, 오류/비고)이 나오고, 줄을 누르면 그 어카운트에서 수집한 항목(서비스)별 작업/수집 수/시간이 펼쳐집니다.
  열지 못한 어카운트(예: 프로필 불일치)도 사유와 함께 표시됩니다. 실행 중에는 "실행 현황"에 어카운트별 진행(`이름 2/7`)이 나오고, 문제 목록에도 어카운트 이름이 붙습니다. 이 정보는 `scans.summary.accounts`에 저장됩니다.
- 수집 항목 표는 티어(Tier 1/2/3)별로 접고 펼 수 있습니다. 티어 줄을 누르거나 `▼/▶` 버튼을 누르고, `티어 모두 접기` / `모두 펼치기`와 티어 줄의 체크박스(그 티어 전체 선택)도 있습니다. 접은 상태는 브라우저에 기억됩니다.
- 그룹은 카드의 `편집`(이름, 멤버)과 `삭제` 버튼으로도 바로 고칠 수 있습니다. 삭제하면 그 그룹을 대상으로 쓰던 자동 수집은 전체로 넓어지지 않고 건너뜁니다.
- 한 번에 하나의 실행만 처리합니다. 실행 중이거나 대기 중인 항목은 다시 접수되지 않고 사유가 표시됩니다. 실행 취소는 실행 이력과 실행 현황의 `취소` 버튼으로 합니다(이미 시작한 작업은 끝까지 하고, 취소한 실행은 삭제 표시를 하지 않습니다).
- 스케줄/동시 실행 설정/감사 기록은 `schedules`, `settings`, `audit`, `runtime` 컬렉션(접두사 포함)에 저장됩니다. 여러 서버를 띄워도 `runtime`의 임대(lease)로 한 곳만 스케줄을 발사합니다.
- 접근 제어: 기본은 localhost만 허용합니다. 다른 주소로 열려면 `CSPM_WEB_TOKEN`(Bearer 토큰), `--user-header`(SSO 프록시가 넣는 사용자 헤더), 또는 `--no-auth` 중 하나가 필요합니다.
  변경 요청은 `X-CSPM-UI` 헤더가 있어야 하고, Host는 허용 목록만 받습니다.

## 문제 해결

| 증상 | 원인과 조치 |
|---|---|
| `ForeignCollectionError` | 대상 DB에 같은 이름의 컬렉션이 이미 있습니다. 다른 DB 이름을 쓰세요 (기존 DB는 건드리지 않습니다) |
| `ACCESS_DENIED` 행 | 정책 누락. `collect status`에 나온 API의 동작을 Role에 추가 (`collect iam-policy` 재생성) |
| `NOT_ENABLED` 행 | 해당 서비스가 그 리전에서 꺼져 있음 (정상 결과). `<서비스>_enablement` 설정이 `enabled: false` |
| `NOT_SUPPORTED`, 많은 `ERROR` | 그 리전에 서비스가 없거나 옵트인 리전이 비활성입니다. `--regions`로 제한하세요 |
| `THROTTLED_GIVEUP` | 재시도 후에도 제한에 걸림. `concurrency`를 낮추고 `--retry-failed`로 다시 |
| Akamai `HTTP 429` | `requests_per_second`를 낮추세요 |
| `CERTIFICATE_VERIFY_FAILED` (Route 53, CloudFront, WAF Classic, S3 전역 엔드포인트 등) | 사내 TLS 검사 프록시(예: Zscaler)가 일부 AWS 호스트의 인증서를 자체 CA로 다시 서명합니다. `collect export-ca-bundle --out ca-bundle.pem`으로 OS 신뢰 루트를 합친 번들을 만들고 `AWS_CA_BUNDLE`(AWS)과 `REQUESTS_CA_BUNDLE`(Akamai) 환경변수로 지정하세요. S3는 리전 엔드포인트를 쓰므로 영향이 없습니다 |
| 스캔 `PARTIAL` | 일부 범위 실패. `collect status`로 확인 후 `--retry-failed` |

## 개발과 테스트

```bash
.venv/Scripts/python -m pytest -q                 # 전체 (약 2~3분: moto 기반 통합 테스트가 느립니다)
.venv/Scripts/python -m pytest -q tests/test_masking.py tests/test_iam_policy.py   # 빠른 단위 테스트
```

- AWS는 moto, MongoDB는 mongomock, Akamai는 가짜 응답으로 시험합니다. 테스트가 실제 자격증명을 쓰지 않도록 `conftest.py`가 가짜 자격증명을 강제합니다.
- moto는 일부 API를 구현하지 않습니다. 그런 호출은 에러 행으로 기록되는 것까지만 확인합니다.
- `tests/flow_helpers.py`의 공용 환경을 쓰는 모듈 단위 테스트와 격리가 필요한 테스트(`test_flow_isolated.py`)는 모듈을 분리했습니다. moto 상태가 모듈 안에서 공유되기 때문입니다.

## 더 읽을 것

- [가정과 열린 이슈](docs/assumptions-and-open-issues.md): 검증된 것/안 된 것, 설계 가정, 미구현 항목
#   c s p m - c o l l e c t o r  
 