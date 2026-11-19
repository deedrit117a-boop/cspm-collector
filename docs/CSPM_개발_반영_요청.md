# 수집기 → CSPM 프로그램: 반영 요청과 데이터 변경 안내

작성: 2026-10-30 · 대상: CSPM(점검 도구) 개발 · 수집기: `D:\GIT\cspm_collector`
컬렉션 이름은 `collection_prefix`(기본 `cspm_`)가 앞에 붙습니다. 예: `edges` → `cspm_edges`.

이 문서는 세 부분입니다. (1) 수집기가 새로 저장하는 데이터와 바뀐 규칙, (2) CSPM 쪽에서 해 주셨으면 하는 일, (3) 수집기가 하지 않는 일(한계). 맨 아래에 반영 후 확인용 쿼리를 모았습니다.

---

## 1. 수집기에서 바뀐 것 (데이터 계약)

### 1-1. 새로 수집하는 항목

| 위치 | `service` / `resource_type` | 내용 |
|---|---|---|
| `resources` | `wafv2`, `wafv2_cloudfront` / `ip_set` | IP 집합. 주소는 `config._details.get_ip_set.IPSet.Addresses`, 버전은 `IPAddressVersion`. `resource_id`와 `arn`은 IP 집합 ARN. |
| `akamai_raw` | `akamai` / `appsec_ip_geo_firewall` | 정책별 IP/Geo 방화벽. `resource_id`=`{configId}\|{policyId}`. `config.block`(모드), `config.ipControls.blockedIPNetworkLists.networkList`(차단 리스트 ID), `...allowedIPNetworkLists.networkList`(허용), `config.geoControls`, `config.asnControls`. |
| `akamai_raw` | `akamai` / `appsec_policy_custom_rules` | 정책이 쓰는 커스텀 룰과 동작. `resource_id`=`{configId}\|{policyId}`. `config.customRules[]` = `{ruleId, name, action, isDeleted}`. |
| `akamai_raw` | `akamai` / `appsec_custom_rule` | 커스텀 룰 상세(조건). `resource_id`=`{configId}\|{ruleId}`. `config.conditions[]`에 `networkListMatch`(`value`=리스트 ID) 등. 삭제된 룰은 수집하지 않음. |
| `akamai_raw` | `akamai` / `appsec_bypass_network_lists` | 설정별 우회 리스트. **이 계약(상품)에서는 "Feature not available in this product"(HTTP 400)로 쓸 수 없어 문서가 없습니다.** 문서 없음 = 미지원이지 "우회 리스트 없음"이 아닙니다 (`collection_status`에 `NOT_SUPPORTED`). |

공통 메타(`extra`): `config_id`, `config_name`, `version`, `version_source`(production → staging → latest), 정책 단위 문서는 `policy_id`, 커스텀 룰은 `rule_id`, `rule_version`.
네트워크 리스트는 기존 `akamai_raw` `network_list`(`resource_id`=`uniqueId`)와 ID로 연결됩니다.

### 1-2. 관계 인덱스: `edges` 컬렉션 (신규, 가장 중요)

리소스 사이의 관계를 문서 하나씩 미리 풀어 둔 것입니다. 구성을 매번 파싱하지 않고 인덱스 조회로 따라갈 수 있습니다. 코드: `src/cspm_collector/core/edges.py`.

문서 형태

```json
{ "_id": "sha1", "account_id": "...", "region": "...", "service": "...", "resource_type": "...",
  "src_key": "resources._id", "src_id": "resource_id", "rel": "uses_security_group",
  "dst_type": "security_group", "dst_id": "sg-1", "dst_key": "resources._id 또는 null",
  "attrs": {"...": "..."} | null, "scan_id": "...", "last_seen": "...", "deleted_at": null }
```

- `account_id/region/service/resource_type`은 **출발(source) 리소스**의 값입니다.
- `src_key`는 출발 리소스 문서의 `_id`입니다(AWS는 `resources`, Akamai는 `akamai_raw`).
- `dst_key`는 도착이 저장된 리소스일 때 그 `_id`입니다. 도착이 **가상 노드**(`hostname`, `ip`)면 `null`이고 `dst_type`+`dst_id`로 찾습니다.
- `deleted_at`이 `null`인 것이 현재 유효한 관계입니다. 완전히 수집된 범위에서 더 이상 보이지 않으면 삭제 표시되고, 다시 보이면 되살아납니다.
- `hostname`은 소문자, 끝의 `.` 없음. 호스트명 노드가 시스템을 잇습니다: CloudFront 오리진, ALB의 `DNSName`, Route 53 레코드, Akamai 오리진/호스트가 같은 `hostname` 노드를 가리킵니다.

관계(`rel`) 목록

| 출발 | `rel` | 도착 | `attrs` |
|---|---|---|---|
| ec2 `instance` | `uses_security_group` / `in_subnet` / `has_network_interface` / `has_public_ip` | `security_group` / `subnet` / `network_interface` / `ip` | |
| ec2 `network_interface` | `uses_security_group` / `attached_to` / `in_subnet` / `has_public_ip` | `security_group` / `instance` / `subnet` / `ip` | |
| ec2 `security_group` | `allows_from_security_group`, `allows_to_security_group` | `security_group` | `protocol`, `from`, `to` |
| ec2 `elastic_ip` | `has_public_ip`, `associated_with` | `ip`, `instance`/`network_interface` | |
| elbv2 `load_balancer` | `uses_security_group`, `in_subnet`, `has_hostname` | | |
| elbv2 `listener` / `listener_rule` | `belongs_to`, `forwards_to` | `load_balancer`·`listener` / `target_group` | |
| elbv2 `target_group` | `attached_to`, `targets` | `load_balancer`, `instance` 또는 `ip` | |
| elb `load_balancer` | `uses_security_group`, `targets`, `has_hostname` | | |
| wafv2 / wafv2_cloudfront `web_acl` | `protects` | ALB 등 리소스(ARN), CloudFront `distribution` | |
| 〃 | `references_ip_set`, `references_rule_group` | `ip_set`, `rule_group` | `rule`, `priority`, `action`(Allow/Block/Count/…, 룰 그룹 재정의는 `override:…`), `negated`(NotStatement 안이면 true) |
| cloudfront `distribution` | `protected_by`, `has_hostname`, `serves_hostname`, `origin` | `web_acl`, `hostname` | |
| route53 `record_set` | `has_hostname`, `points_to` | `hostname` 또는 `ip` | `type`, `alias` |
| akamai `property_version` | `serves_hostname`, `uses_edge_hostname`, `origin` | `hostname` | `network` |
| akamai `appsec_match_target` | `uses_policy`, `applies_to_hostname` | `appsec_policy`, `hostname` | |
| akamai `appsec_config` | `selected_hostname` | `hostname` | |
| akamai `appsec_ip_geo_firewall` | `blocks_list`, `allows_list` | `network_list` | `kind`(ip/geo/asn), `mode` |
| akamai `appsec_policy_custom_rules` | `uses_custom_rule` | `appsec_custom_rule` | `action`, `name` |
| akamai `appsec_custom_rule` | `matches_list` | `network_list` | `positive` |

아직 관계로 풀지 않은 것: S3 오리진, API Gateway, 보안 그룹의 CIDR 규칙(규칙 내용은 `security_group.config`를 그대로 읽으세요), 네트워크 ACL, 라우팅. 필요한 관계는 요청해 주시면 `edges.py`에 추출 함수를 추가합니다.

### 1-3. 수집 실행 기록의 바뀐 점

| 항목 | 내용 |
|---|---|
| `scans.status` | `COMPLETED`, `PARTIAL`, `FAILED`, **`CANCELLED`(신규)**, `INTERRUPTED`. `CANCELLED`는 사용자가 중간에 멈춘 실행으로 **일부만 읽었고 삭제 표시(sweep)를 하지 않았습니다.** |
| `scans.options.trigger.type` | `manual`, `schedule`, `cli`, **`retry`(신규: 일시적 실패만 자동 재수집)**. `retry` 실행은 일부 항목만 담습니다. 전체 수와 비교하는 용도로 쓰면 안 됩니다. |
| `scans.options.preflight_excluded` | 실행 전 점검에서 접속할 수 없어 뺀 어카운트 ID 목록 (신규). |
| 어카운트별 결과 | `scans.summary.accounts`는 **`scan_accounts` 컬렉션으로 이동**했습니다(스캔×어카운트당 문서 1개: `status`, `tasks`, `resources`, `seconds`, `statuses`, `error`, `services`). 이전 스캔은 예전 위치에 남아 있습니다. |
| `scan_accounts.services.<항목>` | `tasks`, `resources`, `seconds`, **`failed`(신규: 그 항목에서 실패한 API 행 수)**. 실패가 0인 마지막 수집을 알 수 있습니다. |
| `collection_status` | 계정 단위 실패 행은 `region="*"`, `service="*"`입니다. `error_code`는 `SSO_LOGIN_NEEDED`, `ASSUME_DENIED`, `EXTERNAL_ID_ENV_MISSING`, `ACCOUNT_MISMATCH` 같은 점검 코드이거나 예외 이름이고, `error`에 이유와 해결 방법이 들어 있습니다. Akamai 응답 형식이 바뀌면 `error_code="UNEXPECTED_RESPONSE"`. |
| `scans.summary.shape_changes` | 정상으로 끝난 실행에서 AWS 응답의 필드가 바뀐 항목 목록 (신규): `{service, resource_type, count, added[], removed[]}`. 필드 이름만 담고 값은 없습니다. 비어 있으면 변화 없음. |
| `scan_accounts.services.<항목>.reused` | 변경 시각이 그대로라 상세 호출을 건너뛰고 저장된 값을 쓴 리소스 수 (신규, Lambda·CloudFront). 이 리소스의 `config`는 지난 수집 때 읽은 상세 값이며, 7일(`full_refresh_days`)마다 전부 다시 읽습니다. |
| `resources.detail_checked_at` | 상세를 마지막으로 전부 읽은 시각 (신규, 해당 항목만). `last_seen`과 다를 수 있습니다. |
| 리전 | 어카운트마다 수집 리전이 다릅니다(지정하면 그 리전만, 비우면 활성 리전 전체). 리전이 목록에 없다는 사실이 "그 리전에 리소스가 없다"는 뜻은 아닙니다. 수집기는 목록에 없는 사용 리전을 감지해 알려 줍니다(`runtime` 문서 `region_detect`). |

### 1-4. 삭제와 신선도에 대한 약속

- `deleted_at`은 **완전히 읽은 범위(어카운트·리전·항목)에서 이번 스캔에 보이지 않은 것**에만 붙습니다. 실패한 범위, 취소된 실행, 열 수 없던 어카운트의 데이터는 그대로 남고 **오래될 수 있습니다.** 오래됐는지는 `last_seen`과 `scans`의 시각으로 판단하세요.
- 수집이 `COMPLETED`여도 특정 항목만 계속 실패할 수 있습니다. 그런 항목의 데이터는 점점 낡습니다(수집기의 "데이터 신선도" 화면이 이를 보여 줍니다).

---

## 2. CSPM 프로그램에 반영해 주실 것

우선순위는 효과 대비 작업량입니다.

### P1 (바로 효과)

1. **ACL 검색을 `edges` 기반으로** — 요청해 주신 두 가지가 모두 데이터로 준비됩니다.
   - **AWS WAF**: IP 집합 내용으로 판정하세요. 입력 IP가 `ip_set.config._details.get_ip_set.IPSet.Addresses`(CIDR 포함)에 들어 있는 집합을 찾고, `edges`에서 `rel=references_ip_set`·`dst_key=<그 IP 집합의 _id>`인 관계로 규칙(`attrs.rule`, `attrs.action`)을 얻습니다. **`attrs.negated=true`는 "이 집합에 없는 IP"에 규칙이 적용된다는 뜻**이라 결과를 뒤집어 해석해야 합니다. 그 웹 ACL이 보호하는 대상은 `rel=protects`입니다.
   - **Akamai WAF**: IP가 들어 있는 `network_list`를 찾고, `edges`에서 `dst_id=<리스트 ID>`로 `blocks_list`(차단), `allows_list`(허용), `matches_list`(커스텀 룰 조건)를 따라 정책과 용도를 얻습니다. 정책이 적용되는 호스트명은 `appsec_match_target`의 `uses_policy` + `applies_to_hostname`입니다. 우회 리스트는 이 계약에서는 쓸 수 없습니다(위 1-1).
   - **IP로 시작하는 검색**: `dst_type=ip`로 찾으면 그 공인 IP가 붙은 인스턴스, 네트워크 인터페이스, 탄력적 IP를 바로 얻고, 그 보안 그룹은 `uses_security_group`으로 이어집니다.
2. **"확인 불가"와 "문제 없음"을 구분해서 표시** — 수집 실패나 낡은 데이터를 비어 있는 결과로 보여 주면 안 됩니다. 판단 재료:
   - 어카운트가 `scans.options.preflight_excluded`에 있거나 `scan_accounts.status`가 `FAILED`/`PARTIAL`
   - `scan_accounts.services.<항목>.failed > 0`
   - `last_seen`이 오래됨
   - 해당 `collection_status`가 `ACCESS_DENIED`, `UNEXPECTED_RESPONSE` 등
3. **변경 내역 화면** — `resource_history`(변경 전 설정)와 `deleted_at`으로 "지난 수집 이후 추가, 삭제, 변경"을 어카운트·항목·기간으로 보여 줍니다. `retry` 실행이 만든 변경도 정상적인 변경입니다(나중에 일부 항목만 다시 읽은 것).

### P2

4. **조회 화면과 읽기 API**: 자주 쓰는 질의(예: 0.0.0.0/0을 여는 보안 그룹)를 템플릿으로 저장하고 CSV로 내보냅니다. 다른 도구용 페이지 단위 API도 필요합니다.
5. **알림**: 점검 결과의 새 위반, 수집 실패와 신선도 경고(규칙별로 묶고 반복은 걸러서).
6. **노출 경로**: `edges`를 따라 `ip`/`hostname` → Akamai 속성 → 오리진 호스트명 → ALB → 대상 그룹 → 인스턴스 → 보안 그룹으로 이어지는 경로를 보여 줍니다. 한 방향 조회만으로 구현할 수 있습니다.

### P3

7. 점검 규칙별 점수, 규정(CIS 등) 연결. 태그(담당 팀) 기준 묶기(`resources.tags`는 키 정렬된 `[{key,value}]`로 정규화되어 있습니다).

---

## 3. 수집기가 하지 않는 것 / 알아둘 한계

- 수집은 읽기 전용(Akamai는 GET만)입니다. 설정을 바꾸거나 활성화하지 않습니다.
- 사용 리전 감지는 EC2·SQS·SNS·Lambda·DynamoDB 목록 1건만 확인합니다. 그 서비스를 쓰지 않는 리전은 놓칠 수 있어, 감지는 **제안**이고 적용은 사람이 합니다.
- `edges`는 수집 시점의 구성으로 만든 것입니다. 같은 스캔에서 다른 어카운트·리전 사이의 관계는 도착 리소스가 아직 저장되지 않았을 수 있어(`dst_key`로 조회했을 때 문서가 없을 수 있음) 항상 존재 여부를 확인하세요.
- Akamai 커스텀 룰 상세는 설정당 룰 수만큼 호출해서 수집 시간이 늘어납니다. 삭제된 룰은 제외합니다.
- 스캔이 취소되면 그 범위의 데이터는 이전 값 그대로입니다.

---

## 4. 반영 후 확인용 쿼리 (mongosh, 접두사 `cspm_`)

```js
// WAF: IP 집합 문서 수가 웹 ACL 규칙이 참조하는 IP 집합 수 이상인지
db.cspm_resources.countDocuments({service: {$in: ["wafv2", "wafv2_cloudfront"]}, resource_type: "ip_set", deleted_at: null})
db.cspm_edges.distinct("dst_id", {rel: "references_ip_set", deleted_at: null}).length

// Akamai: 정책 방화벽 문서가 정책 수(현재 33)만큼 있는지
db.cspm_akamai_raw.countDocuments({resource_type: "appsec_ip_geo_firewall", deleted_at: null})

// 이 IP(공인)가 붙은 리소스와 그 보안 그룹
db.cspm_edges.find({dst_type: "ip", dst_id: "203.0.113.9", deleted_at: null})
db.cspm_edges.find({src_key: "<위에서 나온 src_key>", rel: "uses_security_group", deleted_at: null})

// 이 ALB를 보호하는 웹 ACL
db.cspm_edges.find({rel: "protects", dst_key: "<ALB의 resources._id>", deleted_at: null})

// 이 Akamai 네트워크 리스트를 쓰는 정책(차단/허용)과 커스텀 룰
db.cspm_edges.find({dst_type: "network_list", dst_id: "1_BLOCK", deleted_at: null})

// 이 호스트명을 서빙하는 Akamai 속성과 그 오리진
db.cspm_edges.find({dst_type: "hostname", dst_id: "www.example.com", rel: "serves_hostname", deleted_at: null})
db.cspm_edges.find({src_key: "<속성 문서 _id>", rel: "origin", deleted_at: null})

// 마지막 수집에서 항목이 실패한 어카운트
db.cspm_scan_accounts.find({scan_id: "<최근 scan_id>", "services.sqs.failed": {$gt: 0}})
```

## 5. 이 문서에 대한 확인 요청

- `edges`의 `rel` 이름이나 `attrs` 구조가 읽기에 불편하면 알려 주세요(이름은 아직 바꾸기 쉽습니다).
- 추가로 필요한 관계(S3 오리진, API Gateway 등)나 `ip` 노드로 받고 싶은 대상이 있으면 알려 주세요.
- Akamai 응답 필드는 실제 서버 구조로 확인했고(정책 방화벽, 커스텀 룰 목록), 커스텀 룰 상세의 `conditions` 필드는 첫 수집 뒤 한 건 열어서 확인이 필요합니다.
