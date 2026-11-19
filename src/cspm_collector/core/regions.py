"""Find the regions an AWS account really uses, without any cost (read-only list calls, one item each).

``DescribeRegions`` only says which regions are *enabled*. Here every enabled region gets a few cheap probes and a
region counts as used when one of them finds something. The probes are free (EC2 / SQS / SNS / Lambda / DynamoDB list
calls); no Cost Explorer. A region where every probe failed (an SCP that denies the region, a missing permission) is
reported as ``unknown`` and never as unused, so that nothing is silently dropped from a collection.

What the probes cannot see: a region that only holds services outside this list (for example only an S3-less
CloudFormation stack). Pin such regions yourself (``always``).
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from botocore.config import Config

from .session import AccountSession, region_supported

DETECT_WORKERS = 12
# short timeouts: a probe that hangs in a blocked region must not hold the whole detection
DETECT_CONFIG = Config(retries={"mode": "standard", "max_attempts": 2}, connect_timeout=5, read_timeout=15,
                       max_pool_connections=DETECT_WORKERS * 2, user_agent_extra="cspm-collector-regions")

USED, UNUSED, UNKNOWN = "used", "unused", "unknown"


@dataclass(frozen=True)
class Probe:
    key: str
    label: str  # shown as the evidence for a region
    client: str  # boto3 client name
    found: Callable[[object], bool]  # runs the call; True when it finds something


def _enis(c) -> bool:
    return bool(c.describe_network_interfaces(MaxResults=5)["NetworkInterfaces"])


def _custom_vpcs(c) -> bool:
    return bool(c.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["false"]}])["Vpcs"])


def _instances(c) -> bool:
    return any(r["Instances"] for r in c.describe_instances(MaxResults=5)["Reservations"])


PROBES: tuple[Probe, ...] = (
    Probe("eni", "네트워크 인터페이스", "ec2", _enis),  # EC2, load balancers, RDS, VPC Lambda, endpoints, NAT ...
    Probe("vpc", "기본이 아닌 VPC", "ec2", _custom_vpcs),
    Probe("ec2", "EC2 인스턴스", "ec2", _instances),
    Probe("sqs", "SQS 큐", "sqs", lambda c: bool(c.list_queues(MaxResults=1).get("QueueUrls"))),
    Probe("sns", "SNS 토픽", "sns", lambda c: bool(c.list_topics().get("Topics"))),
    Probe("lambda", "Lambda 함수", "lambda", lambda c: bool(c.list_functions(MaxItems=1).get("Functions"))),
    Probe("dynamodb", "DynamoDB 테이블", "dynamodb", lambda c: bool(c.list_tables(Limit=1).get("TableNames"))),
)


@dataclass
class RegionResult:
    region: str
    state: str = UNKNOWN
    evidence: list[str] = field(default_factory=list)  # labels of the probes that found something
    errors: dict[str, str] = field(default_factory=dict)  # probe key -> exception class name
    pinned: bool = False  # kept because the caller asked for it (``always``), whatever the probes found


@dataclass
class Detection:
    regions: list[RegionResult]
    seconds: float

    def by_state(self, state: str) -> list[str]:
        return [r.region for r in self.regions if r.state == state]

    @property
    def collect(self) -> list[str]:
        """Regions to collect: used + pinned (``unknown`` ones are reported separately, never added silently)."""
        return [r.region for r in self.regions if r.state == USED or r.pinned]


def detect_used_regions(sess: AccountSession, *, always: tuple[str, ...] = (), probes: tuple[Probe, ...] = PROBES,
                        workers: int = DETECT_WORKERS) -> Detection:
    began = time.perf_counter()
    enabled = sess.enabled_regions(include_opt_in=True)
    results = {r: RegionResult(r, pinned=r in always) for r in enabled}
    ok_probes: dict[str, int] = {r: 0 for r in enabled}

    def run(region: str, probe: Probe):
        if not region_supported(probe.client, region):
            return region, probe, None, None  # the service does not exist there: not a failure, not a finding
        try:
            return region, probe, probe.found(sess.client(probe.client, region)), None
        except Exception as exc:  # noqa: BLE001 - any failure of one probe is only "I could not tell"
            return region, probe, None, type(exc).__name__

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(enabled) * len(probes) or 1))) as pool:
        futures = [pool.submit(run, r, p) for r in enabled for p in probes]
        for fut in futures:
            region, probe, found, error = fut.result()
            res = results[region]
            if error:
                res.errors[probe.key] = error
            elif found is not None:
                ok_probes[region] += 1
                if found:
                    res.evidence.append(probe.label)
    for region, res in results.items():
        res.state = USED if res.evidence else UNUSED if ok_probes[region] else UNKNOWN
    return Detection(sorted(results.values(), key=lambda r: r.region), round(time.perf_counter() - began, 1))


def open_session(account) -> AccountSession:
    """The detection session of an account: the same credentials as a collection, with short timeouts."""
    return AccountSession(account, client_config=DETECT_CONFIG)
