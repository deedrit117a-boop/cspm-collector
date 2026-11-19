from cspm_collector.core.errors import Status
from cspm_collector.storage.records import StatusRecord, SweepScope
from cspm_collector.storage.sweep import derive_scan_status, sweepable_scopes


def row(service, api, status, rtype=None, region="r1", account="a"):
    return StatusRecord(account, region, service, api, status, resource_type=rtype)


def test_all_success_sweeps_everything():
    rows = [row("ec2", "describe_instances", Status.SUCCESS, "instance"),
            row("ec2", "describe_volumes", Status.SUCCESS, "volume")]
    assert sweepable_scopes(rows) == [SweepScope("a", "r1", "ec2", None)]


def test_failed_scope_is_never_swept():
    rows = [row("s3", "list_buckets", Status.ACCESS_DENIED)]
    assert sweepable_scopes(rows) == []


def test_partial_scope_sweeps_only_good_types():
    rows = [row("ec2", "describe_instances", Status.SUCCESS, "instance"),
            row("ec2", "describe_volumes", Status.THROTTLED_GIVEUP, "volume")]
    assert sweepable_scopes(rows) == [SweepScope("a", "r1", "ec2", frozenset({"instance"}))]


def test_untyped_failure_blocks_whole_scope():
    rows = [row("ec2", "describe_instances", Status.SUCCESS, "instance"),
            row("ec2", "describe_x", Status.ERROR)]
    assert sweepable_scopes(rows) == []


def test_skipped_and_not_enabled_are_not_swept():
    assert sweepable_scopes([row("guardduty", "list_detectors", Status.NOT_ENABLED)]) == []
    assert sweepable_scopes([row("ec2", "describe_instances", Status.SKIPPED)]) == []


def test_scan_status():
    ok, bad = row("a", "x", Status.SUCCESS), row("a", "y", Status.ERROR)
    assert derive_scan_status([ok, row("a", "z", Status.NOT_ENABLED)]) == "COMPLETED"
    assert derive_scan_status([ok, bad]) == "PARTIAL"
    assert derive_scan_status([bad]) == "FAILED" and derive_scan_status([]) == "FAILED"
