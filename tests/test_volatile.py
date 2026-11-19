from datetime import datetime, timedelta, timezone

import mongomock

from cspm_collector.core.config import MongoSettings
from cspm_collector.storage.records import ResourceRecord
from cspm_collector.storage.store import Store
from cspm_collector.storage.volatile import stable_view, volatile_values

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def store():
    s = Store(mongomock.MongoClient()["d"], MongoSettings())
    s.init_db()
    return s


def role(last_used, max_session=3600, name="app"):
    return ResourceRecord("1", "global", "iam", "role", name, config={
        "RoleName": name, "MaxSessionDuration": max_session,
        "_details": {"get_role": {"Role": {"RoleLastUsed": {"LastUsedDate": last_used, "Region": "ap-northeast-2"}}}}})


def doc(s, rec):
    return s.db.resources.find_one({"_id": rec.key})


def test_last_used_changes_are_not_history_but_the_stored_value_stays_current():
    s = store()
    s.save_resources("s1", [role("2026-10-21T07:02:17+00:00")], now=T0)
    st = s.save_resources("s2", [role("2026-10-21T07:07:58+00:00")], now=T0 + timedelta(hours=1))
    assert (st.updated, st.unchanged, st.history) == (0, 1, 0)
    d = doc(s, role("x"))
    assert d["config"]["_details"]["get_role"]["Role"]["RoleLastUsed"]["LastUsedDate"] == "2026-10-21T07:07:58+00:00"
    assert d["scan_id"] == "s2" and d["config_changed_at"] == T0.replace(tzinfo=None)  # the config itself did not change
    assert s.db.resource_history.count_documents({}) == 0


def test_a_real_change_still_records_history_with_the_old_last_used_value():
    s = store()
    s.save_resources("s1", [role("2026-10-21T07:02:17+00:00", max_session=3600)], now=T0)
    st = s.save_resources("s2", [role("2026-10-21T08:00:00+00:00", max_session=7200)], now=T0 + timedelta(hours=1))
    assert (st.updated, st.history) == (1, 1)
    h = s.db.resource_history.find_one({})
    assert h["config"]["MaxSessionDuration"] == 3600
    assert h["config"]["_details"]["get_role"]["Role"]["RoleLastUsed"]["LastUsedDate"] == "2026-10-21T07:02:17+00:00"
    assert doc(s, role("x"))["config"]["MaxSessionDuration"] == 7200


def test_a_role_that_was_never_used_has_nothing_to_refresh():
    s = store()
    bare = ResourceRecord("1", "global", "iam", "role", "r", config={"RoleName": "r", "_details": {"get_role": {"Role": {}}}})
    s.save_resources("s1", [bare], now=T0)
    assert s.save_resources("s2", [bare], now=T0).unchanged == 1


def test_credential_report_usage_columns_are_volatile():
    def row(used):
        return ResourceRecord("1", "global", "iam", "credential_report_row", "alice", config={
            "user": "alice", "mfa_active": "true", "password_last_used": used, "access_key_1_last_used_date": used,
            "_generated_time": used})

    s = store()
    s.save_resources("s1", [row("2026-10-01T00:00:00+00:00")], now=T0)
    assert s.save_resources("s2", [row("2026-10-02T00:00:00+00:00")], now=T0).unchanged == 1
    assert doc(s, row("x"))["config"]["password_last_used"] == "2026-10-02T00:00:00+00:00"

    flipped = row("2026-10-02T00:00:00+00:00")
    flipped.config["mfa_active"] = "false"  # MFA switched off is a real change
    assert s.save_resources("s3", [flipped], now=T0).updated == 1


def route_table(assoc, service="vpc"):
    return ResourceRecord("1", "r", service, "route_table", "rtb-1", config={"RouteTableId": "rtb-1", "Associations": assoc})


def test_unordered_lists_compare_as_sets_only_where_declared():
    a = [{"RouteTableAssociationId": "rtbassoc-1", "SubnetId": "subnet-1"}, {"RouteTableAssociationId": "rtbassoc-2", "SubnetId": "subnet-2"}]
    s = store()
    s.save_resources("s1", [route_table(a)], now=T0)
    assert s.save_resources("s2", [route_table(list(reversed(a)))], now=T0).unchanged == 1  # AWS reordered them
    assert s.save_resources("s3", [route_table(a[:1])], now=T0).updated == 1  # one association removed: real change

    other = store()
    other.save_resources("s1", [route_table(a, service="other")], now=T0)
    # the same reordering for a type that is not declared unordered still counts as a change
    assert other.save_resources("s2", [route_table(list(reversed(a)), service="other")], now=T0).updated == 1


def test_helpers():
    cfg = {"a": {"b": 1}, "Associations": [{"x": 2}, {"x": 1}]}
    assert stable_view("ec2", "instance", cfg) is cfg  # untouched types are not even copied
    view = stable_view("vpc", "route_table", cfg)
    assert view["Associations"] == [{"x": 1}, {"x": 2}] and cfg["Associations"][0] == {"x": 2}  # input is not modified
    assert volatile_values("iam", "role", {"_details": {"get_role": {"Role": {"RoleLastUsed": {"a": 1}}}}}) == {
        "_details.get_role.Role.RoleLastUsed": {"a": 1}}
    assert volatile_values("iam", "role", {"RoleName": "r"}) == {}


def test_restorable_time_of_rds_clusters_is_volatile():
    def cluster(latest, retention=7):
        return ResourceRecord("1", "r", "rds", "db_cluster", "c1", config={
            "DBClusterIdentifier": "c1", "BackupRetentionPeriod": retention, "LatestRestorableTime": latest})

    s = store()
    s.save_resources("s1", [cluster("2026-10-21T07:20:39+00:00")], now=T0)
    assert s.save_resources("s2", [cluster("2026-10-21T07:22:40+00:00")], now=T0).unchanged == 1
    assert doc(s, cluster("x"))["config"]["LatestRestorableTime"] == "2026-10-21T07:22:40+00:00"
    assert s.save_resources("s3", [cluster("2026-10-21T07:30:00+00:00", retention=1)], now=T0).updated == 1  # backups shortened


def test_trusted_advisor_results_are_stored_fresh_but_never_a_change():
    def check(ts, resources, status="warning", name="Idle Load Balancers"):
        return ResourceRecord("1", "global", "trustedadvisor", "check", "c1", config={
            "id": "c1", "name": name, "_details": {"describe_trusted_advisor_check_result": {"result": {
                "timestamp": ts, "status": status, "flaggedResources": resources}}}})

    a = [{"resourceId": "r1", "region": "ap-northeast-2"}, {"resourceId": "r2", "region": "ap-northeast-1"}]
    s = store()
    s.save_resources("s1", [check("2026-10-21T07:38:18Z", a)], now=T0)
    # a different cached snapshot: older timestamp, other order, other status, fewer resources
    snap = check("2026-10-20T07:44:50Z", a[:1], status="ok")
    assert s.save_resources("s2", [snap], now=T0).unchanged == 1
    stored = doc(s, snap)["config"]["_details"]["describe_trusted_advisor_check_result"]["result"]
    assert stored["status"] == "ok" and stored["timestamp"] == "2026-10-20T07:44:50Z" and len(stored["flaggedResources"]) == 1
    assert s.db.resource_history.count_documents({}) == 0
    # the check definition itself changing is still a change
    assert s.save_resources("s3", [check("2026-10-21T08:00:00Z", a, name="Idle Load Balancers (v2)")], now=T0).updated == 1


def test_ssm_agent_pings_are_volatile():
    def inst(ping):
        return ResourceRecord("1", "r", "ssm", "managed_instance", "i-1", config={
            "InstanceId": "i-1", "PingStatus": "Online", "LastPingDateTime": ping})

    s = store()
    s.save_resources("s1", [inst("2026-10-21T16:33:15+09:00")], now=T0)
    assert s.save_resources("s2", [inst("2026-10-21T16:38:15+09:00")], now=T0).unchanged == 1
