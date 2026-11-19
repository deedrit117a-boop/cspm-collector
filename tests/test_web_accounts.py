"""Accounts added on the control page: validation, merge with the file's accounts, effect on groups and runs."""
import pytest

from test_web_api import UI, items, make

OK = {"account_id": "444455556666", "name": "dev-game", "env": "dev",
      "role_arn": "arn:aws:iam::444455556666:role/CspmReadOnly", "external_id_env": "CSPM_EXTID_GAME",
      "regions": ["ap-northeast-2", "us-east-1"]}


@pytest.fixture
def web():
    client, rt, stub, store = make()
    yield client, rt, stub, store
    rt.stop()


def accounts(client):
    return {a["account_id"]: a for a in client.get("/api/overview").json()["accounts"]}


def test_added_account_shows_up_with_its_source_and_survives_a_restart(web):
    client, rt, stub, store = web
    r = client.post("/api/accounts", json=OK, headers=UI)
    assert r.status_code == 201 and r.json()["source"] == "web" and r.json()["regions"] == ["ap-northeast-2", "us-east-1"]
    acc = accounts(client)
    assert list(acc) == ["111", "444455556666"] and acc["111"]["source"] == "file"
    # tasks per item follow the new account: s3 is one per account, ec2 one per configured region (2 + 2)
    it = items(client)
    assert it["s3"]["tasks"] == 2 and it["ec2"]["tasks"] == 4
    # a second server on the same database sees it too
    client2, rt2, *_ = make()
    rt2.stop()
    from cspm_collector.web.accounts import WebAccounts
    assert [a.account_id for a in WebAccounts(store).list()] == ["444455556666"]


def test_a_run_uses_the_added_account_and_can_be_limited_to_it(web):
    client, rt, stub, _ = web
    client.post("/api/accounts", json=OK, headers=UI)
    client.post("/api/runs", json={"services": ["sqs"], "target": {"accounts": ["444455556666"]}}, headers=UI)
    assert rt.runner.wait_idle() and stub.calls[0]["accounts"] == ["444455556666"]


def test_validation_rejects_bad_ids_roles_regions_and_secrets_in_place_of_names(web):
    client, *_ = web

    def post(**over):
        return client.post("/api/accounts", json={**OK, **over}, headers=UI)

    assert post(account_id="1234").status_code == 422
    assert post(account_id="12345678901a").status_code == 422
    assert post(role_arn="arn:aws:iam::999999999999:role/X").status_code == 422  # role of another account
    assert post(role_arn="not-an-arn").status_code == 422
    assert post(regions=["Seoul"]).status_code == 422
    assert post(external_id_env="my-secret-value!").status_code == 422  # must be an env var NAME
    assert post(role_arn=None, external_id_env="CSPM_X").status_code == 422  # an ExternalId needs a role
    assert post(env="DEV Team").status_code == 422
    assert client.post("/api/accounts", json={**OK, "extra": 1}, headers=UI).status_code == 422
    assert post().status_code == 201
    assert post().status_code == 422  # duplicate
    assert post(account_id="111").status_code == 422  # already in the file
    assert client.post("/api/accounts", json=OK).status_code == 403  # needs the UI header


def test_blank_fields_become_none_and_no_regions_means_all(web):
    client, *_ = web
    r = client.post("/api/accounts", json={"account_id": "777788889999", "name": " ", "env": "", "role_arn": "", "regions": []}, headers=UI)
    assert r.status_code == 201
    a = accounts(client)["777788889999"]
    assert a["name"] is None and a["env"] is None and a["role_arn"] is None and a["regions"] is None


def test_edit_keeps_the_id_and_file_accounts_are_read_only(web):
    client, *_ = web
    client.post("/api/accounts", json=OK, headers=UI)
    r = client.put("/api/accounts/444455556666", json={**OK, "name": "renamed", "regions": ["ap-northeast-2"]}, headers=UI)
    assert r.status_code == 200 and accounts(client)["444455556666"]["name"] == "renamed"
    assert client.put("/api/accounts/444455556666", json={**OK, "account_id": "555566667777", "role_arn": None,
                                                         "external_id_env": None}, headers=UI).status_code == 422
    assert client.put("/api/accounts/999999999999", json={**OK, "account_id": "999999999999", "role_arn": None,
                                                         "external_id_env": None}, headers=UI).status_code == 404
    # the file's account (id "111" in the test fixture) is refused before its body is even looked at
    assert client.delete("/api/accounts/111", headers=UI).status_code == 409


def test_delete_removes_the_account_from_groups_and_reports_schedules(web):
    client, rt, stub, _ = web
    client.post("/api/accounts", json=OK, headers=UI)
    gid = client.post("/api/groups", json={"kind": "accounts", "name": "g", "members": ["111", "444455556666"]},
                      headers=UI).json()["id"]
    client.put("/api/items/sqs/schedule", json={"auto": True, "schedule": {"kind": "daily", "time": "03:00"},
                                                "target": {"accounts": ["444455556666"]}}, headers=UI)
    r = client.delete("/api/accounts/444455556666", headers=UI).json()
    assert r == {"deleted": "444455556666", "removed_from_groups": ["g"], "schedules_naming_it": ["sqs"]}
    assert "444455556666" not in accounts(client)
    assert [g for g in client.get("/api/groups").json()["accounts"] if g["id"] == gid][0]["members"] == ["111"]
    assert client.delete("/api/accounts/444455556666", headers=UI).status_code == 404


def test_env_label_of_an_added_account_joins_the_automatic_group(web):
    client, *_ = web
    client.post("/api/accounts", json=OK, headers=UI)
    g = {g["id"]: g for g in client.get("/api/groups").json()["accounts"]}
    assert g["env:dev"]["members"] == ["444455556666"]


# ----------------------------------------------------------------------------- CSV
HEADER = "account_id,name,env,role_arn,external_id_env,regions\n"
PHEADER = "account_id,name,env,profile,role_arn,external_id_env,regions\n"
GOOD = (HEADER +
        "444455556666,dev-game,dev,arn:aws:iam::444455556666:role/R,CSPM_EXT_A,ap-northeast-2 us-east-1\n"
        "777788889999,dev-web,dev,,,\n")


def imp(client, text, apply=False):
    return client.post("/api/accounts/import", json={"csv": text, "apply": apply}, headers=UI)


def test_csv_check_does_not_save_and_apply_adds_every_row(web):
    client, rt, *_ = web
    r = imp(client, GOOD).json()
    assert r["applied"] is False and r["counts"] == {"add": 2, "update": 0, "skip": 0, "error": 0}
    assert list(accounts(client)) == ["111"]  # only checked
    r = imp(client, GOOD, apply=True).json()
    assert r["applied"] is True
    acc = accounts(client)
    assert acc["444455556666"]["regions"] == ["ap-northeast-2", "us-east-1"] and acc["444455556666"]["external_id_env"] == "CSPM_EXT_A"
    assert acc["777788889999"]["regions"] is None and acc["777788889999"]["source"] == "web"
    # importing the same file again updates instead of duplicating
    again = imp(client, GOOD.replace("dev-web", "renamed"), apply=True).json()
    assert again["counts"] == {"add": 0, "update": 2, "skip": 0, "error": 0} and accounts(client)["777788889999"]["name"] == "renamed"


def test_one_bad_row_blocks_the_whole_import_and_is_reported_by_line(web):
    client, *_ = web
    bad = GOOD + "12345678901x,short,dev,,,\n" + "1234567890123,long,dev,,,\n" + "444455556666,dup,dev,,,\n"
    r = imp(client, bad, apply=True).json()
    assert r["applied"] is False and r["counts"]["error"] == 3 and r["counts"]["add"] == 2
    by_line = {x["line"]: x for x in r["rows"] if x["action"] == "error"}
    assert "12자리" in by_line[4]["message"] and "12자리" in by_line[5]["message"] and "또 있습니다" in by_line[6]["message"]
    assert list(accounts(client)) == ["111"]  # nothing was saved


def test_csv_formats_excel_bom_tabs_semicolons_quotes_and_aliases(web):
    client, *_ = web
    excel = "\ufeffid;name;env;region\r\n444455556666;\"game, a\";dev;ap-northeast-2;\r\n"
    assert imp(client, excel, apply=True).json()["applied"] is True
    assert accounts(client)["444455556666"]["name"] == "game, a"
    tabbed = "account_id\tname\n777788889999\tpasted\n"  # copied from a spreadsheet
    assert imp(client, tabbed, apply=True).json()["applied"] is True
    assert accounts(client)["777788889999"]["name"] == "pasted"
    # columns may come in any order
    assert imp(client, "name,account_id\nx,888899990000\n", apply=True).json()["applied"] is True


def test_csv_structure_errors_are_refused_with_a_message(web):
    client, *_ = web
    for text, needle in [("", "헤더"), ("account_id\n", "헤더"), ("name,env\nx,dev\n", "account_id 열"),
                         ("account_id,secret\n444455556666,x\n", "알 수 없는 열"),
                         ("account_id,account_id\n444455556666,444455556666\n", "두 번")]:
        r = imp(client, text)
        assert r.status_code == 422 and needle in r.json()["detail"], (text, r.json())
    big = HEADER + "444455556666,n,dev,,,\n" * 501
    assert imp(client, big).status_code == 422
    assert imp(client, "account_id\n" + "1" * 250_000).status_code == 413
    assert client.post("/api/accounts/import", json={"csv": GOOD}).status_code == 403  # needs the UI header


def test_export_round_trips_through_import(web):
    client, *_ = web
    imp(client, GOOD, apply=True)
    res = client.get("/api/accounts.csv")
    assert res.headers["content-type"].startswith("text/csv") and "accounts.csv" in res.headers["content-disposition"]
    text = res.text
    assert text.startswith("\ufeffaccount_id,name,env,profile,role_arn") and "444455556666,dev-game,dev,,arn:aws:iam::444455556666:role/R" in text
    r = imp(client, text).json()  # the two imported accounts are updates
    # the fixture's file account has the (invalid) short id "111": it is exported as is and comes back zero-padded
    assert r["counts"] == {"add": 1, "update": 2, "skip": 0, "error": 0}


# ----------------------------------------------------------------------------- Excel damage
@pytest.mark.parametrize("damaged,real", [
    ("1.24249E+11", "124249168210"),   # scientific notation, rounded down
    ("2.8884E+11", "288839812113"),    # rounded up
    ("4.956E+11", "495599738232"),     # trailing zeros dropped by Excel
])
def test_excel_damaged_ids_are_repaired_from_the_role_arn(damaged, real):
    from cspm_collector.web.accounts import repair_excel_id
    arn = f"arn:aws:iam::{real}:role/CspmReadOnly"
    assert repair_excel_id(damaged, arn)[0] == real and "복구" in repair_excel_id(damaged, arn)[1]


@pytest.mark.parametrize("damaged,real", [("69647263611", "069647263611"), ("1674983063", "001674983063"), ("8969382493", "008969382493")])
def test_dropped_leading_zeros_are_restored_even_when_the_arn_lost_them_too(damaged, real):
    from cspm_collector.web.accounts import parse_csv
    row = parse_csv(f"account_id,role_arn\n{damaged},arn:aws:iam::{damaged}:role/R\n")[0]
    assert row["error"] is None and row["account_id"] == real
    assert row["body"].role_arn == f"arn:aws:iam::{real}:role/R" and "앞의 0" in row["note"]


@pytest.mark.parametrize("value,arn", [
    ("1.24249E+11", "arn:aws:iam::999999999999:role/R"),   # does not fit the ARN: a real mismatch stays an error
    ("1.24249E+11", None),                                 # nothing to repair from
    ("124249168210", "arn:aws:iam::999999999999:role/R"),  # a valid id is never touched
    ("abc", "arn:aws:iam::124249168210:role/R"),
])
def test_repair_leaves_everything_else_alone(value, arn):
    from cspm_collector.web.accounts import repair_excel_id
    assert repair_excel_id(value, arn) == (value, None)


def test_import_of_an_excel_saved_file_repairs_and_says_so(web):
    client, *_ = web
    text = (HEADER + "1.24249E+11,admin,live,arn:aws:iam::124249168210:role/R,,ap-northeast-2\n"
            "69647263611,rnd,dev,arn:aws:iam::069647263611:role/R,,\n"
            "9.99E+11,wrong,dev,arn:aws:iam::123456789012:role/R,,\n")
    r = imp(client, text).json()
    rows = {x["line"]: x for x in r["rows"]}
    assert rows[2]["account_id"] == "124249168210" and "복구" in rows[2]["message"] and rows[2]["action"] == "add"
    assert rows[3]["account_id"] == "069647263611"  # the ARN's own id is the 12-digit one here
    assert rows[4]["action"] == "error" and "12자리" in rows[4]["message"]  # the mismatch is not hidden
    assert imp(client, text, apply=True).json()["applied"] is False
    assert imp(client, "\n".join(text.splitlines()[:3]) + "\n", apply=True).json()["applied"] is True
    assert {"124249168210", "069647263611"} <= set(accounts(client))


def test_a_row_for_a_config_file_account_is_skipped_not_fatal():
    from cspm_collector.core.config import AccountSettings
    # the shared fixture's file account has the short id "111", so build a runtime with a real-looking one
    from test_web_api import SPEC, MongoSettings, Settings, Store, Stub, build_runtime
    import mongomock
    from fastapi.testclient import TestClient
    store = Store(mongomock.MongoClient()["d"], MongoSettings())
    store.init_db()
    settings = Settings(accounts=[AccountSettings(account_id="334446289340", name="dev", regions=["ap-northeast-2"])])
    rt = build_runtime(settings, store, spec_path=SPEC, run_fn=Stub(), allowed_hosts=("testserver",))
    try:
        c = TestClient(rt.app)
        text = HEADER + "334446289340,x,dev,,,\n999900001111,new,dev,,,\n"
        r = imp(c, text, apply=True).json()
        assert r["applied"] is True and r["counts"] == {"add": 1, "update": 0, "skip": 1, "error": 0}
        assert [a["account_id"] for a in c.get("/api/overview").json()["accounts"]] == ["334446289340", "999900001111"]
        assert c.get("/api/overview").json()["accounts"][0]["name"] == "dev"  # untouched
    finally:
        rt.stop()


# ----------------------------------------------------------------------------- AWS (SSO) profile per account
@pytest.fixture
def profiles(monkeypatch):
    """Pretend this machine has an SSO profile for each of these accounts."""
    names = {"live-bubblyz-global", "qa-bubblyz-global", "dev-stove-platform-rnd"}
    monkeypatch.setattr("cspm_collector.web.app.available_profiles", lambda: names)
    return names


def test_a_profile_can_be_set_and_must_exist_on_this_machine(web, profiles):
    client, *_ = web
    body = {"account_id": "060504558768", "name": "live-bubblyz-global", "env": "live", "profile": "live-bubblyz-global"}
    r = client.post("/api/accounts", json=body, headers=UI)
    assert r.status_code == 201 and r.json()["profile"] == "live-bubblyz-global" and r.json()["role_arn"] is None
    bad = client.post("/api/accounts", json={**body, "account_id": "194160272925", "profile": "no-such-profile"}, headers=UI)
    assert bad.status_code == 422 and "no-such-profile" in bad.json()["detail"]
    assert client.post("/api/accounts", json={**body, "account_id": "194160272925", "profile": "bad name!"}, headers=UI).status_code == 422
    r = client.put("/api/accounts/060504558768", json={**body, "profile": "qa-bubblyz-global"}, headers=UI)
    assert r.status_code == 200 and accounts(client)["060504558768"]["profile"] == "qa-bubblyz-global"
    assert client.get("/api/profiles").json()["profiles"] == sorted(profiles)


def test_csv_can_name_a_profile_or_pick_the_one_with_the_same_name(web, profiles):
    client, *_ = web
    text = (PHEADER +
            "060504558768,live-bubblyz-global,live,,arn:aws:iam::060504558768:role/CspmReadOnly,CSPM_EXT,ap-northeast-2\n"
            "194160272925,qa-bubblyz-global,qa,,,,\n"
            "069647263611,other-name,dev,dev-stove-platform-rnd,,,\n"
            "111122223333,unknown-profile,dev,nope,,,\n")
    r = client.post("/api/accounts/import", json={"csv": text}, headers=UI).json()
    rows = {x["line"]: x for x in r["rows"]}
    assert rows[5]["action"] == "error" and "nope" in rows[5]["message"]
    # without the option the first row keeps its role and gets no profile; with it the same-name profile wins
    r = client.post("/api/accounts/import", json={"csv": "\n".join(text.splitlines()[:4]) + "\n", "use_profiles": True, "apply": True}, headers=UI).json()
    assert r["applied"] is True
    acc = accounts(client)
    assert acc["060504558768"]["profile"] == "live-bubblyz-global" and acc["060504558768"]["role_arn"] is None
    assert acc["060504558768"]["external_id_env"] is None
    assert acc["194160272925"]["profile"] == "qa-bubblyz-global"
    assert acc["069647263611"]["profile"] == "dev-stove-platform-rnd"  # an explicit profile is kept as given
    notes = [x["message"] for x in r["rows"]]
    assert "Role은 쓰지 않음" in notes[0] and "같은 이름" in notes[1]


def test_without_the_option_the_role_stays(web, profiles):
    client, *_ = web
    text = PHEADER + "060504558768,live-bubblyz-global,live,,arn:aws:iam::060504558768:role/R,,\n"
    assert client.post("/api/accounts/import", json={"csv": text, "apply": True}, headers=UI).json()["applied"] is True
    a = accounts(client)["060504558768"]
    assert a["profile"] is None and a["role_arn"] == "arn:aws:iam::060504558768:role/R"


# ----------------------------------------------------------------------------- review fixes
@pytest.mark.parametrize("name", ["=HYPERLINK(1)", "+1", "-2", "@SUM(A1)", "ok\nname"])
def test_names_that_a_spreadsheet_would_run_as_formulas_are_refused(web, name):
    client, *_ = web
    r = client.post("/api/accounts", json={**OK, "name": name}, headers=UI)
    assert r.status_code == 422 and "수식" in r.text
    g = client.post("/api/groups", json={"kind": "items", "name": name, "members": []}, headers=UI)
    assert g.status_code == 422


def test_csv_import_refuses_formula_names_for_accounts_and_groups(web):
    client, *_ = web
    r = client.post("/api/accounts/import", json={"csv": HEADER + "444455556666,=cmd,dev,,,\n"}, headers=UI).json()
    assert r["rows"][0]["action"] == "error" and "수식" in r["rows"][0]["message"]
    g = client.post("/api/groups/import", json={"csv": "kind,name,members\nitems,=x,sqs\n"}, headers=UI).json()
    assert g["rows"][0]["error"] and "수식" in g["rows"][0]["error"]
    ok = client.post("/api/accounts", json={**OK, "name": "dev-1+2"}, headers=UI)  # inside the text these are fine
    assert ok.status_code == 201


def test_items_reads_the_database_settings_once_not_once_per_item(web, monkeypatch):
    from cspm_collector.web.accounts import WebAccounts
    client, *_ = web
    calls = []
    real = WebAccounts.list
    monkeypatch.setattr(WebAccounts, "list", lambda self: (calls.append(1), real(self))[1])
    assert len(items(client)) == 93
    assert len(calls) <= 5, f"{len(calls)} reads of the page's accounts for one /api/items"


# ----------------------------------------------------------------------------- the CSV template and its warnings
def csv_import(client, text, **kw):
    return client.post("/api/accounts/import", json={"csv": text, "apply": False, **kw}, headers=UI).json()


HEAD = "account_id,name,env,profile,role_arn,external_id_env,regions\n"


def test_the_example_rows_of_the_template_cannot_be_imported_as_they_are(web):
    client, *_ = web
    r = csv_import(client, HEAD + "123456789012,example-profile-account,dev,,,,\n210987654321,x,dev,,,,\n444455556666,real,dev,,,,\n")
    assert r["counts"]["error"] == 2 and r["counts"]["add"] == 1
    assert all("예시" in x["message"] for x in r["rows"] if x["action"] == "error")
    assert csv_import(client, HEAD + "123456789012,a,dev,,,,\n", apply=True)["applied"] is False  # nothing is saved


def test_the_downloadable_template_leaves_regions_empty_in_its_first_example():
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src" / "cspm_collector" / "web" / "static" / "index.html").read_text(encoding="utf-8")
    template = html[html.index('template: "account_id,name'):].split("\n", 1)[0]
    first = template.split(chr(92) + "n")[1]  # the page file holds a backslash-n, not a newline
    assert first.endswith(",,,"), first  # regions empty = every enabled region, not a copied example value


def test_warns_when_every_account_got_the_same_single_region(web):
    client, *_ = web
    rows = "".join(f"44445555666{i},acc{i},dev,,,,ap-northeast-2\n" for i in range(5))
    r = csv_import(client, HEAD + rows)
    assert r["counts"]["add"] == 5 and any("모두 ap-northeast-2 하나뿐" in w for w in r["warnings"])
    mixed = csv_import(client, HEAD + "444455556661,a,dev,,,,ap-northeast-2\n444455556662,b,dev,,,,us-east-1 ap-northeast-2\n")
    assert not any("하나뿐" in w for w in mixed["warnings"])


def test_warns_about_blank_regions_and_about_an_external_id_variable_that_is_not_set(web, monkeypatch):
    client, *_ = web
    monkeypatch.delenv("CSPM_EXTID_GAME", raising=False)
    role = "arn:aws:iam::444455556661:role/CspmReadOnly"
    r = csv_import(client, HEAD + f"444455556661,a,dev,,{role},CSPM_EXTID_GAME,\n444455556662,b,dev,,,,us-east-1\n")
    assert any("리전이 비어 있어" in w for w in r["warnings"])
    assert any("CSPM_EXTID_GAME" in w for w in r["warnings"])
    monkeypatch.setenv("CSPM_EXTID_GAME", "secret-value")
    assert not any("CSPM_EXTID_GAME" in w for w in csv_import(client, HEAD + f"444455556661,a,dev,,{role},CSPM_EXTID_GAME,us-east-1\n")["warnings"])
