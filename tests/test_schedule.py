from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from cspm_collector.web.schedule import Schedule, describe, next_run

KST = ZoneInfo("Asia/Seoul")


def at(y, mo, d, h=0, mi=0, s=0):
    return datetime(y, mo, d, h, mi, s, tzinfo=KST)


def nxt(schedule, after):
    return next_run(Schedule(**schedule), after)


# ----------------------------------------------------------------------------- validation
@pytest.mark.parametrize("bad", [
    {"kind": "minutes"}, {"kind": "minutes", "every_minutes": 4}, {"kind": "minutes", "every_minutes": 1441},
    {"kind": "daily"}, {"kind": "daily", "time": "25:00"}, {"kind": "daily", "time": "9"}, {"kind": "daily", "time": "ab:cd"},
    {"kind": "weekly", "time": "03:00"}, {"kind": "weekly", "time": "03:00", "weekdays": [7]},
    {"kind": "monthly", "time": "03:00"}, {"kind": "monthly", "time": "03:00", "month_day": 0},
    {"kind": "monthly", "time": "03:00", "month_day": 32}, {"kind": "hourly"}, {"kind": "manual", "bogus": 1},
])
def test_invalid_schedules_are_rejected(bad):
    with pytest.raises(ValidationError):
        Schedule(**bad)


def test_valid_schedules_are_normalised():
    assert Schedule(kind="daily", time="3:5").time == "03:05"
    assert Schedule(kind="weekly", time="03:00", weekdays=[4, 0, 0, 2]).weekdays == [0, 2, 4]
    assert Schedule().kind == "manual"


# ----------------------------------------------------------------------------- next run
def test_manual_never_runs_by_itself():
    assert nxt({"kind": "manual"}, at(2026, 10, 22, 9)) is None


def test_every_n_minutes_follows_the_clock_grid():
    s = {"kind": "minutes", "every_minutes": 30}
    assert nxt(s, at(2026, 10, 22, 9, 0, 0)) == at(2026, 10, 22, 9, 30)  # strictly after
    assert nxt(s, at(2026, 10, 22, 9, 29, 59)) == at(2026, 10, 22, 9, 30)
    assert nxt(s, at(2026, 10, 22, 9, 30)) == at(2026, 10, 22, 10, 0)
    assert nxt({"kind": "minutes", "every_minutes": 90}, at(2026, 10, 22, 0, 10)) == at(2026, 10, 22, 1, 30)


def test_every_n_minutes_restarts_at_midnight():
    s = {"kind": "minutes", "every_minutes": 7}  # 7 does not divide 1440
    last_of_day = at(2026, 10, 22, 23, 55)
    assert nxt(s, last_of_day) == at(2026, 10, 23, 0, 0)
    assert nxt(s, at(2026, 10, 23, 0, 0)) == at(2026, 10, 23, 0, 7)
    assert nxt({"kind": "minutes", "every_minutes": 1440}, at(2026, 10, 22, 8)) == at(2026, 10, 23, 0, 0)


def test_daily():
    s = {"kind": "daily", "time": "03:00"}
    assert nxt(s, at(2026, 10, 22, 2, 59)) == at(2026, 10, 22, 3, 0)
    assert nxt(s, at(2026, 10, 22, 3, 0)) == at(2026, 10, 23, 3, 0)
    assert nxt(s, at(2026, 12, 31, 12)) == at(2027, 1, 1, 3, 0)


def test_weekly_with_several_weekdays():
    s = {"kind": "weekly", "time": "03:00", "weekdays": [0, 2, 4]}  # Mon, Wed, Fri
    assert at(2026, 10, 22).weekday() == 3  # Thursday
    assert nxt(s, at(2026, 10, 22, 12)) == at(2026, 10, 23, 3, 0)  # Fri
    assert nxt(s, at(2026, 10, 23, 3, 0)) == at(2026, 10, 26, 3, 0)  # next Mon
    assert nxt(s, at(2026, 10, 26, 2, 0)) == at(2026, 10, 26, 3, 0)  # same day, still ahead
    assert nxt({"kind": "weekly", "time": "01:00", "weekdays": [3]}, at(2026, 10, 22, 2)) == at(2026, 10, 29, 1, 0)


def test_monthly_and_short_months():
    s = {"kind": "monthly", "time": "04:30", "month_day": 15}
    assert nxt(s, at(2026, 10, 10)) == at(2026, 10, 15, 4, 30)
    assert nxt(s, at(2026, 10, 15, 4, 30)) == at(2026, 11, 15, 4, 30)
    assert nxt(s, at(2026, 12, 20)) == at(2027, 1, 15, 4, 30)
    last = {"kind": "monthly", "time": "00:10", "month_day": 31}
    assert nxt(last, at(2026, 4, 1)) == at(2026, 4, 30, 0, 10)  # April has 30 days
    assert nxt(last, at(2026, 4, 30, 0, 10)) == at(2026, 5, 31, 0, 10)
    assert nxt(last, at(2028, 2, 1)) == at(2028, 2, 29, 0, 10)  # leap year
    assert nxt({"kind": "monthly", "time": "00:10", "month_day": 30}, at(2026, 2, 5)) == at(2026, 2, 28, 0, 10)


def test_results_are_always_in_the_future_and_in_the_same_zone():
    now = at(2026, 10, 22, 13, 37, 12)
    for s in ({"kind": "minutes", "every_minutes": 5}, {"kind": "daily", "time": "13:37"},
              {"kind": "weekly", "time": "13:37", "weekdays": [3]}, {"kind": "monthly", "time": "13:37", "month_day": 22}):
        n = nxt(s, now)
        assert n > now and n.tzinfo == KST, s


# ----------------------------------------------------------------------------- text
def test_describe_in_korean():
    assert describe(Schedule()) == "수동만"
    assert describe(Schedule(kind="minutes", every_minutes=30)) == "30분마다"
    assert describe(Schedule(kind="minutes", every_minutes=120)) == "2시간마다"
    assert describe(Schedule(kind="daily", time="03:00")) == "매일 03:00"
    assert describe(Schedule(kind="weekly", time="03:00", weekdays=[0, 2, 4])) == "매주 월·수·금 03:00"
    assert describe(Schedule(kind="monthly", time="03:00", month_day=1)) == "매월 1일 03:00"
    assert "말일" in describe(Schedule(kind="monthly", time="03:00", month_day=31))
