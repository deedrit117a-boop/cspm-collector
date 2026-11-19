"""Collection schedules: the model, validation and "when is the next run" (pure functions, no clock inside).

Kinds
* ``manual``   never runs by itself
* ``minutes``  every N minutes, aligned to the clock of the local day (N=30: :00 and :30; N=90: 00:00, 01:30, 03:00, ...)
* ``daily``    every day at HH:MM
* ``weekly``   on the chosen weekdays (0=Mon ... 6=Sun) at HH:MM
* ``monthly``  on a day of the month at HH:MM (days beyond the month's end, e.g. 31 in April, run on its last day)
"""
from __future__ import annotations

import calendar
from datetime import datetime, time, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

MIN_INTERVAL = 5  # minutes: below this a collection would still be running when the next one is due
WEEKDAY_NAMES = ["월", "화", "수", "목", "금", "토", "일"]


class Schedule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["manual", "minutes", "daily", "weekly", "monthly"] = "manual"
    every_minutes: int | None = None
    time: str | None = None  # "HH:MM", local time of the configured timezone
    weekdays: list[int] = []
    month_day: int | None = None  # 1..31

    @field_validator("time")
    @classmethod
    def _valid_time(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            hh, mm = v.split(":")
            time(int(hh), int(mm))
        except (ValueError, TypeError) as exc:
            raise ValueError("time must be HH:MM (00:00 - 23:59)") from exc
        return f"{int(hh):02d}:{int(mm):02d}"

    @model_validator(mode="after")
    def _complete(self) -> "Schedule":
        k = self.kind
        if k == "minutes":
            if self.every_minutes is None or not (MIN_INTERVAL <= self.every_minutes <= 1440):
                raise ValueError(f"every_minutes must be between {MIN_INTERVAL} and 1440")
        elif k in ("daily", "weekly", "monthly") and self.time is None:
            raise ValueError("time is required (HH:MM)")
        if k == "weekly":
            if not self.weekdays or any(d not in range(7) for d in self.weekdays):
                raise ValueError("weekdays needs at least one day, 0 (Mon) to 6 (Sun)")
            self.weekdays = sorted(set(self.weekdays))
        if k == "monthly" and (self.month_day is None or not (1 <= self.month_day <= 31)):
            raise ValueError("month_day must be 1 to 31")
        return self


def _at(day: datetime, hhmm: str) -> datetime:
    hh, mm = (int(x) for x in hhmm.split(":"))
    return day.replace(hour=hh, minute=mm, second=0, microsecond=0)


def next_run(schedule: Schedule, after: datetime) -> datetime | None:
    """The first run time strictly after ``after`` (a timezone-aware datetime in the schedule's timezone)."""
    k = schedule.kind
    if k == "manual":
        return None
    if k == "minutes":
        n = schedule.every_minutes
        midnight = after.replace(hour=0, minute=0, second=0, microsecond=0)
        elapsed = int((after - midnight).total_seconds() // 60)
        candidate = midnight + timedelta(minutes=(elapsed // n + 1) * n)
        if candidate.date() != midnight.date():  # the grid restarts at midnight
            return midnight + timedelta(days=1)
        return candidate
    if k == "daily":
        today = _at(after, schedule.time)
        return today if today > after else today + timedelta(days=1)
    if k == "weekly":
        for offset in range(8):
            day = _at(after + timedelta(days=offset), schedule.time)
            if day.weekday() in schedule.weekdays and day > after:
                return day
    if k == "monthly":
        year, month = after.year, after.month
        for _ in range(14):
            day = min(schedule.month_day, calendar.monthrange(year, month)[1])
            candidate = _at(after.replace(year=year, month=month, day=day), schedule.time)
            if candidate > after:
                return candidate
            month += 1
            if month == 13:
                year, month = year + 1, 1
    return None


def describe(schedule: Schedule) -> str:
    """Human readable summary, Korean (the page language)."""
    k = schedule.kind
    if k == "manual":
        return "수동만"
    if k == "minutes":
        n = schedule.every_minutes
        return f"{n // 60}시간마다" if n % 60 == 0 and n >= 60 else f"{n}분마다"
    if k == "daily":
        return f"매일 {schedule.time}"
    if k == "weekly":
        days = "·".join(WEEKDAY_NAMES[d] for d in schedule.weekdays)
        return f"매주 {days} {schedule.time}"
    day = "말일" if schedule.month_day == 31 else f"{schedule.month_day}일"
    return f"매월 {day} {schedule.time}" + (" (짧은 달은 말일)" if schedule.month_day >= 29 else "")
