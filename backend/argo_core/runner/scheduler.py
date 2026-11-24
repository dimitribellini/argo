"""APScheduler 3.11.x routine scheduler with lightweight asyncio fallback for host tests."""

from __future__ import annotations

import asyncio
import logging
import re
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from argo_core.db.repositories import ArgoRepository, utc_now
from argo_core.runner.bot_runner import UniversalBotRunner

logger = logging.getLogger(__name__)

_INTERVAL_RE = re.compile(
    r"^(?:every\s+)?(\d+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)$",
    re.IGNORECASE,
)
_CRON_FIELD_RE = re.compile(r"^[0-9*/,-]+$")
_DOW_ALIASES: dict[str, str] = {
    "mon": "mon",
    "monday": "mon",
    "mondays": "mon",
    "tue": "tue",
    "tues": "tue",
    "tuesday": "tue",
    "tuesdays": "tue",
    "wed": "wed",
    "wednesday": "wed",
    "wednesdays": "wed",
    "thu": "thu",
    "thur": "thu",
    "thurs": "thu",
    "thursday": "thu",
    "thursdays": "thu",
    "fri": "fri",
    "friday": "fri",
    "fridays": "fri",
    "sat": "sat",
    "saturday": "sat",
    "saturdays": "sat",
    "sun": "sun",
    "sunday": "sun",
    "sundays": "sun",
    "weekday": "mon-fri",
    "weekdays": "mon-fri",
    "weekend": "sat,sun",
    "weekends": "sat,sun",
    "day": "*",
    "daily": "*",
}
_CALENDAR_RE = re.compile(
    r"^(?:every\s+)?(?P<cadence>weekdays?|weekends?|daily|day|mon(?:days?)?|tue(?:sdays?)?|wed(?:nesdays?)?|thu(?:rsdays?)?|fri(?:days?)?|sat(?:urdays?)?|sun(?:days?)?)"
    r"(?:\s+at\s+(?P<hour>\d{1,2})(?::(?P<minute>\d{2}))?\s*(?P<ampm>am|pm)?)?$",
    re.IGNORECASE,
)
_ONCE_RELATIVE_RE = re.compile(
    r"^(?:once\s+)?in\s+(\d+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)$",
    re.IGNORECASE,
)
_ONCE_DATETIME_RE = re.compile(
    r"^(?:(?:once|one[\s-]*shot|one[\s-]*time)(?:\s+(?:at|on))?|at)?\s*"
    r"(?P<date>\d{4}-\d{2}-\d{2})"
    r"(?:(?:\s+at|\s+|T)\s*(?P<hour>\d{1,2})(?::(?P<minute>\d{2}))(?::(?P<second>\d{2}))?\s*(?P<ampm>am|pm)?)?"
    r"(?:\s*(?P<tz>(?:Z|[+-]\d{2}:?\d{2})))?$",
    re.IGNORECASE,
)


def validate_timezone_name(timezone_name: str | None) -> str:
    """Validate an IANA timezone name, falling back cleanly to UTC."""
    cand = str(timezone_name or "").strip()
    if not cand:
        return "UTC"
    try:
        ZoneInfo(cand)
        return cand
    except Exception:
        return "UTC"


def _parse_hhmm(hour_str: str | None, minute_str: str | None, ampm: str | None) -> tuple[int, int] | None:
    if not hour_str:
        return (8, 30)
    hour = int(hour_str)
    minute = int(minute_str or 0)
    if minute < 0 or minute > 59:
        return None
    if ampm:
        suffix = ampm.lower()
        if hour < 1 or hour > 12:
            return None
        if suffix == "am":
            hour = 0 if hour == 12 else hour
        elif suffix == "pm":
            hour = 12 if hour == 12 else hour + 12
    elif hour < 0 or hour > 23:
        return None
    return (hour, minute)


def parse_routine_schedule(
    schedule: str | None,
    timezone: str | None = None,
    *,
    now_utc: datetime | None = None,
) -> dict[str, Any] | None:
    """Parse human intervals ('Every 15m'), calendar phrases ('Every weekday at 08:30'), one-shot dates ('Once at YYYY-MM-DD HH:MM', 'In 30m'), or 5-field cron."""
    if not schedule or not schedule.strip():
        return None
    cleaned = schedule.strip()
    lowered = cleaned.lower()
    if lowered in {"manual", "event-driven"} or lowered.startswith("on:"):
        return None

    tz_name = validate_timezone_name(timezone)
    tz_extra = {"timezone": tz_name} if (timezone is not None and str(timezone).strip()) else {}

    if lowered == "hourly":
        return {"kind": "interval", "seconds": 3600, "raw": cleaned, **tz_extra}
    if lowered == "every morning":
        return {
            "kind": "cron",
            "minute": "30",
            "hour": "8",
            "day": "*",
            "month": "*",
            "day_of_week": "*",
            "raw": cleaned,
            **tz_extra,
        }

    once_rel = _ONCE_RELATIVE_RE.match(cleaned)
    if once_rel:
        qty = max(1, int(once_rel.group(1)))
        unit = once_rel.group(2).lower()
        if unit.startswith("h"):
            seconds = qty * 3600
        elif unit.startswith("m"):
            seconds = qty * 60
        else:
            seconds = qty
        base_now = now_utc or datetime.now(UTC)
        target_dt = (base_now + timedelta(seconds=max(5, seconds))).astimezone(ZoneInfo(tz_name))
        fmt = "%Y-%m-%d %H:%M:%S" if unit.startswith("s") else "%Y-%m-%d %H:%M"
        return {
            "kind": "date",
            "run_at": target_dt.isoformat(),
            "raw": cleaned,
            "normalized": f"Once at {target_dt.strftime(fmt)}",
            **tz_extra,
        }

    once_dt = _ONCE_DATETIME_RE.match(cleaned)
    if once_dt:
        date_str = once_dt.group("date")
        try:
            parsed_date = datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            return None
        hhmm = _parse_hhmm(once_dt.group("hour"), once_dt.group("minute"), once_dt.group("ampm"))
        if once_dt.group("hour") is None:
            hhmm = (9, 0)
        if hhmm is None:
            return None
        sec = int(once_dt.group("second") or 0)
        if sec < 0 or sec > 59:
            return None
        tz_suffix = (once_dt.group("tz") or "").strip()
        if tz_suffix:
            if tz_suffix.upper() == "Z":
                tz_obj: Any = UTC
            else:
                iso_tz = tz_suffix if ":" in tz_suffix else f"{tz_suffix[:3]}:{tz_suffix[3:]}"
                try:
                    tz_obj = datetime.fromisoformat(f"2026-01-01T00:00:00{iso_tz}").tzinfo or UTC
                except ValueError:
                    return None
            target_dt = datetime(
                parsed_date.year,
                parsed_date.month,
                parsed_date.day,
                hhmm[0],
                hhmm[1],
                sec,
                tzinfo=tz_obj,
            )
        else:
            target_dt = datetime(
                parsed_date.year,
                parsed_date.month,
                parsed_date.day,
                hhmm[0],
                hhmm[1],
                sec,
                tzinfo=ZoneInfo(tz_name),
            )
        fmt = "%Y-%m-%d %H:%M:%S" if target_dt.second else "%Y-%m-%d %H:%M"
        return {
            "kind": "date",
            "run_at": target_dt.isoformat(),
            "raw": cleaned,
            "normalized": f"Once at {target_dt.strftime(fmt)}",
            **tz_extra,
        }

    match = _INTERVAL_RE.match(cleaned)
    if match:
        qty = max(1, int(match.group(1)))
        unit = match.group(2).lower()
        if unit.startswith("h"):
            seconds = qty * 3600
        elif unit.startswith("m"):
            seconds = qty * 60
        else:
            seconds = qty
        return {"kind": "interval", "seconds": max(10, seconds), "raw": cleaned, **tz_extra}

    cal_match = _CALENDAR_RE.match(cleaned)
    if cal_match:
        cadence_key = cal_match.group("cadence").lower()
        dow = _DOW_ALIASES.get(cadence_key)
        if dow is not None:
            hhmm = _parse_hhmm(
                cal_match.group("hour"),
                cal_match.group("minute"),
                cal_match.group("ampm"),
            )
            if hhmm is not None:
                hour_val, min_val = hhmm
                return {
                    "kind": "cron",
                    "minute": str(min_val),
                    "hour": str(hour_val),
                    "day": "*",
                    "month": "*",
                    "day_of_week": dow,
                    "raw": cleaned,
                    **tz_extra,
                }

    parts = cleaned.split()
    if len(parts) == 5 and all(_CRON_FIELD_RE.match(p) or p in {"mon-fri", "sat,sun"} for p in parts):
        return {
            "kind": "cron",
            "minute": parts[0],
            "hour": parts[1],
            "day": parts[2],
            "month": parts[3],
            "day_of_week": parts[4],
            "raw": cleaned,
            **tz_extra,
        }
    return None


def is_one_shot_schedule(
    schedule: str | None,
    timezone: str | None = None,
    routine_type: str | None = None,
    one_shot_flag: bool | None = None,
) -> bool:
    """Return True when a routine represents a one-shot run rather than a recurring schedule."""
    if one_shot_flag or str(routine_type or "").strip().lower() == "once":
        return True
    parsed = parse_routine_schedule(schedule, timezone)
    return bool(parsed and parsed.get("kind") == "date")


class BotScheduler:
    """Reconciles enabled bot routines against APScheduler 3.11.x AsyncIOScheduler."""

    def __init__(self, *, repo: ArgoRepository, runner: UniversalBotRunner) -> None:
        self._repo = repo
        self._runner = runner
        self._scheduler: Any = None
        self._backend: str = "stopped"
        self._jobs: dict[str, dict[str, Any]] = {}
        self._fallback_tasks: dict[str, asyncio.Task[None]] = {}
        self._started = False

    @property
    def backend(self) -> str:
        return self._backend

    async def start(self) -> None:
        """Start APScheduler AsyncIOScheduler (or host asyncio fallback) and sync all bots."""
        if self._started:
            return
        self._started = True
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore[import-not-found]

            self._scheduler = AsyncIOScheduler(timezone="UTC")
            self._scheduler.start()
            self._backend = "apscheduler"
        except ImportError:
            self._scheduler = None
            self._backend = "asyncio_fallback"
            logger.info("APScheduler not installed locally; using asyncio interval fallback.")

        self.sync_bots()

    async def stop(self) -> None:
        """Stop APScheduler and cancel fallback tasks cleanly."""
        self._started = False
        if self._scheduler is not None:
            with suppress(Exception):
                self._scheduler.shutdown(wait=False)
            self._scheduler = None
        for task in list(self._fallback_tasks.values()):
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        self._fallback_tasks.clear()
        self._jobs.clear()
        self._backend = "stopped"

    async def _run_scheduled_routine(self, bot_slug: str, routine_id: str) -> None:
        is_one_shot = False
        with suppress(Exception):
            bot_rec = self._repo.get_bot(bot_slug)
            r_rec = next(
                (r for r in (bot_rec.get("routines") or []) if isinstance(r, dict) and r.get("id") == routine_id),
                None,
            )
            if isinstance(r_rec, dict):
                is_one_shot = is_one_shot_schedule(
                    r_rec.get("schedule"),
                    r_rec.get("timezone"),
                    r_rec.get("type"),
                    r_rec.get("one_shot"),
                )
        try:
            await self._runner.execute_bot(
                bot_slug,
                trigger_type=f"cron:{routine_id}",
                hop_count=1,
                routine_id=routine_id,
            )
        except Exception as exc:
            logger.warning("Scheduled routine %s/%s failed: %s", bot_slug, routine_id, exc)
        finally:
            if is_one_shot:
                with suppress(Exception):
                    latest_bot = self._repo.get_bot(bot_slug)
                    done_ts = utc_now()
                    updated_routines: list[Any] = []
                    changed = False
                    for r in latest_bot.get("routines") or []:
                        if isinstance(r, dict) and r.get("id") == routine_id:
                            nr = dict(r)
                            nr["enabled"] = False
                            nr["one_shot"] = True
                            nr["type"] = "once"
                            nr["completed_at"] = done_ts
                            updated_routines.append(nr)
                            changed = True
                        else:
                            updated_routines.append(r)
                    if changed:
                        self._repo.update_bot(bot_slug, {"routines": updated_routines})
                    job_id = f"{bot_slug}::{routine_id}"
                    self._remove_job(job_id)
                    self._jobs.pop(job_id, None)

    async def _fallback_interval_loop(self, bot_slug: str, routine_id: str, seconds: int) -> None:
        try:
            while self._started:
                await asyncio.sleep(seconds)
                await self._run_scheduled_routine(bot_slug, routine_id)
        except asyncio.CancelledError:
            raise

    async def _fallback_once_sleep(self, bot_slug: str, routine_id: str, delay_seconds: float) -> None:
        try:
            if delay_seconds > 0:
                await asyncio.sleep(delay_seconds)
            if self._started:
                await self._run_scheduled_routine(bot_slug, routine_id)
        except asyncio.CancelledError:
            raise

    def sync_bots(self) -> list[dict[str, Any]]:
        """Reconcile active scheduled jobs with all enabled declarative bots in SQLite."""
        desired: dict[str, dict[str, Any]] = {}
        now_utc = datetime.now(UTC)
        for bot in self._repo.list_bots():
            if not bot["enabled"]:
                continue
            for routine in bot.get("routines", []):
                if not isinstance(routine, dict) or not routine.get("enabled", True):
                    continue
                if str(routine.get("type") or "") == "on_event" or routine.get("event"):
                    continue
                parsed = parse_routine_schedule(
                    routine.get("schedule"),
                    routine.get("timezone"),
                    now_utc=now_utc,
                )
                if parsed is None:
                    continue
                if parsed["kind"] == "date":
                    try:
                        run_dt = datetime.fromisoformat(str(parsed["run_at"])).astimezone(UTC)
                    except ValueError:
                        continue
                    if run_dt <= now_utc - timedelta(seconds=60):
                        continue
                job_id = f"{bot['slug']}::{routine['id']}"
                desired[job_id] = {
                    "job_id": job_id,
                    "bot_slug": bot["slug"],
                    "routine_id": routine["id"],
                    "label": routine.get("label") or routine["id"],
                    "spec": parsed,
                }

        stale_ids = set(self._jobs.keys()) - set(desired.keys())
        for job_id in stale_ids:
            self._remove_job(job_id)

        for job_id, meta in desired.items():
            existing = self._jobs.get(job_id)
            if existing and existing["spec"] == meta["spec"]:
                continue
            if existing is not None:
                self._remove_job(job_id)
            self._add_job(job_id, meta)

        self._jobs = desired
        return self.list_scheduled_jobs()

    def _remove_job(self, job_id: str) -> None:
        if self._scheduler is not None:
            with suppress(Exception):
                self._scheduler.remove_job(job_id)
        task = self._fallback_tasks.pop(job_id, None)
        if task is not None:
            cur_task = None
            with suppress(RuntimeError):
                cur_task = asyncio.current_task()
            if task is not cur_task:
                task.cancel()

    def _add_job(self, job_id: str, meta: dict[str, Any]) -> None:
        spec = meta["spec"]
        bot_slug = meta["bot_slug"]
        routine_id = meta["routine_id"]

        if self._scheduler is not None:
            if spec["kind"] == "date":
                try:
                    from apscheduler.triggers.date import DateTrigger  # type: ignore[import-not-found]
                except ImportError:
                    run_dt = datetime.fromisoformat(str(spec["run_at"])).astimezone(UTC)
                    delay = max(0.0, (run_dt - datetime.now(UTC)).total_seconds())
                    self._fallback_tasks[job_id] = asyncio.create_task(
                        self._fallback_once_sleep(bot_slug, routine_id, delay)
                    )
                    return
                run_dt = datetime.fromisoformat(str(spec["run_at"]))
                trigger = DateTrigger(run_date=run_dt)
                self._scheduler.add_job(
                    self._run_scheduled_routine,
                    trigger=trigger,
                    id=job_id,
                    kwargs={"bot_slug": bot_slug, "routine_id": routine_id},
                    replace_existing=True,
                    coalesce=True,
                    max_instances=1,
                    misfire_grace_time=300,
                )
                return

            from apscheduler.triggers.cron import CronTrigger  # type: ignore[import-not-found]
            from apscheduler.triggers.interval import IntervalTrigger  # type: ignore[import-not-found]

            if spec["kind"] == "interval":
                trigger = IntervalTrigger(seconds=int(spec["seconds"]))
            else:
                tz_obj = ZoneInfo(validate_timezone_name(spec.get("timezone")))
                trigger = CronTrigger(
                    minute=spec["minute"],
                    hour=spec["hour"],
                    day=spec["day"],
                    month=spec["month"],
                    day_of_week=spec["day_of_week"],
                    timezone=tz_obj,
                )
            self._scheduler.add_job(
                self._run_scheduled_routine,
                trigger=trigger,
                id=job_id,
                kwargs={"bot_slug": bot_slug, "routine_id": routine_id},
                replace_existing=True,
                coalesce=True,
                max_instances=1,
                misfire_grace_time=60,
            )
            return

        if self._started:
            if spec["kind"] == "date":
                run_dt = datetime.fromisoformat(str(spec["run_at"])).astimezone(UTC)
                delay = max(0.0, (run_dt - datetime.now(UTC)).total_seconds())
                self._fallback_tasks[job_id] = asyncio.create_task(
                    self._fallback_once_sleep(bot_slug, routine_id, delay)
                )
                return
            interval_seconds = int(spec["seconds"]) if spec["kind"] == "interval" else 900
            self._fallback_tasks[job_id] = asyncio.create_task(
                self._fallback_interval_loop(bot_slug, routine_id, interval_seconds)
            )

    def list_scheduled_jobs(self) -> list[dict[str, Any]]:
        """Return currently registered scheduled routine metadata."""
        return [
            {
                "job_id": meta["job_id"],
                "bot_slug": meta["bot_slug"],
                "routine_id": meta["routine_id"],
                "label": meta["label"],
                "schedule": meta["spec"]["raw"],
                "timezone": meta["spec"].get("timezone", "UTC"),
                "kind": meta["spec"]["kind"],
                "backend": self._backend,
            }
            for meta in self._jobs.values()
        ]
