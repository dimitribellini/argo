"""Autonomous Host Resource Guard using psutil with /proc fallback."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from argo_core.bus.valkey_bus import EventBus
    from argo_core.connectors.telegram_bot import TelegramBotService
    from argo_core.db.repositories import ArgoRepository
    from argo_core.desktop.manager import DesktopManager

logger = logging.getLogger(__name__)

RAM_STARTUP_GATE_PCT = 80.0
RAM_CRITICAL_PCT = 90.0
DISK_WARNING_PCT = 85.0


@dataclass(frozen=True, slots=True)
class HostTelemetry:
    """Point-in-time host resource telemetry and guardrail flags."""

    cpu_percent: float
    ram_percent: float
    ram_total_gb: float
    disk_percent: float
    ram_startup_gate_blocked: bool
    ram_critical: bool
    disk_warning: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize telemetry for JSON API responses."""
        return asdict(self)


def _read_proc_meminfo() -> tuple[float, float]:
    """Read (ram_percent, ram_total_gb) from /proc/meminfo when psutil is unavailable."""
    meminfo = Path("/proc/meminfo")
    if not meminfo.is_file():
        return 0.0, 0.0
    values: dict[str, int] = {}
    for line in meminfo.read_text(encoding="utf-8").splitlines():
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        fields = parts[1].strip().split()
        if fields and fields[0].isdigit():
            values[parts[0]] = int(fields[0])
    total_kb = values.get("MemTotal", 0)
    avail_kb = values.get("MemAvailable", 0)
    if total_kb <= 0:
        return 0.0, 0.0
    ram_pct = round(((total_kb - avail_kb) / total_kb) * 100.0, 1)
    total_gb = round(total_kb / (1024 * 1024), 1)
    return ram_pct, total_gb


def _default_metrics_sample() -> dict[str, float]:
    """Collect host CPU, RAM, and disk metrics using psutil or stdlib fallbacks."""
    try:
        import psutil  # type: ignore[import-untyped]

        mem = psutil.virtual_memory()
        return {
            "cpu_percent": round(float(psutil.cpu_percent(interval=None)), 1),
            "ram_percent": round(float(mem.percent), 1),
            "ram_total_gb": round(float(mem.total) / (1024**3), 1),
            "disk_percent": round(float(psutil.disk_usage("/").percent), 1),
        }
    except ImportError:
        ram_pct, total_gb = _read_proc_meminfo()
        usage = shutil.disk_usage("/")
        disk_pct = round((usage.used / usage.total) * 100.0, 1) if usage.total > 0 else 0.0
        try:
            load1 = os.getloadavg()[0]
            cpu_pct = round(min(100.0, (load1 / (os.cpu_count() or 1)) * 100.0), 1)
        except OSError:
            cpu_pct = 0.0
        return {
            "cpu_percent": cpu_pct,
            "ram_percent": ram_pct,
            "ram_total_gb": total_gb,
            "disk_percent": disk_pct,
        }


_PROTECTED_PREFIXES = ("/data", "/srv/argo/desktops", "/srv/argo/sandboxes")
_PROTECTED_SUFFIXES = (".db", ".db-wal", ".db-shm", "-wal", "-shm")


class HostResourceGuard:
    """Monitors host memory, CPU, and disk thresholds to enforce desktop capacity gates."""

    def __init__(
        self,
        metrics_provider: Callable[[], dict[str, float]] | None = None,
        *,
        alert_cooldown_seconds: float = 300.0,
        temp_cleanup_dir: str | Path | None = None,
    ) -> None:
        self._metrics_provider = metrics_provider or _default_metrics_sample
        self._alert_cooldown_seconds = float(alert_cooldown_seconds)
        self._temp_cleanup_dir = Path(temp_cleanup_dir) if temp_cleanup_dir else None
        self._last_alert_at: dict[str, float] = {}
        self.latest: HostTelemetry = self.sample()

    def sample(self) -> HostTelemetry:
        """Sample host metrics and evaluate warning/critical thresholds."""
        raw = self._metrics_provider()
        cpu_pct = round(float(raw.get("cpu_percent", 0.0)), 1)
        ram_pct = round(float(raw.get("ram_percent", 0.0)), 1)
        ram_total_gb = round(float(raw.get("ram_total_gb", 0.0)), 1)
        disk_pct = round(float(raw.get("disk_percent", 0.0)), 1)

        telemetry = HostTelemetry(
            cpu_percent=cpu_pct,
            ram_percent=ram_pct,
            ram_total_gb=ram_total_gb,
            disk_percent=disk_pct,
            ram_startup_gate_blocked=ram_pct >= RAM_STARTUP_GATE_PCT,
            ram_critical=ram_pct >= RAM_CRITICAL_PCT,
            disk_warning=disk_pct >= DISK_WARNING_PCT,
        )
        self.latest = telemetry
        return telemetry

    def can_start_desktop(self) -> tuple[bool, HostTelemetry]:
        """Return whether a new argo-desktop container is permitted under the 80% RAM gate."""
        telemetry = self.sample()
        return (not telemetry.ram_startup_gate_blocked), telemetry

    def _cooldown_elapsed(self, key: str, now: float) -> bool:
        last_sent = self._last_alert_at.get(key)
        if last_sent is None:
            return True
        return (now - last_sent) >= self._alert_cooldown_seconds

    def _cleanup_temp_dir(self) -> int:
        """Remove stale temporary artifacts without touching SQLite files or desktop profiles."""
        target = self._temp_cleanup_dir
        if target is None or not target.is_dir():
            return 0
        resolved_str = str(target.resolve())
        if any(resolved_str == p or resolved_str.startswith(f"{p}/") for p in _PROTECTED_PREFIXES):
            return 0
        removed = 0
        for entry in target.iterdir():
            if not entry.is_file():
                continue
            if entry.name.lower().endswith(_PROTECTED_SUFFIXES):
                continue
            try:
                entry.unlink()
                removed += 1
            except OSError:
                continue
        return removed

    async def _dispatch_threshold_alert(
        self,
        *,
        alert_kind: Literal["ram_warning", "ram_critical", "disk_warning"],
        telemetry: HostTelemetry,
        bus: EventBus | None,
        telegram: TelegramBotService | None,
        title: str,
        badge: str,
        badge_tone: str,
        summary: str,
        meta: str,
        stopped_desktops: list[str] | None = None,
        cleaned_files: int = 0,
    ) -> list[dict[str, Any]]:
        if bus is not None:
            from argo_core.db.repositories import make_id

            await bus.publish(
                correlation_id=make_id("corr"),
                source_slug="host-guard",
                target_slug="telegram",
                event_type=f"watchdog.{alert_kind}",
                payload={
                    "category": "alerts",
                    "title": title,
                    "badge": badge,
                    "badge_tone": badge_tone,
                    "summary": summary,
                    "meta": meta,
                },
                hop_count=1,
            )
        if telegram is not None:
            return await telegram.send_resource_alert(
                telemetry=telemetry,
                alert_kind=alert_kind,
                stopped_desktops=stopped_desktops,
                cleaned_files=cleaned_files,
            )
        return []

    async def evaluate_and_enforce(
        self,
        *,
        repo: ArgoRepository | None = None,
        bus: EventBus | None = None,
        telegram: TelegramBotService | None = None,
        desktop_manager: DesktopManager | None = None,
        sandbox_manager: Any = None,
        force_notify: bool = False,
    ) -> dict[str, Any]:
        """Evaluate host telemetry, enforce critical auto-stops, and dispatch Telegram alerts."""
        telemetry = self.sample()
        now = time.monotonic()

        if not telemetry.ram_startup_gate_blocked:
            self._last_alert_at.pop("ram_warning", None)
            self._last_alert_at.pop("ram_critical", None)
        elif not telemetry.ram_critical:
            self._last_alert_at.pop("ram_critical", None)
        if not telemetry.disk_warning:
            self._last_alert_at.pop("disk_warning", None)

        actions: list[str] = []
        stopped_desktops: list[str] = []
        stopped_sandboxes: list[str] = []
        deliveries: list[dict[str, Any]] = []

        if telemetry.ram_critical:
            if desktop_manager is not None:
                stopped_desktops = await desktop_manager.stop_all_desktops(reason="ram_critical")
            elif repo is not None:
                stopped_desktops = repo.stop_running_desktops()
            if sandbox_manager is not None:
                stopped_sandboxes = await sandbox_manager.stop_all_sandboxes(reason="ram_critical")
            elif repo is not None and hasattr(repo, "stop_running_sandboxes"):
                stopped_sandboxes = repo.stop_running_sandboxes()
            if stopped_desktops:
                actions.append(f"auto_stopped_desktops:{len(stopped_desktops)}")
            if stopped_sandboxes:
                actions.append(f"auto_stopped_sandboxes:{len(stopped_sandboxes)}")
            if stopped_desktops or stopped_sandboxes or force_notify or self._cooldown_elapsed("ram_critical", now):
                self._last_alert_at["ram_critical"] = now
                self._last_alert_at["ram_warning"] = now
                actions.append("notified_ram_critical")
                stopped_all = [*stopped_desktops, *[f"sandbox:{s}" for s in stopped_sandboxes]]
                deliveries.extend(
                    await self._dispatch_threshold_alert(
                        alert_kind="ram_critical",
                        telemetry=telemetry,
                        bus=bus,
                        telegram=telegram,
                        title="Critical Host RAM Auto-Stop (>90%)",
                        badge=f"Critical · RAM {telemetry.ram_percent}%",
                        badge_tone="rose",
                        summary=(
                            f"Host RAM reached {telemetry.ram_percent}% (>= 90%). "
                            f"Stopped containers: {', '.join(stopped_all) or 'none running'}."
                        ),
                        meta="Host Resource Guard (>90% Critical Auto-Stop)",
                        stopped_desktops=stopped_desktops,
                    )
                )
        elif telemetry.ram_startup_gate_blocked:
            actions.append("ram_startup_gate_active")
            if force_notify or self._cooldown_elapsed("ram_warning", now):
                self._last_alert_at["ram_warning"] = now
                actions.append("notified_ram_warning")
                deliveries.extend(
                    await self._dispatch_threshold_alert(
                        alert_kind="ram_warning",
                        telemetry=telemetry,
                        bus=bus,
                        telegram=telegram,
                        title="Host RAM Startup Gate Active (>80%)",
                        badge=f"RAM Gate · {telemetry.ram_percent}%",
                        badge_tone="amber",
                        summary=(
                            f"Host memory at {telemetry.ram_percent}% (>= 80%). "
                            "Blocking new argo-desktop launches; sent inline Stop Idle Desktops control."
                        ),
                        meta="Host Resource Guard (>80% RAM Gate)",
                    )
                )

        if telemetry.disk_warning:
            cleaned = self._cleanup_temp_dir()
            actions.append(f"cleaned_temp_files:{cleaned}")
            if force_notify or self._cooldown_elapsed("disk_warning", now):
                self._last_alert_at["disk_warning"] = now
                actions.append("notified_disk_warning")
                deliveries.extend(
                    await self._dispatch_threshold_alert(
                        alert_kind="disk_warning",
                        telemetry=telemetry,
                        bus=bus,
                        telegram=telegram,
                        title="Host Disk Warning (>85%)",
                        badge=f"Disk · {telemetry.disk_percent}%",
                        badge_tone="amber",
                        summary=(
                            f"Host disk usage reached {telemetry.disk_percent}% (>= 85%). "
                            f"Removed {cleaned} temporary file(s); database and desktop profiles preserved."
                        ),
                        meta="Host Resource Guard (>85% Disk Cleanup)",
                        cleaned_files=cleaned,
                    )
                )

        return {
            "telemetry": telemetry.to_dict(),
            "actions": actions,
            "stopped_desktops": stopped_desktops,
            "stopped_sandboxes": stopped_sandboxes,
            "telegram_deliveries": deliveries,
        }

    async def run_periodic(
        self,
        interval_seconds: float = 30.0,
        on_threshold: Callable[[HostTelemetry], Any] | None = None,
    ) -> None:
        """Continuously sample host telemetry on the configured interval."""
        while True:
            telemetry = self.sample()
            if telemetry.ram_critical or telemetry.ram_startup_gate_blocked or telemetry.disk_warning:
                logger.warning(
                    "Host Resource Guard threshold alert: ram=%.1f%% disk=%.1f%%",
                    telemetry.ram_percent,
                    telemetry.disk_percent,
                )
                if on_threshold is not None:
                    result = on_threshold(telemetry)
                    if asyncio.iscoroutine(result):
                        await result
            await asyncio.sleep(interval_seconds)
