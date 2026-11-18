"""Host Resource Guard watchdog for memory, CPU, and disk capacity gates."""

from argo_core.watchdog.debug_buffer import DebugLogBuffer
from argo_core.watchdog.resource_guard import (
    DISK_WARNING_PCT,
    RAM_CRITICAL_PCT,
    RAM_STARTUP_GATE_PCT,
    HostResourceGuard,
    HostTelemetry,
)

__all__ = [
    "DISK_WARNING_PCT",
    "DebugLogBuffer",
    "HostResourceGuard",
    "HostTelemetry",
    "RAM_CRITICAL_PCT",
    "RAM_STARTUP_GATE_PCT",
]
