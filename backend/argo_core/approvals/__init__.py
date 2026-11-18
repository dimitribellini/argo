"""Connector RBAC gate and dual-UI Web/Telegram approval lifecycle."""

from argo_core.approvals.coordinator import (
    APPROVAL_NO_PREFIX,
    APPROVAL_OK_PREFIX,
    ApprovalCoordinator,
    ConnectorPermissionError,
    check_outbound_safety,
)

__all__ = [
    "APPROVAL_NO_PREFIX",
    "APPROVAL_OK_PREFIX",
    "ApprovalCoordinator",
    "ConnectorPermissionError",
    "check_outbound_safety",
]
