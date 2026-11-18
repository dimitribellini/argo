"""Runtime configuration settings loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ArgoSettings:
    """Bootstrap configuration for argo-core."""

    master_key: str
    db_path: str
    valkey_url: str
    desktop_volumes_root: str
    public_base_url: str
    static_dir: str
    desktop_idle_timeout_seconds: float = 300.0
    google_client_id: str = ""
    google_client_secret: str = ""
    workspace_files_root: str = ""

    def resolved_workspace_files_root(self) -> str:
        if self.workspace_files_root and self.workspace_files_root.strip():
            return self.workspace_files_root.strip()
        return str(Path(self.db_path).resolve().parent / "workspace_files")

    @classmethod
    def from_env(cls) -> ArgoSettings:
        """Build settings from environment variables with safe local defaults."""
        env_static = os.environ.get("ARGO_STATIC_DIR")
        if env_static is not None:
            static_dir = env_static
        else:
            candidate = Path(__file__).resolve().parents[2] / "frontend" / "dist"
            static_dir = str(candidate) if candidate.is_dir() else ""

        idle_raw = os.environ.get("ARGO_DESKTOP_IDLE_TIMEOUT_SECONDS", "300")
        try:
            idle_seconds = max(5.0, float(idle_raw))
        except ValueError:
            idle_seconds = 300.0

        def _clean_env(name: str) -> str:
            value = os.environ.get(name, "").strip()
            if not value or value.startswith("CHANGE_ME"):
                return ""
            return value

        google_client_id = _clean_env("ARGO_GOOGLE_CLIENT_ID")
        google_client_secret = _clean_env("ARGO_GOOGLE_CLIENT_SECRET")
        db_path = os.environ.get("ARGO_DB_PATH", "./data/argo.db")
        workspace_files_root = os.environ.get("ARGO_WORKSPACE_FILES_ROOT", "").strip() or str(
            Path(db_path).resolve().parent / "workspace_files"
        )

        return cls(
            master_key=os.environ.get("ARGO_MASTER_KEY", ""),
            db_path=db_path,
            valkey_url=os.environ.get("ARGO_VALKEY_URL", "valkey://valkey:6379/0"),
            desktop_volumes_root=os.environ.get("ARGO_DESKTOP_VOLUMES_ROOT", "/srv/argo/desktops"),
            public_base_url=os.environ.get("ARGO_PUBLIC_BASE_URL", "http://localhost:4180"),
            static_dir=static_dir,
            desktop_idle_timeout_seconds=idle_seconds,
            google_client_id=google_client_id,
            google_client_secret=google_client_secret,
            workspace_files_root=workspace_files_root,
        )
