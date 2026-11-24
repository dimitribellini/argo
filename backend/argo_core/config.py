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
    sandbox_volumes_root: str = ""
    sandbox_idle_timeout_seconds: float = 300.0
    sandbox_image: str = "ghcr.io/dimitribellini/argo-sandbox:latest"
    sandbox_network: str = "argo-sandbox-net"
    google_client_id: str = ""
    google_client_secret: str = ""
    workspace_files_root: str = ""
    ssh_audit_root: str = ""
    ssh_default_retention_hours: int = 24
    ssh_idle_timeout_seconds: float = 600.0
    require_sso: bool = False
    trusted_proxy_host: str = ""
    trusted_proxy_ips: tuple[str, ...] = ()
    proxy_secret: str = ""
    multi_user: bool = False
    admin_emails: tuple[str, ...] = ()
    max_active_desktops_per_user: int = 2
    max_active_sandboxes_per_user: int = 4
    auth_mode: str = ""
    google_auth_client_id: str = ""
    google_auth_client_secret: str = ""
    initial_admin_password: str = ""
    session_ttl_hours: int = 168

    def resolved_auth_mode(self) -> str:
        """Resolve effective auth mode ('sso' | 'local' | 'hybrid') safely."""
        raw = str(self.auth_mode or "").strip().lower()
        if raw in {"sso", "local", "hybrid"}:
            return raw
        if (
            self.trusted_proxy_host
            or self.trusted_proxy_ips
            or self.proxy_secret
            or not self.require_sso
        ):
            return "sso"
        return "hybrid"

    def google_auth_configured(self) -> bool:
        """Return True when native Sign in with Google OAuth credentials are configured."""
        return bool(
            str(self.google_auth_client_id or "").strip()
            and str(self.google_auth_client_secret or "").strip()
        )

    def resolved_google_integration_client(self) -> tuple[str, str]:
        """Return explicit bot Google OAuth client or fall back to Hybrid Sign-In credentials."""
        cid = str(self.google_client_id or "").strip()
        csec = str(self.google_client_secret or "").strip()
        if cid and csec:
            return cid, csec
        auth_cid = str(self.google_auth_client_id or "").strip()
        auth_csec = str(self.google_auth_client_secret or "").strip()
        if auth_cid and auth_csec:
            return auth_cid, auth_csec
        return cid, csec

    def resolved_sandbox_volumes_root(self) -> str:
        if self.sandbox_volumes_root and self.sandbox_volumes_root.strip():
            return self.sandbox_volumes_root.strip()
        return str(Path(self.desktop_volumes_root) / "_sandboxes")

    def resolved_workspace_files_root(self) -> str:
        if self.workspace_files_root and self.workspace_files_root.strip():
            return self.workspace_files_root.strip()
        return str(Path(self.db_path).resolve().parent / "workspace_files")

    def resolved_ssh_audit_root(self) -> str:
        if self.ssh_audit_root and self.ssh_audit_root.strip():
            return self.ssh_audit_root.strip()
        return str(Path(self.db_path).resolve().parent / "ssh_audit")

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

        sb_idle_raw = os.environ.get("ARGO_SANDBOX_IDLE_TIMEOUT_SECONDS", str(idle_seconds))
        try:
            sb_idle_seconds = max(5.0, float(sb_idle_raw))
        except ValueError:
            sb_idle_seconds = idle_seconds

        sandbox_volumes_root = os.environ.get("ARGO_SANDBOX_VOLUMES_ROOT", "").strip()
        sandbox_image = (
            os.environ.get("ARGO_SANDBOX_IMAGE", "").strip()
            or "ghcr.io/dimitribellini/argo-sandbox:latest"
        )
        sandbox_network = (
            os.environ.get("ARGO_SANDBOX_NETWORK", "").strip()
            or "argo-sandbox-net"
        )

        ssh_ret_raw = os.environ.get("ARGO_SSH_DEFAULT_RETENTION_HOURS", "24")
        try:
            ssh_retention_hours = max(1, min(8760, int(ssh_ret_raw)))
        except ValueError:
            ssh_retention_hours = 24

        ssh_idle_raw = os.environ.get("ARGO_SSH_IDLE_TIMEOUT_SECONDS", "600")
        try:
            ssh_idle_seconds = max(5.0, float(ssh_idle_raw))
        except ValueError:
            ssh_idle_seconds = 600.0

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
        ssh_audit_root = os.environ.get("ARGO_SSH_AUDIT_ROOT", "").strip() or str(
            Path(db_path).resolve().parent / "ssh_audit"
        )

        require_sso = os.environ.get("ARGO_REQUIRE_SSO", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        trusted_proxy_host = os.environ.get("ARGO_TRUSTED_PROXY_HOST", "").strip()
        trusted_proxy_ips = tuple(
            ip.strip()
            for ip in os.environ.get("ARGO_TRUSTED_PROXY_IPS", "").split(",")
            if ip.strip()
        )
        proxy_secret = os.environ.get("ARGO_PROXY_SECRET", "").strip()

        multi_user = os.environ.get("ARGO_MULTI_USER", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        admin_emails = tuple(
            dict.fromkeys(
                em.strip().lower()
                for em in os.environ.get("ARGO_ADMIN_EMAILS", "").split(",")
                if em.strip()
            )
        )
        try:
            max_active_desktops_per_user = max(
                0, int(os.environ.get("ARGO_MAX_ACTIVE_DESKTOPS_PER_USER", "2"))
            )
        except ValueError:
            max_active_desktops_per_user = 2
        try:
            max_active_sandboxes_per_user = max(
                0, int(os.environ.get("ARGO_MAX_ACTIVE_SANDBOXES_PER_USER", "4"))
            )
        except ValueError:
            max_active_sandboxes_per_user = 4

        auth_mode_raw = os.environ.get("ARGO_AUTH_MODE", "").strip().lower()
        auth_mode = auth_mode_raw if auth_mode_raw in {"sso", "local", "hybrid"} else ""
        google_auth_client_id = _clean_env("ARGO_GOOGLE_AUTH_CLIENT_ID")
        google_auth_client_secret = _clean_env("ARGO_GOOGLE_AUTH_CLIENT_SECRET")
        initial_admin_password = _clean_env("ARGO_INITIAL_ADMIN_PASSWORD")
        try:
            session_ttl_hours = max(
                1, min(720, int(os.environ.get("ARGO_SESSION_TTL_HOURS", "168")))
            )
        except ValueError:
            session_ttl_hours = 168

        return cls(
            master_key=os.environ.get("ARGO_MASTER_KEY", ""),
            db_path=db_path,
            valkey_url=os.environ.get("ARGO_VALKEY_URL", "valkey://valkey:6379/0"),
            desktop_volumes_root=os.environ.get("ARGO_DESKTOP_VOLUMES_ROOT", "/srv/argo/desktops"),
            sandbox_volumes_root=sandbox_volumes_root,
            public_base_url=os.environ.get("ARGO_PUBLIC_BASE_URL", "http://localhost:4180"),
            static_dir=static_dir,
            desktop_idle_timeout_seconds=idle_seconds,
            sandbox_idle_timeout_seconds=sb_idle_seconds,
            sandbox_image=sandbox_image,
            sandbox_network=sandbox_network,
            google_client_id=google_client_id,
            google_client_secret=google_client_secret,
            workspace_files_root=workspace_files_root,
            ssh_audit_root=ssh_audit_root,
            ssh_default_retention_hours=ssh_retention_hours,
            ssh_idle_timeout_seconds=ssh_idle_seconds,
            require_sso=require_sso,
            trusted_proxy_host=trusted_proxy_host,
            trusted_proxy_ips=trusted_proxy_ips,
            proxy_secret=proxy_secret,
            multi_user=multi_user,
            admin_emails=admin_emails,
            max_active_desktops_per_user=max_active_desktops_per_user,
            max_active_sandboxes_per_user=max_active_sandboxes_per_user,
            auth_mode=auth_mode,
            google_auth_client_id=google_auth_client_id,
            google_auth_client_secret=google_auth_client_secret,
            initial_admin_password=initial_admin_password,
            session_ttl_hours=session_ttl_hours,
        )
