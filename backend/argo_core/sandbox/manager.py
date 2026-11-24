"""Managed 1-bot-1-container Fedora 45 headless script sandbox lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import posixpath
import re
import shutil
import socket
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from argo_core.db.repositories import ArgoRepository, make_id
from argo_core.docker_mounts import resolve_host_bind_path
from argo_core.security.tenancy import normalize_email, normalize_visibility
from argo_core.security.vault import redact_secrets

if TYPE_CHECKING:
    from argo_core.bus.valkey_bus import EventBus
    from argo_core.watchdog.resource_guard import HostResourceGuard

logger = logging.getLogger(__name__)

SANDBOX_IMAGE = "ghcr.io/dimitribellini/argo-sandbox:latest"
SANDBOX_NETWORK = "argo-sandbox-net"
SANDBOX_UID = 1000
SANDBOX_GID = 1000
SANDBOX_USER = f"{SANDBOX_UID}:{SANDBOX_GID}"
SANDBOX_TMPFS_SIZE = "64m"
SANDBOX_TMPFS_OPTS = f"rw,noexec,nosuid,nodev,size={SANDBOX_TMPFS_SIZE}"
SANDBOX_MEM_LIMIT = "512m"
SANDBOX_RAM_LIMIT_MB = 512
SANDBOX_NANO_CPUS = 500_000_000
SANDBOX_PIDS_LIMIT = 128
SANDBOX_WORKDIR = "/workspace"
DEFAULT_SANDBOX_IDLE_TIMEOUT_SECONDS = 300.0
DEFAULT_SANDBOX_EXEC_TIMEOUT_SECONDS = 45.0

_SANDBOX_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_FORBIDDEN_IMAGE_TOKENS = ("ubuntu", "debian", "fedora:41", "fedora:43")
_FORBIDDEN_SANDBOX_NETWORKS = ("argo-core-net",)
_EXTRA_ISOLATION_HOSTS: dict[str, str] = {
    "argo-core": "127.0.0.1",
    "valkey": "127.0.0.1",
    "oauth2-proxy": "127.0.0.1",
    "host.docker.internal": "127.0.0.1",
    "metadata.google.internal": "127.0.0.1",
}


class SandboxConfigError(ValueError):
    """Raised when a sandbox configuration, slug, path, or image violates policy."""


class SandboxStartupBlockedError(RuntimeError):
    """Raised when launching a sandbox container is blocked by the >80% RAM gate."""

    def __init__(self, message: str, *, ram_percent: float) -> None:
        super().__init__(message)
        self.ram_percent = ram_percent


class SandboxRuntimeError(RuntimeError):
    """Raised when Docker/Podman sandbox orchestration fails at runtime."""


def validate_sandbox_slug(bot_slug: str) -> str:
    """Validate and normalize a container-safe sandbox bot slug."""
    cleaned = str(bot_slug or "").strip()
    if not _SANDBOX_SLUG_RE.fullmatch(cleaned):
        raise SandboxConfigError(
            f"Invalid sandbox bot slug '{bot_slug}'; expected lowercase alphanumeric/hyphen identifier."
        )
    return cleaned


def validate_sandbox_image(image: str) -> str:
    """Enforce Fedora 45+ open-source image policy and reject forbidden EOL/non-Fedora images."""
    cleaned = str(image or "").strip()
    lowered = cleaned.lower()
    if not lowered:
        raise SandboxConfigError("Sandbox container image cannot be empty.")
    for bad in _FORBIDDEN_IMAGE_TOKENS:
        if bad in lowered:
            raise SandboxConfigError(
                f"Forbidden container image '{image}': disallowed token '{bad}'."
            )
    return cleaned


def validate_sandbox_network(network: str) -> str:
    """Ensure sandbox containers never attach to control-plane argo-core-net."""
    cleaned = str(network or "").strip()
    lowered = cleaned.lower()
    if not lowered:
        raise SandboxConfigError("Sandbox network name cannot be empty.")
    for forbidden in _FORBIDDEN_SANDBOX_NETWORKS:
        if lowered == forbidden or lowered.endswith(f"_{forbidden}"):
            raise SandboxConfigError(
                f"Forbidden sandbox network '{network}': sandboxes cannot attach to control-plane network '{forbidden}'."
            )
    return cleaned


def _prepare_workspace_dir(host_dir: Path) -> None:
    """Ensure /workspace host mount and legacy root-owned entries are writable by UID 1000."""
    host_dir.mkdir(parents=True, exist_ok=True)
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    with contextlib.suppress(OSError):
        if host_dir.lstat().st_uid == 0:
            os.chown(host_dir, SANDBOX_UID, SANDBOX_GID)
        host_dir.chmod(0o755)
    with contextlib.suppress(OSError):
        for root, dirs, files in os.walk(host_dir, followlinks=False):
            root_path = Path(root)
            for dname in dirs:
                dp = root_path / dname
                with contextlib.suppress(OSError):
                    if not dp.is_symlink() and dp.lstat().st_uid == 0:
                        os.chown(dp, SANDBOX_UID, SANDBOX_GID)
            for fname in files:
                fp = root_path / fname
                with contextlib.suppress(OSError):
                    if not fp.is_symlink() and fp.lstat().st_uid == 0:
                        os.chown(fp, SANDBOX_UID, SANDBOX_GID)


def _prepare_workspace_file(target_file: Path, *, root_dir: Path, executable: bool) -> None:
    """Apply non-root-compatible permissions and UID 1000 ownership on saved /workspace scripts."""
    with contextlib.suppress(OSError):
        target_file.chmod(0o755 if executable else 0o644)
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    resolved_root = root_dir.resolve()
    cur = target_file.parent.resolve()
    while cur == resolved_root or cur.is_relative_to(resolved_root):
        with contextlib.suppress(OSError):
            os.chown(cur, SANDBOX_UID, SANDBOX_GID)
        if cur == resolved_root:
            break
        cur = cur.parent
    with contextlib.suppress(OSError):
        os.chown(target_file, SANDBOX_UID, SANDBOX_GID)


def validate_workspace_relative_path(raw_path: str) -> str:
    """Ensure script filenames stay safely within /workspace without traversal or leading dashes."""
    candidate = str(raw_path or "").strip().replace("\\", "/")
    if not candidate:
        raise SandboxConfigError("Script save_as path cannot be empty.")
    if "\x00" in candidate:
        raise SandboxConfigError("Script path contains NUL byte.")
    if candidate.startswith("/") or candidate.startswith("-"):
        raise SandboxConfigError(
            f"Script path '{raw_path}' must be relative inside {SANDBOX_WORKDIR}."
        )
    parts = [p for p in candidate.split("/") if p != ""]
    if not parts or any(part in {".", ".."} or part.startswith("-") for part in parts):
        raise SandboxConfigError(f"Unsafe workspace relative path '{raw_path}'.")
    normalized = posixpath.normpath("/".join(parts))
    if normalized.startswith("..") or normalized == "." or normalized.startswith("/"):
        raise SandboxConfigError(f"Unsafe workspace relative path '{raw_path}'.")
    return normalized


def _validate_container_workdir(raw_workdir: str | None) -> str:
    candidate = str(raw_workdir or SANDBOX_WORKDIR).strip() or SANDBOX_WORKDIR
    if "\x00" in candidate:
        raise SandboxConfigError("Workdir contains NUL byte.")
    norm = posixpath.normpath(candidate)
    if norm != SANDBOX_WORKDIR and not norm.startswith(f"{SANDBOX_WORKDIR}/"):
        raise SandboxConfigError(
            f"Workdir '{raw_workdir}' must stay inside {SANDBOX_WORKDIR}."
        )
    return norm


@dataclass(frozen=True, slots=True)
class SandboxRuntimeSpec:
    """Declarative single-bot script sandbox container specification."""

    bot_slug: str
    container_name: str
    image: str
    network: str
    host_volume_path: str
    mem_limit: str = SANDBOX_MEM_LIMIT
    nano_cpus: int = SANDBOX_NANO_CPUS
    pids_limit: int = SANDBOX_PIDS_LIMIT
    user: str = SANDBOX_USER
    read_only: bool = True
    tmpfs_size: str = SANDBOX_TMPFS_SIZE
    environment: dict[str, str] | None = None


class SandboxDriver(Protocol):
    """Backend driver interface for starting, executing scripts in, and stopping sandboxes."""

    async def ensure_started(self, spec: SandboxRuntimeSpec) -> dict[str, Any]:
        """Start (or create and start) a bot's isolated headless sandbox container."""
        ...

    async def exec_in_container(
        self,
        container_name: str,
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        workdir: str = SANDBOX_WORKDIR,
        timeout_seconds: float = DEFAULT_SANDBOX_EXEC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        """Execute a command vector inside a running sandbox container."""
        ...

    async def ensure_stopped(self, container_name: str, *, timeout: int = 10) -> bool:
        """Stop a sandbox container while preserving its /workspace bind volume."""
        ...

    async def remove_container(self, container_name: str, *, timeout: int = 5) -> bool:
        """Stop and remove a bot's sandbox container permanently."""
        ...

    async def inspect_status(self, container_name: str) -> dict[str, Any]:
        """Return live container running state and memory usage."""
        ...


class InMemorySandboxDriver:
    """Deterministic in-memory driver used when /var/run/docker.sock is absent."""

    def __init__(
        self,
        *,
        exec_callback: Callable[
            [str, list[str], dict[str, str] | None, str, float],
            dict[str, Any] | Awaitable[dict[str, Any]],
        ]
        | None = None,
    ) -> None:
        self.containers: dict[str, dict[str, Any]] = {}
        self.start_calls: list[SandboxRuntimeSpec] = []
        self.stop_calls: list[str] = []
        self.exec_calls: list[dict[str, Any]] = []
        self._exec_callback = exec_callback

    async def ensure_started(self, spec: SandboxRuntimeSpec) -> dict[str, Any]:
        validate_sandbox_image(spec.image)
        with contextlib.suppress(OSError):
            Path(spec.host_volume_path).mkdir(parents=True, exist_ok=True)
        self.start_calls.append(spec)
        state = {
            "container_id": f"sim-{spec.container_name}",
            "container_name": spec.container_name,
            "image": spec.image,
            "network": spec.network,
            "host_volume_path": spec.host_volume_path,
            "mem_limit": spec.mem_limit,
            "nano_cpus": spec.nano_cpus,
            "pids_limit": spec.pids_limit,
            "user": spec.user,
            "read_only": spec.read_only,
            "tmpfs_size": spec.tmpfs_size,
            "status": "running",
            "ram_mb": 48,
        }
        self.containers[spec.container_name] = state
        return dict(state)

    async def exec_in_container(
        self,
        container_name: str,
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        workdir: str = SANDBOX_WORKDIR,
        timeout_seconds: float = DEFAULT_SANDBOX_EXEC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        existing = self.containers.get(container_name)
        if not existing or existing.get("status") != "running":
            raise SandboxRuntimeError(f"Sandbox container '{container_name}' is not running.")
        clean_env = dict(env or {})
        self.exec_calls.append(
            {
                "container_name": container_name,
                "cmd": list(cmd),
                "env": clean_env,
                "workdir": workdir,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self._exec_callback is not None:
            res = self._exec_callback(container_name, list(cmd), clean_env, workdir, timeout_seconds)
            if asyncio.iscoroutine(res) or isinstance(res, Awaitable):
                res = await res  # type: ignore[misc]
            return dict(res)
        return {
            "exit_code": 0,
            "stdout": f"[sandbox:{container_name}] executed {' '.join(cmd)[:160]}",
            "stderr": "",
            "timed_out": False,
        }

    async def ensure_stopped(self, container_name: str, *, timeout: int = 10) -> bool:
        del timeout
        self.stop_calls.append(container_name)
        existing = self.containers.get(container_name)
        if existing is None:
            return False
        was_running = existing.get("status") == "running"
        existing["status"] = "exited"
        existing["ram_mb"] = 0
        return was_running

    async def remove_container(self, container_name: str, *, timeout: int = 5) -> bool:
        del timeout
        self.stop_calls.append(container_name)
        existed = container_name in self.containers
        self.containers.pop(container_name, None)
        return existed

    async def inspect_status(self, container_name: str) -> dict[str, Any]:
        existing = self.containers.get(container_name)
        if existing is None:
            return {"running": False, "ram_mb": 0, "container_id": None}
        running = existing.get("status") == "running"
        return {
            "running": running,
            "ram_mb": int(existing.get("ram_mb", 0)) if running else 0,
            "container_id": existing.get("container_id"),
        }


class DockerSandboxDriver:
    """Production Docker/Podman socket driver using lazy-imported docker >= 7.2.0."""

    def __init__(
        self,
        *,
        client: Any = None,
        base_url: str = "unix:///var/run/docker.sock",
    ) -> None:
        self._client = client
        self._base_url = base_url

    def _get_client(self) -> tuple[Any, type[Exception]]:
        import docker  # type: ignore[import-not-found]
        import docker.errors  # type: ignore[import-not-found]

        if self._client is None:
            try:
                self._client = docker.DockerClient(base_url=self._base_url, timeout=20)
            except TypeError:
                self._client = docker.DockerClient(base_url=self._base_url)
        not_found_exc = getattr(docker.errors, "NotFound", KeyError)
        return self._client, not_found_exc

    def _resolve_network(self, client: Any, preferred_network: str) -> str:
        """Resolve or create an ICC-disabled sandbox bridge isolated from argo-core and desktops."""
        clean_pref = validate_sandbox_network(preferred_network)
        if hasattr(client, "networks"):
            with contextlib.suppress(Exception):
                all_nets = [
                    str(getattr(n, "name", ""))
                    for n in client.networks.list()
                    if getattr(n, "name", "")
                ]
                if clean_pref in all_nets:
                    return clean_pref
                for net_name in all_nets:
                    if net_name.endswith(f"_{clean_pref}"):
                        return net_name
                for net_opts in (
                    {"com.docker.network.bridge.enable_icc": "false"},
                    {"isolate": "true"},
                    None,
                ):
                    try:
                        if net_opts is not None:
                            client.networks.create(clean_pref, driver="bridge", options=net_opts)
                        else:
                            logger.warning(
                                "Creating sandbox network '%s' without driver ICC isolation options.",
                                clean_pref,
                            )
                            client.networks.create(clean_pref, driver="bridge")
                        return clean_pref
                    except Exception:
                        continue
        return clean_pref

    @staticmethod
    def _container_matches_hardening(
        attrs: dict[str, Any],
        *,
        spec: SandboxRuntimeSpec,
        target_network: str,
        expected_host_volume: str | None = None,
    ) -> bool:
        """Verify existing sandbox container enforces Phase 1 non-root, read-only, network, and bind mount isolation."""
        host_cfg = attrs.get("HostConfig") if isinstance(attrs.get("HostConfig"), dict) else {}
        cfg = attrs.get("Config") if isinstance(attrs.get("Config"), dict) else {}
        net_map = (
            (attrs.get("NetworkSettings") or {}).get("Networks") or {}
            if isinstance(attrs.get("NetworkSettings"), dict)
            else {}
        )
        readonly_ok = bool(host_cfg.get("ReadonlyRootfs", False)) == bool(spec.read_only)
        user_ok = str(cfg.get("User") or "") == str(spec.user)
        net_ok = set(net_map.keys()) == {target_network}
        raw_hosts = host_cfg.get("ExtraHosts")
        hosts_list = list(raw_hosts) if isinstance(raw_hosts, list) else []
        hosts_ok = all(f"{host}:{ip}" in hosts_list for host, ip in _EXTRA_ISOLATION_HOSTS.items())
        mount_ok = True
        raw_mounts = attrs.get("Mounts")
        if expected_host_volume and isinstance(raw_mounts, list):
            expected_norm = posixpath.normpath(expected_host_volume)
            mount_ok = any(
                isinstance(m, dict)
                and posixpath.normpath(str(m.get("Destination") or "")) == SANDBOX_WORKDIR
                and posixpath.normpath(str(m.get("Source") or "")) == expected_norm
                for m in raw_mounts
            )
        return readonly_ok and user_ok and net_ok and hosts_ok and mount_ok

    def _sync_ensure_started(self, spec: SandboxRuntimeSpec) -> dict[str, Any]:
        validate_sandbox_image(spec.image)
        validate_sandbox_network(spec.network)
        _prepare_workspace_dir(Path(spec.host_volume_path))
        try:
            client, not_found_exc = self._get_client()
            target_network = self._resolve_network(client, spec.network)
            host_bind_path = resolve_host_bind_path(client, spec.host_volume_path)
            container = None
            try:
                container = client.containers.get(spec.container_name)
            except Exception as exc:
                if not isinstance(exc, not_found_exc) and type(exc).__name__ != "NotFound":
                    raise

            if container is not None and isinstance(getattr(container, "attrs", None), dict):
                if not self._container_matches_hardening(
                    container.attrs,
                    spec=spec,
                    target_network=target_network,
                    expected_host_volume=host_bind_path,
                ):
                    with contextlib.suppress(Exception):
                        container.stop(timeout=5)
                    container.remove(force=True)
                    container = None

            if container is None:
                if hasattr(client, "images"):
                    try:
                        client.images.get(spec.image)
                    except Exception as exc:
                        if isinstance(exc, not_found_exc) or type(exc).__name__ in {
                            "NotFound",
                            "ImageNotFound",
                        }:
                            if "/" in spec.image:
                                try:
                                    client.images.pull(spec.image)
                                except Exception as pull_exc:
                                    raise SandboxRuntimeError(
                                        f"Failed to pull sandbox image '{spec.image}': {pull_exc}. "
                                        f"If the registry requires authentication, run 'docker pull {spec.image}' on the host."
                                    ) from pull_exc
                            else:
                                raise SandboxRuntimeError(
                                    f"Local sandbox image '{spec.image}' is not built yet. "
                                    f"Build it with: docker build -f Dockerfile.sandbox -t {spec.image} ."
                                ) from exc
                        else:
                            raise
                container = client.containers.run(
                    spec.image,
                    name=spec.container_name,
                    command=["sleep", "infinity"],
                    detach=True,
                    working_dir=SANDBOX_WORKDIR,
                    user=spec.user,
                    read_only=spec.read_only,
                    tmpfs={"/tmp": f"rw,noexec,nosuid,nodev,size={spec.tmpfs_size}"},
                    mem_limit=spec.mem_limit,
                    nano_cpus=spec.nano_cpus,
                    pids_limit=spec.pids_limit,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    extra_hosts=dict(_EXTRA_ISOLATION_HOSTS),
                    network=target_network,
                    volumes={host_bind_path: {"bind": SANDBOX_WORKDIR, "mode": "rw"}},
                    environment=dict(spec.environment or {}),
                    labels={
                        "argo.managed": "true",
                        "argo.runtime": "sandbox",
                        "argo.bot_slug": spec.bot_slug,
                        "argo.isolation": "1-bot-1-container",
                        "argo.network_isolation": "icc-disabled",
                    },
                    restart_policy={"Name": "no"},
                )
            else:
                if getattr(container, "status", "") != "running":
                    container.start()
                if hasattr(container, "reload"):
                    container.reload()
                attrs = getattr(container, "attrs", None)
                if isinstance(attrs, dict) and hasattr(client, "networks"):
                    attached = set((attrs.get("NetworkSettings", {}).get("Networks") or {}).keys())
                    if target_network not in attached:
                        with contextlib.suppress(Exception):
                            client.networks.get(target_network).connect(container)

            return {
                "container_id": str(getattr(container, "id", spec.container_name)),
                "container_name": spec.container_name,
                "status": "running",
                "ram_mb": 48,
            }
        except (SandboxConfigError, SandboxRuntimeError):
            raise
        except Exception as exc:
            raise SandboxRuntimeError(
                f"Docker sandbox driver error for '{spec.container_name}': {exc}"
            ) from exc

    async def ensure_started(self, spec: SandboxRuntimeSpec) -> dict[str, Any]:
        return await asyncio.to_thread(self._sync_ensure_started, spec)

    def _sync_exec_in_container(
        self,
        container_name: str,
        cmd: list[str],
        env: dict[str, str] | None,
        workdir: str,
    ) -> dict[str, Any]:
        client, not_found_exc = self._get_client()
        try:
            container = client.containers.get(container_name)
        except Exception as exc:
            if isinstance(exc, not_found_exc) or type(exc).__name__ == "NotFound":
                raise SandboxRuntimeError(
                    f"Sandbox container '{container_name}' does not exist."
                ) from exc
            raise
        exec_res = container.exec_run(
            cmd,
            workdir=workdir,
            environment=env or {},
            user=SANDBOX_USER,
            demux=True,
        )
        exit_code = int(getattr(exec_res, "exit_code", 0) or 0)
        output = getattr(exec_res, "output", (b"", b""))
        if isinstance(output, tuple) and len(output) == 2:
            raw_out, raw_err = output
        else:
            raw_out, raw_err = output, b""
        stdout = (
            raw_out.decode("utf-8", errors="replace")
            if isinstance(raw_out, (bytes, bytearray))
            else str(raw_out or "")
        )
        stderr = (
            raw_err.decode("utf-8", errors="replace")
            if isinstance(raw_err, (bytes, bytearray))
            else str(raw_err or "")
        )
        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": False,
        }

    async def exec_in_container(
        self,
        container_name: str,
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        workdir: str = SANDBOX_WORKDIR,
        timeout_seconds: float = DEFAULT_SANDBOX_EXEC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._sync_exec_in_container, container_name, cmd, env, workdir),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            return {
                "exit_code": 124,
                "stdout": "",
                "stderr": f"Sandbox script timed out after {int(timeout_seconds)}s.",
                "timed_out": True,
            }
        except SandboxRuntimeError:
            raise
        except Exception as exc:
            raise SandboxRuntimeError(
                f"Docker sandbox exec failed in '{container_name}': {exc}"
            ) from exc

    def _sync_ensure_stopped(self, container_name: str, timeout: int) -> bool:
        try:
            client, not_found_exc = self._get_client()
            try:
                container = client.containers.get(container_name)
            except Exception as exc:
                if isinstance(exc, not_found_exc) or type(exc).__name__ == "NotFound":
                    return False
                raise
            container.stop(timeout=timeout)
            return True
        except Exception as exc:
            raise SandboxRuntimeError(
                f"Docker sandbox stop failed for '{container_name}': {exc}"
            ) from exc

    async def ensure_stopped(self, container_name: str, *, timeout: int = 10) -> bool:
        return await asyncio.to_thread(self._sync_ensure_stopped, container_name, timeout)

    def _sync_remove_container(self, container_name: str, timeout: int) -> bool:
        try:
            client, not_found_exc = self._get_client()
            try:
                container = client.containers.get(container_name)
            except Exception as exc:
                if isinstance(exc, not_found_exc) or type(exc).__name__ == "NotFound":
                    return False
                raise
            with contextlib.suppress(Exception):
                container.stop(timeout=timeout)
            container.remove(force=True)
            return True
        except Exception as exc:
            if type(exc).__name__ == "NotFound":
                return False
            raise SandboxRuntimeError(
                f"Docker sandbox remove failed for '{container_name}': {exc}"
            ) from exc

    async def remove_container(self, container_name: str, *, timeout: int = 5) -> bool:
        return await asyncio.to_thread(self._sync_remove_container, container_name, timeout)

    def _sync_inspect_status(self, container_name: str) -> dict[str, Any]:
        try:
            client, not_found_exc = self._get_client()
            try:
                container = client.containers.get(container_name)
            except Exception as exc:
                if isinstance(exc, not_found_exc) or type(exc).__name__ == "NotFound":
                    return {"running": False, "ram_mb": 0, "container_id": None}
                raise
            if hasattr(container, "reload"):
                container.reload()
            running = getattr(container, "status", "") == "running"
            return {
                "running": running,
                "ram_mb": 48 if running else 0,
                "container_id": str(getattr(container, "id", container_name)),
            }
        except Exception:
            return {"running": False, "ram_mb": 0, "container_id": None}

    async def inspect_status(self, container_name: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._sync_inspect_status, container_name)


class SandboxManager:
    """Manages per-bot isolated headless script sandboxes, RAM capacity gates, and idle reaping."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        bus: EventBus,
        guard: HostResourceGuard,
        volumes_root: str | Path,
        idle_timeout_seconds: float = DEFAULT_SANDBOX_IDLE_TIMEOUT_SECONDS,
        image: str = SANDBOX_IMAGE,
        network: str | None = None,
        driver: SandboxDriver | None = None,
        clock: Callable[[], float] | None = None,
        multi_user: bool = False,
        max_active_sandboxes_per_user: int = 4,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._guard = guard
        self._volumes_root = Path(volumes_root)
        self._idle_timeout_seconds = max(1.0, float(idle_timeout_seconds))
        self._image = validate_sandbox_image(image)
        self._network = validate_sandbox_network(
            (network or os.environ.get("ARGO_SANDBOX_NETWORK", "") or SANDBOX_NETWORK).strip()
            or SANDBOX_NETWORK
        )
        if driver is not None:
            self._driver: SandboxDriver = driver
        elif Path("/var/run/docker.sock").exists():
            self._driver = DockerSandboxDriver()
        else:
            self._driver = InMemorySandboxDriver()
        self._clock = clock or time.monotonic
        self._multi_user = bool(multi_user)
        self._max_active_sandboxes_per_user = max(0, int(max_active_sandboxes_per_user))
        self._last_activity_at: dict[str, float] = {}

    def touch_activity(self, slug: str) -> None:
        """Reset idle hibernation countdown for an active sandbox bot."""
        with contextlib.suppress(SandboxConfigError):
            clean = validate_sandbox_slug(slug)
            self._last_activity_at[clean] = self._clock()

    def build_spec(self, slug: str) -> SandboxRuntimeSpec:
        """Build the hardened Fedora 45 headless sandbox container specification for a bot."""
        clean_slug = validate_sandbox_slug(slug)
        host_dir = self._volumes_root / clean_slug
        return SandboxRuntimeSpec(
            bot_slug=clean_slug,
            container_name=f"argo-sandbox-{clean_slug}",
            image=self._image,
            network=self._network,
            host_volume_path=str(host_dir),
            mem_limit=SANDBOX_MEM_LIMIT,
            nano_cpus=SANDBOX_NANO_CPUS,
            pids_limit=SANDBOX_PIDS_LIMIT,
            user=SANDBOX_USER,
            read_only=True,
            tmpfs_size=SANDBOX_TMPFS_SIZE,
            environment={
                "HOME": SANDBOX_WORKDIR,
                "TMPDIR": "/tmp",
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )

    def _enforce_user_sandbox_quota(self, bot: dict[str, Any]) -> None:
        """Enforce per-user active Script Sandbox quota in opt-in multi-user mode."""
        if not self._multi_user:
            return
        if bot.get("sandbox_state") == "running":
            return
        owner = normalize_email(bot.get("owner_email"))
        if not owner:
            return
        user_rec = self._repo.get_user(owner) if hasattr(self._repo, "get_user") else None
        raw_override = user_rec.get("max_active_sandboxes") if isinstance(user_rec, dict) else None
        if raw_override is not None:
            effective_cap = max(0, int(raw_override))
        else:
            effective_cap = self._max_active_sandboxes_per_user
            if effective_cap <= 0:
                return
        active_for_owner = [
            b
            for b in self._repo.list_bots()
            if b.get("runtime") == "sandbox"
            and b.get("sandbox_state") == "running"
            and normalize_email(b.get("owner_email")) == owner
        ]
        if len(active_for_owner) >= effective_cap:
            telemetry = self._guard.sample()
            raise SandboxStartupBlockedError(
                (
                    f"User '{owner}' reached the active Script Sandbox quota "
                    f"({effective_cap} active)."
                ),
                ram_percent=telemetry.ram_percent,
            )

    async def ensure_started(
        self,
        slug: str,
        *,
        reason: str = "manual",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Boot argo-sandbox-<slug> under the 80% Host RAM gate and Valkey mutex."""
        clean_slug = validate_sandbox_slug(slug)
        bot = self._repo.get_bot(clean_slug)
        if bot["runtime"] != "sandbox":
            raise SandboxConfigError(f"Bot '{clean_slug}' is configured for '{bot['runtime']}' runtime, not 'sandbox'.")

        spec = self.build_spec(clean_slug)
        if bot.get("sandbox_state") == "running":
            status_info = await self._driver.inspect_status(spec.container_name)
            if status_info.get("running"):
                self.touch_activity(clean_slug)
                return bot

        self._enforce_user_sandbox_quota(bot)
        allowed, telemetry = self._guard.can_start_desktop()
        corr = correlation_id or make_id("corr")
        if not allowed:
            await self._bus.publish(
                correlation_id=corr,
                source_slug="host-guard",
                target_slug=clean_slug,
                event_type="sandbox.queued_ram_gate",
                payload={
                    "category": "alerts",
                    "title": f"RAM Gate Blocked {spec.container_name}",
                    "badge": f"Queued · RAM {telemetry.ram_percent}%",
                    "badge_tone": "amber",
                    "summary": (
                        f"Host memory at {telemetry.ram_percent}% (>=80%). "
                        f"Blocked startup of lightweight sandbox {spec.container_name}."
                    ),
                    "meta": f"Reason: {reason}",
                },
                hop_count=1,
            )
            raise SandboxStartupBlockedError(
                f"Host RAM at {telemetry.ram_percent}% (>=80%); blocking startup of {spec.container_name}.",
                ram_percent=telemetry.ram_percent,
            )

        acquired = await self._bus.acquire_lock(
            "sandbox", clean_slug, "sandbox-manager", ttl_seconds=90
        )
        if not acquired:
            raise SandboxRuntimeError(f"Sandbox container '{spec.container_name}' is busy.")
        try:
            start_info = await self._driver.ensure_started(spec)
            ram_mb = int(start_info.get("ram_mb") or 48)
            updated = self._repo.set_sandbox_state(clean_slug, "running", ram_mb=ram_mb)
            self._last_activity_at[clean_slug] = self._clock()
            await self._bus.publish(
                correlation_id=corr,
                source_slug="host-guard",
                target_slug=clean_slug,
                event_type="sandbox.started",
                payload={
                    "category": "reviews",
                    "title": f"Started {spec.container_name}",
                    "badge": f"Fedora 45 CLI · {ram_mb} MB",
                    "badge_tone": "emerald",
                    "summary": f"On-demand isolated script sandbox started (reason: {reason}).",
                    "meta": f"Workspace: {spec.host_volume_path}",
                },
                hop_count=1,
            )
            return updated
        finally:
            await self._bus.release_lock("sandbox", clean_slug, "sandbox-manager")

    async def exec_script(
        self,
        slug: str,
        *,
        command: str | None = None,
        commands: list[str] | None = None,
        script: str | None = None,
        interpreter: str = "bash",
        save_as: str | None = None,
        workdir: str | None = SANDBOX_WORKDIR,
        timeout_seconds: float | int | None = DEFAULT_SANDBOX_EXEC_TIMEOUT_SECONDS,
        extra_env: dict[str, str] | None = None,
        redact_values: list[str] | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute a bash or Python script/command inside an isolated bot's headless sandbox."""
        clean_slug = validate_sandbox_slug(slug)
        clean_interp = str(interpreter or "bash").strip().lower()
        if clean_interp not in {"bash", "python3"}:
            raise SandboxConfigError(
                f"Unsupported sandbox interpreter '{interpreter}'; expected 'bash' or 'python3'."
            )
        clean_workdir = _validate_container_workdir(workdir)
        clamped_timeout = max(
            5.0,
            min(120.0, float(timeout_seconds or DEFAULT_SANDBOX_EXEC_TIMEOUT_SECONDS)),
        )

        await self.ensure_started(
            clean_slug, reason="sandbox_exec", correlation_id=correlation_id
        )

        spec = self.build_spec(clean_slug)
        host_dir = Path(spec.host_volume_path).resolve()
        _prepare_workspace_dir(host_dir)
        saved_script_path: str | None = None

        clean_commands = [str(c).strip() for c in (commands or []) if str(c).strip()]
        script_body = str(script or "")
        command_text = str(command or "").strip()

        if save_as and str(save_as).strip():
            rel_path = validate_workspace_relative_path(str(save_as))
            body_to_write = script_body or "\n".join(clean_commands) or command_text
            if not body_to_write.strip():
                raise SandboxConfigError("Missing script or command content when save_as is provided.")
            target_file = (host_dir / rel_path).resolve()
            if not target_file.is_relative_to(host_dir):
                raise SandboxConfigError(f"Unsafe workspace target '{save_as}'.")
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(body_to_write, encoding="utf-8")
            _prepare_workspace_file(
                target_file,
                root_dir=host_dir,
                executable=(clean_interp == "bash"),
            )
            saved_script_path = f"{SANDBOX_WORKDIR}/{rel_path}"
            container_cmd = [clean_interp, saved_script_path]
        elif script_body.strip():
            container_cmd = (
                ["python3", "-c", script_body]
                if clean_interp == "python3"
                else ["/bin/bash", "-lc", script_body]
            )
        elif clean_commands:
            if clean_interp == "python3":
                container_cmd = ["python3", "-c", "\n".join(clean_commands)]
            else:
                container_cmd = ["/bin/bash", "-lc", "set -e\n" + "\n".join(clean_commands)]
        elif command_text:
            container_cmd = (
                ["python3", "-c", command_text]
                if clean_interp == "python3"
                else ["/bin/bash", "-lc", command_text]
            )
        else:
            raise SandboxConfigError(
                "Missing command, commands, or script for sandbox_exec."
            )

        t0 = time.monotonic()
        raw_res = await self._driver.exec_in_container(
            spec.container_name,
            container_cmd,
            env=extra_env,
            workdir=clean_workdir,
            timeout_seconds=clamped_timeout,
        )
        elapsed_ms = max(0, int((time.monotonic() - t0) * 1000))
        self.touch_activity(clean_slug)

        secrets = list(redact_values or [])
        stdout_txt = redact_secrets(str(raw_res.get("stdout") or ""), secrets)[:16_000]
        stderr_txt = redact_secrets(str(raw_res.get("stderr") or ""), secrets)[:16_000]
        exit_code = int(raw_res.get("exit_code") or 0)
        timed_out = bool(raw_res.get("timed_out"))
        status = "timeout" if timed_out else ("ok" if exit_code == 0 else "command_failed")
        return {
            "status": status,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": stdout_txt,
            "stderr": stderr_txt,
            "workdir": clean_workdir,
            "interpreter": clean_interp,
            "container_name": spec.container_name,
            "saved_script": saved_script_path,
            "elapsed_ms": elapsed_ms,
        }

    async def stop_sandbox(self, slug: str, *, reason: str = "manual") -> dict[str, Any]:
        """Stop argo-sandbox-<slug> gracefully while preserving its persistent /workspace volume."""
        clean_slug = validate_sandbox_slug(slug)
        bot = self._repo.get_bot(clean_slug)
        if bot["runtime"] != "sandbox":
            raise SandboxConfigError(f"Bot '{clean_slug}' does not use sandbox runtime.")

        container_name = f"argo-sandbox-{clean_slug}"
        acquired = await self._bus.acquire_lock(
            "sandbox", clean_slug, "sandbox-manager", ttl_seconds=60
        )
        if not acquired:
            raise SandboxRuntimeError(f"Sandbox container '{container_name}' is busy.")
        try:
            await self._driver.ensure_stopped(container_name)
            self._last_activity_at.pop(clean_slug, None)
            updated = self._repo.set_sandbox_state(clean_slug, "hibernated", ram_mb=0)
            event_type = (
                "sandbox.auto_hibernated" if reason == "idle_timeout" else "sandbox.hibernated"
            )
            await self._bus.publish(
                correlation_id=make_id("corr"),
                source_slug="host-guard",
                target_slug=clean_slug,
                event_type=event_type,
                payload={
                    "category": "alerts",
                    "title": f"Stopped {container_name}",
                    "badge": "Auto-Sleep · 0 MB" if reason == "idle_timeout" else "Stopped · 0 MB",
                    "badge_tone": "slate",
                    "summary": f"Script sandbox stopped (reason: {reason}); persistent /workspace volume preserved.",
                    "meta": f"Reason: {reason}",
                },
                hop_count=1,
            )
            return updated
        finally:
            await self._bus.release_lock("sandbox", clean_slug, "sandbox-manager")

    async def stop_all_sandboxes(
        self,
        *,
        reason: str = "manual",
        owner_email: str | None = None,
    ) -> list[str]:
        """Stop all running script sandbox containers (optionally scoped to owner_email)."""
        norm_owner: str | None = None
        if owner_email is not None and self._multi_user:
            norm_owner = normalize_email(owner_email)
            if not norm_owner:
                return []
        stopped: list[str] = []
        for bot in self._repo.list_bots():
            if bot["runtime"] != "sandbox" or bot.get("sandbox_state") != "running":
                continue
            if norm_owner is not None and normalize_email(bot.get("owner_email")) != norm_owner:
                continue
            await self.stop_sandbox(bot["slug"], reason=reason)
            stopped.append(bot["slug"])
        return stopped

    async def destroy_sandbox(self, slug: str, *, remove_volume: bool = True) -> None:
        """Stop and remove a bot's sandbox container, locks, and optional workspace volume."""
        try:
            clean_slug = validate_sandbox_slug(slug)
        except SandboxConfigError:
            return
        self._last_activity_at.pop(clean_slug, None)
        container_name = f"argo-sandbox-{clean_slug}"
        with contextlib.suppress(Exception):
            await self._driver.remove_container(container_name, timeout=5)
        with contextlib.suppress(Exception):
            await self._bus.release_lock("sandbox", clean_slug, "sandbox-manager")
        if remove_volume:
            with contextlib.suppress(Exception):
                root = self._volumes_root.resolve()
                vol = (self._volumes_root / clean_slug).resolve()
                if vol != root and vol.is_relative_to(root) and vol.exists():
                    await asyncio.to_thread(shutil.rmtree, vol, True)

    async def sweep_idle_sandboxes(self, *, owner_email: str | None = None) -> list[str]:
        """Auto-hibernate any sandbox container exceeding idle_timeout_seconds."""
        norm_owner: str | None = None
        if owner_email is not None and self._multi_user:
            norm_owner = normalize_email(owner_email)
            if not norm_owner:
                return []
        now = self._clock()
        stopped: list[str] = []
        for bot in self._repo.list_bots():
            if bot["runtime"] != "sandbox" or bot.get("sandbox_state") != "running":
                continue
            if norm_owner is not None and normalize_email(bot.get("owner_email")) != norm_owner:
                continue
            slug = bot["slug"]
            last_seen = self._last_activity_at.get(slug)
            if last_seen is None:
                self._last_activity_at[slug] = now
                continue
            if (now - last_seen) >= self._idle_timeout_seconds:
                await self.stop_sandbox(slug, reason="idle_timeout")
                stopped.append(slug)
        return stopped

    async def run_periodic_idle_sweep(self, interval_seconds: float = 30.0) -> None:
        """Background sandbox idle auto-sleep loop cleanly cancelled on app shutdown."""
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                await self.sweep_idle_sandboxes()
            except Exception as exc:
                logger.warning("Sandbox idle sweep error: %s", exc)

    def _sandbox_item_payload(
        self,
        item: dict[str, Any],
        *,
        bot_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        slug = item["bot_slug"]
        bot_info = bot_meta or {}
        last_seen = self._last_activity_at.get(slug)
        idle_seconds = (
            max(0, int(self._clock() - last_seen))
            if item.get("sandbox_state") == "running" and last_seen is not None
            else 0
        )
        owner_val = str(item.get("owner_email") or bot_info.get("owner_email") or "")
        vis_raw = item.get("visibility") or bot_info.get("visibility")
        vis_val = normalize_visibility(str(vis_raw) if vis_raw else None, default="shared")
        raw_groups = item.get("allowed_groups") if "allowed_groups" in item else bot_info.get("allowed_groups")
        allowed_groups = list(raw_groups or []) if vis_val == "team" else []
        return {
            **item,
            "owner_email": owner_val,
            "visibility": vis_val,
            "allowed_groups": allowed_groups,
            "image": self._image,
            "volume_path": str(self._volumes_root / slug),
            "idle_seconds": idle_seconds,
            "idle_timeout_seconds": int(self._idle_timeout_seconds),
        }

    def list_sandboxes_status(
        self,
        *,
        allowed_bot_slugs: set[str] | None = None,
    ) -> dict[str, Any]:
        """Return host telemetry and enriched lightweight script sandbox status cards."""
        sandboxes = self._repo.list_sandboxes()
        if isinstance(self._driver, DockerSandboxDriver):
            synced = False
            for sb in sandboxes:
                if sb.get("sandbox_state") == "running":
                    slug = str(sb["bot_slug"])
                    with contextlib.suppress(Exception):
                        st = self._driver._sync_inspect_status(f"argo-sandbox-{slug}")
                        if not st.get("running"):
                            self._repo.set_sandbox_state(slug, "hibernated", ram_mb=0)
                            synced = True
            if synced:
                sandboxes = self._repo.list_sandboxes()
        bots_by_slug = {b["slug"]: b for b in self._repo.list_bots()}
        if allowed_bot_slugs is not None:
            sandboxes = [s for s in sandboxes if str(s.get("bot_slug") or "") in allowed_bot_slugs]
        return {
            "host": self._guard.sample().to_dict(),
            "sandboxes": [
                self._sandbox_item_payload(
                    s,
                    bot_meta=bots_by_slug.get(str(s.get("bot_slug") or "")),
                )
                for s in sandboxes
            ],
        }
