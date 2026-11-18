"""Managed 1-bot-1-container Fedora XFCE + Selkies desktop lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import html
import io
import logging
import os
import re
import shutil
import socket
import tarfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from argo_core.db.repositories import ArgoRepository, make_id, utc_now
from argo_core.desktop.mcp_bridge import (
    DESKTOP_AGENT_VERSION,
    DESKTOP_MCP_PORT,
    _DESKTOP_AGENT_SCRIPT,
)

if TYPE_CHECKING:
    from argo_core.bus.valkey_bus import EventBus
    from argo_core.connectors.telegram_bot import TelegramBotService
    from argo_core.watchdog.resource_guard import HostResourceGuard

logger = logging.getLogger(__name__)

DESKTOP_IMAGE = "lscr.io/linuxserver/webtop:fedora-xfce"
DESKTOP_NETWORK = "argo-net"
DESKTOP_MEM_LIMIT = "2g"
DESKTOP_NANO_CPUS = 1_500_000_000
DESKTOP_SHM_SIZE = "1g"
SELKIES_HTTP_PORT = 3000
SELKIES_HTTPS_PORT = 3001
CDP_PORT = 9222
MCP_PORT = DESKTOP_MCP_PORT
DEFAULT_IDLE_TIMEOUT_SECONDS = 300.0

_DESKTOP_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_FORBIDDEN_IMAGE_TOKENS = ("ubuntu", "debian", "fedora:41", "fedora:43")
_LEGACY_VNC_PATH_TOKENS = ("vnc", "novnc", "rfb", "5900", "6080")


class DesktopConfigError(ValueError):
    """Raised when a desktop configuration, slug, image, or route path is invalid."""


class DesktopStartupBlockedError(RuntimeError):
    """Raised when launching a desktop container is blocked by the >80% RAM gate."""

    def __init__(self, message: str, *, ram_percent: float) -> None:
        super().__init__(message)
        self.ram_percent = ram_percent


class DesktopStateError(RuntimeError):
    """Raised when an operation requires a running desktop container."""


class DesktopRuntimeError(RuntimeError):
    """Raised when Docker/Selkies container orchestration fails at runtime."""


_CDP_PROXY_SCRIPT = '''"""Lightweight internal CDP :9222 -> 127.0.0.1:19222 Host-rewriting proxy."""
import asyncio
import os
import re

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("ARGO_CDP_LISTEN_PORT", "9222"))
TARGET_HOST = "127.0.0.1"
TARGET_PORT = int(os.environ.get("ARGO_CDP_TARGET_PORT", "19222"))
_HOST_HEADER_RE = re.compile(rb"(?im)^host:\\s*([^\\r\\n]+)\\r?\\n")
_CL_HEADER_RE = re.compile(rb"(?im)^content-length:\\s*(\\d+)\\r?\\n")
_TE_HEADER_RE = re.compile(rb"(?im)^transfer-encoding:\\s*[^\\r\\n]+\\r?\\n")


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def _decode_chunked(raw: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(raw):
        nl = raw.find(b"\\r\\n", pos)
        if nl == -1:
            break
        size_line = raw[pos:nl].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        pos = nl + 2
        if size == 0:
            break
        out.extend(raw[pos : pos + size])
        pos += size + 2
    return bytes(out)


async def _handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    upstream_writer = None
    try:
        raw_head = await asyncio.wait_for(client_reader.readuntil(b"\\r\\n\\r\\n"), timeout=15.0)
    except Exception:
        client_writer.close()
        return

    host_match = _HOST_HEADER_RE.search(raw_head)
    orig_host = host_match.group(1).strip().decode("latin1") if host_match else f"127.0.0.1:{LISTEN_PORT}"
    rewritten_req = _HOST_HEADER_RE.sub(
        f"Host: {TARGET_HOST}:{TARGET_PORT}\\r\\n".encode("latin1"),
        raw_head,
        count=1,
    )
    if not host_match:
        rewritten_req = rewritten_req[:-2] + f"Host: {TARGET_HOST}:{TARGET_PORT}\\r\\n\\r\\n".encode("latin1")

    req_cl = _CL_HEADER_RE.search(raw_head)
    req_body = b""
    if req_cl:
        cl_val = int(req_cl.group(1))
        if cl_val > 0:
            req_body = await asyncio.wait_for(client_reader.readexactly(cl_val), timeout=15.0)

    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(TARGET_HOST, TARGET_PORT),
            timeout=10.0,
        )
        upstream_writer.write(rewritten_req + req_body)
        await upstream_writer.drain()

        resp_head = await asyncio.wait_for(upstream_reader.readuntil(b"\\r\\n\\r\\n"), timeout=15.0)
        status_line = resp_head.split(b"\\r\\n", 1)[0]
        if b" 101 " in status_line:
            client_writer.write(resp_head)
            await client_writer.drain()
            await asyncio.gather(
                _pipe(client_reader, upstream_writer),
                _pipe(upstream_reader, client_writer),
            )
            return

        resp_cl = _CL_HEADER_RE.search(resp_head)
        is_chunked = b"transfer-encoding: chunked" in resp_head.lower()
        if resp_cl:
            body_len = int(resp_cl.group(1))
            body = await asyncio.wait_for(upstream_reader.readexactly(body_len), timeout=15.0) if body_len > 0 else b""
        else:
            raw_body = await asyncio.wait_for(upstream_reader.read(), timeout=15.0)
            body = _decode_chunked(raw_body) if is_chunked else raw_body

        target_bytes = f"{TARGET_HOST}:{TARGET_PORT}".encode("latin1")
        orig_bytes = orig_host.encode("latin1")
        if target_bytes in body and orig_bytes:
            body = body.replace(target_bytes, orig_bytes)

        clean_head = _TE_HEADER_RE.sub(b"", resp_head)
        if _CL_HEADER_RE.search(clean_head):
            clean_head = _CL_HEADER_RE.sub(
                f"Content-Length: {len(body)}\\r\\n".encode("latin1"),
                clean_head,
                count=1,
            )
        else:
            clean_head = clean_head[:-2] + f"Content-Length: {len(body)}\\r\\n\\r\\n".encode("latin1")

        client_writer.write(clean_head + body)
        await client_writer.drain()
    except Exception:
        try:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n")
            await client_writer.drain()
        except Exception:
            pass
    finally:
        if upstream_writer is not None:
            try:
                upstream_writer.close()
            except Exception:
                pass
        try:
            client_writer.close()
        except Exception:
            pass


async def _main() -> None:
    server = await asyncio.start_server(_handle_client, LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(_main())
'''

_LAUNCH_BROWSER_SCRIPT = '''#!/usr/bin/env bash
set -uo pipefail

export HOME=/config

set_status() {
  printf '%s|%s\n' "$1" "$2" > /config/.argo-provision-status.tmp && mv /config/.argo-provision-status.tmp /config/.argo-provision-status || true
}

is_port_open() {
  python3 -c "import socket; s=socket.socket(); s.settimeout(0.4); s.connect(('127.0.0.1', int('$1'))); s.close()" >/dev/null 2>&1
}

find_chrome() {
  for cand in chromium-browser chromium google-chrome; do
    if command -v "$cand" >/dev/null 2>&1; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}

detect_display() {
  for sock in /tmp/.X11-unix/X1 /tmp/.X11-unix/X0 /tmp/.X11-unix/X*; do
    if [ -S "$sock" ]; then
      echo ":${sock##*X}"
      return 0
    fi
  done
  return 1
}

set_status "starting" "Starting Desktop MCP agent (:9223) and CDP proxy (:9222)..."

# Restart MCP agent if missing or running an older agent version
NEED_AGENT_START=0
if ! is_port_open 9223; then
  NEED_AGENT_START=1
else
  CUR_VER=$(python3 -c "import json,urllib.request; print(json.loads(urllib.request.urlopen('http://127.0.0.1:9223/health',timeout=1.5).read()).get('agent_version',''))" 2>/dev/null || echo "")
  WANT_VER=$(cat /config/.argo-agent-version 2>/dev/null || echo "2")
  if [ "$CUR_VER" != "$WANT_VER" ]; then
    if [ -f /config/.argo-agent.pid ]; then
      kill "$(cat /config/.argo-agent.pid)" >/dev/null 2>&1 || true
      sleep 0.3
    fi
    NEED_AGENT_START=1
  fi
fi

if [ "$NEED_AGENT_START" = "1" ] && [ -f /config/.argo-desktop-agent.py ]; then
  nohup python3 /config/.argo-desktop-agent.py >> /config/.argo-desktop-agent.log 2>&1 &
  echo $! > /config/.argo-agent.pid
fi

if ! is_port_open 9222 && [ -f /config/.argo-cdp-proxy.py ]; then
  nohup python3 /config/.argo-cdp-proxy.py >> /config/.argo-cdp-proxy.log 2>&1 &
fi

DETECTED_DISPLAY="${DISPLAY:-}"
if [ -z "$DETECTED_DISPLAY" ] || ! detect_display >/dev/null 2>&1; then
  set_status "waiting_x11" "Waiting for XFCE X11 display server..."
  for _ in $(seq 1 25); do
    FOUND_DISP=$(detect_display || true)
    if [ -n "$FOUND_DISP" ]; then
      DETECTED_DISPLAY="$FOUND_DISP"
      break
    fi
    sleep 1
  done
fi

export DISPLAY="${DETECTED_DISPLAY:-:1}"
mkdir -p /config/.config/argo-chromium
rm -f /config/.cache/sessions/xfce4-session* >/dev/null 2>&1 || true

# Prevent Chromium "Restore pages?" bubble after unexpected container hibernation
if [ -f /config/.config/argo-chromium/Default/Preferences ]; then
  python3 -c 'import json; p="/config/.config/argo-chromium/Default/Preferences"; d=json.load(open(p,"r",encoding="utf-8")); pf=d.setdefault("profile",{}); pf["exit_type"]="Normal"; pf["exited_cleanly"]=True; json.dump(d,open(p,"w",encoding="utf-8"))' >/dev/null 2>&1 || true
fi

# Apply clean Chromium flags so manual or bot launches suppress --no-sandbox warnings & restore bubbles
CHROME_FLAGS="--no-sandbox --test-type --no-first-run --no-default-browser-check --hide-crash-restore-bubble --disable-session-crashed-bubble --disable-infobars --password-store=basic --user-data-dir=/config/.config/argo-chromium --remote-debugging-port=19222 --remote-debugging-address=127.0.0.1 --remote-allow-origins=*"
printf '%s\n' $CHROME_FLAGS > /config/.config/chromium-flags.conf 2>/dev/null || true
if [ -d /etc/chromium ] && command -v sudo >/dev/null 2>&1; then
  sudo -n sh -c "printf 'CHROMIUM_FLAGS=\"%s\"\n' '$CHROME_FLAGS' > /etc/chromium/chromium.conf" >/dev/null 2>&1 || true
fi

CHROME_BIN=$(find_chrome || true)
MISSING_PKGS=""
if [ -z "$CHROME_BIN" ]; then
  MISSING_PKGS="chromium"
fi
if ! command -v xdotool >/dev/null 2>&1; then
  MISSING_PKGS="${MISSING_PKGS:+$MISSING_PKGS }xdotool"
fi
if ! command -v wmctrl >/dev/null 2>&1; then
  MISSING_PKGS="${MISSING_PKGS:+$MISSING_PKGS }wmctrl"
fi
if ! command -v ping >/dev/null 2>&1; then
  MISSING_PKGS="${MISSING_PKGS:+$MISSING_PKGS }iputils"
fi
if ! command -v ssh >/dev/null 2>&1; then
  MISSING_PKGS="${MISSING_PKGS:+$MISSING_PKGS }openssh-clients"
fi
if ! command -v sshpass >/dev/null 2>&1; then
  MISSING_PKGS="${MISSING_PKGS:+$MISSING_PKGS }sshpass"
fi

if [ -n "$MISSING_PKGS" ] && command -v dnf >/dev/null 2>&1; then
  set_status "installing_packages" "First-time setup: installing $MISSING_PKGS on Virtual Desktop..."
  sudo -n dnf install -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs $MISSING_PKGS >> /config/.argo-browser.log 2>&1 || true
fi

# Do not auto-start Chromium on container boot; launch on-demand when a bot opens a browser or operator clicks Chromium.
set_status "ready" "Virtual Desktop & MCP agent ready"
exit 0
'''

_CHROMIUM_AUTOSTART_DESKTOP = '''[Desktop Entry]
Type=Application
Name=Argo Desktop Agent & Browser
Exec=/bin/bash /config/.argo-launch-browser.sh
Terminal=false
StartupNotify=false
'''


def _add_tar_bytes(
    tf: tarfile.TarFile,
    arcname: str,
    payload: bytes,
    *,
    mode: int = 0o644,
) -> None:
    info = tarfile.TarInfo(name=arcname)
    info.size = len(payload)
    info.mode = mode
    info.uid = 1000
    info.gid = 1000
    info.mtime = int(time.time())
    tf.addfile(info, io.BytesIO(payload))


def _add_tar_dir(tf: tarfile.TarFile, arcname: str) -> None:
    info = tarfile.TarInfo(name=arcname.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = 1000
    info.gid = 1000
    info.mtime = int(time.time())
    tf.addfile(info)


def _build_agent_tar_archive() -> bytes:
    """Build an in-memory TAR archive extracted directly into container /config via put_archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        _add_tar_bytes(tf, ".argo-desktop-agent.py", _DESKTOP_AGENT_SCRIPT.encode("utf-8"), mode=0o755)
        _add_tar_bytes(tf, ".argo-cdp-proxy.py", _CDP_PROXY_SCRIPT.encode("utf-8"), mode=0o644)
        _add_tar_bytes(tf, ".argo-launch-browser.sh", _LAUNCH_BROWSER_SCRIPT.encode("utf-8"), mode=0o755)
        _add_tar_bytes(tf, ".argo-agent-version", DESKTOP_AGENT_VERSION.encode("utf-8"), mode=0o644)
        _add_tar_dir(tf, ".config")
        _add_tar_dir(tf, ".config/autostart")
        _add_tar_bytes(
            tf,
            ".config/autostart/argo-chromium.desktop",
            _CHROMIUM_AUTOSTART_DESKTOP.encode("utf-8"),
            mode=0o644,
        )
    return buf.getvalue()


def _seed_desktop_browser_files(host_volume_path: str) -> None:
    """Seed persistent XFCE autostart, Desktop MCP agent (:9223), & CDP proxy (:9222) on host volume."""
    with contextlib.suppress(OSError):
        vol = Path(host_volume_path)
        vol.mkdir(parents=True, exist_ok=True)
        agent_file = vol / ".argo-desktop-agent.py"
        agent_file.write_text(_DESKTOP_AGENT_SCRIPT, encoding="utf-8")
        with contextlib.suppress(OSError):
            os.chmod(agent_file, 0o755)

        ver_file = vol / ".argo-agent-version"
        ver_file.write_text(DESKTOP_AGENT_VERSION, encoding="utf-8")

        proxy_file = vol / ".argo-cdp-proxy.py"
        proxy_file.write_text(_CDP_PROXY_SCRIPT, encoding="utf-8")

        launch_file = vol / ".argo-launch-browser.sh"
        launch_file.write_text(_LAUNCH_BROWSER_SCRIPT, encoding="utf-8")
        with contextlib.suppress(OSError):
            os.chmod(launch_file, 0o755)

        autostart_dir = vol / ".config" / "autostart"
        autostart_dir.mkdir(parents=True, exist_ok=True)
        desktop_file = autostart_dir / "argo-chromium.desktop"
        desktop_file.write_text(_CHROMIUM_AUTOSTART_DESKTOP, encoding="utf-8")

        with contextlib.suppress(OSError, AttributeError):
            for p in (
                vol,
                agent_file,
                ver_file,
                proxy_file,
                launch_file,
                vol / ".config",
                autostart_dir,
                desktop_file,
            ):
                os.chown(p, 1000, 1000)


def validate_desktop_slug(slug: str) -> str:
    """Validate that a bot slug maps safely to a single container and persistent directory."""
    cleaned = slug.strip()
    if not _DESKTOP_SLUG_RE.match(cleaned):
        raise DesktopConfigError(
            f"Invalid desktop bot slug '{slug}': expected lowercase alphanumeric and hyphens only."
        )
    return cleaned


def validate_desktop_image(image: str) -> str:
    """Enforce the lscr.io/linuxserver/webtop:fedora-xfce Selkies baseline."""
    cleaned = image.strip()
    lower = cleaned.lower()
    if any(token in lower for token in _FORBIDDEN_IMAGE_TOKENS):
        raise DesktopConfigError(f"Forbidden non-Fedora desktop base image '{image}'.")
    if not cleaned or "webtop:fedora-xfce" not in lower:
        raise DesktopConfigError(
            f"Desktop containers must use '{DESKTOP_IMAGE}' (got '{image}')."
        )
    return cleaned


@dataclass(frozen=True, slots=True)
class DesktopRuntimeSpec:
    """Isolated 1-bot-1-container runtime specification for webtop:fedora-xfce."""

    bot_slug: str
    container_name: str
    image: str
    network: str
    host_volume_path: str
    mem_limit: str
    nano_cpus: int
    shm_size: str
    environment: dict[str, str]


class DockerDriver(Protocol):
    """Driver abstraction over docker-py SDK or local deterministic fallback."""

    async def ensure_started(self, spec: DesktopRuntimeSpec) -> dict[str, Any]:
        """Create/start the isolated container with persistent /config mount."""
        ...

    async def ensure_stopped(self, container_name: str, *, timeout: int = 10) -> bool:
        """Stop the container cleanly while preserving its persistent profile volume."""
        ...

    async def remove_container(self, container_name: str, *, timeout: int = 5) -> bool:
        """Stop and remove the isolated container when permanently deleting a bot."""
        ...

    async def inspect_status(self, container_name: str) -> dict[str, Any]:
        """Return live container status and memory estimate."""
        ...


class InMemoryDockerDriver:
    """Deterministic in-memory driver used when /var/run/docker.sock is absent."""

    def __init__(self) -> None:
        self.containers: dict[str, dict[str, Any]] = {}
        self.start_calls: list[DesktopRuntimeSpec] = []
        self.stop_calls: list[str] = []

    async def ensure_started(self, spec: DesktopRuntimeSpec) -> dict[str, Any]:
        validate_desktop_image(spec.image)
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
            "shm_size": spec.shm_size,
            "status": "running",
            "ram_mb": 1380,
        }
        self.containers[spec.container_name] = state
        return dict(state)

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


class DockerSdkDriver:
    """Production Docker/Podman socket driver using lazy-imported docker >= 7.2.0."""

    def __init__(
        self,
        *,
        client: Any = None,
        base_url: str = "unix:///var/run/docker.sock",
    ) -> None:
        self._client = client
        self._base_url = base_url
        self._status_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._status_cache_ttl_seconds = 1.5

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
        """Resolve the active Docker Compose / bridge network shared with argo-core."""
        host_candidates = [
            val
            for val in (os.environ.get("HOSTNAME", "").strip(), socket.gethostname().strip())
            if val
        ]
        for host_id in host_candidates:
            with contextlib.suppress(Exception):
                self_ctr = client.containers.get(host_id)
                attrs = getattr(self_ctr, "attrs", None)
                if isinstance(attrs, dict):
                    nets = list((attrs.get("NetworkSettings", {}).get("Networks") or {}).keys())
                    if preferred_network in nets:
                        return preferred_network
                    for net_name in nets:
                        if net_name.endswith(f"_{preferred_network}") or "argo-net" in net_name:
                            return net_name
                    for net_name in nets:
                        if net_name not in {"host", "none"}:
                            return net_name

        if hasattr(client, "networks"):
            with contextlib.suppress(Exception):
                all_nets = [str(getattr(n, "name", "")) for n in client.networks.list() if getattr(n, "name", "")]
                if preferred_network in all_nets:
                    return preferred_network
                for net_name in all_nets:
                    if net_name.endswith(f"_{preferred_network}") or "argo-net" in net_name:
                        return net_name
                client.networks.create(preferred_network, driver="bridge")
                return preferred_network

        return preferred_network

    def _sync_ensure_agent_injected(
        self,
        container: Any,
        spec: DesktopRuntimeSpec,
        progress_cb: Callable[[str], None] | None = None,
    ) -> None:
        if progress_cb:
            progress_cb(
                f"Injecting Desktop MCP agent (:{DESKTOP_MCP_PORT}) & starting services in {spec.container_name}..."
            )
        if hasattr(container, "put_archive"):
            with contextlib.suppress(Exception):
                container.put_archive("/config", _build_agent_tar_archive())
        if hasattr(container, "exec_run"):
            with contextlib.suppress(Exception):
                container.exec_run(
                    [
                        "/bin/bash",
                        "-lc",
                        "nohup /config/.argo-launch-browser.sh >>/config/.argo-browser.log 2>&1 &",
                    ],
                    user="1000:1000",
                    detach=True,
                )

    def _sync_ensure_started(
        self,
        spec: DesktopRuntimeSpec,
        progress_cb: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        validate_desktop_image(spec.image)
        _seed_desktop_browser_files(spec.host_volume_path)
        try:
            client, not_found_exc = self._get_client()
            target_network = self._resolve_network(client, spec.network)

            container = None
            try:
                container = client.containers.get(spec.container_name)
            except Exception as exc:
                if not isinstance(exc, not_found_exc) and type(exc).__name__ != "NotFound":
                    raise

            expected_subfolder = f"SUBFOLDER=/api/desktops/{spec.bot_slug}/selkies/"
            if container is not None and isinstance(getattr(container, "attrs", None), dict):
                attrs = container.attrs
                env_list = list((attrs.get("Config") or {}).get("Env") or [])
                sec_opts = list((attrs.get("HostConfig") or {}).get("SecurityOpt") or [])
                has_subfolder = expected_subfolder in env_list
                has_seccomp = any("seccomp=unconfined" in str(opt) for opt in sec_opts)
                if not (has_subfolder and has_seccomp):
                    with contextlib.suppress(Exception):
                        container.stop(timeout=5)
                    container.remove(force=True)
                    container = None

            if container is None:
                if hasattr(client, "images"):
                    try:
                        client.images.get(spec.image)
                    except Exception as exc:
                        if isinstance(exc, not_found_exc) or type(exc).__name__ in {"NotFound", "ImageNotFound"}:
                            if progress_cb:
                                progress_cb(
                                    f"Pulling Fedora XFCE desktop image ({spec.image}) — first launch may take a minute..."
                                )
                            client.images.pull(spec.image)
                        else:
                            raise
                if progress_cb:
                    progress_cb(f"Creating isolated Fedora XFCE container ({spec.container_name})...")
                # Ports stay unbound on host: traffic routes strictly over internal argo-net.
                container = client.containers.run(
                    spec.image,
                    name=spec.container_name,
                    detach=True,
                    mem_limit=spec.mem_limit,
                    nano_cpus=spec.nano_cpus,
                    shm_size=spec.shm_size,
                    network=target_network,
                    security_opt=["seccomp=unconfined"],
                    volumes={spec.host_volume_path: {"bind": "/config", "mode": "rw"}},
                    environment=spec.environment,
                    labels={
                        "argo.managed": "true",
                        "argo.bot_slug": spec.bot_slug,
                        "argo.isolation": "1-bot-1-container",
                    },
                    restart_policy={"Name": "no"},
                )
            else:
                if getattr(container, "status", "") != "running":
                    if progress_cb:
                        progress_cb(f"Waking Fedora XFCE desktop container ({spec.container_name})...")
                    container.start()
                if hasattr(container, "reload"):
                    container.reload()
                attrs = getattr(container, "attrs", None)
                if isinstance(attrs, dict) and hasattr(client, "networks"):
                    attached = set((attrs.get("NetworkSettings", {}).get("Networks") or {}).keys())
                    if target_network not in attached:
                        with contextlib.suppress(Exception):
                            client.networks.get(target_network).connect(container)

            self._sync_ensure_agent_injected(container, spec, progress_cb=progress_cb)
            self._status_cache.pop(spec.container_name, None)

            return {
                "container_id": str(getattr(container, "id", spec.container_name)),
                "container_name": spec.container_name,
                "status": "running",
                "ram_mb": 1380,
            }
        except DesktopConfigError:
            raise
        except Exception as exc:
            self._status_cache.pop(spec.container_name, None)
            raise DesktopRuntimeError(
                f"Docker desktop driver error for '{spec.container_name}': {exc}"
            ) from exc

    def _sync_ensure_stopped(self, container_name: str, timeout: int) -> bool:
        self._status_cache.pop(container_name, None)
        try:
            client, not_found_exc = self._get_client()
            try:
                container = client.containers.get(container_name)
            except Exception as exc:
                if isinstance(exc, not_found_exc) or type(exc).__name__ == "NotFound":
                    return False
                raise
            container.stop(timeout=timeout)
            self._status_cache.pop(container_name, None)
            return True
        except Exception as exc:
            raise DesktopRuntimeError(
                f"Docker desktop stop failed for '{container_name}': {exc}"
            ) from exc

    def _sync_remove_container(self, container_name: str, timeout: int) -> bool:
        self._status_cache.pop(container_name, None)
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
            self._status_cache.pop(container_name, None)
            return True
        except Exception as exc:
            if type(exc).__name__ == "NotFound":
                return False
            raise DesktopRuntimeError(
                f"Docker desktop remove failed for '{container_name}': {exc}"
            ) from exc

    def _sync_inspect_status(self, container_name: str) -> dict[str, Any]:
        cached = self._status_cache.get(container_name)
        now = time.monotonic()
        if cached is not None and (now - cached[0]) < self._status_cache_ttl_seconds:
            return dict(cached[1])
        try:
            client, not_found_exc = self._get_client()
            try:
                container = client.containers.get(container_name)
            except Exception as exc:
                if isinstance(exc, not_found_exc) or type(exc).__name__ == "NotFound":
                    result = {"running": False, "ram_mb": 0, "container_id": None}
                    self._status_cache[container_name] = (time.monotonic(), result)
                    return dict(result)
                raise
            if hasattr(container, "reload"):
                with contextlib.suppress(Exception):
                    container.reload()
            running = getattr(container, "status", "") == "running"
            result = {
                "running": running,
                "ram_mb": 1380 if running else 0,
                "container_id": str(getattr(container, "id", container_name)),
            }
            self._status_cache[container_name] = (time.monotonic(), result)
            return dict(result)
        except Exception as exc:
            raise DesktopRuntimeError(
                f"Docker desktop inspect failed for '{container_name}': {exc}"
            ) from exc

    async def ensure_started(
        self,
        spec: DesktopRuntimeSpec,
        *,
        progress_cb: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(self._sync_ensure_started, spec, progress_cb)

    async def ensure_stopped(self, container_name: str, *, timeout: int = 10) -> bool:
        return await asyncio.to_thread(self._sync_ensure_stopped, container_name, timeout)

    async def remove_container(self, container_name: str, *, timeout: int = 5) -> bool:
        return await asyncio.to_thread(self._sync_remove_container, container_name, timeout)

    async def inspect_status(self, container_name: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._sync_inspect_status, container_name)


SelkiesProxyTransport = Callable[[str, str, str], Awaitable[tuple[int, str, bytes]]]


def _auto_select_driver() -> DockerDriver:
    sock_path = Path(os.environ.get("ARGO_DOCKER_SOCKET", "/var/run/docker.sock"))
    if sock_path.exists():
        try:
            import docker  # noqa: F401  # type: ignore[import-not-found]

            return DockerSdkDriver(base_url=f"unix://{sock_path}")
        except ImportError:
            pass
    return InMemoryDockerDriver()


class DesktopManager:
    """Manages per-bot webtop:fedora-xfce Selkies desktops, RAM gates, and auto-sleep."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        bus: EventBus,
        guard: HostResourceGuard,
        telegram_service: TelegramBotService | None = None,
        volumes_root: str = "/srv/argo/desktops",
        network: str | None = None,
        idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
        driver: DockerDriver | None = None,
        selkies_proxy_transport: SelkiesProxyTransport | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._guard = guard
        self._telegram = telegram_service
        self._volumes_root = Path(volumes_root)
        self._network = (
            network or os.environ.get("ARGO_DOCKER_NETWORK") or DESKTOP_NETWORK
        ).strip() or DESKTOP_NETWORK
        self._idle_timeout_seconds = max(5.0, float(idle_timeout_seconds))
        self._driver: DockerDriver = driver or _auto_select_driver()
        self._selkies_proxy_transport = selkies_proxy_transport
        self._clock = clock or time.monotonic

        self._last_activity_at: dict[str, float] = {}
        self._takeover_active: set[str] = set()
        self._awaiting_takeover: dict[str, dict[str, str]] = {}
        self._queued_launches: list[dict[str, Any]] = []
        self._latest_screenshots: dict[str, tuple[bytes, dict[str, Any], str]] = {}

    @property
    def driver(self) -> DockerDriver:
        """Expose active DockerDriver instance."""
        return self._driver

    def is_in_memory(self) -> bool:
        """Return True when running without a live Docker daemon (tests / simulated mode)."""
        return isinstance(self._driver, InMemoryDockerDriver)

    def container_name_for(self, slug: str) -> str:
        """Canonical isolated desktop container name."""
        return f"argo-desktop-{validate_desktop_slug(slug)}"

    def record_screenshot(
        self, slug: str, png_bytes: bytes, meta: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Cache latest captured PNG desktop frame in memory."""
        clean_slug = validate_desktop_slug(slug)
        captured_at = utc_now()
        enriched_meta = {
            **dict(meta or {}),
            "captured_at": captured_at,
            "byte_length": len(png_bytes),
        }
        self._latest_screenshots[clean_slug] = (png_bytes, enriched_meta, captured_at)
        return enriched_meta

    def get_cached_screenshot(self, slug: str) -> tuple[bytes, dict[str, Any]] | None:
        """Return latest cached desktop PNG screenshot if captured in this session."""
        clean_slug = validate_desktop_slug(slug)
        item = self._latest_screenshots.get(clean_slug)
        if item is None:
            return None
        return item[0], dict(item[1])

    async def _emit_boot_progress(
        self,
        slug: str,
        *,
        state: str,
        step: str,
        correlation_id: str | None = None,
    ) -> None:
        with contextlib.suppress(Exception):
            await self._bus.emit_progress(
                slug,
                state,
                step=step,
                correlation_id=correlation_id or "",
            )

    def build_runtime_spec(self, bot: dict[str, Any]) -> DesktopRuntimeSpec:
        """Build an isolated 1-bot-1-container Selkies desktop spec."""
        clean_slug = validate_desktop_slug(str(bot["slug"]))
        container_name = f"argo-desktop-{clean_slug}"
        volume_path = str((self._volumes_root / clean_slug))
        return DesktopRuntimeSpec(
            bot_slug=clean_slug,
            container_name=container_name,
            image=DESKTOP_IMAGE,
            network=self._network,
            host_volume_path=volume_path,
            mem_limit=DESKTOP_MEM_LIMIT,
            nano_cpus=DESKTOP_NANO_CPUS,
            shm_size=DESKTOP_SHM_SIZE,
            environment={
                "PUID": "1000",
                "PGID": "1000",
                "TZ": "UTC",
                "TITLE": f"Argo Desktop ({bot.get('name') or clean_slug})",
                "CUSTOM_PORT": str(SELKIES_HTTP_PORT),
                "CUSTOM_HTTPS_PORT": str(SELKIES_HTTPS_PORT),
                "SUBFOLDER": f"/api/desktops/{clean_slug}/selkies/",
                "CHROME_CLI": (
                    f"--remote-debugging-port={CDP_PORT} "
                    "--remote-debugging-address=0.0.0.0 --no-first-run"
                ),
            },
        )

    def touch_activity(self, slug: str) -> None:
        """Reset idle hibernation timer after browser tool use or Selkies interaction."""
        clean_slug = validate_desktop_slug(slug)
        self._last_activity_at[clean_slug] = self._clock()

    def _enqueue_launch(self, slug: str, *, reason: str, ram_percent: float) -> None:
        for existing in self._queued_launches:
            if existing["bot_slug"] == slug:
                existing["ram_percent"] = ram_percent
                existing["reason"] = reason
                return
        self._queued_launches.append(
            {
                "bot_slug": slug,
                "reason": reason,
                "ram_percent": ram_percent,
                "queued_at": utc_now(),
            }
        )

    def _clear_queued_launch(self, slug: str) -> None:
        self._queued_launches = [item for item in self._queued_launches if item["bot_slug"] != slug]

    def mark_awaiting_takeover(self, slug: str, *, url: str, reason: str) -> None:
        """Record that a desktop bot halted cleanly on a portal gate for human Selkies takeover."""
        clean_slug = validate_desktop_slug(slug)
        self._awaiting_takeover[clean_slug] = {
            "url": url,
            "reason": reason,
            "marked_at": utc_now(),
        }

    async def start_desktop(
        self,
        slug: str,
        *,
        reason: str = "manual",
        queue_if_blocked: bool = True,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Start or wake argo-desktop-<slug> if RAM < 80%, enforcing 1-bot-1-container."""
        clean_slug = validate_desktop_slug(slug)
        bot = self._repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' is API-only.")

        spec = self.build_runtime_spec(bot)
        acquired = await self._bus.acquire_lock(
            "desktop", clean_slug, "desktop-manager", ttl_seconds=300
        )
        if not acquired:
            raise DesktopStateError(
                f"Desktop container '{spec.container_name}' is busy with another transition."
            )

        progress_state = "desktop_boot" if reason in ("manual", "operator_takeover") else "working"

        try:
            driver_status = await self._driver.inspect_status(spec.container_name)
            if bot["desktop_state"] == "running" and driver_status.get("running"):
                if isinstance(self._driver, DockerSdkDriver):
                    await self._driver.ensure_started(spec)
                self.touch_activity(clean_slug)
                return self._repo.get_bot(clean_slug)

            await self._emit_boot_progress(
                clean_slug,
                state=progress_state,
                step=f"Checking host memory gate before booting {spec.container_name}...",
                correlation_id=correlation_id,
            )

            allowed, telemetry = self._guard.can_start_desktop()
            if not allowed:
                if queue_if_blocked:
                    self._enqueue_launch(clean_slug, reason=reason, ram_percent=telemetry.ram_percent)
                await self._bus.publish(
                    correlation_id=make_id("corr"),
                    source_slug="host-guard",
                    target_slug=clean_slug,
                    event_type="desktop.gate_blocked",
                    payload={
                        "category": "alerts",
                        "title": "RAM Startup Gate Blocked Desktop Launch",
                        "badge": f"Blocked · RAM {telemetry.ram_percent}%",
                        "badge_tone": "amber",
                        "summary": (
                            f"Launch of {spec.container_name} rejected because host memory "
                            f"({telemetry.ram_percent}%) exceeded the 80% RAM Startup Gate."
                        ),
                        "meta": "Host Resource Guard (>80% RAM Gate)",
                    },
                    hop_count=1,
                )
                if self._telegram is not None:
                    await self._telegram.send_resource_alert(
                        telemetry=telemetry,
                        alert_kind="ram_warning",
                    )
                raise DesktopStartupBlockedError(
                    f"Blocked by >80% RAM Startup Gate (current RAM: {telemetry.ram_percent}%)",
                    ram_percent=telemetry.ram_percent,
                )

            loop = asyncio.get_running_loop()

            def _sync_progress_forward(msg: str) -> None:
                with contextlib.suppress(Exception):
                    asyncio.run_coroutine_threadsafe(
                        self._emit_boot_progress(
                            clean_slug,
                            state=progress_state,
                            step=msg,
                            correlation_id=correlation_id,
                        ),
                        loop,
                    )

            await self._emit_boot_progress(
                clean_slug,
                state=progress_state,
                step=f"Starting Virtual Desktop ({spec.container_name})...",
                correlation_id=correlation_id,
            )

            try:
                if isinstance(self._driver, DockerSdkDriver):
                    await self._driver.ensure_started(spec, progress_cb=_sync_progress_forward)
                else:
                    await self._driver.ensure_started(spec)
            except DesktopRuntimeError as exc:
                await self._emit_boot_progress(
                    clean_slug,
                    state="desktop_error" if progress_state == "desktop_boot" else "error",
                    step=f"Virtual Desktop failed to start: {str(exc)[:180]}",
                    correlation_id=correlation_id,
                )
                await self._bus.publish(
                    correlation_id=make_id("corr"),
                    source_slug="host-guard",
                    target_slug=clean_slug,
                    event_type="desktop.error",
                    payload={
                        "category": "alerts",
                        "title": f"Desktop Launch Failed · {spec.container_name}",
                        "badge": "Docker Error",
                        "badge_tone": "red",
                        "summary": str(exc)[:300],
                        "meta": f"Network: {spec.network} · Image: {spec.image}",
                    },
                    hop_count=1,
                )
                raise

            self._clear_queued_launch(clean_slug)
            self._last_activity_at[clean_slug] = self._clock()
            updated = self._repo.update_bot(clean_slug, {"desktop_state": "running"})

            await self._emit_boot_progress(
                clean_slug,
                state="desktop_ready" if progress_state == "desktop_boot" else "working",
                step=(
                    "Virtual Desktop container started; warming up Selkies, Chromium & MCP agent..."
                    if progress_state == "desktop_boot"
                    else f"Virtual Desktop started; warming up Selkies & MCP agent (:{DESKTOP_MCP_PORT})..."
                ),
                correlation_id=correlation_id,
            )

            await self._bus.publish(
                correlation_id=make_id("corr"),
                source_slug="host-guard",
                target_slug=clean_slug,
                event_type="desktop.started",
                payload={
                    "category": "alerts",
                    "title": f"Started {spec.container_name}",
                    "badge": f"Selkies :{SELKIES_HTTP_PORT} · CDP :{CDP_PORT} · MCP :{DESKTOP_MCP_PORT}",
                    "badge_tone": "emerald",
                    "summary": (
                        f"Isolated Fedora XFCE container active with persistent profile at "
                        f"{spec.host_volume_path}."
                    ),
                    "meta": f"Host RAM: {telemetry.ram_percent}% (below 80% gate)",
                },
                hop_count=1,
            )
            return updated
        finally:
            await self._bus.release_lock("desktop", clean_slug, "desktop-manager")

    async def hibernate_desktop(self, slug: str, *, reason: str = "manual") -> dict[str, Any]:
        """Stop argo-desktop-<slug> gracefully while preserving its persistent /config volume."""
        clean_slug = validate_desktop_slug(slug)
        bot = self._repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' is API-only.")

        container_name = f"argo-desktop-{clean_slug}"
        acquired = await self._bus.acquire_lock(
            "desktop", clean_slug, "desktop-manager", ttl_seconds=60
        )
        if not acquired:
            raise DesktopStateError(f"Desktop container '{container_name}' is busy.")

        try:
            await self._driver.ensure_stopped(container_name)
            self._takeover_active.discard(clean_slug)
            self._last_activity_at.pop(clean_slug, None)
            updated = self._repo.update_bot(clean_slug, {"desktop_state": "hibernated"})

            event_type = (
                "desktop.auto_hibernated" if reason == "idle_timeout" else "desktop.hibernated"
            )
            badge = "Auto-Sleep · 0 MB" if reason == "idle_timeout" else "Hibernated · 0 MB"
            summary = (
                f"Auto-hibernated after {int(self._idle_timeout_seconds)}s idle timeout; "
                "persistent session volume preserved."
                if reason == "idle_timeout"
                else "Session state preserved in persistent desktop volume."
            )
            await self._bus.publish(
                correlation_id=make_id("corr"),
                source_slug="host-guard",
                target_slug=clean_slug,
                event_type=event_type,
                payload={
                    "category": "alerts",
                    "title": f"Hibernated {container_name}",
                    "badge": badge,
                    "badge_tone": "slate",
                    "summary": summary,
                    "meta": f"Reason: {reason}",
                },
                hop_count=1,
            )
            return updated
        finally:
            await self._bus.release_lock("desktop", clean_slug, "desktop-manager")

    async def toggle_desktop(self, slug: str) -> dict[str, Any]:
        """Toggle a desktop bot between running and hibernated states."""
        clean_slug = validate_desktop_slug(slug)
        bot = self._repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' is API-only.")
        driver_status = await self._driver.inspect_status(f"argo-desktop-{clean_slug}")
        actually_running = bot["desktop_state"] == "running" and (
            not isinstance(self._driver, DockerSdkDriver) or bool(driver_status.get("running"))
        )
        if actually_running:
            return await self.hibernate_desktop(clean_slug, reason="manual")
        return await self.start_desktop(clean_slug, reason="manual")

    async def destroy_desktop(self, slug: str, *, remove_volume: bool = True) -> None:
        """Stop and remove a bot's desktop container, cached state, and optional persistent volume."""
        try:
            clean_slug = validate_desktop_slug(slug)
        except DesktopConfigError:
            return
        self._clear_queued_launch(clean_slug)
        self._takeover_active.discard(clean_slug)
        self._awaiting_takeover.pop(clean_slug, None)
        self._last_activity_at.pop(clean_slug, None)
        self._latest_screenshots.pop(clean_slug, None)
        container_name = f"argo-desktop-{clean_slug}"
        with contextlib.suppress(Exception):
            await self._driver.remove_container(container_name, timeout=5)
        with contextlib.suppress(Exception):
            await self._bus.release_lock("desktop", clean_slug, "desktop-manager")
        if remove_volume:
            with contextlib.suppress(Exception):
                root = self._volumes_root.resolve()
                vol = (self._volumes_root / clean_slug).resolve()
                if vol != root and vol.is_relative_to(root) and vol.exists():
                    await asyncio.to_thread(shutil.rmtree, vol, True)

    async def stop_all_desktops(
        self,
        *,
        reason: str = "manual",
        idle_only: bool = False,
    ) -> list[str]:
        """Stop all running desktop containers (or only non-takeover desktops when idle_only)."""
        stopped: list[str] = []
        for bot in self._repo.list_bots():
            if bot["runtime"] != "desktop" or bot["desktop_state"] != "running":
                continue
            slug = bot["slug"]
            if idle_only and slug in self._takeover_active:
                continue
            await self.hibernate_desktop(slug, reason=reason)
            stopped.append(slug)
        return stopped

    async def sweep_idle_desktops(self) -> list[str]:
        """Auto-hibernate any desktop exceeding idle_timeout_seconds outside active takeover."""
        now = self._clock()
        hibernated: list[str] = []
        for bot in self._repo.list_bots():
            if bot["runtime"] != "desktop" or bot["desktop_state"] != "running":
                continue
            slug = bot["slug"]
            if slug in self._takeover_active:
                continue
            last_seen = self._last_activity_at.get(slug)
            if last_seen is None:
                self._last_activity_at[slug] = now
                continue
            if (now - last_seen) >= self._idle_timeout_seconds:
                await self.hibernate_desktop(slug, reason="idle_timeout")
                hibernated.append(slug)
        return hibernated

    async def run_periodic_idle_sweep(self, interval_seconds: float = 30.0) -> None:
        """Background idle auto-sleep loop cleanly cancelled on app shutdown."""
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                await self.sweep_idle_desktops()
            except Exception as exc:
                logger.warning("Desktop idle sweep error: %s", exc)

    def _desktop_item_payload(self, item: dict[str, Any]) -> dict[str, Any]:
        slug = item["bot_slug"]
        last_seen = self._last_activity_at.get(slug)
        idle_seconds = (
            max(0, int(self._clock() - last_seen))
            if item["desktop_state"] == "running" and last_seen is not None
            else 0
        )
        awaiting_info = self._awaiting_takeover.get(slug)
        shot_entry = self._latest_screenshots.get(slug)
        return {
            **item,
            "image": DESKTOP_IMAGE,
            "volume_path": str(self._volumes_root / slug),
            "selkies_url": f"/api/desktops/{slug}/selkies/",
            "mcp_port": DESKTOP_MCP_PORT,
            "mcp_url": f"http://argo-desktop-{slug}:{DESKTOP_MCP_PORT}/mcp",
            "screenshot_url": f"/api/desktops/{slug}/screenshot",
            "has_screenshot": shot_entry is not None,
            "last_screenshot_at": shot_entry[2] if shot_entry is not None else None,
            "idle_seconds": idle_seconds,
            "idle_timeout_seconds": int(self._idle_timeout_seconds),
            "takeover_active": slug in self._takeover_active,
            "awaiting_takeover": awaiting_info is not None,
            "takeover_reason": awaiting_info["reason"] if awaiting_info else None,
        }

    def list_desktops_status(self) -> dict[str, Any]:
        """Return host telemetry, enriched desktop status cards, and RAM-gated queue."""
        desktops = self._repo.list_desktops()
        if isinstance(self._driver, DockerSdkDriver):
            synced = False
            for d in desktops:
                if d.get("desktop_state") == "running":
                    slug = str(d["bot_slug"])
                    with contextlib.suppress(Exception):
                        st = self._driver._sync_inspect_status(f"argo-desktop-{slug}")
                        if not st.get("running"):
                            self._repo.update_bot(slug, {"desktop_state": "hibernated"})
                            synced = True
            if synced:
                desktops = self._repo.list_desktops()
        base_desktops = [self._desktop_item_payload(d) for d in desktops]
        return {
            "host": self._guard.sample().to_dict(),
            "desktops": base_desktops,
            "queued_launches": list(self._queued_launches),
        }

    async def start_takeover(self, slug: str, *, actor: str) -> dict[str, Any]:
        """Wake desktop if needed and enter protected operator Selkies takeover mode."""
        clean_slug = validate_desktop_slug(slug)
        bot = await self.start_desktop(clean_slug, reason="operator_takeover")
        self._takeover_active.add(clean_slug)
        self.touch_activity(clean_slug)
        await self._bus.publish(
            correlation_id=make_id("corr"),
            source_slug=actor,
            target_slug=clean_slug,
            event_type="desktop.takeover_started",
            payload={
                "category": "alerts",
                "title": f"Selkies Takeover Started · {bot['name']}",
                "badge": f"Selkies :{SELKIES_HTTP_PORT} Active",
                "badge_tone": "indigo",
                "summary": f"Operator {actor} attached to argo-desktop-{clean_slug} behind SSO.",
                "meta": f"Volume: {self._volumes_root / clean_slug}",
            },
            hop_count=1,
        )
        enriched = next(
            d for d in self.list_desktops_status()["desktops"] if d["bot_slug"] == clean_slug
        )
        return {"status": "takeover_active", "desktop": enriched}

    async def release_takeover(self, slug: str, *, actor: str) -> dict[str, Any]:
        """Release manual Selkies takeover lock and clear pending gate warnings."""
        clean_slug = validate_desktop_slug(slug)
        bot = self._repo.get_bot(clean_slug)
        self._takeover_active.discard(clean_slug)
        self._awaiting_takeover.pop(clean_slug, None)
        if bot["desktop_state"] == "running":
            self.touch_activity(clean_slug)
        await self._bus.publish(
            correlation_id=make_id("corr"),
            source_slug=actor,
            target_slug=clean_slug,
            event_type="desktop.takeover_released",
            payload={
                "category": "alerts",
                "title": f"Selkies Takeover Released · {bot['name']}",
                "badge": "Authenticated Session Saved",
                "badge_tone": "emerald",
                "summary": (
                    f"Operator {actor} released manual control; session cookies remain stored in "
                    f"{self._volumes_root / clean_slug}."
                ),
                "meta": f"Idle auto-sleep: {int(self._idle_timeout_seconds)}s",
            },
            hop_count=1,
        )
        enriched = next(
            d for d in self.list_desktops_status()["desktops"] if d["bot_slug"] == clean_slug
        )
        return {"status": "released", "desktop": enriched}

    async def proxy_selkies_request(
        self,
        slug: str,
        *,
        subpath: str = "",
        query_string: str = "",
        method: str = "GET",
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, bytes, dict[str, str]]:
        """Proxy authenticated Selkies HTTP/asset/API routes over internal argo-net :3000."""
        clean_slug = validate_desktop_slug(slug)
        lower_subpath = subpath.lower()
        if any(token in lower_subpath for token in _LEGACY_VNC_PATH_TOKENS):
            raise DesktopConfigError(
                "Legacy VNC paths are forbidden; use Selkies WebRTC/WebSocket streams on :3000."
            )

        bot = self._repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' does not use a desktop container.")

        if self._selkies_proxy_transport is not None:
            if bot["desktop_state"] != "running":
                raise DesktopStateError(
                    f"Desktop container argo-desktop-{clean_slug} is hibernated. Wake it before connecting."
                )
            self.touch_activity(clean_slug)
            status_code, media_type, content = await self._selkies_proxy_transport(
                clean_slug, subpath, query_string
            )
            return status_code, media_type, content, {}

        if isinstance(self._driver, DockerSdkDriver):
            driver_status = await self._driver.inspect_status(f"argo-desktop-{clean_slug}")
            if bot["desktop_state"] != "running" or not driver_status.get("running"):
                await self.start_desktop(clean_slug, reason="selkies_stream")

            self.touch_activity(clean_slug)
            import aiohttp  # type: ignore[import-not-found]

            clean_sub = subpath.lstrip("/")
            subfolder_prefix = f"/api/desktops/{clean_slug}/selkies"
            if clean_sub.startswith(subfolder_prefix.lstrip("/") + "/"):
                clean_sub = clean_sub[len(subfolder_prefix.lstrip("/") + "/") :]

            base_host = f"http://argo-desktop-{clean_slug}:{SELKIES_HTTP_PORT}"
            primary_url = f"{base_host}{subfolder_prefix}/{clean_sub}"
            fallback_url = f"{base_host}/{clean_sub}"
            if query_string:
                primary_url = f"{primary_url}?{query_string}"
                fallback_url = f"{fallback_url}?{query_string}"

            forward_headers: dict[str, str] = {}
            for k, v in (headers or {}).items():
                kl = k.lower()
                if kl in {"accept", "accept-language", "content-type", "range", "origin", "referer"}:
                    forward_headers[k] = v

            last_exc: Exception | None = None
            async with aiohttp.ClientSession() as session:
                for attempt in range(12):
                    try:
                        async with session.request(
                            method.upper(),
                            primary_url,
                            data=body if body else None,
                            headers=forward_headers,
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=15),
                        ) as resp:
                            if resp.status == 404 and clean_sub == "":
                                async with session.request(
                                    method.upper(),
                                    fallback_url,
                                    data=body if body else None,
                                    headers=forward_headers,
                                    allow_redirects=False,
                                    timeout=aiohttp.ClientTimeout(total=15),
                                ) as fb_resp:
                                    fb_body = await fb_resp.read()
                                    fb_ct = fb_resp.headers.get(
                                        "Content-Type", "application/octet-stream"
                                    )
                                    fb_headers = {
                                        hk: fb_resp.headers[hk]
                                        for hk in ("Cache-Control", "ETag", "Accept-Ranges", "Content-Range", "Vary")
                                        if hk in fb_resp.headers
                                    }
                                    return fb_resp.status, fb_ct, fb_body, fb_headers
                            resp_body = await resp.read()
                            content_type = resp.headers.get(
                                "Content-Type", "application/octet-stream"
                            )
                            safe_headers = {
                                hk: resp.headers[hk]
                                for hk in ("Cache-Control", "ETag", "Accept-Ranges", "Content-Range", "Vary", "Location")
                                if hk in resp.headers
                            }
                            return resp.status, content_type, resp_body, safe_headers
                    except (aiohttp.ClientConnectorError, aiohttp.ServerDisconnectedError, TimeoutError, OSError) as exc:
                        last_exc = exc
                        if attempt < 11:
                            await asyncio.sleep(0.5)

            if clean_sub == "":
                safe_title = html.escape(bot["name"])
                safe_slug = html.escape(clean_slug)
                warming_html = (
                    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta http-equiv='refresh' content='2'>"
                    f"<title>Starting {safe_title}…</title>"
                    "<style>body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;"
                    "font-family:system-ui,-apple-system,sans-serif;background:#020617;color:#e2e8f0;}"
                    ".card{max-width:440px;border:1px solid #1e293b;border-radius:12px;background:#0f172a;padding:24px;text-align:center;}"
                    ".dot{display:inline-block;width:10px;height:10px;border-radius:999px;background:#38bdf8;margin-right:8px;}"
                    "p{font-size:12px;color:#94a3b8;line-height:1.5;margin:8px 0 0;}</style>"
                    "</head><body><div class='card'>"
                    f"<div style='font-size:14px;font-weight:600;color:#f8fafc;'><span class='dot'></span>Starting Fedora XFCE Virtual Desktop…</div>"
                    f"<p>Container <code>argo-desktop-{safe_slug}</code> is warming up Selkies on port :{SELKIES_HTTP_PORT}. This view refreshes automatically.</p>"
                    "</div></body></html>"
                )
                return 200, "text/html; charset=utf-8", warming_html.encode("utf-8"), {"Cache-Control": "no-store"}

            raise DesktopRuntimeError(
                f"Selkies upstream unreachable for argo-desktop-{clean_slug}: {last_exc}"
            )

        if bot["desktop_state"] != "running":
            raise DesktopStateError(
                f"Desktop container argo-desktop-{clean_slug} is hibernated. Wake it before connecting."
            )

        self.touch_activity(clean_slug)
        takeover_note = self._awaiting_takeover.get(clean_slug, {}).get("reason", "")
        safe_title = html.escape(bot["name"])
        safe_slug = html.escape(clean_slug)
        safe_volume = html.escape(str(self._volumes_root / clean_slug))
        safe_note = html.escape(takeover_note) if takeover_note else "Ready for authenticated portal workflow."
        rendered = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>Selkies Desktop · argo-desktop-{safe_slug}</title>"
            "<style>body{margin:0;padding:20px;font-family:\"Inter\",-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;"
            "background:#161920;color:#e5e7eb;font-size:13px;line-height:1.5;}"
            ".card{border:1px solid #2d3440;border-radius:10px;background:#1e232c;padding:16px;}"
            ".badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:12px;"
            "background:#252b36;color:#d1d5db;border:1px solid #353f50;margin-bottom:10px;}"
            "p{font-size:13px;color:#9ca3af;line-height:1.5;margin:6px 0;}"
            "code{color:#f3f4f6;background:#141820;border:1px solid #2d3440;padding:2px 6px;border-radius:4px;font-size:12px;}</style>"
            "</head><body><div class='card'>"
            f"<span class='badge'>Selkies HTML5 :3000 · CDP :{CDP_PORT}</span>"
            f"<h3 style='margin:0 0 6px;font-size:15px;color:#f3f4f6;'>{safe_title} (argo-desktop-{safe_slug})</h3>"
            f"<p>{safe_note}</p>"
            f"<p>Persistent Session Volume: <code>{safe_volume}</code></p>"
            "<p>Proxied behind oauth2-proxy on internal network <code>argo-net</code>.</p>"
            "</div></body></html>"
        )
        return 200, "text/html; charset=utf-8", rendered.encode("utf-8"), {}

    async def proxy_selkies_http(
        self,
        slug: str,
        *,
        subpath: str = "",
        query_string: str = "",
    ) -> tuple[int, str, bytes]:
        """Proxy authenticated Selkies HTML5 stream routes over internal argo-net :3000."""
        status_code, media_type, content, _ = await self.proxy_selkies_request(
            slug,
            subpath=subpath,
            query_string=query_string,
        )
        return status_code, media_type, content
