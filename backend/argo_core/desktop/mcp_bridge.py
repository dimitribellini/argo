from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import re
import struct
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlparse

from argo_core.security.ssrf import SSRFBlockedError, validate_public_url

if TYPE_CHECKING:
    from argo_core.bus.valkey_bus import EventBus
    from argo_core.desktop.manager import DesktopManager

logger = logging.getLogger(__name__)

DESKTOP_MCP_PORT = 9223
DESKTOP_MCP_PATH = "/mcp"
DESKTOP_AGENT_VERSION = "6"

_MCP_TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "desktop_inspect",
        "description": "Inspect the running Fedora XFCE virtual desktop: active display, screen resolution, running GUI apps, open windows, provisioning status, and Chromium CDP readiness.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "desktop_screenshot",
        "description": "Capture a PNG screenshot of the current XFCE virtual desktop screen so you can visually inspect open windows, dialogs, terminals, or web pages.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "max_width": {
                    "type": "integer",
                    "default": 1280,
                    "description": "Optional maximum image width for compact vision inspection (0 for native).",
                }
            },
        },
    },
    {
        "name": "desktop_check_app",
        "description": "Check whether a desktop application or CLI binary (e.g. chromium, firefox, xfce4-terminal, thunar, libreoffice, python3) is installed, running, or has open windows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app": {"type": "string", "description": "Application binary or window name to inspect."}
            },
            "required": ["app"],
        },
    },
    {
        "name": "desktop_launch",
        "description": "Launch a desktop application (chromium, firefox, thunar, xfce4-terminal, mousepad, etc.) or open a public URL visibly inside the virtual desktop.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app": {"type": "string", "description": "Desktop app executable name (default chromium when url provided)."},
                "url": {"type": "string", "description": "Optional public http/https URL to open visibly."},
                "args": {"type": "array", "items": {"type": "string"}, "description": "Optional CLI flags."},
            },
        },
    },
    {
        "name": "desktop_focus_window",
        "description": "Bring a window whose title matches the substring to the foreground on the XFCE desktop.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Substring of target window title."}
            },
            "required": ["title"],
        },
    },
    {
        "name": "desktop_click",
        "description": "Move the pointer to (x, y) on the virtual desktop and perform a mouse click (left=1, middle=2, right=3).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer"},
                "y": {"type": "integer"},
                "button": {"type": "integer", "default": 1},
                "double": {"type": "boolean", "default": False},
            },
            "required": ["x", "y"],
        },
    },
    {
        "name": "desktop_type",
        "description": "Type text into the currently focused desktop window.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"}
            },
            "required": ["text"],
        },
    },
    {
        "name": "desktop_key",
        "description": "Send a keyboard key or shortcut (e.g. 'Return', 'Escape', 'Tab', 'ctrl+l', 'alt+Tab') to the focused desktop window.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {"type": "string"}
            },
            "required": ["keys"],
        },
    },
    {
        "name": "desktop_scroll",
        "description": "Scroll the mouse wheel up or down at optional (x, y) screen coordinates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "direction": {"type": "string", "enum": ["up", "down"], "default": "down"},
                "clicks": {"type": "integer", "default": 3},
                "x": {"type": "integer"},
                "y": {"type": "integer"},
            },
        },
    },
    {
        "name": "desktop_exec",
        "description": "Execute one or multiple shell commands inside the isolated Fedora desktop container (working directory /config, optional visible terminal output), returning exact exit_code, stdout, stderr, and per-step status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Single shell command or script to run via bash -lc."},
                "commands": {"type": "array", "items": {"type": "string"}, "description": "Ordered list of shell commands; halts on first non-zero exit_code unless continue_on_error is true."},
                "cwd": {"type": "string", "default": "/config"},
                "timeout_seconds": {"type": "integer", "default": 60},
                "continue_on_error": {"type": "boolean", "default": False},
                "show_terminal": {"type": "boolean", "default": True},
            },
        },
    },
]

# Pure Python 3 stdlib embedded Desktop Control & MCP Streamable HTTP Server (:9223)
# injected into every argo-desktop-<slug> container via docker put_archive.
_DESKTOP_AGENT_SCRIPT = '''#!/usr/bin/env python3
"""Argo embedded Virtual Desktop MCP & X11 control daemon on :9223."""
from __future__ import annotations

import base64
import ctypes
import glob
import json
import os
import shutil
import socket
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PORT = int(os.environ.get("ARGO_DESKTOP_MCP_PORT", "9223"))
AGENT_VERSION = "6"
CDP_PROXY_PORT = 9222
CDP_INTERNAL_PORT = 19222
PROVISION_STATUS_PATH = "/config/.argo-provision-status"
SESSION_ID = "argo-desktop-mcp-v6"
RECORDER_FLAG_PATH = "/config/.argo-recording-active"
RECORDER_CMD_LOG = "/config/.argo-recorded-commands.jsonl"

TOOLS_SPEC = ''' + repr(_MCP_TOOL_DEFINITIONS) + '''


def _detect_display() -> str:
    env_disp = (os.environ.get("DISPLAY") or "").strip()
    sockets = sorted(glob.glob("/tmp/.X11-unix/X*"))
    if sockets:
        preferred = []
        for sock_path in sockets:
            suffix = os.path.basename(sock_path).lstrip("X")
            if suffix.isdigit():
                preferred.append(f":{suffix}")
        if env_disp in preferred:
            return env_disp
        if ":1" in preferred:
            return ":1"
        if preferred:
            return preferred[0]
    return env_disp or ":1"


def _x_env(display: str | None = None) -> dict[str, str]:
    disp = display or _detect_display()
    env = dict(os.environ)
    env["DISPLAY"] = disp
    if not env.get("XAUTHORITY"):
        for candidate in ("/config/.Xauthority", os.path.expanduser("~/.Xauthority")):
            if os.path.exists(candidate):
                env["XAUTHORITY"] = candidate
                break
    return env


def _probe_tcp(host: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _read_provision_status() -> dict[str, Any]:
    try:
        with open(PROVISION_STATUS_PATH, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    except OSError:
        raw = "starting"
    if not raw:
        raw = "starting"
    if "|" in raw:
        state, detail = raw.split("|", 1)
        return {"state": state.strip(), "detail": detail.strip()}
    return {"state": raw, "detail": raw}


def _encode_png_rgb(width: int, height: int, rgb_bytes: bytes) -> bytes:
    stride = width * 3
    scanlines = bytearray(height * (stride + 1))
    dst_row_len = stride + 1
    for y in range(height):
        src_start = y * stride
        dst_start = y * dst_row_len
        scanlines[dst_start] = 0
        scanlines[dst_start + 1 : dst_start + dst_row_len] = rgb_bytes[src_start : src_start + stride]

    compressed = zlib.compress(bytes(scanlines), level=1)

    def _chunk(tag: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(tag)
        crc = zlib.crc32(payload, crc) & 0xFFFFFFFF
        return struct.pack("!I", len(payload)) + tag + payload + struct.pack("!I", crc)

    ihdr = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\\x89PNG\\r\\n\\x1a\\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", compressed)
        + _chunk(b"IEND", b"")
    )


class _XImage(ctypes.Structure):
    _fields_ = [
        ("width", ctypes.c_int),
        ("height", ctypes.c_int),
        ("xoffset", ctypes.c_int),
        ("format", ctypes.c_int),
        ("data", ctypes.c_void_p),
        ("byte_order", ctypes.c_int),
        ("bitmap_unit", ctypes.c_int),
        ("bitmap_bit_order", ctypes.c_int),
        ("bitmap_pad", ctypes.c_int),
        ("depth", ctypes.c_int),
        ("bytes_per_line", ctypes.c_int),
        ("bits_per_pixel", ctypes.c_int),
        ("red_mask", ctypes.c_ulong),
        ("green_mask", ctypes.c_ulong),
        ("blue_mask", ctypes.c_ulong),
    ]


_X11_LIB = None


def _load_x11():
    global _X11_LIB
    if _X11_LIB is not None:
        return _X11_LIB
    for name in ("libX11.so.6", "libX11.so"):
        try:
            lib = ctypes.CDLL(name)
            lib.XOpenDisplay.argtypes = [ctypes.c_char_p]
            lib.XOpenDisplay.restype = ctypes.c_void_p
            lib.XDefaultScreen.argtypes = [ctypes.c_void_p]
            lib.XDefaultScreen.restype = ctypes.c_int
            lib.XRootWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.XRootWindow.restype = ctypes.c_ulong
            lib.XDisplayWidth.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.XDisplayWidth.restype = ctypes.c_int
            lib.XDisplayHeight.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.XDisplayHeight.restype = ctypes.c_int
            lib.XGetImage.argtypes = [
                ctypes.c_void_p,
                ctypes.c_ulong,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint,
                ctypes.c_uint,
                ctypes.c_ulong,
                ctypes.c_int,
            ]
            lib.XGetImage.restype = ctypes.POINTER(_XImage)
            lib.XQueryPointer.argtypes = [
                ctypes.c_void_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_uint),
            ]
            lib.XQueryPointer.restype = ctypes.c_int
            lib.XCloseDisplay.argtypes = [ctypes.c_void_p]
            lib.XCloseDisplay.restype = ctypes.c_int
            if hasattr(lib, "XDestroyImage"):
                lib.XDestroyImage.argtypes = [ctypes.c_void_p]
                lib.XDestroyImage.restype = ctypes.c_int
            try:
                lib.XQueryKeymap.argtypes = [ctypes.c_void_p, ctypes.c_char * 32]
                lib.XQueryKeymap.restype = ctypes.c_int
                lib.XKeycodeToKeysym.argtypes = [ctypes.c_void_p, ctypes.c_ubyte, ctypes.c_int]
                lib.XKeycodeToKeysym.restype = ctypes.c_ulong
                lib.XKeysymToString.argtypes = [ctypes.c_ulong]
                lib.XKeysymToString.restype = ctypes.c_char_p
            except AttributeError:
                pass
            _X11_LIB = lib
            return lib
        except OSError:
            continue
    return None


def _x11_screen_size(display: str) -> tuple[int, int] | None:
    lib = _load_x11()
    if lib is None:
        return None
    dpy = lib.XOpenDisplay(display.encode("utf-8"))
    if not dpy:
        return None
    try:
        scr = lib.XDefaultScreen(dpy)
        return int(lib.XDisplayWidth(dpy, scr)), int(lib.XDisplayHeight(dpy, scr))
    finally:
        lib.XCloseDisplay(dpy)


def _capture_x11_png(display: str, max_width: int = 1280) -> tuple[bytes, int, int]:
    lib = _load_x11()
    if lib is None:
        raise RuntimeError("libX11 not available in container")
    dpy = lib.XOpenDisplay(display.encode("utf-8"))
    if not dpy:
        raise RuntimeError(f"Cannot open X11 display {display!r}")
    try:
        scr = lib.XDefaultScreen(dpy)
        root = lib.XRootWindow(dpy, scr)
        src_w = int(lib.XDisplayWidth(dpy, scr))
        src_h = int(lib.XDisplayHeight(dpy, scr))
        if src_w <= 0 or src_h <= 0:
            raise RuntimeError(f"Invalid X11 screen dimensions {src_w}x{src_h}")
        img_ptr = lib.XGetImage(dpy, root, 0, 0, src_w, src_h, 0xFFFFFFFF, 2)
        if not img_ptr:
            raise RuntimeError("XGetImage returned NULL")
        try:
            img = img_ptr.contents
            bpp = int(img.bits_per_pixel)
            bpl = int(img.bytes_per_line)
            if not img.data or bpp not in (24, 32):
                raise RuntimeError(f"Unsupported XImage format: bpp={bpp}")
            raw_mv = memoryview(ctypes.string_at(img.data, bpl * src_h))
            step = 1
            if max_width > 0 and src_w > max_width:
                step = max(1, (src_w + max_width - 1) // max_width)
            px_bytes = bpp // 8
            if step == 1 and bpl == src_w * 4 and px_bytes == 4:
                out_w, out_h = src_w, src_h
                rgb = bytearray(out_w * out_h * 3)
                # Little-endian BGRX -> RGB when red_mask=0xFF0000
                if img.red_mask == 0x0000FF:
                    rgb[0::3] = raw_mv[0::4]
                    rgb[1::3] = raw_mv[1::4]
                    rgb[2::3] = raw_mv[2::4]
                else:
                    rgb[0::3] = raw_mv[2::4]
                    rgb[1::3] = raw_mv[1::4]
                    rgb[2::3] = raw_mv[0::4]
            else:
                xs = range(0, src_w, step)
                ys = range(0, src_h, step)
                out_w = len(xs)
                out_h = len(ys)
                rgb = bytearray(out_w * out_h * 3)
                r_off, g_off, b_off = (0, 1, 2) if img.red_mask == 0x0000FF else (2, 1, 0)
                row_stride = out_w * 3
                row_step = px_bytes * step
                src_lim = src_w * px_bytes
                for dy, sy in enumerate(ys):
                    row_base = sy * bpl
                    row_mv = raw_mv[row_base : row_base + src_lim]
                    dst_base = dy * row_stride
                    dst_end = dst_base + row_stride
                    rgb[dst_base:dst_end:3] = row_mv[r_off::row_step]
                    rgb[dst_base + 1 : dst_end : 3] = row_mv[g_off::row_step]
                    rgb[dst_base + 2 : dst_end : 3] = row_mv[b_off::row_step]
            return _encode_png_rgb(out_w, out_h, bytes(rgb)), out_w, out_h
        finally:
            if hasattr(lib, "XDestroyImage"):
                lib.XDestroyImage(img_ptr)
    finally:
        lib.XCloseDisplay(dpy)


def _capture_screenshot_png(max_width: int = 1280) -> tuple[bytes, int, int, str]:
    display = _detect_display()
    try:
        png_bytes, width, height = _capture_x11_png(display, max_width=max_width)
        return png_bytes, width, height, display
    except Exception as x11_exc:
        env = _x_env(display)
        tmp_path = f"/tmp/.argo-shot-{os.getpid()}.png"
        for cmd in (
            ["xfce4-screenshooter", "-f", "-s", tmp_path],
            ["scrot", "-o", tmp_path],
            ["import", "-window", "root", tmp_path],
        ):
            if shutil.which(cmd[0]):
                try:
                    subprocess.run(cmd, env=env, timeout=10, check=True, capture_output=True)
                    with open(tmp_path, "rb") as shot_fh:
                        data = shot_fh.read()
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
                    if data.startswith(b"\\x89PNG"):
                        w, h = struct.unpack("!II", data[16:24])
                        return data, int(w), int(h), display
                except Exception:
                    continue
        raise RuntimeError(f"Desktop screenshot failed on {display}: {x11_exc}")


def _find_chromium_binary() -> str | None:
    for candidate in ("chromium", "chromium-browser", "google-chrome", "chrome"):
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _list_windows(display: str) -> list[dict[str, Any]]:
    env = _x_env(display)
    windows: list[dict[str, Any]] = []
    if shutil.which("wmctrl"):
        try:
            out = subprocess.run(
                ["wmctrl", "-lp", "-x"],
                env=env,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    parts = line.split(None, 5)
                    if len(parts) >= 5:
                        wid = parts[0]
                        desktop = parts[1]
                        pid = parts[2]
                        wm_class = parts[3] if len(parts) > 4 else ""
                        title = parts[5] if len(parts) > 5 else (parts[4] if len(parts) == 5 else "")
                        windows.append(
                            {
                                "id": wid,
                                "desktop": desktop,
                                "pid": int(pid) if pid.isdigit() else pid,
                                "wm_class": wm_class,
                                "title": title.strip(),
                            }
                        )
                return windows
        except Exception:
            pass
    if shutil.which("xdotool"):
        try:
            out = subprocess.run(
                ["xdotool", "search", "--onlyvisible", "--name", ""],
                env=env,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if out.returncode == 0:
                for wid in out.stdout.splitlines()[:40]:
                    wid = wid.strip()
                    if not wid:
                        continue
                    title_res = subprocess.run(
                        ["xdotool", "getwindowname", wid],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=2,
                        check=False,
                    )
                    windows.append(
                        {"id": wid, "title": title_res.stdout.strip()}
                    )
        except Exception:
            pass
    return windows


def _active_window_title(display: str) -> str:
    if not shutil.which("xdotool"):
        return ""
    try:
        res = subprocess.run(
            ["xdotool", "getactivewindow", "getwindowname"],
            env=_x_env(display),
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        return res.stdout.strip() if res.returncode == 0 else ""
    except Exception:
        return ""


def _list_processes() -> list[dict[str, Any]]:
    ignore = {"ps", "sleep", "tee", "sh", "bash"}
    procs: list[dict[str, Any]] = []
    try:
        out = subprocess.run(
            ["ps", "-eo", "pid,comm,args", "--no-headers"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) < 2:
                    continue
                pid_str, comm = parts[0], parts[1]
                args = parts[2] if len(parts) > 2 else comm
                if comm in ignore:
                    continue
                procs.append(
                    {
                        "pid": int(pid_str) if pid_str.isdigit() else pid_str,
                        "comm": comm,
                        "args": args[:160],
                    }
                )
    except Exception:
        pass
    return procs[:80]


def _inspect_status() -> dict[str, Any]:
    display = _detect_display()
    dims = _x11_screen_size(display)
    prov = _read_provision_status()
    chromium_bin = _find_chromium_binary()
    firefox_bin = shutil.which("firefox")
    xdotool_bin = shutil.which("xdotool")
    wmctrl_bin = shutil.which("wmctrl")
    windows = _list_windows(display)
    processes = _list_processes()
    return {
        "status": "ok",
        "agent_version": AGENT_VERSION,
        "mcp_port": PORT,
        "display": display,
        "screen": {
            "width": dims[0] if dims else None,
            "height": dims[1] if dims else None,
        },
        "provision": prov,
        "cdp_proxy_ready": _probe_tcp("127.0.0.1", CDP_PROXY_PORT),
        "cdp_internal_ready": _probe_tcp("127.0.0.1", CDP_INTERNAL_PORT),
        "tools": {
            "x11_ctypes": _load_x11() is not None,
            "xdotool": bool(xdotool_bin),
            "wmctrl": bool(wmctrl_bin),
            "chromium": bool(chromium_bin),
            "firefox": bool(firefox_bin),
        },
        "active_window": _active_window_title(display),
        "windows": windows,
        "window_count": len(windows),
        "processes": processes,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _run_xdotool(args: list[str], display: str) -> subprocess.CompletedProcess[str]:
    if not shutil.which("xdotool"):
        raise RuntimeError("xdotool is not installed yet (desktop provisioning may still be finishing)")
    return subprocess.run(
        ["xdotool", *args],
        env=_x_env(display),
        capture_output=True,
        text=True,
        timeout=8,
        check=True,
    )


_REC_LOCK = threading.Lock()
_REC_STATE: dict[str, Any] = {
    "active": False,
    "started_at": "",
    "started_epoch": 0.0,
    "bash_history_offset": 0,
    "windows": [],
    "clicks": [],
    "urls": [],
    "dom_events": [],
    "typed_inputs": [],
    "seen_urls": set(),
    "last_window": "",
    "last_btn_mask": 0,
    "last_keymap": b"",
    "typed_buf": [],
    "typed_last_epoch": 0.0,
    "stop_event": None,
    "thread": None,
}

_BASH_RECORDER_SNIPPET = (
    "\\n# ARGO_RECORDER_HOOK\\n"
    "__argo_rec_prompt() {\\n"
    "  local ec=$?\\n"
    "  if [ -f /config/.argo-recording-active ]; then\\n"
    "    local c\\n"
    "    c=$(HISTTIMEFORMAT='' history 1 2>/dev/null | sed 's/^[ ]*[0-9]*[ ]*//')\\n"
    "    if [ -n \\"$c\\" ] && [ \\"$c\\" != \\"${__ARGO_LAST_CMD:-}\\" ]; then\\n"
    "      __ARGO_LAST_CMD=\\"$c\\"\\n"
    "      python3 -c 'import json,os,sys,time; open(\\"/config/.argo-recorded-commands.jsonl\\",\\"a\\").write(json.dumps({\\"ts\\":time.strftime(\\"%Y-%m-%dT%H:%M:%SZ\\",time.gmtime()),\\"cwd\\":os.getcwd(),\\"exit_code\\":int(sys.argv[1]),\\"cmd\\":sys.argv[2]})+\\"\\\\n\\")' \\"$ec\\" \\"$c\\" 2>/dev/null || true\\n"
    "    fi\\n"
    "  fi\\n"
    "}\\n"
    "PROMPT_COMMAND=\\"__argo_rec_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}\\"\\n"
)


def _ensure_bash_recorder_hook() -> None:
    if not os.path.isdir("/config"):
        return
    bashrc_path = "/config/.bashrc"
    try:
        existing = ""
        if os.path.exists(bashrc_path):
            with open(bashrc_path, "r", encoding="utf-8", errors="ignore") as fh:
                existing = fh.read()
        if "# ARGO_RECORDER_HOOK" not in existing:
            with open(bashrc_path, "a", encoding="utf-8") as fh:
                fh.write(_BASH_RECORDER_SNIPPET)
    except OSError:
        pass


def _read_cdp_tab_urls() -> list[dict[str, str]]:
    if not _probe_tcp("127.0.0.1", CDP_INTERNAL_PORT, timeout=0.25):
        return []
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{CDP_INTERNAL_PORT}/json/list",
            headers={"Host": f"127.0.0.1:{CDP_INTERNAL_PORT}"},
        )
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            tabs = json.loads(resp.read().decode("utf-8") or "[]")
        out: list[dict[str, str]] = []
        for tab in tabs:
            if tab.get("type") == "page":
                u = str(tab.get("url") or "").strip()
                if u.startswith(("http://", "https://")):
                    out.append(
                        {
                            "url": u,
                            "title": str(tab.get("title") or "")[:120],
                            "ws": str(tab.get("webSocketDebuggerUrl") or "").strip(),
                        }
                    )
        return out
    except Exception:
        return []


def _cdp_eval_js(ws_url: str, expression: str, timeout: float = 0.8) -> Any:
    if not ws_url:
        return None
    parsed = urllib.parse.urlparse(ws_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or CDP_INTERNAL_PORT
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    crlf = chr(13) + chr(10)
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        handshake = (
            f"GET {path} HTTP/1.1{crlf}"
            f"Host: 127.0.0.1:{port}{crlf}"
            f"Upgrade: websocket{crlf}"
            f"Connection: Upgrade{crlf}"
            f"Sec-WebSocket-Key: {ws_key}{crlf}"
            f"Sec-WebSocket-Version: 13{crlf}{crlf}"
        ).encode("ascii")
        sock.sendall(handshake)
        buf = b""
        sep = (crlf + crlf).encode("ascii")
        while sep not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf += chunk
        payload = json.dumps(
            {
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {"expression": expression, "returnByValue": True},
            },
            ensure_ascii=False,
        ).encode("utf-8")
        mask = os.urandom(4)
        plen = len(payload)
        hdr = bytearray([0x81])
        if plen < 126:
            hdr.append(0x80 | plen)
        elif plen < 65536:
            hdr.append(0x80 | 126)
            hdr.extend(struct.pack("!H", plen))
        else:
            hdr.append(0x80 | 127)
            hdr.extend(struct.pack("!Q", plen))
        hdr.extend(mask)
        masked = bytes(payload[idx] ^ mask[idx % 4] for idx in range(plen))
        sock.sendall(bytes(hdr) + masked)

        def _recv_exact(n: int) -> bytes:
            out_b = bytearray()
            while len(out_b) < n:
                ch = sock.recv(n - len(out_b))
                if not ch:
                    raise EOFError("ws eof")
                out_b.extend(ch)
            return bytes(out_b)

        for _ in range(8):
            b0, b1 = struct.unpack("!BB", _recv_exact(2))
            opcode = b0 & 0x0F
            ln = b1 & 0x7F
            if ln == 126:
                ln = struct.unpack("!H", _recv_exact(2))[0]
            elif ln == 127:
                ln = struct.unpack("!Q", _recv_exact(8))[0]
            if b1 & 0x80:
                _ = _recv_exact(4)
            frame_data = _recv_exact(ln) if ln else b""
            if opcode == 0x8:
                return None
            if opcode == 0x1:
                msg = json.loads(frame_data.decode("utf-8", errors="ignore") or "{}")
                if msg.get("id") == 1:
                    val = (((msg.get("result") or {}).get("result") or {}).get("value"))
                    return val
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


_CDP_DOM_RECORDER_JS = """(() => {
  if (!window.__argoRec) {
    window.__argoRec = [];
    const _lbl = (el) => {
      if (!el) return "";
      return (el.getAttribute("aria-label") || el.getAttribute("placeholder") || el.name || el.id || el.innerText || "").replace(/\\\\s+/g, " ").trim().slice(0, 80);
    };
    const _sel = (el) => {
      if (!el || !el.tagName) return "";
      if (el.id) return "#" + el.id;
      const aria = el.getAttribute && el.getAttribute("aria-label");
      if (aria) return el.tagName.toLowerCase() + "[aria-label='" + aria.slice(0, 40) + "']";
      if (el.name) return el.tagName.toLowerCase() + "[name='" + el.name.slice(0, 40) + "']";
      return el.tagName.toLowerCase();
    };
    document.addEventListener("click", (e) => {
      const t = e.target;
      window.__argoRec.push({ts: new Date().toISOString(), kind: "click", tag: t && t.tagName ? t.tagName.toLowerCase() : "", label: _lbl(t), selector: _sel(t), x: Math.round(e.clientX || 0), y: Math.round(e.clientY || 0), url: location.href});
    }, true);
    document.addEventListener("change", (e) => {
      const t = e.target;
      if (!t || !("value" in t)) return;
      const typ = String(t.type || "").toLowerCase();
      if (typ === "password") return;
      window.__argoRec.push({ts: new Date().toISOString(), kind: "input", tag: (t.tagName || "").toLowerCase(), label: _lbl(t), selector: _sel(t), value: String(t.value || "").slice(0, 160), url: location.href});
    }, true);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === "Tab" || e.key === "Escape") {
        window.__argoRec.push({ts: new Date().toISOString(), kind: "key", key: e.key, label: _lbl(e.target), selector: _sel(e.target), url: location.href});
      }
    }, true);
  }
  return JSON.stringify(window.__argoRec.splice(0, 50));
})()"""


def _poll_cdp_dom_recorder() -> None:
    tabs = _read_cdp_tab_urls()
    for tab in tabs:
        ws = tab.get("ws") or ""
        if not ws:
            continue
        try:
            raw = _cdp_eval_js(ws, _CDP_DOM_RECORDER_JS, timeout=0.6)
            if isinstance(raw, str) and raw.startswith("["):
                events = json.loads(raw)
                if isinstance(events, list) and events:
                    with _REC_LOCK:
                        for ev in events:
                            if isinstance(ev, dict) and len(_REC_STATE["dom_events"]) < 250:
                                _REC_STATE["dom_events"].append(ev)
        except Exception:
            continue


def _query_x11_keymap_chars(
    display: str,
    prev_map: bytes,
    shared_dpy: Any = None,
) -> tuple[bytes, list[str]]:
    lib = _load_x11()
    if lib is None or not hasattr(lib, "XQueryKeymap"):
        return prev_map, []
    owns_dpy = shared_dpy is None
    dpy = shared_dpy if shared_dpy is not None else lib.XOpenDisplay(display.encode("utf-8"))
    if not dpy:
        return prev_map, []
    keys_pressed: list[str] = []
    try:
        arr = (ctypes.c_char * 32)()
        lib.XQueryKeymap(dpy, arr)
        cur_map = bytes(arr)
        if prev_map and len(prev_map) == 32:
            shift_on = False
            for byte_idx in range(32):
                b = cur_map[byte_idx]
                if b:
                    for bit in range(8):
                        if b & (1 << bit):
                            kc = byte_idx * 8 + bit
                            ks = lib.XKeycodeToKeysym(dpy, kc, 0)
                            if ks:
                                kn = lib.XKeysymToString(ks)
                                if kn in (b"Shift_L", b"Shift_R"):
                                    shift_on = True
            lvl = 1 if shift_on else 0
            for byte_idx in range(32):
                diff = cur_map[byte_idx] & (~prev_map[byte_idx] & 0xFF)
                if not diff:
                    continue
                for bit in range(8):
                    if diff & (1 << bit):
                        kc = byte_idx * 8 + bit
                        ks = lib.XKeycodeToKeysym(dpy, kc, lvl)
                        if not ks and lvl:
                            ks = lib.XKeycodeToKeysym(dpy, kc, 0)
                        if ks:
                            raw_name = lib.XKeysymToString(ks)
                            if raw_name:
                                kname = raw_name.decode("utf-8", errors="ignore")
                                if kname not in ("Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R", "Super_L", "Super_R", "Caps_Lock"):
                                    keys_pressed.append(kname)
        return cur_map, keys_pressed
    except Exception:
        return prev_map, []
    finally:
        if owns_dpy:
            lib.XCloseDisplay(dpy)


def _query_x11_pointer(
    display: str,
    shared_dpy: Any = None,
) -> tuple[int, int, int] | None:
    lib = _load_x11()
    if lib is None:
        return None
    owns_dpy = shared_dpy is None
    dpy = shared_dpy if shared_dpy is not None else lib.XOpenDisplay(display.encode("utf-8"))
    if not dpy:
        return None
    try:
        scr = lib.XDefaultScreen(dpy)
        root = lib.XRootWindow(dpy, scr)
        r_win = ctypes.c_ulong()
        c_win = ctypes.c_ulong()
        rx = ctypes.c_int()
        ry = ctypes.c_int()
        wx = ctypes.c_int()
        wy = ctypes.c_int()
        mask = ctypes.c_uint()
        ok = lib.XQueryPointer(
            dpy,
            root,
            ctypes.byref(r_win),
            ctypes.byref(c_win),
            ctypes.byref(rx),
            ctypes.byref(ry),
            ctypes.byref(wx),
            ctypes.byref(wy),
            ctypes.byref(mask),
        )
        if not ok:
            return None
        return int(rx.value), int(ry.value), int(mask.value)
    finally:
        if owns_dpy:
            lib.XCloseDisplay(dpy)


_KEYSYM_MAP = {
    "space": " ",
    "period": ".",
    "comma": ",",
    "minus": "-",
    "underscore": "_",
    "slash": "/",
    "colon": ":",
    "semicolon": ";",
    "at": "@",
    "plus": "+",
    "equal": "=",
    "question": "?",
    "ampersand": "&",
    "exclam": "!",
}


def _flush_typed_buffer_locked(now_iso: str) -> None:
    buf = _REC_STATE.get("typed_buf") or []
    if not buf:
        return
    txt = "".join(buf).strip()
    _REC_STATE["typed_buf"] = []
    if txt and len(_REC_STATE["typed_inputs"]) < 200:
        _REC_STATE["typed_inputs"].append(
            {
                "ts": now_iso,
                "text": txt[:240],
                "window": str(_REC_STATE.get("last_window") or ""),
            }
        )


def _recorder_sampler_loop(stop_ev: threading.Event) -> None:
    tick = 0
    prev_kmap = b""
    lib = _load_x11()
    dpy = None
    last_disp = ""
    try:
        while not stop_ev.is_set():
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            now_ep = time.time()
            with _REC_LOCK:
                started_epoch = float(_REC_STATE.get("started_epoch") or 0.0)
            if started_epoch and (now_ep - started_epoch) > 1800.0:
                break
            disp = _detect_display()
            if lib is not None and (not dpy or disp != last_disp):
                if dpy:
                    try:
                        lib.XCloseDisplay(dpy)
                    except Exception:
                        pass
                    dpy = None
                try:
                    dpy = lib.XOpenDisplay(disp.encode("utf-8"))
                    last_disp = disp
                except Exception:
                    dpy = None

            ptr = _query_x11_pointer(disp, shared_dpy=dpy)
            if ptr is not None:
                rx, ry, mask = ptr
                btn_bits = mask & (256 | 512 | 1024)
                with _REC_LOCK:
                    prev_bits = int(_REC_STATE.get("last_btn_mask") or 0)
                    if btn_bits and not prev_bits and len(_REC_STATE["clicks"]) < 250:
                        _flush_typed_buffer_locked(now_iso)
                        _REC_STATE["clicks"].append(
                            {
                                "ts": now_iso,
                                "x": rx,
                                "y": ry,
                                "window": str(_REC_STATE.get("last_window") or ""),
                            }
                        )
                    _REC_STATE["last_btn_mask"] = btn_bits

            prev_kmap, keys_pressed = _query_x11_keymap_chars(disp, prev_kmap, shared_dpy=dpy)
            if keys_pressed:
                with _REC_LOCK:
                    for kn in keys_pressed:
                        if kn == "BackSpace":
                            if _REC_STATE["typed_buf"]:
                                _REC_STATE["typed_buf"].pop()
                        elif kn in ("Return", "KP_Enter", "Tab", "Escape"):
                            _flush_typed_buffer_locked(now_iso)
                            if len(_REC_STATE["typed_inputs"]) < 200:
                                _REC_STATE["typed_inputs"].append(
                                    {
                                        "ts": now_iso,
                                        "text": f"[{kn}]",
                                        "key": kn,
                                        "window": str(_REC_STATE.get("last_window") or ""),
                                    }
                                )
                        elif len(kn) == 1 and kn.isprintable():
                            _REC_STATE["typed_buf"].append(kn)
                            _REC_STATE["typed_last_epoch"] = now_ep
                        elif kn in _KEYSYM_MAP:
                            _REC_STATE["typed_buf"].append(_KEYSYM_MAP[kn])
                            _REC_STATE["typed_last_epoch"] = now_ep
            else:
                with _REC_LOCK:
                    last_t = float(_REC_STATE.get("typed_last_epoch") or 0.0)
                    if _REC_STATE.get("typed_buf") and last_t and (now_ep - last_t) > 1.5:
                        _flush_typed_buffer_locked(now_iso)

            if tick % 12 == 0:
                active_w = _active_window_title(disp)
                with _REC_LOCK:
                    if active_w and active_w != _REC_STATE.get("last_window"):
                        _REC_STATE["last_window"] = active_w
                        if len(_REC_STATE["windows"]) < 200:
                            _REC_STATE["windows"].append({"ts": now_iso, "window": active_w})
                for tab in _read_cdp_tab_urls():
                    u = tab["url"]
                    with _REC_LOCK:
                        if u not in _REC_STATE["seen_urls"] and len(_REC_STATE["urls"]) < 150:
                            _REC_STATE["seen_urls"].add(u)
                            _REC_STATE["urls"].append({"ts": now_iso, "url": u, "title": tab["title"]})
                _poll_cdp_dom_recorder()
            tick += 1
            stop_ev.wait(0.08)
    finally:
        if lib is not None and dpy:
            try:
                lib.XCloseDisplay(dpy)
            except Exception:
                pass


def _read_recorded_commands(hist_offset: int) -> list[dict[str, Any]]:
    cmds: list[dict[str, Any]] = []
    seen_texts: set[str] = set()
    if os.path.exists(RECORDER_CMD_LOG):
        try:
            with open(RECORDER_CMD_LOG, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        obj = json.loads(raw)
                        cmd_txt = str(obj.get("cmd") or "").strip()
                        if cmd_txt:
                            cmds.append(obj)
                            seen_texts.add(cmd_txt)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
    hist_path = "/config/.bash_history"
    if os.path.exists(hist_path):
        try:
            with open(hist_path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = [ln.strip() for ln in fh.read().splitlines() if ln.strip() and not ln.startswith("#")]
            for ln in lines[hist_offset:]:
                if ln not in seen_texts:
                    cmds.append({"ts": "", "cwd": "/config", "exit_code": 0, "cmd": ln})
                    seen_texts.add(ln)
        except OSError:
            pass
    return cmds[-150:]


def _start_recording() -> dict[str, Any]:
    _ensure_bash_recorder_hook()
    hist_offset = 0
    hist_path = "/config/.bash_history"
    if os.path.exists(hist_path):
        try:
            with open(hist_path, "r", encoding="utf-8", errors="ignore") as fh:
                hist_offset = len([ln for ln in fh.read().splitlines() if ln.strip() and not ln.startswith("#")])
        except OSError:
            hist_offset = 0
    if os.path.isdir("/config"):
        try:
            with open(RECORDER_CMD_LOG, "w", encoding="utf-8") as fh:
                fh.write("")
            with open(RECORDER_FLAG_PATH, "w", encoding="utf-8") as fh:
                fh.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        except OSError:
            pass
    with _REC_LOCK:
        old_ev = _REC_STATE.get("stop_event")
        if old_ev is not None:
            old_ev.set()
        stop_ev = threading.Event()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        now_epoch = time.time()
        _REC_STATE.update(
            {
                "active": True,
                "started_at": now_iso,
                "started_epoch": now_epoch,
                "bash_history_offset": hist_offset,
                "windows": [],
                "clicks": [],
                "urls": [],
                "dom_events": [],
                "typed_inputs": [],
                "seen_urls": set(),
                "last_window": "",
                "last_btn_mask": 0,
                "last_keymap": b"",
                "typed_buf": [],
                "typed_last_epoch": 0.0,
                "stop_event": stop_ev,
                "thread": None,
            }
        )
        t = threading.Thread(target=_recorder_sampler_loop, args=(stop_ev,), daemon=True)
        _REC_STATE["thread"] = t
        t.start()
    return {"status": "ok", "recording": True, "started_at": now_iso, "elapsed_seconds": 0}


def _recording_status() -> dict[str, Any]:
    with _REC_LOCK:
        active = bool(_REC_STATE.get("active"))
        started_at = str(_REC_STATE.get("started_at") or "")
        started_epoch = float(_REC_STATE.get("started_epoch") or 0.0)
        hist_offset = int(_REC_STATE.get("bash_history_offset") or 0)
        event_count = (
            len(_REC_STATE.get("windows") or [])
            + len(_REC_STATE.get("clicks") or [])
            + len(_REC_STATE.get("urls") or [])
            + len(_REC_STATE.get("dom_events") or [])
            + len(_REC_STATE.get("typed_inputs") or [])
        )
    cmd_count = len(_read_recorded_commands(hist_offset)) if active else 0
    elapsed = int(max(0.0, time.time() - started_epoch)) if active and started_epoch else 0
    return {
        "status": "ok",
        "recording": active,
        "started_at": started_at,
        "elapsed_seconds": elapsed,
        "command_count": cmd_count,
        "event_count": event_count,
    }


def _stop_recording() -> dict[str, Any]:
    if os.path.exists(RECORDER_FLAG_PATH):
        try:
            os.remove(RECORDER_FLAG_PATH)
        except OSError:
            pass
    with _REC_LOCK:
        stop_ev = _REC_STATE.get("stop_event")
        t = _REC_STATE.get("thread")
        _REC_STATE["active"] = False
        _REC_STATE["stop_event"] = None
        _REC_STATE["thread"] = None
    if stop_ev is not None:
        stop_ev.set()
    if t is not None:
        t.join(timeout=1.5)
    _poll_cdp_dom_recorder()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _REC_LOCK:
        _flush_typed_buffer_locked(now_iso)
        started_at = str(_REC_STATE.get("started_at") or "")
        started_epoch = float(_REC_STATE.get("started_epoch") or 0.0)
        hist_offset = int(_REC_STATE.get("bash_history_offset") or 0)
        windows = list(_REC_STATE.get("windows") or [])
        clicks = list(_REC_STATE.get("clicks") or [])
        urls = list(_REC_STATE.get("urls") or [])
        dom_events = list(_REC_STATE.get("dom_events") or [])
        typed_inputs = list(_REC_STATE.get("typed_inputs") or [])
    commands = _read_recorded_commands(hist_offset)
    if os.path.exists(RECORDER_CMD_LOG):
        try:
            os.remove(RECORDER_CMD_LOG)
        except OSError:
            pass
    duration = int(max(0.0, time.time() - started_epoch)) if started_epoch else 0
    return {
        "status": "ok",
        "recording": False,
        "started_at": started_at,
        "duration_seconds": duration,
        "commands": commands,
        "visited_urls": urls,
        "window_events": windows,
        "clicks": clicks,
        "dom_events": dom_events,
        "typed_inputs": typed_inputs,
    }


def _perform_action(action: str, params: dict[str, Any]) -> dict[str, Any]:
    act = (action or "").strip().lower()
    display = _detect_display()

    if act in ("inspect", "status"):
        return _inspect_status()

    if act == "screenshot":
        max_w = int(params.get("max_width", 1280) or 1280)
        png_bytes, width, height, disp = _capture_screenshot_png(max_width=max_w)
        return {
            "status": "ok",
            "action": "screenshot",
            "display": disp,
            "width": width,
            "height": height,
            "mime_type": "image/png",
            "image_base64": base64.b64encode(png_bytes).decode("ascii"),
            "byte_length": len(png_bytes),
        }

    if act == "check_app":
        app = str(params.get("app") or "").strip()
        if not app:
            return {"status": "error", "detail": "app is required"}
        exe = _find_chromium_binary() if app.lower() in ("chromium", "chrome", "google-chrome") else shutil.which(app)
        procs = [
            p for p in _list_processes()
            if app.lower() in str(p.get("comm", "")).lower()
            or app.lower() in str(p.get("args", "")).lower()
        ]
        wins = [
            w for w in _list_windows(display)
            if app.lower() in str(w.get("title", "")).lower()
            or app.lower() in str(w.get("wm_class", "")).lower()
        ]
        return {
            "status": "ok",
            "action": "check_app",
            "app": app,
            "installed": bool(exe),
            "executable": exe,
            "running": bool(procs),
            "processes": procs[:15],
            "windows": wins,
            "provision": _read_provision_status(),
        }

    if act == "launch":
        raw_app = str(params.get("app") or "").strip()
        raw_url = str(params.get("url") or "").strip()
        extra_args = [str(a) for a in (params.get("args") or []) if str(a).strip()]
        target_app = raw_app or ("chromium" if raw_url else "")
        if not target_app:
            return {"status": "error", "detail": "Specify app or url to launch"}
        exe = None
        if target_app.lower() in ("chromium", "chromium-browser", "chrome", "google-chrome", "browser"):
            if not raw_url and _probe_tcp("127.0.0.1", CDP_INTERNAL_PORT, timeout=0.3):
                return {
                    "status": "ok",
                    "action": "launch",
                    "app": target_app,
                    "already_running": True,
                    "display": display,
                    "windows": _list_windows(display),
                }
            prefs_path = "/config/.config/argo-chromium/Default/Preferences"
            if os.path.exists(prefs_path):
                try:
                    with open(prefs_path, "r", encoding="utf-8", errors="ignore") as pfh:
                        pdata = json.load(pfh)
                    prof = pdata.setdefault("profile", {})
                    prof["exit_type"] = "Normal"
                    prof["exited_cleanly"] = True
                    with open(prefs_path, "w", encoding="utf-8") as pfh:
                        json.dump(pdata, pfh)
                except Exception:
                    pass
            exe = _find_chromium_binary()
            if not exe and not raw_app:
                exe = shutil.which("firefox")
            if exe and "chromium" in os.path.basename(exe):
                extra_args = [
                    "--no-sandbox",
                    "--test-type",
                    "--disable-dev-shm-usage",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--hide-crash-restore-bubble",
                    "--disable-session-crashed-bubble",
                    "--disable-infobars",
                    f"--remote-debugging-port={CDP_INTERNAL_PORT}",
                    "--remote-debugging-address=127.0.0.1",
                    "--remote-allow-origins=*",
                    "--user-data-dir=/config/.config/argo-chromium",
                    "--password-store=basic",
                    "--window-size=1280,860",
                    *extra_args,
                ]
        else:
            exe = shutil.which(target_app)
        if not exe:
            return {
                "status": "error",
                "action": "launch",
                "app": target_app,
                "detail": f"Application '{target_app}' is not installed on this desktop container.",
                "provision": _read_provision_status(),
            }
        cmd = [exe, *extra_args]
        if raw_url:
            cmd.append(raw_url)
        env = _x_env(display)
        with open("/config/.argo-launch-actions.log", "a", encoding="utf-8") as log_file:
            proc = subprocess.Popen(
                cmd,
                env=env,
                stdout=log_file,
                stderr=log_file,
                start_new_session=True,
            )
        time.sleep(0.8)
        return {
            "status": "ok",
            "action": "launch",
            "app": target_app,
            "executable": exe,
            "url": raw_url or None,
            "pid": proc.pid,
            "display": display,
            "windows": _list_windows(display),
        }

    if act == "focus_window":
        title = str(params.get("title") or "").strip()
        if not title:
            return {"status": "error", "detail": "title is required"}
        if shutil.which("wmctrl"):
            res = subprocess.run(
                ["wmctrl", "-a", title],
                env=_x_env(display),
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            if res.returncode == 0:
                return {"status": "ok", "action": "focus_window", "title": title, "active_window": _active_window_title(display)}
        res = _run_xdotool(["search", "--name", title, "windowactivate"], display)
        return {"status": "ok", "action": "focus_window", "title": title, "active_window": _active_window_title(display), "output": res.stdout.strip()}

    if act in ("click", "move"):
        x = int(params["x"])
        y = int(params["y"])
        if act == "move":
            _run_xdotool(["mousemove", "--sync", str(x), str(y)], display)
            return {"status": "ok", "action": "move", "x": x, "y": y}
        button = int(params.get("button", 1) or 1)
        args = ["mousemove", "--sync", str(x), str(y), "click"]
        if params.get("double"):
            args.extend(["--repeat", "2", "--delay", "80"])
        args.append(str(button))
        _run_xdotool(args, display)
        time.sleep(0.25)
        return {"status": "ok", "action": "click", "x": x, "y": y, "button": button, "double": bool(params.get("double"))}

    if act == "type":
        text = str(params.get("text") or "")
        if not text:
            return {"status": "error", "detail": "text is required"}
        _run_xdotool(["type", "--clearmodifiers", "--delay", "12", "--", text], display)
        return {"status": "ok", "action": "type", "length": len(text)}

    if act == "key":
        keys = str(params.get("keys") or params.get("key") or "").strip()
        if not keys:
            return {"status": "error", "detail": "keys is required"}
        _run_xdotool(["key", "--clearmodifiers", keys], display)
        if keys.lower() in ("return", "kp_enter", "enter", "tab", "escape"):
            time.sleep(0.25)
        return {"status": "ok", "action": "key", "keys": keys}

    if act == "scroll":
        direction = str(params.get("direction") or "down").strip().lower()
        clicks = max(1, min(20, int(params.get("clicks", 3) or 3)))
        btn = "4" if direction == "up" else "5"
        args: list[str] = []
        if params.get("x") is not None and params.get("y") is not None:
            args.extend(["mousemove", "--sync", str(int(params["x"])), str(int(params["y"]))])
        args.extend(["click", "--repeat", str(clicks), btn])
        _run_xdotool(args, display)
        return {"status": "ok", "action": "scroll", "direction": direction, "clicks": clicks}

    if act in ("exec", "shell", "bash", "run_command"):
        raw_commands = params.get("commands")
        cmds: list[str] = []
        if isinstance(raw_commands, list):
            cmds = [str(c).strip() for c in raw_commands if str(c).strip()]
        elif str(params.get("command") or "").strip():
            cmds = [str(params.get("command")).strip()]
        if not cmds:
            return {"status": "error", "action": "exec", "detail": "command or commands is required"}

        raw_cwd = str(params.get("cwd") or "/config").strip() or "/config"
        if os.path.isdir(raw_cwd):
            resolved_cwd = raw_cwd
        elif os.path.isdir("/config"):
            resolved_cwd = "/config"
        else:
            resolved_cwd = os.getcwd()

        timeout_s = max(2, min(180, int(params.get("timeout_seconds") or 60)))
        continue_on_error = bool(params.get("continue_on_error", False))
        show_terminal = bool(params.get("show_terminal", True))

        term_log_path = "/config/.argo-terminal.log"
        if show_terminal and os.path.isdir("/config"):
            try:
                with open(term_log_path, "a", encoding="utf-8"):
                    pass
                disp_num = display.lstrip(":")
                if (
                    shutil.which("xfce4-terminal")
                    and os.path.exists(f"/tmp/.X11-unix/X{disp_num}")
                    and not any("argo shell" in str(w.get("title", "")).lower() for w in _list_windows(display))
                ):
                    subprocess.Popen(
                        [
                            "xfce4-terminal",
                            "--title=Argo Shell",
                            "-e",
                            f"bash -lc 'touch {term_log_path}; tail -n 80 -f {term_log_path}'",
                        ],
                        env=_x_env(display),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    time.sleep(0.35)
            except OSError:
                pass

        steps: list[dict[str, Any]] = []
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        overall_status = "ok"
        final_exit = 0
        failed_cmd: str | None = None
        env = _x_env(display)
        extra_env = params.get("env")
        temp_key_files: list[str] = []
        if isinstance(extra_env, dict):
            for raw_k, raw_v in extra_env.items():
                key = str(raw_k or "").strip()
                if not key or raw_v is None:
                    continue
                val = str(raw_v)
                env[key] = val
                if key.startswith("ARGO_VAULT_") and key.endswith("_PRIVATE_KEY") and val.strip():
                    key_path = f"/tmp/.argo-vk-{os.getpid()}-{len(temp_key_files)}.pem"
                    try:
                        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, "w", encoding="utf-8") as kf:
                            kf.write(val if val.endswith("\\n") else val + "\\n")
                        os.chmod(key_path, 0o600)
                        env[key[: -len("_PRIVATE_KEY")] + "_KEY_PATH"] = key_path
                        temp_key_files.append(key_path)
                    except OSError:
                        pass

        try:
            for cmd in cmds:
                try:
                    res = subprocess.run(
                        ["/bin/bash", "-lc", cmd],
                        cwd=resolved_cwd,
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=timeout_s,
                        check=False,
                    )
                    step_out = res.stdout[-3000:] if res.stdout else ""
                    step_err = res.stderr[-3000:] if res.stderr else ""
                    steps.append(
                        {
                            "command": cmd,
                            "exit_code": int(res.returncode),
                            "status": "ok" if res.returncode == 0 else "command_failed",
                            "stdout": step_out,
                            "stderr": step_err,
                        }
                    )
                    if step_out:
                        stdout_chunks.append(step_out)
                    if step_err:
                        stderr_chunks.append(step_err)
                    if show_terminal and os.path.isdir("/config"):
                        try:
                            with open(term_log_path, "a", encoding="utf-8") as log_fh:
                                log_fh.write(f"$ {cmd}\\n")
                                if step_out:
                                    log_fh.write(step_out + ("" if step_out.endswith("\\n") else "\\n"))
                                if step_err:
                                    log_fh.write(step_err + ("" if step_err.endswith("\\n") else "\\n"))
                                log_fh.write(f"[exit_code={res.returncode}]\\n")
                        except OSError:
                            pass
                    if res.returncode != 0:
                        overall_status = "command_failed"
                        final_exit = int(res.returncode)
                        failed_cmd = cmd
                        if not continue_on_error:
                            break
                except subprocess.TimeoutExpired as exc:
                    raw_out = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                    raw_err = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                    timeout_msg = f"Command timed out after {timeout_s}s: {cmd}"
                    step_err = (raw_err + ("\\n" if raw_err else "") + timeout_msg)[-3000:]
                    steps.append(
                        {
                            "command": cmd,
                            "exit_code": 124,
                            "status": "timeout",
                            "stdout": raw_out[-3000:],
                            "stderr": step_err,
                        }
                    )
                    if raw_out:
                        stdout_chunks.append(raw_out[-3000:])
                    stderr_chunks.append(step_err)
                    overall_status = "timeout"
                    final_exit = 124
                    failed_cmd = cmd
                    break
        finally:
            for kp in temp_key_files:
                try:
                    os.remove(kp)
                except OSError:
                    pass

        return {
            "status": overall_status,
            "action": "exec",
            "cwd": resolved_cwd,
            "exit_code": final_exit,
            "failed_command": failed_cmd,
            "stdout": "\\n".join(stdout_chunks)[-4000:],
            "stderr": "\\n".join(stderr_chunks)[-4000:],
            "steps": steps,
        }

    if act == "record_start":
        return _start_recording()

    if act == "record_status":
        return _recording_status()

    if act == "record_stop":
        return _stop_recording()

    return {"status": "error", "detail": f"Unsupported desktop action: {action}"}


def _handle_mcp_rpc(payload: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
    req_id = payload.get("id")
    method = str(payload.get("method") or "")
    params = payload.get("params") or {}

    if method == "notifications/initialized":
        return 202, None

    if method == "initialize":
        return 200, {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "argo-desktop-mcp", "version": f"{AGENT_VERSION}.0.0"},
            },
        }

    if method == "ping":
        return 200, {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return 200, {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS_SPEC},
        }

    if method == "tools/call":
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        action_name = tool_name[len("desktop_") :] if tool_name.startswith("desktop_") else tool_name
        try:
            res = _perform_action(action_name, arguments)
            if action_name == "screenshot" and res.get("status") == "ok":
                content = [
                    {
                        "type": "image",
                        "data": res["image_base64"],
                        "mimeType": "image/png",
                    },
                    {
                        "type": "text",
                        "text": f"Captured desktop screenshot ({res['width']}x{res['height']} on {res['display']}).",
                    },
                ]
            else:
                content = [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}]
            return 200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": content,
                    "isError": res.get("status") in ("error", "command_failed", "timeout"),
                },
            }
        except Exception as exc:
            return 200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"status": "error", "detail": str(exc)})}],
                    "isError": True,
                },
            }

    return 200, {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length > 0 else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/health":
            disp = _detect_display()
            self._send_json(
                200,
                {
                    "status": "ok",
                    "agent_version": AGENT_VERSION,
                    "display": disp,
                    "cdp_ready": _probe_tcp("127.0.0.1", CDP_PROXY_PORT),
                    "xdotool_ready": bool(shutil.which("xdotool")),
                    "wmctrl_ready": bool(shutil.which("wmctrl")),
                    "chromium_ready": bool(_find_chromium_binary()),
                    "provision": _read_provision_status(),
                },
            )
            return

        if path == "/status":
            self._send_json(200, _inspect_status())
            return

        if path == "/screenshot":
            try:
                max_w = int((qs.get("max_width") or ["1280"])[0])
                png_bytes, width, height, disp = _capture_screenshot_png(max_width=max_w)
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(png_bytes)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Argo-Width", str(width))
                self.send_header("X-Argo-Height", str(height))
                self.send_header("X-Argo-Display", disp)
                self.end_headers()
                self.wfile.write(png_bytes)
            except Exception as exc:
                self._send_json(503, {"status": "error", "detail": str(exc)})
            return

        if path == "/mcp":
            self._send_json(
                200,
                {
                    "name": "argo-desktop-mcp",
                    "version": AGENT_VERSION,
                    "transport": "streamable-http",
                    "tools": [t["name"] for t in TOOLS_SPEC],
                },
                headers={"Mcp-Session-Id": SESSION_ID},
            )
            return

        self._send_json(404, {"status": "error", "detail": f"Unknown path: {path}"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/action":
            try:
                payload = self._read_json()
                action = str(payload.get("action") or "")
                params = dict(payload)
                params.pop("action", None)
                res = _perform_action(action, params)
                code = 200 if res.get("status") != "error" else 400
                self._send_json(code, res)
            except Exception as exc:
                self._send_json(500, {"status": "error", "detail": str(exc)})
            return

        if path == "/mcp":
            try:
                payload = self._read_json()
                status, resp = _handle_mcp_rpc(payload)
                if resp is None:
                    self.send_response(status)
                    self.send_header("Content-Length", "0")
                    self.send_header("Mcp-Session-Id", SESSION_ID)
                    self.end_headers()
                    return
                self._send_json(status, resp, headers={"Mcp-Session-Id": SESSION_ID})
            except Exception as exc:
                self._send_json(
                    400,
                    {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}},
                )
            return

        self._send_json(404, {"status": "error", "detail": f"Unknown path: {path}"})

    def do_DELETE(self) -> None:
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    server = _Server(("0.0.0.0", PORT), _Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
'''


def _encode_png_rgb_fallback(width: int, height: int, rgb: bytes) -> bytes:
    """Create a valid RGB PNG purely with stdlib for in-memory test simulations."""
    stride = width * 3
    scanlines = bytearray(height * (stride + 1))
    for y in range(height):
        src = y * stride
        dst = y * (stride + 1)
        scanlines[dst] = 0
        scanlines[dst + 1 : dst + 1 + stride] = rgb[src : src + stride]
    compressed = zlib.compress(bytes(scanlines), level=1)

    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(data, zlib.crc32(tag)) & 0xFFFFFFFF
        return struct.pack("!I", len(data)) + tag + data + struct.pack("!I", crc)

    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", compressed)
        + _chunk(b"IEND", b"")
    )


def make_placeholder_desktop_png(width: int = 320, height: int = 180) -> bytes:
    """Deterministic compact PNG representing an XFCE desktop frame in InMemoryDockerDriver mode."""
    row = bytes([28, 42, 66] * width)
    return _encode_png_rgb_fallback(width, height, row * height)


class DesktopMCPError(RuntimeError):
    """Raised when the per-bot Desktop MCP agent is unreachable or fails."""


class DesktopAgentTransport(Protocol):
    async def health(
        self, bot_slug: str, endpoint: str, *, timeout: float = 5.0
    ) -> dict[str, Any]: ...

    async def inspect(
        self, bot_slug: str, endpoint: str, *, timeout: float = 15.0
    ) -> dict[str, Any]: ...

    async def screenshot(
        self, bot_slug: str, endpoint: str, *, max_width: int = 1280, timeout: float = 20.0
    ) -> tuple[bytes, dict[str, Any]]: ...

    async def execute_action(
        self,
        bot_slug: str,
        endpoint: str,
        action: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float = 25.0,
    ) -> dict[str, Any]: ...

    async def call_mcp(
        self,
        bot_slug: str,
        endpoint: str,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float = 25.0,
    ) -> dict[str, Any]: ...


class _DefaultDesktopAgentTransport:
    async def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        timeout: float = 15.0,
    ) -> tuple[int, dict[str, str], bytes]:
        try:
            import aiohttp  # type: ignore[import-not-found]
        except ImportError:
            aiohttp = None  # type: ignore[assignment]

        if aiohttp is not None:
            client_timeout = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.request(method, url, json=json_body) as resp:
                    raw = await resp.read()
                    return resp.status, dict(resp.headers), raw

        def _sync_urllib() -> tuple[int, dict[str, str], bytes]:
            data: bytes | None = None
            headers: dict[str, str] = {}
            if json_body is not None:
                data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return int(resp.status), dict(resp.headers.items()), resp.read()
            except urllib.error.HTTPError as exc:
                raw_err = exc.read()
                return int(exc.code), dict(exc.headers.items()) if exc.headers else {}, raw_err

        return await asyncio.to_thread(_sync_urllib)

    async def health(
        self, bot_slug: str, endpoint: str, *, timeout: float = 5.0
    ) -> dict[str, Any]:
        del bot_slug
        url = f"{endpoint.rstrip('/')}/health"
        status, _, raw = await self._request("GET", url, timeout=timeout)
        data = json.loads(raw.decode("utf-8") or "{}")
        if status >= 400:
            raise DesktopMCPError(f"Desktop health returned HTTP {status}: {data}")
        return data

    async def inspect(
        self, bot_slug: str, endpoint: str, *, timeout: float = 15.0
    ) -> dict[str, Any]:
        del bot_slug
        url = f"{endpoint.rstrip('/')}/status"
        status, _, raw = await self._request("GET", url, timeout=timeout)
        data = json.loads(raw.decode("utf-8") or "{}")
        if status >= 400:
            raise DesktopMCPError(f"Desktop inspect returned HTTP {status}: {data}")
        return data

    async def screenshot(
        self, bot_slug: str, endpoint: str, *, max_width: int = 1280, timeout: float = 20.0
    ) -> tuple[bytes, dict[str, Any]]:
        del bot_slug
        url = f"{endpoint.rstrip('/')}/screenshot?max_width={int(max_width)}"
        status, headers, raw = await self._request("GET", url, timeout=timeout)
        if status >= 400:
            detail = raw.decode("utf-8", errors="ignore")
            raise DesktopMCPError(f"Desktop screenshot returned HTTP {status}: {detail}")
        lowered_headers = {k.lower(): v for k, v in headers.items()}
        meta = {
            "width": int(lowered_headers.get("x-argo-width", "0") or 0),
            "height": int(lowered_headers.get("x-argo-height", "0") or 0),
            "display": lowered_headers.get("x-argo-display", ":1"),
            "mime_type": lowered_headers.get("content-type", "image/png"),
        }
        return raw, meta

    async def execute_action(
        self,
        bot_slug: str,
        endpoint: str,
        action: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float = 25.0,
    ) -> dict[str, Any]:
        del bot_slug
        url = f"{endpoint.rstrip('/')}/action"
        payload = {"action": action, **(params or {})}
        req_timeout = (
            max(timeout, float(payload.get("timeout_seconds") or 60) + 10.0)
            if action in {"exec", "shell", "bash", "run_command"}
            else timeout
        )
        status, _, raw = await self._request("POST", url, json_body=payload, timeout=req_timeout)
        data = json.loads(raw.decode("utf-8") or "{}")
        if status >= 400 and data.get("status") != "error":
            raise DesktopMCPError(f"Desktop action '{action}' returned HTTP {status}: {data}")
        return data

    async def call_mcp(
        self,
        bot_slug: str,
        endpoint: str,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float = 25.0,
    ) -> dict[str, Any]:
        del bot_slug
        url = f"{endpoint.rstrip('/')}{DESKTOP_MCP_PATH}"
        rpc = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        status, _, raw = await self._request("POST", url, json_body=rpc, timeout=timeout)
        data = json.loads(raw.decode("utf-8") or "{}")
        if status >= 400:
            raise DesktopMCPError(f"Desktop MCP '{method}' returned HTTP {status}: {data}")
        return data


@dataclass(slots=True)
class _SimDesktopState:
    active_window: str = "Xfce Desktop"
    windows: list[dict[str, Any]] | None = None
    launched_apps: list[str] | None = None
    recording_active: bool = False
    recording_started_at: str = ""
    recorded_commands: list[dict[str, Any]] | None = None
    recorded_urls: list[dict[str, Any]] | None = None
    recorded_windows: list[dict[str, Any]] | None = None
    recorded_clicks: list[dict[str, Any]] | None = None
    recorded_dom_events: list[dict[str, Any]] | None = None
    recorded_typed_inputs: list[dict[str, Any]] | None = None
    last_exec_env: dict[str, str] | None = None


class DesktopMCPBridge:
    """Host-side bridge talking to the embedded per-container Desktop MCP daemon (:9223)."""

    def __init__(
        self,
        desktop_manager: DesktopManager,
        *,
        bus: EventBus | None = None,
        transport: DesktopAgentTransport | None = None,
        probe_interval_seconds: float = 1.0,
        ready_timeout_seconds: float = 35.0,
    ) -> None:
        self._desktop_manager = desktop_manager
        self._bus = bus
        self._transport = transport or _DefaultDesktopAgentTransport()
        self._using_default_transport = transport is None
        self._probe_interval_seconds = probe_interval_seconds
        self._ready_timeout_seconds = ready_timeout_seconds
        self._sim_states: dict[str, _SimDesktopState] = {}

    def endpoint_for(self, bot_slug: str) -> str:
        return f"http://{self._desktop_manager.container_name_for(bot_slug)}:{DESKTOP_MCP_PORT}"

    def mcp_url_for(self, bot_slug: str) -> str:
        return f"{self.endpoint_for(bot_slug)}{DESKTOP_MCP_PATH}"

    def build_mcp_server_config(self, bot_slug: str) -> dict[str, Any]:
        clean_slug = self._desktop_manager.container_name_for(bot_slug).removeprefix("argo-desktop-")
        return {
            "transport": "streamable_http",
            "url": self.mcp_url_for(clean_slug),
            "endpoint": self.endpoint_for(clean_slug),
            "port": DESKTOP_MCP_PORT,
            "path": DESKTOP_MCP_PATH,
        }

    @classmethod
    def create_pydantic_ai_mcp_toolset(
        cls, bot_slug: str, mcp_url: str | None = None
    ) -> Any:
        """Instantiate pydantic_ai.mcp.MCPToolset with FastMCP StreamableHttpTransport bound to argo-desktop-<slug>:9223/mcp."""
        from fastmcp.client.transports import StreamableHttpTransport  # type: ignore[import-not-found]
        from pydantic_ai.mcp import MCPToolset  # type: ignore[import-not-found]

        from argo_core.desktop.manager import validate_desktop_slug

        clean_slug = validate_desktop_slug(bot_slug)
        target_url = (
            mcp_url
            or f"http://argo-desktop-{clean_slug}:{DESKTOP_MCP_PORT}{DESKTOP_MCP_PATH}"
        )
        transport = StreamableHttpTransport(url=target_url)
        return MCPToolset(transport, id=f"desktop_mcp_{clean_slug}")

    def _use_in_memory_simulation(self) -> bool:
        return self._using_default_transport and self._desktop_manager.is_in_memory()

    async def _emit_progress(
        self, bot_slug: str, state: str, step: str, correlation_id: str | None = None
    ) -> None:
        if self._bus is None:
            return
        with contextlib.suppress(Exception):
            await self._bus.emit_progress(
                bot_slug,
                state,
                step=step,
                correlation_id=correlation_id or "",
            )

    async def _ensure_running(
        self, bot_slug: str, *, correlation_id: str | None = None
    ) -> tuple[str, str]:
        from argo_core.desktop.manager import validate_desktop_slug

        clean_slug = validate_desktop_slug(bot_slug)
        await self._desktop_manager.start_desktop(clean_slug, correlation_id=correlation_id)
        self._desktop_manager.touch_activity(clean_slug)
        endpoint = self.endpoint_for(clean_slug)
        return clean_slug, endpoint

    async def wait_until_ready(
        self,
        bot_slug: str,
        *,
        correlation_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        clean_slug, endpoint = await self._ensure_running(bot_slug, correlation_id=correlation_id)
        if self._use_in_memory_simulation():
            return {
                "status": "ok",
                "agent_version": DESKTOP_AGENT_VERSION,
                "display": ":1",
                "cdp_ready": True,
                "xdotool_ready": True,
                "wmctrl_ready": True,
                "chromium_ready": True,
                "provision": {"state": "ready", "detail": "ready"},
            }

        deadline = asyncio.get_running_loop().time() + (timeout_seconds or self._ready_timeout_seconds)
        last_exc: Exception | None = None
        last_notice = -10.0
        while True:
            try:
                health = await self._transport.health(clean_slug, endpoint, timeout=4.0)
                if health.get("status") == "ok":
                    return health
            except Exception as exc:
                last_exc = exc
            now = asyncio.get_running_loop().time()
            if now >= deadline:
                raise DesktopMCPError(
                    f"Desktop MCP agent :{DESKTOP_MCP_PORT} did not become ready at {endpoint}: {last_exc}"
                )
            if now - last_notice >= 3.0:
                last_notice = now
                await self._emit_progress(
                    clean_slug,
                    "working",
                    f"Waiting for Virtual Desktop MCP agent (:{DESKTOP_MCP_PORT})...",
                    correlation_id=correlation_id,
                )
            await asyncio.sleep(self._probe_interval_seconds)

    def _sim_state(self, clean_slug: str) -> _SimDesktopState:
        if clean_slug not in self._sim_states:
            self._sim_states[clean_slug] = _SimDesktopState(
                active_window="Xfce Desktop",
                windows=[
                    {"id": "0x0100001", "title": "Xfce Desktop", "wm_class": "xfdesktop", "pid": 120},
                ],
                launched_apps=[],
            )
        return self._sim_states[clean_slug]

    async def inspect_desktop(
        self,
        bot_slug: str,
        *,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        clean_slug, endpoint = await self._ensure_running(bot_slug, correlation_id=correlation_id)
        if self._use_in_memory_simulation():
            st = self._sim_state(clean_slug)
            return {
                "status": "ok",
                "agent_version": DESKTOP_AGENT_VERSION,
                "mcp_port": DESKTOP_MCP_PORT,
                "display": ":1",
                "screen": {"width": 1280, "height": 720},
                "provision": {"state": "ready", "detail": "ready"},
                "cdp_proxy_ready": True,
                "tools": {
                    "x11_ctypes": True,
                    "xdotool": True,
                    "wmctrl": True,
                    "chromium": True,
                    "firefox": False,
                },
                "active_window": st.active_window,
                "windows": list(st.windows or []),
                "window_count": len(st.windows or []),
                "processes": [
                    {"pid": 120, "comm": "xfdesktop", "args": "xfdesktop --display :1"},
                    *[{"pid": 500 + idx, "comm": app, "args": app} for idx, app in enumerate(st.launched_apps or [])],
                ],
            }
        await self.wait_until_ready(clean_slug, correlation_id=correlation_id)
        return await self._transport.inspect(clean_slug, endpoint)

    async def capture_screenshot(
        self,
        bot_slug: str,
        *,
        max_width: int = 1280,
        correlation_id: str | None = None,
        ready_timeout_seconds: float | None = None,
    ) -> tuple[bytes, dict[str, Any]]:
        clean_slug, endpoint = await self._ensure_running(bot_slug, correlation_id=correlation_id)
        if correlation_id:
            await self._emit_progress(
                clean_slug,
                "working",
                "Capturing Virtual Desktop screenshot...",
                correlation_id=correlation_id,
            )
        if self._use_in_memory_simulation():
            png_bytes = make_placeholder_desktop_png(320, 180)
            meta = {
                "width": 320,
                "height": 180,
                "display": ":1",
                "mime_type": "image/png",
                "screenshot_url": f"/api/desktops/{clean_slug}/screenshot",
            }
            self._desktop_manager.record_screenshot(clean_slug, png_bytes, meta)
            return png_bytes, meta

        await self.wait_until_ready(
            clean_slug,
            correlation_id=correlation_id,
            timeout_seconds=ready_timeout_seconds,
        )
        png_bytes, meta = await self._transport.screenshot(clean_slug, endpoint, max_width=max_width)
        meta["screenshot_url"] = f"/api/desktops/{clean_slug}/screenshot"
        self._desktop_manager.record_screenshot(clean_slug, png_bytes, meta)
        return png_bytes, meta

    async def execute_action(
        self,
        bot_slug: str,
        action: str,
        params: dict[str, Any] | None = None,
        *,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        payload = dict(params or {})
        act = (action or "").strip().lower()
        clean_slug, endpoint = await self._ensure_running(bot_slug, correlation_id=correlation_id)

        # SSRF guard if launching a URL
        if act == "launch" and payload.get("url"):
            try:
                raw_url = str(payload["url"]).strip()
                parsed = urlparse(raw_url)
                if not parsed.scheme:
                    raw_url = f"https://{raw_url}"
                cleaned_url, _ = validate_public_url(raw_url)
                payload["url"] = cleaned_url
            except SSRFBlockedError as exc:
                return {"status": "error", "action": act, "detail": f"URL blocked by SSRF policy: {exc}"}

        if act == "screenshot":
            png_bytes, meta = await self.capture_screenshot(
                clean_slug,
                max_width=int(payload.get("max_width", 1280) or 1280),
                correlation_id=correlation_id,
            )
            return {
                "status": "ok",
                "action": "screenshot",
                **meta,
                "byte_length": len(png_bytes),
            }

        if act == "inspect":
            return await self.inspect_desktop(clean_slug, correlation_id=correlation_id)

        if correlation_id:
            await self._emit_progress(
                clean_slug,
                "working",
                f"Running Virtual Desktop action: {act}",
                correlation_id=correlation_id,
            )

        if self._use_in_memory_simulation():
            st = self._sim_state(clean_slug)
            if act == "record_start":
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                st.recording_active = True
                st.recording_started_at = now_iso
                st.recorded_commands = []
                st.recorded_urls = []
                st.recorded_windows = []
                st.recorded_clicks = []
                st.recorded_dom_events = []
                st.recorded_typed_inputs = []
                return {"status": "ok", "recording": True, "started_at": now_iso, "elapsed_seconds": 0}
            if act == "record_status":
                return {
                    "status": "ok",
                    "recording": st.recording_active,
                    "started_at": st.recording_started_at,
                    "elapsed_seconds": 1 if st.recording_active else 0,
                    "command_count": len(st.recorded_commands or []),
                    "event_count": (
                        len(st.recorded_urls or [])
                        + len(st.recorded_windows or [])
                        + len(st.recorded_clicks or [])
                        + len(st.recorded_dom_events or [])
                        + len(st.recorded_typed_inputs or [])
                    ),
                }
            if act == "record_stop":
                st.recording_active = False
                return {
                    "status": "ok",
                    "recording": False,
                    "started_at": st.recording_started_at,
                    "duration_seconds": 1,
                    "commands": list(st.recorded_commands or []),
                    "visited_urls": list(st.recorded_urls or []),
                    "window_events": list(st.recorded_windows or []),
                    "clicks": list(st.recorded_clicks or []),
                    "dom_events": list(st.recorded_dom_events or []),
                    "typed_inputs": list(st.recorded_typed_inputs or []),
                }
            if act == "check_app":
                app = str(payload.get("app") or "").strip()
                running = app in (st.launched_apps or [])
                return {
                    "status": "ok",
                    "action": "check_app",
                    "app": app,
                    "installed": app.lower() in {"chromium", "firefox", "thunar", "xfce4-terminal", "mousepad"},
                    "executable": f"/usr/bin/{app}",
                    "running": running,
                    "windows": [w for w in (st.windows or []) if app.lower() in str(w.get("title", "")).lower()],
                }
            if act == "launch":
                app = str(payload.get("app") or "chromium").strip()
                url = str(payload.get("url") or "").strip()
                if app not in (st.launched_apps or []):
                    assert st.launched_apps is not None
                    st.launched_apps.append(app)
                title = f"{app} - {url}" if url else app
                assert st.windows is not None
                st.windows.append({"id": f"0x0{len(st.windows)+1}00001", "title": title, "wm_class": app, "pid": 600})
                st.active_window = title
                if st.recording_active and url:
                    if st.recorded_urls is None:
                        st.recorded_urls = []
                    st.recorded_urls.append({"ts": "", "url": url, "title": title})
                return {
                    "status": "ok",
                    "action": "launch",
                    "app": app,
                    "url": url or None,
                    "pid": 600,
                    "display": ":1",
                    "windows": list(st.windows),
                }
            if act == "focus_window":
                title = str(payload.get("title") or "").strip()
                st.active_window = title or st.active_window
                if st.recording_active and title:
                    if st.recorded_windows is None:
                        st.recorded_windows = []
                    st.recorded_windows.append({"ts": "", "window": title})
                return {"status": "ok", "action": "focus_window", "title": title, "active_window": st.active_window}
            if act == "click":
                if st.recording_active:
                    if st.recorded_clicks is None:
                        st.recorded_clicks = []
                    st.recorded_clicks.append({"ts": "", "x": payload.get("x", 0), "y": payload.get("y", 0), "window": st.active_window})
                return {"status": "ok", "action": "click", **payload}
            if act == "type":
                if st.recording_active and str(payload.get("text") or ""):
                    if st.recorded_typed_inputs is None:
                        st.recorded_typed_inputs = []
                    st.recorded_typed_inputs.append({"ts": "", "text": str(payload.get("text")), "window": st.active_window})
                return {"status": "ok", "action": "type", "length": len(str(payload.get("text") or ""))}
            if act == "key":
                keys = str(payload.get("keys") or payload.get("key") or "")
                if st.recording_active and keys:
                    if st.recorded_typed_inputs is None:
                        st.recorded_typed_inputs = []
                    st.recorded_typed_inputs.append({"ts": "", "text": f"[{keys}]", "key": keys, "window": st.active_window})
                return {"status": "ok", "action": "key", "keys": keys}
            if act in {"exec", "shell", "bash", "run_command"}:
                raw_cmds = payload.get("commands")
                cmds = (
                    [str(c).strip() for c in raw_cmds if str(c).strip()]
                    if isinstance(raw_cmds, list)
                    else ([str(payload.get("command")).strip()] if str(payload.get("command") or "").strip() else [])
                )
                if not cmds:
                    return {"status": "error", "action": "exec", "detail": "command or commands is required"}
                assert st.windows is not None
                if not any(w.get("title") == "Argo Shell" for w in st.windows):
                    st.windows.append({"id": f"0x0{len(st.windows)+1}00001", "title": "Argo Shell", "wm_class": "xfce4-terminal", "pid": 650})
                st.active_window = "Argo Shell"
                st.last_exec_env = (
                    {str(k): str(v) for k, v in payload.get("env", {}).items()}
                    if isinstance(payload.get("env"), dict)
                    else None
                )
                cont = bool(payload.get("continue_on_error", False))
                steps: list[dict[str, Any]] = []
                out_chunks: list[str] = []
                err_chunks: list[str] = []
                overall_status = "ok"
                final_exit = 0
                failed_cmd: str | None = None
                for cmd in cmds:
                    m_exit = re.search(r"\bexit\s+(\d+)", cmd)
                    code = int(m_exit.group(1)) if m_exit else (1 if cmd.strip() == "false" else 0)
                    if st.recording_active:
                        if st.recorded_commands is None:
                            st.recorded_commands = []
                        st.recorded_commands.append({"ts": "", "cwd": str(payload.get("cwd") or "/config"), "exit_code": code, "cmd": cmd})
                    if code == 0:
                        resolved_cmd = cmd
                        for ek, ev in (st.last_exec_env or {}).items():
                            resolved_cmd = resolved_cmd.replace(f"${ek}", ev).replace(f"${{{ek}}}", ev)
                        step_out = f"executed: {resolved_cmd}"
                        out_chunks.append(step_out)
                        steps.append({"command": cmd, "exit_code": 0, "status": "ok", "stdout": step_out, "stderr": ""})
                    else:
                        step_err = f"command exited with status {code}: {cmd}"
                        err_chunks.append(step_err)
                        steps.append({"command": cmd, "exit_code": code, "status": "command_failed", "stdout": "", "stderr": step_err})
                        overall_status = "command_failed"
                        final_exit = code
                        failed_cmd = cmd
                        if not cont:
                            break
                return {
                    "status": overall_status,
                    "action": "exec",
                    "cwd": str(payload.get("cwd") or "/config"),
                    "exit_code": final_exit,
                    "failed_command": failed_cmd,
                    "stdout": "\n".join(out_chunks),
                    "stderr": "\n".join(err_chunks),
                    "steps": steps,
                }
            return {"status": "ok", "action": act, **payload}

        await self.wait_until_ready(clean_slug, correlation_id=correlation_id)
        return await self._transport.execute_action(clean_slug, endpoint, act, payload)

    async def call_mcp_tool(
        self,
        bot_slug: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        clean_slug, endpoint = await self._ensure_running(bot_slug, correlation_id=correlation_id)
        if self._use_in_memory_simulation():
            action_name = tool_name[len("desktop_") :] if tool_name.startswith("desktop_") else tool_name
            res = await self.execute_action(clean_slug, action_name, arguments, correlation_id=correlation_id)
            return {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": json.dumps(res)}]}}
        await self.wait_until_ready(clean_slug, correlation_id=correlation_id)
        return await self._transport.call_mcp(
            clean_slug,
            endpoint,
            "tools/call",
            {"name": tool_name, "arguments": arguments or {}},
        )
