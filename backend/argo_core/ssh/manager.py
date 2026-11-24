"""Stateful in-process AsyncSSH PTY session manager, Valkey locking, and zero-exposure sudo."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import fcntl
import logging
import os
import pty
import re
import shlex
import shutil
import signal
import struct
import termios
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import asyncssh

from argo_core.bus.valkey_bus import MAX_HOP_COUNT, EventBus
from argo_core.config import ArgoSettings
from argo_core.db.repositories import ArgoRepository, NotFoundError, make_id, utc_now
from argo_core.security.vault import redact_secrets
from argo_core.ssh.host_guard import (
    SSHHostKeyMismatchError,
    SSHTargetBlockedError,
    resolve_authorized_ssh_target_with_ip,
    verify_or_pin_host_key,
)
from argo_core.ssh.recorder import SSHSessionRecorder, sweep_expired_ssh_recordings
from argo_core.ssh.vt_screen import VirtualTerminalScreen

logger = logging.getLogger(__name__)

_SUDO_PROMPT_RE = re.compile(
    r"(?:\[sudo\]\s*password(?:\s+for\s+[^:]+)?\s*:|password(?:\s+for\s+[^:]+)?\s*:)\s*$",
    re.IGNORECASE,
)

_INTERACTIVE_PROMPT_RE = re.compile(
    r"(?:"
    r"\[\s*(?:y/n|n/y|yes/no|y/n/a)\s*\]"
    r"|\(\s*(?:y/n|n/y|yes/no(?:/\[fingerprint\])?)\s*\)"
    r"|\[Y\]\s*Yes\b|\[A\]\s*Yes to All"
    r"|(?:are\s+you\s+sure|do\s+you\s+want\s+to|would\s+you\s+like\s+to|wish\s+to\s+continue|want\s+to\s+continue|proceed|overwrite|replace|confirm|continue|accept|delete|remove)[^\n]{0,80}[?:]\s*$"
    r"|(?:press\s+(?:enter|return|any\s+key)|hit\s+enter)[^\n]{0,40}$"
    r"|(?:passphrase|password|pin|otp|token|verification\s+code|your\s+choice|selection|enter\s+(?:a\s+|the\s+)?(?:choice|option|number|value|name|path|port|host|user|email|pass))[^\n]{0,60}:\s*$"
    r"|(?:^|\s)y/n\s*[?:]?\s*$"
    r")",
    re.IGNORECASE,
)

_SHELL_PROMPT_RE = re.compile(
    r"(?:^|\s)(?:PS\s+[A-Za-z]:\\[^>]*>|[A-Za-z]:\\[^>]*>|[^\s@]+@[^\s:]+:[^$#>\r\n]*[$#>]|\[[^\]]+\][$#>])\s*$"
)

_CATASTROPHIC_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?:^|[;&|]\s*)(?:sudo\s+)?rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive\s+--force|--force\s+--recursive|-r\s+-f|-f\s+-r)[^\n]*(?:\s+/(?:\s*$|[;&|]|\*)|\s+--no-preserve-root)",
            re.IGNORECASE,
        ),
        "Destructive root filesystem wipe ('rm -rf /') is hard-blocked.",
    ),
    (
        re.compile(
            r"(?:^|[;&|]\s*)(?:rd|rmdir)\s+[^\n]*(?:/s[^\n]*/q|/q[^\n]*/s)[^\n]*(?:[a-z]:\\(?:\s*$|[;&|\"'])|\s+\\(?:\s*$|[;&|]))",
            re.IGNORECASE,
        ),
        "Destructive Windows drive wipe ('rd /s /q') is hard-blocked.",
    ),
    (
        re.compile(r"(?:^|[;&|]\s*)format(?:\.com|\.exe)?\s+[a-z]:(?:\s*$|[;&|/])", re.IGNORECASE),
        "Windows disk formatting command ('format <drive>:') is hard-blocked.",
    ),
    (
        re.compile(
            r"(?:^|[;&|]\s*)(?:remove-item|ri)\b[^\n]*-recurse[^\n]*-force[^\n]*(?:[a-z]:\\[\"'\s;|&]*$|\\[\"'\s;|&]*$)",
            re.IGNORECASE,
        ),
        "Destructive PowerShell drive wipe ('Remove-Item -Recurse -Force') is hard-blocked.",
    ),
    (
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        "Fork bomb pattern is hard-blocked.",
    ),
    (
        re.compile(r"(?:^|[;&|]\s*)(?:sudo\s+)?mkfs(?:\.[a-z0-9_]+)?\b", re.IGNORECASE),
        "Filesystem formatting command ('mkfs') is hard-blocked.",
    ),
    (
        re.compile(
            r"(?:^|[;&|]\s*)(?:sudo\s+)?dd\b[^\n;]*\bof=/dev/(?:sd|vd|nvme|xvd|mmcblk|hd|loop)",
            re.IGNORECASE,
        ),
        "Raw block device write ('dd of=/dev/...') is hard-blocked.",
    ),
    (
        re.compile(
            r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:ba|z|da|k|a)?sh\b",
            re.IGNORECASE,
        ),
        "Remote script pipe-to-shell ('curl/wget | sh') is hard-blocked.",
    ),
    (
        re.compile(
            r"\b(?:irm|iwr|invoke-webrequest|invoke-restmethod)\b[^|\n]*\|\s*(?:iex|invoke-expression)\b",
            re.IGNORECASE,
        ),
        "Remote script pipe-to-shell ('irm/iwr | iex') is hard-blocked.",
    ),
    (
        re.compile(
            r"(?:/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^\n;]*\s-[ec]\s|\bbash\s+-i\s+>&)",
            re.IGNORECASE,
        ),
        "Reverse shell / raw socket execution pattern is hard-blocked.",
    ),
    (
        re.compile(
            r"(?:>>?|\btee\b|\bsed\s+-i\b|\bchmod\b|\bchown\b|\bcp\b|\bmv\b|\bln\s+-s\b)[^\n]*(?:~/?\.ssh/authorized_keys|/root/\.ssh/authorized_keys|/home/[^/\s]+/\.ssh/authorized_keys|/etc/sudoers(?:\.d)?|/etc/shadow)",
            re.IGNORECASE,
        ),
        "Unauthorized modification of SSH keys, sudoers, or /etc/shadow is hard-blocked.",
    ),
)

_READONLY_BASE_COMMANDS = frozenset(
    {
        "whoami",
        "id",
        "uname",
        "uptime",
        "hostname",
        "pwd",
        "date",
        "ls",
        "ll",
        "stat",
        "file",
        "df",
        "du",
        "free",
        "vmstat",
        "iostat",
        "lscpu",
        "lsblk",
        "ps",
        "pgrep",
        "top",
        "cat",
        "head",
        "tail",
        "wc",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "awk",
        "sed",
        "sort",
        "uniq",
        "cut",
        "tr",
        "find",
        "systemctl",
        "journalctl",
        "ss",
        "netstat",
        "ip",
        "ping",
        "dig",
        "nslookup",
        "host",
        "traceroute",
        "docker",
        "podman",
        "git",
        "env",
        "printenv",
        "which",
        "command",
        "echo",
        "printf",
        "dmesg",
        "last",
        "lastlog",
        "who",
        "w",
        "hostnamectl",
        "timedatectl",
        "lsb_release",
        "arch",
        "nproc",
        "lsmod",
        "findmnt",
        "sar",
        "mpstat",
        "lslogins",
        "modinfo",
        "true",
        "false",
        "test",
    }
)


def check_catastrophic_ssh_command(command: str) -> str | None:
    """Return a block reason if command matches catastrophic/exfil patterns across all RBAC tiers."""
    text = str(command or "").strip()
    if not text:
        return None
    for pattern, reason in _CATASTROPHIC_PATTERNS:
        if pattern.search(text):
            return reason
    return None


def _strip_quoted_literals(command: str) -> str:
    """Replace single/double quoted literals with empty placeholders for command-verb inspection."""
    out: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for ch in command:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(" ")
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(" ")
            continue
        if not in_single and not in_double:
            out.append(ch)
    return "".join(out)


def _strip_single_quoted_only(command: str) -> tuple[str, bool, bool]:
    """Mask only single-quoted literals while keeping double-quoted expansions visible and checking quote/escape balance."""
    out: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    unsafe_unquoted_escape = False
    raw = str(command or "")
    n = len(raw)
    i = 0
    while i < n:
        ch = raw[i]
        if escaped:
            if in_double:
                out.append(" ")
            escaped = False
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(" ")
            i += 1
            continue
        if in_single:
            out.append(" ")
            i += 1
            continue
        if ch == "\\":
            nxt = raw[i + 1] if i + 1 < n else ""
            if in_double:
                if nxt in {'"', "\\", "$", "`"}:
                    escaped = True
                    out.append(" ")
                    i += 1
                    continue
            else:
                if nxt in {'"', "'", ";", "&", "|", "$", "`", "<", ">", "(", ")", "{", "}", " ", "\t"} or nxt == "":
                    unsafe_unquoted_escape = True
                out.append(ch)
                i += 1
                continue
        if ch == '"':
            in_double = not in_double
            out.append('"')
            i += 1
            continue
        out.append(ch)
        i += 1
    balanced = (not in_single) and (not in_double)
    return "".join(out), balanced, unsafe_unquoted_escape


def _has_unsafe_shell_syntax(command: str, *, allow_pipes_and_chains: bool = True) -> bool:
    """Return True if command contains shell expansions, unsafe unquoted escapes, unbalanced quotes, or output redirects."""
    masked, balanced, unsafe_escape = _strip_single_quoted_only(command)
    if not balanced or unsafe_escape:
        return True
    cleaned = _STDERR_REDIRECT_RE.sub(" ", masked)
    if any(tok in cleaned for tok in (">", ">>", "$(", "`", "${", "<(", ">(")):
        return True
    if not allow_pipes_and_chains:
        unquoted = _strip_quoted_literals(command)
        if any(tok in unquoted for tok in (";", "|", "&", "<")):
            return True
    return False


def _command_invokes_sudo(command: str) -> bool:
    """Return True strictly when sudo is invoked as an actual shell command token."""
    raw = str(command or "")
    unquoted = _strip_quoted_literals(raw)
    if re.search(r"(?:^|[;&|]\s*|(?:&&|\|\|)\s*)sudo(?:\s|$)", unquoted):
        return True
    for seg in _split_command_segments(raw):
        toks = _tokenize_command_segment(_STDERR_REDIRECT_RE.sub(" ", seg).strip())
        if toks and Path(toks[0].replace("\\", "/")).name.lower() == "sudo":
            return True
    masked, _, _ = _strip_single_quoted_only(raw)
    return bool(re.search(r"(?:\$\(|`)\s*sudo(?:\s|$)", masked))


_STDERR_REDIRECT_RE = re.compile(
    r"(?<![^\s;&|(])2>\s*(?:/dev/null|\$null)(?=$|\s|[;&|)])|(?<![^\s;&|(])2>&1(?=$|\s|[;&|)])",
    re.IGNORECASE,
)

_WINDOWS_DRIVE_OR_UNC_RE = re.compile(r"(?:^|\s|['\"])(?:[A-Za-z]:\\|\\\\)")
_POWERSHELL_VERB_NOUN_RE = re.compile(r"^[A-Za-z]+-[A-Za-z]+$")
_SUBCOMMAND_OR_FLAG_TOKEN_RE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9_-]{0,23}|-[A-Za-z0-9]{1,20}|/[A-Za-z0-9_-]{1,16})$"
)

# Shell interpreters, privilege wrappers, and destructive verbs that must NEVER be trusted as a prefix head.
_FORBIDDEN_TRUST_HEAD_VERBS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ash",
        "ksh",
        "csh",
        "fish",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "sudo",
        "su",
        "doas",
        "eval",
        "exec",
        "iex",
        "invoke-expression",
        "rm",
        "del",
        "erase",
        "rd",
        "rmdir",
        "format",
        "format.com",
        "format.exe",
        "dd",
        "mkfs",
        "remove-item",
        "ri",
    }
)

# Verbs/tools that must never be trusted as a bare 1-token wildcard prefix (require a specific subcommand/arg).
_NON_TRUSTABLE_SINGLETON_VERBS = frozenset(
    {
        "env",
        "command",
        "xargs",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "awk",
        "sed",
        "ssh",
        "scp",
        "sftp",
        "curl",
        "wget",
        "nc",
        "ncat",
        "chmod",
        "chown",
        "mv",
        "cp",
        "tee",
        "kill",
        "killall",
        "pkill",
        "shutdown",
        "reboot",
        "poweroff",
        "halt",
        "init",
        "irm",
        "iwr",
        "invoke-webrequest",
        "invoke-restmethod",
        "set-content",
        "add-content",
        "out-file",
        "sc",
        "wmic",
        "wevtutil",
        "net",
        "reg",
        "diskpart",
        "bcdedit",
        "schtasks",
    }
)


def _split_command_segments(command: str) -> list[str]:
    """Split a shell line into command segments on unquoted &&, ||, ;, |, or & (preserving 2>&1)."""
    raw = str(command or "")
    segments: list[str] = []
    cur: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if escaped:
            cur.append(ch)
            escaped = False
            i += 1
            continue
        if ch == "\\" and not in_single:
            nxt = raw[i + 1] if i + 1 < n else ""
            if in_double and nxt in {'"', "\\", "$", "`"}:
                cur.append(ch)
                escaped = True
                i += 1
                continue
            if not in_double and nxt in {'"', "'", ";", "&", "|", "$", "`", "<", ">", "(", ")", " ", "\t"}:
                cur.append(ch)
                escaped = True
                i += 1
                continue
        if ch == "'" and not in_double:
            in_single = not in_single
            cur.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            cur.append(ch)
            i += 1
            continue
        if not in_single and not in_double:
            if ch in (";", "|"):
                if ch == "|" and i + 1 < n and raw[i + 1] == "|":
                    i += 2
                else:
                    i += 1
                segments.append("".join(cur))
                cur = []
                continue
            if ch == "&":
                # Keep `2>&1` intact inside its segment so _STDERR_REDIRECT_RE strips it safely
                if i >= 2 and raw[i - 2 : i + 2] == "2>&1" and (
                    i + 2 >= n or raw[i + 2].isspace() or raw[i + 2] in ";|&)"
                ):
                    cur.append(ch)
                    i += 1
                    continue
                segments.append("".join(cur))
                cur = []
                i += 2 if (i + 1 < n and raw[i + 1] == "&") else 1
                continue
        cur.append(ch)
        i += 1
    if cur:
        segments.append("".join(cur))
    return segments


def _tokenize_command_segment(seg: str) -> list[str] | None:
    """Tokenize a single shell segment safely across POSIX and Windows path syntax."""
    clean = str(seg or "").strip()
    if not clean:
        return []
    use_non_posix = bool(_WINDOWS_DRIVE_OR_UNC_RE.search(clean))
    if not use_non_posix:
        try:
            return shlex.split(clean, posix=True)
        except ValueError:
            pass
    try:
        raw_tokens = shlex.split(clean, posix=False)
    except ValueError:
        return None
    cleaned: list[str] = []
    for tok in raw_tokens:
        if len(tok) >= 2 and (
            (tok[0] == '"' and tok[-1] == '"') or (tok[0] == "'" and tok[-1] == "'")
        ):
            cleaned.append(tok[1:-1])
        else:
            cleaned.append(tok)
    return cleaned


_SED_UNSAFE_SCRIPT_RE = re.compile(
    r"(?:^|[;\d,$!])\s*[eEwW](?:\s|$|/)"
    r"|\bs([^\s\w])(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[a-zA-Z0-9]*[eEwW]",
)
_SENSITIVE_READ_PATHS = ("/etc/shadow", "id_rsa", "id_ed25519", ".ssh/id_", ".argo_master_key", "/srv/argo")
_SENSITIVE_READ_RE = re.compile(
    r"(?:/proc/(?:\d+|self)/environ\b|(?:^|[/\s\"'])\.env(?:\b|[./_\"'\s]|$))"
)


def _check_segment_readonly(seg: str) -> bool:
    seg_clean = _STDERR_REDIRECT_RE.sub(" ", seg).strip()
    if not seg_clean:
        return True
    tokens = _tokenize_command_segment(seg_clean)
    if tokens is None:
        return False
    if not tokens:
        return True
    cmd_name = Path(tokens[0].replace("\\", "/")).name.lower()
    if cmd_name not in _READONLY_BASE_COMMANDS:
        return False
    joined_lower = " ".join(tokens).lower()
    if cmd_name in {"cat", "head", "tail", "grep", "egrep", "fgrep", "rg"} and (
        any(s in joined_lower for s in _SENSITIVE_READ_PATHS)
        or _SENSITIVE_READ_RE.search(joined_lower)
    ):
        return False
    if cmd_name == "env":
        return len(tokens) == 1
    if cmd_name == "command":
        has_lookup_flag = any(t in {"-v", "-V"} for t in tokens[1:])
        has_other_flag = any(t.startswith("-") and t not in {"-v", "-V"} for t in tokens[1:])
        return has_lookup_flag and not has_other_flag and len(tokens) >= 3
    if cmd_name == "rg":
        for t in tokens[1:]:
            tl = t.lower()
            if tl in {"--pre", "--pre-glob"} or tl.startswith(("--pre=", "--pre-glob=")):
                return False
    if cmd_name == "sort":
        for t in tokens[1:]:
            tl = t.lower()
            if (
                tl == "-o"
                or (t.startswith("-o") and len(t) > 2)
                or tl in {"--output", "--compress-program"}
                or tl.startswith(("--output=", "--compress-program="))
            ):
                return False
    if cmd_name == "printf":
        for t in tokens[1:]:
            if t == "-v" or (t.startswith("-") and not t.startswith("--") and "v" in t[1:]):
                return False
    if cmd_name == "awk":
        for t in tokens[1:]:
            tl = t.lower()
            if (
                "system(" in tl
                or "getline" in tl
                or ">" in t
                or "|" in t
                or "/dev/" in tl
                or tl in {"-i", "--inplace"}
                or tl.startswith(("-i", "--inplace="))
            ):
                return False
    if cmd_name == "sed":
        for t in tokens[1:]:
            tl = t.lower()
            if (
                tl == "-i"
                or t.startswith("-i")
                or tl == "--in-place"
                or tl.startswith("--in-place=")
                or tl in {"-f", "--file"}
                or tl.startswith("--file=")
                or (t.startswith("-") and not t.startswith("--") and ("i" in t[1:] or "f" in t[1:]))
            ):
                return False
            if not t.startswith("-") and _SED_UNSAFE_SCRIPT_RE.search(t):
                return False
            if tl.startswith(("-e", "--expression=")):
                expr_val = t.split("=", 1)[1] if tl.startswith("--expression=") else t[2:]
                if expr_val and _SED_UNSAFE_SCRIPT_RE.search(expr_val):
                    return False
    if cmd_name == "tail" and any(t in {"-f", "-F", "--follow"} for t in tokens[1:]):
        return False
    if cmd_name == "find" and any(
        t in {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
        for t in tokens[1:]
    ):
        return False
    if cmd_name == "systemctl":
        sub = next((t.lower() for t in tokens[1:] if not t.startswith("-")), "")
        if not (
            (not sub and any(t == "--failed" for t in tokens[1:]))
            or sub
            in {
                "status",
                "is-active",
                "is-enabled",
                "is-failed",
                "is-system-running",
                "list-units",
                "list-unit-files",
                "list-timers",
                "show",
                "cat",
            }
        ):
            return False
    if cmd_name == "journalctl":
        for t in tokens[1:]:
            tl = t.lower()
            if tl in {
                "-f",
                "--follow",
                "--flush",
                "--rotate",
                "--sync",
                "--relinquish-var",
                "--update-catalog",
                "--setup-keys",
            } or tl.startswith("--vacuum-"):
                return False
            if t.startswith("-") and not t.startswith("--") and "f" in t[1:]:
                return False
    if cmd_name == "dmesg":
        for t in tokens[1:]:
            if t in {
                "-c",
                "--read-clear",
                "-C",
                "--clear",
                "-D",
                "--console-off",
                "-E",
                "--console-on",
                "-n",
                "--console-level",
                "-w",
                "--follow",
            }:
                return False
    if cmd_name in {"hostnamectl", "timedatectl"}:
        sub = next((t.lower() for t in tokens[1:] if not t.startswith("-")), "")
        if sub not in {"", "status"}:
            return False
    if cmd_name == "ip":
        for t in tokens[1:]:
            tl = t.lower()
            if tl in {"-b", "-batch", "--batch", "-force", "--force"} or tl.startswith(
                ("-batch=", "--batch=")
            ):
                return False
        pos = [t.lower() for t in tokens[1:] if not t.startswith("-")]
        obj = pos[0] if pos else ""
        act = pos[1] if len(pos) > 1 else ""
        if obj not in {"addr", "a", "address", "route", "r", "link", "l", "neigh", "n"}:
            return False
        if act not in {"", "show", "list", "ls", "get"}:
            return False
    if cmd_name in {"docker", "podman"}:
        sub = next((t.lower() for t in tokens[1:] if not t.startswith("-")), "")
        if sub not in {"ps", "images", "logs", "inspect", "stats", "info", "version"}:
            return False
    if cmd_name == "git":
        for t in tokens[1:]:
            tl = t.lower()
            if (
                t == "-c"
                or t.startswith("-c")
                or tl.startswith(("--config-env", "--git-dir", "--work-tree", "--exec-path", "--output", "--ext-diff", "--upload-pack"))
                or tl in {"--output", "--ext-diff"}
            ):
                return False
        pos = [t.lower() for t in tokens[1:] if not t.startswith("-")]
        sub = pos[0] if pos else ""
        if sub not in {"status", "log", "diff", "branch", "show", "rev-parse"}:
            return False
        if sub == "branch":
            unsafe_branch_flags = {
                "-d", "-D", "-m", "-M", "-c", "-C", "-f", "--delete", "--move", "--copy", "--force",
                "--set-upstream-to", "--unset-upstream", "--edit-description",
            }
            if any(
                t in unsafe_branch_flags
                or t.startswith(("--delete=", "--move=", "--copy=", "--set-upstream-to=", "-D", "-d", "-m", "-M"))
                for t in tokens[1:]
                if t.startswith("-")
            ):
                return False
            positional_filter_flags = {"--list", "--contains", "--no-contains", "--merged", "--no-merged"}
            has_positional_filter = any(
                t in positional_filter_flags
                or t.startswith(("--list=", "--contains=", "--no-contains=", "--merged=", "--no-merged="))
                for t in tokens[1:]
            )
            if len(pos) > 1 and not has_positional_filter:
                return False
    return True


def is_readonly_ssh_command(command: str) -> bool:
    """Allowlist check for strictly non-mutating diagnostic shell commands."""
    raw = str(command or "").strip()
    if not raw or "\n" in raw or "\r" in raw:
        return False
    if _has_unsafe_shell_syntax(raw):
        return False

    segments = _split_command_segments(raw)
    if not any(_STDERR_REDIRECT_RE.sub(" ", s).strip() for s in segments):
        return False
    return all(_check_segment_readonly(seg) for seg in segments)


def normalize_and_validate_trust_prefix(prefix: str) -> str | None:
    """Validate and normalize a human-approved Vault command prefix (cross-OS, zero shell escapes)."""
    clean = str(prefix or "").strip()
    if not clean or "\n" in clean or "\r" in clean or len(clean) > 160:
        return None
    if check_catastrophic_ssh_command(clean) is not None:
        return None
    if _has_unsafe_shell_syntax(clean, allow_pipes_and_chains=False):
        return None
    tokens = _tokenize_command_segment(clean)
    if not tokens or len(tokens) > 6:
        return None
    cmd0 = Path(tokens[0].replace("\\", "/")).name.lower()
    if not cmd0:
        return None
    if cmd0 in _FORBIDDEN_TRUST_HEAD_VERBS or cmd0.startswith("mkfs"):
        return None
    if len(tokens) == 1 and cmd0 in _NON_TRUSTABLE_SINGLETON_VERBS:
        return None
    return " ".join(tokens)


def extract_suggested_trust_prefixes(command: str) -> list[str]:
    """Derive safe token prefixes from non-readonly segments for 'Always Allow' proposals."""
    raw = str(command or "").strip()
    if not raw or "\n" in raw or "\r" in raw:
        return []
    if _has_unsafe_shell_syntax(raw):
        return []

    out: list[str] = []
    seen_lower: set[str] = set()
    for seg in _split_command_segments(raw):
        seg_clean = _STDERR_REDIRECT_RE.sub(" ", seg).strip()
        if not seg_clean or _check_segment_readonly(seg_clean):
            continue
        tokens = _tokenize_command_segment(seg_clean)
        if not tokens:
            continue
        t0 = tokens[0]
        if len(tokens) >= 2 and not _POWERSHELL_VERB_NOUN_RE.match(t0) and _SUBCOMMAND_OR_FLAG_TOKEN_RE.match(tokens[1]):
            candidate = f"{t0} {tokens[1]}"
        else:
            candidate = t0
        normalized = normalize_and_validate_trust_prefix(candidate)
        if normalized and normalized.lower() not in seen_lower:
            seen_lower.add(normalized.lower())
            out.append(normalized)
    return out


def is_command_trusted_for_vault(
    command: str,
    trusted_prefixes: list[str] | tuple[str, ...] | None,
) -> bool:
    """Deterministically check whether every segment is POSIX-readonly or matches a Vault-trusted prefix."""
    raw = str(command or "").strip()
    if not raw or "\n" in raw or "\r" in raw:
        return False
    if check_catastrophic_ssh_command(raw) is not None:
        return False
    if _has_unsafe_shell_syntax(raw):
        return False

    parsed_prefixes: list[list[str]] = []
    for raw_p in trusted_prefixes or ():
        norm = normalize_and_validate_trust_prefix(str(raw_p))
        if not norm:
            continue
        ptoks = _tokenize_command_segment(norm)
        if ptoks:
            parsed_prefixes.append([t.lower() for t in ptoks])
    if not parsed_prefixes:
        return False

    segments = _split_command_segments(raw)
    non_empty = [_STDERR_REDIRECT_RE.sub(" ", s).strip() for s in segments]
    non_empty = [s for s in non_empty if s]
    if not non_empty:
        return False

    for seg_clean in non_empty:
        if _check_segment_readonly(seg_clean):
            continue
        seg_tokens_raw = _tokenize_command_segment(seg_clean)
        if not seg_tokens_raw:
            return False
        seg_tokens = [t.lower() for t in seg_tokens_raw]
        matched = False
        for p_tokens in parsed_prefixes:
            plen = len(p_tokens)
            if len(seg_tokens) >= plen and seg_tokens[:plen] == p_tokens:
                matched = True
                break
        if not matched:
            return False
    return True


def format_ssh_terminal_summary(
    ssh_result: dict[str, Any],
    *,
    paused_note: str | None = None,
) -> str:
    """Format an SSH execution result into readable Markdown with bounded output."""
    host = str(ssh_result.get("host") or "target host").strip()
    cmd = str(ssh_result.get("command") or "").strip()
    status = str(ssh_result.get("status") or "completed").strip()
    exit_code = ssh_result.get("exit_code")
    header = (
        f"Ran `{cmd}` on `{host}`"
        if cmd
        else f"SSH command completed on `{host}`"
    )
    meta_parts: list[str] = [f"status: {status}"]
    if exit_code is not None:
        meta_parts.append(f"exit_code: {exit_code}")
    lines = [f"{header} ({', '.join(meta_parts)})."]
    if paused_note:
        lines.append("")
        lines.append(paused_note)
    screen = str(ssh_result.get("screen_text") or "").strip()
    if screen:
        clipped = screen[-6000:]
        lines.append("")
        lines.append(f"```text\n{clipped}\n```")
    elif ssh_result.get("detail"):
        lines.append("")
        lines.append(str(ssh_result["detail"]))
    return "\n".join(lines)


class SSHProcessChannel(Protocol):
    """Abstract interactive PTY channel protocol."""

    def write(self, data: bytes) -> None: ...
    def resize(self, cols: int, rows: int) -> None: ...
    def read(self, max_bytes: int = 4096) -> Awaitable[bytes]: ...
    def close(self) -> Awaitable[None]: ...


class SSHConnectionHandle(Protocol):
    """Abstract authenticated SSH connection handle."""

    @property
    def peer_host_key(self) -> tuple[str, str]: ...
    def open_shell(self, cols: int = 120, rows: int = 36) -> Awaitable[SSHProcessChannel]: ...
    def close(self) -> Awaitable[None]: ...


class SSHTransport(Protocol):
    """Pluggable SSH transport interface (AsyncSSH production + deterministic test doubles)."""

    def connect(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str | None = None,
        private_key: str | None = None,
        passphrase: str | None = None,
        timeout_seconds: float = 15.0,
        host_key_verifier: Callable[[str, str], None] | None = None,
    ) -> Awaitable[SSHConnectionHandle]: ...


class _AsyncSSHProcessAdapter:
    def __init__(self, proc: asyncssh.SSHClientProcess[bytes]) -> None:
        self._proc = proc

    def write(self, data: bytes) -> None:
        self._proc.stdin.write(data)

    def resize(self, cols: int, rows: int) -> None:
        with contextlib.suppress(Exception):
            self._proc.change_terminal_size(cols, rows)

    async def read(self, max_bytes: int = 4096) -> bytes:
        chunk = await self._proc.stdout.read(max_bytes)
        if isinstance(chunk, str):
            return chunk.encode("utf-8", errors="replace")
        return bytes(chunk or b"")

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            self._proc.terminate()
            self._proc.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._proc.wait_closed(), timeout=2.0)


class _AsyncSSHConnectionAdapter:
    def __init__(self, conn: asyncssh.SSHClientConnection, peer_host_key: tuple[str, str]) -> None:
        self._conn = conn
        self._peer_host_key = peer_host_key

    @property
    def peer_host_key(self) -> tuple[str, str]:
        return self._peer_host_key

    async def open_shell(self, cols: int = 120, rows: int = 36) -> SSHProcessChannel:
        proc = await self._conn.create_process(
            term_type="xterm-256color",
            term_size=(cols, rows),
            encoding=None,
            stderr=asyncssh.STDOUT,
        )
        return _AsyncSSHProcessAdapter(proc)

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            self._conn.close()
            await asyncio.wait_for(self._conn.wait_closed(), timeout=2.0)


class AsyncSSHTransport:
    """Production in-process AsyncSSH transport enforcing pre-auth host-key verification."""

    async def connect(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str | None = None,
        private_key: str | None = None,
        passphrase: str | None = None,
        timeout_seconds: float = 15.0,
        host_key_verifier: Callable[[str, str], None] | None = None,
    ) -> SSHConnectionHandle:
        captured_key: list[tuple[str, str]] = []
        captured_error: list[Exception] = []

        class _PinningSSHClient(asyncssh.SSHClient):
            def validate_host_public_key(
                self,
                _host: str,
                _addr: str,
                _port: int,
                key: asyncssh.SSHKey,
            ) -> bool:
                alg = str(key.get_algorithm() or "ssh-unknown")
                pub_b64 = base64.b64encode(key.encode_ssh_public()).decode("ascii")
                captured_key.append((alg, pub_b64))
                if host_key_verifier is not None:
                    try:
                        host_key_verifier(alg, pub_b64)
                    except Exception as exc:
                        captured_error.append(exc)
                        return False
                return True

        client_keys: list[asyncssh.SSHKey] = []
        if private_key and private_key.strip():
            client_keys.append(
                asyncssh.import_private_key(
                    private_key.strip(),
                    passphrase=passphrase or None,
                )
            )

        try:
            conn = await asyncssh.connect(
                host,
                port=int(port),
                username=username,
                password=password if password else None,
                client_keys=client_keys or (),
                known_hosts=None,
                client_factory=_PinningSSHClient,
                connect_timeout=timeout_seconds,
            )
        except Exception as exc:
            if captured_error:
                raise captured_error[0] from exc
            raise
        if captured_error:
            conn.close()
            raise captured_error[0]
        return _AsyncSSHConnectionAdapter(
            conn,
            captured_key[-1] if captured_key else ("ssh-unknown", ""),
        )


class _InMemoryProcessChannel:
    """Deterministic simulated PTY channel for unit and integration testing."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        server_spec: dict[str, Any],
    ) -> None:
        self.host = host
        self.port = port
        self.spec = server_spec
        self._out_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.received_writes: list[bytes] = []
        self.sizes: list[tuple[int, int]] = []
        self._closed = False
        self._mode = "shell"  # shell | awaiting_yn | awaiting_sudo | operator_shell
        self._pending_cmd = ""
        self._line_buf = ""

    def push_output(self, data: bytes | str) -> None:
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        self._out_queue.put_nowait(raw)

    def write(self, data: bytes) -> None:
        if self._closed:
            return
        self.received_writes.append(data)
        text = data.decode("utf-8", errors="replace")

        if "\x03" in text:
            self._mode = "shell"
            self._line_buf = ""
            self.push_output(b"^C\r\n\x1b]133;D;130\x07")
            return

        if self._mode == "awaiting_yn":
            self._line_buf += text
            if "\n" in self._line_buf or "\r" in self._line_buf:
                reply = self._line_buf.strip()
                self._line_buf = ""
                self._mode = "shell"
                if reply.lower().startswith("y"):
                    self.push_output(
                        b"Unpacking packages...\r\n"
                        b"\x1b[?1049hALT_SCREEN_DIALOG\x1b[?1049l"
                        b"Upgrade completed cleanly.\r\n\x1b]133;D;0\x07"
                    )
                else:
                    self.push_output(b"Aborted by user.\r\n\x1b]133;D;1\x07")
            return

        if self._mode == "awaiting_sudo":
            self._line_buf += text
            if "\n" in self._line_buf or "\r" in self._line_buf:
                pw = self._line_buf.strip("\r\n")
                self._line_buf = ""
                self._mode = "shell"
                expected_sudo = str(self.spec.get("sudo_password") or "")
                if expected_sudo and pw == expected_sudo:
                    out = str(self.spec.get("sudo_success_output") or "sudo command succeeded\r\n")
                    self.push_output(out.encode("utf-8") + b"\x1b]133;D;0\x07")
                else:
                    self.push_output(b"Sorry, try again.\r\n\x1b]133;D;1\x07")
            return

        self._line_buf += text
        while "\n" in self._line_buf or "\r" in self._line_buf:
            sep_idx = min(
                [i for i in (self._line_buf.find("\n"), self._line_buf.find("\r")) if i >= 0]
            )
            line = self._line_buf[:sep_idx]
            self._line_buf = self._line_buf[sep_idx + 1 :]
            self._execute_line(line)

    def _execute_line(self, cmd: str) -> None:
        stripped = cmd.strip()
        if not stripped:
            return
        if (
            ("PROMPT_COMMAND=" in stripped and "133;D" in stripped)
            or ("function global:prompt" in stripped and "133;D" in stripped)
            or (stripped.startswith("prompt ") and "133;D" in stripped)
        ):
            self.push_output(b"__bootstrap__\r\n\x1b]133;D;0\x07")
            return

        custom_handler = self.spec.get("handler")
        if callable(custom_handler):
            res = custom_handler(stripped, self)
            if isinstance(res, (bytes, str)):
                self.push_output(res)
            return

        if "apt upgrade" in stripped or "interactive-yn" in stripped:
            self._mode = "awaiting_yn"
            self._pending_cmd = stripped
            self.push_output(
                b"Reading package lists... 10%\r\x1b[KReading package lists... 100%\r\n"
                b"Do you want to continue? [Y/n]: "
            )
            return

        if stripped.startswith("sudo ") or " sudo " in stripped:
            self._mode = "awaiting_sudo"
            self._pending_cmd = stripped
            user = str(self.spec.get("username") or "root")
            self.push_output(f"[sudo] password for {user}: ".encode("utf-8"))
            return

        if "spoof-password" in stripped or stripped.startswith("echo Password:"):
            self.push_output(b"Password: ")
            return

        if stripped.startswith("echo "):
            payload = stripped[5:].strip().strip("'\"")
            self.push_output(f"{payload}\r\n\x1b]133;D;0\x07".encode("utf-8"))
            return

        if stripped == "uname -a":
            self.push_output(
                f"Linux {self.host} 6.12.0-fedora45 x86_64 GNU/Linux\r\n\x1b]133;D;0\x07".encode("utf-8")
            )
            return

        if stripped == "whoami":
            user = str(self.spec.get("username") or "ops")
            self.push_output(f"{user}\r\n\x1b]133;D;0\x07".encode("utf-8"))
            return

        if "takeover-check" in stripped:
            self.push_output(b"TAKEOVER_HANDLED_OK\r\n\x1b]133;D;0\x07")
            return

        self.push_output(f"ran:{stripped}@{self.host}\r\n\x1b]133;D;0\x07".encode("utf-8"))

    def resize(self, cols: int, rows: int) -> None:
        self.sizes.append((cols, rows))

    async def read(self, max_bytes: int = 4096) -> bytes:
        del max_bytes
        if self._closed and self._out_queue.empty():
            return b""
        data = await self._out_queue.get()
        return data

    async def close(self) -> None:
        self._closed = True
        with contextlib.suppress(Exception):
            self._out_queue.put_nowait(b"")


class _InMemoryConnectionHandle:
    def __init__(self, *, host: str, port: int, server_spec: dict[str, Any]) -> None:
        self.host = host
        self.port = port
        self.server_spec = server_spec
        self.channels: list[_InMemoryProcessChannel] = []
        raw_key = server_spec.get("host_key") or (
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAIMockArgoHostKey00000000000000000001",
        )
        self._peer_host_key = (str(raw_key[0]), str(raw_key[1]))

    @property
    def peer_host_key(self) -> tuple[str, str]:
        return self._peer_host_key

    async def open_shell(self, cols: int = 120, rows: int = 36) -> SSHProcessChannel:
        ch = _InMemoryProcessChannel(host=self.host, port=self.port, server_spec=self.server_spec)
        ch.resize(cols, rows)
        initial_banner = self.server_spec.get("initial_banner")
        if initial_banner:
            ch.push_output(initial_banner)
        self.channels.append(ch)
        return ch

    async def close(self) -> None:
        for ch in self.channels:
            await ch.close()


class InMemorySSHTransport:
    """In-memory deterministic SSH server registry for offline unit & integration tests."""

    def __init__(self) -> None:
        self.servers: dict[tuple[str, int], dict[str, Any]] = {}
        self.connections: list[dict[str, Any]] = []

    def register_server(
        self,
        host: str,
        port: int = 22,
        *,
        host_key: tuple[str, str] | None = None,
        sudo_password: str = "",
        sudo_success_output: str = "sudo command succeeded\r\n",
        username: str = "ops",
        initial_banner: bytes | str = "",
        handler: Callable[[str, _InMemoryProcessChannel], bytes | str | None] | None = None,
    ) -> None:
        self.servers[(host.strip().lower(), int(port))] = {
            "host_key": host_key
            or ("ssh-ed25519", f"AAAAC3NzaC1lZDI1NTE5AAAAIMockKey_{host}_{port}"),
            "sudo_password": sudo_password,
            "sudo_success_output": sudo_success_output,
            "username": username,
            "initial_banner": initial_banner,
            "handler": handler,
        }

    async def connect(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str | None = None,
        private_key: str | None = None,
        passphrase: str | None = None,
        timeout_seconds: float = 15.0,
        host_key_verifier: Callable[[str, str], None] | None = None,
    ) -> SSHConnectionHandle:
        del passphrase, timeout_seconds
        spec = dict(self.servers.get((host.strip().lower(), int(port))) or {})
        spec.setdefault("username", username)
        raw_key = spec.get("host_key") or (
            "ssh-ed25519",
            f"AAAAC3NzaC1lZDI1NTE5AAAAIMockKey_{host}_{port}",
        )
        key_type, key_b64 = str(raw_key[0]), str(raw_key[1])
        # Enforce host key validation strictly BEFORE recording credential use
        if host_key_verifier is not None:
            host_key_verifier(key_type, key_b64)
        conn = _InMemoryConnectionHandle(host=host, port=int(port), server_spec=spec)
        self.connections.append(
            {
                "host": host,
                "port": int(port),
                "username": username,
                "has_password": bool(password),
                "has_private_key": bool(private_key),
                "conn": conn,
            }
        )
        return conn


class _LocalPTYProcessAdapter:
    """Real Linux PTY subprocess channel (/bin/sh or /bin/bash) for CI PTY verification."""

    def __init__(self, master_fd: int, proc: asyncio.subprocess.Process) -> None:
        self._master_fd = master_fd
        self._proc = proc
        self._closed = False
        os.set_blocking(self._master_fd, False)

    def write(self, data: bytes) -> None:
        if not self._closed:
            os.write(self._master_fd, data)

    def resize(self, cols: int, rows: int) -> None:
        if not self._closed:
            with contextlib.suppress(OSError):
                winsize = struct.pack("HHHH", int(rows), int(cols), 0, 0)
                fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, winsize)

    async def read(self, max_bytes: int = 4096) -> bytes:
        if self._closed:
            return b""
        loop = asyncio.get_running_loop()
        ready = asyncio.Event()

        def _on_readable() -> None:
            ready.set()

        try:
            loop.add_reader(self._master_fd, _on_readable)
        except Exception:
            return b""
        try:
            while not self._closed:
                try:
                    chunk = os.read(self._master_fd, max_bytes)
                    if chunk:
                        return chunk
                    return b""
                except BlockingIOError:
                    ready.clear()
                    await ready.wait()
                except OSError:
                    return b""
            return b""
        finally:
            with contextlib.suppress(Exception):
                loop.remove_reader(self._master_fd)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            asyncio.get_running_loop().remove_reader(self._master_fd)
        with contextlib.suppress(OSError):
            os.close(self._master_fd)
        if self._proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self._proc.pid, signal.SIGTERM)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._proc.wait(), timeout=2.0)


class _LocalPTYConnectionHandle:
    def __init__(self, host_key: tuple[str, str]) -> None:
        self._peer_host_key = host_key
        self._procs: list[_LocalPTYProcessAdapter] = []

    @property
    def peer_host_key(self) -> tuple[str, str]:
        return self._peer_host_key

    async def open_shell(self, cols: int = 120, rows: int = 36) -> SSHProcessChannel:
        master_fd, slave_fd = pty.openpty()
        with contextlib.suppress(OSError):
            winsize = struct.pack("HHHH", int(rows), int(cols), 0, 0)
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
        env = {
            **os.environ,
            "TERM": "xterm-256color",
            "PS1": "argo-pty$ ",
        }
        shell_cmd = (
            [shutil.which("bash") or "/bin/bash", "--norc", "--noprofile", "-i"]
            if (shutil.which("bash") or os.path.exists("/bin/bash"))
            else ["/bin/sh", "-i"]
        )
        proc = await asyncio.create_subprocess_exec(
            *shell_cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            start_new_session=True,
        )
        os.close(slave_fd)
        adapter = _LocalPTYProcessAdapter(master_fd, proc)
        self._procs.append(adapter)
        return adapter

    async def close(self) -> None:
        for p in self._procs:
            await p.close()


class LocalPTYSSHTransport:
    """SSHTransport backed by a real Linux pty.openpty() shell for deterministic PTY tests."""

    def __init__(self, host_key: tuple[str, str] | None = None) -> None:
        self.host_key = host_key or (
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAILocalPTYTestKey000000000000000001",
        )

    async def connect(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str | None = None,
        private_key: str | None = None,
        passphrase: str | None = None,
        timeout_seconds: float = 15.0,
        host_key_verifier: Callable[[str, str], None] | None = None,
    ) -> SSHConnectionHandle:
        del host, port, username, password, private_key, passphrase, timeout_seconds
        if host_key_verifier is not None:
            host_key_verifier(self.host_key[0], self.host_key[1])
        return _LocalPTYConnectionHandle(self.host_key)


@dataclass
class SSHSessionState:
    session_id: str
    bot_slug: str
    vault_slug: str
    host: str
    port: int
    correlation_id: str
    conn: SSHConnectionHandle
    channel: SSHProcessChannel
    vt: VirtualTerminalScreen
    recorder: SSHSessionRecorder
    lock_resource_id: str
    host_key_verified: bool = True
    status: str = "active"  # active | awaiting_input | taken_over | paused | closed
    operator_takeover: bool = False
    paused: bool = False
    pinned: bool = False
    shell_kind: str = "posix"
    osc133_supported: bool = False
    turn_seq: int = 0
    last_command: str = ""
    last_command_invoked_sudo: bool = False
    sudo_injected_for_turn: bool = False
    command_in_flight: bool = False
    in_flight_start_seq: int = 0
    in_flight_start_bytes: int = 0
    created_at: str = ""
    last_activity_mono: float = field(default_factory=time.monotonic)
    last_output_mono: float = 0.0
    total_output_bytes: int = 0
    data_event: asyncio.Event = field(default_factory=asyncio.Event)
    ws_subscribers: set[asyncio.Queue[dict[str, Any]]] = field(default_factory=set)
    reader_task: asyncio.Task[None] | None = None
    exec_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class SSHManager:
    """In-process AsyncSSH PTY session lifecycle, dual-layer audit, takeover, and TTL manager."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        bus: EventBus,
        settings: ArgoSettings,
        transport: SSHTransport | None = None,
        quiescence_seconds: float = 0.3,
        idle_timeout_seconds: float | None = None,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._settings = settings
        self._transport: SSHTransport = transport or AsyncSSHTransport()
        self._quiescence_seconds = max(0.05, float(quiescence_seconds))
        self._idle_timeout_seconds = (
            float(idle_timeout_seconds)
            if idle_timeout_seconds is not None
            else float(settings.ssh_idle_timeout_seconds)
        )
        self._sessions: dict[str, SSHSessionState] = {}
        self._lifecycle_lock = asyncio.Lock()

    @property
    def transport(self) -> SSHTransport:
        return self._transport

    def _audit_root(self) -> Path:
        return Path(self._settings.resolved_ssh_audit_root())

    def _should_resolve_dns(self) -> bool:
        return isinstance(self._transport, AsyncSSHTransport)

    def _scrub_text(self, text: str) -> str:
        secrets = self._repo.collect_all_sensitive_secrets()
        return redact_secrets(text, secrets)

    def _serialize_live_session(self, s: SSHSessionState) -> dict[str, Any]:
        return {
            "session_id": s.session_id,
            "bot_slug": s.bot_slug,
            "vault_slug": s.vault_slug,
            "host": s.host,
            "port": s.port,
            "correlation_id": s.correlation_id,
            "status": s.status,
            "operator_takeover": s.operator_takeover,
            "paused": s.paused,
            "pinned": s.pinned,
            "last_command": self._scrub_text(s.last_command),
            "screen_text": self._scrub_text(s.vt.render_text()),
            "cast_relpath": s.recorder.cast_relpath,
            "cast_sha256": s.recorder.cast_sha256,
            "created_at": s.created_at,
            "expires_at": s.recorder.expires_at,
            "live": s.status != "closed",
        }

    def get_session(self, session_id: str) -> SSHSessionState | None:
        return self._sessions.get(session_id)

    def list_sessions(
        self,
        *,
        bot_slug: str | None = None,
        include_closed: bool = True,
    ) -> list[dict[str, Any]]:
        """List active and optionally retained historical SSH sessions."""
        items_by_id: dict[str, dict[str, Any]] = {}
        for s in self._sessions.values():
            if bot_slug and s.bot_slug != bot_slug:
                continue
            if s.status == "closed":
                continue
            items_by_id[s.session_id] = self._serialize_live_session(s)

        if include_closed:
            for hist in self._repo.list_recent_ssh_sessions_from_log(bot_slug=bot_slug, limit=100):
                sid = hist["session_id"]
                if sid not in items_by_id:
                    hist["live"] = False
                    items_by_id[sid] = hist

        result = list(items_by_id.values())
        result.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return result

    async def _broadcast_ws(self, session: SSHSessionState, event: dict[str, Any]) -> None:
        for queue in list(session.ws_subscribers):
            if queue.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
            await queue.put(event)

    async def _reader_loop(self, session: SSHSessionState) -> None:
        try:
            while session.status != "closed":
                chunk = await session.channel.read(4096)
                if not chunk:
                    if session.status != "closed":
                        session.status = "closed"
                        session.command_in_flight = False
                        session.operator_takeover = False
                        with contextlib.suppress(Exception):
                            sha256_hex = session.recorder.finalize()
                            await self._bus.release_lock("ssh", session.lock_resource_id, session.bot_slug)
                            await self._broadcast_ws(
                                session,
                                {"type": "closed", "status": "closed", "cast_sha256": sha256_hex},
                            )
                    break
                text = chunk.decode("utf-8", errors="replace")
                scrubbed = self._scrub_text(text)
                scrubbed_bytes = scrubbed.encode("utf-8", errors="replace")
                session.vt.feed(scrubbed_bytes)
                session.recorder.write_output(scrubbed_bytes)
                session.total_output_bytes += len(scrubbed_bytes)
                session.last_output_mono = time.monotonic()
                session.last_activity_mono = session.last_output_mono
                session.data_event.set()
                await self._broadcast_ws(
                    session,
                    {"type": "output", "data": scrubbed},
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("SSH reader loop ended for %s: %s", session.session_id, exc)
        finally:
            session.data_event.set()

    async def _bootstrap_shell(self, session: SSHSessionState) -> None:
        """Install OS-appropriate OSC 133;D exit-code hook while preserving prompt cursor alignment."""
        # Wait briefly for initial login banner / shell prompt to identify POSIX vs Windows shell
        has_banner = bool(
            hasattr(session.conn, "server_spec")
            and isinstance(getattr(session.conn, "server_spec", None), dict)
            and session.conn.server_spec.get("initial_banner")
        )
        banner_wait = (
            0.005
            if (isinstance(self._transport, InMemorySSHTransport) and not has_banner)
            else 0.15
        )
        if session.total_output_bytes == 0 and banner_wait > 0:
            session.data_event.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(session.data_event.wait(), timeout=banner_wait)
        if session.total_output_bytes > 0:
            await asyncio.sleep(0.02)

        banner_text = session.vt.render_text()
        if re.search(r"(?:Windows PowerShell|PowerShell\s+\d|PS\s+[A-Za-z]:\\)", banner_text, re.IGNORECASE):
            session.shell_kind = "powershell"
        elif re.search(r"(?:Microsoft Windows \[Version|[A-Za-z]:\\[^>\r\n]*>)", banner_text, re.IGNORECASE):
            session.shell_kind = "cmd"
        else:
            session.shell_kind = "posix"

        start_seq = session.vt.command_completed_seq
        if session.shell_kind == "powershell":
            bootstrap_str = (
                'function global:prompt { $e = if ($?) { 0 } else { 1 }; '
                '[Console]::Write("$([char]27)]133;D;$e$([char]7)"); '
                '"PS $((Get-Location).Path)> " }; '
                '[Console]::Write("$([char]27)]133;D;0$([char]7)")\r\n'
            )
        elif session.shell_kind == "cmd":
            bootstrap_str = "prompt $E]133;D;0$E\\$P$G\r\n"
        else:
            bootstrap_str = (
                ' stty -echoctl 2>/dev/null; export TERM=xterm-256color; '
                'PROMPT_COMMAND=\'printf "\\033]133;D;%s\\007" "$?"\'; '
                'precmd() { printf "\\033]133;D;%s\\007" "$?"; }; '
                'printf "\\033]133;D;0\\007"\n'
            )
        session.channel.write(bootstrap_str.encode("utf-8"))

        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            if session.vt.command_completed_seq > start_seq:
                break
            session.data_event.clear()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(session.data_event.wait(), timeout=min(0.15, remaining))

        session.osc133_supported = session.vt.command_completed_seq > start_seq
        # Drain any trailing prompt bytes right after bootstrap completion, preserving cursor column
        await asyncio.sleep(0.03)
        session.vt.clear_history_keep_prompt()
        session.vt.last_exit_code = None
        session.vt.command_completed_seq = 0
        session.total_output_bytes = 0
        session.last_output_mono = 0.0

    async def open_or_reuse_session(
        self,
        *,
        bot_slug: str,
        vault_slug: str,
        requested_host: str | None = None,
        requested_port: int | str | None = None,
        correlation_id: str,
        trusted_operator_texts: list[str] | tuple[str, ...] = (),
        session_id: str | None = None,
    ) -> SSHSessionState:
        """Resolve Dual-Mode Host Guard, acquire Valkey mutex, pin TOFU key, and open PTY shell."""
        trusted_texts_local = list(trusted_operator_texts)
        if session_id and session_id in self._sessions and not (requested_host and str(requested_host).strip()):
            existing = self._sessions[session_id]
            if existing.status != "closed" and existing.bot_slug == bot_slug:
                requested_host = existing.host
                requested_port = existing.port
                trusted_texts_local.append(existing.host)

        vault_entry = self._repo.get_vault_secret_decrypted(vault_slug)
        if vault_entry is None:
            raise NotFoundError(f"Vault secret '@{vault_slug}' not found.")

        target_host, target_port, pinned_ip = resolve_authorized_ssh_target_with_ip(
            vault_entry=vault_entry,
            requested_host=requested_host,
            requested_port=requested_port,
            trusted_operator_texts=trusted_texts_local,
            resolve_dns=self._should_resolve_dns(),
        )

        # Reuse explicit session_id only when it matches the resolved target vault, host, and port
        if session_id and session_id in self._sessions:
            existing = self._sessions[session_id]
            if (
                existing.status != "closed"
                and existing.bot_slug == bot_slug
                and existing.vault_slug == vault_entry["slug"]
                and existing.host == target_host
                and existing.port == target_port
            ):
                return existing

        # Reuse active session owned by the same bot + vault + target server
        for s in self._sessions.values():
            if (
                s.status != "closed"
                and s.bot_slug == bot_slug
                and s.vault_slug == vault_entry["slug"]
                and s.host == target_host
                and s.port == target_port
            ):
                return s

        lock_resource = f"{vault_entry['slug']}:{target_host}:{target_port}"
        acquired = await self._bus.acquire_lock("ssh", lock_resource, bot_slug, ttl_seconds=600)
        if not acquired:
            raise PermissionError(
                f"Target SSH host '{target_host}:{target_port}' is currently locked by another active bot session."
            )

        secrets = vault_entry.get("secrets") or {}
        username = str(secrets.get("username") or secrets.get("user") or "root").strip() or "root"
        password = str(secrets.get("password") or "") or None
        private_key = str(secrets.get("private_key") or "") or None
        passphrase = str(secrets.get("passphrase") or "") or None

        def _verify_host_key(alg: str, key_b64: str) -> None:
            verify_or_pin_host_key(
                repo=self._repo,
                vault_slug=vault_entry["slug"],
                host=target_host,
                port=target_port,
                key_type=alg,
                key_b64=key_b64,
                decrypted_vault_entry=vault_entry,
            )

        try:
            conn = await self._transport.connect(
                host=pinned_ip or target_host,
                port=target_port,
                username=username,
                password=password,
                private_key=private_key,
                passphrase=passphrase,
                timeout_seconds=15.0,
                host_key_verifier=_verify_host_key,
            )
            channel = await conn.open_shell(cols=120, rows=36)
        except Exception:
            await self._bus.release_lock("ssh", lock_resource, bot_slug)
            raise

        new_sid = make_id("ssh")
        audit_cfg = self._repo.get_ssh_audit_settings(self._settings.ssh_default_retention_hours)
        recorder = SSHSessionRecorder(
            audit_root=self._audit_root(),
            session_id=new_sid,
            bot_slug=bot_slug,
            vault_slug=vault_entry["slug"],
            host=target_host,
            port=target_port,
            correlation_id=correlation_id,
            repo=self._repo,
            cols=120,
            rows=36,
            retention_hours=int(audit_cfg.get("retention_hours") or 24),
        )
        session = SSHSessionState(
            session_id=new_sid,
            bot_slug=bot_slug,
            vault_slug=vault_entry["slug"],
            host=target_host,
            port=target_port,
            correlation_id=correlation_id,
            conn=conn,
            channel=channel,
            vt=VirtualTerminalScreen(cols=120, rows=36),
            recorder=recorder,
            lock_resource_id=lock_resource,
            host_key_verified=True,
            created_at=utc_now(),
        )
        session.reader_task = asyncio.create_task(self._reader_loop(session))
        self._sessions[new_sid] = session
        await self._bootstrap_shell(session)
        return session

    async def _publish_turn_event(
        self,
        session: SSHSessionState,
        *,
        event_type: str,
        command: str,
        input_kind: str,
        status: str,
        exit_code: int | None,
        prompt_line: str = "",
    ) -> None:
        payload: dict[str, Any] = {
            "category": "runs",
            "title": f"SSH {status} · {session.host}",
            "badge": "SSH",
            "badge_tone": "emerald" if status == "completed" else "amber",
            "summary": self._scrub_text(f"{command or input_kind} -> {status}"),
            "session_id": session.session_id,
            "turn_seq": session.turn_seq,
            "bot_slug": session.bot_slug,
            "vault_slug": session.vault_slug,
            "host": session.host,
            "port": session.port,
            "command": self._scrub_text(command)[:1000],
            "input_kind": input_kind,
            "status": status,
            "exit_code": exit_code,
            "screen_excerpt": self._scrub_text(session.vt.render_text())[:4000],
            "timestamp": utc_now(),
        }
        if prompt_line:
            payload["prompt_line"] = self._scrub_text(prompt_line)[:500]
        await self._bus.publish(
            correlation_id=session.correlation_id,
            source_slug=session.bot_slug,
            target_slug=None,
            event_type=event_type,
            payload=payload,
            hop_count=1,
        )

    async def _finalize_completed_turn(
        self,
        session: SSHSessionState,
        *,
        command: str,
        input_kind: str,
        exit_code: int | None,
    ) -> dict[str, Any]:
        session.command_in_flight = False
        session.status = "taken_over" if session.operator_takeover else "active"
        session.recorder.write_exit(exit_code or 0)
        screen_txt = self._scrub_text(session.vt.render_text())
        session.recorder.record_turn(
            turn_seq=session.turn_seq,
            command=command,
            input_kind=input_kind,
            status="completed",
            exit_code=exit_code,
            screen_excerpt=screen_txt,
        )
        await self._publish_turn_event(
            session,
            event_type="ssh.turn.completed",
            command=command,
            input_kind=input_kind,
            status="completed",
            exit_code=exit_code,
        )
        await self._broadcast_ws(
            session,
            {
                "type": "state",
                "status": session.status,
                "paused": session.paused,
                "operator_takeover": session.operator_takeover,
                "pinned": session.pinned,
            },
        )
        return {
            "status": "completed",
            "session_id": session.session_id,
            "host": session.host,
            "port": session.port,
            "exit_code": exit_code,
            "screen_text": screen_txt,
            "cast_relpath": session.recorder.cast_relpath,
            "cast_sha256": session.recorder.cast_sha256,
        }

    async def _await_turn_outcome(
        self,
        session: SSHSessionState,
        *,
        command: str,
        input_kind: str,
        rbac_mode: str,
        vault_entry: dict[str, Any],
        start_seq: int,
        start_bytes: int,
        timeout_seconds: float,
        max_duration_seconds: float | None = None,
        approved_by_human: bool,
    ) -> dict[str, Any]:
        start_mono = time.monotonic()
        idle_limit = max(0.15, float(timeout_seconds))
        if max_duration_seconds is not None:
            hard_limit = max(idle_limit, float(max_duration_seconds))
        elif idle_limit >= 10.0:
            hard_limit = max(idle_limit, 300.0 if approved_by_human else 120.0)
        else:
            hard_limit = idle_limit
        hard_deadline = start_mono + hard_limit

        while True:
            if session.paused:
                session.recorder.record_turn(
                    turn_seq=session.turn_seq,
                    command=command,
                    input_kind=input_kind,
                    status="paused",
                    exit_code=None,
                    screen_excerpt=session.vt.render_text(),
                )
                return {
                    "status": "paused",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "detail": "SSH session was frozen by operator or security review.",
                }

            if session.vt.command_completed_seq > start_seq:
                return await self._finalize_completed_turn(
                    session,
                    command=command,
                    input_kind=input_kind,
                    exit_code=session.vt.last_exit_code,
                )

            if session.status == "closed":
                session.command_in_flight = False
                return {
                    "status": "closed",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "detail": "SSH session closed by remote host.",
                }

            now_mono = time.monotonic()
            has_new_output = session.total_output_bytes > start_bytes and session.last_output_mono > 0
            last_activity = max(start_mono, session.last_output_mono) if has_new_output else start_mono
            effective_deadline = min(hard_deadline, last_activity + idle_limit)
            if has_new_output and (now_mono - session.last_output_mono) >= self._quiescence_seconds:
                prompt_line = self._scrub_text(session.vt.tail_prompt_line())
                screen_txt = self._scrub_text(session.vt.render_text())
                secrets_map = vault_entry.get("secrets") or {}
                sudo_pw = str(secrets_map.get("sudo_password") or "")
                is_verified_sudo = bool(
                    session.host_key_verified
                    and session.last_command_invoked_sudo
                    and not session.vt.last_char_was_newline
                    and _SUDO_PROMPT_RE.search(prompt_line)
                    and not session.sudo_injected_for_turn
                    and sudo_pw
                )

                if is_verified_sudo:
                    if rbac_mode == "execute" or approved_by_human:
                        session.sudo_injected_for_turn = True
                        start_bytes = session.total_output_bytes
                        session.recorder.write_input("<REDACTED_SUDO_PASSWORD>\n")
                        session.channel.write((sudo_pw + "\n").encode("utf-8"))
                        session.recorder.record_turn(
                            turn_seq=session.turn_seq,
                            command=command,
                            input_kind="vault_sudo",
                            status="active",
                            exit_code=None,
                            screen_excerpt=screen_txt,
                        )
                        input_kind = "vault_sudo"
                        session.turn_seq += 1
                        continue
                    if rbac_mode == "internal":
                        session.channel.write(b"\x03")
                        session.status = "active"
                        session.recorder.record_turn(
                            turn_seq=session.turn_seq,
                            command=command,
                            input_kind=input_kind,
                            status="blocked",
                            exit_code=None,
                            screen_excerpt=screen_txt,
                        )
                        return {
                            "status": "blocked_rbac",
                            "session_id": session.session_id,
                            "host": session.host,
                            "port": session.port,
                            "prompt_line": prompt_line,
                            "screen_text": screen_txt,
                            "detail": "Read-only bot aborted interactive sudo password prompt.",
                        }
                    session.status = "awaiting_input"
                    session.recorder.record_turn(
                        turn_seq=session.turn_seq,
                        command=command,
                        input_kind=input_kind,
                        status="awaiting_input",
                        exit_code=None,
                        screen_excerpt=screen_txt,
                    )
                    await self._publish_turn_event(
                        session,
                        event_type="ssh.prompt.waiting",
                        command=command,
                        input_kind=input_kind,
                        status="awaiting_input",
                        exit_code=None,
                        prompt_line=prompt_line,
                    )
                    return {
                        "status": "awaiting_sudo_approval",
                        "sudo_prompt": True,
                        "echo_disabled": True,
                        "session_id": session.session_id,
                        "host": session.host,
                        "port": session.port,
                        "prompt_line": prompt_line,
                        "screen_text": screen_txt,
                        "completed_seq": session.vt.command_completed_seq,
                    }

                is_interactive_prompt = bool(
                    not session.vt.last_char_was_newline
                    and (
                        _INTERACTIVE_PROMPT_RE.search(prompt_line)
                        or _SUDO_PROMPT_RE.search(prompt_line)
                    )
                )
                if is_interactive_prompt:
                    if rbac_mode == "internal":
                        session.channel.write(b"\x03")
                        session.status = "active"
                        session.recorder.record_turn(
                            turn_seq=session.turn_seq,
                            command=command,
                            input_kind=input_kind,
                            status="blocked",
                            exit_code=None,
                            screen_excerpt=screen_txt,
                        )
                        return {
                            "status": "blocked_rbac",
                            "session_id": session.session_id,
                            "host": session.host,
                            "port": session.port,
                            "prompt_line": prompt_line,
                            "screen_text": screen_txt,
                            "detail": "Read-only bot aborted interactive prompt (Ctrl+C).",
                        }

                    session.status = "awaiting_input"
                    session.recorder.record_turn(
                        turn_seq=session.turn_seq,
                        command=command,
                        input_kind=input_kind,
                        status="awaiting_input",
                        exit_code=None,
                        screen_excerpt=screen_txt,
                    )
                    await self._publish_turn_event(
                        session,
                        event_type="ssh.prompt.waiting",
                        command=command,
                        input_kind=input_kind,
                        status="awaiting_input",
                        exit_code=None,
                        prompt_line=prompt_line,
                    )
                    return {
                        "status": "awaiting_input",
                        "sudo_prompt": False,
                        "echo_disabled": bool(_SUDO_PROMPT_RE.search(prompt_line)),
                        "session_id": session.session_id,
                        "host": session.host,
                        "port": session.port,
                        "prompt_line": prompt_line,
                        "screen_text": screen_txt,
                        "completed_seq": session.vt.command_completed_seq,
                    }

                if (
                    not session.osc133_supported
                    and not session.vt.last_char_was_newline
                    and _SHELL_PROMPT_RE.search(prompt_line)
                ):
                    return await self._finalize_completed_turn(
                        session,
                        command=command,
                        input_kind=input_kind,
                        exit_code=session.vt.last_exit_code if session.vt.last_exit_code is not None else 0,
                    )

            if now_mono >= effective_deadline:
                screen_txt = self._scrub_text(session.vt.render_text())
                session.recorder.record_turn(
                    turn_seq=session.turn_seq,
                    command=command,
                    input_kind=input_kind,
                    status="running_timeout",
                    exit_code=None,
                    screen_excerpt=screen_txt,
                )
                await self._publish_turn_event(
                    session,
                    event_type="ssh.turn.completed",
                    command=command,
                    input_kind=input_kind,
                    status="running_timeout",
                    exit_code=None,
                )
                return {
                    "status": "running_timeout",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": screen_txt,
                }

            wait_slice = min(0.05, max(0.01, effective_deadline - now_mono))
            if has_new_output:
                rem_quiesce = self._quiescence_seconds - (now_mono - session.last_output_mono)
                if rem_quiesce > 0:
                    wait_slice = min(wait_slice, max(0.01, rem_quiesce))
            session.data_event.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(session.data_event.wait(), timeout=wait_slice)

    async def exec_command(
        self,
        *,
        bot_slug: str,
        vault_slug: str,
        command: str,
        requested_host: str | None = None,
        requested_port: int | str | None = None,
        correlation_id: str,
        rbac_mode: str = "draft",
        trusted_operator_texts: list[str] | tuple[str, ...] = (),
        session_id: str | None = None,
        timeout_seconds: float = 30.0,
        max_duration_seconds: float | None = None,
        approved_by_human: bool = False,
    ) -> dict[str, Any]:
        """Execute an interactive SSH command on an audited PTY session."""
        blocked_reason = check_catastrophic_ssh_command(command)
        if blocked_reason:
            return {
                "status": "blocked_catastrophic",
                "detail": blocked_reason,
                "command": self._scrub_text(command),
            }

        session = await self.open_or_reuse_session(
            bot_slug=bot_slug,
            vault_slug=vault_slug,
            requested_host=requested_host,
            requested_port=requested_port,
            correlation_id=correlation_id,
            trusted_operator_texts=trusted_operator_texts,
            session_id=session_id,
        )
        async with session.exec_lock:
            if session.operator_takeover:
                return {
                    "status": "operator_active",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "detail": "Operator currently controls the live terminal. Wait for 'Hand Back to Bot'.",
                }
            if session.paused:
                return {
                    "status": "paused",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "detail": "SSH session is currently frozen for security review.",
                }
            if session.status == "closed":
                return {
                    "status": "closed",
                    "session_id": session.session_id,
                    "detail": "SSH session is already closed.",
                }

            vault_entry = self._repo.get_vault_secret_decrypted(session.vault_slug) or {}
            clean_cmd = str(command or "").rstrip("\r\n")
            session.turn_seq += 1
            session.last_command = clean_cmd
            session.last_command_invoked_sudo = _command_invokes_sudo(clean_cmd)
            session.sudo_injected_for_turn = False
            session.last_activity_mono = time.monotonic()

            start_seq = session.vt.command_completed_seq
            start_bytes = session.total_output_bytes
            session.command_in_flight = True
            session.in_flight_start_seq = start_seq
            session.in_flight_start_bytes = start_bytes
            session.recorder.write_input(clean_cmd + "\n")
            session.channel.write((clean_cmd + "\n").encode("utf-8"))

            return await self._await_turn_outcome(
                session,
                command=clean_cmd,
                input_kind="command",
                rbac_mode=rbac_mode,
                vault_entry=vault_entry,
                start_seq=start_seq,
                start_bytes=start_bytes,
                timeout_seconds=timeout_seconds,
                max_duration_seconds=max_duration_seconds,
                approved_by_human=approved_by_human,
            )

    async def send_input(
        self,
        *,
        session_id: str,
        bot_slug: str,
        text: str = "",
        rbac_mode: str = "execute",
        timeout_seconds: float = 30.0,
        max_duration_seconds: float | None = None,
        approved_by_human: bool = False,
        inject_vault_sudo: bool = False,
        expected_completed_seq: int | None = None,
    ) -> dict[str, Any]:
        """Send an interactive prompt reply (or approved Vault sudo secret) to an awaiting PTY session."""
        session = self._sessions.get(session_id)
        if session is None or session.status == "closed":
            raise NotFoundError(f"Active SSH session '{session_id}' not found.")
        if session.bot_slug != bot_slug and not approved_by_human:
            raise PermissionError(f"Bot '{bot_slug}' does not own SSH session '{session_id}'.")

        async with session.exec_lock:
            if (
                expected_completed_seq is not None
                and session.vt.command_completed_seq > expected_completed_seq
            ):
                session.command_in_flight = False
                session.status = "taken_over" if session.operator_takeover else "active"
                await self._broadcast_ws(
                    session,
                    {
                        "type": "state",
                        "status": session.status,
                        "paused": session.paused,
                        "operator_takeover": session.operator_takeover,
                        "pinned": session.pinned,
                    },
                )
                return {
                    "status": "completed",
                    "already_completed": True,
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "exit_code": session.vt.last_exit_code,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "cast_relpath": session.recorder.cast_relpath,
                    "cast_sha256": session.recorder.cast_sha256,
                }
            if session.operator_takeover:
                return {
                    "status": "operator_active",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "detail": "Operator currently controls the live terminal.",
                }
            if session.paused:
                return {
                    "status": "paused",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "detail": "SSH session is currently frozen for security review.",
                }

            vault_entry = self._repo.get_vault_secret_decrypted(session.vault_slug) or {}
            start_seq = session.vt.command_completed_seq
            start_bytes = session.total_output_bytes
            session.turn_seq += 1
            session.last_activity_mono = time.monotonic()

            if inject_vault_sudo:
                secrets_map = vault_entry.get("secrets") or {}
                sudo_pw = str(secrets_map.get("sudo_password") or "")
                prompt_line = self._scrub_text(session.vt.tail_prompt_line())
                if not (
                    session.host_key_verified
                    and session.last_command_invoked_sudo
                    and not session.vt.last_char_was_newline
                    and _SUDO_PROMPT_RE.search(prompt_line)
                    and sudo_pw
                    and approved_by_human
                ):
                    return {
                        "status": "blocked_rbac",
                        "session_id": session.session_id,
                        "detail": "Verified sudo conditions did not hold for Vault password injection.",
                    }
                session.sudo_injected_for_turn = True
                session.command_in_flight = True
                session.in_flight_start_seq = start_seq
                session.in_flight_start_bytes = start_bytes
                session.recorder.write_input("<REDACTED_SUDO_PASSWORD>\n")
                session.channel.write((sudo_pw + "\n").encode("utf-8"))
                return await self._await_turn_outcome(
                    session,
                    command=session.last_command,
                    input_kind="vault_sudo",
                    rbac_mode=rbac_mode,
                    vault_entry=vault_entry,
                    start_seq=start_seq,
                    start_bytes=start_bytes,
                    timeout_seconds=timeout_seconds,
                    max_duration_seconds=max_duration_seconds,
                    approved_by_human=True,
                )

            blocked_reason = check_catastrophic_ssh_command(text)
            if blocked_reason:
                return {
                    "status": "blocked_catastrophic",
                    "session_id": session.session_id,
                    "detail": blocked_reason,
                }

            payload_text = text if text.endswith(("\n", "\r")) or text == "\x03" else (text + "\n")
            session.command_in_flight = True
            session.in_flight_start_seq = start_seq
            session.in_flight_start_bytes = start_bytes
            session.recorder.write_input(payload_text)
            session.channel.write(payload_text.encode("utf-8"))
            return await self._await_turn_outcome(
                session,
                command=payload_text.strip() or "<input>",
                input_kind="prompt_reply",
                rbac_mode=rbac_mode,
                vault_entry=vault_entry,
                start_seq=start_seq,
                start_bytes=start_bytes,
                timeout_seconds=timeout_seconds,
                max_duration_seconds=max_duration_seconds,
                approved_by_human=approved_by_human,
            )

    async def wait_for_turn(
        self,
        *,
        session_id: str,
        bot_slug: str,
        timeout_seconds: float = 45.0,
        max_duration_seconds: float | None = None,
        rbac_mode: str = "draft",
        approved_by_human: bool = False,
    ) -> dict[str, Any]:
        """Wait for an in-flight SSH command without sending input to the remote PTY."""
        session = self._sessions.get(session_id)
        if session is None or session.status == "closed":
            raise NotFoundError(f"Active SSH session '{session_id}' not found.")
        if session.bot_slug != bot_slug and not approved_by_human:
            raise PermissionError(f"Bot '{bot_slug}' does not own SSH session '{session_id}'.")

        async with session.exec_lock:
            if session.operator_takeover:
                return {
                    "status": "operator_active",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "detail": "Operator currently controls the live terminal.",
                }
            if session.paused:
                return {
                    "status": "paused",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "detail": "SSH session is currently frozen for security review.",
                }
            if session.status == "closed":
                session.command_in_flight = False
                return {
                    "status": "closed",
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "detail": "SSH session is already closed.",
                }
            if not session.command_in_flight and session.status != "awaiting_input":
                return {
                    "status": "completed",
                    "already_completed": True,
                    "session_id": session.session_id,
                    "host": session.host,
                    "port": session.port,
                    "exit_code": session.vt.last_exit_code,
                    "screen_text": self._scrub_text(session.vt.render_text()),
                    "cast_relpath": session.recorder.cast_relpath,
                    "cast_sha256": session.recorder.cast_sha256,
                }
            vault_entry = self._repo.get_vault_secret_decrypted(session.vault_slug) or {}
            session.last_activity_mono = time.monotonic()
            return await self._await_turn_outcome(
                session,
                command=session.last_command or "<wait>",
                input_kind="wait",
                rbac_mode=rbac_mode,
                vault_entry=vault_entry,
                start_seq=session.in_flight_start_seq,
                start_bytes=session.in_flight_start_bytes,
                timeout_seconds=timeout_seconds,
                max_duration_seconds=max_duration_seconds,
                approved_by_human=approved_by_human,
            )

    def abort_prompt_sync_or_async(self, session_id: str) -> None:
        """Send Ctrl+C to unstick an awaiting interactive prompt when a draft approval is rejected."""
        session = self._sessions.get(session_id)
        if session is None or session.status == "closed":
            return
        with contextlib.suppress(Exception):
            session.channel.write(b"\x03")
            session.status = "active"

    async def takeover(self, session_id: str, actor: str = "operator") -> dict[str, Any]:
        """Give live keyboard control to the human operator and lock out concurrent Bot writes."""
        session = self._sessions.get(session_id)
        if session is None or session.status == "closed":
            raise NotFoundError(f"Active SSH session '{session_id}' not found.")
        session.operator_takeover = True
        session.status = "taken_over"
        session.last_activity_mono = time.monotonic()
        session.recorder.write_marker("takeover_start")
        await self._broadcast_ws(
            session,
            {
                "type": "state",
                "status": session.status,
                "operator_takeover": True,
                "paused": session.paused,
                "pinned": session.pinned,
                "actor": actor,
            },
        )
        return self._serialize_live_session(session)

    async def handback(self, session_id: str, actor: str = "operator") -> dict[str, Any]:
        """Return session control to the Bot and return the refreshed post-takeover 2D screen."""
        session = self._sessions.get(session_id)
        if session is None or session.status == "closed":
            raise NotFoundError(f"Active SSH session '{session_id}' not found.")
        session.operator_takeover = False
        session.status = "paused" if session.paused else "active"
        session.last_activity_mono = time.monotonic()
        session.recorder.write_marker("handback")
        screen_txt = self._scrub_text(session.vt.render_text())
        session.turn_seq += 1
        session.recorder.record_turn(
            turn_seq=session.turn_seq,
            command="Human interactive takeover session",
            input_kind="human_takeover",
            status="completed",
            exit_code=session.vt.last_exit_code,
            screen_excerpt=screen_txt,
        )
        await self._broadcast_ws(
            session,
            {
                "type": "state",
                "status": session.status,
                "operator_takeover": False,
                "paused": session.paused,
                "pinned": session.pinned,
                "actor": actor,
            },
        )
        return self._serialize_live_session(session)

    async def send_operator_ws_input(self, session_id: str, data: str) -> bool:
        """Forward live operator keystrokes from WebSocket strictly when operator_takeover is True."""
        session = self._sessions.get(session_id)
        if session is None or session.status == "closed" or not session.operator_takeover:
            return False
        session.last_activity_mono = time.monotonic()
        session.recorder.write_input(data)
        session.channel.write(data.encode("utf-8", errors="replace"))
        return True

    async def resize_session(self, session_id: str, cols: int, rows: int) -> bool:
        session = self._sessions.get(session_id)
        if session is None or session.status == "closed" or not session.operator_takeover:
            return False
        c = max(20, min(300, int(cols)))
        r = max(5, min(120, int(rows)))
        session.vt.resize(c, r)
        session.channel.resize(c, r)
        session.recorder.write_resize(c, r)
        return True

    async def control_session(
        self,
        session_id: str,
        *,
        operation: str,
        reason: str = "",
        actor: str = "operator",
        pin_audit: bool = False,
    ) -> dict[str, Any]:
        """Pause, resume, terminate, or pin/unpin an SSH session and its audit evidence."""
        op = str(operation or "").strip().lower()
        if op == "pin_audit":
            op = "pin"
        session = self._sessions.get(session_id)

        if op in {"pin", "unpin"}:
            pinned_val = op == "pin"
            if session is not None:
                session.pinned = pinned_val
                session.recorder.set_pinned(pinned_val)
                if pinned_val:
                    session.recorder.write_marker("incident_frozen")
                await self._broadcast_ws(
                    session,
                    {
                        "type": "state",
                        "status": session.status,
                        "operator_takeover": session.operator_takeover,
                        "paused": session.paused,
                        "pinned": session.pinned,
                    },
                )
                return self._serialize_live_session(session)
            updated = self._repo.set_ssh_session_pinned(session_id, pinned_val)
            if updated == 0:
                raise NotFoundError(f"SSH session '{session_id}' not found.")
            matches = [s for s in self.list_sessions(include_closed=True) if s["session_id"] == session_id]
            return matches[0] if matches else {"session_id": session_id, "pinned": pinned_val}

        if session is None:
            raise NotFoundError(f"Active SSH session '{session_id}' not found.")

        if op == "pause":
            session.paused = True
            session.status = "paused"
            session.recorder.write_marker("session_paused")
            if pin_audit:
                session.pinned = True
                session.recorder.set_pinned(True)
                session.recorder.write_marker("incident_frozen")
            session.turn_seq += 1
            session.recorder.record_turn(
                turn_seq=session.turn_seq,
                command=f"Session frozen by {actor}: {reason}".strip(": "),
                input_kind="human_takeover",
                status="paused",
                exit_code=None,
                screen_excerpt=self._scrub_text(session.vt.render_text()),
            )
            await self._broadcast_ws(
                session,
                {
                    "type": "state",
                    "status": session.status,
                    "operator_takeover": session.operator_takeover,
                    "paused": True,
                    "pinned": session.pinned,
                },
            )
            return self._serialize_live_session(session)

        if op == "resume":
            session.paused = False
            session.status = "taken_over" if session.operator_takeover else "active"
            session.recorder.write_marker("session_resumed")
            await self._broadcast_ws(
                session,
                {
                    "type": "state",
                    "status": session.status,
                    "operator_takeover": session.operator_takeover,
                    "paused": False,
                    "pinned": session.pinned,
                },
            )
            return self._serialize_live_session(session)

        if op == "terminate":
            if pin_audit:
                session.pinned = True
                session.recorder.set_pinned(True)
            return await self.close_session(session_id, reason=reason or f"Terminated by {actor}")

        raise ValueError(f"Unsupported SSH session control operation '{operation}'.")

    async def close_session(self, session_id: str, reason: str = "closed") -> dict[str, Any]:
        """Close an SSH PTY session, finalize .cast.zst SHA-256, release Valkey lock, and emit ssh.session.closed."""
        session = self._sessions.get(session_id)
        if session is None:
            raise NotFoundError(f"SSH session '{session_id}' not found.")
        if session.status == "closed":
            return self._serialize_live_session(session)

        session.status = "closed"
        session.command_in_flight = False
        session.operator_takeover = False
        session.data_event.set()
        await session.channel.close()
        await session.conn.close()
        if session.reader_task is not None:
            session.reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(session.reader_task, timeout=1.0)
        sha256_hex = session.recorder.finalize()
        if session.turn_seq == 0:
            session.turn_seq = 1
        session.recorder.record_turn(
            turn_seq=session.turn_seq,
            command=session.last_command or reason,
            input_kind="command",
            status="terminated" if "terminat" in reason.lower() else "completed",
            exit_code=session.vt.last_exit_code,
            screen_excerpt=self._scrub_text(session.vt.render_text()),
        )
        await self._bus.release_lock("ssh", session.lock_resource_id, session.bot_slug)
        await self._broadcast_ws(
            session,
            {"type": "closed", "status": "closed", "cast_sha256": sha256_hex},
        )
        await self._bus.publish(
            correlation_id=session.correlation_id,
            source_slug=session.bot_slug,
            target_slug=None,
            event_type="ssh.session.closed",
            payload={
                "category": "runs",
                "title": f"SSH Session Closed · {session.host}",
                "badge": "SSH Closed",
                "badge_tone": "slate",
                "summary": f"Closed session on {session.host} ({session.turn_seq} turns).",
                "session_id": session.session_id,
                "bot_slug": session.bot_slug,
                "vault_slug": session.vault_slug,
                "host": session.host,
                "total_turns": session.turn_seq,
                "cast_relpath": session.recorder.cast_relpath,
                "cast_sha256": sha256_hex,
                "pinned": session.pinned,
            },
            hop_count=1,
        )
        return self._serialize_live_session(session)

    async def close_all(self) -> None:
        """Close all open SSH sessions cleanly during application shutdown."""
        for sid, s in list(self._sessions.items()):
            if s.status != "closed":
                with contextlib.suppress(Exception):
                    await self.close_session(sid, reason="shutdown")

    def get_cast_path_for_session(self, session_id: str) -> tuple[Path, str]:
        """Resolve .cast.zst Path and SHA-256 hex for live or retained sessions."""
        session = self._sessions.get(session_id)
        if session is not None and session.recorder.cast_path.is_file():
            sha = session.recorder.refresh_sha256()
            return session.recorder.cast_path, sha
        for hist in self._repo.list_recent_ssh_sessions_from_log(limit=500):
            if hist["session_id"] == session_id:
                rel = str(hist.get("cast_relpath") or "").strip()
                if rel:
                    cand = (self._audit_root() / rel).resolve()
                    if cand.is_relative_to(self._audit_root().resolve()) and cand.is_file():
                        sha = str(hist.get("cast_sha256") or "") or ""
                        return cand, sha
        raise NotFoundError(f"Terminal recording for session '{session_id}' not found.")

    async def run_maintenance_once(self) -> dict[str, int]:
        """Close idle SSH sessions past timeout and sweep expired unpinned recordings."""
        now_mono = time.monotonic()
        closed_idle = 0
        for sid, s in list(self._sessions.items()):
            if s.status != "closed" and not s.operator_takeover:
                if (now_mono - s.last_activity_mono) >= self._idle_timeout_seconds:
                    with contextlib.suppress(Exception):
                        await self.close_session(sid, reason="idle_timeout")
                        closed_idle += 1

        active_ids = {sid for sid, s in self._sessions.items() if s.status != "closed"}
        swept = sweep_expired_ssh_recordings(
            audit_root=self._audit_root(),
            repo=self._repo,
            active_session_ids=active_ids,
        )
        for sid in list(self._sessions):
            s = self._sessions.get(sid)
            if s is not None and s.status == "closed" and not s.recorder.cast_path.is_file():
                self._sessions.pop(sid, None)
        return {"closed_idle": closed_idle, **swept}

    async def run_periodic_maintenance(self, interval_seconds: float = 60.0) -> None:
        """Periodic background maintenance loop started in FastAPI lifespan."""
        while True:
            try:
                await asyncio.sleep(max(1.0, float(interval_seconds)))
                await self.run_maintenance_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("SSH maintenance sweep error: %s", exc)
