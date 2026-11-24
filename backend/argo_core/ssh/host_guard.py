"""Dual-mode Zero-ACL SSH host guard, anti-self-pivot validator, and TOFU host key pinning."""

from __future__ import annotations

import hmac
import ipaddress
import os
import re
import socket
import struct
import urllib.parse
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

try:
    import psutil  # type: ignore[import-not-found]
except ImportError:
    psutil = None

_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_BENCHMARK_NET = ipaddress.ip_network("198.18.0.0/15")
_DISALLOWED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "argo-core",
        "valkey",
        "oauth2-proxy",
        "host.docker.internal",
        "metadata.google.internal",
    }
)
_DISALLOWED_SUFFIXES = (".localhost", ".local", ".internal")

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_BRACKETED_IPV6_RE = re.compile(r"\[([0-9a-fA-F:]+)\](?::\d{1,5})?")
_SSH_URI_RE = re.compile(r"\bssh://(?:[^@\s/]+@)?(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(?::\d{1,5})?")
_USER_AT_HOST_RE = re.compile(r"(?<![a-zA-Z0-9_.+-])[^@\s/]+@(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(?::\d{1,5})?")
_FQDN_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)\b")
_EXPLICIT_HOST_DIRECTIVE_RE = re.compile(
    r"(?:\bssh\b(?:\s+-[A-Za-z0-9]+(?:\s+\S+)?)*|\b(?:host|server|target_host|hostname)\s*[:=]?)\s+(?:\[([0-9a-fA-F:]+)\]|([a-zA-Z0-9][a-zA-Z0-9.-]*))(?::\d{1,5})?",
    re.IGNORECASE,
)


class SSHTargetBlockedError(PermissionError):
    """Raised when an SSH target points to loopback, metadata, container internals, or local host."""


class RogueSSHDBlockedError(PermissionError):
    """Raised when an Option B target host is not literally present in trusted operator text."""


class SSHHostKeyMismatchError(PermissionError):
    """Raised when a remote SSH server's host public key differs from its pinned key."""


def _detect_local_self_and_gateway_ips() -> set[str]:
    """Collect local interface IPs and container default gateway IPs to block self-pivoting."""
    blocked: set[str] = {"172.17.0.1"}

    if psutil is not None:
        try:
            for _ifname, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    raw = str(getattr(addr, "address", "") or "").split("%", 1)[0].strip()
                    if not raw:
                        continue
                    try:
                        ip_obj = ipaddress.ip_address(raw)
                    except ValueError:
                        continue
                    if not ip_obj.is_loopback and not ip_obj.is_link_local:
                        blocked.add(str(ip_obj))
        except Exception:
            pass
    else:
        fib_path = Path("/proc/net/fib_trie")
        if fib_path.is_file():
            try:
                lines = fib_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                for idx, line in enumerate(lines):
                    stripped = line.strip()
                    if stripped.startswith("|-- ") and idx + 1 < len(lines):
                        if "/32 host LOCAL" in lines[idx + 1]:
                            cand = stripped[4:].strip()
                            try:
                                ip_obj = ipaddress.ip_address(cand)
                                if not ip_obj.is_loopback and not ip_obj.is_link_local:
                                    blocked.add(str(ip_obj))
                            except ValueError:
                                pass
            except Exception:
                pass

    try:
        hostname = socket.gethostname()
        for _, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
            raw = str(sockaddr[0]).split("%", 1)[0].strip()
            if raw:
                blocked.add(raw)
    except Exception:
        pass

    route_path = Path("/proc/net/route")
    if route_path.is_file():
        try:
            for line in route_path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000" and parts[2] != "00000000":
                    gw_int = int(parts[2], 16)
                    gw_ip = socket.inet_ntoa(struct.pack("<L", gw_int))
                    blocked.add(gw_ip)
        except Exception:
            pass

    if os.path.exists("/.dockerenv"):
        # Standard rootless/bridge default gateways if route file was restricted
        blocked.add("172.17.0.1")

    return blocked


def _check_ssh_ip_obj(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    local_ips: set[str],
) -> tuple[bool, str]:
    """Validate an IP address for SSH: allow operator LAN/CGNAT while blocking self-pivot targets."""
    if addr.is_loopback:
        return True, f"Loopback address '{addr}' is disallowed for SSH."
    if addr.is_unspecified:
        return True, f"Unspecified address '{addr}' is disallowed for SSH."
    if addr.is_link_local:
        return True, f"Link-local/metadata address '{addr}' is disallowed for SSH."
    if addr.is_multicast:
        return True, f"Multicast address '{addr}' is disallowed for SSH."
    if isinstance(addr, ipaddress.IPv4Address) and addr in _BENCHMARK_NET:
        return True, f"Benchmark address '{addr}' is disallowed for SSH."
    if str(addr) in local_ips:
        return True, f"Argo host/container address '{addr}' is disallowed for SSH self-pivot protection."

    # Explicitly permit RFC1918 private LAN (except local_ips above), IPv6 ULA, and VPN CGNAT (100.64.0.0/10)
    if addr.is_private:
        return False, ""
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NET:
        return False, ""
    if addr.is_reserved:
        return True, f"Reserved address '{addr}' is disallowed for SSH."
    return False, ""


def is_blocked_ssh_ip(
    raw_ip: str,
    *,
    local_ips: set[str] | None = None,
) -> tuple[bool, str]:
    """Return (blocked, reason) for an IPv4/IPv6 literal targeting loopback, metadata, or Argo itself."""
    candidate = str(raw_ip or "").strip().strip("[]")
    if not candidate:
        return True, "Empty SSH target IP is disallowed."
    if "%" in candidate:
        return True, f"Scoped link-local IP address '{candidate}' is disallowed."
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return True, f"Malformed IP address '{candidate}'."

    resolved_local = local_ips if local_ips is not None else _detect_local_self_and_gateway_ips()
    blocked, reason = _check_ssh_ip_obj(addr, local_ips=resolved_local)
    if blocked:
        return True, reason

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        mapped_blocked, mapped_reason = _check_ssh_ip_obj(
            addr.ipv4_mapped,
            local_ips=resolved_local,
        )
        if mapped_blocked:
            return True, f"IPv4-mapped address '{addr}' rejected: {mapped_reason}"
    return False, ""


def _default_ssh_dns_resolve(hostname: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for _, _, _, _, sockaddr in infos:
        ip_str = str(sockaddr[0])
        if ip_str not in seen:
            seen.append(ip_str)
    return seen


def normalize_ssh_host(raw_host: str) -> tuple[str, int | None]:
    """Strip whitespace/brackets/ssh:// scheme and split optional inline :port."""
    cleaned = str(raw_host or "").strip()
    if not cleaned:
        return "", None
    if cleaned.lower().startswith("ssh://"):
        parsed = urllib.parse.urlsplit(cleaned)
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        return host, parsed.port
    if "@" in cleaned and not cleaned.startswith("["):
        cleaned = cleaned.rsplit("@", 1)[1].strip()
    if cleaned.startswith("["):
        if "]:" in cleaned:
            h_part, p_part = cleaned[1:].split("]:", 1)
            port_val = int(p_part) if p_part.isdigit() else None
            return h_part.strip().lower().rstrip("."), port_val
        return cleaned.strip("[]").strip().lower().rstrip("."), None
    if cleaned.count(":") == 1:
        h_part, p_part = cleaned.split(":", 1)
        if p_part.isdigit():
            return h_part.strip().lower().rstrip("."), int(p_part)
    return cleaned.lower().rstrip("."), None


def validate_ssh_target_not_self_with_ip(
    host: str,
    port: int = 22,
    *,
    resolve_dns: bool = True,
    resolver: Callable[[str, int], list[str]] | None = None,
    local_ips: set[str] | None = None,
) -> tuple[str, int, str | None]:
    """Validate SSH host/port and return (normalized_host, port, first_pinned_ip)."""
    norm_host, inline_port = normalize_ssh_host(host)
    if inline_port is not None and port == 22:
        port = inline_port
    if not norm_host:
        raise SSHTargetBlockedError("SSH target host cannot be empty.")
    if any(ch.isspace() or ch in {"/", "\\", ";", "&", "|", "$", "`"} for ch in norm_host):
        raise SSHTargetBlockedError(f"Invalid SSH target hostname '{norm_host}'.")
    try:
        port_num = int(port)
    except (TypeError, ValueError) as exc:
        raise SSHTargetBlockedError(f"Invalid SSH port '{port}'.") from exc
    if port_num < 1 or port_num > 65535:
        raise SSHTargetBlockedError(f"SSH port {port_num} is outside allowed range 1..65535.")

    if norm_host in _DISALLOWED_HOSTNAMES or norm_host.endswith(_DISALLOWED_SUFFIXES):
        raise SSHTargetBlockedError(
            f"Internal/container hostname '{norm_host}' is disallowed for SSH."
        )

    resolved_local = local_ips if local_ips is not None else _detect_local_self_and_gateway_ips()

    try:
        ip_literal = ipaddress.ip_address(norm_host.split("%", 1)[0])
    except ValueError:
        ip_literal = None

    if ip_literal is not None or "%" in norm_host:
        blocked, reason = is_blocked_ssh_ip(norm_host, local_ips=resolved_local)
        if blocked:
            raise SSHTargetBlockedError(reason)
        ip_text = str(ip_literal)
        return ip_text, port_num, ip_text

    pinned_ip: str | None = None
    if resolver is not None or resolve_dns:
        try:
            ips = (
                resolver(norm_host, port_num)
                if resolver is not None
                else _default_ssh_dns_resolve(norm_host, port_num)
            )
        except OSError as exc:
            raise SSHTargetBlockedError(
                f"DNS resolution failed for SSH host '{norm_host}': {exc}"
            ) from exc
        if not ips:
            raise SSHTargetBlockedError(f"SSH host '{norm_host}' did not resolve to any address.")
        for ip_str in ips:
            blocked, reason = is_blocked_ssh_ip(ip_str, local_ips=resolved_local)
            if blocked:
                raise SSHTargetBlockedError(
                    f"SSH host '{norm_host}' resolved to disallowed IP '{ip_str}': {reason}"
                )
        pinned_ip = str(ips[0])

    return norm_host, port_num, pinned_ip


def validate_ssh_target_not_self(
    host: str,
    port: int = 22,
    *,
    resolve_dns: bool = True,
    resolver: Callable[[str, int], list[str]] | None = None,
    local_ips: set[str] | None = None,
) -> tuple[str, int]:
    """Validate SSH host/port against anti-self-pivot, loopback, metadata, and local container IPs."""
    norm_host, port_num, _ = validate_ssh_target_not_self_with_ip(
        host,
        port,
        resolve_dns=resolve_dns,
        resolver=resolver,
        local_ips=local_ips,
    )
    return norm_host, port_num


def extract_literal_hosts(trusted_texts: Iterable[str]) -> set[str]:
    """Deterministically extract allowed literal IPs/hostnames strictly from operator-authored text."""
    hosts: set[str] = set()
    for raw in trusted_texts:
        text = str(raw or "")
        if not text.strip():
            continue
        for match in _IPV4_RE.finditer(text):
            hosts.add(match.group(0).lower())
        for match in _BRACKETED_IPV6_RE.finditer(text):
            candidate = match.group(1).strip().lower()
            try:
                hosts.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                pass
        for match in _SSH_URI_RE.finditer(text):
            h, _ = normalize_ssh_host(match.group(1))
            if h:
                hosts.add(h)
        for match in _USER_AT_HOST_RE.finditer(text):
            h, _ = normalize_ssh_host(match.group(1))
            if h:
                hosts.add(h)
        for match in _FQDN_RE.finditer(text):
            h = match.group(1).strip().lower().rstrip(".")
            if h:
                hosts.add(h)
        for match in _EXPLICIT_HOST_DIRECTIVE_RE.finditer(text):
            token = (match.group(1) or match.group(2) or "").strip()
            h, _ = normalize_ssh_host(token)
            if h and h not in {"-p", "-i", "-l", "-o"}:
                hosts.add(h)
        # Also detect raw IPv6 tokens separated by whitespace
        for tok in re.split(r"[\s,;()\"'<>]+", text):
            if ":" in tok:
                cand = tok.strip("[]").split("%", 1)[0]
                try:
                    ip_obj = ipaddress.ip_address(cand)
                    if isinstance(ip_obj, ipaddress.IPv6Address):
                        hosts.add(str(ip_obj))
                except ValueError:
                    pass
    return hosts


def resolve_authorized_ssh_target_with_ip(
    *,
    vault_entry: dict[str, Any],
    requested_host: str | None = None,
    requested_port: int | str | None = None,
    trusted_operator_texts: Iterable[str] = (),
    resolve_dns: bool = True,
    resolver: Callable[[str, int], list[str]] | None = None,
    local_ips: set[str] | None = None,
) -> tuple[str, int, str | None]:
    """Resolve and enforce Dual-Mode SSH Host Guard and return (host, port, pinned_ip)."""
    pinned_host = str(vault_entry.get("host") or "").strip()
    raw_vault_port = str(vault_entry.get("port") or "22").strip() or "22"
    try:
        vault_port = int(raw_vault_port)
    except ValueError:
        vault_port = 22

    # Option A: Host-Pinned Vault Entry -> completely ignore any LLM-supplied host/port overrides
    if pinned_host:
        return validate_ssh_target_not_self_with_ip(
            pinned_host,
            vault_port,
            resolve_dns=resolve_dns,
            resolver=resolver,
            local_ips=local_ips,
        )

    # Option B: Shared Credential + Operator-Literal Guard
    norm_req_host, inline_port = normalize_ssh_host(str(requested_host or ""))
    if not norm_req_host:
        raise RogueSSHDBlockedError(
            "No target server host provided for shared SSH Vault credential. "
            "Specify a literal server hostname or IP in your message."
        )

    allowed_hosts = extract_literal_hosts(trusted_operator_texts)
    if norm_req_host not in allowed_hosts:
        raise RogueSSHDBlockedError(
            f"Blocked SSH target '{norm_req_host}': host was not explicitly specified in operator prompt or routine instructions."
        )

    chosen_port = vault_port
    if inline_port is not None:
        chosen_port = inline_port
    elif requested_port is not None and str(requested_port).strip():
        try:
            chosen_port = int(str(requested_port).strip())
        except ValueError as exc:
            raise SSHTargetBlockedError(f"Invalid SSH port '{requested_port}'.") from exc

    return validate_ssh_target_not_self_with_ip(
        norm_req_host,
        chosen_port,
        resolve_dns=resolve_dns,
        resolver=resolver,
        local_ips=local_ips,
    )


def resolve_authorized_ssh_target(
    *,
    vault_entry: dict[str, Any],
    requested_host: str | None = None,
    requested_port: int | str | None = None,
    trusted_operator_texts: Iterable[str] = (),
    resolve_dns: bool = True,
    resolver: Callable[[str, int], list[str]] | None = None,
    local_ips: set[str] | None = None,
) -> tuple[str, int]:
    """Resolve and enforce Dual-Mode SSH Host Guard (Option A pinned vs Option B operator-literal)."""
    norm_host, port_num, _ = resolve_authorized_ssh_target_with_ip(
        vault_entry=vault_entry,
        requested_host=requested_host,
        requested_port=requested_port,
        trusted_operator_texts=trusted_operator_texts,
        resolve_dns=resolve_dns,
        resolver=resolver,
        local_ips=local_ips,
    )
    return norm_host, port_num


def verify_or_pin_host_key(
    *,
    repo: Any,
    vault_slug: str,
    host: str,
    port: int,
    key_type: str,
    key_b64: str,
    decrypted_vault_entry: dict[str, Any] | None = None,
) -> str:
    """Enforce TOFU SSH host key pinning on vault_secrets.pinned_host_keys."""
    clean_host_port = f"{host.strip().lower()}:{int(port)}"
    entry = decrypted_vault_entry or repo.get_vault_secret_decrypted(vault_slug)
    if entry is None:
        raise SSHTargetBlockedError(f"SSH Vault secret '@{vault_slug}' not found.")

    pinned_map = entry.get("pinned_host_keys") or {}
    existing = pinned_map.get(clean_host_port)
    clean_type = str(key_type or "").strip()
    clean_b64 = str(key_b64 or "").strip()

    if existing is None:
        updated_meta = repo.pin_vault_host_key(
            vault_slug,
            host,
            int(port),
            clean_type,
            clean_b64,
        )
        return str((updated_meta.get("host_key_fingerprints") or {}).get(clean_host_port) or "")

    if isinstance(existing, dict):
        expected_type = str(existing.get("key_type") or "").strip()
        expected_b64 = str(existing.get("key_b64") or "").strip()
        expected_fp = str(existing.get("fingerprint") or "").strip()
    else:
        parts = str(existing).strip().split(None, 1)
        expected_type = parts[0] if parts else ""
        expected_b64 = parts[1] if len(parts) > 1 else parts[0]
        expected_fp = ""

    type_ok = hmac.compare_digest(expected_type, clean_type)
    key_ok = hmac.compare_digest(expected_b64, clean_b64)
    if not (type_ok and key_ok):
        raise SSHHostKeyMismatchError(
            f"Server identity key changed for {clean_host_port} — verify before reconnecting "
            "or click 'Reset Server Key' in Settings -> Secrets Vault."
        )
    return f"{expected_type} {expected_fp}".strip()
