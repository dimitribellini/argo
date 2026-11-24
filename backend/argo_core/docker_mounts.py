"""Translate container-local bind paths to host source paths via Docker self-inspection."""

from __future__ import annotations

import contextlib
import posixpath
import socket
from typing import Any


def _extract_bind_mounts(attrs: Any) -> list[tuple[str, str]]:
    """Extract normalized (destination, source) bind mount pairs sorted longest-dest-first."""
    if not isinstance(attrs, dict):
        return []
    raw_mounts = attrs.get("Mounts")
    if not isinstance(raw_mounts, list):
        return []
    mounts: list[tuple[str, str]] = []
    for item in raw_mounts:
        if not isinstance(item, dict):
            continue
        mount_type = item.get("Type")
        if mount_type not in (None, "", "bind"):
            continue
        raw_src = str(item.get("Source") or "").strip()
        raw_dst = str(item.get("Destination") or "").strip()
        if not raw_src.startswith("/") or not raw_dst.startswith("/"):
            continue
        mounts.append((posixpath.normpath(raw_dst), posixpath.normpath(raw_src)))
    mounts.sort(key=lambda pair: len(pair[0]), reverse=True)
    return mounts


def _get_self_bind_mounts(
    client: Any,
    *,
    hostname: str | None = None,
) -> list[tuple[str, str]]:
    """Inspect the running argo-core container's Docker bind mounts."""
    if hostname is None:
        cached = getattr(client, "_argo_self_bind_mounts", None)
        if isinstance(cached, list):
            return cached

    containers = getattr(client, "containers", None)
    if containers is None:
        return []

    host_id = str(hostname or "").strip() or socket.gethostname()
    mounts: list[tuple[str, str]] = []

    if hasattr(containers, "get") and host_id:
        with contextlib.suppress(Exception):
            ctr = containers.get(host_id)
            mounts = _extract_bind_mounts(getattr(ctr, "attrs", None))

    if not mounts and hasattr(containers, "list"):
        with contextlib.suppress(Exception):
            for ctr in containers.list():
                attrs = getattr(ctr, "attrs", None)
                if not isinstance(attrs, dict):
                    continue
                cfg = attrs.get("Config")
                ctr_hostname = str(cfg.get("Hostname") or "").strip() if isinstance(cfg, dict) else ""
                if ctr_hostname == host_id:
                    mounts = _extract_bind_mounts(attrs)
                    if mounts:
                        break

    if hostname is None:
        with contextlib.suppress(Exception):
            setattr(client, "_argo_self_bind_mounts", mounts)

    return mounts


def resolve_host_bind_path(
    client: Any,
    container_path: str,
    *,
    hostname: str | None = None,
) -> str:
    """Translate a container-visible path inside argo-core to the real host path for sibling binds."""
    raw = str(container_path or "").strip()
    if not raw or not raw.startswith("/"):
        return container_path
    target = posixpath.normpath(raw)
    for dest, src in _get_self_bind_mounts(client, hostname=hostname):
        if target == dest:
            return src
        prefix = "/" if dest == "/" else dest.rstrip("/") + "/"
        if target.startswith(prefix):
            rel = target[len(prefix):]
            return posixpath.normpath(posixpath.join(src, rel))
    return container_path
