"""Argo core platform package."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path

_BASE_VERSION = "0.1.0"
_GIT_DESCRIBE_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)-(\d+)-g([0-9a-fA-F]{7,40})$")
_SEMVER_RE = re.compile(r"^[vV]?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?)$")
_BRANCH_SHA_RE = re.compile(r"^(?:main|dev)-([0-9a-fA-F]{7,40})$")
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def _run_git(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=1.5,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def resolve_version_info(
    env: Mapping[str, str] | None = None,
    repo_root: Path | None = None,
) -> tuple[str, str]:
    """Return `(semver_without_v, short_commit_sha)` from CI build env or local git history."""
    source_env = os.environ if env is None else env
    raw_version = str(source_env.get("APP_VERSION") or "").strip()
    raw_commit = str(source_env.get("APP_COMMIT_SHA") or "").strip()

    commit_sha = raw_commit[:7].lower() if _HEX_SHA_RE.match(raw_commit) else ""
    version = ""

    if raw_version and raw_version.lower() != "dev":
        if desc_match := _GIT_DESCRIBE_RE.match(raw_version):
            major, minor, patch, commits_since, desc_sha = desc_match.groups()
            version = f"{major}.{minor}.{int(patch) + int(commits_since)}"
            if not commit_sha:
                commit_sha = desc_sha[:7].lower()
        elif semver_match := _SEMVER_RE.match(raw_version):
            version = semver_match.group(1)
        elif branch_match := _BRANCH_SHA_RE.match(raw_version):
            if not commit_sha:
                commit_sha = branch_match.group(1)[:7].lower()

    if not version or not commit_sha:
        root = repo_root if repo_root is not None else Path(__file__).resolve().parents[2]
        try:
            if (root / ".git").exists():
                if not version:
                    described = _run_git(root, "describe", "--tags", "--match", "v[0-9]*", "--long")
                    if desc_match := _GIT_DESCRIBE_RE.match(described):
                        major, minor, patch, commits_since, desc_sha = desc_match.groups()
                        version = f"{major}.{minor}.{int(patch) + int(commits_since)}"
                        if not commit_sha:
                            commit_sha = desc_sha[:7].lower()
                    else:
                        count_raw = _run_git(root, "rev-list", "--count", "HEAD")
                        if count_raw.isdigit():
                            base_parts = _BASE_VERSION.split(".")
                            version = f"{base_parts[0]}.{base_parts[1]}.{int(count_raw)}"
                if not commit_sha:
                    head_sha = _run_git(root, "rev-parse", "--short=7", "HEAD")
                    if _HEX_SHA_RE.match(head_sha):
                        commit_sha = head_sha[:7].lower()
        except Exception:
            pass

    return (version or _BASE_VERSION, commit_sha)


__version__, __commit__ = resolve_version_info()

__all__ = ["__version__", "__commit__", "resolve_version_info"]
