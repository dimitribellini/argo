"""Fernet-backed encrypted credential vault for SQLite secrets."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

_PLACEHOLDER_KEYS = {"", "CHANGE_ME_FERNET_BASE64_KEY"}
_TELEGRAM_TOKEN_RE = re.compile(r"(?:bot)?\d{5,}:[A-Za-z0-9_-]{20,}")
_API_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}")
_GEMINI_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")
_XAI_KEY_RE = re.compile(r"\bxai-[A-Za-z0-9_-]{20,}")
_GITHUB_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"
)
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_GOOGLE_ACCESS_TOKEN_RE = re.compile(r"\bya29\.[A-Za-z0-9._-]{12,}")
_GOOGLE_REFRESH_TOKEN_RE = re.compile(r"\b1//[A-Za-z0-9._-]{12,}")
_GOOGLE_CLIENT_SECRET_RE = re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{10,}")
_BEARER_TOKEN_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")


def redact_secrets(text: str, secrets: Iterable[str] = ()) -> str:
    """Scrub explicit secrets and recognizable API/OAuth/Telegram tokens from diagnostic strings."""
    cleaned = text
    sorted_secrets = sorted(
        {
            s.strip()
            for s in secrets
            if isinstance(s, str) and len(s.strip()) >= 6
        },
        key=len,
        reverse=True,
    )
    for secret in sorted_secrets:
        cleaned = cleaned.replace(secret, "<REDACTED>")
    cleaned = _PEM_PRIVATE_KEY_RE.sub("<REDACTED_PRIVATE_KEY>", cleaned)
    cleaned = _TELEGRAM_TOKEN_RE.sub("<REDACTED_TELEGRAM_TOKEN>", cleaned)
    cleaned = _API_KEY_RE.sub("<REDACTED_API_KEY>", cleaned)
    cleaned = _GEMINI_KEY_RE.sub("<REDACTED_API_KEY>", cleaned)
    cleaned = _XAI_KEY_RE.sub("<REDACTED_API_KEY>", cleaned)
    cleaned = _GITHUB_TOKEN_RE.sub("<REDACTED_TOKEN>", cleaned)
    cleaned = _AWS_KEY_RE.sub("<REDACTED_API_KEY>", cleaned)
    cleaned = _SLACK_TOKEN_RE.sub("<REDACTED_TOKEN>", cleaned)
    cleaned = _GOOGLE_ACCESS_TOKEN_RE.sub("<REDACTED_OAUTH_ACCESS_TOKEN>", cleaned)
    cleaned = _GOOGLE_REFRESH_TOKEN_RE.sub("<REDACTED_OAUTH_REFRESH_TOKEN>", cleaned)
    cleaned = _GOOGLE_CLIENT_SECRET_RE.sub("<REDACTED_CLIENT_SECRET>", cleaned)
    cleaned = _BEARER_TOKEN_RE.sub("Bearer <REDACTED_TOKEN>", cleaned)
    return cleaned


def _has_existing_encrypted_rows(conn: sqlite3.Connection) -> bool:
    """Return True when SQLite already contains encrypted credentials or secrets."""
    checks = (
        "SELECT 1 FROM oauth_accounts LIMIT 1",
        "SELECT 1 FROM model_providers WHERE encrypted_api_key IS NOT NULL LIMIT 1",
        "SELECT 1 FROM collection_documents WHERE collection = 'vault_secrets' LIMIT 1",
    )
    for query in checks:
        try:
            if conn.execute(query).fetchone() is not None:
                return True
        except sqlite3.Error:
            continue
    return False


def resolve_or_persist_master_key(
    master_key: str | None,
    db_path: str | Path,
    conn: sqlite3.Connection,
) -> tuple[str, str]:
    """Resolve ARGO_MASTER_KEY from env or persist a 0o600 key alongside the DB; fail closed on missing key for existing encrypted DBs."""
    raw_key = (master_key or "").strip()
    if raw_key not in _PLACEHOLDER_KEYS:
        try:
            Fernet(raw_key.encode("utf-8"))
        except Exception as exc:
            raise RuntimeError("ARGO_MASTER_KEY is invalid; expected a URL-safe base64 32-byte Fernet key.") from exc
        return raw_key, "env"

    db_str = str(db_path)
    if db_str == ":memory:":
        logger.warning(
            "ARGO_MASTER_KEY is unset or placeholder on :memory: DB; using an ephemeral runtime Fernet key."
        )
        return Fernet.generate_key().decode("ascii"), "ephemeral"

    key_file = Path(db_str).resolve().parent / ".argo_master_key"
    if key_file.is_file():
        try:
            persisted = key_file.read_text(encoding="utf-8").strip()
            Fernet(persisted.encode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                f"Persisted vault key file '{key_file}' is unreadable or invalid."
            ) from exc
        logger.warning(
            "ARGO_MASTER_KEY env var is unset/placeholder; loaded persisted Fernet key from '%s'. "
            "Configure ARGO_MASTER_KEY in compose.yml for explicit backup portability.",
            key_file,
        )
        return persisted, "file"

    if _has_existing_encrypted_rows(conn):
        raise RuntimeError(
            "ARGO_MASTER_KEY is unset/placeholder and no persisted .argo_master_key file exists, "
            "yet encrypted credentials already exist in SQLite. Refusing startup to prevent "
            "permanent credential loss; supply the original ARGO_MASTER_KEY."
        )

    generated = Fernet.generate_key().decode("ascii")
    key_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, (generated + "\n").encode("ascii"))
        finally:
            os.close(fd)
        os.chmod(str(key_file), 0o600)
    except FileExistsError:
        persisted = key_file.read_text(encoding="utf-8").strip()
        Fernet(persisted.encode("utf-8"))
        return persisted, "file"
    logger.warning(
        "ARGO_MASTER_KEY is unset or placeholder; generated and persisted a 0o600 Fernet key at '%s'. "
        "Back up this key or configure ARGO_MASTER_KEY in compose.yml.",
        key_file,
    )
    return generated, "file"


class SecretVault:
    """Encrypts and decrypts secrets at rest using cryptography.fernet."""

    def __init__(self, master_key: str | None = None) -> None:
        raw_key = (master_key or "").strip()
        if raw_key in _PLACEHOLDER_KEYS:
            logger.warning(
                "ARGO_MASTER_KEY is unset or placeholder; using an ephemeral runtime Fernet key."
            )
            self._fernet = Fernet(Fernet.generate_key())
            self.is_configured = False
        else:
            self._fernet = Fernet(raw_key.encode("utf-8"))
            self.is_configured = True

    def derive_scoped_token(self, scope: str) -> str:
        """Derive a deterministic HMAC-SHA256 hex token scoped to an internal component."""
        signing_key = getattr(self._fernet, "_signing_key", b"")
        return hmac.new(signing_key, scope.encode("utf-8"), hashlib.sha256).hexdigest()

    def encrypt_str(self, plaintext: str) -> bytes:
        """Encrypt a UTF-8 plaintext string into a Fernet token."""
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt_str(self, token: bytes) -> str:
        """Decrypt a Fernet token into a UTF-8 plaintext string."""
        return self._fernet.decrypt(token).decode("utf-8")

    def encrypt_json(self, payload: dict[str, Any]) -> bytes:
        """Serialize a dict as JSON and encrypt it."""
        return self.encrypt_str(json.dumps(payload, sort_keys=True))

    def decrypt_json(self, token: bytes) -> dict[str, Any]:
        """Decrypt a Fernet token and deserialize it as a JSON dict."""
        data = json.loads(self.decrypt_str(token))
        if not isinstance(data, dict):
            raise ValueError("Decrypted vault payload is not a JSON object.")
        return data
