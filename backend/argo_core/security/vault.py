"""Fernet-backed encrypted credential vault for SQLite secrets."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from typing import Any

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

_PLACEHOLDER_KEYS = {"", "CHANGE_ME_FERNET_BASE64_KEY"}
_TELEGRAM_TOKEN_RE = re.compile(r"(?:bot)?\d{5,}:[A-Za-z0-9_-]{20,}")
_API_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}")
_GOOGLE_ACCESS_TOKEN_RE = re.compile(r"\bya29\.[A-Za-z0-9._-]{12,}")
_GOOGLE_REFRESH_TOKEN_RE = re.compile(r"\b1//[A-Za-z0-9._-]{12,}")
_GOOGLE_CLIENT_SECRET_RE = re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{10,}")
_BEARER_TOKEN_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")


def redact_secrets(text: str, secrets: Iterable[str] = ()) -> str:
    """Scrub explicit secrets and recognizable API/OAuth/Telegram tokens from diagnostic strings."""
    cleaned = text
    for secret in secrets:
        if isinstance(secret, str) and len(secret.strip()) >= 6:
            cleaned = cleaned.replace(secret.strip(), "<REDACTED>")
    cleaned = _TELEGRAM_TOKEN_RE.sub("<REDACTED_TELEGRAM_TOKEN>", cleaned)
    cleaned = _API_KEY_RE.sub("<REDACTED_API_KEY>", cleaned)
    cleaned = _GOOGLE_ACCESS_TOKEN_RE.sub("<REDACTED_OAUTH_ACCESS_TOKEN>", cleaned)
    cleaned = _GOOGLE_REFRESH_TOKEN_RE.sub("<REDACTED_OAUTH_REFRESH_TOKEN>", cleaned)
    cleaned = _GOOGLE_CLIENT_SECRET_RE.sub("<REDACTED_CLIENT_SECRET>", cleaned)
    cleaned = _BEARER_TOKEN_RE.sub("Bearer <REDACTED_TOKEN>", cleaned)
    return cleaned


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
