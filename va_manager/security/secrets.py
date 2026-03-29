"""Helpers for encrypting secrets stored by the VA manager.

The backend stores scanner credentials only in encrypted form so accidental
database disclosure does not immediately expose reusable passwords. Decryption
is intentionally limited to the execution path that hands credentials to a
scanner, and callers must avoid logging returned plaintext values.
"""

from __future__ import annotations

import os
from base64 import urlsafe_b64encode
from functools import lru_cache
from hashlib import sha256

from cryptography.fernet import Fernet, InvalidToken

from va_manager.config import ENCRYPTION_KEY


class SecretManager:
    """Encrypt and decrypt application secrets using Fernet.

    Existing deployments may still have plaintext credentials from before
    encryption was introduced. For backward compatibility, invalid Fernet
    payloads are treated as legacy plaintext and returned unchanged so old
    assets continue to scan until they are rotated or re-saved.
    """

    def __init__(self, key: str | None = None) -> None:
        configured_key = key or os.getenv("SWAN_SECRET_KEY") or ENCRYPTION_KEY
        if not configured_key:
            raise RuntimeError("Credential encryption key is not configured.")

        normalized_key = self._normalize_key(configured_key)
        self.fernet = Fernet(normalized_key)

    def encrypt(self, value: str) -> str:
        """Encrypt a secret for database storage."""

        return self.fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt(self, value: str) -> str:
        """Decrypt a stored secret.

        If the payload is not a valid Fernet token, return it unchanged to
        support legacy plaintext rows during the migration period.
        """

        try:
            return self.fernet.decrypt(value.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            return value

    @staticmethod
    def _normalize_key(key: str) -> bytes:
        """Normalize configured secret text into a stable Fernet-compatible key."""

        return urlsafe_b64encode(sha256(key.encode("utf-8")).digest())


@lru_cache(maxsize=1)
def get_secret_manager() -> SecretManager:
    """Create and cache the process-local secret manager."""

    return SecretManager()


secret_manager = get_secret_manager()


def encrypt_secret(plain: str) -> str:
    """Encrypt a secret string for database storage."""

    return secret_manager.encrypt(plain)


def decrypt_secret(encrypted: str) -> str:
    """Decrypt a database secret into plaintext for short-lived runtime use."""

    return secret_manager.decrypt(encrypted)
