"""Recursive redaction for user-visible output and error messages."""

from __future__ import annotations

from collections.abc import Mapping

SENSITIVE_KEYS = {
    "token",
    "api_token",
    "password",
    "private_key",
    "authorization",
    "encrypted_token",
    "fernet_key",
}
REDACTED = "[REDACTED]"


def _redact_string(value: str, secrets: tuple[str, ...]) -> str:
    result = value
    for secret in secrets:
        if secret:
            result = result.replace(secret, REDACTED)
    return result


def redact(value: object, secrets: tuple[str, ...] = ()) -> object:
    """Return a shape-preserving copy with known secrets removed."""

    if isinstance(value, str):
        return _redact_string(value, secrets)
    if isinstance(value, Mapping):
        return {
            key: REDACTED
            if isinstance(key, str) and key.lower() in SENSITIVE_KEYS
            else redact(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item, secrets) for item in value)
    return value
