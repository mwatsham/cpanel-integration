"""Fernet-backed secret handling with safe configuration errors."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

from .errors import ConfigError


@dataclass(frozen=True)
class SecretCodec:
    """Encrypt and decrypt short secrets using one environment-supplied key."""

    key: bytes

    def __post_init__(self) -> None:
        try:
            Fernet(self.key)
        except (TypeError, ValueError) as exc:
            raise ConfigError("CPANEL_ADMIN_FERNET_KEY is not a valid Fernet key") from exc

    @classmethod
    def from_environment(cls, env: Mapping[str, str]) -> SecretCodec:
        value = env.get("CPANEL_ADMIN_FERNET_KEY")
        if not value:
            raise ConfigError("CPANEL_ADMIN_FERNET_KEY is required")
        try:
            key = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ConfigError("CPANEL_ADMIN_FERNET_KEY is not a valid Fernet key") from exc
        return cls(key)

    def encrypt(self, plaintext: str) -> str:
        if not plaintext:
            raise ConfigError("Secret value must not be empty")
        return Fernet(self.key).encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        try:
            raw = Fernet(self.key).decrypt(ciphertext.encode("ascii"))
            return raw.decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError, TypeError) as exc:
            raise ConfigError("Unable to decrypt profile token with the configured key") from exc
