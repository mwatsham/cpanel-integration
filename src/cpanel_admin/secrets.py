"""Fernet-backed secret handling with safe configuration errors."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .errors import ConfigError

MAX_KEY_FILE_BYTES = 4096


def default_fernet_key_path(env: Mapping[str, str]) -> Path:
    """Return the configured or platform-default Fernet key file path."""
    if explicit := env.get("CPANEL_ADMIN_FERNET_KEY_FILE"):
        return Path(explicit).expanduser()
    if xdg := env.get("XDG_CONFIG_HOME"):
        root = Path(xdg).expanduser()
    else:
        root = Path.home() / ".config"
    return root / "cpanel-admin" / "fernet.key"


def _read_key_file(path: Path) -> bytes:
    if path.is_symlink():
        raise ConfigError("Fernet key file must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ConfigError(
            "CPANEL_ADMIN_FERNET_KEY is required, or create a secure key file"
        ) from exc
    except OSError as exc:
        raise ConfigError("Unable to open Fernet key file securely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigError("Fernet key file must be a regular file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ConfigError("Fernet key file must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ConfigError("Fernet key file permissions must be 0600")
        chunks: list[bytes] = []
        remaining = MAX_KEY_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
    except OSError as exc:
        raise ConfigError("Unable to read Fernet key file securely") from exc
    finally:
        os.close(descriptor)
    if len(content) > MAX_KEY_FILE_BYTES:
        raise ConfigError("Fernet key file exceeds the allowed size")
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ConfigError("Fernet key file must contain a single Fernet key") from exc
    value = text.removesuffix("\n").removesuffix("\r")
    if not value or "\n" in value or "\r" in value:
        raise ConfigError("Fernet key file must contain a single Fernet key")
    return value.encode("ascii")


@dataclass(frozen=True)
class SecretCodec:
    """Encrypt and decrypt short secrets using an environment or secure file key."""

    key: bytes

    def __post_init__(self) -> None:
        try:
            Fernet(self.key)
        except (TypeError, ValueError) as exc:
            raise ConfigError("CPANEL_ADMIN_FERNET_KEY is not a valid Fernet key") from exc

    @classmethod
    def from_environment(cls, env: Mapping[str, str]) -> SecretCodec:
        value = env.get("CPANEL_ADMIN_FERNET_KEY")
        if value:
            try:
                key = value.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ConfigError("CPANEL_ADMIN_FERNET_KEY is not a valid Fernet key") from exc
        else:
            key = _read_key_file(default_fernet_key_path(env))
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
