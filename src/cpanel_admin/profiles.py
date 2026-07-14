"""Validation and atomic storage for named cPanel profiles."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .secrets import SecretCodec

SCHEMA_VERSION = 1
PROFILE_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")


@dataclass(frozen=True)
class Profile:
    name: str
    host: str
    port: int
    username: str
    encrypted_token: str

    def public_dict(self) -> dict[str, str | int]:
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
        }


def default_profile_path(env: Mapping[str, str] | None = None) -> Path:
    values = os.environ if env is None else env
    if explicit := values.get("CPANEL_ADMIN_CONFIG"):
        return Path(explicit).expanduser()
    if xdg := values.get("XDG_CONFIG_HOME"):
        root = Path(xdg).expanduser()
    else:
        root = Path.home() / ".config"
    return root / "cpanel-admin" / "profiles.json"


def _normalize_host(host: str) -> str:
    if not isinstance(host, str) or not host or host != host.strip():
        raise ConfigError("Invalid cPanel host")
    if any(character in host for character in "/?#@") or "://" in host:
        raise ConfigError("Invalid cPanel host")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ConfigError("Invalid cPanel host") from exc
    if len(ascii_host) > 253 or "." not in ascii_host:
        raise ConfigError("Invalid cPanel host")
    labels = ascii_host.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        raise ConfigError("Invalid cPanel host")
    return ascii_host


def _validate_identity(name: str, host: str, username: str) -> tuple[str, str, str]:
    if not isinstance(name, str) or not PROFILE_RE.fullmatch(name):
        raise ConfigError("Invalid profile name; use lowercase letters, digits, and hyphens")
    normalized_host = _normalize_host(host)
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise ConfigError("Invalid cPanel username")
    return name, normalized_host, username


class ProfileStore:
    """Persist named profiles in a versioned, user-readable-only JSON file."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = default_profile_path() if path is None else Path(path).expanduser()

    def _load_raw(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": SCHEMA_VERSION, "profiles": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"Profile store is not valid JSON: {self.path}") from exc
        if not isinstance(value, dict) or value.get("version") != SCHEMA_VERSION:
            raise ConfigError(f"Unsupported profile store version in {self.path}")
        if not isinstance(value.get("profiles"), dict):
            raise ConfigError(f"Profile store has an invalid profiles object: {self.path}")
        return value

    def _profile_from_raw(self, name: str, raw: object) -> Profile:
        if not isinstance(raw, dict):
            raise ConfigError(f"Profile {name!r} has invalid data")
        try:
            stored_name, host, username = _validate_identity(name, raw["host"], raw["username"])
            port = raw["port"]
            encrypted_token = raw["encrypted_token"]
        except (KeyError, TypeError) as exc:
            raise ConfigError(f"Profile {name!r} has invalid data") from exc
        if port != 2083:
            raise ConfigError(f"Profile {name!r} must use HTTPS port 2083")
        if not isinstance(encrypted_token, str) or not encrypted_token:
            raise ConfigError(f"Profile {name!r} has invalid encrypted token data")
        return Profile(stored_name, host, port, username, encrypted_token)

    def _write_raw(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with suppress(OSError):
            os.chmod(self.path.parent, 0o700)
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                delete=False,
            ) as temporary:
                temporary_name = temporary.name
                os.fchmod(temporary.fileno(), 0o600)
                json.dump(value, temporary, indent=2, sort_keys=True)
                temporary.write("\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_name, self.path)
            temporary_name = None
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise ConfigError(f"Unable to write profile store: {self.path}") from exc
        finally:
            if temporary_name is not None:
                with suppress(OSError):
                    Path(temporary_name).unlink()

    def list(self) -> list[Profile]:
        raw_profiles = self._load_raw()["profiles"]
        return [self._profile_from_raw(name, raw_profiles[name]) for name in sorted(raw_profiles)]

    def get(self, name: str) -> Profile:
        if not isinstance(name, str) or not PROFILE_RE.fullmatch(name):
            raise ConfigError("Invalid profile name; use lowercase letters, digits, and hyphens")
        raw_profiles = self._load_raw()["profiles"]
        if name not in raw_profiles:
            raise ConfigError(f"Profile {name!r} not found")
        return self._profile_from_raw(name, raw_profiles[name])

    def add(
        self,
        name: str,
        host: str,
        username: str,
        token: str,
        codec: SecretCodec,
        *,
        replace: bool = False,
    ) -> Profile:
        name, host, username = _validate_identity(name, host, username)
        if not isinstance(token, str) or not token or token != token.strip():
            raise ConfigError("API token must be non-empty and contain no surrounding whitespace")
        value = self._load_raw()
        raw_profiles = value["profiles"]
        if name in raw_profiles and not replace:
            raise ConfigError(f"Profile {name!r} already exists; use --replace")
        profile = Profile(name, host, 2083, username, codec.encrypt(token))
        raw_profiles[name] = {key: item for key, item in asdict(profile).items() if key != "name"}
        self._write_raw(value)
        return profile

    def remove(self, name: str) -> Profile:
        profile = self.get(name)
        value = self._load_raw()
        del value["profiles"][name]
        self._write_raw(value)
        return profile

    def rotate(self, codec: SecretCodec, new_codec: SecretCodec) -> int:
        value = self._load_raw()
        profiles = [
            self._profile_from_raw(name, raw) for name, raw in sorted(value["profiles"].items())
        ]
        plaintext_tokens = [codec.decrypt(profile.encrypted_token) for profile in profiles]
        for profile, plaintext in zip(profiles, plaintext_tokens, strict=True):
            value["profiles"][profile.name]["encrypted_token"] = new_codec.encrypt(plaintext)
        self._write_raw(value)
        return len(profiles)
