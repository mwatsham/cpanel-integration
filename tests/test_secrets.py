import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.errors import ConfigError
from cpanel_admin.secrets import SecretCodec


def test_secret_codec_round_trip_without_plaintext_in_ciphertext() -> None:
    codec = SecretCodec(Fernet.generate_key())
    ciphertext = codec.encrypt("api-token-value")
    assert "api-token-value" not in ciphertext
    assert codec.decrypt(ciphertext) == "api-token-value"


def test_missing_master_key_has_safe_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="CPANEL_ADMIN_FERNET_KEY is required"):
        SecretCodec.from_environment({"XDG_CONFIG_HOME": str(tmp_path)})


def test_malformed_master_key_has_safe_error() -> None:
    with pytest.raises(ConfigError, match="not a valid Fernet key"):
        SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY": "not-a-key"})


def test_wrong_key_does_not_expose_ciphertext() -> None:
    ciphertext = SecretCodec(Fernet.generate_key()).encrypt("secret-token")
    with pytest.raises(ConfigError, match="Unable to decrypt profile token") as error:
        SecretCodec(Fernet.generate_key()).decrypt(ciphertext)
    assert "secret-token" not in str(error.value)
    assert ciphertext not in str(error.value)


def _write_key(path: Path, key: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key + b"\n")
    path.chmod(mode)


def test_default_secure_key_file_supports_unattended_sessions(tmp_path: Path) -> None:
    key = Fernet.generate_key()
    path = tmp_path / "cpanel-admin" / "fernet.key"
    _write_key(path, key)

    codec = SecretCodec.from_environment({"XDG_CONFIG_HOME": str(tmp_path)})

    assert codec.key == key


def test_explicit_key_file_override_is_supported(tmp_path: Path) -> None:
    key = Fernet.generate_key()
    path = tmp_path / "secrets" / "cpanel.key"
    _write_key(path, key)

    codec = SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY_FILE": str(path)})

    assert codec.key == key


def test_environment_key_takes_precedence_over_key_file(tmp_path: Path) -> None:
    environment_key = Fernet.generate_key()
    file_key = Fernet.generate_key()
    path = tmp_path / "fernet.key"
    _write_key(path, file_key)

    codec = SecretCodec.from_environment(
        {
            "CPANEL_ADMIN_FERNET_KEY": environment_key.decode(),
            "CPANEL_ADMIN_FERNET_KEY_FILE": str(path),
        }
    )

    assert codec.key == environment_key


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o400])
def test_key_file_requires_exact_user_only_permissions(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "fernet.key"
    _write_key(path, Fernet.generate_key(), mode)

    with pytest.raises(ConfigError, match="permissions must be 0600"):
        SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY_FILE": str(path)})


def test_key_file_rejects_symlink_and_non_regular_file(tmp_path: Path) -> None:
    target = tmp_path / "target.key"
    _write_key(target, Fernet.generate_key())
    symlink = tmp_path / "linked.key"
    symlink.symlink_to(target)
    with pytest.raises(ConfigError, match="symbolic link"):
        SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY_FILE": str(symlink)})

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ConfigError, match="regular file"):
        SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY_FILE": str(directory)})


def test_key_file_rejects_wrong_owner_and_malformed_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "fernet.key"
    _write_key(path, Fernet.generate_key())
    monkeypatch.setattr(os, "getuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(ConfigError, match="owned by the current user"):
        SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY_FILE": str(path)})

    monkeypatch.undo()
    path.write_text("first\nsecond\n")
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="single Fernet key"):
        SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY_FILE": str(path)})


def test_key_file_rejects_oversized_and_non_ascii_content(tmp_path: Path) -> None:
    path = tmp_path / "fernet.key"
    path.write_bytes(b"x" * 4097)
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="allowed size"):
        SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY_FILE": str(path)})

    path.write_bytes(b"\xff\n")
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="single Fernet key"):
        SecretCodec.from_environment({"CPANEL_ADMIN_FERNET_KEY_FILE": str(path)})
