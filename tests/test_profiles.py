import json
import stat
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.errors import ConfigError
from cpanel_admin.profiles import ProfileStore, default_profile_path
from cpanel_admin.secrets import SecretCodec


def test_add_profile_encrypts_token_and_round_trips(tmp_path: Path) -> None:
    codec = SecretCodec(Fernet.generate_key())
    path = tmp_path / "profiles.json"
    store = ProfileStore(path)
    store.add("production", "cpanel.example.com", "account", "secret-token", codec)
    raw = path.read_text()
    assert "secret-token" not in raw
    profile = store.get("production")
    assert codec.decrypt(profile.encrypted_token) == "secret-token"
    assert json.loads(raw)["version"] == 1
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_add_requires_replace_for_existing_profile(tmp_path: Path) -> None:
    codec = SecretCodec(Fernet.generate_key())
    store = ProfileStore(tmp_path / "profiles.json")
    store.add("production", "cpanel.example.com", "account", "one", codec)
    with pytest.raises(ConfigError, match="already exists"):
        store.add("production", "cpanel.example.com", "account", "two", codec)
    replaced = store.add(
        "production", "cpanel2.example.com", "account2", "two", codec, replace=True
    )
    assert replaced.host == "cpanel2.example.com"
    assert codec.decrypt(replaced.encrypted_token) == "two"


@pytest.mark.parametrize(
    ("name", "host", "username", "message"),
    [
        ("Production", "cpanel.example.com", "account", "profile name"),
        ("production", "https://cpanel.example.com", "account", "host"),
        ("production", "cpanel.example.com/path", "account", "host"),
        ("production", "cpanel.example.com", "bad-user", "username"),
    ],
)
def test_profile_validation_rejects_unsafe_values(
    tmp_path: Path, name: str, host: str, username: str, message: str
) -> None:
    store = ProfileStore(tmp_path / "profiles.json")
    codec = SecretCodec(Fernet.generate_key())
    with pytest.raises(ConfigError, match=message):
        store.add(name, host, username, "token", codec)


def test_list_is_sorted_and_remove_returns_profile(tmp_path: Path) -> None:
    codec = SecretCodec(Fernet.generate_key())
    store = ProfileStore(tmp_path / "profiles.json")
    store.add("zeta", "zeta.example.com", "account", "one", codec)
    store.add("alpha", "alpha.example.com", "account", "two", codec)
    assert [profile.name for profile in store.list()] == ["alpha", "zeta"]
    assert store.remove("alpha").name == "alpha"
    with pytest.raises(ConfigError, match="not found"):
        store.get("alpha")


def test_rotate_reencrypts_every_profile_atomically(tmp_path: Path) -> None:
    old = SecretCodec(Fernet.generate_key())
    new = SecretCodec(Fernet.generate_key())
    store = ProfileStore(tmp_path / "profiles.json")
    store.add("one", "one.example.com", "account", "token-one", old)
    store.add("two", "two.example.com", "account", "token-two", old)
    assert store.rotate(old, new) == 2
    assert new.decrypt(store.get("one").encrypted_token) == "token-one"
    assert new.decrypt(store.get("two").encrypted_token) == "token-two"
    with pytest.raises(ConfigError):
        old.decrypt(store.get("one").encrypted_token)


def test_malformed_store_and_version_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text("not json")
    with pytest.raises(ConfigError, match="valid JSON"):
        ProfileStore(path).list()
    path.write_text('{"version": 2, "profiles": {}}')
    with pytest.raises(ConfigError, match="version"):
        ProfileStore(path).list()


def test_default_profile_path_honors_explicit_and_xdg_environment(tmp_path: Path) -> None:
    explicit = tmp_path / "custom.json"
    assert default_profile_path({"CPANEL_ADMIN_CONFIG": str(explicit)}) == explicit
    assert default_profile_path({"XDG_CONFIG_HOME": str(tmp_path)}) == (
        tmp_path / "cpanel-admin" / "profiles.json"
    )
