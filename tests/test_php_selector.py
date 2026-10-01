"""Account-only PHP Selector regression and SSH boundary tests."""

import json
import subprocess
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from test_cli import add_profile, invoke


@pytest.fixture
def configured(tmp_path):
    key = Fernet.generate_key().decode()
    env = {"CPANEL_ADMIN_FERNET_KEY": key, "CPANEL_ADMIN_CONFIG": str(tmp_path / "profiles.json")}
    add_profile(env, key)
    code, _, error = invoke(["profiles", "configure-ssh", "test", "--port", "2222"], env=env)
    assert code == 0, error
    return env


class Runner:
    def __init__(self):
        self.calls = []
        self.current = "8.2"
        self.extensions = {"curl": "+", "intl": "-"}
        self.memory = "128M"

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        command = args[-1]
        output = ""
        if "--user-summary" in command:
            output = "8.2 e - s\n8.3 e d -\nnative e - -\n"
        elif "--user-current" in command:
            output = self.current + " 8.2.20 /opt/alt/php82/usr/bin/php-cgi\n"
        elif "--set-user-current=" in command:
            self.current = command.split("--set-user-current=")[1].split()[0]
        elif "--list-user-extensions" in command:
            output = "\n".join(f"{state} {name}" for name, state in self.extensions.items())
        elif "--enable-user-extensions=" in command:
            self.extensions["intl"] = "+"
        elif "--disable-user-extensions=" in command:
            self.extensions["intl"] = "-"
        elif "--print-options" in command:
            output = "TITLE:memory_limit\nDEFAULT:" + self.memory + "\nTYPE:value\n"
        elif "--add-options=" in command:
            self.memory = command.split("--add-options=memory_limit:")[1].split()[0]
        return subprocess.CompletedProcess(args, 0, output, "")


def test_profile_ssh_settings_roundtrip(configured):
    code, result, error = invoke(["profiles", "show", "test"], env=configured)
    assert code == 0, error
    assert result["data"]["ssh"]["port"] == 2222
    assert "encrypted_token" not in json.dumps(result)


def test_read_reports_audit_failure(configured, monkeypatch):
    from cpanel_admin.audit import AuditWriter

    monkeypatch.setattr(subprocess, "run", Runner())
    monkeypatch.setattr(AuditWriter, "write", lambda *args, **kwargs: False)
    code, result, error = invoke(["--profile", "test", "php-selector", "versions"], env=configured)
    assert code == 0, error
    assert result["warnings"] == ["Unable to write protected audit record"]


def test_versions_uses_fixed_secure_account_command(configured, monkeypatch):
    runner = Runner()
    monkeypatch.setattr(subprocess, "run", runner)
    code, result, error = invoke(["--profile", "test", "php-selector", "versions"], env=configured)
    assert code == 0, error
    assert result["data"]["8.3"]["enabled"] is True
    args, kwargs = runner.calls[0]
    assert args[0] == "/usr/bin/ssh"
    assert "StrictHostKeyChecking=yes" in args
    assert "BatchMode=yes" in args
    assert "ForwardAgent=no" in args
    assert args[-1] == "/usr/bin/selectorctl --interpreter=php --user-summary"
    assert "--user=" not in args[-1]
    assert "root" not in args
    assert not kwargs.get("shell", False)
    assert "CPANEL_ADMIN_FERNET_KEY" not in kwargs["env"]


def test_version_change_requires_confirmation_and_verifies(configured, monkeypatch):
    runner = Runner()
    monkeypatch.setattr(subprocess, "run", runner)
    args = ["--profile", "test", "php-selector", "set-version", "--version", "8.3"]
    code, _, _ = invoke(args, env=configured)
    assert code != 0
    assert not runner.calls
    code, plan, error = invoke([*args, "--dry-run"], env=configured)
    assert code == 0, error
    assert runner.current == "8.2"
    code, result, error = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=configured,
    )
    assert code == 0, error
    assert runner.current == "8.3"
    assert result["verified"] is True


def test_enable_extension_verified(configured, monkeypatch):
    runner = Runner()
    monkeypatch.setattr(subprocess, "run", runner)
    args = [
        "--profile",
        "test",
        "php-selector",
        "enable-extensions",
        "--version",
        "8.2",
        "--extensions",
        "intl",
    ]
    code, plan, error = invoke([*args, "--dry-run"], env=configured)
    assert code == 0, error
    code, result, error = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=configured,
    )
    assert code == 0, error
    assert result["verified"]
    assert runner.extensions["intl"] == "+"


@pytest.mark.parametrize("version", ["8.3;id", "$(id)", "--user=root", "8.3\nwhoami"])
def test_selector_rejects_injection_before_ssh(configured, monkeypatch, version):
    runner = Runner()
    monkeypatch.setattr(subprocess, "run", runner)
    code, _, _ = invoke(
        ["--profile", "test", "php-selector", "set-version", "--version", version, "--dry-run"],
        env=configured,
    )
    assert code != 0
    assert not runner.calls


def test_ssh_failure_is_error_without_raw_output(configured, monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 255, "", "secret-host-detail"),
    )
    code, _, error = invoke(["--profile", "test", "php-selector", "versions"], env=configured)
    assert code != 0
    assert "secret-host-detail" not in error
    assert "SSH" in error


def test_setting_php_option_verifies_effective_value(configured, monkeypatch):
    runner = Runner()
    monkeypatch.setattr(subprocess, "run", runner)
    args = [
        "--profile",
        "test",
        "php-selector",
        "set-option",
        "--version",
        "8.2",
        "--option",
        "memory_limit",
        "--value",
        "256M",
    ]
    code, plan, error = invoke([*args, "--dry-run"], env=configured)
    assert code == 0, error
    code, result, error = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=configured,
    )
    assert code == 0, error
    assert result["data"]["memory_limit"] == "256M"


def test_changed_state_invalidates_approval(configured, monkeypatch):
    runner = Runner()
    monkeypatch.setattr(subprocess, "run", runner)
    args = ["--profile", "test", "php-selector", "set-version", "--version", "8.3"]
    _, plan, _ = invoke([*args, "--dry-run"], env=configured)
    runner.current = "native"
    code, _, _ = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=configured,
    )
    assert code != 0
    assert all("--set-user-current=" not in args[-1] for args, _ in runner.calls)


def test_changed_ssh_endpoint_invalidates_approval(configured, monkeypatch):
    runner = Runner()
    monkeypatch.setattr(subprocess, "run", runner)
    args = ["--profile", "test", "php-selector", "set-version", "--version", "8.3"]
    _, plan, _ = invoke([*args, "--dry-run"], env=configured)
    invoke(["profiles", "configure-ssh", "test", "--port", "2223"], env=configured)
    code, _, _ = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=configured,
    )
    assert code != 0
    assert all("--set-user-current=" not in args[-1] for args, _ in runner.calls)


@pytest.mark.parametrize("output", ["", "Error: unavailable", "8.3 e d s\n8.3 e d s"])
def test_malformed_inventory_fails_closed(configured, monkeypatch, output):
    monkeypatch.setattr(
        subprocess, "run", lambda args, **kwargs: subprocess.CompletedProcess(args, 0, output, "")
    )
    code, _, _ = invoke(["--profile", "test", "php-selector", "versions"], env=configured)
    assert code != 0


def test_timeout_is_not_retried(configured, monkeypatch):
    calls = []

    def timeout(args, **kwargs):
        calls.append(args)
        raise subprocess.TimeoutExpired(args, 30)

    monkeypatch.setattr(subprocess, "run", timeout)
    code, _, error = invoke(["--profile", "test", "php-selector", "current"], env=configured)
    assert code != 0
    assert "timed out" in error
    assert len(calls) == 1


def test_identity_file_permissions_checked_before_ssh(configured, monkeypatch, tmp_path):
    source = tmp_path / "ssh-key"
    source.write_text("test key fixture")
    source.chmod(0o644)
    invoke(["profiles", "configure-ssh", "test", "--identity-file", str(source)], env=configured)
    runner = Runner()
    monkeypatch.setattr(subprocess, "run", runner)
    code, _, error = invoke(["--profile", "test", "php-selector", "current"], env=configured)
    assert code != 0
    assert "0400 or 0600" in error
    assert not runner.calls


def test_root_profile_is_rejected(configured, monkeypatch):
    path = Path(configured["CPANEL_ADMIN_CONFIG"])
    value = json.loads(path.read_text())
    value["profiles"]["test"]["username"] = "root"
    path.write_text(json.dumps(value))
    runner = Runner()
    monkeypatch.setattr(subprocess, "run", runner)
    code, _, error = invoke(["--profile", "test", "php-selector", "current"], env=configured)
    assert code != 0
    assert "root" in error
    assert not runner.calls


def test_ssh_profile_survives_token_rotation(configured):
    env = {**configured, "CPANEL_ADMIN_FERNET_KEY_NEW": Fernet.generate_key().decode()}
    code, _, error = invoke(["profiles", "rotate-key"], env=env)
    assert code == 0, error
    code, result, error = invoke(["profiles", "show", "test"], env=env)
    assert code == 0, error
    assert result["data"]["ssh"]["port"] == 2222
