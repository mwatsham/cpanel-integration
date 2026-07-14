"""Opt-in checks for a user-provided disposable cPanel account."""

from __future__ import annotations

import io
import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

import pytest

from cpanel_admin.cli import main

pytestmark = pytest.mark.live

DESTRUCTIVE_LIVE_ACK = "I_ACCEPT_LIVE_RESOURCE_MUTATION"
PREFIX_PATTERN = re.compile(r"^codex_live_[a-z0-9]{2,8}_?$")


@dataclass(frozen=True)
class LiveCommand:
    """A representative read-only command safe for a disposable account."""

    operation: str
    arguments: tuple[str, ...]


LIVE_COMMANDS: tuple[LiveCommand, ...] = (
    LiveCommand("domains.list", ("domains", "list")),
    LiveCommand("ssl.hosts", ("ssl", "hosts")),
    LiveCommand("databases.list", ("databases", "list")),
    LiveCommand("email.accounts", ("email", "accounts")),
    LiveCommand("ftp.accounts", ("ftp", "accounts")),
    LiveCommand("diagnostics.quota", ("diagnostics", "quota")),
    LiveCommand("security.modsec-installed", ("security", "modsec-installed")),
    LiveCommand("runtime.php-installed", ("runtime", "php-installed")),
    LiveCommand("backups.list", ("backups", "list")),
    LiveCommand("capabilities.inspect", ("capabilities", "inspect")),
)


def _live_environment() -> tuple[dict[str, str], str]:
    env = dict(os.environ)
    return _live_environment_from(env)


def _live_environment_from(env: dict[str, str]) -> tuple[dict[str, str], str]:
    if env.get("CPANEL_ADMIN_RUN_LIVE_TESTS") != "1":
        pytest.skip("set CPANEL_ADMIN_RUN_LIVE_TESTS=1 to run disposable-account tests")
    if env.get("CPANEL_ADMIN_LIVE_DISPOSABLE") != "I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE":
        pytest.skip("explicit disposable-account acknowledgement is required")
    profile = env.get("CPANEL_ADMIN_LIVE_PROFILE")
    if not profile:
        pytest.skip("set CPANEL_ADMIN_LIVE_PROFILE to an explicitly disposable named profile")
    return env, profile


def _destructive_live_environment(
    env: dict[str, str] | None = None,
) -> tuple[dict[str, str], str]:
    values, profile = _live_environment_from(dict(os.environ) if env is None else env)
    if values.get("CPANEL_ADMIN_LIVE_ENABLE_DESTRUCTIVE") != DESTRUCTIVE_LIVE_ACK:
        pytest.skip(
            "set CPANEL_ADMIN_LIVE_ENABLE_DESTRUCTIVE=I_ACCEPT_LIVE_RESOURCE_MUTATION "
            "to run destructive disposable-account lifecycle tests"
        )
    return values, profile


def _live_run_prefix(env: dict[str, str]) -> str:
    value = env.get("CPANEL_ADMIN_LIVE_RUN_PREFIX")
    if value:
        if not PREFIX_PATTERN.fullmatch(value):
            pytest.fail(
                "CPANEL_ADMIN_LIVE_RUN_PREFIX must match codex_live_<2-8 lowercase letters/digits>_"
            )
        return value
    return f"codex_live_{secrets.token_hex(3)}_"


def _invoke(env: dict[str, str], arguments: list[str], stdin: str = "") -> dict[str, object]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(
        arguments,
        env=env,
        stdin=io.StringIO(stdin),
        stdout=stdout,
        stderr=stderr,
    )
    assert code == 0, stderr.getvalue()
    value = json.loads(stdout.getvalue())
    assert value["ok"] is True
    return value


def _write_report(env: dict[str, str], command: LiveCommand, code: int, result: object) -> None:
    report_path = env.get("CPANEL_ADMIN_LIVE_REPORT")
    if not report_path:
        return
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    summary: dict[str, object] = {
        "command": " ".join(command.arguments),
        "expected_operation": command.operation,
        "exit_code": code,
    }
    if isinstance(result, dict):
        summary.update(
            {
                "ok": result.get("ok"),
                "operation": result.get("operation"),
                "data_type": type(result.get("data")).__name__,
                "warning_count": len(result.get("warnings", [])),
                "message_count": len(result.get("messages", [])),
            }
        )
    else:
        summary["stderr"] = str(result).splitlines()[0][:160] if str(result) else ""
    with path.open("a", encoding="utf-8") as handle:
        json.dump(summary, handle, sort_keys=True)
        handle.write("\n")


def _write_lifecycle_report(
    env: dict[str, str],
    *,
    capability: str,
    phase: str,
    status: str,
    resource: str,
    details: dict[str, object] | None = None,
) -> None:
    report_path = env.get("CPANEL_ADMIN_LIVE_REPORT")
    if not report_path:
        return
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_details = {
        key: value
        for key, value in (details or {}).items()
        if key.lower() not in {"secret", "password", "token", "key", "authorization"}
    }
    with path.open("a", encoding="utf-8") as handle:
        json.dump(
            {
                "capability": capability,
                "phase": phase,
                "status": status,
                "resource": resource,
                "details": safe_details,
            },
            handle,
            sort_keys=True,
        )
        handle.write("\n")


def _invoke_command(env: dict[str, str], profile: str, command: LiveCommand) -> dict[str, object]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(
        ["--profile", profile, *command.arguments],
        env=env,
        stdin=io.StringIO(""),
        stdout=stdout,
        stderr=stderr,
    )
    error = stderr.getvalue()
    feature_missing = (code == 7 and "operation feature is not available" in error) or (
        code == 6 and "do not have the feature" in error
    )
    if feature_missing:
        _write_report(env, command, code, error)
        pytest.skip(f"{command.operation} is not available on this disposable cPanel account")
    assert code == 0, error
    value = json.loads(stdout.getvalue())
    assert value["ok"] is True
    assert value["operation"] == command.operation
    _write_report(env, command, code, value)
    return value


def test_live_read_only_discovery() -> None:
    env, profile = _live_environment()
    domains = _invoke(env, ["--profile", profile, "domains", "list"])
    certificates = _invoke(env, ["--profile", profile, "ssl", "hosts"])
    databases = _invoke(env, ["--profile", profile, "databases", "list"])
    assert "data" in domains
    assert "data" in certificates
    assert "data" in databases


@pytest.mark.parametrize("command", LIVE_COMMANDS, ids=lambda command: command.operation)
def test_live_representative_read_only_commands(command: LiveCommand) -> None:
    env, profile = _live_environment()
    result = _invoke_command(env, profile, command)
    assert "data" in result


def test_live_isolated_database_lifecycle() -> None:
    env, profile = _destructive_live_environment()
    prefix = env.get("CPANEL_ADMIN_LIVE_DATABASE_PREFIX") or _live_run_prefix(env)
    database = f"{prefix}{secrets.token_hex(4)}"
    if len(database) > 64:
        pytest.skip("live database test name exceeds cPanel's 64-character limit")

    created = False
    try:
        _write_lifecycle_report(
            env,
            capability="databases",
            phase="create",
            status="attempt",
            resource=database,
        )
        _invoke(env, ["--profile", profile, "databases", "create", "--name", database])
        created = True
        _write_lifecycle_report(
            env,
            capability="databases",
            phase="create",
            status="ok",
            resource=database,
        )
        listed = _invoke(env, ["--profile", profile, "databases", "list"])
        assert database in json.dumps(listed["data"])
    finally:
        if created:
            try:
                _write_lifecycle_report(
                    env,
                    capability="databases",
                    phase="cleanup",
                    status="attempt",
                    resource=database,
                )
                plan = _invoke(
                    env,
                    [
                        "--profile",
                        profile,
                        "databases",
                        "remove",
                        "--name",
                        database,
                        "--dry-run",
                    ],
                )
                _invoke(
                    env,
                    [
                        "--profile",
                        profile,
                        "databases",
                        "remove",
                        "--name",
                        database,
                        "--confirm",
                        str(plan["confirmation"]),
                        "--expires-at",
                        str(plan["expires_at"]),
                    ],
                )
                _write_lifecycle_report(
                    env,
                    capability="databases",
                    phase="cleanup",
                    status="ok",
                    resource=database,
                )
            except Exception as exc:
                _write_lifecycle_report(
                    env,
                    capability="databases",
                    phase="cleanup",
                    status="failed",
                    resource=database,
                    details={"error": str(exc)},
                )
                pytest.fail(f"LIVE CLEANUP FAILED; remove leftover database {database}: {exc}")
    after = _invoke(env, ["--profile", profile, "databases", "list"])
    assert database not in json.dumps(after["data"])
