"""Opt-in checks for a user-provided disposable cPanel account."""

from __future__ import annotations

import io
import json
import os
import secrets

import pytest

from cpanel_admin.cli import main

pytestmark = pytest.mark.live


def _live_environment() -> tuple[dict[str, str], str]:
    env = dict(os.environ)
    if env.get("CPANEL_ADMIN_RUN_LIVE_TESTS") != "1":
        pytest.skip("set CPANEL_ADMIN_RUN_LIVE_TESTS=1 to run disposable-account tests")
    if env.get("CPANEL_ADMIN_LIVE_DISPOSABLE") != "I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE":
        pytest.skip("explicit disposable-account acknowledgement is required")
    profile = env.get("CPANEL_ADMIN_LIVE_PROFILE")
    if not profile:
        pytest.skip("set CPANEL_ADMIN_LIVE_PROFILE to an explicitly disposable named profile")
    return env, profile


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


def test_live_read_only_discovery() -> None:
    env, profile = _live_environment()
    domains = _invoke(env, ["--profile", profile, "domains", "list"])
    certificates = _invoke(env, ["--profile", profile, "ssl", "hosts"])
    databases = _invoke(env, ["--profile", profile, "databases", "list"])
    assert "data" in domains
    assert "data" in certificates
    assert "data" in databases


def test_live_isolated_database_lifecycle() -> None:
    env, profile = _live_environment()
    prefix = env.get("CPANEL_ADMIN_LIVE_DATABASE_PREFIX")
    if not prefix or "codex_mvp_" not in prefix:
        pytest.skip("set a cPanel-valid CPANEL_ADMIN_LIVE_DATABASE_PREFIX containing codex_mvp_")
    database = f"{prefix}{secrets.token_hex(4)}"
    if len(database) > 64:
        pytest.skip("live database test name exceeds cPanel's 64-character limit")

    created = False
    try:
        _invoke(env, ["--profile", profile, "databases", "create", "--name", database])
        created = True
        listed = _invoke(env, ["--profile", profile, "databases", "list"])
        assert database in json.dumps(listed["data"])
    finally:
        if created:
            try:
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
            except Exception as exc:
                pytest.fail(f"LIVE CLEANUP FAILED; remove leftover database {database}: {exc}")
    after = _invoke(env, ["--profile", profile, "databases", "list"])
    assert database not in json.dumps(after["data"])
