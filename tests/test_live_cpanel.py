"""Opt-in checks for a user-provided disposable cPanel account."""

from __future__ import annotations

import io
import json
import os
import re
import secrets
from collections.abc import Callable
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


@dataclass(frozen=True)
class LifecyclePlan:
    """A disposable live dry-run plan candidate."""

    arguments: tuple[str, ...]
    stdin: str
    resource: str
    skip_reason: str | None = None


@dataclass(frozen=True)
class LiveLifecycleSpec:
    """A mutation lifecycle dry-run spec for a capability pack."""

    capability: str
    operation: str
    phase: str
    build: Callable[[dict[str, str], str], LifecyclePlan]
    dry_run: bool = True
    requires_domain: bool = False


@dataclass(frozen=True)
class LiveExecutionSpec:
    """A reversible live mutation lifecycle for a disposable account."""

    capability: str
    create: Callable[[dict[str, str], str, str], str]
    verify_created: Callable[[dict[str, str], str, str], None]
    cleanup: Callable[[dict[str, str], str, str], None]
    verify_cleaned: Callable[[dict[str, str], str, str], None]
    requires_domain: bool = False


def _domain(env: dict[str, str], capability: str) -> str | None:
    value = env.get("CPANEL_ADMIN_LIVE_DOMAIN", "").strip()
    if value:
        return value
    return None


def _requires_domain(capability: str, operation: str) -> LifecyclePlan:
    return LifecyclePlan((), "", "", f"{operation} requires CPANEL_ADMIN_LIVE_DOMAIN")


def _domain_subdomain_plan(env: dict[str, str], prefix: str) -> LifecyclePlan:
    rootdomain = _domain(env, "domains")
    if rootdomain is None:
        return _requires_domain("domains", "domains.add-subdomain")
    label = prefix.rstrip("_").replace("_", "-")
    return LifecyclePlan(
        (
            "domains",
            "add-subdomain",
            "--domain",
            label,
            "--rootdomain",
            rootdomain,
            "--dir",
            f"public_html/{prefix}subdomain",
            "--dry-run",
        ),
        "",
        f"{prefix}subdomain.{rootdomain}",
    )


def _files_write_plan(_env: dict[str, str], prefix: str) -> LifecyclePlan:
    filename = f"{prefix}probe.txt"
    return LifecyclePlan(
        (
            "files",
            "write",
            "--directory",
            "public_html",
            "--filename",
            filename,
            "--content-stdin",
            "--dry-run",
        ),
        "codex live disposable probe\n",
        filename,
    )


def _database_create_plan(_env: dict[str, str], prefix: str) -> LifecyclePlan:
    database = f"{prefix}db"
    return LifecyclePlan(("databases", "create", "--name", database, "--dry-run"), "", database)


def _email_create_plan(env: dict[str, str], prefix: str) -> LifecyclePlan:
    domain = _domain(env, "email")
    if domain is None:
        return _requires_domain("email", "email.create-account")
    local = f"{prefix}mail".rstrip("_")[:32]
    return LifecyclePlan(
        (
            "email",
            "create-account",
            "--email",
            local,
            "--domain",
            domain,
            "--password-stdin",
            "--quota",
            "128",
            "--dry-run",
        ),
        "CorrectHorseBatteryStaple!42",
        f"{local}@{domain}",
    )


def _ftp_create_plan(env: dict[str, str], prefix: str) -> LifecyclePlan:
    domain = _domain(env, "ftp")
    if domain is None:
        return _requires_domain("ftp", "ftp.create")
    user = f"{prefix}ftp".rstrip("_")[:32]
    return LifecyclePlan(
        (
            "ftp",
            "create",
            "--user",
            user,
            "--domain",
            domain,
            "--password-stdin",
            "--quota",
            "128",
            "--dry-run",
        ),
        "CorrectHorseBatteryStaple!42",
        f"{user}@{domain}",
    )


def _security_block_ip_plan(_env: dict[str, str], prefix: str) -> LifecyclePlan:
    return LifecyclePlan(
        ("security", "block-ip", "--ip", "203.0.113.9", "--dry-run"),
        "",
        f"{prefix}203.0.113.9",
    )


def _runtime_nginx_plan(_env: dict[str, str], _prefix: str) -> LifecyclePlan:
    return LifecyclePlan(("runtime", "nginx-clear-cache", "--dry-run"), "", "nginx-cache")


def _backup_full_plan(_env: dict[str, str], _prefix: str) -> LifecyclePlan:
    return LifecyclePlan(("backups", "full-to-home", "--dry-run"), "", "home-directory-backup")


def _ssl_remove_plan(env: dict[str, str], _prefix: str) -> LifecyclePlan:
    domain = _domain(env, "ssl")
    if domain is None:
        return _requires_domain("ssl", "ssl.remove")
    return LifecyclePlan(("ssl", "remove", "--domain", domain, "--dry-run"), "", domain)


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

LIVE_LIFECYCLE_SPECS: tuple[LiveLifecycleSpec, ...] = (
    LiveLifecycleSpec("backups", "backups.full-to-home", "start", _backup_full_plan),
    LiveLifecycleSpec("databases", "databases.create", "create", _database_create_plan),
    LiveLifecycleSpec(
        "domains",
        "domains.add-subdomain",
        "create",
        _domain_subdomain_plan,
        requires_domain=True,
    ),
    LiveLifecycleSpec("email", "email.create-account", "create", _email_create_plan, True, True),
    LiveLifecycleSpec("files", "files.write", "create", _files_write_plan),
    LiveLifecycleSpec("ftp", "ftp.create", "create", _ftp_create_plan, True, True),
    LiveLifecycleSpec("runtime", "runtime.nginx-clear-cache", "update", _runtime_nginx_plan),
    LiveLifecycleSpec("security", "security.block-ip", "create", _security_block_ip_plan),
    LiveLifecycleSpec("ssl", "ssl.remove", "delete", _ssl_remove_plan, True, True),
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


def _execute_mutation(
    env: dict[str, str],
    profile: str,
    arguments: list[str],
    stdin: str = "",
) -> dict[str, object]:
    plan = _invoke(env, ["--profile", profile, *arguments, "--dry-run"], stdin=stdin)
    assert plan["dry_run"] is True
    if plan.get("requires_confirmation") is True:
        return _invoke(
            env,
            [
                "--profile",
                profile,
                *arguments,
                "--confirm",
                str(plan["confirmation"]),
                "--expires-at",
                str(plan["expires_at"]),
            ],
            stdin=stdin,
        )
    return _invoke(env, ["--profile", profile, *arguments], stdin=stdin)


def _execute_confirmed(
    env: dict[str, str],
    profile: str,
    arguments: list[str],
    stdin: str = "",
) -> dict[str, object]:
    plan = _invoke(env, ["--profile", profile, *arguments, "--dry-run"], stdin=stdin)
    assert plan["dry_run"] is True
    return _invoke(
        env,
        [
            "--profile",
            profile,
            *arguments,
            "--confirm",
            str(plan["confirmation"]),
            "--expires-at",
            str(plan["expires_at"]),
        ],
        stdin=stdin,
    )


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


def _json_contains(value: object, needle: str) -> bool:
    return needle in json.dumps(value, sort_keys=True)


def _create_database(env: dict[str, str], profile: str, prefix: str) -> str:
    database = f"{prefix}{secrets.token_hex(4)}"
    if len(database) > 64:
        pytest.skip("live database test name exceeds cPanel's 64-character limit")
    _execute_mutation(env, profile, ["databases", "create", "--name", database])
    return database


def _verify_database_created(env: dict[str, str], profile: str, resource: str) -> None:
    listed = _invoke(env, ["--profile", profile, "databases", "list"])
    assert _json_contains(listed["data"], resource)


def _cleanup_database(env: dict[str, str], profile: str, resource: str) -> None:
    _execute_confirmed(env, profile, ["databases", "remove", "--name", resource])


def _verify_database_cleaned(env: dict[str, str], profile: str, resource: str) -> None:
    listed = _invoke(env, ["--profile", profile, "databases", "list"])
    assert not _json_contains(listed["data"], resource)


def _create_email(env: dict[str, str], profile: str, prefix: str) -> str:
    domain = _domain(env, "email")
    if domain is None:
        pytest.skip("email lifecycle requires CPANEL_ADMIN_LIVE_DOMAIN")
    local = f"{prefix}mail".rstrip("_")[:32]
    _execute_mutation(
        env,
        profile,
        [
            "email",
            "create-account",
            "--email",
            local,
            "--domain",
            domain,
            "--password-stdin",
            "--quota",
            "128",
        ],
        stdin="CorrectHorseBatteryStaple!42",
    )
    return f"{local}@{domain}"


def _verify_email_created(env: dict[str, str], profile: str, resource: str) -> None:
    listed = _invoke(env, ["--profile", profile, "email", "accounts"])
    assert _json_contains(listed["data"], resource)


def _cleanup_email(env: dict[str, str], profile: str, resource: str) -> None:
    local, domain = resource.split("@", 1)
    _execute_confirmed(
        env,
        profile,
        ["email", "delete-account", "--email", local, "--domain", domain],
    )


def _verify_email_cleaned(env: dict[str, str], profile: str, resource: str) -> None:
    listed = _invoke(env, ["--profile", profile, "email", "accounts"])
    assert not _json_contains(listed["data"], resource)


def _create_ftp(env: dict[str, str], profile: str, prefix: str) -> str:
    domain = _domain(env, "ftp")
    if domain is None:
        pytest.skip("FTP lifecycle requires CPANEL_ADMIN_LIVE_DOMAIN")
    user = f"{prefix}ftp".rstrip("_")[:32]
    _execute_mutation(
        env,
        profile,
        [
            "ftp",
            "create",
            "--user",
            user,
            "--domain",
            domain,
            "--password-stdin",
            "--quota",
            "128",
        ],
        stdin="CorrectHorseBatteryStaple!42",
    )
    return f"{user}@{domain}"


def _verify_ftp_created(env: dict[str, str], profile: str, resource: str) -> None:
    listed = _invoke(env, ["--profile", profile, "ftp", "accounts"])
    assert _json_contains(listed["data"], resource)


def _cleanup_ftp(env: dict[str, str], profile: str, resource: str) -> None:
    user, domain = resource.split("@", 1)
    _execute_confirmed(env, profile, ["ftp", "delete", "--user", user, "--domain", domain])


def _verify_ftp_cleaned(env: dict[str, str], profile: str, resource: str) -> None:
    listed = _invoke(env, ["--profile", profile, "ftp", "accounts"])
    assert not _json_contains(listed["data"], resource)


def _create_security_block(env: dict[str, str], profile: str, prefix: str) -> str:
    resource = f"{prefix}203.0.113.9"
    _execute_mutation(env, profile, ["security", "block-ip", "--ip", "203.0.113.9"])
    return resource


def _verify_security_block_created(_env: dict[str, str], _profile: str, _resource: str) -> None:
    # The reviewed security surface has no independent read for BlockIP state.
    return None


def _cleanup_security_block(env: dict[str, str], profile: str, _resource: str) -> None:
    _execute_mutation(env, profile, ["security", "unblock-ip", "--ip", "203.0.113.9"])


def _verify_security_block_cleaned(_env: dict[str, str], _profile: str, _resource: str) -> None:
    # The cleanup command succeeding is the available evidence for this reversible operation.
    return None


LIVE_EXECUTION_SPECS: tuple[LiveExecutionSpec, ...] = (
    LiveExecutionSpec(
        "databases",
        _create_database,
        _verify_database_created,
        _cleanup_database,
        _verify_database_cleaned,
    ),
    LiveExecutionSpec(
        "email",
        _create_email,
        _verify_email_created,
        _cleanup_email,
        _verify_email_cleaned,
        requires_domain=True,
    ),
    LiveExecutionSpec(
        "ftp",
        _create_ftp,
        _verify_ftp_created,
        _cleanup_ftp,
        _verify_ftp_cleaned,
        requires_domain=True,
    ),
    LiveExecutionSpec(
        "security",
        _create_security_block,
        _verify_security_block_created,
        _cleanup_security_block,
        _verify_security_block_cleaned,
    ),
)


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


@pytest.mark.parametrize("spec", LIVE_LIFECYCLE_SPECS, ids=lambda spec: spec.operation)
def test_live_lifecycle_dry_run_plans(spec: LiveLifecycleSpec) -> None:
    env, profile = _destructive_live_environment()
    prefix = _live_run_prefix(env)
    plan = spec.build(env, prefix)
    if plan.skip_reason is not None:
        pytest.skip(plan.skip_reason)
    _write_lifecycle_report(
        env,
        capability=spec.capability,
        phase=spec.phase,
        status="dry-run-attempt",
        resource=plan.resource,
    )
    result = _invoke(env, ["--profile", profile, *plan.arguments], stdin=plan.stdin)
    assert result["dry_run"] is True
    assert result["operation"] == spec.operation
    _write_lifecycle_report(
        env,
        capability=spec.capability,
        phase=spec.phase,
        status="dry-run-ok",
        resource=plan.resource,
        details={"operation": spec.operation},
    )


@pytest.mark.parametrize("spec", LIVE_EXECUTION_SPECS, ids=lambda spec: spec.capability)
def test_live_reversible_lifecycle_execution(spec: LiveExecutionSpec) -> None:
    env, profile = _destructive_live_environment()
    prefix = _live_run_prefix(env)
    resource: str | None = None
    try:
        _write_lifecycle_report(
            env,
            capability=spec.capability,
            phase="create",
            status="attempt",
            resource=prefix,
        )
        resource = spec.create(env, profile, prefix)
        _write_lifecycle_report(
            env,
            capability=spec.capability,
            phase="create",
            status="ok",
            resource=resource,
        )
        spec.verify_created(env, profile, resource)
    finally:
        if resource is not None:
            try:
                _write_lifecycle_report(
                    env,
                    capability=spec.capability,
                    phase="cleanup",
                    status="attempt",
                    resource=resource,
                )
                spec.cleanup(env, profile, resource)
                spec.verify_cleaned(env, profile, resource)
                _write_lifecycle_report(
                    env,
                    capability=spec.capability,
                    phase="cleanup",
                    status="ok",
                    resource=resource,
                )
            except Exception as exc:
                _write_lifecycle_report(
                    env,
                    capability=spec.capability,
                    phase="cleanup",
                    status="failed",
                    resource=resource,
                    details={"error": str(exc)},
                )
                pytest.fail(
                    f"LIVE CLEANUP FAILED; remove leftover {spec.capability} {resource}: {exc}"
                )
