"""Static checks for the disposable-account live verification harness."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import test_live_cpanel


def test_live_harness_covers_representative_capability_groups() -> None:
    commands = {command.operation: command.arguments for command in test_live_cpanel.LIVE_COMMANDS}
    expected = {
        "domains.list",
        "ssl.hosts",
        "databases.list",
        "email.accounts",
        "ftp.accounts",
        "diagnostics.quota",
        "security.modsec-installed",
        "runtime.php-installed",
        "backups.list",
        "capabilities.inspect",
    }
    assert expected <= commands.keys()
    assert all(arguments[0] != "profiles" for arguments in commands.values())


def test_live_lifecycle_specs_cover_mutable_capability_packs() -> None:
    specs = {spec.capability: spec for spec in test_live_cpanel.LIVE_LIFECYCLE_SPECS}
    expected = {
        "backups",
        "databases",
        "domains",
        "email",
        "files",
        "ftp",
        "runtime",
        "security",
        "ssl",
    }
    assert expected <= specs.keys()
    for spec in specs.values():
        assert spec.operation
        assert spec.phase in {"create", "update", "delete", "start"}
        assert spec.dry_run is True


def test_lifecycle_spec_builders_use_prefix_and_require_domain_when_needed() -> None:
    prefix = "codex_live_a1_"
    env = {"CPANEL_ADMIN_LIVE_DOMAIN": "example.com"}
    for spec in test_live_cpanel.LIVE_LIFECYCLE_SPECS:
        built = spec.build(env, prefix)
        assert built.resource.startswith(prefix) or spec.capability in {"runtime", "backups", "ssl"}
        assert "--dry-run" in built.arguments

    missing_domain = [
        spec.capability
        for spec in test_live_cpanel.LIVE_LIFECYCLE_SPECS
        if spec.requires_domain
        and spec.build({"CPANEL_ADMIN_LIVE_DOMAIN": ""}, prefix).skip_reason is not None
    ]
    assert {"domains", "email", "ftp", "ssl"} <= set(missing_domain)


def test_live_execution_specs_are_reversible_only() -> None:
    specs = {spec.capability: spec for spec in test_live_cpanel.LIVE_EXECUTION_SPECS}
    assert {"databases", "email", "ftp", "security"} <= specs.keys()
    for spec in specs.values():
        assert spec.create is not None
        assert spec.verify_created is not None
        assert spec.cleanup is not None
        assert spec.verify_cleaned is not None


def test_live_testing_reference_documents_required_gates() -> None:
    reference = Path("references/live-testing.md")
    assert reference.exists()
    text = reference.read_text(encoding="utf-8")
    assert "CPANEL_ADMIN_RUN_LIVE_TESTS=1" in text
    assert "CPANEL_ADMIN_LIVE_DISPOSABLE=I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE" in text
    assert "CPANEL_ADMIN_LIVE_PROFILE" in text
    assert "CPANEL_ADMIN_LIVE_ENABLE_DESTRUCTIVE=I_ACCEPT_LIVE_RESOURCE_MUTATION" in text
    assert "CPANEL_ADMIN_LIVE_RUN_PREFIX" in text
    assert "CPANEL_ADMIN_LIVE_DOMAIN" in text
    assert "test_live_lifecycle_dry_run_plans" in text
    assert "test_live_reversible_lifecycle_execution" in text
    assert "disposable" in text.lower()
    assert "pytest tests/test_live_cpanel.py -m live" in text


def test_destructive_live_gate_requires_second_explicit_acknowledgement() -> None:
    env = {
        "CPANEL_ADMIN_RUN_LIVE_TESTS": "1",
        "CPANEL_ADMIN_LIVE_DISPOSABLE": "I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE",
        "CPANEL_ADMIN_LIVE_PROFILE": "disposable",
    }
    with pytest.raises(pytest.skip.Exception, match="destructive"):
        test_live_cpanel._destructive_live_environment(env)

    allowed = dict(env)
    allowed["CPANEL_ADMIN_LIVE_ENABLE_DESTRUCTIVE"] = "I_ACCEPT_LIVE_RESOURCE_MUTATION"
    values, profile = test_live_cpanel._destructive_live_environment(allowed)
    assert values is allowed
    assert profile == "disposable"


def test_live_run_prefix_is_unique_and_cpanel_safe() -> None:
    first = test_live_cpanel._live_run_prefix({})
    second = test_live_cpanel._live_run_prefix({})
    assert first.startswith("codex_live_")
    assert second.startswith("codex_live_")
    assert first != second
    assert first.replace("_", "").isalnum()
    assert len(first) <= 24


def test_live_run_prefix_accepts_safe_operator_override() -> None:
    assert test_live_cpanel._live_run_prefix(
        {"CPANEL_ADMIN_LIVE_RUN_PREFIX": "codex_live_a1_"}
    ) == ("codex_live_a1_")
    with pytest.raises(pytest.fail.Exception, match="CPANEL_ADMIN_LIVE_RUN_PREFIX"):
        test_live_cpanel._live_run_prefix({"CPANEL_ADMIN_LIVE_RUN_PREFIX": "prod"})


def test_live_report_event_redacts_data_and_records_lifecycle(tmp_path: Path) -> None:
    env = {"CPANEL_ADMIN_LIVE_REPORT": str(tmp_path / "live.jsonl")}
    test_live_cpanel._write_lifecycle_report(
        env,
        capability="files",
        phase="cleanup",
        status="ok",
        resource="codex_live_abc_file",
        details={"secret": "must-not-appear", "count": 1},
    )

    text = (tmp_path / "live.jsonl").read_text(encoding="utf-8")
    assert "files" in text
    assert "cleanup" in text
    assert "codex_live_abc_file" in text
    assert "must-not-appear" not in text
