"""Static checks for the disposable-account live verification harness."""

from __future__ import annotations

from pathlib import Path

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


def test_live_testing_reference_documents_required_gates() -> None:
    reference = Path("references/live-testing.md")
    assert reference.exists()
    text = reference.read_text(encoding="utf-8")
    assert "CPANEL_ADMIN_RUN_LIVE_TESTS=1" in text
    assert "CPANEL_ADMIN_LIVE_DISPOSABLE=I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE" in text
    assert "CPANEL_ADMIN_LIVE_PROFILE" in text
    assert "disposable" in text.lower()
    assert "pytest tests/test_live_cpanel.py -m live" in text
