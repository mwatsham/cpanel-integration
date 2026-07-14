from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from cpanel_admin.audit import AuditEvent, AuditWriter, audit_transport
from cpanel_admin.errors import AuditError


def event(*, target: str = "user@example.test", secret: str = "do-not-write") -> AuditEvent:
    del secret
    return AuditEvent.from_policy(
        timestamp="2026-07-14T12:00:00Z",
        profile="staging",
        operation="email.accounts.create",
        identity="Email/add_pop",
        risk="mutate",
        confirmed=True,
        safe_values={"email": target, "password": {"sha256": "a" * 64, "bytes": 12}},
        audit_fields=("email",),
        outcome="intent",
        error_category=None,
        verification=None,
    )


def test_audit_file_is_created_with_mode_0600(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    writer.write(event(), fail_closed=True)
    assert stat.S_IMODE((tmp_path / "audit.jsonl").stat().st_mode) == 0o600


def test_audit_event_contains_only_allowlisted_redacted_fields(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    writer.write(event(target="user@example.test", secret="do-not-write"), fail_closed=True)

    content = (tmp_path / "audit.jsonl").read_text()
    record = json.loads(content)
    assert "do-not-write" not in content
    assert record["operation"] == "email.accounts.create"
    assert record["target"] == {"email": "user@example.test"}
    assert set(record) == {
        "timestamp",
        "profile",
        "operation",
        "identity",
        "risk",
        "confirmed",
        "target",
        "outcome",
        "error_category",
        "verification",
    }


def test_audit_event_is_immutable_and_rejects_unknown_target_values() -> None:
    item = event()
    with pytest.raises((AttributeError, TypeError)):
        item.operation = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        item.target["email"] = "changed"  # type: ignore[index]
    with pytest.raises(AuditError, match="JSON-safe"):
        AuditEvent.from_policy(
            timestamp="2026-07-14T12:00:00Z",
            profile="staging",
            operation="email.accounts.create",
            identity="Email/add_pop",
            risk="mutate",
            confirmed=True,
            safe_values={"email": object()},
            audit_fields=("email",),
            outcome="intent",
            error_category=None,
            verification=None,
        )


def test_confirmed_mutation_does_not_call_transport_when_audit_intent_fails(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.mkdir()
    writer = AuditWriter(path)
    calls: list[str] = []

    with pytest.raises(AuditError):
        audit_transport(writer, event(), is_mutation=True, transport=lambda: calls.append("called"))
    assert calls == []


def test_read_operation_returns_audit_warning_after_transport_succeeds(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.mkdir()
    writer = AuditWriter(path)
    calls: list[str] = []

    result = audit_transport(
        writer,
        event(),
        is_mutation=False,
        transport=lambda: calls.append("called") or {"result": "ok"},
    )

    assert calls == ["called"]
    assert result.value == {"result": "ok"}
    assert result.warnings == ("audit",)


def test_writer_rejects_symlink_non_regular_owner_or_mode_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.write_text("existing\n")
    target.chmod(0o600)
    path = tmp_path / "audit.jsonl"
    path.symlink_to(target)
    with pytest.raises(AuditError, match="symbolic link"):
        AuditWriter(path).write(event(), fail_closed=True)

    path.unlink()
    path.mkdir()
    with pytest.raises(AuditError, match="regular file"):
        AuditWriter(path).write(event(), fail_closed=True)

    path.rmdir()
    path.write_text("existing\n")
    path.chmod(0o644)
    with pytest.raises(AuditError, match="permissions"):
        AuditWriter(path).write(event(), fail_closed=True)

    path.chmod(0o600)
    monkeypatch.setattr(os, "getuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(AuditError, match="owned by the current user"):
        AuditWriter(path).write(event(), fail_closed=True)


def test_writer_uses_nonblocking_nofollow_append_and_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"
    observed: dict[str, int] = {}
    original_open = os.open
    original_fsync = os.fsync

    def checked_open(
        name: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        observed["flags"] = flags
        return original_open(name, flags, mode)

    def checked_fsync(descriptor: int) -> None:
        observed["fsync"] = descriptor
        original_fsync(descriptor)

    monkeypatch.setattr(os, "open", checked_open)
    monkeypatch.setattr(os, "fsync", checked_fsync)
    AuditWriter(path).write(event(), fail_closed=True)

    assert observed["flags"] & os.O_APPEND
    assert observed["flags"] & os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        assert observed["flags"] & os.O_NOFOLLOW
    assert "fsync" in observed


def test_writer_rejects_regular_file_to_symlink_swap_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.write_text("unrelated")
    target.chmod(0o600)
    path = tmp_path / "audit.jsonl"
    path.write_text("existing\n")
    path.chmod(0o600)
    original_open = os.open

    def swapped_open(
        name: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        path.unlink()
        path.symlink_to(target)
        return original_open(name, flags, mode)

    monkeypatch.setattr(os, "open", swapped_open)
    with pytest.raises(AuditError):
        AuditWriter(path).write(event(), fail_closed=True)
    assert target.read_text() == "unrelated"
