"""Protected, redacted JSONL audit events for cPanel operations."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, TypeVar

from .catalog import JsonValue
from .errors import AuditError

_AUDIT_MODE = 0o600
_EVENT_FIELDS = (
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
)
_SENSITIVE_TARGET_KEYS = frozenset(
    {
        "secret",
        "token",
        "password",
        "key",
        "content",
        "path",
        "raw_exception",
        "request",
        "response",
    }
)
_ResultT = TypeVar("_ResultT")
_KeyT = TypeVar("_KeyT")
_ValueT = TypeVar("_ValueT")


class _FrozenDict(dict[_KeyT, _ValueT]):
    """JSON-serializable mapping whose contents cannot be altered."""

    def _reject_mutation(self, *_args: object, **_kwargs: object) -> NoReturn:
        raise TypeError("audit event fields are immutable")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    clear = _reject_mutation
    pop = _reject_mutation
    popitem = _reject_mutation
    setdefault = _reject_mutation
    update = _reject_mutation
    __ior__ = _reject_mutation


class _FrozenList(list[_ValueT]):
    """JSON-serializable sequence whose contents cannot be altered."""

    def _reject_mutation(self, *_args: object, **_kwargs: object) -> NoReturn:
        raise TypeError("audit event fields are immutable")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    append = _reject_mutation
    clear = _reject_mutation
    extend = _reject_mutation
    insert = _reject_mutation
    pop = _reject_mutation
    remove = _reject_mutation
    reverse = _reject_mutation
    sort = _reject_mutation
    __iadd__ = _reject_mutation
    __imul__ = _reject_mutation


@dataclass(frozen=True)
class AuditEvent:
    """One closed-schema, safe audit event.

    Instances should be created with :meth:`from_policy`, which copies only the
    policy's reviewed audit fields from already-redacted ``safe_values``.
    """

    timestamp: str
    profile: str
    operation: str
    identity: str
    risk: str
    confirmed: bool
    target: JsonValue
    outcome: str
    error_category: str | None
    verification: str | None

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (
                self.timestamp,
                self.profile,
                self.operation,
                self.identity,
                self.risk,
                self.outcome,
            )
        ):
            raise AuditError("Audit event has invalid required metadata")
        if not isinstance(self.confirmed, bool):
            raise AuditError("Audit event confirmation state is invalid")
        if self.error_category is not None and not isinstance(self.error_category, str):
            raise AuditError("Audit event error category is invalid")
        if self.verification is not None and not isinstance(self.verification, str):
            raise AuditError("Audit event verification is invalid")
        _validate_json_value(self.target)
        object.__setattr__(self, "target", _freeze_safe_value(self.target))

    @classmethod
    def from_policy(
        cls,
        *,
        timestamp: str,
        profile: str,
        operation: str,
        identity: str,
        risk: str,
        confirmed: bool,
        safe_values: Mapping[str, JsonValue],
        audit_fields: tuple[str, ...],
        outcome: str,
        error_category: str | None,
        verification: str | None,
    ) -> AuditEvent:
        """Build an event from only reviewed field names and redacted values."""

        if len(set(audit_fields)) != len(audit_fields) or any(
            not isinstance(name, str) or not name for name in audit_fields
        ):
            raise AuditError("Audit field allowlist is invalid")
        if any(name not in safe_values for name in audit_fields):
            raise AuditError("Audit field is unavailable")
        target = {name: _copy_safe_value(safe_values[name]) for name in audit_fields}
        return cls(
            timestamp,
            profile,
            operation,
            identity,
            risk,
            confirmed,
            target,
            outcome,
            error_category,
            verification,
        )

    def to_json(self) -> str:
        """Return exactly one compact, closed-schema JSONL record."""

        record = {name: _copy_safe_value(getattr(self, name)) for name in _EVENT_FIELDS}
        return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


@dataclass(frozen=True)
class AuditedResult:
    """A read result with any explicit, non-sensitive audit warnings."""

    value: object
    warnings: tuple[str, ...] = ()


class AuditWriter:
    """Append closed-schema records only to a user-owned regular ``0600`` file."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def write(self, event: AuditEvent, *, fail_closed: bool) -> bool:
        """Write and fsync one event, or return ``False`` for an allowed read warning."""

        if not isinstance(event, AuditEvent):
            return self._failure(fail_closed, "Audit event is invalid")
        try:
            descriptor = _open_audit_descriptor(self._path)
            with os.fdopen(descriptor, "ab", closefd=True) as stream:
                _verify_descriptor(stream.fileno(), self._path)
                stream.write(event.to_json().encode("ascii"))
                stream.flush()
                os.fsync(stream.fileno())
        except AuditError as exc:
            return self._failure(fail_closed, str(exc))
        except (OSError, ValueError, TypeError):
            return self._failure(fail_closed, "Unable to write protected audit record")
        return True

    @staticmethod
    def _failure(fail_closed: bool, message: str) -> bool:
        if fail_closed:
            raise AuditError(message) from None
        return False


def audit_transport(
    writer: AuditWriter,
    intent: AuditEvent,
    *,
    is_mutation: bool,
    transport: Callable[[], _ResultT],
) -> AuditedResult:
    """Gate a transport call on audit intent and mark read audit failures explicitly.

    This small integration seam is intentionally transport-agnostic; the later
    executor supplies policy, confirmation, and result-event construction.
    """

    if is_mutation:
        writer.write(intent, fail_closed=True)
        return AuditedResult(transport())
    if writer.write(intent, fail_closed=False):
        return AuditedResult(transport())
    return AuditedResult(transport(), ("audit",))


def _open_audit_descriptor(path: Path) -> int:
    before: os.stat_result | None
    try:
        before = path.lstat()
    except FileNotFoundError:
        before = None
    except OSError as exc:
        raise AuditError("Unable to inspect protected audit record") from exc
    if before is not None:
        _verify_metadata(before)
    flags = (
        os.O_CREAT
        | os.O_APPEND
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags, _AUDIT_MODE)
    except OSError as exc:
        raise AuditError("Unable to open protected audit record") from exc
    try:
        opened = os.fstat(descriptor)
        _verify_metadata(opened)
        if before is not None and (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise AuditError("Protected audit record changed while opening")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _verify_descriptor(descriptor: int, path: Path) -> None:
    try:
        current = path.lstat()
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise AuditError("Unable to inspect protected audit record") from exc
    _verify_metadata(current)
    _verify_metadata(opened)
    if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        raise AuditError("Protected audit record changed before append")


def _verify_metadata(metadata: os.stat_result) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise AuditError("Protected audit record must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise AuditError("Protected audit record must be a regular file")
    if metadata.st_uid != os.getuid():
        raise AuditError("Protected audit record must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != _AUDIT_MODE:
        raise AuditError("Protected audit record permissions must be 0600")
    if metadata.st_nlink != 1:
        raise AuditError("Protected audit record must not have hard links")


def _copy_safe_value(value: JsonValue) -> JsonValue:
    _validate_json_value(value)
    if isinstance(value, list):
        return [_copy_safe_value(item) for item in value]
    if isinstance(value, Mapping):
        return {key: _copy_safe_value(item) for key, item in value.items()}
    return value


def _freeze_safe_value(value: JsonValue) -> JsonValue:
    if isinstance(value, list):
        return _FrozenList(_freeze_safe_value(item) for item in value)
    if isinstance(value, Mapping):
        return _FrozenDict({key: _freeze_safe_value(item) for key, item in value.items()})
    return value


def _validate_json_value(value: object) -> None:
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        if value.startswith("/"):
            raise AuditError("Audit values must not contain absolute paths")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            if _is_sensitive_target_key(key):
                raise AuditError("Audit values must not contain sensitive target keys")
            _validate_json_value(item)
        return
    raise AuditError("Audit values must be JSON-safe")


def _is_sensitive_target_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if normalized in _SENSITIVE_TARGET_KEYS:
        return True
    return any(part in _SENSITIVE_TARGET_KEYS for part in normalized.split("_"))
