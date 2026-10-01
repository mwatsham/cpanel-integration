"""Narrow, reviewed cPanel API 2 bridge for Cron operations missing from UAPI."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from .errors import UsageError
from .inputs import fingerprint
from .operations import MAX_TEXT_BYTES, validate_value
from .profiles import Profile
from .transport import UAPIResponse


class API2TransportLike(Protocol):
    def call_api2(
        self,
        profile: Profile,
        token: str,
        module: str,
        function: str,
        parameters: Mapping[str, object],
        timeout: int = 30,
        **kwargs: object,
    ) -> UAPIResponse: ...


@dataclass(frozen=True)
class LegacyCronOperation:
    name: str
    command: tuple[str, ...]
    module: str
    function: str
    risk: str
    elevated_impact: bool
    impact: str
    recovery: str
    fields: Mapping[str, str]
    required: tuple[str, ...]
    sensitive_fields: tuple[str, ...] = ()

    @property
    def identity(self) -> str:
        return f"cpanel-api-2/{self.module}/{self.function}"

    @property
    def requires_confirmation(self) -> bool:
        return self.risk == "destructive" or self.elevated_impact


def _operation(
    name: str,
    action: str,
    function: str,
    *,
    risk: str = "mutate",
    elevated_impact: bool = False,
    impact: str,
    recovery: str,
    fields: Mapping[str, str],
    required: tuple[str, ...] = (),
    sensitive_fields: tuple[str, ...] = (),
) -> LegacyCronOperation:
    return LegacyCronOperation(
        name=name,
        command=("cron", action),
        module="Cron",
        function=function,
        risk=risk,
        elevated_impact=elevated_impact,
        impact=impact,
        recovery=recovery,
        fields=MappingProxyType(dict(fields)),
        required=required,
        sensitive_fields=sensitive_fields,
    )


_SCHEDULE_FIELDS = ("minute", "hour", "day", "month", "weekday")
_SCHEDULE_RANGES = {
    "minute": (0, 59),
    "hour": (0, 23),
    "day": (1, 31),
    "month": (1, 12),
    "weekday": (0, 7),
}
_LINEKEY_RE = re.compile(r"^[A-Fa-f0-9]{8,128}$")


LEGACY_CRON_OPERATIONS = MappingProxyType(
    {
        "cron.list": _operation(
            "cron.list",
            "list",
            "listcron",
            risk="read",
            impact="List cron jobs through cPanel API 2 Cron::listcron.",
            recovery="No change is made.",
            fields={},
        ),
        "cron.get-email": _operation(
            "cron.get-email",
            "get-email",
            "get_email",
            risk="read",
            impact="Read the cron notification email through cPanel API 2 Cron::get_email.",
            recovery="No change is made.",
            fields={},
        ),
        "cron.set-email": _operation(
            "cron.set-email",
            "set-email",
            "set_email",
            impact="Set the cron notification email through cPanel API 2 Cron::set_email.",
            recovery="Set the cron notification email back to its previous value.",
            fields={"email": "email"},
            required=("email",),
        ),
        "cron.add": _operation(
            "cron.add",
            "add",
            "add_line",
            impact="Add a crontab entry through cPanel API 2 Cron::add_line.",
            recovery="Remove the added cron entry by linekey if it was created incorrectly.",
            fields={
                "minute": "minute",
                "hour": "hour",
                "day": "day",
                "month": "month",
                "weekday": "weekday",
                "command": "command",
            },
            required=(*_SCHEDULE_FIELDS, "command"),
            sensitive_fields=("command",),
        ),
        "cron.edit": _operation(
            "cron.edit",
            "edit",
            "edit_line",
            elevated_impact=True,
            impact=(
                "Edit an existing crontab entry by linekey through cPanel API 2 Cron::edit_line."
            ),
            recovery="Edit the cron entry back to its previous schedule and command.",
            fields={
                "linekey": "linekey",
                "minute": "minute",
                "hour": "hour",
                "day": "day",
                "month": "month",
                "weekday": "weekday",
                "command": "command",
            },
            required=("linekey", *_SCHEDULE_FIELDS, "command"),
            sensitive_fields=("command",),
        ),
        "cron.remove": _operation(
            "cron.remove",
            "remove",
            "remove_line",
            risk="destructive",
            impact=(
                "Remove an existing crontab entry by linekey through cPanel API 2 "
                "Cron::remove_line."
            ),
            recovery=(
                "Recreate the cron entry from a verified copy of its previous schedule and command."
            ),
            fields={"linekey": "linekey"},
            required=("linekey",),
        ),
    }
)


def _cron_atom(value: str, low: int, high: int, label: str) -> str:
    base = value
    step: str | None = None
    if "/" in value:
        base, step = value.split("/", 1)
        if not step.isdigit() or int(step) < 1 or int(step) > high:
            raise UsageError(f"Invalid cron {label}")
    if base == "*":
        return value
    if "-" in base:
        start, end = base.split("-", 1)
        if not start.isdigit() or not end.isdigit():
            raise UsageError(f"Invalid cron {label}")
        start_int, end_int = int(start), int(end)
        if start_int > end_int or start_int < low or end_int > high:
            raise UsageError(f"Invalid cron {label}")
        return value
    if not base.isdigit():
        raise UsageError(f"Invalid cron {label}")
    numeric = int(base)
    if numeric < low or numeric > high:
        raise UsageError(f"Invalid cron {label}")
    return value


def _cron_field(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise UsageError(f"Invalid cron {name}")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise UsageError(f"Invalid cron {name}")
    low, high = _SCHEDULE_RANGES[name]
    for atom in value.split(","):
        if not atom:
            raise UsageError(f"Invalid cron {name}")
        _cron_atom(atom, low, high, name)
    return value


def _linekey(value: object) -> str:
    if not isinstance(value, str) or _LINEKEY_RE.fullmatch(value) is None:
        raise UsageError("Invalid cron line key")
    return value


def _command(value: object) -> str:
    command = validate_value("bounded_text", value)
    if not isinstance(command, str) or not command:
        raise UsageError("Cron command must not be empty")
    if len(command.encode("utf-8")) > MAX_TEXT_BYTES:
        raise UsageError("Cron command exceeds the allowed size")
    if any(character in command for character in "\r\n"):
        raise UsageError("Cron command must be one line")
    if any(ord(character) < 32 and character not in "\t" for character in command):
        raise UsageError("Cron command contains unsupported control characters")
    return command


def _field_value(name: str, value: object) -> object:
    if name in _SCHEDULE_FIELDS:
        return _cron_field(name, value)
    if name == "linekey":
        return _linekey(value)
    if name == "command":
        return _command(value)
    if name == "email":
        return validate_value("email", value)
    return validate_value("bounded_text", value)


def resolve_legacy_cron_inputs(
    operation: LegacyCronOperation, values: Mapping[str, object]
) -> dict[str, object]:
    missing = [name for name in operation.required if values.get(name) is None]
    if missing:
        raise UsageError(f"Missing legacy cron parameter: {', '.join(missing)}")
    parameters: dict[str, object] = {}
    for name, api2_name in operation.fields.items():
        value = values.get(name)
        if value is None:
            continue
        parameters[api2_name] = _field_value(name, value)
    return parameters


def safe_legacy_cron_parameters(
    operation: LegacyCronOperation, parameters: Mapping[str, object]
) -> dict[str, object]:
    safe = dict(parameters)
    for name in operation.sensitive_fields:
        api2_name = operation.fields[name]
        value = safe.get(api2_name)
        if value is None:
            continue
        safe[api2_name] = fingerprint(str(value).encode("utf-8"))
    return safe


class LegacyCronExecutor:
    """Execute one fixed cPanel API 2 Cron operation."""

    def __init__(self, transport: API2TransportLike) -> None:
        self._transport = transport

    def execute(
        self,
        profile: Profile,
        token: str,
        operation: LegacyCronOperation,
        values: Mapping[str, object],
        *,
        timeout: int = 30,
    ) -> UAPIResponse:
        parameters = resolve_legacy_cron_inputs(operation, values)
        return self._transport.call_api2(
            profile,
            token,
            operation.module,
            operation.function,
            parameters,
            timeout,
        )
