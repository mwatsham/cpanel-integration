"""Fail-closed policy metadata for the reviewed cPanel UAPI surface."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import TypeVar, cast

from .catalog import Catalog, CatalogOperation
from .errors import CPanelAdminError

SELECTED_MODULES = (
    "AccountEnhancements",
    "Backup",
    "Bandwidth",
    "BlockIP",
    "Chkservd",
    "ClamScanner",
    "ContactInformation",
    "DCV",
    "DNS",
    "DNSSEC",
    "DirectoryIndexes",
    "DirectoryPrivacy",
    "DirectoryProtection",
    "Domain",
    "DomainInfo",
    "DynamicDNS",
    "Email",
    "EmailAuth",
    "Features",
    "Fileman",
    "Ftp",
    "KnownHosts",
    "LangPHP",
    "LastLogin",
    "LogManager",
    "Mailboxes",
    "Mime",
    "ModSecurity",
    "Mysql",
    "NginxCaching",
    "PassengerApps",
    "Quota",
    "ResourceUsage",
    "Restore",
    "SSH",
    "SSL",
    "ServerInformation",
    "SpamAssassin",
    "Stats",
    "StatsBar",
    "StatsManager",
    "SubDomain",
    "UserTasks",
    "Variables",
    "VersionControl",
    "VersionControlDeployment",
    "WebVhosts",
    "cPGreyList",
)

_PROTECTED_SECRET_SOURCES = frozenset(
    {
        "stdin",
        "protected_file",
        "environment",
        "encrypted_profile",
    }
)
_CATALOG_PARAMETER_OMISSIONS = {
    # The pinned operation delegates multipart details to an external tutorial and declares no
    # parameters or request body, while the stable MVP transport requires these two fields.
    "Fileman/upload_files": frozenset({"dir", "source"}),
}
_EnumT = TypeVar("_EnumT", bound=StrEnum)


class PolicyError(CPanelAdminError):
    """The operation policy is missing, malformed, or contradictory."""


class SupportStatus(StrEnum):
    INCLUDED = "included"
    EXCLUDED = "excluded"


class Risk(StrEnum):
    READ = "read"
    MUTATE = "mutate"
    DESTRUCTIVE = "destructive"


class InputSource(StrEnum):
    ARGUMENT = "argument"
    STDIN = "stdin"
    PROTECTED_FILE = "protected_file"
    LOCAL_FILE = "local_file"
    ENVIRONMENT = "environment"
    ENCRYPTED_PROFILE = "encrypted_profile"


@dataclass(frozen=True)
class PolicyParameter:
    name: str
    uapi_name: str
    sources: tuple[InputSource, ...]
    validator: str
    required: bool
    secret: bool = False
    sensitive_output: bool = False


@dataclass(frozen=True)
class PolicyOperation:
    name: str
    identity: str
    command: tuple[str, ...]
    capability: str
    status: SupportStatus
    reason: str
    risk: Risk | None
    elevated_impact: bool
    parameters: dict[str, PolicyParameter]
    impact: str
    recovery: str
    preflight: str | None
    verification: str | None
    feature: str | None
    audit_fields: tuple[str, ...]

    @property
    def requires_confirmation(self) -> bool:
        return self.risk is Risk.DESTRUCTIVE or self.elevated_impact


@dataclass(frozen=True)
class PolicyCoverage:
    selected_modules: int
    candidate_operations: int
    missing: tuple[str, ...]
    pending_review: tuple[str, ...]


class PolicyRegistry:
    """Validated, immutable lookup boundary around explicit operation policy."""

    def __init__(
        self,
        operations: tuple[PolicyOperation, ...],
        selected_modules: tuple[str, ...],
        candidate_identities: tuple[str, ...],
    ) -> None:
        self._operations = operations
        self._selected_modules = selected_modules
        self._candidate_identities = candidate_identities
        self._by_name = {operation.name: operation for operation in operations}
        self._by_identity = {operation.identity: operation for operation in operations}
        self._by_command = {
            operation.command: operation for operation in operations if operation.command
        }

    @classmethod
    def load(cls, catalog: Catalog, path: Path | None = None) -> PolicyRegistry:
        try:
            if path is None:
                raw = (
                    resources.files("cpanel_admin")
                    .joinpath("data/operations.json")
                    .read_text(encoding="utf-8")
                )
            else:
                raw = path.read_text(encoding="utf-8")
            value = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            location = "packaged policy" if path is None else str(path)
            raise PolicyError(f"unable to load policy from {location}") from exc
        return cls.from_dict(catalog, _mapping(value, "policy"))

    @classmethod
    def from_dict(cls, catalog: Catalog, value: Mapping[str, object]) -> PolicyRegistry:
        _reject_unknown_fields(
            value,
            frozenset({"schema_version", "selected_modules", "operations"}),
            "policy",
        )
        if value.get("schema_version") != 1:
            raise PolicyError("policy schema_version must be 1")
        selected_modules = _selected_modules(value.get("selected_modules"))
        candidates = tuple(
            identity
            for identity, operation in sorted(catalog.operations.items())
            if operation.module in selected_modules
        )
        raw_operations = _operation_records(value.get("operations"))
        parsed: list[PolicyOperation] = []
        for identity, raw_operation in raw_operations:
            parsed.append(_operation_from_dict(catalog, identity, raw_operation))
        operations = tuple(sorted(parsed, key=lambda operation: operation.identity))
        _validate_uniqueness(operations)
        identities = {operation.identity for operation in operations}
        candidate_set = set(candidates)
        unexpected = tuple(sorted(identities - candidate_set))
        if unexpected:
            raise PolicyError(
                f"policy records are outside selected modules: {', '.join(unexpected)}"
            )
        missing = tuple(sorted(candidate_set - identities))
        if missing:
            raise PolicyError(f"missing policy records: {', '.join(missing)}")
        return cls(operations, selected_modules, candidates)

    def all(self) -> tuple[PolicyOperation, ...]:
        return self._operations

    def included(self) -> tuple[PolicyOperation, ...]:
        return tuple(
            operation
            for operation in self._operations
            if operation.status is SupportStatus.INCLUDED
        )

    def excluded(self) -> tuple[PolicyOperation, ...]:
        return tuple(
            operation
            for operation in self._operations
            if operation.status is SupportStatus.EXCLUDED
        )

    def get(self, name: str) -> PolicyOperation:
        try:
            operation = self._by_name[name]
        except KeyError as exc:
            raise PolicyError(f"unknown included policy operation: {name}") from exc
        if operation.status is not SupportStatus.INCLUDED:
            raise PolicyError(f"policy operation is excluded: {name}")
        return operation

    def by_command(self, path: tuple[str, ...]) -> PolicyOperation:
        try:
            return self._by_command[path]
        except KeyError as exc:
            raise PolicyError(f"unknown included command path: {' '.join(path)}") from exc

    def included_identities(self, capability: str) -> set[str]:
        return {
            operation.identity
            for operation in self.included()
            if operation.capability == capability
        }

    def exclusion(self, identity: str) -> PolicyOperation:
        try:
            operation = self._by_identity[identity]
        except KeyError as exc:
            raise PolicyError(f"unknown policy operation identity: {identity}") from exc
        if operation.status is not SupportStatus.EXCLUDED:
            raise PolicyError(f"policy operation is included: {identity}")
        return operation

    def coverage(self) -> PolicyCoverage:
        identities = set(self._by_identity)
        candidates = set(self._candidate_identities)
        return PolicyCoverage(
            selected_modules=len(self._selected_modules),
            candidate_operations=len(self._candidate_identities),
            missing=tuple(sorted(candidates - identities)),
            pending_review=(),
        )


def _selected_modules(value: object) -> tuple[str, ...]:
    raw = _sequence(value, "policy selected_modules")
    if not raw or not all(isinstance(item, str) and item for item in raw):
        raise PolicyError("policy selected_modules must contain non-empty strings")
    selected = cast(tuple[str, ...], raw)
    if len(set(selected)) != len(selected):
        raise PolicyError("policy selected_modules must be unique")
    return tuple(sorted(selected))


def _operation_records(
    value: object,
) -> tuple[tuple[str, Mapping[str, object]], ...]:
    if isinstance(value, Mapping):
        records: list[tuple[str, Mapping[str, object]]] = []
        for identity in sorted(value):
            if not isinstance(identity, str) or not identity:
                raise PolicyError("policy operation identities must be non-empty strings")
            records.append((identity, _mapping(value[identity], f"policy operation {identity}")))
        return tuple(records)
    raw_records = _sequence(value, "policy operations")
    records = []
    for value_record in raw_records:
        record = _mapping(value_record, "policy operation")
        identity = record.get("identity")
        if not isinstance(identity, str) or not identity:
            raise PolicyError("policy operation identity must be a non-empty string")
        records.append((identity, record))
    return tuple(records)


def _operation_from_dict(
    catalog: Catalog, identity: str, value: Mapping[str, object]
) -> PolicyOperation:
    allowed = frozenset(
        {
            "name",
            "identity",
            "command",
            "capability",
            "status",
            "reason",
            "risk",
            "elevated_impact",
            "parameters",
            "impact",
            "recovery",
            "preflight",
            "verification",
            "feature",
            "audit_fields",
        }
    )
    _reject_unknown_fields(value, allowed, f"policy operation {identity}")
    declared_identity = value.get("identity", identity)
    if declared_identity != identity:
        raise PolicyError(f"policy operation identity mismatch: {identity}")
    try:
        catalog_operation = catalog.operations[identity]
    except KeyError as exc:
        raise PolicyError(f"unknown catalog operation: {identity}") from exc
    status = _enum_value(SupportStatus, value.get("status"), "support status", identity)
    reason = _required_string(value.get("reason"), f"policy operation {identity} reason")
    if status is SupportStatus.EXCLUDED:
        return _excluded_operation(identity, value, reason)
    return _included_operation(identity, value, reason, catalog_operation)


def _excluded_operation(identity: str, value: Mapping[str, object], reason: str) -> PolicyOperation:
    contradictory = (
        value.get("risk") is not None
        or bool(value.get("command", ()))
        or bool(value.get("parameters", {}))
        or bool(value.get("elevated_impact", False))
    )
    if contradictory:
        raise PolicyError(f"excluded policy operation has contradictory metadata: {identity}")
    capability = _required_string(
        value.get("capability"), f"policy operation {identity} capability"
    )
    return PolicyOperation(
        name=_string(value.get("name", identity), f"policy operation {identity} name"),
        identity=identity,
        command=(),
        capability=capability,
        status=SupportStatus.EXCLUDED,
        reason=reason,
        risk=None,
        elevated_impact=False,
        parameters={},
        impact="",
        recovery="",
        preflight=None,
        verification=None,
        feature=_optional_string(value.get("feature"), f"policy operation {identity} feature"),
        audit_fields=(),
    )


def _included_operation(
    identity: str,
    value: Mapping[str, object],
    reason: str,
    catalog_operation: CatalogOperation,
) -> PolicyOperation:
    if catalog_operation.deprecated:
        raise PolicyError(f"deprecated catalog operation cannot be included: {identity}")
    risk = _enum_value(Risk, value.get("risk"), "risk", identity)
    command = _string_tuple(value.get("command"), f"policy operation {identity} command")
    if not command:
        raise PolicyError(f"policy operation {identity} command must not be empty")
    capability = _required_string(
        value.get("capability"), f"policy operation {identity} capability"
    )
    parameters = _parameters(value.get("parameters"), identity, catalog_operation)
    elevated_impact = _boolean(
        value.get("elevated_impact"), f"policy operation {identity} elevated_impact"
    )
    impact = _string(value.get("impact"), f"policy operation {identity} impact")
    recovery = _string(value.get("recovery"), f"policy operation {identity} recovery")
    if risk in {Risk.MUTATE, Risk.DESTRUCTIVE}:
        if not impact:
            raise PolicyError(f"mutating policy operation {identity} requires impact")
        if not recovery:
            raise PolicyError(f"mutating policy operation {identity} requires recovery")
    audit_fields = _string_tuple(
        value.get("audit_fields"), f"policy operation {identity} audit_fields"
    )
    unknown_audit_fields = set(audit_fields) - set(parameters)
    secret_audit_fields = {
        name for name in audit_fields if name in parameters and parameters[name].secret
    }
    if unknown_audit_fields or secret_audit_fields:
        raise PolicyError(f"policy operation {identity} has unsafe audit fields")
    return PolicyOperation(
        name=_required_string(value.get("name"), f"policy operation {identity} name"),
        identity=identity,
        command=command,
        capability=capability,
        status=SupportStatus.INCLUDED,
        reason=reason,
        risk=risk,
        elevated_impact=elevated_impact,
        parameters=parameters,
        impact=impact,
        recovery=recovery,
        preflight=_optional_string(
            value.get("preflight"), f"policy operation {identity} preflight"
        ),
        verification=_optional_string(
            value.get("verification"), f"policy operation {identity} verification"
        ),
        feature=_optional_string(value.get("feature"), f"policy operation {identity} feature"),
        audit_fields=audit_fields,
    )


def _parameters(
    value: object, identity: str, catalog_operation: CatalogOperation
) -> dict[str, PolicyParameter]:
    raw_parameters = _mapping(value, f"policy operation {identity} parameters")
    parameters: dict[str, PolicyParameter] = {}
    for name in sorted(raw_parameters):
        if not isinstance(name, str) or not name:
            raise PolicyError(f"policy operation {identity} parameter names must be strings")
        raw = _mapping(raw_parameters[name], f"policy parameter {identity}:{name}")
        _reject_unknown_fields(
            raw,
            frozenset(
                {
                    "name",
                    "uapi_name",
                    "sources",
                    "validator",
                    "required",
                    "secret",
                    "sensitive_output",
                }
            ),
            f"policy parameter {identity}:{name}",
        )
        if raw.get("name") != name:
            raise PolicyError(f"policy parameter name mismatch: {identity}:{name}")
        sources = tuple(
            _enum_value(InputSource, source, "input source", f"{identity}:{name}")
            for source in _sequence(
                raw.get("sources"), f"policy parameter {identity}:{name} sources"
            )
        )
        if not sources or len(set(sources)) != len(sources):
            raise PolicyError(f"policy parameter {identity}:{name} sources must be unique")
        secret = _boolean(raw.get("secret", False), f"policy parameter {identity}:{name} secret")
        if secret and any(source.value not in _PROTECTED_SECRET_SOURCES for source in sources):
            raise PolicyError(f"secret parameter {identity}:{name} requires a protected source")
        uapi_name = _required_string(
            raw.get("uapi_name"), f"policy parameter {identity}:{name} uapi_name"
        )
        required = _boolean(raw.get("required"), f"policy parameter {identity}:{name} required")
        catalog_parameter = catalog_operation.parameters.get(uapi_name)
        permitted_omissions = _CATALOG_PARAMETER_OMISSIONS.get(identity, frozenset())
        if (
            catalog_parameter is None
            and uapi_name not in permitted_omissions
            and "multipart/form-data" not in catalog_operation.request_media_types
        ):
            raise PolicyError(f"policy parameters do not match catalog for {identity}: {uapi_name}")
        if catalog_parameter is not None and catalog_parameter.required and not required:
            raise PolicyError(
                f"policy parameters do not match required catalog input for {identity}"
            )
        parameters[name] = PolicyParameter(
            name=name,
            uapi_name=uapi_name,
            sources=sources,
            validator=_required_string(
                raw.get("validator"), f"policy parameter {identity}:{name} validator"
            ),
            required=required,
            secret=secret,
            sensitive_output=_boolean(
                raw.get("sensitive_output", False),
                f"policy parameter {identity}:{name} sensitive_output",
            ),
        )
    exposed_names = {parameter.uapi_name for parameter in parameters.values()}
    missing_required = {
        name
        for name, parameter in catalog_operation.parameters.items()
        if parameter.required and name not in exposed_names
    }
    if missing_required:
        raise PolicyError(
            f"policy parameters do not match required catalog inputs for {identity}: "
            f"{', '.join(sorted(missing_required))}"
        )
    return parameters


def _validate_uniqueness(operations: tuple[PolicyOperation, ...]) -> None:
    names: set[str] = set()
    commands: set[tuple[str, ...]] = set()
    identities: set[str] = set()
    for operation in operations:
        if operation.name in names:
            raise PolicyError(f"duplicate policy operation name: {operation.name}")
        names.add(operation.name)
        if operation.identity in identities:
            raise PolicyError(f"duplicate policy operation identity: {operation.identity}")
        identities.add(operation.identity)
        if operation.command:
            if operation.command in commands:
                raise PolicyError(f"duplicate policy command path: {' '.join(operation.command)}")
            commands.add(operation.command)


def _enum_value(enum: type[_EnumT], value: object, label: str, identity: str) -> _EnumT:
    try:
        return enum(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"unknown {label} for {identity}: {value!r}") from exc


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> tuple[object, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise PolicyError(f"{label} must be an array")
    return tuple(value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise PolicyError(f"{label} must be a string")
    return value


def _required_string(value: object, label: str) -> str:
    result = _string(value, label)
    if not result:
        raise PolicyError(f"{label} must not be empty")
    return result


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _required_string(value, label)


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    result = _sequence(value, label)
    if not all(isinstance(item, str) and item for item in result):
        raise PolicyError(f"{label} must contain non-empty strings")
    return cast(tuple[str, ...], result)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{label} must be a boolean")
    return value


def _reject_unknown_fields(
    value: Mapping[str, object], allowed: frozenset[str], label: str
) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise PolicyError(f"{label} has unknown fields: {', '.join(sorted(unknown))}")
