"""Fail-closed policy metadata for the reviewed cPanel UAPI surface."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import NoReturn, TypeVar, cast

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
EXPECTED_CANDIDATE_OPERATIONS = 393
EXPECTED_CANDIDATE_IDENTITY_SHA256 = (
    "834c8bd9c048d93e9089fd22a7c569d4923cc8a5c9ecbc4172123ec2276a6ecb"
)
EXPECTED_POLICY_SHA256 = "7a8ab37229520c21486333d6f569ba4c434892916d449249398388f8c9cefbf0"

_PROTECTED_SECRET_SOURCES = frozenset(
    {
        "stdin",
        "protected_file",
        "environment",
        "encrypted_profile",
    }
)
_UPLOAD_IDENTITY = "Fileman/upload_files"
_UPLOAD_POLICY_PARAMETERS = frozenset({"directory", "source"})
_UPLOAD_UAPI_PARAMETERS = frozenset({"dir", "source"})
_RESERVED_DISPATCH_PARAMETERS = frozenset({"module", "function"})
_EnumT = TypeVar("_EnumT", bound=StrEnum)
_KeyT = TypeVar("_KeyT")
_ValueT = TypeVar("_ValueT")


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
class StableMVPOperationContract:
    name: str
    command: tuple[str, ...]
    status: SupportStatus = SupportStatus.INCLUDED


STABLE_MVP_OPERATION_CONTRACTS = MappingProxyType(
    {
        "DomainInfo/list_domains": StableMVPOperationContract("domains.list", ("domains", "list")),
        "DomainInfo/single_domain_data": StableMVPOperationContract(
            "domains.inspect", ("domains", "inspect")
        ),
        "WebVhosts/list_ssl_capable_domains": StableMVPOperationContract(
            "domains.ssl-capable", ("domains", "ssl-capable")
        ),
        "SubDomain/addsubdomain": StableMVPOperationContract(
            "domains.add-subdomain", ("domains", "add-subdomain")
        ),
        "Fileman/list_files": StableMVPOperationContract("files.list", ("files", "list")),
        "Fileman/get_file_information": StableMVPOperationContract(
            "files.inspect", ("files", "inspect")
        ),
        "Fileman/get_file_content": StableMVPOperationContract("files.read", ("files", "read")),
        "Fileman/save_file_content": StableMVPOperationContract("files.write", ("files", "write")),
        "Fileman/upload_files": StableMVPOperationContract("files.upload", ("files", "upload")),
        "Fileman/empty_trash": StableMVPOperationContract(
            "files.empty-trash", ("files", "empty-trash")
        ),
        "SSL/list_certs": StableMVPOperationContract("ssl.list", ("ssl", "list")),
        "SSL/installed_hosts": StableMVPOperationContract("ssl.hosts", ("ssl", "hosts")),
        "SSL/install_ssl": StableMVPOperationContract("ssl.install", ("ssl", "install")),
        "SSL/delete_ssl": StableMVPOperationContract("ssl.remove", ("ssl", "remove")),
        "Mysql/list_databases": StableMVPOperationContract("databases.list", ("databases", "list")),
        "Mysql/list_users": StableMVPOperationContract("databases.users", ("databases", "users")),
        "Mysql/create_database": StableMVPOperationContract(
            "databases.create", ("databases", "create")
        ),
        "Mysql/create_user": StableMVPOperationContract(
            "databases.create-user", ("databases", "create-user")
        ),
        "Mysql/set_privileges_on_database": StableMVPOperationContract(
            "databases.grant", ("databases", "grant")
        ),
        "Mysql/delete_database": StableMVPOperationContract(
            "databases.remove", ("databases", "remove")
        ),
        "Mysql/delete_user": StableMVPOperationContract(
            "databases.remove-user", ("databases", "remove-user")
        ),
    }
)


@dataclass(frozen=True)
class PolicyParameter:
    name: str
    uapi_name: str
    sources: tuple[InputSource, ...]
    validator: str
    required: bool
    secret: bool = False
    sensitive_output: bool = False


class _FrozenDict(dict[_KeyT, _ValueT]):
    """Concrete dict with all supported mutation entry points disabled."""

    def __init__(self, values: Mapping[_KeyT, _ValueT]) -> None:
        dict.__init__(self, values)

    def _reject_mutation(self, *args: object, **kwargs: object) -> NoReturn:
        raise TypeError("validated policy mappings are immutable")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    clear = _reject_mutation
    pop = _reject_mutation
    popitem = _reject_mutation
    setdefault = _reject_mutation
    update = _reject_mutation
    __ior__ = _reject_mutation


_PROTECTED_INPUT_CONTRACTS = MappingProxyType(
    dict(
        {
            ("Fileman/save_file_content", "content"): PolicyParameter(
                name="content",
                uapi_name="content",
                sources=(InputSource.STDIN,),
                validator="content",
                required=True,
                secret=True,
                sensitive_output=True,
            ),
            ("Mysql/create_user", "password"): PolicyParameter(
                name="password",
                uapi_name="password",
                sources=(InputSource.STDIN,),
                validator="secret",
                required=True,
                secret=True,
                sensitive_output=True,
            ),
            ("Email/add_pop", "password"): PolicyParameter(
                name="password",
                uapi_name="password",
                sources=(InputSource.STDIN,),
                validator="secret",
                required=True,
                secret=True,
                sensitive_output=True,
            ),
            ("Email/passwd_pop", "password"): PolicyParameter(
                name="password",
                uapi_name="password",
                sources=(InputSource.STDIN,),
                validator="secret",
                required=True,
                secret=True,
                sensitive_output=True,
            ),
            ("Email/verify_password", "password"): PolicyParameter(
                name="password",
                uapi_name="password",
                sources=(InputSource.STDIN,),
                validator="secret",
                required=True,
                secret=True,
                sensitive_output=True,
            ),
            ("Ftp/add_ftp", "password"): PolicyParameter(
                name="password",
                uapi_name="pass",
                sources=(InputSource.STDIN,),
                validator="secret",
                required=True,
                secret=True,
                sensitive_output=True,
            ),
            ("Ftp/passwd", "password"): PolicyParameter(
                name="password",
                uapi_name="pass",
                sources=(InputSource.STDIN,),
                validator="secret",
                required=True,
                secret=True,
                sensitive_output=True,
            ),
            ("EmailAuth/install_dkim_private_keys", "key"): PolicyParameter(
                name="key",
                uapi_name="key",
                sources=(InputSource.PROTECTED_FILE,),
                validator="private_key",
                required=True,
                secret=True,
                sensitive_output=True,
            ),
            ("SSL/install_ssl", "private_key"): PolicyParameter(
                name="private_key",
                uapi_name="key",
                sources=(InputSource.PROTECTED_FILE,),
                validator="private_key",
                required=True,
                secret=True,
                sensitive_output=True,
            ),
        }
    )
)


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


def policy_operation_to_dict(operation: PolicyOperation) -> dict[str, object]:
    """Serialize validated policy metadata without exposing runtime values."""

    return {
        "name": operation.name,
        "identity": operation.identity,
        "command": list(operation.command),
        "capability": operation.capability,
        "status": operation.status.value,
        "reason": operation.reason,
        "risk": operation.risk.value if operation.risk is not None else None,
        "elevated_impact": operation.elevated_impact,
        "parameters": {
            name: {
                "name": parameter.name,
                "uapi_name": parameter.uapi_name,
                "sources": [source.value for source in parameter.sources],
                "validator": parameter.validator,
                "required": parameter.required,
                "secret": parameter.secret,
                "sensitive_output": parameter.sensitive_output,
            }
            for name, parameter in sorted(operation.parameters.items())
        },
        "impact": operation.impact,
        "recovery": operation.recovery,
        "preflight": operation.preflight,
        "verification": operation.verification,
        "feature": operation.feature,
        "audit_fields": list(operation.audit_fields),
    }


class PolicyRegistry:
    """Validated, immutable lookup boundary around explicit operation policy."""

    def __init__(
        self,
        operations: tuple[PolicyOperation, ...],
        selected_modules: tuple[str, ...],
        candidate_identities: tuple[str, ...],
    ) -> None:
        self._operations = tuple(operations)
        self._selected_modules = tuple(selected_modules)
        self._candidate_identities = tuple(candidate_identities)
        self._by_name = MappingProxyType(
            dict({operation.name: operation for operation in operations})
        )
        self._by_identity = MappingProxyType(
            dict({operation.identity: operation for operation in operations})
        )
        self._by_command = MappingProxyType(
            dict({operation.command: operation for operation in operations if operation.command})
        )

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
        if len(candidates) != EXPECTED_CANDIDATE_OPERATIONS:
            raise PolicyError(
                "selected catalog surface must contain exactly "
                f"{EXPECTED_CANDIDATE_OPERATIONS} candidate operations"
            )
        candidate_digest = hashlib.sha256("\n".join(candidates).encode()).hexdigest()
        if candidate_digest != EXPECTED_CANDIDATE_IDENTITY_SHA256:
            raise PolicyError(
                "selected catalog surface does not match reviewed candidate identity digest"
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
        _validate_stable_mvp_operation_contracts(operations)
        _validate_protected_operation_presence(operations)
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


def _canonical_policy_json(operations: Mapping[str, object]) -> str:
    value = {
        "schema_version": 1,
        "selected_modules": list(SELECTED_MODULES),
        "operations": dict(operations),
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def canonical_policy_records_sha256(operations: Mapping[str, object]) -> str:
    """Hash exact normalized records using the reviewed policy representation."""

    return hashlib.sha256(_canonical_policy_json(operations).encode()).hexdigest()


def canonical_policy_sha256(registry: PolicyRegistry) -> str:
    """Hash every normalized field in a fully validated policy registry."""

    records = {
        operation.identity: policy_operation_to_dict(operation) for operation in registry.all()
    }
    return canonical_policy_records_sha256(records)


def _selected_modules(value: object) -> tuple[str, ...]:
    raw = _sequence(value, "policy selected_modules")
    if (
        not all(isinstance(item, str) and item for item in raw)
        or len(raw) != len(SELECTED_MODULES)
        or frozenset(raw) != frozenset(SELECTED_MODULES)
    ):
        raise PolicyError(
            "policy selected_modules must equal the exact approved 48-module boundary"
        )
    return SELECTED_MODULES


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
    required_shape = frozenset(
        {
            "name",
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
    if (
        not required_shape <= set(value)
        or value.get("risk") is not None
        or not isinstance(value.get("command"), list)
        or value.get("command") != []
        or not isinstance(value.get("parameters"), dict)
        or value.get("parameters") != {}
        or value.get("elevated_impact") is not False
        or not isinstance(value.get("impact"), str)
        or value.get("impact") != ""
        or not isinstance(value.get("recovery"), str)
        or value.get("recovery") != ""
        or value.get("preflight") is not None
        or value.get("verification") is not None
        or value.get("feature") is not None
        or not isinstance(value.get("audit_fields"), list)
        or value.get("audit_fields") != []
    ):
        raise PolicyError(f"excluded policy operation has invalid non-executable shape: {identity}")
    capability = _required_string(
        value.get("capability"), f"policy operation {identity} capability"
    )
    return PolicyOperation(
        name=_required_string(value.get("name"), f"policy operation {identity} name"),
        identity=identity,
        command=(),
        capability=capability,
        status=SupportStatus.EXCLUDED,
        reason=reason,
        risk=None,
        elevated_impact=False,
        parameters=_FrozenDict({}),
        impact="",
        recovery="",
        preflight=None,
        verification=None,
        feature=None,
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
        parameters=_FrozenDict(dict(parameters)),
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
    if identity == _UPLOAD_IDENTITY and frozenset(raw_parameters) != _UPLOAD_POLICY_PARAMETERS:
        raise PolicyError("Fileman/upload_files requires the exact directory and source parameters")
    parameters: dict[str, PolicyParameter] = {}
    for name in sorted(raw_parameters):
        if not isinstance(name, str) or not name:
            raise PolicyError(f"policy operation {identity} parameter names must be strings")
        if name.casefold() in _RESERVED_DISPATCH_PARAMETERS:
            raise PolicyError(f"reserved dispatch parameter for {identity}: {name}")
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
        if uapi_name.casefold() in _RESERVED_DISPATCH_PARAMETERS:
            raise PolicyError(f"reserved dispatch parameter for {identity}: {uapi_name}")
        required = _boolean(raw.get("required"), f"policy parameter {identity}:{name} required")
        catalog_parameter = catalog_operation.parameters.get(uapi_name)
        permitted_omission = identity == _UPLOAD_IDENTITY and uapi_name in (_UPLOAD_UAPI_PARAMETERS)
        if catalog_parameter is None and not permitted_omission:
            raise PolicyError(f"policy parameters do not match catalog for {identity}: {uapi_name}")
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
    if identity == _UPLOAD_IDENTITY:
        _validate_upload_contract(parameters)
    _validate_protected_input_contracts(identity, parameters)
    uapi_names = [parameter.uapi_name for parameter in parameters.values()]
    if len(uapi_names) != len(set(uapi_names)):
        raise PolicyError(f"duplicate UAPI parameter mapping for {identity}")
    missing_required = {
        name
        for name, parameter in catalog_operation.parameters.items()
        if parameter.required
        and not any(
            policy_parameter.uapi_name == name and policy_parameter.required
            for policy_parameter in parameters.values()
        )
    }
    if missing_required:
        raise PolicyError(
            f"policy parameters do not match required catalog inputs for {identity}: "
            f"{', '.join(sorted(missing_required))}"
        )
    return parameters


def _validate_protected_input_contracts(
    identity: str, parameters: Mapping[str, PolicyParameter]
) -> None:
    for (contract_identity, name), expected in _PROTECTED_INPUT_CONTRACTS.items():
        if contract_identity == identity and parameters.get(name) != expected:
            raise PolicyError(f"protected input contract mismatch for {identity}:{name}")


def _validate_protected_operation_presence(
    operations: tuple[PolicyOperation, ...],
) -> None:
    included_identities = {
        operation.identity for operation in operations if operation.status is SupportStatus.INCLUDED
    }
    required_identities = {identity for identity, _name in _PROTECTED_INPUT_CONTRACTS}
    missing = required_identities - included_identities
    if missing:
        raise PolicyError(
            "protected input operations must remain included: " + ", ".join(sorted(missing))
        )
    actual_secret_inputs = {
        (operation.identity, name)
        for operation in operations
        for name, parameter in operation.parameters.items()
        if parameter.secret
    }
    expected_secret_inputs = set(_PROTECTED_INPUT_CONTRACTS)
    if actual_secret_inputs != expected_secret_inputs:
        raise PolicyError("policy does not match authoritative secret input inventory")


def _validate_stable_mvp_operation_contracts(
    operations: tuple[PolicyOperation, ...],
) -> None:
    by_identity = {operation.identity: operation for operation in operations}
    name_owners = {
        contract.name: identity for identity, contract in STABLE_MVP_OPERATION_CONTRACTS.items()
    }
    command_owners = {
        contract.command: identity for identity, contract in STABLE_MVP_OPERATION_CONTRACTS.items()
    }
    for identity, contract in STABLE_MVP_OPERATION_CONTRACTS.items():
        operation = by_identity.get(identity)
        if (
            operation is None
            or operation.name != contract.name
            or operation.command != contract.command
            or operation.status is not contract.status
        ):
            raise PolicyError(f"stable MVP operation contract mismatch for {identity}")
    for operation in operations:
        if (
            operation.name in name_owners and name_owners[operation.name] != operation.identity
        ) or (
            operation.command in command_owners
            and command_owners[operation.command] != operation.identity
        ):
            raise PolicyError(f"extra stable MVP operation contract claim: {operation.identity}")


def _validate_upload_contract(parameters: Mapping[str, PolicyParameter]) -> None:
    directory = parameters["directory"]
    source = parameters["source"]
    if (
        directory.uapi_name != "dir"
        or directory.sources != (InputSource.ARGUMENT,)
        or directory.validator != "path"
        or directory.required is not True
        or directory.secret is not False
        or directory.sensitive_output is not False
    ):
        raise PolicyError("Fileman/upload_files directory parameter violates the dir contract")
    if (
        source.uapi_name != "source"
        or source.sources != (InputSource.LOCAL_FILE,)
        or source.validator != "local_file"
        or source.required is not True
        or source.secret is not False
        or source.sensitive_output is not False
    ):
        raise PolicyError("Fileman/upload_files source parameter violates the source contract")


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
