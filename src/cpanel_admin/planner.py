"""Confirmation-bound plans for reviewed cPanel policy operations."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from math import isfinite
from os.path import basename, isabs
from types import MappingProxyType
from typing import Protocol, cast

from .catalog import JsonValue
from .confirmation import ConfirmationService
from .errors import TransportError
from .inputs import ResolvedInputs, fingerprint
from .policy import InputSource, PolicyError, PolicyOperation, PolicyRegistry, Risk, SupportStatus
from .redaction import redact
from .transport import UAPIResponse

_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_.-])/(?:[^\s/]+(?:/[^\s/]+)*)")


def _safe_string(value: str, *, secrets: tuple[str, ...]) -> str:
    """Return a public string that cannot disclose a secret or local path."""

    redacted = cast(str, redact(value, secrets=secrets))
    if isabs(redacted) or _ABSOLUTE_PATH.search(redacted):
        return "[REDACTED]"
    return redacted


def _safe_mapping(
    value: Mapping[str, object],
    *,
    secrets: tuple[str, ...] = (),
    preserve_fingerprints: bool = False,
) -> Mapping[str, JsonValue]:
    """Return a copied, deeply immutable public JSON mapping."""

    if not all(isinstance(key, str) for key in value):
        raise PolicyError("public evidence must be a JSON object with string keys")
    public: dict[str, JsonValue] = {}
    for key, item in sorted(value.items()):
        public_key = _safe_string(key, secrets=secrets)
        if public_key in public:
            raise PolicyError("public evidence contains duplicate redacted keys")
        redacted_item = item
        if not (preserve_fingerprints and _is_fingerprint(item)):
            redacted_item = cast(Mapping[str, object], redact({key: item}, secrets=secrets))[key]
        public[public_key] = cast(JsonValue, _safe_value(redacted_item, secrets=secrets))
    return MappingProxyType(public)


def _is_fingerprint(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != {"bytes", "sha256"}:
        return False
    size = value["bytes"]
    digest = value["sha256"]
    return (
        isinstance(size, int)
        and not isinstance(size, bool)
        and size >= 0
        and isinstance(digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
    )


def _is_file_fingerprint(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != {"name", "bytes", "sha256"}:
        return False
    name = value["name"]
    return (
        isinstance(name, str)
        and bool(name)
        and _is_fingerprint({"bytes": value["bytes"], "sha256": value["sha256"]})
    )


def _safe_value(value: object, *, secrets: tuple[str, ...] = ()) -> JsonValue:
    """Create immutable, redacted JSON evidence without retaining caller state."""

    if value is None or isinstance(value, bool | int):
        return cast(JsonValue, value)
    if isinstance(value, float):
        if not isfinite(value):
            raise PolicyError("public evidence must use finite JSON numbers")
        return cast(JsonValue, value)
    if isinstance(value, str):
        return _safe_string(value, secrets=secrets)
    if isinstance(value, Mapping):
        return _safe_mapping(value, secrets=secrets)
    if isinstance(value, list):
        return tuple(_safe_value(item, secrets=secrets) for item in value)
    if isinstance(value, tuple):
        return tuple(_safe_value(item, secrets=secrets) for item in value)
    raise PolicyError("public evidence must be JSON-safe")


def _canonical_public_inputs(
    operation: PolicyOperation, inputs: ResolvedInputs
) -> tuple[Mapping[str, JsonValue], tuple[str, ...]]:
    """Validate reviewed values and derive their only permitted public projection."""

    declared = set(operation.parameters)
    supplied = set(inputs.values)
    required = {name for name, parameter in operation.parameters.items() if parameter.required}
    if supplied - declared or required - supplied:
        raise PolicyError("resolved inputs must exactly match reviewed operation parameters")
    safe_values: dict[str, JsonValue] = {}
    secrets: list[str] = []
    for name in sorted(supplied):
        parameter = operation.parameters[name]
        value = inputs.values[name]
        if value is None:
            raise PolicyError(f"resolved inputs contain unnormalized optional parameter: {name}")
        source = parameter.sources[0] if len(parameter.sources) == 1 else None
        if source is InputSource.JSON_FILE:
            if not isinstance(value, Mapping) or not value:
                raise PolicyError(f"resolved JSON file input is invalid: {name}")
            safe_file = inputs.safe_values.get(name)
            if not _is_file_fingerprint(safe_file):
                raise PolicyError(f"resolved JSON file input has no fingerprint: {name}")
            safe_values[name] = cast(JsonValue, safe_file)
            continue
        try:
            from .operations import validate_value

            normalized = validate_value(parameter.validator, value)
        except Exception as exc:
            raise PolicyError(f"resolved input is invalid for reviewed parameter: {name}") from exc
        if normalized != value:
            raise PolicyError(f"resolved input is not normalized for reviewed parameter: {name}")
        if source is InputSource.LOCAL_FILE:
            if not isinstance(value, str):
                raise PolicyError(f"resolved local file input is invalid: {name}")
            matching_uploads = [
                upload
                for upload in inputs.uploads.values()
                if getattr(upload, "filename", None) == basename(value)
            ]
            if len(matching_uploads) != 1:
                raise PolicyError(f"resolved local file input has no matching upload: {name}")
            upload = matching_uploads[0]
            content = getattr(upload, "content", None)
            if not isinstance(content, bytes):
                raise PolicyError(f"resolved local file upload is invalid: {name}")
            safe_values[name] = {"name": basename(value), **fingerprint(content)}
        elif (
            parameter.secret
            or parameter.sensitive_output
            or source
            in {
                InputSource.STDIN,
                InputSource.PROTECTED_FILE,
                InputSource.ENVIRONMENT,
                InputSource.ENCRYPTED_PROFILE,
            }
        ):
            if not isinstance(normalized, str):
                raise PolicyError(f"protected reviewed input is invalid: {name}")
            safe_values[name] = fingerprint(normalized.encode("utf-8"))
        else:
            safe_values[name] = cast(JsonValue, _safe_value(normalized))
        if parameter.secret or parameter.sensitive_output:
            secrets.append(str(normalized))
    return _safe_mapping(safe_values, secrets=tuple(secrets), preserve_fingerprints=True), tuple(
        secrets
    )


def _validate_resolved_inputs(operation: PolicyOperation, inputs: ResolvedInputs) -> None:
    """Validate externally constructed values without trusting public metadata."""

    _canonical_public_inputs(operation, inputs)


@dataclass(frozen=True)
class BoundParameters:
    """All non-secret values cryptographically bound to a confirmation."""

    profile: str
    account: str
    identity: str
    operation: str
    risk: Risk
    elevated_impact: bool
    parameters: Mapping[str, JsonValue]
    preflight: JsonValue
    policy_digest: str
    policy_version: str
    expires_at: str | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "parameters", _safe_mapping(self.parameters, preserve_fingerprints=True)
        )
        object.__setattr__(self, "preflight", _safe_value(self.preflight))


@dataclass(frozen=True)
class ExecutionPlan:
    profile: str
    account: str
    operation: str
    identity: str
    risk: Risk
    elevated_impact: bool
    parameters: Mapping[str, JsonValue]
    preflight: JsonValue
    impact: str
    recovery: str
    verification_available: bool
    requires_confirmation: bool
    expires_at: str | None
    confirmation: str | None
    bound_parameters: BoundParameters

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "parameters", _safe_mapping(self.parameters, preserve_fingerprints=True)
        )
        object.__setattr__(self, "preflight", _safe_value(self.preflight))


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    category: str
    evidence: JsonValue

    def __post_init__(self) -> None:
        if not isinstance(self.ok, bool) or not isinstance(self.category, str):
            raise PolicyError("verification result must have a boolean status and string category")
        object.__setattr__(self, "evidence", _safe_value(self.evidence))


class OperationAdapter(Protocol):
    """Reviewed adapter boundary for operation-specific planning behavior."""

    def preflight(
        self, context: object, operation: PolicyOperation, inputs: ResolvedInputs
    ) -> JsonValue: ...

    def to_uapi(
        self, operation: PolicyOperation, inputs: ResolvedInputs, preflight: JsonValue
    ) -> dict[str, object]: ...

    def verify(
        self,
        context: object,
        operation: PolicyOperation,
        inputs: ResolvedInputs,
        response: object,
    ) -> VerificationResult: ...


class DefaultOperationAdapter:
    """Declarative catalog mapping for operations with no bespoke adapter."""

    preflight_selector: None = None

    def preflight(
        self, context: object, operation: PolicyOperation, inputs: ResolvedInputs
    ) -> JsonValue:
        del context, operation, inputs
        return None

    def to_uapi(
        self, operation: PolicyOperation, inputs: ResolvedInputs, preflight: JsonValue
    ) -> dict[str, object]:
        del preflight
        _validate_resolved_inputs(operation, inputs)
        result: dict[str, object] = {}
        for name, parameter in operation.parameters.items():
            if name not in inputs.values:
                continue
            if parameter.sources[0] is InputSource.LOCAL_FILE:
                continue
            result[parameter.uapi_name] = inputs.values[name]
        return result

    def verify(
        self,
        context: object,
        operation: PolicyOperation,
        inputs: ResolvedInputs,
        response: object,
    ) -> VerificationResult:
        del context, inputs, response
        if operation.verification is None:
            return VerificationResult(True, "not_available", {})
        return VerificationResult(
            False,
            "verification",
            {"reason": "reviewed verification operation requires a dedicated adapter"},
        )


class OperationPlanner:
    """Plan, confirm, and verify fixed policy operations."""

    def __init__(
        self,
        confirmations: ConfirmationService,
        *,
        registry: PolicyRegistry,
        policy_digest: str,
        policy_version: str = "1",
        adapters: Mapping[str, OperationAdapter] | None = None,
    ) -> None:
        if not isinstance(policy_digest, str) or not policy_digest:
            raise PolicyError("planner requires a trusted policy digest")
        if not isinstance(policy_version, str) or not policy_version:
            raise PolicyError("planner requires a trusted policy version")
        if not isinstance(registry, PolicyRegistry):
            raise PolicyError("planner requires a validated policy registry")
        adapter_registry = {"default": DefaultOperationAdapter()}
        reviewed_selectors = {
            operation.feature for operation in registry.included() if operation.feature
        }
        if adapters is not None:
            supplied = dict(adapters)
            if set(supplied) - reviewed_selectors or "default" in supplied:
                raise PolicyError("adapter registry contains an unreviewed selector")
            adapter_registry.update(supplied)
        self._confirmations = confirmations
        self._registry = registry
        self._policy_digest = policy_digest
        self._policy_version = policy_version
        self._adapters = MappingProxyType(adapter_registry)

    @staticmethod
    def _context_identity(context: object) -> tuple[str, str]:
        profile = getattr(context, "profile", None)
        name = getattr(profile, "name", None)
        account = getattr(profile, "username", None)
        if not isinstance(name, str) or not name or not isinstance(account, str) or not account:
            raise PolicyError("planner context must contain a validated profile and account")
        return name, account

    def _adapter(self, operation: PolicyOperation) -> OperationAdapter:
        name = operation.feature or "default"
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise PolicyError(f"missing reviewed operation adapter: {name}") from exc

    def _preflight_adapter(self, operation: PolicyOperation) -> OperationAdapter:
        if operation.preflight is None:
            return self._adapter(operation)
        if not operation.feature:
            raise PolicyError("reviewed preflight requires a non-default adapter feature")
        try:
            adapter = self._adapter(operation)
        except PolicyError as exc:
            raise PolicyError("reviewed preflight requires a bound non-default adapter") from exc
        selector = getattr(adapter, "preflight_selector", None)
        if not isinstance(selector, str) or selector != operation.preflight:
            raise PolicyError("reviewed preflight adapter does not support its declared selector")
        return adapter

    def _validate_operation(
        self, operation: PolicyOperation, inputs: ResolvedInputs | None = None
    ) -> None:
        if operation.status is not SupportStatus.INCLUDED or operation.risk is None:
            raise PolicyError(f"operation is not included: {operation.identity}")
        try:
            reviewed = self._registry.get(operation.name)
        except PolicyError as exc:
            raise PolicyError("operation is not from the reviewed policy registry") from exc
        if reviewed is not operation:
            raise PolicyError("operation is not from the reviewed policy registry")
        if inputs is not None:
            _validate_resolved_inputs(operation, inputs)

    def dry_run(
        self, context: object, operation: PolicyOperation, inputs: ResolvedInputs
    ) -> ExecutionPlan:
        self._validate_operation(operation, inputs)
        profile, account = self._context_identity(context)
        values, secrets = _canonical_public_inputs(operation, inputs)
        preflight: JsonValue = None
        if operation.name in {"files.write", "files.upload"}:
            preflight = _safe_value(_file_preflight(context, operation, inputs), secrets=secrets)
        elif operation.preflight is not None:
            adapter = self._preflight_adapter(operation)
            preflight = _safe_value(adapter.preflight(context, operation, inputs), secrets=secrets)
        bound = BoundParameters(
            profile,
            account,
            operation.identity,
            operation.name,
            operation.risk,
            operation.elevated_impact,
            values,
            preflight,
            self._policy_digest,
            self._policy_version,
            None,
        )
        requires_confirmation = operation.requires_confirmation
        confirmation: str | None = None
        expires_at: str | None = None
        if requires_confirmation:
            planned = self._confirmations.plan_v2(
                profile=bound.profile,
                account=bound.account,
                identity=bound.identity,
                operation=bound.operation,
                parameters=bound.parameters,
                preflight=bound.preflight,
                policy_digest=bound.policy_digest,
                risk=bound.risk.value,
                elevated_impact=bound.elevated_impact,
                policy_version=bound.policy_version,
            )
            confirmation, expires_at = planned.confirmation, planned.expires_at
            bound = replace(bound, expires_at=expires_at)
        return ExecutionPlan(
            profile,
            account,
            operation.name,
            operation.identity,
            operation.risk,
            operation.elevated_impact,
            _safe_mapping(values, preserve_fingerprints=True),
            _safe_value(preflight, secrets=secrets),
            operation.impact,
            operation.recovery,
            operation.verification is not None,
            requires_confirmation,
            expires_at,
            confirmation,
            bound,
        )

    def verify_confirmation(
        self,
        context: object,
        operation: PolicyOperation,
        values: BoundParameters,
        digest: str,
        expires_at: str | None,
    ) -> None:
        """Verify a confirmation against a registry-owned v2 operation plan."""

        self._validate_operation(operation)
        if not isinstance(values, BoundParameters):
            raise PolicyError("confirmation must use a reviewed operation plan")
        profile, account = self._context_identity(context)
        if values.profile != profile or values.account != account:
            raise PolicyError("confirmation plan context does not match")
        if values.identity != operation.identity or values.operation != operation.name:
            raise PolicyError("confirmation plan operation does not match")
        if not isinstance(digest, str):
            raise PolicyError("confirmation digest must be a string")
        if expires_at is None:
            raise PolicyError("confirmation expiry is required")
        if not isinstance(expires_at, str):
            raise PolicyError("confirmation expiry must be a string")
        self._confirmations.verify_v2(
            digest,
            profile=values.profile,
            account=values.account,
            identity=values.identity,
            operation=values.operation,
            parameters=values.parameters,
            preflight=values.preflight,
            policy_digest=values.policy_digest,
            expires_at=expires_at,
            risk=values.risk.value,
            elevated_impact=values.elevated_impact,
            policy_version=values.policy_version,
        )

    def verify(
        self,
        context: object,
        operation: PolicyOperation,
        inputs: ResolvedInputs,
        response: object,
    ) -> VerificationResult:
        self._validate_operation(operation, inputs)
        self._context_identity(context)
        _, secrets = _canonical_public_inputs(operation, inputs)
        result = self._adapter(operation).verify(context, operation, inputs, response)
        if not isinstance(result, VerificationResult):
            try:
                result = VerificationResult(result.ok, result.category, result.evidence)
            except (AttributeError, PolicyError) as exc:
                raise PolicyError("adapter returned malformed verification evidence") from exc
        return VerificationResult(
            bool(result.ok),
            str(result.category),
            _safe_value(result.evidence, secrets=secrets),
        )


def _file_preflight(
    context: object, operation: PolicyOperation, inputs: ResolvedInputs
) -> JsonValue:
    profile = getattr(context, "profile", None)
    token = getattr(context, "token", None)
    transport = getattr(context, "transport", None)
    timeout = getattr(context, "timeout", 30)
    if profile is None or not isinstance(token, str) or transport is None:
        raise PolicyError("file preflight requires a validated execution context")
    directory = str(inputs.values["directory"])
    filename = _file_preflight_filename(operation, inputs)
    response = transport.call(
        profile,
        token,
        "Fileman",
        "list_files",
        {"dir": directory},
        timeout,
    )
    if not isinstance(response, UAPIResponse) or not isinstance(response.data, list):
        raise TransportError("cPanel returned an invalid file preflight listing")
    for item in response.data:
        if isinstance(item, Mapping) and item.get("file") == filename:
            metadata = _json_compatible(_safe_value(item, secrets=(token, *inputs.secrets)))
            return {"exists": True, "metadata": metadata}
    return {"exists": False}


def _file_preflight_filename(operation: PolicyOperation, inputs: ResolvedInputs) -> str:
    if operation.name == "files.write":
        return str(inputs.values["filename"])
    if operation.name == "files.upload":
        uploads = tuple(inputs.uploads.values())
        if len(uploads) != 1:
            raise PolicyError("file upload preflight requires exactly one upload")
        return uploads[0].filename
    raise PolicyError("operation does not support file preflight")


def _json_compatible(value: object) -> JsonValue:
    if value is None or isinstance(value, str | int | bool):
        return cast(JsonValue, value)
    if isinstance(value, float):
        if not isfinite(value):
            raise PolicyError("public evidence must use finite JSON numbers")
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_compatible(item) for item in value]
    raise PolicyError("public evidence must be JSON-safe")
