"""Confirmation-bound plans for reviewed cPanel policy operations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import NoReturn, Protocol, TypeVar, cast

from .catalog import JsonValue
from .confirmation import ConfirmationService
from .inputs import ResolvedInputs
from .policy import PolicyError, PolicyOperation, Risk, SupportStatus

_KeyT = TypeVar("_KeyT")
_ValueT = TypeVar("_ValueT")


class _FrozenDict(dict[_KeyT, _ValueT]):
    def __init__(self, values: Mapping[_KeyT, _ValueT]) -> None:
        dict.__init__(self, values)

    def _reject_mutation(self, *args: object, **kwargs: object) -> NoReturn:
        raise TypeError("execution plan mappings are immutable")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    clear = _reject_mutation
    pop = _reject_mutation
    popitem = _reject_mutation
    setdefault = _reject_mutation
    update = _reject_mutation
    __ior__ = _reject_mutation


class _FrozenList(list[_ValueT]):
    def _reject_mutation(self, *args: object, **kwargs: object) -> NoReturn:
        raise TypeError("execution plan lists are immutable")

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


def _safe_mapping(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Copy a JSON mapping so plans cannot retain mutable caller state."""

    return _FrozenDict(
        {key: cast(JsonValue, _safe_value(item)) for key, item in sorted(value.items())}
    )


def _safe_value(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return _safe_mapping(value)
    if isinstance(value, list):
        return _FrozenList(_safe_value(item) for item in value)
    return value


@dataclass(frozen=True)
class BoundParameters:
    """All non-secret values cryptographically bound to a confirmation."""

    profile: str
    account: str
    identity: str
    operation: str
    risk: Risk
    elevated_impact: bool
    parameters: dict[str, JsonValue]
    preflight: JsonValue
    policy_digest: str
    policy_version: str
    expires_at: str | None


@dataclass(frozen=True)
class ExecutionPlan:
    profile: str
    account: str
    operation: str
    identity: str
    risk: Risk
    elevated_impact: bool
    parameters: dict[str, JsonValue]
    preflight: JsonValue
    impact: str
    recovery: str
    verification_available: bool
    requires_confirmation: bool
    expires_at: str | None
    confirmation: str | None
    bound_parameters: BoundParameters


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    category: str
    evidence: JsonValue


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

    def preflight(
        self, context: object, operation: PolicyOperation, inputs: ResolvedInputs
    ) -> JsonValue:
        del context, operation, inputs
        return None

    def to_uapi(
        self, operation: PolicyOperation, inputs: ResolvedInputs, preflight: JsonValue
    ) -> dict[str, object]:
        del preflight
        result: dict[str, object] = {}
        for name, parameter in operation.parameters.items():
            if name in inputs.values:
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
        policy_digest: str,
        policy_version: str = "1",
        adapters: Mapping[str, OperationAdapter] | None = None,
    ) -> None:
        if not isinstance(policy_digest, str) or not policy_digest:
            raise PolicyError("planner requires a trusted policy digest")
        if not isinstance(policy_version, str) or not policy_version:
            raise PolicyError("planner requires a trusted policy version")
        registry = {"default": DefaultOperationAdapter()}
        if adapters is not None:
            registry.update(dict(adapters))
        self._confirmations = confirmations
        self._policy_digest = policy_digest
        self._policy_version = policy_version
        self._adapters = MappingProxyType(registry)

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

    @staticmethod
    def _validate_operation(operation: PolicyOperation, inputs: ResolvedInputs) -> None:
        if operation.status is not SupportStatus.INCLUDED or operation.risk is None:
            raise PolicyError(f"operation is not included: {operation.identity}")
        unknown = set(inputs.values) - set(operation.parameters)
        if unknown:
            raise PolicyError("resolved inputs are outside the reviewed operation policy")

    def dry_run(
        self, context: object, operation: PolicyOperation, inputs: ResolvedInputs
    ) -> ExecutionPlan:
        self._validate_operation(operation, inputs)
        profile, account = self._context_identity(context)
        adapter = self._adapter(operation)
        preflight = _safe_value(adapter.preflight(context, operation, inputs))
        values = _safe_mapping(inputs.safe_values)
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
            _safe_mapping(values),
            _safe_value(preflight),
            operation.impact,
            operation.recovery,
            operation.verification is not None,
            requires_confirmation,
            expires_at,
            confirmation,
            bound,
        )

    def verify_confirmation(self, *args: object) -> None:
        """Verify a v2 plan; accepts the compact plan form and executor form."""

        if len(args) == 2 and isinstance(args[0], str) and isinstance(args[1], BoundParameters):
            digest, values = args
            expires_at = values.expires_at
        elif len(args) == 5:
            context, operation, values, digest, expires_at = args
            if not isinstance(operation, PolicyOperation) or not isinstance(
                values, BoundParameters
            ):
                raise PolicyError("confirmation must use a reviewed operation plan")
            profile, account = self._context_identity(context)
            if values.profile != profile or values.account != account:
                raise PolicyError("confirmation plan context does not match")
            if values.identity != operation.identity or values.operation != operation.name:
                raise PolicyError("confirmation plan operation does not match")
        else:
            raise TypeError(
                "verify_confirmation expects a plan or execution confirmation arguments"
            )
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
        return self._adapter(operation).verify(context, operation, inputs, response)
