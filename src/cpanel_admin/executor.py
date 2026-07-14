"""Policy-driven execution pipeline for reviewed cPanel operations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Protocol, cast

from .audit import AuditEvent
from .capabilities import CapabilityService
from .catalog import JsonValue
from .errors import (
    CapabilityError,
    PartialFailure,
    TransportError,
    UAPIError,
    VerificationError,
)
from .inputs import ResolvedInputs
from .operations import OPERATIONS
from .planner import DefaultOperationAdapter, ExecutionPlan, OperationPlanner, VerificationResult
from .policy import PolicyError, PolicyOperation, PolicyRegistry, Risk
from .profiles import Profile
from .redaction import redact
from .transport import UAPIResponse


class TransportLike(Protocol):
    def call(
        self,
        profile: Profile,
        token: str,
        module: str,
        function: str,
        parameters: Mapping[str, object],
        timeout: int = 30,
        **kwargs: object,
    ) -> UAPIResponse: ...


class AuditLike(Protocol):
    def write(self, event: AuditEvent, *, fail_closed: bool) -> bool: ...


@dataclass(frozen=True)
class ExecutionContext:
    profile: Profile
    token: str
    timeout: int
    transport: TransportLike
    audit: AuditLike
    policy: PolicyRegistry | None = None


@dataclass(frozen=True)
class ExecutionResult:
    ok: bool
    profile: str
    operation: str
    identity: str
    data: JsonValue
    warnings: tuple[str, ...]
    messages: tuple[str, ...]
    verification: VerificationResult | None


class OperationExecutor:
    """Execute fixed policy operations through the shared safety pipeline."""

    def __init__(
        self,
        *,
        registry: PolicyRegistry,
        planner: OperationPlanner,
        capabilities: CapabilityService | None = None,
    ) -> None:
        if not isinstance(registry, PolicyRegistry):
            raise PolicyError("executor requires a validated policy registry")
        self._registry = registry
        self._planner = planner
        self._capabilities = capabilities or CapabilityService()
        self._adapter = DefaultOperationAdapter()

    def dry_run(
        self, context: ExecutionContext, operation: PolicyOperation, inputs: ResolvedInputs
    ) -> ExecutionPlan:
        reviewed = self._reviewed(operation)
        pipeline_context = self._pipeline_context(context)
        self._capabilities.require(pipeline_context, reviewed)
        return self._planner.dry_run(pipeline_context, reviewed, inputs)

    def execute(
        self,
        context: ExecutionContext,
        operation: PolicyOperation,
        inputs: ResolvedInputs,
        confirmation: str | None,
        expires_at: str | None = None,
    ) -> ExecutionResult:
        reviewed = self._reviewed(operation)
        pipeline_context = self._pipeline_context(context)
        self._capabilities.require(pipeline_context, reviewed)
        plan = self._planner.dry_run(pipeline_context, reviewed, inputs)
        if plan.requires_confirmation:
            self._planner.verify_confirmation(
                pipeline_context,
                reviewed,
                plan.bound_parameters,
                confirmation,
                expires_at,
            )
        is_mutation = reviewed.risk is not Risk.READ
        if is_mutation:
            self._write_audit(context, reviewed, plan, outcome="intent", fail_closed=True)
        verification: VerificationResult | None = None
        try:
            response = self._call_transport(context, reviewed, inputs, plan.preflight)
            if not isinstance(response, UAPIResponse):
                raise TransportError("cPanel transport returned an invalid response")
            if reviewed.verification is not None:
                verification = self._planner.verify(
                    pipeline_context, reviewed, inputs, response.data
                )
                if not verification.ok:
                    raise VerificationError("cPanel operation verification failed")
        except Exception as exc:
            if is_mutation:
                self._write_failure_audit(context, reviewed, plan, exc)
            raise
        fail_closed = is_mutation
        audit_ok = self._write_audit(
            context,
            reviewed,
            plan,
            outcome="success",
            fail_closed=fail_closed,
            verification=verification,
        )
        secrets = (context.token, *inputs.secrets)
        warnings = tuple(str(redact(str(item), secrets=secrets)) for item in response.warnings)
        if not is_mutation and not audit_ok:
            warnings = (*warnings, "audit")
        return ExecutionResult(
            ok=True,
            profile=context.profile.name,
            operation=reviewed.name,
            identity=reviewed.identity,
            data=cast(JsonValue, redact(response.data, secrets=secrets)),
            warnings=warnings,
            messages=tuple(str(redact(str(item), secrets=secrets)) for item in response.messages),
            verification=verification,
        )

    def _reviewed(self, operation: PolicyOperation) -> PolicyOperation:
        reviewed = self._registry.get(operation.name)
        if reviewed is not operation:
            raise PolicyError("operation is not from the reviewed policy registry")
        if reviewed.risk is None:
            raise PolicyError(f"operation is not executable: {reviewed.identity}")
        return reviewed

    def _pipeline_context(self, context: ExecutionContext) -> object:
        return SimpleNamespace(
            profile=context.profile,
            token=context.token,
            timeout=context.timeout,
            transport=context.transport,
            audit=context.audit,
            policy=self._registry,
        )

    def _call_transport(
        self,
        context: ExecutionContext,
        operation: PolicyOperation,
        inputs: ResolvedInputs,
        preflight: JsonValue,
    ) -> UAPIResponse:
        module, function = _identity_parts(operation)
        parameters = self._adapter.to_uapi(operation, inputs, preflight)
        legacy = OPERATIONS.get(operation.name)
        method = legacy.method if legacy is not None else "GET"
        kwargs: dict[str, object] = {"method": method}
        if inputs.uploads:
            kwargs["files"] = inputs.uploads
        sensitive_names = tuple(
            parameter.uapi_name
            for parameter in operation.parameters.values()
            if parameter.secret or parameter.sensitive_output
        )
        if sensitive_names:
            kwargs["sensitive_names"] = sensitive_names
        return context.transport.call(
            context.profile,
            context.token,
            module,
            function,
            parameters,
            context.timeout,
            **kwargs,
        )

    def _write_audit(
        self,
        context: ExecutionContext,
        operation: PolicyOperation,
        plan: ExecutionPlan,
        *,
        outcome: str,
        fail_closed: bool,
        error_category: str | None = None,
        verification: VerificationResult | None = None,
    ) -> bool:
        event = AuditEvent.from_policy(
            timestamp=datetime.now(UTC).isoformat(),
            profile=context.profile.name,
            operation=operation.name,
            identity=operation.identity,
            risk=operation.risk.value if operation.risk is not None else "unknown",
            confirmed=plan.requires_confirmation,
            safe_values=plan.parameters,
            audit_fields=operation.audit_fields,
            outcome=outcome,
            error_category=error_category,
            verification=verification.category if verification is not None else None,
        )
        return context.audit.write(event, fail_closed=fail_closed)

    def _write_failure_audit(
        self,
        context: ExecutionContext,
        operation: PolicyOperation,
        plan: ExecutionPlan,
        exc: BaseException,
    ) -> None:
        self._write_audit(
            context,
            operation,
            plan,
            outcome="failure",
            fail_closed=True,
            error_category=_error_category(exc),
        )


def _identity_parts(operation: PolicyOperation) -> tuple[str, str]:
    try:
        module, function = operation.identity.split("/", 1)
    except ValueError as exc:
        raise PolicyError("reviewed operation identity is invalid") from exc
    if not module or not function:
        raise PolicyError("reviewed operation identity is invalid")
    return module, function


def _error_category(exc: BaseException) -> str:
    if isinstance(exc, TransportError | UAPIError | PartialFailure):
        return "transport"
    if isinstance(exc, VerificationError):
        return "verification"
    if isinstance(exc, PolicyError | CapabilityError):
        return "policy"
    return "internal"
