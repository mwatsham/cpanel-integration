from __future__ import annotations

from dataclasses import dataclass

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.confirmation import ConfirmationService
from cpanel_admin.errors import AuditError, ConfirmationError, TransportError
from cpanel_admin.executor import ExecutionContext, OperationExecutor
from cpanel_admin.inputs import ResolvedInputs
from cpanel_admin.planner import OperationPlanner
from cpanel_admin.policy import (
    InputSource,
    PolicyOperation,
    PolicyParameter,
    PolicyRegistry,
    Risk,
    SupportStatus,
)
from cpanel_admin.profiles import Profile
from cpanel_admin.transport import UAPIResponse


def operation(*, risk: Risk = Risk.READ, elevated_impact: bool = False) -> PolicyOperation:
    return PolicyOperation(
        name="domains.list",
        identity="DomainInfo/list_domains",
        command=("domains", "list"),
        capability="domains",
        status=SupportStatus.INCLUDED,
        reason="covered by a unit test",
        risk=risk,
        elevated_impact=elevated_impact,
        parameters={},
        impact="Inspect domains",
        recovery="No account change is made",
        preflight=None,
        verification=None,
        feature=None,
        audit_fields=(),
    )


def mutation(*, risk: Risk = Risk.MUTATE) -> PolicyOperation:
    return PolicyOperation(
        name="databases.create",
        identity="Mysql/create_database",
        command=("databases", "create"),
        capability="databases",
        status=SupportStatus.INCLUDED,
        reason="covered by a unit test",
        risk=risk,
        elevated_impact=False,
        parameters={
            "name": PolicyParameter("name", "name", (InputSource.ARGUMENT,), "database", True)
        },
        impact="Create a database",
        recovery="Remove the database",
        preflight=None,
        verification=None,
        feature=None,
        audit_fields=("name",),
    )


def inputs(values: dict[str, object] | None = None) -> ResolvedInputs:
    return ResolvedInputs(values or {}, values or {}, {}, ())


@dataclass
class TransportCall:
    identity: str
    parameters: dict[str, object]
    method: str


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[TransportCall] = []
        self.mutation_calls: list[TransportCall] = []

    def call(
        self,
        profile,
        token,
        module,
        function,
        parameters,
        timeout=30,
        *,
        method="GET",
        **kwargs,
    ):
        del token, timeout, kwargs
        call = TransportCall(f"{module}/{function}", dict(parameters), method)
        self.calls.append(call)
        if method == "POST" or function not in {"list_domains"}:
            self.mutation_calls.append(call)
        return UAPIResponse(data={"profile": profile.name}, warnings=[], messages=[])


@dataclass(frozen=True)
class AuditRecord:
    operation: str
    identity: str
    outcome: str
    error_category: str | None


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[AuditRecord] = []

    def write(self, event, *, fail_closed):
        del fail_closed
        self.events.append(
            AuditRecord(event.operation, event.identity, event.outcome, event.error_category)
        )
        return True


def context(subject: PolicyOperation) -> ExecutionContext:
    transport = FakeTransport()
    audit = FakeAudit()
    return ExecutionContext(
        profile=Profile("test", "panel.example.test", 2083, "acct", "encrypted"),
        token="api-token",
        timeout=30,
        transport=transport,
        audit=audit,
        policy=PolicyRegistry((subject,), (), ()),
    )


def executor(subject: PolicyOperation) -> OperationExecutor:
    registry = PolicyRegistry((subject,), (), ())
    return OperationExecutor(
        registry=registry,
        planner=OperationPlanner(
            ConfirmationService(Fernet.generate_key()),
            registry=registry,
            policy_digest="test-policy",
        ),
    )


def test_read_execution_checks_policy_calls_transport_and_audits() -> None:
    subject = operation()
    runtime = context(subject)

    result = executor(subject).execute(runtime, subject, inputs(), confirmation=None)

    assert result.ok is True
    assert result.identity == "DomainInfo/list_domains"
    assert runtime.transport.calls[0].identity == "DomainInfo/list_domains"
    assert runtime.audit.events[0].outcome == "success"


def test_mutation_dry_run_never_calls_mutating_transport() -> None:
    subject = mutation()
    runtime = context(subject)

    plan = executor(subject).dry_run(runtime, subject, inputs({"name": "acct_demo"}))

    assert plan.operation == subject.name
    assert runtime.transport.mutation_calls == []


def test_confirmed_execution_uses_original_confirmation_expiry() -> None:
    subject = mutation(risk=Risk.DESTRUCTIVE)
    runtime = context(subject)
    subject_inputs = inputs({"name": "acct_demo"})
    subject_executor = executor(subject)

    plan = subject_executor.dry_run(runtime, subject, subject_inputs)
    result = subject_executor.execute(
        runtime,
        subject,
        subject_inputs,
        confirmation=plan.confirmation,
        expires_at=plan.expires_at,
    )

    assert result.ok is True
    assert runtime.transport.mutation_calls[-1].identity == "Mysql/create_database"

    with pytest.raises(ConfirmationError, match="does not match"):
        subject_executor.execute(
            runtime,
            subject,
            inputs({"name": "acct_changed"}),
            confirmation=plan.confirmation,
            expires_at=plan.expires_at,
        )


def test_mutation_transport_failure_writes_failure_audit_and_reraises() -> None:
    subject = mutation()
    runtime = context(subject)

    class FailingTransport(FakeTransport):
        def call(self, *args, **kwargs):
            raise TransportError("remote API rejected safe message")

    runtime = ExecutionContext(
        profile=runtime.profile,
        token=runtime.token,
        timeout=runtime.timeout,
        transport=FailingTransport(),
        audit=runtime.audit,
        policy=runtime.policy,
    )

    with pytest.raises(TransportError, match="remote API rejected safe message"):
        executor(subject).execute(
            runtime,
            subject,
            inputs({"name": "acct_demo"}),
            confirmation=None,
        )

    assert [(event.outcome, event.error_category) for event in runtime.audit.events] == [
        ("intent", None),
        ("failure", "transport"),
    ]


def test_mutation_failure_audit_is_fail_closed() -> None:
    subject = mutation()
    runtime = context(subject)

    class FailingTransport(FakeTransport):
        def call(self, *args, **kwargs):
            raise TransportError("remote API rejected safe message")

    class FailingFailureAudit(FakeAudit):
        def write(self, event, *, fail_closed):
            super().write(event, fail_closed=fail_closed)
            if event.outcome == "failure":
                raise AuditError("Unable to write protected audit record")
            return True

    runtime = ExecutionContext(
        profile=runtime.profile,
        token=runtime.token,
        timeout=runtime.timeout,
        transport=FailingTransport(),
        audit=FailingFailureAudit(),
        policy=runtime.policy,
    )

    with pytest.raises(AuditError, match="Unable to write protected audit record"):
        executor(subject).execute(
            runtime,
            subject,
            inputs({"name": "acct_demo"}),
            confirmation=None,
        )

    assert [(event.outcome, event.error_category) for event in runtime.audit.events] == [
        ("intent", None),
        ("failure", "transport"),
    ]
