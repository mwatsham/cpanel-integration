from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.confirmation import ConfirmationError, ConfirmationService
from cpanel_admin.inputs import ResolvedInputs, fingerprint
from cpanel_admin.planner import OperationPlanner
from cpanel_admin.policy import (
    InputSource,
    PolicyError,
    PolicyOperation,
    PolicyParameter,
    PolicyRegistry,
    Risk,
    SupportStatus,
)
from cpanel_admin.profiles import Profile
from cpanel_admin.transport import Upload


@dataclass(frozen=True)
class Context:
    profile: Profile


def operation(
    *,
    name: str = "databases.create-user",
    identity: str = "Mysql/create_user",
    risk: Risk = Risk.MUTATE,
    elevated_impact: bool = True,
    verification: str | None = None,
    parameters: dict[str, PolicyParameter] | None = None,
) -> PolicyOperation:
    return PolicyOperation(
        name=name,
        identity=identity,
        command=("databases", "create-user"),
        capability="databases",
        status=SupportStatus.INCLUDED,
        reason="covered by a unit test",
        risk=risk,
        elevated_impact=elevated_impact,
        parameters=parameters
        or {
            "name": PolicyParameter("name", "name", (InputSource.ARGUMENT,), "database", True),
            "source": PolicyParameter(
                "source", "source", (InputSource.LOCAL_FILE,), "local_file", True
            ),
        },
        impact="Change the test account",
        recovery="Reverse the test change",
        preflight=None,
        verification=verification,
        feature=None,
        audit_fields=(),
    )


def context() -> Context:
    return Context(Profile("test", "panel.example.test", 2083, "acct", "encrypted"))


def inputs() -> ResolvedInputs:
    source = b"upload-data"
    return ResolvedInputs(
        values={"name": "acct_user", "source": "/private/path/upload.txt"},
        safe_values={"name": "acct_user", "source": {"name": "upload.txt", **fingerprint(source)}},
        uploads={"file-1": Upload("upload.txt", source, "text/plain")},
        secrets=(),
    )


def planner(subject: PolicyOperation) -> OperationPlanner:
    key = Fernet.generate_key()
    return OperationPlanner(
        ConfirmationService(key, clock=lambda: datetime(2026, 7, 14, tzinfo=UTC)),
        policy_digest="reviewed-policy",
        registry=PolicyRegistry((subject,), (), ()),
    )


def test_elevated_mutation_requires_confirmation() -> None:
    policy = operation()
    plan = planner(policy).dry_run(context(), policy, inputs())

    assert plan.requires_confirmation is True
    assert plan.confirmation is not None


def test_confirmation_binds_identity_file_hash_and_preflight() -> None:
    policy = operation()
    subject = planner(policy)
    plan = subject.dry_run(context(), policy, inputs())
    changed = replace(plan.bound_parameters, preflight={"etag": "changed"})

    with pytest.raises(ConfirmationError, match="does not match"):
        subject.verify_confirmation(context(), policy, changed, plan.confirmation, plan.expires_at)


def test_mutation_verification_detects_contradictory_state() -> None:
    policy = operation(verification="verified")
    subject = planner(policy)
    result = subject.verify(context(), policy, inputs(), {"expected": False})

    assert result.ok is False
    assert result.category == "verification"


def test_plan_values_are_immutable_and_bind_elevated_impact() -> None:
    policy = operation()
    subject = planner(policy)
    plan = subject.dry_run(context(), policy, inputs())

    with pytest.raises(TypeError):
        plan.parameters["name"] = "changed"
    changed = replace(plan.bound_parameters, elevated_impact=False)
    with pytest.raises(ConfirmationError, match="does not match"):
        subject.verify_confirmation(context(), policy, changed, plan.confirmation, plan.expires_at)


def test_planner_rejects_caller_constructed_operation_before_adapter_resolution() -> None:
    with pytest.raises(PolicyError, match="reviewed policy registry"):
        policy = operation()
        planner(policy).dry_run(context(), operation(), inputs())


class ContradictionAdapter:
    def __init__(self) -> None:
        self.preflight_calls = 0

    def preflight(
        self, context: object, operation: PolicyOperation, inputs: ResolvedInputs
    ) -> object:
        del context, operation, inputs
        self.preflight_calls += 1
        return {"etag": "stable"}

    def to_uapi(
        self, operation: PolicyOperation, inputs: ResolvedInputs, preflight: object
    ) -> dict[str, object]:
        del operation, inputs, preflight
        return {}

    def verify(
        self, context: object, operation: PolicyOperation, inputs: ResolvedInputs, response: object
    ):
        del context, operation, inputs
        return type(
            "Result",
            (),
            {
                "ok": response == {"exists": True},
                "category": "verification",
                "evidence": {"response": response},
            },
        )()


def test_preflight_runs_only_when_policy_declares_it_and_adapter_detects_contradiction() -> None:
    adapter = ContradictionAdapter()
    policy = operation(verification="verify")
    planner_without_preflight = OperationPlanner(
        ConfirmationService(Fernet.generate_key()),
        registry=PolicyRegistry((policy,), (), ()),
        policy_digest="reviewed-policy",
    )
    planner_without_preflight.dry_run(context(), policy, inputs())
    assert adapter.preflight_calls == 0

    declared = replace(policy, preflight="check", feature="test-adapter")
    subject = OperationPlanner(
        ConfirmationService(Fernet.generate_key()),
        registry=PolicyRegistry((declared,), (), ()),
        policy_digest="reviewed-policy",
        adapters={"test-adapter": adapter},
    )
    plan = subject.dry_run(context(), declared, inputs())
    result = subject.verify(context(), declared, inputs(), {"exists": False})

    assert adapter.preflight_calls == 1
    assert plan.preflight == {"etag": "stable"}
    assert result.ok is False
    assert result.category == "verification"
