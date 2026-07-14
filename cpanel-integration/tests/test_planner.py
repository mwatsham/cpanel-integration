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
    PolicyOperation,
    PolicyParameter,
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


def planner() -> OperationPlanner:
    key = Fernet.generate_key()
    return OperationPlanner(
        ConfirmationService(key, clock=lambda: datetime(2026, 7, 14, tzinfo=UTC)),
        policy_digest="reviewed-policy",
    )


def test_elevated_mutation_requires_confirmation() -> None:
    plan = planner().dry_run(context(), operation(), inputs())

    assert plan.requires_confirmation is True
    assert plan.confirmation is not None


def test_confirmation_binds_identity_file_hash_and_preflight() -> None:
    subject = planner()
    plan = subject.dry_run(context(), operation(), inputs())
    changed = replace(plan.bound_parameters, preflight={"etag": "changed"})

    with pytest.raises(ConfirmationError, match="does not match"):
        subject.verify_confirmation(plan.confirmation, changed)


def test_mutation_verification_detects_contradictory_state() -> None:
    subject = planner()
    result = subject.verify(
        context(), operation(verification="verified"), inputs(), {"expected": False}
    )

    assert result.ok is False
    assert result.category == "verification"


def test_plan_values_are_immutable_and_bind_elevated_impact() -> None:
    subject = planner()
    plan = subject.dry_run(context(), operation(), inputs())

    with pytest.raises(TypeError):
        plan.parameters["name"] = "changed"
    changed = replace(plan.bound_parameters, elevated_impact=False)
    with pytest.raises(ConfirmationError, match="does not match"):
        subject.verify_confirmation(plan.confirmation, changed)
