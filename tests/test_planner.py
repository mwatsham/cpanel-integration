from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.confirmation import ConfirmationError, ConfirmationService
from cpanel_admin.inputs import ResolvedInputs, fingerprint
from cpanel_admin.planner import (
    DefaultOperationAdapter,
    ExecutionPlan,
    OperationPlanner,
    VerificationResult,
)
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
    preflight_selector = "check"

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


@pytest.mark.parametrize(
    "resolved",
    (
        ResolvedInputs({"name": "acct"}, {"name": "acct"}, {}, ()),
        ResolvedInputs(
            {"name": "acct", "source": "/tmp/source", "extra": "no"},
            {"name": "acct", "source": {"name": "source"}, "extra": "no"},
            {},
            (),
        ),
    ),
)
def test_adapter_and_planner_reject_missing_or_extra_declared_inputs(
    resolved: ResolvedInputs,
) -> None:
    policy = operation()
    with pytest.raises(PolicyError, match="resolved inputs"):
        DefaultOperationAdapter().to_uapi(policy, resolved, None)
    with pytest.raises(PolicyError, match="resolved inputs"):
        planner(policy).dry_run(context(), policy, resolved)


def test_adapter_serializes_json_file_inputs_for_uapi() -> None:
    policy = operation(
        parameters={
            "source_repository": PolicyParameter(
                "source_repository",
                "source_repository",
                (InputSource.JSON_FILE,),
                "json_file",
                True,
            )
        }
    )
    source = {"url": "git@example.test:owner/site.git", "branch": "deploy-staging"}
    content = json.dumps(source).encode()
    resolved = ResolvedInputs(
        values={"source_repository": source},
        safe_values={
            "source_repository": {
                "name": "source-repository.json",
                **fingerprint(content),
            }
        },
        uploads={},
        secrets=(),
    )

    assert DefaultOperationAdapter().to_uapi(policy, resolved, None) == {
        "source_repository": ('{"branch":"deploy-staging","url":"git@example.test:owner/site.git"}')
    }


def test_preflight_requires_bound_reviewed_adapter_with_exact_selector() -> None:
    policy = replace(operation(), preflight="check", feature=None)
    with pytest.raises(PolicyError, match="preflight"):
        planner(policy).dry_run(context(), policy, inputs())

    policy = replace(policy, feature="test-adapter")
    with pytest.raises(PolicyError, match="preflight"):
        planner(policy).dry_run(context(), policy, inputs())

    wrong_selector = ContradictionAdapter()
    wrong_selector.preflight_selector = "other"
    subject = OperationPlanner(
        ConfirmationService(Fernet.generate_key()),
        registry=PolicyRegistry((policy,), (), ()),
        policy_digest="reviewed-policy",
        adapters={"test-adapter": wrong_selector},
    )
    with pytest.raises(PolicyError, match="preflight"):
        subject.dry_run(context(), policy, inputs())


def test_public_plan_and_verification_evidence_are_redacted_copied_and_json_safe() -> None:
    raw_safe = {
        "name": "acct_user",
        "password": "open-sesame",
        "source": {"nested": [{"path": "/private/tmp/token.txt", "note": "open-sesame"}]},
    }
    resolved = ResolvedInputs(
        {"name": "acct_user", "password": "open-sesame", "source": "/private/source"},
        raw_safe,
        {"file-1": Upload("source", b"source", "text/plain")},
        ("open-sesame",),
    )
    policy = operation(
        parameters={
            "name": PolicyParameter("name", "name", (InputSource.ARGUMENT,), "database", True),
            "password": PolicyParameter(
                "password", "password", (InputSource.STDIN,), "secret", True, secret=True
            ),
            "source": PolicyParameter(
                "source", "source", (InputSource.LOCAL_FILE,), "local_file", True
            ),
        }
    )
    subject = planner(policy)
    plan = subject.dry_run(context(), policy, resolved)
    raw_safe["source"]["nested"][0]["path"] = "/changed"

    assert "open-sesame" not in repr(plan)
    assert "/private/tmp/token.txt" not in repr(plan)
    assert plan.parameters["password"] == fingerprint(b"open-sesame")
    assert plan.parameters["source"] == {"name": "source", **fingerprint(b"source")}
    with pytest.raises(TypeError):
        plan.parameters["source"]["name"] = "changed"

    evidence = {"password": "open-sesame", "nested": ["/private/evidence"]}
    result = VerificationResult(True, "verified", evidence)
    evidence["nested"][0] = "changed"
    assert result.evidence == {"password": "[REDACTED]", "nested": ("[REDACTED]",)}
    with pytest.raises(PolicyError, match="JSON"):
        VerificationResult(True, "verified", {"bad": object()})

    with pytest.raises(PolicyError, match="JSON"):
        ExecutionPlan(
            "profile",
            "account",
            "operation",
            "identity",
            Risk.READ,
            False,
            {},
            object(),
            "",
            "",
            False,
            False,
            None,
            None,
            subject.dry_run(context(), policy, resolved).bound_parameters,
        )


def test_planner_redacts_and_copies_untrusted_adapter_evidence() -> None:
    evidence = {"password": "open-sesame", "details": [{"path": "/private/adapter"}]}

    class MaliciousAdapter:
        def preflight(self, context, operation, inputs):
            del context, operation, inputs
            return None

        def to_uapi(self, operation, inputs, preflight):
            del operation, inputs, preflight
            return {}

        def verify(self, context, operation, inputs, response):
            del context, operation, inputs, response
            return type(
                "UntrustedResult", (), {"ok": True, "category": "verified", "evidence": evidence}
            )()

    policy = replace(operation(), feature="malicious")
    subject = OperationPlanner(
        ConfirmationService(Fernet.generate_key()),
        registry=PolicyRegistry((policy,), (), ()),
        policy_digest="reviewed-policy",
        adapters={"malicious": MaliciousAdapter()},
    )

    result = subject.verify(context(), policy, inputs(), {})
    evidence["details"][0]["path"] = "/changed"

    assert result.evidence == {
        "password": "[REDACTED]",
        "details": ({"path": "[REDACTED]"},),
    }
    with pytest.raises(TypeError):
        result.evidence["details"][0]["path"] = "changed"


def test_planner_derives_safe_values_and_secret_redaction_from_reviewed_inputs() -> None:
    marker = "unlisted-secret"
    policy = operation(
        parameters={
            "name": PolicyParameter("name", "name", (InputSource.ARGUMENT,), "database", True),
            "password": PolicyParameter(
                "password", "password", (InputSource.STDIN,), "secret", True, secret=True
            ),
        }
    )
    resolved = ResolvedInputs(
        values={"name": "acct_user", "password": marker},
        safe_values={"name": "acct_user", "password": marker},
        uploads={},
        secrets=(),
    )

    plan = planner(policy).dry_run(context(), policy, resolved)

    assert plan.parameters == {
        "name": "acct_user",
        "password": fingerprint(marker.encode("utf-8")),
    }
    assert marker not in repr(plan)
    assert marker not in repr(plan.bound_parameters)


def test_planner_redacts_unlisted_secret_and_absolute_path_from_adapter_outputs() -> None:
    marker = "unlisted-secret"
    path = "/private/adapter/secret.txt"

    class MaliciousAdapter:
        preflight_selector = "check"

        def preflight(self, context, operation, inputs):
            del context, operation, inputs
            return {"ordinary": {"secret": marker, "path": path}}

        def to_uapi(self, operation, inputs, preflight):
            del operation, inputs, preflight
            return {}

        def verify(self, context, operation, inputs, response):
            del context, operation, inputs, response
            return type(
                "Result",
                (),
                {
                    "ok": True,
                    "category": "verified",
                    "evidence": {"ordinary": [marker, {"path": path}]},
                },
            )()

    policy = replace(
        operation(
            parameters={
                "name": PolicyParameter("name", "name", (InputSource.ARGUMENT,), "database", True),
                "password": PolicyParameter(
                    "password", "password", (InputSource.STDIN,), "secret", True, secret=True
                ),
            }
        ),
        feature="malicious",
        preflight="check",
    )
    resolved = ResolvedInputs(
        values={"name": "acct_user", "password": marker},
        safe_values={"name": "acct_user", "password": marker},
        uploads={},
        secrets=(),
    )
    subject = OperationPlanner(
        ConfirmationService(Fernet.generate_key()),
        registry=PolicyRegistry((policy,), (), ()),
        policy_digest="reviewed-policy",
        adapters={"malicious": MaliciousAdapter()},
    )

    plan = subject.dry_run(context(), policy, resolved)
    result = subject.verify(context(), policy, resolved, {})

    for public in (plan, plan.bound_parameters, result, plan.preflight, result.evidence):
        assert marker not in repr(public)
        assert path not in repr(public)
    assert plan.preflight == {"ordinary": {"secret": "[REDACTED]", "path": "[REDACTED]"}}
    assert result.evidence == {"ordinary": ("[REDACTED]", {"path": "[REDACTED]"})}


def test_public_plan_and_verification_containers_are_genuinely_immutable_mappings_and_tuples() -> (
    None
):
    class EvidenceAdapter:
        preflight_selector = "check"

        def preflight(self, context, operation, inputs):
            del context, operation, inputs
            return {"items": [{"etag": "stable"}]}

        def to_uapi(self, operation, inputs, preflight):
            del operation, inputs, preflight
            return {}

        def verify(self, context, operation, inputs, response):
            del context, operation, inputs, response
            return VerificationResult(True, "verified", {"items": [{"etag": "stable"}]})

    policy = replace(operation(), feature="evidence", preflight="check")
    subject = OperationPlanner(
        ConfirmationService(Fernet.generate_key()),
        registry=PolicyRegistry((policy,), (), ()),
        policy_digest="reviewed-policy",
        adapters={"evidence": EvidenceAdapter()},
    )
    plan = subject.dry_run(context(), policy, inputs())
    result = subject.verify(context(), policy, inputs(), {})

    for value in (plan.parameters, plan.preflight, result.evidence):
        assert isinstance(value, Mapping)
        assert not isinstance(value, dict)
        with pytest.raises(TypeError):
            dict.__setitem__(value, "changed", "value")
    for value in (plan.preflight["items"], result.evidence["items"]):
        assert isinstance(value, tuple)
        with pytest.raises(TypeError):
            list.__setitem__(value, 0, "changed")
