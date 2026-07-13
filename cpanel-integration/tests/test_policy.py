import json
from pathlib import Path

import pytest

from cpanel_admin.catalog import Catalog, normalize_document
from cpanel_admin.policy import (
    InputSource,
    PolicyError,
    PolicyRegistry,
    Risk,
    SupportStatus,
)
from scripts.generate_catalog import EXPECTED_SHA256, policy_candidate_identities

ROOT = Path(__file__).parents[1]
PINNED_SPEC = ROOT / "specifications" / "cpanel.openapi.json"
POLICY_PATH = ROOT / "policy" / "operations.json"


def pinned_catalog() -> Catalog:
    return normalize_document(
        json.loads(PINNED_SPEC.read_text()),
        EXPECTED_SHA256,
        excluded_noncanonical_paths=frozenset({"/get_php_recommendations", "/get_recommendations"}),
    )


def minimal_catalog(*, deprecated: bool = False) -> Catalog:
    value = {
        "schema_version": 1,
        "source_version": "test",
        "source_sha256": "test",
        "excluded_paths": [],
        "operations": {
            "Email/add_pop": {
                "identity": "Email/add_pop",
                "module": "Email",
                "function": "add_pop",
                "method": "GET",
                "summary": "Add an email account",
                "deprecated": deprecated,
                "parameters": {
                    "email": {
                        "name": "email",
                        "location": "query",
                        "required": True,
                        "schema_type": "string",
                        "enum": [],
                        "default": None,
                    }
                },
                "request_media_types": [],
            }
        },
    }
    return Catalog.from_dict(value)


def minimal_policy(**operation_overrides: object) -> dict[str, object]:
    operation: dict[str, object] = {
        "name": "email.create",
        "identity": "Email/add_pop",
        "command": ["email", "create"],
        "capability": "email",
        "status": "included",
        "reason": "supported operation",
        "risk": "mutate",
        "elevated_impact": False,
        "parameters": {
            "email": {
                "name": "email",
                "uapi_name": "email",
                "sources": ["argument"],
                "validator": "email",
                "required": True,
                "secret": False,
                "sensitive_output": False,
            }
        },
        "impact": "Create an email account",
        "recovery": "Delete the email account",
        "preflight": None,
        "verification": None,
        "feature": None,
        "audit_fields": ["email"],
    }
    operation.update(operation_overrides)
    return {
        "schema_version": 1,
        "selected_modules": ["Email"],
        "operations": [operation],
    }


def test_selected_modules_have_explicit_policy() -> None:
    catalog = pinned_catalog()
    registry = PolicyRegistry.load(catalog, POLICY_PATH)
    report = registry.coverage()
    assert report.selected_modules == 48
    assert report.candidate_operations == 393
    assert report.missing == ()
    assert report.pending_review == ()
    assert policy_candidate_identities(catalog) == tuple(
        operation.identity for operation in registry.all()
    )


def test_foundation_operations_keep_stable_names_commands_and_lookup() -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    assert registry.get("domains.list").identity == "DomainInfo/list_domains"
    assert registry.by_command(("domains", "list")).name == "domains.list"
    assert registry.included_identities("databases") >= {
        "Mysql/create_database",
        "Mysql/delete_database",
    }
    assert registry.exclusion("Email/add_pop").status is SupportStatus.EXCLUDED
    assert tuple(operation.identity for operation in registry.included()) == tuple(
        sorted(operation.identity for operation in registry.included())
    )


def test_unknown_or_unclassified_operation_fails_closed() -> None:
    with pytest.raises(PolicyError, match="risk"):
        PolicyRegistry.from_dict(minimal_catalog(), minimal_policy(risk=None))
    with pytest.raises(PolicyError, match="unknown support status"):
        PolicyRegistry.from_dict(minimal_catalog(), minimal_policy(status="pending"))


def test_no_command_accepts_module_or_function_parameters() -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    for operation in registry.included():
        assert "module" not in operation.parameters
        assert "function" not in operation.parameters


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"identity": "Missing/function"}, "unknown catalog operation"),
        ({"reason": ""}, "reason"),
        ({"parameters": {}}, "parameters do not match"),
        ({"impact": ""}, "impact"),
        ({"recovery": ""}, "recovery"),
    ],
)
def test_included_policy_rejects_incomplete_or_unknown_metadata(
    override: dict[str, object], message: str
) -> None:
    with pytest.raises(PolicyError, match=message):
        PolicyRegistry.from_dict(minimal_catalog(), minimal_policy(**override))


def test_deprecated_inclusion_and_unprotected_secret_fail_closed() -> None:
    with pytest.raises(PolicyError, match="deprecated"):
        PolicyRegistry.from_dict(minimal_catalog(deprecated=True), minimal_policy())
    policy = minimal_policy()
    parameter = policy["operations"][0]["parameters"]["email"]
    parameter.update(secret=True, sources=["argument"])
    with pytest.raises(PolicyError, match="protected source"):
        PolicyRegistry.from_dict(minimal_catalog(), policy)


def test_policy_types_and_confirmation_rule_are_stable() -> None:
    registry = PolicyRegistry.from_dict(minimal_catalog(), minimal_policy())
    operation = registry.get("email.create")
    assert operation.risk is Risk.MUTATE
    assert operation.parameters["email"].sources == (InputSource.ARGUMENT,)
    assert operation.requires_confirmation is False
    destructive = minimal_policy(risk="destructive")
    assert (
        PolicyRegistry.from_dict(minimal_catalog(), destructive)
        .get("email.create")
        .requires_confirmation
    )


def test_duplicate_names_commands_and_missing_candidates_fail_closed() -> None:
    duplicate = minimal_policy()
    duplicate["operations"].append(dict(duplicate["operations"][0]))
    with pytest.raises(PolicyError, match="duplicate policy operation name"):
        PolicyRegistry.from_dict(minimal_catalog(), duplicate)
    with pytest.raises(PolicyError, match="missing policy records"):
        PolicyRegistry.from_dict(minimal_catalog(), {**minimal_policy(), "operations": []})


def test_excluded_and_unknown_lookups_never_resolve() -> None:
    included = PolicyRegistry.from_dict(minimal_catalog(), minimal_policy())
    with pytest.raises(PolicyError, match="unknown included policy operation"):
        included.get("missing")
    with pytest.raises(PolicyError, match="unknown included command path"):
        included.by_command(("email", "missing"))
    with pytest.raises(PolicyError, match="operation is included"):
        included.exclusion("Email/add_pop")

    excluded_policy = minimal_policy(
        status="excluded",
        risk=None,
        command=[],
        parameters={},
        elevated_impact=False,
    )
    excluded = PolicyRegistry.from_dict(minimal_catalog(), excluded_policy)
    with pytest.raises(PolicyError, match="operation is excluded"):
        excluded.get("email.create")
    with pytest.raises(PolicyError, match="unknown policy operation identity"):
        excluded.exclusion("Missing/function")


def test_policy_load_normalizes_invalid_json_error(tmp_path: Path) -> None:
    path = tmp_path / "operations.json"
    path.write_text("not-json")
    with pytest.raises(PolicyError, match="unable to load policy"):
        PolicyRegistry.load(minimal_catalog(), path)
