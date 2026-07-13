import json
from collections.abc import Callable
from pathlib import Path

import pytest

from cpanel_admin.catalog import Catalog, CatalogOperation, normalize_document
from cpanel_admin.policy import (
    SELECTED_MODULES,
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
MINIMAL_PADDING_COUNT = 389
PROTECTED_MVP_INPUTS = {
    ("Fileman/save_file_content", "content"): (
        "content",
        (InputSource.STDIN,),
        "content",
    ),
    ("Mysql/create_user", "password"): (
        "password",
        (InputSource.STDIN,),
        "secret",
    ),
    ("SSL/install_ssl", "private_key"): (
        "key",
        (InputSource.PROTECTED_FILE,),
        "private_key",
    ),
}
MINIMAL_PROTECTED_IDENTITIES = tuple(identity for identity, _name in PROTECTED_MVP_INPUTS)
PROTECTED_ALTERNATE_UAPI_NAMES = {
    "Fileman/save_file_content": "file",
    "Mysql/create_user": "name",
    "SSL/install_ssl": "cert",
}


def pinned_catalog() -> Catalog:
    return normalize_document(
        json.loads(PINNED_SPEC.read_text()),
        EXPECTED_SHA256,
        excluded_noncanonical_paths=frozenset({"/get_php_recommendations", "/get_recommendations"}),
    )


def minimal_catalog(
    *, deprecated: bool = False, request_media_types: list[str] | None = None
) -> Catalog:
    operation = {
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
        "request_media_types": request_media_types or [],
    }
    operations = {"Email/add_pop": operation}
    protected_operations = {
        "Fileman/save_file_content": (
            "Fileman",
            "save_file_content",
            {"content": False, "dir": False, "file": True},
        ),
        "Mysql/create_user": (
            "Mysql",
            "create_user",
            {"name": True, "password": True},
        ),
        "SSL/install_ssl": (
            "SSL",
            "install_ssl",
            {"cabundle": False, "cert": True, "domain": True, "key": False},
        ),
    }
    for identity, (module, function, raw_parameters) in protected_operations.items():
        operations[identity] = {
            "identity": identity,
            "module": module,
            "function": function,
            "method": "GET",
            "summary": "Test-only protected operation",
            "deprecated": False,
            "parameters": {
                name: {
                    "name": name,
                    "location": "query",
                    "required": required,
                    "schema_type": "string",
                    "enum": [],
                    "default": None,
                }
                for name, required in raw_parameters.items()
            },
            "request_media_types": [],
        }
    for index in range(MINIMAL_PADDING_COUNT):
        identity = f"Features/test_operation_{index:03d}"
        operations[identity] = {
            "identity": identity,
            "module": "Features",
            "function": f"test_operation_{index:03d}",
            "method": "GET",
            "summary": "Test-only catalog padding",
            "deprecated": False,
            "parameters": {},
            "request_media_types": [],
        }
    value = {
        "schema_version": 1,
        "source_version": "test",
        "source_sha256": "test",
        "excluded_paths": [],
        "operations": operations,
    }
    return Catalog.from_dict(value)


def excluded_record(identity: str) -> dict[str, object]:
    return {
        "name": identity,
        "identity": identity,
        "command": [],
        "capability": "diagnostics",
        "status": "excluded",
        "reason": "test-only explicit exclusion",
        "risk": None,
        "elevated_impact": False,
        "parameters": {},
        "impact": "",
        "recovery": "",
        "preflight": None,
        "verification": None,
        "feature": None,
        "audit_fields": [],
    }


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
    source_policy = json.loads(POLICY_PATH.read_text())
    protected = [
        {**source_policy["operations"][identity], "identity": identity}
        for identity in MINIMAL_PROTECTED_IDENTITIES
    ]
    padding = [
        excluded_record(f"Features/test_operation_{index:03d}")
        for index in range(MINIMAL_PADDING_COUNT)
    ]
    return {
        "schema_version": 1,
        "selected_modules": list(SELECTED_MODULES),
        "operations": [operation, *protected, *padding],
    }


def excluded_policy(**operation_overrides: object) -> dict[str, object]:
    policy = minimal_policy(
        name="Email/add_pop",
        status="excluded",
        risk=None,
        command=[],
        parameters={},
        elevated_impact=False,
        impact="",
        recovery="",
        preflight=None,
        verification=None,
        feature=None,
        audit_fields=[],
    )
    policy["operations"][0].update(operation_overrides)
    return policy


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


@pytest.mark.parametrize("candidate_count", [392, 394])
def test_candidate_cardinality_rejects_coordinated_catalog_and_policy_drift(
    candidate_count: int,
) -> None:
    catalog = minimal_catalog()
    policy = minimal_policy()
    if candidate_count == 392:
        identity = "Features/test_operation_388"
        del catalog.operations[identity]
        policy["operations"] = [
            operation for operation in policy["operations"] if operation["identity"] != identity
        ]
    else:
        identity = "Features/test_operation_extra"
        catalog.operations[identity] = CatalogOperation(
            identity=identity,
            module="Features",
            function="test_operation_extra",
            method="GET",
            summary="Coordinated extra operation",
            deprecated=False,
            parameters={},
        )
        policy["operations"].append(excluded_record(identity))
    assert len(policy_candidate_identities(catalog)) == candidate_count
    assert len(policy["operations"]) == candidate_count
    with pytest.raises(PolicyError, match="exactly 393 candidate operations"):
        PolicyRegistry.from_dict(catalog, policy)


def test_foundation_operations_keep_stable_names_commands_and_lookup() -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    expected = {
        "DomainInfo/list_domains": ("domains.list", ("domains", "list")),
        "DomainInfo/single_domain_data": ("domains.inspect", ("domains", "inspect")),
        "WebVhosts/list_ssl_capable_domains": (
            "domains.ssl-capable",
            ("domains", "ssl-capable"),
        ),
        "SubDomain/addsubdomain": (
            "domains.add-subdomain",
            ("domains", "add-subdomain"),
        ),
        "Fileman/list_files": ("files.list", ("files", "list")),
        "Fileman/get_file_information": ("files.inspect", ("files", "inspect")),
        "Fileman/get_file_content": ("files.read", ("files", "read")),
        "Fileman/save_file_content": ("files.write", ("files", "write")),
        "Fileman/upload_files": ("files.upload", ("files", "upload")),
        "Fileman/empty_trash": ("files.empty-trash", ("files", "empty-trash")),
        "SSL/list_certs": ("ssl.list", ("ssl", "list")),
        "SSL/installed_hosts": ("ssl.hosts", ("ssl", "hosts")),
        "SSL/install_ssl": ("ssl.install", ("ssl", "install")),
        "SSL/delete_ssl": ("ssl.remove", ("ssl", "remove")),
        "Mysql/list_databases": ("databases.list", ("databases", "list")),
        "Mysql/list_users": ("databases.users", ("databases", "users")),
        "Mysql/create_database": ("databases.create", ("databases", "create")),
        "Mysql/create_user": (
            "databases.create-user",
            ("databases", "create-user"),
        ),
        "Mysql/set_privileges_on_database": (
            "databases.grant",
            ("databases", "grant"),
        ),
        "Mysql/delete_database": ("databases.remove", ("databases", "remove")),
        "Mysql/delete_user": (
            "databases.remove-user",
            ("databases", "remove-user"),
        ),
    }
    assert {
        operation.identity: (operation.name, operation.command) for operation in registry.included()
    } == expected
    for identity, (name, command) in expected.items():
        assert registry.get(name).identity == identity
        assert registry.by_command(command).identity == identity
    assert registry.exclusion("Email/add_pop").status is SupportStatus.EXCLUDED
    assert tuple(operation.identity for operation in registry.included()) == tuple(
        sorted(operation.identity for operation in registry.included())
    )


def test_unknown_or_unclassified_operation_fails_closed() -> None:
    with pytest.raises(PolicyError, match="risk"):
        PolicyRegistry.from_dict(minimal_catalog(), minimal_policy(risk=None))
    with pytest.raises(PolicyError, match="unknown support status"):
        PolicyRegistry.from_dict(minimal_catalog(), minimal_policy(status="pending"))


@pytest.mark.parametrize(
    "selected_modules",
    [
        [],
        [*SELECTED_MODULES[:-1]],
        [*SELECTED_MODULES, "UnknownModule"],
        [*SELECTED_MODULES, "Email"],
    ],
)
def test_selected_modules_must_equal_approved_boundary(
    selected_modules: list[str],
) -> None:
    policy = minimal_policy()
    policy["selected_modules"] = selected_modules
    with pytest.raises(PolicyError, match="exact approved 48-module boundary"):
        PolicyRegistry.from_dict(minimal_catalog(), policy)


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


def test_multipart_catalog_does_not_allow_arbitrary_undeclared_parameters() -> None:
    policy = minimal_policy()
    policy["operations"][0]["parameters"]["arbitrary"] = {
        "name": "arbitrary",
        "uapi_name": "arbitrary",
        "sources": ["argument"],
        "validator": "string",
        "required": False,
        "secret": False,
        "sensitive_output": False,
    }
    with pytest.raises(PolicyError, match="parameters do not match catalog"):
        PolicyRegistry.from_dict(
            minimal_catalog(request_media_types=["multipart/form-data"]), policy
        )


def test_duplicate_local_parameters_cannot_share_uapi_name() -> None:
    policy = minimal_policy()
    policy["operations"][0]["parameters"]["email_alias"] = {
        "name": "email_alias",
        "uapi_name": "email",
        "sources": ["argument"],
        "validator": "email",
        "required": True,
        "secret": False,
        "sensitive_output": False,
    }
    with pytest.raises(PolicyError, match="duplicate UAPI parameter mapping"):
        PolicyRegistry.from_dict(minimal_catalog(), policy)


@pytest.mark.parametrize(
    ("identity", "name", "expected"),
    [(identity, name, expected) for (identity, name), expected in PROTECTED_MVP_INPUTS.items()],
)
def test_protected_mvp_inputs_match_authoritative_contract(
    identity: str,
    name: str,
    expected: tuple[str, tuple[InputSource, ...], str],
) -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    operation = next(item for item in registry.included() if item.identity == identity)
    protected = operation.parameters[name]
    assert (protected.uapi_name, protected.sources, protected.validator) == expected
    assert protected.required is True
    assert protected.secret is True
    assert protected.sensitive_output is True


def test_authoritative_contract_covers_every_current_secret_bearing_mvp_input() -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    actual = {
        (operation.identity, name)
        for operation in registry.included()
        for name, parameter in operation.parameters.items()
        if parameter.secret
    }
    assert actual == set(PROTECTED_MVP_INPUTS)


@pytest.mark.parametrize(("identity", "name"), PROTECTED_MVP_INPUTS)
@pytest.mark.parametrize(
    "mutation",
    ["secret", "sensitive_output", "sources", "validator", "required", "uapi_name"],
)
def test_protected_mvp_inputs_cannot_be_declassified(
    identity: str, name: str, mutation: str
) -> None:
    policy = json.loads(POLICY_PATH.read_text())
    parameter = policy["operations"][identity]["parameters"][name]
    if mutation in {"secret", "sensitive_output", "required"}:
        parameter[mutation] = False
    elif mutation == "sources":
        parameter[mutation] = ["argument"]
    elif mutation == "validator":
        parameter[mutation] = "string"
    else:
        parameter[mutation] = PROTECTED_ALTERNATE_UAPI_NAMES[identity]
    with pytest.raises(PolicyError, match=r"protected input|protected source"):
        PolicyRegistry.from_dict(pinned_catalog(), policy)


def test_mysql_password_secret_flag_cannot_be_declassified() -> None:
    policy = json.loads(POLICY_PATH.read_text())
    password = policy["operations"]["Mysql/create_user"]["parameters"]["password"]
    password["secret"] = False
    with pytest.raises(PolicyError, match="protected input"):
        PolicyRegistry.from_dict(pinned_catalog(), policy)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda parameters: parameters.__setitem__(
                "extra",
                {
                    "name": "extra",
                    "uapi_name": "extra",
                    "sources": ["argument"],
                    "validator": "string",
                    "required": False,
                    "secret": False,
                    "sensitive_output": False,
                },
            ),
            "exact directory and source parameters",
        ),
        (
            lambda parameters: parameters["source"].__setitem__("sources", ["argument"]),
            "source contract",
        ),
        (
            lambda parameters: parameters["source"].__setitem__("validator", "path"),
            "source contract",
        ),
        (
            lambda parameters: parameters["directory"].__setitem__("required", False),
            "dir contract",
        ),
        (
            lambda parameters: parameters["directory"].__setitem__("sources", ["local_file"]),
            "dir contract",
        ),
        (
            lambda parameters: parameters["directory"].__setitem__("validator", "string"),
            "dir contract",
        ),
        (
            lambda parameters: parameters["source"].__setitem__("required", False),
            "source contract",
        ),
        (
            lambda parameters: parameters["source"].__setitem__("secret", True),
            "protected source",
        ),
        (
            lambda parameters: parameters["source"].__setitem__("sensitive_output", True),
            "source contract",
        ),
    ],
)
def test_upload_parameter_omission_requires_exact_reviewed_contract(
    mutation: Callable[[dict[str, dict[str, object]]], object], message: str
) -> None:
    policy = json.loads(POLICY_PATH.read_text())
    parameters = policy["operations"]["Fileman/upload_files"]["parameters"]
    mutation(parameters)
    with pytest.raises(PolicyError, match=message):
        PolicyRegistry.from_dict(pinned_catalog(), policy)


def test_upload_parameter_omission_accepts_exact_reviewed_contract() -> None:
    operation = PolicyRegistry.load(pinned_catalog(), POLICY_PATH).get("files.upload")
    assert tuple(operation.parameters) == ("directory", "source")
    assert operation.parameters["directory"].sources == (InputSource.ARGUMENT,)
    assert operation.parameters["source"].sources == (InputSource.LOCAL_FILE,)
    assert operation.parameters["source"].validator == "local_file"


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

    excluded = PolicyRegistry.from_dict(minimal_catalog(), excluded_policy())
    with pytest.raises(PolicyError, match="operation is excluded"):
        excluded.get("Email/add_pop")
    with pytest.raises(PolicyError, match="unknown policy operation identity"):
        excluded.exclusion("Missing/function")


def test_policy_load_normalizes_invalid_json_error(tmp_path: Path) -> None:
    path = tmp_path / "operations.json"
    path.write_text("not-json")
    with pytest.raises(PolicyError, match="unable to load policy"):
        PolicyRegistry.load(minimal_catalog(), path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("risk", "read"),
        ("risk", 0),
        ("command", ["email", "create"]),
        ("command", ""),
        ("parameters", {"email": {}}),
        ("parameters", []),
        ("elevated_impact", True),
        ("elevated_impact", 0),
        ("impact", "changes state"),
        ("impact", None),
        ("recovery", "restore state"),
        ("recovery", []),
        ("preflight", "Email/list_pops"),
        ("preflight", False),
        ("verification", "Email/list_pops"),
        ("verification", 0),
        ("feature", "mail"),
        ("feature", False),
        ("audit_fields", ["email"]),
        ("audit_fields", {}),
    ],
)
def test_excluded_policy_requires_exact_non_executable_shape(field: str, value: object) -> None:
    with pytest.raises(PolicyError, match="excluded policy operation"):
        PolicyRegistry.from_dict(minimal_catalog(), excluded_policy(**{field: value}))


@pytest.mark.parametrize(
    "field",
    [
        "command",
        "risk",
        "elevated_impact",
        "parameters",
        "impact",
        "recovery",
        "preflight",
        "verification",
        "feature",
        "audit_fields",
    ],
)
def test_excluded_policy_requires_complete_non_executable_shape(field: str) -> None:
    policy = excluded_policy()
    del policy["operations"][0][field]
    with pytest.raises(PolicyError, match="excluded policy operation"):
        PolicyRegistry.from_dict(minimal_catalog(), policy)
