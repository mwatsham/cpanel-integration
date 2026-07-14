import hashlib
import json
import operator
from collections.abc import Callable
from pathlib import Path
from typing import get_type_hints

import pytest

import cpanel_admin.policy as policy_module
from cpanel_admin.catalog import (
    Catalog,
    CatalogOperation,
    CatalogParameter,
    normalize_document,
)
from cpanel_admin.policy import (
    SELECTED_MODULES,
    STABLE_MVP_OPERATION_CONTRACTS,
    InputSource,
    PolicyError,
    PolicyOperation,
    PolicyParameter,
    PolicyRegistry,
    Risk,
    SupportStatus,
)
from scripts.generate_catalog import EXPECTED_SHA256, policy_candidate_identities

ROOT = Path(__file__).parents[1]
PINNED_SPEC = ROOT / "specifications" / "cpanel.openapi.json"
POLICY_PATH = ROOT / "policy" / "operations.json"
EXPECTED_CANDIDATE_IDENTITY_SHA256 = (
    "834c8bd9c048d93e9089fd22a7c569d4923cc8a5c9ecbc4172123ec2276a6ecb"
)
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
    ("Email/add_pop", "password"): (
        "password",
        (InputSource.STDIN,),
        "secret",
    ),
    ("Email/passwd_pop", "password"): (
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
PROTECTED_ALTERNATE_UAPI_NAMES = {
    "Fileman/save_file_content": "file",
    "Mysql/create_user": "name",
    "Email/add_pop": "email",
    "Email/passwd_pop": "email",
    "SSL/install_ssl": "cert",
}
EMAIL_ADMIN_OPERATION_CONTRACTS = {
    "Email/list_pops": ("email.accounts", ("email", "accounts")),
    "Email/add_pop": ("email.create-account", ("email", "create-account")),
    "Email/delete_pop": ("email.delete-account", ("email", "delete-account")),
    "Email/passwd_pop": ("email.set-password", ("email", "set-password")),
    "Email/edit_pop_quota": ("email.set-quota", ("email", "set-quota")),
    "Email/list_forwarders": ("email.forwarders", ("email", "forwarders")),
    "Email/add_forwarder": ("email.add-forwarder", ("email", "add-forwarder")),
    "Email/delete_forwarder": ("email.delete-forwarder", ("email", "delete-forwarder")),
    "Email/list_auto_responders": ("email.autoresponders", ("email", "autoresponders")),
    "Email/add_auto_responder": ("email.add-autoresponder", ("email", "add-autoresponder")),
    "Email/delete_auto_responder": (
        "email.delete-autoresponder",
        ("email", "delete-autoresponder"),
    ),
    "Email/list_filters": ("email.filters", ("email", "filters")),
    "Email/enable_filter": ("email.enable-filter", ("email", "enable-filter")),
    "Email/disable_filter": ("email.disable-filter", ("email", "disable-filter")),
    "Email/delete_filter": ("email.delete-filter", ("email", "delete-filter")),
    "Email/get_spam_settings": ("email.spam-settings", ("email", "spam-settings")),
    "Email/enable_spam_assassin": ("email.enable-spam", ("email", "enable-spam")),
    "Email/disable_spam_assassin": ("email.disable-spam", ("email", "disable-spam")),
    "Email/enable_spam_box": ("email.enable-spam-box", ("email", "enable-spam-box")),
    "Email/disable_spam_box": ("email.disable-spam-box", ("email", "disable-spam-box")),
    "Email/list_mxs": ("email.mx-list", ("email", "mx-list")),
    "Email/add_mx": ("email.add-mx", ("email", "add-mx")),
    "Email/delete_mx": ("email.delete-mx", ("email", "delete-mx")),
    "Email/change_mx": ("email.change-mx", ("email", "change-mx")),
    "Email/set_manual_mx_redirects": ("email.set-routing", ("email", "set-routing")),
    "Email/unset_manual_mx_redirects": ("email.unset-routing", ("email", "unset-routing")),
    "EmailAuth/validate_current_spfs": ("email.validate-spf", ("email", "validate-spf")),
    "EmailAuth/validate_current_dkims": ("email.validate-dkim", ("email", "validate-dkim")),
    "EmailAuth/install_spf_records": ("email.install-spf", ("email", "install-spf")),
    "EmailAuth/enable_dkim": ("email.enable-dkim", ("email", "enable-dkim")),
    "EmailAuth/disable_dkim": ("email.disable-dkim", ("email", "disable-dkim")),
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
    catalog = pinned_catalog()
    catalog.operations["Email/add_pop"] = CatalogOperation(
        identity="Email/add_pop",
        module="Email",
        function="add_pop",
        method="GET",
        summary="Add an email account",
        deprecated=deprecated,
        parameters={
            "email": CatalogParameter(
                name="email",
                location="query",
                required=True,
                schema_type="string",
            ),
            "password": CatalogParameter(
                name="password",
                location="query",
                required=True,
                schema_type="string",
            ),
        },
        request_media_types=tuple(request_media_types or []),
    )
    return catalog


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
                "validator": "email_local",
                "required": True,
                "secret": False,
                "sensitive_output": False,
            },
            "password": {
                "name": "password",
                "uapi_name": "password",
                "sources": ["stdin"],
                "validator": "secret",
                "required": True,
                "secret": True,
                "sensitive_output": True,
            },
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
    remaining = [
        {**record, "identity": identity}
        for identity, record in source_policy["operations"].items()
        if identity != "Email/add_pop"
    ]
    return {
        "schema_version": 1,
        "selected_modules": list(SELECTED_MODULES),
        "operations": [operation, *remaining],
    }


def excluded_policy(**operation_overrides: object) -> dict[str, object]:
    policy = minimal_policy()
    for index, operation in enumerate(policy["operations"]):
        if operation["identity"] == "AccountEnhancements/list":
            operation.update(operation_overrides)
            policy["operations"].insert(0, policy["operations"].pop(index))
            break
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


def test_reviewed_candidate_identity_digest_matches_pinned_catalog() -> None:
    identities = policy_candidate_identities(pinned_catalog())
    actual = hashlib.sha256("\n".join(identities).encode()).hexdigest()
    assert actual == EXPECTED_CANDIDATE_IDENTITY_SHA256
    assert (
        getattr(policy_module, "EXPECTED_CANDIDATE_IDENTITY_SHA256", None)
        == EXPECTED_CANDIDATE_IDENTITY_SHA256
    )


@pytest.mark.parametrize("candidate_count", [392, 394])
def test_candidate_cardinality_rejects_coordinated_catalog_and_policy_drift(
    candidate_count: int,
) -> None:
    catalog = minimal_catalog()
    policy = minimal_policy()
    if candidate_count == 392:
        identity = "AccountEnhancements/has_enhancement"
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


def test_candidate_identity_digest_rejects_coordinated_replacement() -> None:
    catalog = minimal_catalog()
    policy = minimal_policy()
    removed = "AccountEnhancements/has_enhancement"
    replacement = "Features/coordinated_identity_substitution"
    del catalog.operations[removed]
    catalog.operations[replacement] = CatalogOperation(
        identity=replacement,
        module="Features",
        function="coordinated_identity_substitution",
        method="GET",
        summary="Coordinated identity substitution",
        deprecated=False,
        parameters={},
    )
    policy["operations"] = [
        operation for operation in policy["operations"] if operation["identity"] != removed
    ]
    policy["operations"].append(excluded_record(replacement))
    assert len(policy_candidate_identities(catalog)) == 393
    assert len(policy["operations"]) == 393
    with pytest.raises(PolicyError, match="reviewed candidate identity digest"):
        PolicyRegistry.from_dict(catalog, policy)


def test_foundation_operations_keep_stable_names_commands_and_lookup() -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    expected = {
        identity: (contract.name, contract.command)
        for identity, contract in STABLE_MVP_OPERATION_CONTRACTS.items()
    }
    assert len(STABLE_MVP_OPERATION_CONTRACTS) == 21
    assert all(
        contract.status is SupportStatus.INCLUDED
        for contract in STABLE_MVP_OPERATION_CONTRACTS.values()
    )
    included = {
        operation.identity: (operation.name, operation.command) for operation in registry.included()
    }
    assert included.items() >= expected.items()
    for identity, (name, command) in expected.items():
        assert registry.get(name).identity == identity
        assert registry.by_command(command).identity == identity
    assert tuple(operation.identity for operation in registry.included()) == tuple(
        sorted(operation.identity for operation in registry.included())
    )


def test_email_administration_operations_are_reviewed_and_stable() -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    included = {
        operation.identity: (operation.name, operation.command) for operation in registry.included()
    }
    assert included.items() >= EMAIL_ADMIN_OPERATION_CONTRACTS.items()
    assert registry.get("email.create-account").parameters["password"].secret is True
    assert registry.get("email.set-password").parameters["password"].secret is True
    assert registry.get("email.add-autoresponder").risk is Risk.MUTATE
    assert registry.get("email.delete-account").risk is Risk.DESTRUCTIVE


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("name", "domains.renamed-list"),
        ("command", ["domains", "renamed-list"]),
        ("status", "excluded"),
    ],
)
def test_stable_mvp_contract_rejects_name_command_or_status_mutation(
    mutation: str, value: object
) -> None:
    policy = json.loads(POLICY_PATH.read_text())
    identity = "DomainInfo/list_domains"
    if mutation == "status":
        policy["operations"][identity] = {
            **excluded_record(identity),
            "capability": "domains",
            "status": value,
        }
    else:
        policy["operations"][identity][mutation] = value
    with pytest.raises(PolicyError, match="stable MVP operation contract"):
        PolicyRegistry.from_dict(pinned_catalog(), policy)


def test_stable_mvp_contract_rejects_missing_mapping() -> None:
    policy = json.loads(POLICY_PATH.read_text())
    del policy["operations"]["DomainInfo/list_domains"]
    with pytest.raises(PolicyError, match="missing policy records"):
        PolicyRegistry.from_dict(pinned_catalog(), policy)


def test_stable_mvp_contract_rejects_extra_claim() -> None:
    policy = json.loads(POLICY_PATH.read_text())
    policy["operations"]["DomainInfo/single_domain_data"]["name"] = "domains.list"
    with pytest.raises(PolicyError, match="duplicate policy operation name"):
        PolicyRegistry.from_dict(pinned_catalog(), policy)


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
        ({"parameters": {}}, r"protected input|parameters do not match"),
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
    ("local_name", "uapi_name"),
    [
        ("module", "safe_name"),
        ("Module", "safe_name"),
        ("safe_name", "function"),
        ("safe_name", "FUNCTION"),
    ],
)
def test_reserved_dispatch_parameters_fail_even_when_catalog_declares_them(
    local_name: str, uapi_name: str
) -> None:
    catalog = minimal_catalog()
    catalog.operations["Email/add_pop"].parameters[uapi_name] = CatalogParameter(
        name=uapi_name,
        location="query",
        required=False,
        schema_type="string",
    )
    policy = minimal_policy()
    policy["operations"][0]["parameters"][local_name] = {
        "name": local_name,
        "uapi_name": uapi_name,
        "sources": ["argument"],
        "validator": "string",
        "required": False,
        "secret": False,
        "sensitive_output": False,
    }
    with pytest.raises(PolicyError, match="reserved dispatch parameter"):
        PolicyRegistry.from_dict(catalog, policy)


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


def policy_with_unreviewed_fourth_secret() -> dict[str, object]:
    policy = json.loads(POLICY_PATH.read_text())
    operation = policy["operations"]["Fileman/save_file_content"]
    filename = operation["parameters"]["filename"]
    filename["sources"] = ["protected_file"]
    filename["secret"] = True
    filename["sensitive_output"] = True
    operation["audit_fields"].remove("filename")
    return policy


def test_unreviewed_fourth_secret_input_fails_closed() -> None:
    with pytest.raises(PolicyError, match="authoritative secret input inventory"):
        PolicyRegistry.from_dict(pinned_catalog(), policy_with_unreviewed_fourth_secret())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda authority, first, second: operator.setitem(
            authority, ("Fileman/save_file_content", "fourth"), authority[first]
        ),
        lambda authority, first, second: operator.setitem(authority, first, authority[second]),
        lambda authority, first, second: operator.delitem(authority, first),
        lambda authority, first, second: authority.clear(),
        lambda authority, first, second: authority.update(
            {("Fileman/save_file_content", "fourth"): authority[first]}
        ),
    ],
    ids=["insert", "replace", "delete", "clear", "update"],
)
def test_protected_input_authority_is_immutable(
    mutation: Callable[[object, object, object], object],
) -> None:
    authority = policy_module._PROTECTED_INPUT_CONTRACTS
    original = dict(authority)
    first, second = tuple(original)[:2]
    try:
        with pytest.raises((TypeError, AttributeError)):
            mutation(authority, first, second)
    finally:
        if isinstance(authority, dict):
            authority.clear()
            authority.update(original)
    assert dict(authority) == original
    with pytest.raises(PolicyError, match="authoritative secret input inventory"):
        PolicyRegistry.from_dict(pinned_catalog(), policy_with_unreviewed_fourth_secret())


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


def _files_write_from_surface(registry: PolicyRegistry, surface: str):
    if surface == "get":
        return registry.get("files.write")
    if surface == "by_command":
        return registry.by_command(("files", "write"))
    operations = registry.all() if surface == "all" else registry.included()
    return next(operation for operation in operations if operation.name == "files.write")


@pytest.mark.parametrize(
    ("index_name", "key"),
    [
        ("_by_name", "files.write"),
        ("_by_identity", "AccountEnhancements/list"),
        ("_by_command", ("files", "write")),
    ],
)
@pytest.mark.parametrize(
    "mutation",
    [
        lambda index, key, replacement: operator.setitem(index, key, replacement),
        lambda index, key, replacement: operator.delitem(index, key),
        lambda index, key, replacement: index.update({key: replacement}),
        lambda index, key, replacement: index.clear(),
    ],
    ids=["replace", "delete", "update", "clear"],
)
def test_registry_indexes_are_immutable_copies(
    index_name: str,
    key: object,
    mutation: Callable[[object, object, PolicyOperation], object],
) -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    index = getattr(registry, index_name)
    files_write = registry.get("files.write")
    excluded = registry.exclusion("AccountEnhancements/list")
    replacement = registry.get("domains.list")

    with pytest.raises((TypeError, AttributeError)):
        mutation(index, key, replacement)

    assert registry.get("files.write") is files_write
    assert registry.by_command(("files", "write")) is files_write
    assert registry.exclusion("AccountEnhancements/list") is excluded


@pytest.mark.parametrize("surface", ["get", "by_command", "all", "included"])
@pytest.mark.parametrize(
    "mutation",
    [
        lambda parameters: operator.delitem(parameters, "content"),
        lambda parameters: operator.setitem(parameters, "module", parameters["filename"]),
        lambda parameters: operator.setitem(parameters, "function", parameters["filename"]),
        lambda parameters: operator.setitem(parameters, "content", parameters["filename"]),
        lambda parameters: operator.setitem(parameters, "content_alias", parameters["content"]),
        lambda parameters: parameters.clear(),
        lambda parameters: parameters.pop("content"),
        lambda parameters: parameters.popitem(),
        lambda parameters: parameters.update(module=parameters["filename"]),
        lambda parameters: parameters.setdefault("module", parameters["filename"]),
        lambda parameters: operator.ior(parameters, {"module": parameters["filename"]}),
    ],
    ids=[
        "delete-protected",
        "insert-module",
        "insert-function",
        "replace-protected",
        "insert-duplicate-alias",
        "clear",
        "pop",
        "popitem",
        "update",
        "setdefault",
        "in-place-union",
    ],
)
def test_parameters_are_immutable_through_every_registry_surface(
    surface: str, mutation: Callable[[object], object]
) -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    operation = _files_write_from_surface(registry, surface)
    original_content = operation.parameters["content"]

    assert get_type_hints(PolicyOperation)["parameters"] == dict[str, PolicyParameter]
    assert isinstance(operation.parameters, dict)
    with pytest.raises(TypeError):
        mutation(operation.parameters)

    looked_up = registry.get("files.write")
    assert tuple(looked_up.parameters) == ("content", "directory", "filename")
    assert looked_up.parameters["content"] is original_content
    assert all(name not in looked_up.parameters for name in ("module", "function", "content_alias"))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda parameters, value: operator.setitem(parameters, "module", value),
        lambda parameters, value: operator.delitem(parameters, "module"),
        lambda parameters, value: parameters.clear(),
        lambda parameters, value: parameters.pop("module", None),
        lambda parameters, value: parameters.popitem(),
        lambda parameters, value: parameters.update(module=value),
        lambda parameters, value: parameters.setdefault("module", value),
        lambda parameters, value: operator.ior(parameters, {"module": value}),
    ],
    ids=["insert", "delete", "clear", "pop", "popitem", "update", "setdefault", "ior"],
)
def test_excluded_operation_parameters_keep_dict_shape_and_are_immutable(
    mutation: Callable[[dict[str, PolicyParameter], PolicyParameter], object],
) -> None:
    registry = PolicyRegistry.load(pinned_catalog(), POLICY_PATH)
    parameters = registry.exclusion("AccountEnhancements/list").parameters
    value = registry.get("files.write").parameters["filename"]

    assert isinstance(parameters, dict)
    with pytest.raises(TypeError):
        mutation(parameters, value)
    assert parameters == {}
    assert registry.exclusion("AccountEnhancements/list").parameters is parameters


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
        excluded.get("AccountEnhancements/list")
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
