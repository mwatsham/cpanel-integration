import copy
import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from importlib import resources
from pathlib import Path

import pytest

from cpanel_admin.catalog import Catalog, CatalogError, CatalogExcludedPath, normalize_document
from scripts.generate_catalog import generate

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "openapi-minimal.json"
PINNED_SOURCE = ROOT / "specifications" / "cpanel.openapi.json"
PINNED_LOCK = ROOT / "specifications" / "cpanel.openapi.lock.json"
POLICY = ROOT / "policy" / "operations.json"
GENERATED_CATALOG = ROOT / "src" / "cpanel_admin" / "data" / "operation_catalog.json"


def test_pinned_openapi_matches_lock() -> None:
    source = ROOT / "specifications" / "cpanel.openapi.json"
    lock = json.loads((ROOT / "specifications" / "cpanel.openapi.lock.json").read_text())
    assert hashlib.sha256(source.read_bytes()).hexdigest() == lock["sha256"]
    document = json.loads(source.read_text())
    assert document["openapi"] == "3.0.2"
    assert document["info"]["version"] == "11.136.0.25"
    assert len(document["paths"]) == 605


def test_normalize_document_uses_module_function_identity() -> None:
    document = json.loads(FIXTURE.read_text())
    catalog = normalize_document(document, source_sha256="abc")
    operation = catalog.operations["Email/add_pop"]
    assert operation.module == "Email"
    assert operation.function == "add_pop"
    assert operation.method == "GET"
    assert operation.parameters["email"].required is True
    assert operation.parameters["quota"].schema_type == "integer"
    assert operation.parameters["flags"].schema_type == "array"
    assert operation.parameters["send_welcome"].enum == (0, 1)
    assert catalog.operations["Backup/restore_databases"].request_media_types == (
        "multipart/form-data",
    )


def test_catalog_json_is_deterministic() -> None:
    catalog = normalize_document(json.loads(FIXTURE.read_text()), source_sha256="abc")
    assert catalog.to_json() == catalog.to_json()
    assert catalog.to_json().endswith("\n")


def test_catalog_round_trips_through_dict_and_explicit_path(tmp_path: Path) -> None:
    catalog = normalize_document(json.loads(FIXTURE.read_text()), source_sha256="abc")
    serialized = catalog.to_json()
    assert Catalog.from_dict(json.loads(serialized)).to_json() == serialized
    path = tmp_path / "catalog.json"
    path.write_text(serialized)
    assert Catalog.load(path).get("Email/add_pop").function == "add_pop"
    with pytest.raises(CatalogError, match="unknown catalog operation"):
        catalog.get("Missing/function")


def test_duplicate_canonical_identity_is_rejected() -> None:
    document = json.loads(FIXTURE.read_text())
    document["paths"]["/Email/add_pop/"] = copy.deepcopy(document["paths"]["/Email/add_pop"])
    with pytest.raises(CatalogError, match="duplicate canonical operation"):
        normalize_document(document, source_sha256="abc")


@pytest.mark.parametrize("openapi", [None, "3.1.0"])
def test_normalize_document_requires_pinned_openapi_version(openapi: str | None) -> None:
    document = json.loads(FIXTURE.read_text())
    if openapi is None:
        del document["openapi"]
    else:
        document["openapi"] = openapi
    with pytest.raises(CatalogError, match=r"OpenAPI version must be 3\.0\.2"):
        normalize_document(document, source_sha256="abc")


@pytest.mark.parametrize(
    "invalid_path",
    [
        "Email/add_pop",
        "//Email/add_pop",
        "/Email/add_pop//",
        "/Email//add_pop",
        "/Email/add_pop/extra",
    ],
)
def test_invalid_path_syntax_fails_closed(invalid_path: str) -> None:
    document = json.loads(FIXTURE.read_text())
    document["paths"][invalid_path] = document["paths"].pop("/Email/add_pop")
    with pytest.raises(CatalogError, match="missing Module/function path segments"):
        normalize_document(document, source_sha256="abc")


def test_generator_rejects_source_and_lock_digest_drift(tmp_path: Path) -> None:
    source = tmp_path / "cpanel.openapi.json"
    lock_path = tmp_path / "cpanel.openapi.lock.json"
    document = json.loads((ROOT / "specifications/cpanel.openapi.json").read_text())
    document["info"]["title"] = "Modified title"
    source.write_text(json.dumps(document))
    lock = json.loads((ROOT / "specifications/cpanel.openapi.lock.json").read_text())
    lock["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    lock_path.write_text(json.dumps(lock))
    with pytest.raises(CatalogError, match="approved SHA-256"):
        generate(source, POLICY, lock_path=lock_path)


@pytest.mark.parametrize(
    ("field", "version", "message"),
    [("openapi", "3.1.0", "OpenAPI version"), ("uapi", "11.999.0", "UAPI version")],
)
def test_generator_rejects_version_drift(
    tmp_path: Path, field: str, version: str, message: str
) -> None:
    source = tmp_path / "cpanel.openapi.json"
    lock_path = ROOT / "specifications" / "cpanel.openapi.lock.json"
    document = json.loads((ROOT / "specifications/cpanel.openapi.json").read_text())
    if field == "openapi":
        document["openapi"] = version
    else:
        document["info"]["version"] = version
    source.write_text(json.dumps(document))
    with pytest.raises(CatalogError, match=message):
        generate(source, POLICY, lock_path=lock_path)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda document: document.__setitem__("info", []), "OpenAPI info"),
        (
            lambda document: document["paths"].__setitem__(
                "/missing-segment", document["paths"].pop("/Email/add_pop")
            ),
            "missing Module/function path segments",
        ),
        (
            lambda document: document["paths"]["/Email/add_pop"]["get"]["parameters"][
                0
            ].__setitem__("in", "header"),
            "unsupported parameter location",
        ),
        (
            lambda document: document["paths"]["/Email/add_pop"]["get"]["parameters"][0][
                "schema"
            ].__setitem__("type", "null"),
            "unsupported schema type",
        ),
    ],
)
def test_malformed_openapi_is_rejected(
    mutate: Callable[[dict[str, object]], object], message: str
) -> None:
    document = json.loads(FIXTURE.read_text())
    mutate(document)
    with pytest.raises(CatalogError, match=message):
        normalize_document(document, source_sha256="abc")


def test_only_lock_approved_noncanonical_paths_are_excluded() -> None:
    document = json.loads(FIXTURE.read_text())
    document["paths"]["/get_recommendations"] = {"get": {"operationId": "get_recommendations"}}
    catalog = normalize_document(
        document,
        source_sha256="abc",
        excluded_noncanonical_paths=frozenset({"/get_recommendations"}),
    )
    assert catalog.excluded_paths == (
        CatalogExcludedPath(
            path="/get_recommendations",
            reason="path has no canonical Module/function identity",
        ),
    )


def test_unapproved_noncanonical_path_fails_closed() -> None:
    document = json.loads(FIXTURE.read_text())
    document["paths"]["/new_unknown_path"] = {"get": {"operationId": "new_unknown_path"}}
    with pytest.raises(CatalogError, match="missing Module/function path segments"):
        normalize_document(document, source_sha256="abc")


def test_pinned_document_records_its_two_lock_approved_exclusions() -> None:
    document = json.loads((ROOT / "specifications" / "cpanel.openapi.json").read_text())
    lock = json.loads((ROOT / "specifications" / "cpanel.openapi.lock.json").read_text())
    catalog = normalize_document(
        document,
        source_sha256="abc",
        excluded_noncanonical_paths=frozenset(lock["excluded_noncanonical_paths"]),
    )
    assert len(catalog.operations) == 603
    assert tuple(excluded.path for excluded in catalog.excluded_paths) == (
        "/get_php_recommendations",
        "/get_recommendations",
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.pop("schema_version"), "missing field"),
        (lambda value: value.__setitem__("schema_version", True), "schema_version"),
        (lambda value: value.__setitem__("source_version", ""), "source_version"),
        (lambda value: value.__setitem__("source_sha256", ""), "source_sha256"),
        (lambda value: value.__setitem__("excluded_paths", {}), "excluded_paths"),
        (
            lambda value: value.__setitem__(
                "excluded_paths",
                [
                    {"path": "/excluded", "reason": "reason"},
                    {"path": "/excluded", "reason": "reason"},
                ],
            ),
            "duplicate excluded paths",
        ),
        (
            lambda value: value["operations"]["Email/add_pop"].pop("summary"),
            "missing field",
        ),
        (
            lambda value: value["operations"]["Email/add_pop"].__setitem__(
                "identity", "Other/function"
            ),
            "identity mismatch",
        ),
    ],
)
def test_catalog_from_dict_rejects_malformed_metadata(
    mutate: Callable[[dict[str, object]], object], message: str
) -> None:
    catalog = normalize_document(json.loads(FIXTURE.read_text()), source_sha256="abc")
    value = json.loads(catalog.to_json())
    mutate(value)
    with pytest.raises(CatalogError, match=message):
        Catalog.from_dict(value)


def test_catalog_load_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "catalog.json"
    path.write_text("not-json")
    with pytest.raises(CatalogError, match="unable to load catalog"):
        Catalog.load(path)


def test_committed_catalog_matches_generator() -> None:
    generated = generate(PINNED_SOURCE, POLICY, lock_path=PINNED_LOCK)
    assert generated == GENERATED_CATALOG.read_text(encoding="utf-8")


def test_catalog_is_available_from_installed_package() -> None:
    packaged = resources.files("cpanel_admin.data").joinpath("operation_catalog.json")
    assert packaged.is_file()
    catalog = Catalog.load()
    assert catalog.source_sha256 == (
        "3d9ec80cd8d774312c4bb6b0dfdbc17e6e6ffc92a8f0c2cd88f01e32864fa2c6"
    )
    assert catalog.get("DomainInfo/list_domains").function == "list_domains"


def test_generated_catalog_preserves_reviewed_policy_safety_fields() -> None:
    generated = json.loads(generate(PINNED_SOURCE, POLICY, lock_path=PINNED_LOCK))
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    for identity in ("DomainInfo/list_domains", "Email/add_pop", "Mysql/create_user"):
        assert generated["operations"][identity]["policy"] == {
            "identity": identity,
            **policy["operations"][identity],
        }
    assert generated["generator_schema"] == 1
    assert "must not be edited manually" in generated["generated_notice"]


def test_generator_emits_deterministic_safe_support_matrix(tmp_path: Path) -> None:
    outputs = []
    for suffix in ("one", "two"):
        output = tmp_path / f"catalog-{suffix}.json"
        support_output = tmp_path / f"support-{suffix}.md"
        completed = subprocess.run(
            [
                sys.executable,
                "scripts/generate_catalog.py",
                "--output",
                str(output),
                "--support-output",
                str(support_output),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        outputs.append((output.read_bytes(), support_output.read_text(encoding="utf-8")))
    assert outputs[0] == outputs[1]
    support = outputs[0][1]
    assert "| `DomainInfo/list_domains` | included | domains | read |" in support
    assert (
        "| `Email/add_pop` | excluded | email | - | "
        "not enabled until the email capability review |" in support
    )
    assert "protected_file" not in support
    assert "sensitive_output" not in support


def test_check_mode_is_write_free_when_outputs_are_stale(tmp_path: Path) -> None:
    output = tmp_path / "operation_catalog.json"
    support_output = tmp_path / "operation-support.md"
    generate_command = [
        sys.executable,
        "scripts/generate_catalog.py",
        "--source",
        str(PINNED_SOURCE),
        "--lock",
        str(PINNED_LOCK),
        "--policy",
        str(POLICY),
        "--output",
        str(output),
        "--support-output",
        str(support_output),
    ]
    assert subprocess.run(generate_command, cwd=ROOT, check=False).returncode == 0
    output.write_text("stale\n", encoding="utf-8")
    before = {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (output, support_output)
    }

    completed = subprocess.run(
        [*generate_command, "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "stale generated output" in completed.stderr
    assert before == {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (output, support_output)
    }


def test_check_mode_is_write_free_when_policy_is_invalid(tmp_path: Path) -> None:
    policy = tmp_path / "operations.json"
    policy.write_text("{}\n", encoding="utf-8")
    output = tmp_path / "missing" / "operation_catalog.json"
    support_output = tmp_path / "missing" / "operation-support.md"

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/generate_catalog.py",
            "--source",
            str(PINNED_SOURCE),
            "--lock",
            str(PINNED_LOCK),
            "--policy",
            str(policy),
            "--output",
            str(output),
            "--support-output",
            str(support_output),
            "--check",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "policy schema_version must be 1" in completed.stderr
    assert not output.parent.exists()
