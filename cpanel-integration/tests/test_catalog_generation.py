import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from cpanel_admin.catalog import Catalog, CatalogError, CatalogExcludedPath, normalize_document

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "openapi-minimal.json"


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
