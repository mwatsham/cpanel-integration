"""Deterministic metadata normalized from the pinned cPanel OpenAPI document."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias, cast

from .errors import CPanelAdminError

if TYPE_CHECKING:
    from .policy import PolicyOperation

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

_HTTP_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "trace"})
_PARAMETER_LOCATIONS = frozenset({"query"})
_SCHEMA_TYPES = frozenset({"array", "boolean", "integer", "number", "object", "string"})
_NONCANONICAL_REASON = "path has no canonical Module/function identity"
GENERATOR_SCHEMA = 1
GENERATED_NOTICE = "Generated from pinned cPanel metadata; must not be edited manually."


class CatalogError(CPanelAdminError):
    """The catalog source or serialized catalog is invalid."""


@dataclass(frozen=True)
class CatalogParameter:
    name: str
    location: str
    required: bool
    schema_type: str
    enum: tuple[JsonScalar, ...] = ()
    default: JsonValue = None


@dataclass(frozen=True)
class CatalogOperation:
    identity: str
    module: str
    function: str
    method: str
    summary: str
    deprecated: bool
    parameters: dict[str, CatalogParameter]
    request_media_types: tuple[str, ...] = ()
    policy: PolicyOperation | None = None


@dataclass(frozen=True)
class CatalogExcludedPath:
    path: str
    reason: str


@dataclass(frozen=True)
class Catalog:
    schema_version: int
    source_version: str
    source_sha256: str
    operations: dict[str, CatalogOperation]
    excluded_paths: tuple[CatalogExcludedPath, ...]
    generator_schema: int | None = None
    generated_notice: str | None = None

    def get(self, identity: str) -> CatalogOperation:
        try:
            return self.operations[identity]
        except KeyError as exc:
            raise CatalogError(f"unknown catalog operation: {identity}") from exc

    def to_json(self) -> str:
        value: dict[str, object] = {
            "schema_version": self.schema_version,
            "source_version": self.source_version,
            "source_sha256": self.source_sha256,
            "operations": {
                identity: _operation_to_dict(self.operations[identity])
                for identity in sorted(self.operations)
            },
            "excluded_paths": [
                {"path": item.path, "reason": item.reason} for item in self.excluded_paths
            ],
        }
        if self.generator_schema is not None:
            value["generator_schema"] = self.generator_schema
        if self.generated_notice is not None:
            value["generated_notice"] = self.generated_notice
        return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Catalog:
        try:
            schema_version = value["schema_version"]
            source_version = value["source_version"]
            source_sha256 = value["source_sha256"]
            raw_operations = value["operations"]
            raw_excluded_paths = value["excluded_paths"]
        except KeyError as exc:
            raise CatalogError(f"catalog is missing field: {exc.args[0]}") from exc
        if not isinstance(schema_version, int) or isinstance(schema_version, bool):
            raise CatalogError("catalog schema_version must be an integer")
        if not isinstance(source_version, str) or not source_version:
            raise CatalogError("catalog source_version must be a non-empty string")
        if not isinstance(source_sha256, str) or not source_sha256:
            raise CatalogError("catalog source_sha256 must be a non-empty string")
        operations_value = _mapping(raw_operations, "catalog operations")
        operations: dict[str, CatalogOperation] = {}
        for identity in sorted(operations_value):
            if not isinstance(identity, str):
                raise CatalogError("catalog operation identities must be strings")
            operation = _operation_from_dict(identity, operations_value[identity])
            operations[identity] = operation
        excluded_paths = _excluded_paths_from_value(raw_excluded_paths)
        catalog = cls(schema_version, source_version, source_sha256, operations, excluded_paths)
        return _attach_generated_policy(catalog, value, operations_value)

    @classmethod
    def load(cls, path: Path | None = None) -> Catalog:
        try:
            if path is None:
                raw = (
                    resources.files("cpanel_admin")
                    .joinpath("data/operation_catalog.json")
                    .read_text(encoding="utf-8")
                )
            else:
                raw = path.read_text(encoding="utf-8")
            value = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            location = "packaged catalog" if path is None else str(path)
            raise CatalogError(f"unable to load catalog from {location}") from exc
        return cls.from_dict(_mapping(value, "catalog"))


def normalize_document(
    document: Mapping[str, object],
    source_sha256: str,
    *,
    excluded_noncanonical_paths: frozenset[str] = frozenset(),
) -> Catalog:
    """Normalize an OpenAPI document using path-derived ``Module/function`` identities."""

    if not isinstance(source_sha256, str) or not source_sha256:
        raise CatalogError("source SHA-256 must be a non-empty string")
    if document.get("openapi") != "3.0.2":
        raise CatalogError("OpenAPI version must be 3.0.2")
    info = _mapping(document.get("info"), "OpenAPI info")
    source_version = info.get("version")
    if not isinstance(source_version, str) or not source_version:
        raise CatalogError("OpenAPI info.version must be a non-empty string")
    paths = _mapping(document.get("paths"), "OpenAPI paths")
    operations: dict[str, CatalogOperation] = {}
    excluded_paths: list[CatalogExcludedPath] = []
    for raw_path in sorted(paths):
        if not isinstance(raw_path, str):
            raise CatalogError("OpenAPI paths must use string keys")
        try:
            module, function = _path_identity(raw_path)
        except CatalogError:
            if raw_path not in excluded_noncanonical_paths or not _is_single_segment_path(raw_path):
                raise
            excluded_paths.append(CatalogExcludedPath(raw_path, _NONCANONICAL_REASON))
            continue
        path_item = _mapping(paths[raw_path], f"path item {raw_path!r}")
        path_parameters = _parameter_sequence(path_item.get("parameters", ()), raw_path)
        for method in sorted(key for key in path_item if key in _HTTP_METHODS):
            operation_value = _mapping(path_item[method], f"operation {method.upper()} {raw_path}")
            identity = f"{module}/{function}"
            if identity in operations:
                raise CatalogError(f"duplicate canonical operation: {identity}")
            operation_parameters = _parameter_sequence(
                operation_value.get("parameters", ()), raw_path
            )
            parameters = _normalize_parameters((*path_parameters, *operation_parameters), identity)
            request_media_types = _request_media_types(operation_value, identity)
            summary = operation_value.get("summary", "")
            deprecated = operation_value.get("deprecated", False)
            if not isinstance(summary, str):
                raise CatalogError(f"operation {identity} has an invalid summary")
            if not isinstance(deprecated, bool):
                raise CatalogError(f"operation {identity} has an invalid deprecated flag")
            operations[identity] = CatalogOperation(
                identity=identity,
                module=module,
                function=function,
                method=method.upper(),
                summary=summary,
                deprecated=deprecated,
                parameters=parameters,
                request_media_types=request_media_types,
            )
    return Catalog(
        1,
        source_version,
        source_sha256,
        dict(sorted(operations.items())),
        tuple(sorted(excluded_paths, key=lambda item: item.path)),
    )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CatalogError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _path_identity(path: str) -> tuple[str, str]:
    if not path.startswith("/") or path.startswith("//") or path.endswith("//"):
        raise CatalogError(f"OpenAPI path is missing Module/function path segments: {path!r}")
    normalized = path[1:-1] if path.endswith("/") else path[1:]
    segments = normalized.split("/")
    if len(segments) != 2 or not all(segments):
        raise CatalogError(f"OpenAPI path is missing Module/function path segments: {path!r}")
    return segments[0], segments[1]


def _is_single_segment_path(path: str) -> bool:
    return path.startswith("/") and not path.startswith("//") and "/" not in path[1:]


def _excluded_paths_from_value(value: object) -> tuple[CatalogExcludedPath, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise CatalogError("catalog excluded_paths must be an array")
    excluded_paths: list[CatalogExcludedPath] = []
    for item in value:
        raw = _mapping(item, "catalog excluded path")
        path = raw.get("path")
        reason = raw.get("reason")
        if not isinstance(path, str) or not path or not isinstance(reason, str) or not reason:
            raise CatalogError("catalog excluded path has invalid metadata")
        excluded_paths.append(CatalogExcludedPath(path, reason))
    if len({item.path for item in excluded_paths}) != len(excluded_paths):
        raise CatalogError("catalog has duplicate excluded paths")
    return tuple(sorted(excluded_paths, key=lambda item: item.path))


def _parameter_sequence(value: object, path: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise CatalogError(f"parameters for {path!r} must be an array")
    return tuple(_mapping(item, f"parameter for {path!r}") for item in value)


def _normalize_parameters(
    raw_parameters: tuple[Mapping[str, object], ...], identity: str
) -> dict[str, CatalogParameter]:
    parameters: dict[str, CatalogParameter] = {}
    for raw in raw_parameters:
        name = raw.get("name")
        location = raw.get("in")
        required = raw.get("required", False)
        if not isinstance(name, str) or not name:
            raise CatalogError(f"operation {identity} has a parameter with an invalid name")
        if location not in _PARAMETER_LOCATIONS:
            raise CatalogError(
                f"operation {identity} has unsupported parameter location: {location}"
            )
        if not isinstance(required, bool):
            raise CatalogError(f"parameter {identity}:{name} has an invalid required flag")
        if name in parameters:
            raise CatalogError(f"operation {identity} has duplicate parameter: {name}")
        schema = _mapping(raw.get("schema", {}), f"schema for parameter {identity}:{name}")
        schema_type = _schema_type(schema, identity, name)
        enum = _enum_values(schema.get("enum", _combined_schema_enum(schema)), identity, name)
        default = schema.get("default")
        if not _is_json_value(default):
            raise CatalogError(f"parameter {identity}:{name} has an unsupported default")
        parameters[name] = CatalogParameter(
            name=name,
            location=cast(str, location),
            required=required,
            schema_type=schema_type,
            enum=enum,
            default=cast(JsonValue, default),
        )
    return dict(sorted(parameters.items()))


def _schema_type(schema: Mapping[str, object], identity: str, name: str) -> str:
    raw_type = schema.get("type")
    if raw_type is not None:
        if raw_type not in _SCHEMA_TYPES:
            raise CatalogError(
                f"parameter {identity}:{name} has unsupported schema type: {raw_type}"
            )
        if raw_type == "array":
            items = _mapping(schema.get("items"), f"array items for parameter {identity}:{name}")
            _schema_type(items, identity, name)
        return cast(str, raw_type)
    alternatives: list[Mapping[str, object]] = []
    for keyword in ("oneOf", "anyOf"):
        if keyword in schema:
            value = schema[keyword]
            if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
                raise CatalogError(f"parameter {identity}:{name} has an unsupported schema")
            alternatives.extend(
                _mapping(item, f"{keyword} schema for parameter {identity}:{name}")
                for item in value
            )
    if alternatives:
        types = sorted({_schema_type(item, identity, name) for item in alternatives})
        return "|".join(types)
    if "enum" in schema:
        values = _enum_values(schema["enum"], identity, name)
        inferred = sorted({_json_scalar_type(item) for item in values})
        return "|".join(inferred)
    if isinstance(schema.get("format"), str):
        return "string"
    if not schema:
        return "object"
    raise CatalogError(f"parameter {identity}:{name} has an unsupported schema")


def _combined_schema_enum(schema: Mapping[str, object]) -> object:
    values: list[JsonScalar] = []
    found = False
    for keyword in ("oneOf", "anyOf"):
        raw_alternatives = schema.get(keyword)
        if not isinstance(raw_alternatives, Sequence) or isinstance(
            raw_alternatives, (str, bytes, bytearray)
        ):
            continue
        for raw_alternative in raw_alternatives:
            if isinstance(raw_alternative, Mapping) and "enum" in raw_alternative:
                enum = raw_alternative["enum"]
                if isinstance(enum, Sequence) and not isinstance(enum, (str, bytes, bytearray)):
                    values.extend(cast(Sequence[JsonScalar], enum))
                    found = True
    return values if found else ()


def _enum_values(value: object, identity: str, name: str) -> tuple[JsonScalar, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise CatalogError(f"parameter {identity}:{name} has an unsupported enum")
    if not all(_is_json_scalar(item) for item in value):
        raise CatalogError(f"parameter {identity}:{name} has an unsupported enum")
    return tuple(sorted(cast(Sequence[JsonScalar], value), key=_json_sort_key))


def _request_media_types(operation: Mapping[str, object], identity: str) -> tuple[str, ...]:
    request_body = operation.get("requestBody")
    if request_body is None:
        return ()
    body = _mapping(request_body, f"request body for operation {identity}")
    content = _mapping(body.get("content"), f"request body content for operation {identity}")
    if not all(isinstance(media_type, str) and media_type for media_type in content):
        raise CatalogError(f"operation {identity} has an invalid request media type")
    return tuple(sorted(content))


def _operation_from_dict(identity: str, value: object) -> CatalogOperation:
    raw = _mapping(value, f"catalog operation {identity}")
    try:
        stored_identity = raw["identity"]
        module = raw["module"]
        function = raw["function"]
        method = raw["method"]
        summary = raw["summary"]
        deprecated = raw["deprecated"]
        raw_parameters = raw["parameters"]
    except KeyError as exc:
        raise CatalogError(f"catalog operation {identity} is missing field: {exc.args[0]}") from exc
    if stored_identity != identity:
        raise CatalogError(f"catalog operation identity mismatch: {identity}")
    if not all(isinstance(item, str) and item for item in (module, function, method)):
        raise CatalogError(f"catalog operation {identity} has invalid identity fields")
    if stored_identity != f"{module}/{function}":
        raise CatalogError(f"catalog operation identity mismatch: {identity}")
    if not isinstance(summary, str) or not isinstance(deprecated, bool):
        raise CatalogError(f"catalog operation {identity} has invalid metadata")
    raw_media_types = raw.get("request_media_types", ())
    if (
        not isinstance(raw_media_types, Sequence)
        or isinstance(raw_media_types, (str, bytes, bytearray))
        or not all(isinstance(item, str) and item for item in raw_media_types)
    ):
        raise CatalogError(f"catalog operation {identity} has invalid request media types")
    parameter_values = _mapping(raw_parameters, f"parameters for catalog operation {identity}")
    parameters = {
        name: _parameter_from_dict(identity, name, parameter_values[name])
        for name in sorted(parameter_values)
        if isinstance(name, str)
    }
    if len(parameters) != len(parameter_values):
        raise CatalogError(f"catalog operation {identity} has a non-string parameter name")
    return CatalogOperation(
        identity,
        cast(str, module),
        cast(str, function),
        cast(str, method),
        summary,
        deprecated,
        parameters,
        tuple(sorted(cast(Sequence[str], raw_media_types))),
    )


def _operation_to_dict(operation: CatalogOperation) -> dict[str, object]:
    value: dict[str, object] = {
        "identity": operation.identity,
        "module": operation.module,
        "function": operation.function,
        "method": operation.method,
        "summary": operation.summary,
        "deprecated": operation.deprecated,
        "parameters": {
            name: {
                "name": parameter.name,
                "location": parameter.location,
                "required": parameter.required,
                "schema_type": parameter.schema_type,
                "enum": list(parameter.enum),
                "default": parameter.default,
            }
            for name, parameter in sorted(operation.parameters.items())
        },
        "request_media_types": list(operation.request_media_types),
    }
    if operation.policy is not None:
        from .policy import policy_operation_to_dict

        value["policy"] = policy_operation_to_dict(operation.policy)
    return value


def _attach_generated_policy(
    catalog: Catalog,
    value: Mapping[str, object],
    raw_operations: Mapping[str, object],
) -> Catalog:
    has_schema = "generator_schema" in value
    has_notice = "generated_notice" in value
    has_policy = any(
        isinstance(raw_operation, Mapping) and "policy" in raw_operation
        for raw_operation in raw_operations.values()
    )
    if not (has_schema or has_notice or has_policy):
        return catalog
    if (
        value.get("generator_schema") != GENERATOR_SCHEMA
        or value.get("generated_notice") != GENERATED_NOTICE
    ):
        raise CatalogError("catalog has invalid or partial generated runtime metadata")

    from .policy import SELECTED_MODULES, PolicyError, PolicyRegistry

    embedded: dict[str, object] = {}
    for identity, raw_operation in raw_operations.items():
        raw = _mapping(raw_operation, f"catalog operation {identity}")
        if "policy" in raw:
            embedded[identity] = raw["policy"]
    manifest = {
        "schema_version": 1,
        "selected_modules": list(SELECTED_MODULES),
        "operations": embedded,
    }
    try:
        registry = PolicyRegistry.from_dict(catalog, manifest)
    except PolicyError as exc:
        raise CatalogError("catalog has invalid generated runtime policy metadata") from exc
    by_identity = {operation.identity: operation for operation in registry.all()}
    operations = {
        identity: replace(operation, policy=by_identity.get(identity))
        for identity, operation in catalog.operations.items()
    }
    return replace(
        catalog,
        operations=operations,
        generator_schema=GENERATOR_SCHEMA,
        generated_notice=GENERATED_NOTICE,
    )


def _parameter_from_dict(identity: str, name: str, value: object) -> CatalogParameter:
    raw = _mapping(value, f"catalog parameter {identity}:{name}")
    try:
        stored_name = raw["name"]
        location = raw["location"]
        required = raw["required"]
        schema_type = raw["schema_type"]
    except KeyError as exc:
        raise CatalogError(
            f"catalog parameter {identity}:{name} is missing field: {exc.args[0]}"
        ) from exc
    if stored_name != name or location not in _PARAMETER_LOCATIONS:
        raise CatalogError(f"catalog parameter {identity}:{name} has invalid identity fields")
    if not isinstance(required, bool) or not isinstance(schema_type, str) or not schema_type:
        raise CatalogError(f"catalog parameter {identity}:{name} has invalid metadata")
    enum = _enum_values(raw.get("enum", ()), identity, name)
    default = raw.get("default")
    if not _is_json_value(default):
        raise CatalogError(f"catalog parameter {identity}:{name} has an unsupported default")
    return CatalogParameter(
        name, cast(str, location), required, schema_type, enum, cast(JsonValue, default)
    )


def _is_json_scalar(value: object) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _is_json_value(value: object) -> bool:
    if _is_json_scalar(value):
        return True
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_value(item) for key, item in value.items())
    return False


def _json_scalar_type(value: JsonScalar) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    return "number"


def _json_sort_key(value: JsonScalar) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
