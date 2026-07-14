#!/usr/bin/env python3
"""Generate deterministic packaged metadata from the pinned cPanel API and policy."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cpanel_admin.catalog import (
    GENERATED_NOTICE,
    GENERATOR_SCHEMA,
    Catalog,
    CatalogError,
    normalize_document,
)
from cpanel_admin.policy import (
    EXPECTED_POLICY_SHA256,
    SELECTED_MODULES,
    PolicyError,
    PolicyRegistry,
    canonical_policy_sha256,
    policy_operation_to_dict,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "specifications/cpanel.openapi.json"
DEFAULT_LOCK = ROOT / "specifications/cpanel.openapi.lock.json"
DEFAULT_POLICY = ROOT / "policy/operations.json"
DEFAULT_OUTPUT = ROOT / "src/cpanel_admin/data/operation_catalog.json"
DEFAULT_SUPPORT_OUTPUT = ROOT / "references/operation-support.md"
EXPECTED_SHA256 = "3d9ec80cd8d774312c4bb6b0dfdbc17e6e6ffc92a8f0c2cd88f01e32864fa2c6"
EXPECTED_OPENAPI_VERSION = "3.0.2"
EXPECTED_UAPI_VERSION = "11.136.0.25"
EXPECTED_NONCANONICAL_PATHS = frozenset({"/get_php_recommendations", "/get_recommendations"})


def policy_candidate_identities(catalog: Catalog) -> tuple[str, ...]:
    """Return the deterministic explicit-policy surface for the approved module set."""

    return tuple(
        identity
        for identity, operation in sorted(catalog.operations.items())
        if operation.module in SELECTED_MODULES
    )


def _load_catalog(source: Path, lock_path: Path) -> Catalog:
    source_bytes = source.read_bytes()
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    document = json.loads(source_bytes)
    if not isinstance(document, dict) or document.get("openapi") != EXPECTED_OPENAPI_VERSION:
        raise CatalogError(f"pinned OpenAPI version must be {EXPECTED_OPENAPI_VERSION}")
    info = document.get("info")
    if not isinstance(info, dict) or info.get("version") != EXPECTED_UAPI_VERSION:
        raise CatalogError(f"pinned UAPI version must be {EXPECTED_UAPI_VERSION}")
    if lock.get("generator_schema") != GENERATOR_SCHEMA:
        raise CatalogError(f"lock generator_schema must be {GENERATOR_SCHEMA}")
    if lock.get("openapi") != EXPECTED_OPENAPI_VERSION:
        raise CatalogError(f"lock OpenAPI version must be {EXPECTED_OPENAPI_VERSION}")
    if lock.get("uapi_version") != EXPECTED_UAPI_VERSION:
        raise CatalogError(f"lock UAPI version must be {EXPECTED_UAPI_VERSION}")
    expected_sha256 = lock.get("sha256")
    actual_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if expected_sha256 != EXPECTED_SHA256 or actual_sha256 != EXPECTED_SHA256:
        raise CatalogError(f"pinned OpenAPI must match approved SHA-256 {EXPECTED_SHA256}")
    raw_excluded_paths = lock.get("excluded_noncanonical_paths")
    if not isinstance(raw_excluded_paths, list) or not all(
        isinstance(path, str) for path in raw_excluded_paths
    ):
        raise CatalogError("lock file excluded_noncanonical_paths must be an array of strings")
    excluded_paths = frozenset(raw_excluded_paths)
    if excluded_paths != EXPECTED_NONCANONICAL_PATHS or len(raw_excluded_paths) != 2:
        raise CatalogError("lock file must list exactly the two approved noncanonical paths")
    return normalize_document(
        document,
        source_sha256=actual_sha256,
        excluded_noncanonical_paths=excluded_paths,
    )


def _generate_artifacts(
    source: Path,
    policy_path: Path,
    lock_path: Path,
) -> tuple[str, str]:
    catalog = _load_catalog(source, lock_path)
    registry = PolicyRegistry.load(catalog, policy_path)
    policy_sha256 = canonical_policy_sha256(registry)
    if policy_sha256 != EXPECTED_POLICY_SHA256:
        raise PolicyError("policy does not match trusted reviewed policy digest")
    value = json.loads(catalog.to_json())
    value["generator_schema"] = GENERATOR_SCHEMA
    value["generated_notice"] = GENERATED_NOTICE
    value["policy_sha256"] = policy_sha256
    for operation in registry.all():
        value["operations"][operation.identity]["policy"] = policy_operation_to_dict(operation)
    generated = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    return generated, _support_matrix(catalog, registry)


def generate(
    source: Path,
    policy_path: Path,
    *,
    lock_path: Path = DEFAULT_LOCK,
) -> str:
    """Return the deterministic merged runtime catalog."""

    generated, _support = _generate_artifacts(source, policy_path, lock_path)
    return generated


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _support_matrix(catalog: Catalog, registry: PolicyRegistry) -> str:
    lines = [
        "# cPanel Operation Support Matrix",
        "",
        "> Generated from the pinned cPanel OpenAPI document and reviewed policy. "
        "Do not edit manually.",
        "",
        f"- Source UAPI version: `{catalog.source_version}`",
        f"- Source SHA-256: `{catalog.source_sha256}`",
        f"- Included operations: {len(registry.included())}",
        f"- Excluded operations: {len(registry.excluded())}",
        "",
        "The local allowlist is an application safeguard, not a substitute for cPanel account "
        "permissions. This catalog does not provide arbitrary UAPI passthrough.",
        "",
        "| Canonical operation | Status | Capability | Risk | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for operation in registry.all():
        risk = operation.risk.value if operation.risk is not None else "-"
        lines.append(
            f"| `{_markdown_cell(operation.identity)}` | {operation.status.value} | "
            f"{_markdown_cell(operation.capability)} | {risk} | "
            f"{_markdown_cell(operation.reason)} |"
        )
    return "\n".join(lines) + "\n"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _check_current(path: Path, expected: str, label: str) -> None:
    try:
        actual = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogError(f"stale generated output: {label} is unavailable: {path}") from exc
    if actual != expected:
        raise CatalogError(f"stale generated output: {label}: {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--support-output", type=Path, default=DEFAULT_SUPPORT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        generated, support = _generate_artifacts(args.source, args.policy, args.lock)
        if args.check:
            _check_current(args.output, generated, "runtime catalog")
            _check_current(args.support_output, support, "support matrix")
            print("generated catalog is current")
        else:
            _write(args.output, generated)
            _write(args.support_output, support)
    except (CatalogError, PolicyError, OSError, json.JSONDecodeError) as exc:
        parser.exit(1, f"catalog generation failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
