#!/usr/bin/env python3
"""Normalize the pinned cPanel OpenAPI document into deterministic JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cpanel_admin.catalog import CatalogError, normalize_document

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_NONCANONICAL_PATHS = frozenset({"/get_php_recommendations", "/get_recommendations"})


def generate(source: Path, lock_path: Path) -> str:
    source_bytes = source.read_bytes()
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    expected_sha256 = lock.get("sha256")
    actual_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if not isinstance(expected_sha256, str) or actual_sha256 != expected_sha256:
        raise CatalogError("pinned OpenAPI checksum does not match lock file")
    raw_excluded_paths = lock.get("excluded_noncanonical_paths")
    if not isinstance(raw_excluded_paths, list) or not all(
        isinstance(path, str) for path in raw_excluded_paths
    ):
        raise CatalogError("lock file excluded_noncanonical_paths must be an array of strings")
    excluded_paths = frozenset(raw_excluded_paths)
    if excluded_paths != EXPECTED_NONCANONICAL_PATHS or len(raw_excluded_paths) != 2:
        raise CatalogError("lock file must list exactly the two approved noncanonical paths")
    document = json.loads(source_bytes)
    catalog = normalize_document(
        document,
        source_sha256=actual_sha256,
        excluded_noncanonical_paths=excluded_paths,
    )
    return catalog.to_json()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "specifications/cpanel.openapi.json")
    parser.add_argument(
        "--lock", type=Path, default=ROOT / "specifications/cpanel.openapi.lock.json"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        generated = generate(args.source, args.lock)
        if args.output is None:
            sys.stdout.write(generated)
        else:
            args.output.write_text(generated, encoding="utf-8")
    except (CatalogError, OSError, json.JSONDecodeError) as exc:
        parser.exit(1, f"catalog generation failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
