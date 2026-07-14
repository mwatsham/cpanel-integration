"""Documentation contract for pinned cPanel OpenAPI maintenance."""

from __future__ import annotations

from pathlib import Path


def test_openapi_reference_documents_pinning_and_update_workflow() -> None:
    reference = Path("references/openapi-maintenance.md")
    assert reference.exists()
    text = reference.read_text(encoding="utf-8")
    expected_phrases = (
        "specifications/cpanel.openapi.json",
        "specifications/cpanel.openapi.lock.json",
        "https://api.docs.cpanel.net/_bundle/specifications/cpanel.openapi.json?download",
        "SHA-256",
        "scripts/generate_catalog.py",
        "scripts/check_generated.py",
        "normal builds must not download",
        "reviewed policy",
        "references/operation-support.md",
    )
    for phrase in expected_phrases:
        assert phrase in text
