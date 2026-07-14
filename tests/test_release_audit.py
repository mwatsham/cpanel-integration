"""Documentation contract for the production completion audit."""

from pathlib import Path


def test_release_audit_covers_production_completion_criteria() -> None:
    audit = Path("references/release-audit.md")
    assert audit.exists()
    text = audit.read_text(encoding="utf-8")
    expected_phrases = (
        "Requirement-by-requirement completion audit",
        "official OpenAPI source is pinned",
        "Catalog generation is deterministic",
        "Every candidate operation in scope",
        "Every included operation",
        "Unit, mocked integration, CLI, redaction, and documentation tests",
        "Coverage remains at or above 90%",
        "Ruff lint and formatting checks",
        "project skill validators",
        "README.md, AGENTS.md, SKILL.md",
        "Disposable-account verification",
        "Remaining gaps",
        "live create/read/update/delete lifecycle",
    )
    for phrase in expected_phrases:
        assert phrase in text
