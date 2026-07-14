"""Contract tests for the project-owned skill bundle validator."""

from pathlib import Path

from scripts import validate_skill_bundle


def test_project_skill_bundle_validator_accepts_current_repo() -> None:
    assert Path("scripts/validate_skill_bundle.py").exists()
    assert validate_skill_bundle.validate(Path(".")) == []


def test_project_skill_bundle_validator_reports_missing_capability_reference(
    tmp_path: Path,
) -> None:
    root = tmp_path / "skill"
    (root / "references" / "capabilities").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: cpanel-integration\ndescription: x\n---\n"
        "[references/capabilities.md](references/capabilities.md)\n",
        encoding="utf-8",
    )
    (root / "references" / "capabilities.md").write_text(
        "[capabilities/domains.md](capabilities/domains.md)\n",
        encoding="utf-8",
    )

    errors = validate_skill_bundle.validate(root)

    assert any("references/capabilities/domains.md" in error for error in errors)
