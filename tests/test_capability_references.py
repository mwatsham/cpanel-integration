"""Documentation contracts for task-oriented capability references."""

from pathlib import Path

CAPABILITIES = (
    "backups",
    "databases",
    "diagnostics",
    "domains",
    "email",
    "files",
    "ftp",
    "runtime",
    "security",
    "ssl",
)


def test_capability_reference_index_lists_all_supported_packs() -> None:
    index = Path("references/capabilities.md")
    assert index.exists()
    text = index.read_text(encoding="utf-8")
    for capability in CAPABILITIES:
        assert f"capabilities/{capability}.md" in text
    assert "references/operation-support.md" in text
    assert "references/safety.md" in text


def test_each_capability_reference_has_usage_and_safety_sections() -> None:
    for capability in CAPABILITIES:
        path = Path("references/capabilities") / f"{capability}.md"
        assert path.exists()
        text = path.read_text(encoding="utf-8")
        assert "## Use when" in text
        assert "## Representative commands" in text
        assert "## Safety notes" in text
        assert "references/operation-support.md" in text
        assert "--dry-run" in text
