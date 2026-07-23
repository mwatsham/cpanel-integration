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


def test_runtime_git_examples_use_absolute_account_paths() -> None:
    text = Path("references/capabilities/runtime.md").read_text(encoding="utf-8")

    assert "runtime version-control" in text
    assert "runtime git-repositories" not in text
    assert text.count("--repository-root /home/account/repositories/site") == 4
    assert "--repository-root public_html" not in text


def test_readme_git_workflow_uses_operation_specific_source_descriptors() -> None:
    text = Path("README.md").read_text(encoding="utf-8")
    create_command = text[text.index("runtime git-create") : text.index("runtime git-update")]
    update_command = text[
        text.index("runtime git-update") : text.index("runtime deployment-create")
    ]

    assert '"url": "https://github.com/example/site.git"' in text
    assert text.count('"remote_name": "origin"') >= 2
    assert "--source-repository ./source-repository-create.json" in create_command
    assert "--source-repository ./source-repository-update.json" in update_command
