"""Release scope contract for live execution coverage."""

from pathlib import Path


def test_release_scope_documents_dry_run_only_packs() -> None:
    scope = Path("references/release-scope.md")
    assert scope.exists()
    text = scope.read_text(encoding="utf-8")
    for capability in ("backups", "domains", "files", "runtime", "SSL"):
        assert capability in text
    assert "dry-run-only" in text
    assert "cleanup or rollback path" in text
    assert "databases, email, FTP, and security" in text
