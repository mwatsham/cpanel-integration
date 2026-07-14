#!/usr/bin/env python3
"""Validate project-specific invariants for the bundled cPanel Agent Skill."""

from __future__ import annotations

import re
import sys
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

REQUIRED_FILES = (
    "AGENTS.md",
    "README.md",
    "SKILL.md",
    "references/capabilities.md",
    "references/live-testing.md",
    "references/openapi-maintenance.md",
    "references/operation-support.md",
    "references/operations.md",
    "references/release-audit.md",
    "references/safety.md",
)

SKILL_REQUIRED_PHRASES = (
    "Use the `cpanel-admin` CLI as the execution and safety boundary",
    "Never add raw module/function passthrough",
    "Run `--dry-run` before every mutation",
    "cPanel HTTPS port 2083",
)

LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]+\]\(([^):#]+(?:#[^)]+)?)\)")


def validate(root: Path) -> list[str]:
    """Return validation errors for the skill bundle rooted at ``root``."""

    errors: list[str] = []
    root = root.resolve()
    _validate_required_files(root, errors)
    _validate_skill_frontmatter(root, errors)
    _validate_skill_guardrails(root, errors)
    _validate_capability_references(root, errors)
    _validate_markdown_links(root, errors)
    return errors


def _validate_required_files(root: Path, errors: list[str]) -> None:
    for relative in REQUIRED_FILES:
        _require_file(root / relative, errors)


def _validate_skill_frontmatter(root: Path, errors: list[str]) -> None:
    skill = root / "SKILL.md"
    if not skill.exists():
        return
    text = skill.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        errors.append("SKILL.md must start with YAML frontmatter")
        return
    try:
        _start, frontmatter, _body = text.split("---", 2)
    except ValueError:
        errors.append("SKILL.md frontmatter is not closed")
        return
    fields = _simple_frontmatter(frontmatter)
    if fields.get("name") != "cpanel-integration":
        errors.append("SKILL.md frontmatter name must be cpanel-integration")
    description = fields.get("description", "")
    if not description:
        errors.append("SKILL.md frontmatter description is required")
    if "WHM" not in description or "arbitrary UAPI calls" not in description:
        errors.append("SKILL.md description must advertise WHM and arbitrary-UAPI exclusions")


def _validate_skill_guardrails(root: Path, errors: list[str]) -> None:
    skill = root / "SKILL.md"
    if not skill.exists():
        return
    text = skill.read_text(encoding="utf-8")
    for phrase in SKILL_REQUIRED_PHRASES:
        if phrase not in text:
            errors.append(f"SKILL.md is missing guardrail phrase: {phrase}")


def _validate_capability_references(root: Path, errors: list[str]) -> None:
    index = root / "references" / "capabilities.md"
    if not index.exists():
        return
    index_text = index.read_text(encoding="utf-8")
    for capability in CAPABILITIES:
        relative = Path("references") / "capabilities" / f"{capability}.md"
        link = f"capabilities/{capability}.md"
        if link not in index_text:
            errors.append(f"references/capabilities.md must link {link}")
        path = root / relative
        if not _require_file(path, errors):
            continue
        text = path.read_text(encoding="utf-8")
        for heading in ("## Use when", "## Representative commands", "## Safety notes"):
            if heading not in text:
                errors.append(f"{relative} is missing {heading}")
        if "references/operation-support.md" not in text:
            errors.append(f"{relative} must point to references/operation-support.md")
        if "--dry-run" not in text:
            errors.append(f"{relative} must mention --dry-run")


def _validate_markdown_links(root: Path, errors: list[str]) -> None:
    for path in sorted(root.rglob("*.md")):
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for match in LINK_PATTERN.finditer(text):
            target = match.group(1).split("#", 1)[0]
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            if target.startswith("/"):
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                errors.append(f"{path.relative_to(root)} has out-of-bundle link: {target}")
                continue
            if not resolved.exists():
                errors.append(f"{path.relative_to(root)} has missing link target: {target}")


def _simple_frontmatter(value: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in value.strip().splitlines():
        if not line.strip():
            continue
        if line.startswith(" ") and current is not None:
            fields[current] = f"{fields[current]} {line.strip()}"
            continue
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        current = key.strip()
        fields[current] = raw.strip()
    return fields


def _require_file(path: Path, errors: list[str]) -> bool:
    if path.is_file():
        return True
    errors.append(f"missing required file: {path}")
    return False


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0]) if args else Path.cwd()
    errors = validate(root)
    if errors:
        for error in errors:
            print(f"skill bundle validation failed: {error}", file=sys.stderr)
        return 1
    print(f"Valid cPanel skill bundle: {root.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
