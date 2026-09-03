# File, Directory, and PHP Administration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand `cpanel-integration` so Codex can administer documented cPanel file/directory controls and PHP write operations through guarded UAPI commands.

**Architecture:** Keep the existing policy-driven CLI as the safety boundary. Promote only reviewed operations from the pinned OpenAPI metadata, add small validators/input sources where needed, regenerate the catalog/support matrix, update skill docs, and verify through TDD.

**Tech Stack:** Python 3.11+, cPanel UAPI, JSON policy metadata, pytest, Ruff, Agent Skill bundle validation.

**Spec:** Approved in-chat design on 2026-09-03.

## Global Constraints

- Support individual cPanel accounts only.
- Use cPanel UAPI over verified HTTPS on port `2083`.
- Do not automate the cPanel web interface.
- Do not add arbitrary UAPI passthrough.
- Do not install or add dependencies beyond approved runtime dependency `cryptography`.
- Use test-driven development for new behavior.
- Support `--dry-run` for every mutating operation.
- Use stdin or protected/local files for sensitive inputs.
- Commit and push logical changes.

---

### Task 1: Add file and directory policy coverage

**Files:**
- Modify: `tests/test_file_capability.py`
- Modify: `tests/test_cli.py`
- Modify: `policy/operations.json`
- Generated: `src/cpanel_admin/data/operation_catalog.json`
- Generated: `references/operation-support.md`

**Interfaces:**
- Consumes: existing generic policy CLI parser and input resolver.
- Produces: reviewed commands for file autocomplete, directory indexing, and directory privacy.

- [ ] Write failing tests for these commands:
  - `files autocomplete`
  - `files directory-indexing`
  - `files directory-indexing-list`
  - `files set-directory-indexing`
  - `files directory-privacy-status`
  - `files directory-privacy-list`
  - `files directory-privacy-users`
  - `files protect-directory`
  - `files add-directory-user`
  - `files delete-directory-user`
- [ ] Promote the exact cPanel UAPI identities from excluded to included policy records.
- [ ] Use stdin for `DirectoryPrivacy/add_user` password.
- [ ] Mark directory protection changes and user deletion as elevated-impact where reversal is not guaranteed.
- [ ] Regenerate the catalog and support matrix.
- [ ] Run focused tests.

### Task 2: Add PHP administration policy coverage

**Files:**
- Modify: `tests/test_runtime_capability.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_inputs.py`
- Modify: `policy/operations.json`
- Generated: `src/cpanel_admin/data/operation_catalog.json`
- Generated: `references/operation-support.md`

**Interfaces:**
- Consumes: existing local/protected file resolver patterns.
- Produces: reviewed commands for PHP vhost versions, PHP basic directive writes, and PHP ini content writes.

- [ ] Write failing tests for:
  - `runtime php-set-vhost-version`
  - `runtime php-set-directives`
  - `runtime php-set-ini-content`
- [ ] Add a `json_content_file` input source if needed so directive JSON is read from a local file and sent as content, not uploaded.
- [ ] Use protected/local file input for raw `php.ini` content and keep content redacted from plans/audit output.
- [ ] Promote the exact cPanel UAPI identities from excluded to included policy records.
- [ ] Regenerate the catalog and support matrix.
- [ ] Run focused tests.

### Task 3: Update skill documentation and release notes

**Files:**
- Modify: `SKILL.md`
- Modify: `README.md`
- Modify: `references/capabilities.md`
- Modify: `references/capabilities/files.md`
- Modify: `references/capabilities/runtime.md`
- Modify: `references/release-scope.md`
- Modify: `references/release-audit.md`

**Interfaces:**
- Consumes: final command names from policy.
- Produces: accurate user/agent guidance for guarded file/directory/PHP administration.

- [ ] Document new commands and protected input patterns.
- [ ] Remove stale wording that PHP writes or directory controls are unsupported.
- [ ] Keep live destructive execution scope conservative unless cleanup is independently proven.

### Task 4: Verify, install, commit, and push

**Files:**
- All modified project files.
- Installed copy: `/Users/mwatsham/.codex/skills/cpanel-integration`.

**Interfaces:**
- Consumes: verified repo state.
- Produces: pushed MVP branch and refreshed local Codex skill installation.

- [ ] Run `ruff check .`.
- [ ] Run `ruff format --check .`.
- [ ] Run `python3 scripts/check_generated.py`.
- [ ] Run `python3 scripts/validate_skill_bundle.py "$PWD"`.
- [ ] Run `.venv/bin/agentskills validate "$PWD"` if available.
- [ ] Run the full pytest suite.
- [ ] Copy the verified bundle to the installed skill directory.
- [ ] Validate the installed bundle.
- [ ] Commit and push.
