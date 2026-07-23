# Guarded cPanel Git Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow the cPanel skill to create, update, delete, and deploy cPanel Git repositories through reviewed, policy-driven CLI commands.

**Architecture:** Keep the existing generated policy/catalog and generic CLI parser as the safety boundary. Promote reviewed `VersionControl/*` and `VersionControlDeployment/*` operations from excluded to included policy entries, relying on existing dry-run, confirmation, audit, validation, and generated parser behavior.

**Tech Stack:** Python, argparse, pytest, generated cPanel UAPI catalog, JSON policy metadata, Codex Agent Skill files.

## Global Constraints

- Scope is individual cPanel accounts only; no WHM, root, reseller, or server-wide Git administration.
- No raw UAPI passthrough and no arbitrary shell or Git command execution.
- Mutating operations must support dry-run plans and confirmation controls through the existing planner/executor.
- Repository sources must be supplied as structured JSON via a local file, not chat-pasted secrets.
- Repository roots and deploy IDs must use existing bounded text validation.
- Keep changes small, tested, documented, committed, pushed, and copied into the installed skill after verification.

---

### Task 1: Policy and CLI Tests for Git Management

**Files:**
- Modify: `tests/test_runtime_capability.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: existing `PolicyRegistry`, `Risk`, and CLI fixture patterns.
- Produces: failing tests requiring included Git create/update/delete/deployment operations and CLI argument behavior.

- [ ] **Step 1: Write failing policy tests**

Add the Git mutation identities to `RUNTIME_INCLUDED`, remove them from `RUNTIME_EXCLUDED`, and assert operation risk/elevated-impact/parameter sources:

```python
assert subject.get("runtime.git-create").risk is Risk.MUTATE
assert subject.get("runtime.git-delete").elevated_impact is True
assert subject.get("runtime.deployment-create").risk is Risk.MUTATE
assert subject.get("runtime.deployment-delete").elevated_impact is True
```

- [ ] **Step 2: Write failing CLI tests**

Add CLI tests that call:

```bash
cpanel-admin --profile test runtime git-create --repository-root /home/account/repositories/site --name site --type git --source-repository source.json --dry-run
cpanel-admin --profile test runtime git-update --repository-root /home/account/repositories/site --name site --branch main --source-repository source.json --dry-run
cpanel-admin --profile test runtime git-delete --repository-root /home/account/repositories/site --dry-run
cpanel-admin --profile test runtime deployment-create --repository-root /home/account/repositories/site --dry-run
cpanel-admin --profile test runtime deployment-delete --deploy-id abc123 --dry-run
```

Assert each returns a dry-run plan with the expected `operation`, `identity`, `risk`, and confirmation requirement where applicable.

- [ ] **Step 3: Run tests to verify RED**

Run:

```bash
pytest tests/test_runtime_capability.py tests/test_cli.py -q
```

Expected: failures showing Git mutation operations are excluded or command paths do not exist.

### Task 2: Include Guarded Git Operations in Policy

**Files:**
- Modify: `policy/operations.json`
- Modify generated: `src/cpanel_admin/data/operation_catalog.json`

**Interfaces:**
- Consumes: existing policy schema.
- Produces: included policy entries named `runtime.git-create`, `runtime.git-update`, `runtime.git-delete`, `runtime.deployment-create`, and `runtime.deployment-delete`.

- [ ] **Step 1: Update policy metadata**

Promote these identities to `included`:

```text
VersionControl/create
VersionControl/update
VersionControl/delete
VersionControlDeployment/create
VersionControlDeployment/delete
```

Use command paths:

```text
runtime git-create
runtime git-update
runtime git-delete
runtime deployment-create
runtime deployment-delete
```

Set create/update/deployment-create as `mutate`; set git-delete/deployment-delete as elevated-impact `mutate`.

- [ ] **Step 2: Assign parameter policy**

Use existing validators/sources:

```text
repository_root -> argument, bounded_text
name -> argument, bounded_text
type -> argument, enum
branch -> argument, bounded_text
source_repository -> local_file
deploy_id -> argument, bounded_text
```

- [ ] **Step 3: Regenerate catalog**

Run:

```bash
python3 scripts/generate_catalog.py
```

- [ ] **Step 4: Run focused tests to verify GREEN**

Run:

```bash
pytest tests/test_runtime_capability.py tests/test_cli.py -q
```

Expected: focused Git capability and CLI tests pass.

### Task 3: Documentation and Skill Guardrails

**Files:**
- Modify: `SKILL.md`
- Modify: `README.md`
- Modify: `references/capabilities/runtime.md`
- Modify: `references/operation-support.md`
- Modify: `references/release-scope.md`
- Modify: `references/release-audit.md`

**Interfaces:**
- Consumes: final command names from policy.
- Produces: user-facing Git deployment guidance and safety constraints.

- [ ] **Step 1: Update runtime docs**

Document the supported Git commands and clarify that source repositories are supplied through protected local JSON files.

- [ ] **Step 2: Update skill guardrails**

Replace “Git read-oriented only” language with guarded Git management guidance:

```text
Run dry-run before Git create/update/delete/deploy mutations.
Use local files for source_repository JSON.
Do not run arbitrary shell Git commands or raw UAPI.
```

- [ ] **Step 3: Update operation support references**

Change the five Git operation rows from excluded to included with risk labels and reviewed reasons.

### Task 4: Full Verification, Install Copy, Commit, Push

**Files:**
- Verify all modified files.
- Update installed copy under `/Users/mwatsham/.codex/skills/cpanel-integration`.

**Interfaces:**
- Consumes: verified repo state.
- Produces: pushed branch and refreshed installed skill.

- [ ] **Step 1: Run generated and bundle checks**

Run:

```bash
python3 scripts/check_generated.py
python3 scripts/validate_skill_bundle.py "$PWD"
```

- [ ] **Step 2: Run quality gates**

Run:

```bash
ruff check .
ruff format --check .
pytest -q
```

- [ ] **Step 3: Refresh installed skill**

Copy the verified bundle files into:

```text
/Users/mwatsham/.codex/skills/cpanel-integration
```

- [ ] **Step 4: Commit and push**

Run:

```bash
git add .
git commit -m "feat: add guarded cpanel git management"
git push origin codex/cpanel-admin-mvp
```
