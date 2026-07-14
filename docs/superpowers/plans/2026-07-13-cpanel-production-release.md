# cPanel Production Release and Live Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close operation-policy, documentation, Agent Skill, packaging, automated-test, live disposable-account, cleanup, and requirement-audit gates for a production release.

**Architecture:** Treat generated metadata and the support matrix as audited artifacts, then validate every included and excluded operation through parameterized contracts. Update the Agent Skill using progressive disclosure, run serial gated live lifecycles with redacted evidence, and finish with an explicit requirement-to-evidence matrix.

**Tech Stack:** Python 3.11+, pytest, pytest-cov, Ruff, setuptools/pip wheel, Agent Skills reference validator, cPanel UAPI disposable profile.

## Global Constraints

- Do not add capabilities or dependencies during release closure.
- Every one of the 393 selected candidate operations must have a permanent reviewed policy decision.
- Every included operation must have a contract test; every excluded operation must have a negative
  resolution test.
- Default tests must remain offline.
- Live tests must require the named disposable profile and explicit destructive-action gate.
- Live resources must have a unique prefix and be removed or explicitly reported.
- Never place credentials, private keys, passwords, sensitive file contents, or authorization headers
  in reports or documentation.
- Maintain at least 90% line coverage.
- Do not claim release completion until every audit row has direct evidence.

---

## File Structure

```text
tests/test_operation_contracts.py            every included operation
tests/test_policy_exclusions.py              every excluded operation
tests/test_secret_leaks.py                   stdout/stderr/error/audit/plan regression
tests/test_documentation.py                  generated matrix and command docs
tests/live/conftest.py                       gates, unique prefix, invocation, report
tests/live/test_discovery.py                  read-only capability discovery
tests/live/test_web_lifecycles.py             domains/files/database/SSL/backup lifecycles
tests/live/test_email_access_lifecycles.py    email/FTP lifecycles
tests/live/test_runtime_security.py           runtime/security/diagnostic lifecycles
tests/live/report.py                          redacted structured evidence
references/capabilities/*.md                 pack documentation
references/operation-support.md              generated support matrix
references/live-testing.md                   disposable test procedure
docs/release/production-readiness.md          requirement-to-evidence audit
```

### Task 1: Enforce final operation-policy completeness

**Files:**
- Create: `tests/test_operation_contracts.py`
- Create: `tests/test_policy_exclusions.py`
- Modify: `tests/test_policy.py`
- Modify: `scripts/generate_catalog.py`

**Interfaces:**
- Consumes: final catalog and policy registry.
- Produces: one contract case for every included identity and one denial case per exclusion.

- [ ] **Step 1: Write failing final-completeness tests**

```python
def test_no_temporary_or_blank_policy_reasons(registry: PolicyRegistry) -> None:
    forbidden = {"pending", "not enabled until", "not reviewed", "tbd", "todo"}
    for operation in registry.all():
        assert operation.reason.strip()
        assert not any(token in operation.reason.lower() for token in forbidden)


def test_every_included_operation_has_contract_metadata(registry: PolicyRegistry) -> None:
    for operation in registry.included():
        assert operation.command
        assert operation.risk is not None
        assert operation.audit_fields is not None
        if operation.risk is not Risk.READ:
            assert operation.impact
            assert operation.recovery


def test_every_excluded_operation_is_unresolvable(registry: PolicyRegistry) -> None:
    for operation in registry.excluded():
        with pytest.raises(CapabilityError):
            registry.get(operation.name)
```

- [ ] **Step 2: Run and verify any remaining failures**

Run: `.venv/bin/python -m pytest tests/test_policy.py tests/test_policy_exclusions.py -v`

Expected: failures identify exact incomplete records, if any; do not weaken the assertions.

- [ ] **Step 3: Add parameterized included-operation contracts**

For every included policy record, synthesize valid values from the policy validator fixture and
assert:

```python
@pytest.mark.parametrize("operation", tuple(REGISTRY.included()), ids=lambda op: op.name)
def test_included_operation_contract(operation: PolicyOperation) -> None:
    catalog_operation = CATALOG.get(operation.identity)
    values = valid_values(operation)
    normalized = validate_operation_inputs(operation, catalog_operation, values)
    assert set(normalized) == set(values)
    assert operation.command == REGISTRY.by_command(operation.command).command
    assert not ({"module", "function"} & set(operation.parameters))
```

Add separate parameterized assertions for confirmation, secret source, preflight adapter,
verification adapter, and audit-field requirements.

- [ ] **Step 4: Fix policy defects and run contracts**

Run: `.venv/bin/python -m pytest tests/test_operation_contracts.py tests/test_policy_exclusions.py tests/test_policy.py -v`

Expected: PASS; report exact included/excluded counts.

- [ ] **Step 5: Generate and commit**

```bash
.venv/bin/python scripts/generate_catalog.py
.venv/bin/python scripts/check_generated.py
git add policy scripts references/operation-support.md tests/test_operation_contracts.py tests/test_policy_exclusions.py tests/test_policy.py
git commit -m "test: enforce complete cPanel operation policy"
```

### Task 2: Complete secret-leak and failure-path regression coverage

**Files:**
- Create: `tests/test_secret_leaks.py`
- Modify: `src/cpanel_admin/redaction.py`
- Modify: `src/cpanel_admin/audit.py`
- Modify: `src/cpanel_admin/executor.py`

**Interfaces:**
- Consumes: every secret-bearing policy record.
- Produces: exhaustive safe-output proof across plans, transport, errors, audit, and verification.

- [ ] **Step 1: Write failing parameterized leak tests**

```python
SECRET = "cpanel-admin-unique-secret-marker"

@pytest.mark.parametrize("operation", tuple(secret_operations()), ids=lambda op: op.name)
def test_secret_never_leaks_from_any_output_channel(operation, tmp_path) -> None:
    result = invoke_failure_for(operation, secret=SECRET, audit_dir=tmp_path)
    combined = result.stdout + result.stderr + result.exception + read_audit(tmp_path)
    assert SECRET not in combined
    assert urllib.parse.quote_plus(SECRET) not in combined


def test_nested_key_variants_are_redacted() -> None:
    value = {"dkimPrivateKey": SECRET, "access-token": SECRET, "passphrase": SECRET}
    assert SECRET not in json.dumps(redact(value, secrets=(SECRET,)))
```

- [ ] **Step 2: Run and verify failures without printing markers**

Run: `.venv/bin/python -m pytest tests/test_secret_leaks.py -v`

Expected: any failure names only the operation ID; pytest output does not echo the marker value.

- [ ] **Step 3: Harden redaction and safe serialization**

Normalize sensitive keys by removing `_`, `-`, and case differences. Cover token, password,
passphrase, secret, private key, DKIM key, certificate body, content, authorization, webcall URL, and
encrypted-token variants. Ensure exception chaining never formats request data.

- [ ] **Step 4: Run all security tests**

Run:

```bash
.venv/bin/python -m pytest tests/test_secret_leaks.py tests/test_redaction.py tests/test_transport.py tests/test_audit.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cpanel_admin/redaction.py src/cpanel_admin/audit.py src/cpanel_admin/executor.py tests/test_secret_leaks.py
git commit -m "security: prove cPanel secret non-disclosure"
```

### Task 3: Update the Agent Skill and repository documentation

**Files:**
- Modify: `SKILL.md`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `agents/openai.yaml`
- Modify: `references/operations.md`
- Modify: `references/safety.md`
- Create: `references/live-testing.md`
- Create: `tests/test_documentation.py`

**Interfaces:**
- Consumes: final CLI, policy support matrix, safety behavior.
- Produces: concise skill workflow with progressive capability references and current commands.

- [ ] **Step 1: Read the required skill-authoring instructions**

Read the complete `superpowers:writing-skills` and `skill-creator` `SKILL.md` files before editing
the Agent Skill. Follow their validation and progressive-disclosure requirements.

- [ ] **Step 2: Write failing documentation-contract tests**

```python
def test_every_capability_reference_is_linked_from_skill() -> None:
    skill = SKILL.read_text()
    for reference in sorted((ROOT / "references/capabilities").glob("*.md")):
        assert f"references/capabilities/{reference.name}" in skill


def test_documented_commands_exist_in_policy() -> None:
    for command in documented_command_paths():
        assert REGISTRY.by_command(command)


def test_readme_does_not_call_production_scope_mvp() -> None:
    assert "The MVP supports" not in README.read_text()
```

- [ ] **Step 3: Run and verify stale-documentation failures**

Run: `.venv/bin/python -m pytest tests/test_documentation.py -v`

Expected: FAIL because current docs describe only four MVP groups.

- [ ] **Step 4: Rewrite `SKILL.md` using progressive disclosure**

Keep frontmatter name `cpanel-integration`; expand the description to cover the approved packs and
retain WHM/server/mailbox-content exclusions. Keep the body under 500 lines and include:

```text
Prepare -> Discover -> Select task -> Dry-run -> Approve -> Execute -> Verify -> Report
```

Link all capability references and `references/safety.md`. Instruct the agent never to request a
secret in chat and never to bypass the CLI.

- [ ] **Step 5: Update repository and contributor documentation**

`README.md` documents installation, key/profile configuration, capability discovery, every command
family, confirmation, audit location, OpenAPI pin/update, exclusions, testing, and live verification.
`AGENTS.md` changes status from MVP, lists the new structure and exact generation/check commands,
requires permanent policy review, and retains small commits. Update `agents/openai.yaml`,
`references/operations.md`, and `references/safety.md` to match runtime behavior exactly.

- [ ] **Step 6: Validate docs and Agent Skill**

Run:

```bash
.venv/bin/python -m pytest tests/test_documentation.py -v
.venv/bin/agentskills validate "$PWD"
.venv/bin/agentskills read-properties "$PWD"
```

Expected: tests pass; validator reports a valid skill; properties show the expected name and
description.

- [ ] **Step 7: Commit**

```bash
git add AGENTS.md README.md SKILL.md agents references tests/test_documentation.py
git commit -m "docs: publish production cPanel skill guidance"
```

### Task 4: Add packaging, installation, and CLI smoke gates

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/cpanel_admin/__init__.py`
- Create: `tests/test_packaging.py`

**Interfaces:**
- Consumes: packaged catalog and CLI entry point.
- Produces: installable production version with included runtime data.

- [ ] **Step 1: Write failing package-data test**

```python
def test_runtime_catalog_is_present_in_wheel(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path)
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    assert any(name.endswith("cpanel_admin/data/operation_catalog.json") for name in names)


def test_version_is_production_release() -> None:
    assert cpanel_admin.__version__ == "1.0.0"
```

- [ ] **Step 2: Run and verify version/package failure**

Run: `.venv/bin/python -m pytest tests/test_packaging.py -v`

Expected: FAIL because version remains `0.1.0` or package data is absent.

- [ ] **Step 3: Set version and package metadata**

Set project and module version to `1.0.0`. Ensure `cpanel_admin.data/*.json` is in both editable and
wheel installs. Do not add a build dependency.

- [ ] **Step 4: Build and smoke-test in an isolated venv**

```bash
.venv/bin/python -m pip wheel --no-deps --wheel-dir /tmp/cpanel-admin-wheel .
python3 -m venv /tmp/cpanel-admin-smoke
/tmp/cpanel-admin-smoke/bin/python -m pip install /tmp/cpanel-admin-wheel/cpanel_account_admin-1.0.0-py3-none-any.whl
/tmp/cpanel-admin-smoke/bin/cpanel-admin --help
/tmp/cpanel-admin-smoke/bin/cpanel-admin operations list
```

Expected: wheel builds, installs, help succeeds, and operations JSON is returned without source-tree
files.

- [ ] **Step 5: Run tests and commit**

Run: `.venv/bin/python -m pytest tests/test_packaging.py -v`

Expected: PASS.

```bash
git add pyproject.toml src/cpanel_admin/__init__.py tests/test_packaging.py
git commit -m "build: prepare cPanel skill production package"
```

### Task 5: Build the gated disposable-account live harness

**Files:**
- Create: `tests/live/__init__.py`
- Create: `tests/live/conftest.py`
- Create: `tests/live/report.py`
- Create: `tests/live/test_discovery.py`
- Modify: `tests/test_live_cpanel.py`
- Modify: `pyproject.toml`
- Create: `references/live-testing.md`

**Interfaces:**
- Consumes: existing named disposable profile and environment gates.
- Produces: serial invoker, unique resource namespace, cleanup registry, and redacted report.

- [ ] **Step 1: Write failing harness unit tests**

Add concrete table-driven environment cases missing each required acknowledgement and assert a skip
reason naming only the missing variable. Assert the generated prefix matches
`cpanel_admin_live_[0-9a-f]{8}`, write a report fixture containing unique host/token/password markers
and assert none survive, and register callbacks `first`, `second`, `third` then assert cleanup order
is `third`, `second`, `first`.

Required environment gates are:

```text
CPANEL_ADMIN_RUN_LIVE_TESTS=1
CPANEL_ADMIN_LIVE_DISPOSABLE=I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE
CPANEL_ADMIN_LIVE_PROFILE=test-123reg
CPANEL_ADMIN_LIVE_DESTRUCTIVE=I_APPROVE_DESTRUCTIVE_LIVE_TESTS
```

The destructive gate is required only for destructive/elevated tests, not read-only discovery.

- [ ] **Step 2: Run harness tests offline**

Run: `.venv/bin/python -m pytest tests/live/test_discovery.py -v`

Expected: tests skip without live gates; pure report/cleanup unit cases pass.

- [ ] **Step 3: Implement fixtures and report schema**

```python
@dataclass
class LiveEvidence:
    capability: str
    operation: str
    status: str
    verification: str
    cleanup: str
    reason: str | None = None


@dataclass
class LiveReport:
    run_id: str
    started_at: str
    profile: str
    catalog_sha256: str
    evidence: list[LiveEvidence]
    leftovers: list[str]
```

Write reports to `${CPANEL_ADMIN_LIVE_REPORT_DIR:-/tmp/cpanel-admin-live}/RUN_ID.json` with mode
`0600`. Redact host, username, token, key, passwords, private material, and file contents. Register
cleanup callbacks immediately after successful creation and execute them in reverse order.

- [ ] **Step 4: Add read-only discovery test**

Probe profile, `Features/list_features`, and one read operation per capability pack. Record
`available`, `server_unavailable`, or `failed` with redacted evidence. A failed probe cannot be
silently converted into a skip.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml tests/live tests/test_live_cpanel.py references/live-testing.md
git commit -m "test: add disposable cPanel live harness"
```

### Task 6: Add web capability live lifecycles

**Files:**
- Create: `tests/live/test_web_lifecycles.py`
- Modify: `tests/live/report.py`
- Modify: `references/live-testing.md`

**Interfaces:**
- Consumes: live harness and disposable profile.
- Produces: representative create/read/update/delete evidence for web packs.

- [ ] **Step 1: Add gated lifecycle cases**

Implement serial cases for:

```text
domains/DNS: add, inspect, update, and delete a uniquely prefixed TXT record
files: upload, inspect, overwrite, verify, and purge through supported trash behavior
databases: create database and user, grant, verify, revoke, delete user and database
SSL: generate key/CSR/self-signed certificate metadata, inspect, then delete generated artifacts
backups: list/browse; create local backup only when CPANEL_ADMIN_LIVE_BACKUP=I_ACCEPT_A_LEFTOVER_BACKUP
```

Every mutation first invokes dry-run. Destructive execution uses the returned digest/expiry. Record
all cleanup attempts. If the backup opt-in is enabled, record the created backup as an explicit
leftover because the reviewed UAPI surface has no safe delete operation.

- [ ] **Step 2: Run read-only subset first**

```bash
CPANEL_ADMIN_RUN_LIVE_TESTS=1 \
CPANEL_ADMIN_LIVE_DISPOSABLE=I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE \
CPANEL_ADMIN_LIVE_PROFILE=test-123reg \
.venv/bin/python -m pytest tests/live/test_discovery.py tests/live/test_web_lifecycles.py -m live -v
```

Expected: discovery passes; destructive cases skip without the destructive gate.

- [ ] **Step 3: Run explicitly approved lifecycle set**

Add `CPANEL_ADMIN_LIVE_DESTRUCTIVE=I_APPROVE_DESTRUCTIVE_LIVE_TESTS` and rerun without the optional
backup leftover gate.

Expected: available packs pass, unavailable features record evidence, and cleanup leaves no web test
resources.

- [ ] **Step 4: Commit**

```bash
git add tests/live/test_web_lifecycles.py tests/live/report.py references/live-testing.md
git commit -m "test: verify web packs on disposable cPanel"
```

### Task 7: Add email, FTP, runtime, security, and diagnostic live lifecycles

**Files:**
- Create: `tests/live/test_email_access_lifecycles.py`
- Create: `tests/live/test_runtime_security.py`
- Modify: `tests/live/report.py`
- Modify: `references/live-testing.md`

**Interfaces:**
- Consumes: live harness and capability report.
- Produces: representative live evidence for all remaining packs.

- [ ] **Step 1: Add email and FTP lifecycle cases**

```text
email: create prefixed mailbox with generated local password, set quota, add/remove forwarder and
autoresponder, change/restore a safe spam preference, then delete the mailbox
FTP: create prefixed account under a prefixed home, set quota/password, inspect, then delete
```

Do not browse, read, send, expunge, or delete messages. Never write generated passwords to reports.

- [ ] **Step 2: Add runtime/security lifecycle cases**

```text
Git: use only a host already in the disposable profile allowlist; create/list/update/delete a local
repository without deployment unless the fixture contains an approved benign repository
PHP: read installed/default versions; set and restore one benign basic directive on the test domain
Passenger/NGINX: read status and run mutations only when a disposable prefixed app/cache target exists
Security: add/remove TEST-NET-3 address 203.0.113.254 where accepted; run malware scan status only;
toggle and restore one per-domain control only after capturing original state
Diagnostics: run read operations and set/restore one analyzer or log preference
```

Each case snapshots original state, binds it to confirmation, restores it in cleanup, and reports a
cleanup failure if restoration cannot be verified.

- [ ] **Step 3: Run the full gated live suite**

```bash
CPANEL_ADMIN_RUN_LIVE_TESTS=1 \
CPANEL_ADMIN_LIVE_DISPOSABLE=I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE \
CPANEL_ADMIN_LIVE_PROFILE=test-123reg \
CPANEL_ADMIN_LIVE_DESTRUCTIVE=I_APPROVE_DESTRUCTIVE_LIVE_TESTS \
.venv/bin/python -m pytest tests/live -m live -v
```

Expected: every available pack has evidence; unsupported server features are explicit; cleanup has no
unreported leftovers.

- [ ] **Step 4: Inspect the redacted report**

Run a secret-pattern scan against the report and compare the report capability names with the policy
capability set. Expected: no secret patterns and no missing available pack.

- [ ] **Step 5: Commit**

```bash
git add tests/live/test_email_access_lifecycles.py tests/live/test_runtime_security.py tests/live/report.py references/live-testing.md
git commit -m "test: verify remaining packs on disposable cPanel"
```

### Task 8: Final requirement-to-evidence audit and release gate

**Files:**
- Create: `docs/release/production-readiness.md`
- Modify only files needed to close verified gaps.

**Interfaces:**
- Consumes: approved design, all plan tasks, current worktree, test output, generated metadata, live report.
- Produces: direct evidence for every release requirement.

- [ ] **Step 1: Create the audit matrix**

Use one row per approved requirement:

```markdown
| Requirement | Authoritative artifact | Verification command/evidence | Result |
|---|---|---|---|
| Pinned OpenAPI and checksum | specifications/*.json | scripts/check_generated.py | PASS |
| Explicit 393-operation policy | policy/operations.json | tests/test_policy.py | PASS |
| No arbitrary passthrough | CLI/policy | negative tests | PASS |
| Risk and confirmation binding | planner/confirmation | focused tests | PASS |
| Secret non-disclosure | redaction/audit/transport | test_secret_leaks.py | PASS |
| Fernet profiles and key separation | profiles/secrets | profile and rotation tests | PASS |
| Broad capability packs | policy/support matrix | operation contracts | PASS |
| Documentation and skill | SKILL/README/references | docs tests and validator | PASS |
| Disposable live verification | live report | tests/live | PASS or evidence-backed unavailable |
```

Add rows for every explicit design release gate; do not combine unrelated requirements.

- [ ] **Step 2: Run the complete offline gate from a clean tree**

```bash
.venv/bin/python scripts/check_generated.py
.venv/bin/python -m pytest --cov=cpanel_admin --cov-report=term-missing --cov-fail-under=90
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/agentskills validate "$PWD"
.venv/bin/agentskills read-properties "$PWD"
.venv/bin/python -m pip check
git diff --check
git status --short
```

Expected: every command exits 0, coverage is at least 90%, and only the readiness document is
uncommitted before its commit.

- [ ] **Step 3: Re-run or inspect current live evidence**

Confirm the report catalog SHA matches the committed catalog, every available pack appears, all
cleanup statuses are successful or every leftover is explicitly named, and no secret/host/user data
is present. Re-run affected live cases if code changed after the report.

- [ ] **Step 4: Fill the matrix from direct evidence**

Use `PASS`, `FAIL`, or `UNAVAILABLE` only. `UNAVAILABLE` requires the server feature evidence and a
passing mocked contract. Any `FAIL`, missing row, stale report, indirect assertion, or unreported
leftover means the release is incomplete.

- [ ] **Step 5: Commit the audit**

```bash
git add docs/release/production-readiness.md
git commit -m "docs: record cPanel production readiness evidence"
```

- [ ] **Step 6: Re-run final clean-tree verification**

Repeat Step 2 and verify `git status --short` is empty.

Expected: all gates pass and the tree is clean. Only then may the active goal be marked complete.
