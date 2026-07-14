# cPanel Production Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a reproducible OpenAPI catalog, fail-closed policy registry, protected-input model, generic execution pipeline, confirmation planner, audit trail, capability discovery, and backward-compatible CLI foundation.

**Architecture:** Pin the official OpenAPI input and compile it with an explicit JSON policy manifest into packaged runtime metadata. Refactor the existing hard-coded registry and monolithic CLI behind typed catalog, policy, input, planning, execution, audit, and capability interfaces while preserving existing commands and tests.

**Tech Stack:** Python 3.11+, standard library dataclasses/enums/json/hashlib/argparse/urllib, `cryptography`, pytest, pytest-cov, Ruff.

## Global Constraints

- Target individual cPanel accounts only and reject WHM or port `2087`.
- Use the official cPanel UAPI OpenAPI 3.0.2 document, version `11.136.0.25`.
- Pin source SHA-256 `3d9ec80cd8d774312c4bb6b0dfdbc17e6e6ffc92a8f0c2cd88f01e32864fa2c6`.
- Keep verified HTTPS on port `2083`; reject cross-origin redirects.
- Add no runtime dependency beyond `cryptography>=42,<46`.
- Never add arbitrary module/function passthrough.
- Never put secrets in arguments, plans, logs, exceptions, or generated documentation.
- Preserve Fernet-encrypted profile tokens, atomic profile writes, key rotation, and the separate
  environment-or-`0600`-file master-key lookup.
- Require explicit policy for every operation in the selected 48-module candidate set.
- Keep all existing MVP commands backward compatible.
- Keep default tests offline and coverage at or above 90%.

---

## File Structure

Create or modify these focused units:

```text
specifications/cpanel.openapi.json             pinned upstream source
specifications/cpanel.openapi.lock.json        source and generator lock
policy/operations.json                         reviewed operation decisions
scripts/generate_catalog.py                    deterministic generation entry point
scripts/check_generated.py                     stale-output check entry point
src/cpanel_admin/catalog.py                    generated-catalog types and loader
src/cpanel_admin/policy.py                     policy types and completeness checks
src/cpanel_admin/inputs.py                     argument/stdin/protected-file resolution
src/cpanel_admin/planner.py                    preflight, dry-run, confirmation, verification
src/cpanel_admin/executor.py                   one-operation execution pipeline
src/cpanel_admin/audit.py                      protected redacted JSONL audit writer
src/cpanel_admin/capabilities.py               local and account feature discovery
src/cpanel_admin/data/operation_catalog.json   generated packaged catalog
src/cpanel_admin/data/__init__.py               package-data marker
tests/fixtures/openapi-minimal.json             focused generator fixture
tests/test_catalog_generation.py               generator and lock tests
tests/test_policy.py                            policy completeness and lookup tests
tests/test_inputs.py                            protected input and fingerprint tests
tests/test_planner.py                           dry-run/preflight/verification tests
tests/test_executor.py                          execution-pipeline tests
tests/test_audit.py                             audit safety and permissions tests
tests/test_capabilities.py                      feature-discovery tests
```

`src/cpanel_admin/operations.py` becomes a compatibility facade. `src/cpanel_admin/cli.py` retains
profile commands but delegates cPanel operations to the new pipeline.

### Task 1: Pin and lock the official OpenAPI source

**Files:**
- Create: `specifications/cpanel.openapi.json`
- Create: `specifications/cpanel.openapi.lock.json`
- Create: `tests/test_catalog_generation.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: official URL supplied in the approved design.
- Produces: immutable input and lock metadata used by `scripts/generate_catalog.py`.

- [ ] **Step 1: Write the failing lock-integrity test**

```python
def test_pinned_openapi_matches_lock() -> None:
    root = Path(__file__).parents[1]
    source = root / "specifications" / "cpanel.openapi.json"
    lock = json.loads((root / "specifications" / "cpanel.openapi.lock.json").read_text())
    assert hashlib.sha256(source.read_bytes()).hexdigest() == lock["sha256"]
    document = json.loads(source.read_text())
    assert document["openapi"] == "3.0.2"
    assert document["info"]["version"] == "11.136.0.25"
    assert len(document["paths"]) == 605
```

- [ ] **Step 2: Run the test and verify the missing-artifact failure**

Run: `.venv/bin/python -m pytest tests/test_catalog_generation.py::test_pinned_openapi_matches_lock -v`

Expected: FAIL because `specifications/cpanel.openapi.json` does not exist.

- [ ] **Step 3: Copy the verified source and add exact lock metadata**

Copy the already verified download to `specifications/cpanel.openapi.json`. Create:

```json
{
  "generator_schema": 1,
  "openapi": "3.0.2",
  "retrieved_at": "2026-07-13T22:00:20Z",
  "sha256": "3d9ec80cd8d774312c4bb6b0dfdbc17e6e6ffc92a8f0c2cd88f01e32864fa2c6",
  "source_url": "https://api.docs.cpanel.net/_bundle/specifications/cpanel.openapi.json?download",
  "uapi_version": "11.136.0.25"
}
```

Add only transient download names such as `*.openapi.download` to `.gitignore`; do not ignore the
pinned specification.

- [ ] **Step 4: Run the focused test**

Run: `.venv/bin/python -m pytest tests/test_catalog_generation.py::test_pinned_openapi_matches_lock -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .gitignore specifications tests/test_catalog_generation.py
git commit -m "build: pin cPanel UAPI OpenAPI source"
```

### Task 2: Normalize OpenAPI into deterministic catalog metadata

**Files:**
- Create: `src/cpanel_admin/catalog.py`
- Create: `scripts/generate_catalog.py`
- Create: `tests/fixtures/openapi-minimal.json`
- Modify: `specifications/cpanel.openapi.lock.json`
- Modify: `tests/test_catalog_generation.py`

**Interfaces:**
- Consumes: pinned OpenAPI and lock JSON.
- Produces: `CatalogOperation`, `CatalogParameter`, `normalize_document()`, and deterministic JSON.

- [ ] **Step 1: Add failing normalization tests**

```python
def test_normalize_document_uses_module_function_identity() -> None:
    document = json.loads(FIXTURE.read_text())
    catalog = normalize_document(document, source_sha256="abc")
    operation = catalog.operations["Email/add_pop"]
    assert operation.module == "Email"
    assert operation.function == "add_pop"
    assert operation.method == "GET"
    assert operation.parameters["email"].required is True
    assert operation.parameters["quota"].schema_type == "integer"


def test_catalog_json_is_deterministic() -> None:
    catalog = normalize_document(json.loads(FIXTURE.read_text()), source_sha256="abc")
    assert catalog.to_json() == catalog.to_json()
    assert catalog.to_json().endswith("\n")


def test_duplicate_canonical_identity_is_rejected() -> None:
    document = json.loads(FIXTURE.read_text())
    document["paths"]["/Email/add_pop/"] = copy.deepcopy(document["paths"]["/Email/add_pop"])
    with pytest.raises(CatalogError, match="duplicate canonical operation"):
        normalize_document(document, source_sha256="abc")


def test_only_lock_approved_noncanonical_paths_are_excluded() -> None:
    document = json.loads(FIXTURE.read_text())
    document["paths"]["/get_recommendations"] = {"get": {"operationId": "get_recommendations"}}
    catalog = normalize_document(
        document,
        source_sha256="abc",
        excluded_noncanonical_paths=frozenset({"/get_recommendations"}),
    )
    assert catalog.excluded_paths == (
        CatalogExcludedPath(
            path="/get_recommendations",
            reason="path has no canonical Module/function identity",
        ),
    )


def test_unapproved_noncanonical_path_fails_closed() -> None:
    document = json.loads(FIXTURE.read_text())
    document["paths"]["/new_unknown_path"] = {"get": {"operationId": "new_unknown_path"}}
    with pytest.raises(CatalogError, match="missing Module/function path segments"):
        normalize_document(document, source_sha256="abc")
```

The fixture must contain one GET operation, one POST multipart request body, enums, arrays, defaults,
required query parameters, and two repeated `operationId` values to prove `operationId` is not used
as identity.

- [ ] **Step 2: Run the tests and verify import failure**

Run: `.venv/bin/python -m pytest tests/test_catalog_generation.py -v`

Expected: FAIL because `cpanel_admin.catalog` does not exist.

- [ ] **Step 3: Implement catalog types and normalizer**

Define these exact public shapes:

```python
@dataclass(frozen=True)
class CatalogParameter:
    name: str
    location: str
    required: bool
    schema_type: str
    enum: tuple[JsonScalar, ...] = ()
    default: JsonValue = None


@dataclass(frozen=True)
class CatalogOperation:
    identity: str
    module: str
    function: str
    method: str
    summary: str
    deprecated: bool
    parameters: dict[str, CatalogParameter]
    request_media_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class CatalogExcludedPath:
    path: str
    reason: str


@dataclass(frozen=True)
class Catalog:
    schema_version: int
    source_version: str
    source_sha256: str
    operations: dict[str, CatalogOperation]
    excluded_paths: tuple[CatalogExcludedPath, ...]
```

Implement `Catalog.get(identity: str) -> CatalogOperation`, `Catalog.to_json() -> str`,
`Catalog.from_dict(value: Mapping[str, object]) -> Catalog`, `Catalog.load(path: Path | None = None)
-> Catalog`, and `normalize_document(document: Mapping[str, object], source_sha256: str, *,
excluded_noncanonical_paths: frozenset[str] = frozenset()) -> Catalog`.
`get` raises `CatalogError(f"unknown catalog operation: {identity}")`; `to_json` uses sorted keys and
compact separators plus one final newline; `load` reads the packaged resource when `path` is absent.

Read `excluded_noncanonical_paths` from the lock file. It must contain exactly
`/get_php_recommendations` and `/get_recommendations` for the pinned source. Record each as
`CatalogExcludedPath` with reason `path has no canonical Module/function identity`. Raise
`CatalogError` for any unapproved missing module/function path, malformed document, unsupported
parameter location, unsupported schema, or duplicate `Module/function` identity. Sort all operation
keys, exclusions, parameter keys, enums, and media types before serialization.

- [ ] **Step 4: Run generator tests**

Run: `.venv/bin/python -m pytest tests/test_catalog_generation.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add specifications/cpanel.openapi.lock.json scripts/generate_catalog.py src/cpanel_admin/catalog.py tests/fixtures/openapi-minimal.json tests/test_catalog_generation.py
git commit -m "feat: normalize pinned cPanel OpenAPI catalog"
```

### Task 3: Add explicit fail-closed policy schema and coverage validation

**Files:**
- Create: `src/cpanel_admin/policy.py`
- Create: `policy/operations.json`
- Create: `tests/test_policy.py`
- Modify: `scripts/generate_catalog.py`

**Interfaces:**
- Consumes: `Catalog` and policy JSON.
- Produces: `PolicyRegistry`, `PolicyOperation`, `PolicyParameter`, and completeness report.

- [ ] **Step 1: Write failing policy-schema tests**

```python
def test_selected_modules_have_explicit_policy() -> None:
    catalog = normalize_document(json.loads(PINNED_SPEC.read_text()), EXPECTED_SHA256)
    registry = PolicyRegistry.load(catalog, POLICY_PATH)
    report = registry.coverage()
    assert report.selected_modules == 48
    assert report.candidate_operations == 393
    assert report.missing == ()
    assert report.pending_review == ()


def test_unknown_or_unclassified_operation_fails_closed() -> None:
    policy = minimal_policy(status="included", risk=None)
    with pytest.raises(PolicyError, match="risk"):
        PolicyRegistry.from_dict(minimal_catalog(), policy)


def test_no_command_accepts_module_or_function_parameters() -> None:
    catalog = normalize_document(json.loads(PINNED_SPEC.read_text()), EXPECTED_SHA256)
    registry = PolicyRegistry.load(catalog, POLICY_PATH)
    for operation in registry.included():
        assert "module" not in operation.parameters
        assert "function" not in operation.parameters
```

- [ ] **Step 2: Run tests and verify missing-policy failure**

Run: `.venv/bin/python -m pytest tests/test_policy.py -v`

Expected: FAIL because the policy model and manifest do not exist.

- [ ] **Step 3: Implement the policy model**

Use these exact enums and public types:

```python
class SupportStatus(StrEnum):
    INCLUDED = "included"
    EXCLUDED = "excluded"


class Risk(StrEnum):
    READ = "read"
    MUTATE = "mutate"
    DESTRUCTIVE = "destructive"


class InputSource(StrEnum):
    ARGUMENT = "argument"
    STDIN = "stdin"
    PROTECTED_FILE = "protected_file"
    LOCAL_FILE = "local_file"
    ENVIRONMENT = "environment"
    ENCRYPTED_PROFILE = "encrypted_profile"


@dataclass(frozen=True)
class PolicyParameter:
    name: str
    uapi_name: str
    sources: tuple[InputSource, ...]
    validator: str
    required: bool
    secret: bool = False
    sensitive_output: bool = False


@dataclass(frozen=True)
class PolicyOperation:
    name: str
    identity: str
    command: tuple[str, ...]
    capability: str
    status: SupportStatus
    reason: str
    risk: Risk | None
    elevated_impact: bool
    parameters: dict[str, PolicyParameter]
    impact: str
    recovery: str
    preflight: str | None
    verification: str | None
    feature: str | None
    audit_fields: tuple[str, ...]

    @property
    def requires_confirmation(self) -> bool:
        return self.risk is Risk.DESTRUCTIVE or self.elevated_impact
```

`PolicyRegistry` validates unique names and command paths, catalog identity existence, no deprecated
inclusions, required reasons, risk for inclusions, parameter agreement, secret-source restrictions,
impact/recovery for mutations, and explicit records for every operation in the selected modules.
It exposes `all()`, `included()`, `excluded()`, `get(name)`, `by_command(path)`,
`included_identities(capability)`, `exclusion(identity)`, and `coverage()` with deterministic return
values as declared in the umbrella plan.

- [ ] **Step 4: Seed all 393 candidate records and classify foundation operations**

The selected modules are exactly:

```text
AccountEnhancements Backup Bandwidth BlockIP Chkservd ClamScanner ContactInformation DCV DNS DNSSEC
DirectoryIndexes DirectoryPrivacy DirectoryProtection Domain DomainInfo DynamicDNS Email EmailAuth
Features Fileman Ftp KnownHosts LangPHP LastLogin LogManager Mailboxes Mime ModSecurity Mysql
NginxCaching PassengerApps Quota ResourceUsage Restore SSH SSL ServerInformation SpamAssassin Stats
StatsBar StatsManager SubDomain UserTasks Variables VersionControl VersionControlDeployment WebVhosts
cPGreyList
```

Create one explicit record per operation. Existing MVP operations are included with their current
stable names and command paths. Every other record initially has a concrete pack-specific exclusion
reason such as `"not enabled until the email capability review"`; the final release gate rejects
that phrase, and later plans replace every temporary classification with a permanent include or
exclude decision.

- [ ] **Step 5: Run policy tests**

Run: `.venv/bin/python -m pytest tests/test_policy.py -v`

Expected: PASS with 48 selected modules, 393 candidates, and zero structurally missing records.

- [ ] **Step 6: Commit**

```bash
git add policy/operations.json scripts/generate_catalog.py src/cpanel_admin/policy.py tests/test_policy.py
git commit -m "feat: add fail-closed cPanel operation policy"
```

### Task 4: Generate and package merged runtime metadata

**Files:**
- Create: `src/cpanel_admin/data/__init__.py`
- Create: `src/cpanel_admin/data/operation_catalog.json`
- Create: `scripts/check_generated.py`
- Modify: `scripts/generate_catalog.py`
- Modify: `pyproject.toml`
- Modify: `tests/test_catalog_generation.py`

**Interfaces:**
- Consumes: pinned spec, lock, and reviewed policy.
- Produces: packaged merged catalog loaded through `Catalog.load()` and check-mode command.

- [ ] **Step 1: Add failing generated-output tests**

```python
def test_committed_catalog_matches_generator() -> None:
    generated = generate(ROOT / "specifications/cpanel.openapi.json", ROOT / "policy/operations.json")
    committed = (ROOT / "src/cpanel_admin/data/operation_catalog.json").read_text()
    assert generated == committed


def test_catalog_is_available_from_installed_package() -> None:
    catalog = Catalog.load()
    assert catalog.source_sha256 == EXPECTED_SHA256
    assert catalog.get("DomainInfo/list_domains").function == "list_domains"
```

- [ ] **Step 2: Run tests and verify missing generated file**

Run: `.venv/bin/python -m pytest tests/test_catalog_generation.py -v`

Expected: FAIL because packaged output does not exist.

- [ ] **Step 3: Implement generation and package data**

`scripts/generate_catalog.py` supports:

```text
--source specifications/cpanel.openapi.json
--lock specifications/cpanel.openapi.lock.json
--policy policy/operations.json
--output src/cpanel_admin/data/operation_catalog.json
--support-output references/operation-support.md
--check
```

`--check` writes nothing and exits nonzero on checksum mismatch, policy error, or stale output.
Configure setuptools package data for `cpanel_admin.data/*.json`.

- [ ] **Step 4: Generate and test**

Run: `.venv/bin/python scripts/generate_catalog.py`

Expected: generated runtime catalog and deterministic support matrix.

Run: `.venv/bin/python scripts/check_generated.py`

Expected: exit 0 with `generated catalog is current`.

Run: `.venv/bin/python -m pytest tests/test_catalog_generation.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml scripts src/cpanel_admin/data references/operation-support.md tests/test_catalog_generation.py
git commit -m "build: package generated cPanel operation catalog"
```

### Task 5: Resolve arguments and protected inputs safely

**Files:**
- Create: `src/cpanel_admin/inputs.py`
- Create: `tests/test_inputs.py`
- Modify: `src/cpanel_admin/operations.py`

**Interfaces:**
- Consumes: `PolicyOperation`, argparse namespace, stdin, environment.
- Produces: normalized values, redacted safe values, uploads, and runtime secret tuple.

- [ ] **Step 1: Write failing protected-input tests**

```python
def test_secret_parameter_reads_stdin_and_fingerprints_plan() -> None:
    resolved = InputResolver().resolve(password_operation(), namespace(), io.StringIO("s3cret\n"), {})
    assert resolved.values["password"] == "s3cret"
    assert resolved.safe_values["password"] == {
        "bytes": 6,
        "sha256": hashlib.sha256(b"s3cret").hexdigest(),
    }
    assert resolved.secrets == ("s3cret",)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o400])
def test_protected_file_requires_mode_0600(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "private.pem"
    path.write_text("secret")
    path.chmod(mode)
    with pytest.raises(UsageError, match="permissions must be 0600"):
        read_protected_file(path, maximum=1024 * 1024)


```

Add separate concrete cases that create a symlink and monkeypatch `os.getuid()` for wrong ownership,
assert a local-file safe value equals `{"name": "site.zip", "bytes": 3,
"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}`, and
assert validator name `"unknown"` raises `PolicyError("unknown validator: unknown")`.

- [ ] **Step 2: Run tests and verify import failure**

Run: `.venv/bin/python -m pytest tests/test_inputs.py -v`

Expected: FAIL because `cpanel_admin.inputs` does not exist.

- [ ] **Step 3: Implement the resolver**

```python
@dataclass(frozen=True)
class ResolvedInputs:
    values: dict[str, object]
    safe_values: dict[str, JsonValue]
    uploads: dict[str, Upload]
    secrets: tuple[str, ...]


class InputResolver:
    """Resolve one fixed policy operation from approved input sources."""
```

Implement `InputResolver.resolve(operation: PolicyOperation, namespace: argparse.Namespace,
stdin: TextIO, env: Mapping[str, str]) -> ResolvedInputs`, `read_protected_file(path: Path,
maximum: int) -> bytes`, and `fingerprint(content: bytes) -> dict[str, JsonValue]`. The resolver
iterates policy parameters in sorted order, consumes stdin at most once, validates before creating
safe values, and accumulates exact runtime secrets for redaction.

Move reusable domain, path, filename, database, privilege, integer, boolean, enum, email, IP/CIDR,
URL, PEM, cron-expression, and bounded-text validators into a registry in `operations.py`. The cron
validator exists only to produce a clear unsupported-capability response; no cron UAPI operation is
added. Environment-backed secrets accept only an argument containing an environment variable name
matching `^[A-Z][A-Z0-9_]{0,127}$`; the value is read from the supplied environment and fingerprinted
like stdin. `ENCRYPTED_PROFILE` is limited to policy-declared existing encrypted fields and never
allows a caller-provided JSON path.

- [ ] **Step 4: Run focused and legacy tests**

Run: `.venv/bin/python -m pytest tests/test_inputs.py tests/test_operations.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cpanel_admin/inputs.py src/cpanel_admin/operations.py tests/test_inputs.py tests/test_operations.py
git commit -m "feat: resolve protected cPanel operation inputs"
```

### Task 6: Generalize planning, preflight, confirmation, and verification

**Files:**
- Create: `src/cpanel_admin/planner.py`
- Create: `tests/test_planner.py`
- Modify: `src/cpanel_admin/confirmation.py`
- Modify: `tests/test_confirmation.py`

**Interfaces:**
- Consumes: execution context, `PolicyOperation`, `ResolvedInputs`, adapter registry.
- Produces: confirmation-bound `ExecutionPlan` and `VerificationResult`.

- [ ] **Step 1: Write failing planner tests**

```python
def test_elevated_mutation_requires_confirmation() -> None:
    plan = planner.dry_run(context, elevated_mutation(), inputs)
    assert plan.requires_confirmation is True
    assert plan.confirmation is not None


def test_confirmation_binds_identity_file_hash_and_preflight() -> None:
    plan = planner.dry_run(context, file_overwrite(), inputs)
    changed = replace(plan.bound_parameters, preflight={"etag": "changed"})
    with pytest.raises(ConfirmationError, match="does not match"):
        planner.verify_confirmation(plan.confirmation, changed)


def test_mutation_verification_detects_contradictory_state() -> None:
    result = planner.verify(context, operation, inputs, mutation_response())
    assert result.ok is False
    assert result.category == "verification"
```

- [ ] **Step 2: Run tests and verify missing planner**

Run: `.venv/bin/python -m pytest tests/test_planner.py -v`

Expected: FAIL because `cpanel_admin.planner` does not exist.

- [ ] **Step 3: Implement plan and verification types**

```python
@dataclass(frozen=True)
class ExecutionPlan:
    profile: str
    account: str
    operation: str
    identity: str
    risk: Risk
    elevated_impact: bool
    parameters: dict[str, JsonValue]
    preflight: JsonValue
    impact: str
    recovery: str
    verification_available: bool
    requires_confirmation: bool
    expires_at: str | None
    confirmation: str | None


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    category: str
    evidence: JsonValue


class OperationPlanner:
    """Plan, confirm, and verify fixed policy operations."""
```

Implement `dry_run(context, operation, inputs) -> ExecutionPlan`,
`verify_confirmation(context, operation, plan_values, digest, expires_at) -> None`, and
`verify(context, operation, inputs, response) -> VerificationResult`. Resolve adapters by the exact
policy adapter name; missing adapters fail with `PolicyError` before transport.

Define the adapter contract used by later plans:

```text
OperationAdapter.preflight(context, operation, inputs) -> JsonValue
OperationAdapter.to_uapi(operation, inputs, preflight) -> dict[str, object]
OperationAdapter.verify(context, operation, inputs, response) -> VerificationResult
```

The default adapter performs catalog name mapping, has no preflight, and returns verification
category `not_available` only when policy explicitly declares no verification operation.

Upgrade confirmation payload schema to version 2 and bind profile, account username, identity,
stable operation name, normalized safe values, preflight, file/secret fingerprints, policy version,
and expiry. Preserve verification of existing version-1 profile-removal plans only where tests prove
the compatibility requirement.

- [ ] **Step 4: Run planner and confirmation tests**

Run: `.venv/bin/python -m pytest tests/test_planner.py tests/test_confirmation.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cpanel_admin/planner.py src/cpanel_admin/confirmation.py tests/test_planner.py tests/test_confirmation.py
git commit -m "feat: generalize cPanel operation planning"
```

### Task 7: Add redacted fail-closed audit events and error categories

**Files:**
- Create: `src/cpanel_admin/audit.py`
- Create: `tests/test_audit.py`
- Modify: `src/cpanel_admin/errors.py`
- Modify: `tests/test_errors.py`

**Interfaces:**
- Consumes: policy-approved event fields and profile configuration directory.
- Produces: protected JSONL events; exit codes 8 and 9 for partial and verification failures.

- [ ] **Step 1: Write failing audit tests**

```python
def test_audit_file_is_created_with_mode_0600(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    writer.write(event(), fail_closed=True)
    assert stat.S_IMODE((tmp_path / "audit.jsonl").stat().st_mode) == 0o600


def test_audit_event_contains_only_allowlisted_redacted_fields(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    writer.write(event(target="user@example.test", secret="do-not-write"), fail_closed=True)
    content = (tmp_path / "audit.jsonl").read_text()
    assert "do-not-write" not in content
    assert json.loads(content)["operation"] == "email.accounts.create"


```

Add a concrete confirmed-operation case using an unwritable audit path and assert `AuditError` is
raised before the fake transport records a call. Add a read-operation case with the same writer and
assert the read result carries warning category `audit` after the transport succeeds.

- [ ] **Step 2: Run tests and verify import failure**

Run: `.venv/bin/python -m pytest tests/test_audit.py tests/test_errors.py -v`

Expected: FAIL because the audit writer and new errors do not exist.

- [ ] **Step 3: Implement exact event and errors**

```python
@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    profile: str
    operation: str
    identity: str
    risk: str
    confirmed: bool
    target: JsonValue
    outcome: str
    error_category: str | None
    verification: str | None


class PartialFailure(CPanelAdminError):
    exit_code = 8


class VerificationError(CPanelAdminError):
    exit_code = 9


class AuditError(CPanelAdminError):
    exit_code = 3
```

Use `os.open` with `O_CREAT | O_APPEND | O_WRONLY | O_NOFOLLOW` and mode `0o600` where supported, verify owner
and mode before every append, serialize one compact JSON object per line, flush and `fsync`, and
never serialize arbitrary request or response mappings. Audit intent failure blocks every mutation;
read operations may complete only with an explicit audit warning.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_audit.py tests/test_errors.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cpanel_admin/audit.py src/cpanel_admin/errors.py tests/test_audit.py tests/test_errors.py
git commit -m "feat: add protected cPanel audit trail"
```

### Task 8: Harden schema-driven transport for forms, arrays, and multipart bodies

**Files:**
- Modify: `src/cpanel_admin/transport.py`
- Modify: `tests/test_transport.py`

**Interfaces:**
- Consumes: catalog method/body metadata and resolved uploads.
- Produces: `UAPITransport.call()` with safe query, form, and multipart encoding.

- [ ] **Step 1: Add failing transport tests**

```python
def test_secret_bearing_get_is_promoted_to_post_form(profile: Profile) -> None:
    transport.call(profile, "token", "Email", "add_pop", {"password": "secret"}, sensitive=True)
    request = opener.requests[0][0]
    assert request.method == "POST"
    assert "secret" not in request.full_url
    assert b"password=secret" in request.data


def test_sequence_values_use_repeated_form_keys(profile: Profile) -> None:
    transport.call(profile, "token", "DNS", "mass_edit_zone", {"add": ["one", "two"]}, method="POST")
    assert b"add=one&add=two" in opener.requests[0][0].data


```

Add a response fixture containing one successful and one failed result item and assert
`PartialFailure` includes only item indexes and safe messages. Add a policy-sensitive name
`dkim_private_key` whose value appears in a fake UAPI error and assert the value is absent from the
raised exception.

- [ ] **Step 2: Run tests and verify failures**

Run: `.venv/bin/python -m pytest tests/test_transport.py -v`

Expected: FAIL for sensitive promotion and partial-result handling.

- [ ] **Step 3: Extend transport without changing TLS defaults**

Change the call signature to:

```python
def call(
    self,
    profile: Profile,
    token: str,
    module: str,
    function: str,
    parameters: Mapping[str, object],
    timeout: int = 30,
    *,
    method: str = "GET",
    files: Mapping[str, Upload] | None = None,
    sensitive_names: Collection[str] = (),
) -> UAPIResponse:
    """Send one validated UAPI request and return its normalized result."""
```

If `sensitive_names` intersects submitted parameters, use a POST form even when the OpenAPI catalog
lists GET. Keep multipart for uploads, repeated keys for sequences, the 10 MiB response limit,
same-origin redirects, verified SSL context, and recursive error redaction.

- [ ] **Step 4: Run transport tests**

Run: `.venv/bin/python -m pytest tests/test_transport.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cpanel_admin/transport.py tests/test_transport.py
git commit -m "feat: harden schema-driven UAPI transport"
```

### Task 9: Add account capability discovery

**Files:**
- Create: `src/cpanel_admin/capabilities.py`
- Create: `tests/test_capabilities.py`
- Modify: `src/cpanel_admin/errors.py`

**Interfaces:**
- Consumes: `Features/list_features`, policy feature names, profile execution context.
- Produces: structured availability status without widening policy.

- [ ] **Step 1: Write failing discovery tests**

```python
def test_capability_report_distinguishes_policy_and_server_availability() -> None:
    report = service.inspect(context)
    assert report.operations["email.accounts.list"].status == "available"
    assert report.operations["cron.jobs.list"].status == "excluded"
    assert report.operations["passenger.apps.list"].status == "server_unavailable"


def test_discovery_failure_is_unknown_not_available() -> None:
    report = service.inspect(failing_context)
    assert report.operations["email.accounts.list"].status == "unknown"
```

- [ ] **Step 2: Run tests and verify import failure**

Run: `.venv/bin/python -m pytest tests/test_capabilities.py -v`

Expected: FAIL because `cpanel_admin.capabilities` does not exist.

- [ ] **Step 3: Implement capability types and service**

```python
class Availability(StrEnum):
    AVAILABLE = "available"
    SERVER_UNAVAILABLE = "server_unavailable"
    POLICY_EXCLUDED = "excluded"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CapabilityReport:
    profile: str
    observed_at: str
    operations: dict[str, OperationAvailability]


class CapabilityService:
    """Inspect and enforce account feature prerequisites."""
```

Add `OperationAvailability` with fields `operation: str`, `status: Availability`, `feature: str |
None`, and `reason: str | None`.

Implement `inspect(context: ExecutionContext) -> CapabilityReport` and
`require(context: ExecutionContext, operation: PolicyOperation) -> None`. `require` raises
`CapabilityError` for policy exclusion or observed absence and a distinct safe error for unknown
discovery state.

Cache successful feature lists in memory for at most 60 seconds. Never treat discovery failure as
permission. `require()` checks local policy first, then the operation feature prerequisite.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_capabilities.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cpanel_admin/capabilities.py src/cpanel_admin/errors.py tests/test_capabilities.py
git commit -m "feat: discover cPanel account capabilities"
```

### Task 10: Refactor the executor and dynamic task-oriented CLI

**Files:**
- Create: `src/cpanel_admin/executor.py`
- Create: `tests/test_executor.py`
- Modify: `src/cpanel_admin/cli.py`
- Modify: `src/cpanel_admin/operations.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_operations.py`

**Interfaces:**
- Consumes: catalog, policy registry, profiles, inputs, planner, capabilities, audit, transport.
- Produces: one secure execution pipeline and backward-compatible task commands.

- [ ] **Step 1: Write failing executor tests**

```python
def test_read_execution_checks_policy_calls_transport_and_audits() -> None:
    result = executor.execute(context, operation, inputs, confirmation=None)
    assert result.ok is True
    assert transport.calls[0].identity == "DomainInfo/list_domains"
    assert audit.events[0].outcome == "success"


def test_mutation_dry_run_never_calls_mutating_transport() -> None:
    plan = executor.dry_run(context, mutation, inputs)
    assert plan.operation == mutation.name
    assert transport.mutation_calls == []


def test_no_raw_module_function_parser_exists() -> None:
    parser = build_parser(registry)
    with pytest.raises(SystemExit):
        parser.parse_args(["call", "Email", "list_pops"])
```

- [ ] **Step 2: Run tests and verify missing executor**

Run: `.venv/bin/python -m pytest tests/test_executor.py tests/test_cli.py -v`

Expected: FAIL because `cpanel_admin.executor` does not exist.

- [ ] **Step 3: Implement execution context and pipeline**

```python
@dataclass(frozen=True)
class ExecutionContext:
    profile: Profile
    token: str
    timeout: int
    transport: UAPITransport
    audit: AuditWriter


@dataclass(frozen=True)
class ExecutionResult:
    ok: bool
    profile: str
    operation: str
    identity: str
    data: JsonValue
    warnings: tuple[str, ...]
    messages: tuple[str, ...]
    verification: VerificationResult | None


class OperationExecutor:
    """Execute fixed policy operations through the shared safety pipeline."""
```

Implement `dry_run(context, operation, inputs) -> ExecutionPlan` and
`execute(context, operation, inputs, confirmation) -> ExecutionResult` in the exact order described
below.

The executor order is policy, capability prerequisite, preflight, confirmation when required,
audit-intent for every mutation, transport, response validation, verification, audit-result,
redaction.

- [ ] **Step 4: Build nested parsers from included policy command paths**

`build_parser(registry: PolicyRegistry | None = None)` creates nested argparse groups and options
from fixed policy metadata. It adds global `--profile`, `--config`, `--timeout`, `--pretty`, and
`--audit-file`; mutation parsers add `--dry-run`, `--confirm`, and `--expires-at`. Secret parameters
add only their approved `--*-stdin` or `--*-file` selector and never a value-bearing secret option.

Add these discovery commands:

```text
cpanel-admin operations list [--capability NAME] [--status included|excluded]
cpanel-admin --profile NAME capabilities inspect
```

Keep existing `profiles`, `domains`, `files`, `ssl`, and `databases` syntax working.

- [ ] **Step 5: Run focused tests**

Run: `.venv/bin/python -m pytest tests/test_executor.py tests/test_cli.py tests/test_operations.py -v`

Expected: PASS.

- [ ] **Step 6: Run the complete baseline**

Run: `.venv/bin/python -m pytest`

Expected: all offline tests pass, including existing profile/Fernet/key-rotation tests; live tests
skip unless explicitly enabled.

Run: `.venv/bin/ruff check . && .venv/bin/ruff format --check .`

Expected: both exit 0.

- [ ] **Step 7: Commit**

```bash
git add src/cpanel_admin tests
git commit -m "refactor: add policy-driven cPanel execution pipeline"
```

### Task 11: Foundation self-review and green checkpoint

**Files:**
- Modify only files required to fix review findings.

**Interfaces:**
- Consumes: all foundation tasks.
- Produces: stable interfaces for the four remaining plans.

- [ ] **Step 1: Run specification and placeholder checks**

Run:

```bash
rg -n "not enabled until|pending review|arbitrary.*module|port 2087" policy src scripts tests
```

Expected: temporary pack exclusions may remain only in `policy/operations.json`; there are no code
placeholders, passthroughs, or WHM endpoints.

- [ ] **Step 2: Run all foundation gates**

```bash
.venv/bin/python scripts/check_generated.py
.venv/bin/python -m pytest --cov=cpanel_admin --cov-report=term-missing --cov-fail-under=90
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/agentskills validate "$PWD"
```

Expected: all commands exit 0; live tests are skipped by default.

- [ ] **Step 3: Review public interfaces against the umbrella plan**

Confirm exact signatures for `Catalog`, `PolicyRegistry`, `InputResolver`, `OperationPlanner`,
`OperationExecutor`, `CapabilityService`, and `AuditWriter`. Update later plan documents before code
execution if an approved signature changed.

- [ ] **Step 4: Commit review fixes when needed**

Stage each changed foundation path explicitly with `git add`, then commit with
`git commit -m "test: close cPanel foundation review findings"`.

If no files changed, record the successful commands in the execution log and do not create an empty
commit.
