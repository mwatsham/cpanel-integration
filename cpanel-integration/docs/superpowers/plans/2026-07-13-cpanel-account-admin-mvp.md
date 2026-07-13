# cPanel Account Administration MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a tested Agent Skill and task-oriented Python CLI for individual cPanel account administration with encrypted named profiles and operation-bound destructive confirmations.

**Architecture:** The `cpanel-admin` CLI loads a named profile, decrypts its token with a Fernet key supplied through the environment, validates a command against a fixed operation registry, enforces dry-run and confirmation policy, and calls cPanel UAPI over verified HTTPS. `SKILL.md` teaches an agent to use the CLI and its safety gates without exposing secrets or unsupported WHM functionality.

**Tech Stack:** Python 3.11+, standard library, `cryptography`, pytest, pytest-cov, Ruff, Agent Skills standard.

## Global Constraints

- Support individual cPanel accounts only; reject WHM, root, reseller, and server-level work.
- Use documented UAPI at `https://<host>:2083/execute/<Module>/<function>` with TLS verification always enabled.
- Use only the fixed domains, files, SSL, and MySQL operation registry defined by the approved specification.
- Never expose an arbitrary UAPI passthrough or deprecated cPanel API 2 fallback.
- Read the master key from `CPANEL_ADMIN_FERNET_KEY`; never persist it or plaintext API/database secrets.
- Require an exact, unexpired confirmation digest for every destructive operation.
- Default tests must never access a live server.
- Use a disposable profile and `CPANEL_ADMIN_RUN_LIVE_TESTS=1` for opt-in live tests.
- Finish with at least 90% coverage for `src/cpanel_admin`, clean Ruff checks, and Agent Skill validation.

---

### Task 1: Package Scaffold and Error Contract

**Files:**
- Create: `pyproject.toml`
- Create: `src/cpanel_admin/__init__.py`
- Create: `src/cpanel_admin/errors.py`
- Create: `tests/test_errors.py`

**Interfaces:**
- Produces: `CPanelAdminError(message, exit_code)`, plus `UsageError`, `ConfigError`, `ConfirmationError`, `TransportError`, `UAPIError`, and `CapabilityError`.
- Produces: console script `cpanel-admin = cpanel_admin.cli:main`.

- [ ] **Step 1: Write the error-contract test**

```python
from cpanel_admin.errors import CapabilityError, ConfigError


def test_error_subclasses_have_stable_exit_codes() -> None:
    assert ConfigError("bad config").exit_code == 3
    assert CapabilityError("not supported").exit_code == 7
```

- [ ] **Step 2: Run the test and verify the import fails**

Run: `.venv/bin/python -m pytest tests/test_errors.py -v`

Expected: collection fails because `cpanel_admin.errors` does not exist.

- [ ] **Step 3: Add package metadata and typed errors**

Use this package configuration:

```toml
[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[project]
name = "cpanel-account-admin"
version = "0.1.0"
description = "Safe task-oriented cPanel UAPI administration for AI agents"
readme = "README.md"
requires-python = ">=3.11"
dependencies = ["cryptography>=42,<46"]

[project.optional-dependencies]
dev = ["pytest>=8,<9", "pytest-cov>=5,<7", "ruff>=0.9,<1"]

[project.scripts]
cpanel-admin = "cpanel_admin.cli:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
addopts = "--strict-markers --strict-config"
testpaths = ["tests"]
markers = ["live: opt-in tests against a disposable cPanel account"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "SIM", "RUF"]
```

Implement errors with stable exit codes:

```python
class CPanelAdminError(Exception):
    exit_code = 1


class UsageError(CPanelAdminError):
    exit_code = 2


class ConfigError(CPanelAdminError):
    exit_code = 3


class ConfirmationError(CPanelAdminError):
    exit_code = 4


class TransportError(CPanelAdminError):
    exit_code = 5


class UAPIError(CPanelAdminError):
    exit_code = 6


class CapabilityError(CPanelAdminError):
    exit_code = 7
```

- [ ] **Step 4: Create a virtual environment and install approved dependencies**

Run: `python3 -m venv .venv`

Run: `.venv/bin/python -m pip install -e '.[dev]'`

Expected: editable install succeeds and `.venv/bin/cpanel-admin` exists.

- [ ] **Step 5: Run the focused test**

Run: `.venv/bin/python -m pytest tests/test_errors.py -v`

Expected: all tests pass.

- [ ] **Step 6: Commit the scaffold**

```bash
git add pyproject.toml src/cpanel_admin/__init__.py src/cpanel_admin/errors.py tests/test_errors.py
git commit -m "build: scaffold cPanel admin package"
```

### Task 2: Fernet Secrets and Atomic Named Profiles

**Files:**
- Create: `src/cpanel_admin/secrets.py`
- Create: `src/cpanel_admin/profiles.py`
- Create: `tests/test_secrets.py`
- Create: `tests/test_profiles.py`

**Interfaces:**
- Produces: `SecretCodec.from_environment(env)`, `encrypt(plaintext)`, and `decrypt(ciphertext)`.
- Produces: immutable `Profile(name, host, port, username, encrypted_token)`.
- Produces: `ProfileStore(path=None)` with `list()`, `get(name)`, `add(...)`, `remove(name)`, and `rotate(codec, new_codec)`.

- [ ] **Step 1: Write Fernet behavior tests**

```python
from cryptography.fernet import Fernet
import pytest

from cpanel_admin.errors import ConfigError
from cpanel_admin.secrets import SecretCodec


def test_secret_codec_round_trip_without_plaintext_in_ciphertext() -> None:
    codec = SecretCodec(Fernet.generate_key())
    ciphertext = codec.encrypt("api-token-value")
    assert "api-token-value" not in ciphertext
    assert codec.decrypt(ciphertext) == "api-token-value"


def test_missing_master_key_has_safe_error() -> None:
    with pytest.raises(ConfigError, match="CPANEL_ADMIN_FERNET_KEY is required"):
        SecretCodec.from_environment({})
```

- [ ] **Step 2: Write profile store tests**

```python
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.errors import ConfigError
from cpanel_admin.profiles import ProfileStore
from cpanel_admin.secrets import SecretCodec


def test_add_profile_encrypts_token_and_round_trips(tmp_path: Path) -> None:
    codec = SecretCodec(Fernet.generate_key())
    path = tmp_path / "profiles.json"
    store = ProfileStore(path)
    store.add("production", "cpanel.example.com", "account", "secret-token", codec)
    raw = path.read_text()
    assert "secret-token" not in raw
    profile = store.get("production")
    assert codec.decrypt(profile.encrypted_token) == "secret-token"
    assert json.loads(raw)["version"] == 1


def test_add_requires_replace_for_existing_profile(tmp_path: Path) -> None:
    codec = SecretCodec(Fernet.generate_key())
    store = ProfileStore(tmp_path / "profiles.json")
    store.add("production", "cpanel.example.com", "account", "one", codec)
    with pytest.raises(ConfigError, match="already exists"):
        store.add("production", "cpanel.example.com", "account", "two", codec)
```

- [ ] **Step 3: Run tests and verify missing modules fail**

Run: `.venv/bin/python -m pytest tests/test_secrets.py tests/test_profiles.py -v`

Expected: collection fails because the modules do not exist.

- [ ] **Step 4: Implement secret codec**

```python
@dataclass(frozen=True)
class SecretCodec:
    key: bytes

    @classmethod
    def from_environment(cls, env: Mapping[str, str]) -> "SecretCodec":
        value = env.get("CPANEL_ADMIN_FERNET_KEY")
        if not value:
            raise ConfigError("CPANEL_ADMIN_FERNET_KEY is required")
        try:
            Fernet(value.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise ConfigError("CPANEL_ADMIN_FERNET_KEY is not a valid Fernet key") from exc
        return cls(value.encode("ascii"))

    def encrypt(self, plaintext: str) -> str:
        return Fernet(self.key).encrypt(plaintext.encode()).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        try:
            return Fernet(self.key).decrypt(ciphertext.encode("ascii")).decode()
        except (InvalidToken, ValueError, UnicodeError) as exc:
            raise ConfigError("Unable to decrypt profile token with the configured key") from exc
```

- [ ] **Step 5: Implement profile validation and atomic JSON storage**

Implement the exact schema from the specification. Validate profile names, host syntax, port `2083`, usernames, and non-empty tokens. Use `tempfile.NamedTemporaryFile` in the destination directory, `os.fchmod(..., 0o600)`, `flush`, `os.fsync`, and `os.replace`. `show` and `list` return metadata without decrypted data.

Required signatures:

```python
@dataclass(frozen=True)
class Profile:
    name: str
    host: str
    port: int
    username: str
    encrypted_token: str


class ProfileStore:
    def __init__(self, path: Path | None = None) -> None: ...
    def list(self) -> list[Profile]: ...
    def get(self, name: str) -> Profile: ...
    def add(self, name: str, host: str, username: str, token: str,
            codec: SecretCodec, *, replace: bool = False) -> Profile: ...
    def remove(self, name: str) -> Profile: ...
    def rotate(self, codec: SecretCodec, new_codec: SecretCodec) -> int: ...
```

- [ ] **Step 6: Expand edge-case tests**

Add tests for malformed JSON, schema version mismatch, corrupt ciphertext, invalid profile/host/user values, default XDG path, file mode, replacement, removal, and all-or-nothing key rotation.

- [ ] **Step 7: Run focused tests and lint**

Run: `.venv/bin/python -m pytest tests/test_secrets.py tests/test_profiles.py -v`

Run: `.venv/bin/ruff check src/cpanel_admin/secrets.py src/cpanel_admin/profiles.py tests/test_secrets.py tests/test_profiles.py`

Expected: both commands pass.

- [ ] **Step 8: Commit encrypted profiles**

```bash
git add src/cpanel_admin/secrets.py src/cpanel_admin/profiles.py tests/test_secrets.py tests/test_profiles.py
git commit -m "feat: add encrypted named cPanel profiles"
```

### Task 3: Operation-Bound Confirmation Digests

**Files:**
- Create: `src/cpanel_admin/confirmation.py`
- Create: `tests/test_confirmation.py`

**Interfaces:**
- Produces: `ConfirmationPlan` dataclass.
- Produces: `ConfirmationService(key, clock=None)` with `plan(...)` and `verify(...)`.

- [ ] **Step 1: Write digest binding and expiry tests**

```python
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.confirmation import ConfirmationService
from cpanel_admin.errors import ConfirmationError


def test_digest_is_bound_to_normalized_operation() -> None:
    now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    service = ConfirmationService(Fernet.generate_key(), clock=lambda: now)
    plan = service.plan("production", "databases.remove", {"name": "acct_db"},
                        "Delete acct_db", "Restore a backup")
    service.verify(plan.confirmation, "production", "databases.remove",
                   {"name": "acct_db"}, plan.expires_at)
    with pytest.raises(ConfirmationError, match="does not match"):
        service.verify(plan.confirmation, "production", "databases.remove",
                       {"name": "acct_other"}, plan.expires_at)


def test_expired_digest_is_rejected() -> None:
    now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    service = ConfirmationService(Fernet.generate_key(), clock=lambda: now)
    plan = service.plan("production", "ssl.remove", {"domain": "example.com"},
                        "Remove SSL", "Reinstall certificate")
    service.clock = lambda: now + timedelta(minutes=6)
    with pytest.raises(ConfirmationError, match="expired"):
        service.verify(plan.confirmation, "production", "ssl.remove",
                       {"domain": "example.com"}, plan.expires_at)
```

- [ ] **Step 2: Run tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_confirmation.py -v`

Expected: collection fails because `confirmation.py` does not exist.

- [ ] **Step 3: Implement canonical plans and HMAC verification**

```python
@dataclass(frozen=True)
class ConfirmationPlan:
    profile: str
    operation: str
    parameters: dict[str, object]
    impact: str
    recovery: str
    expires_at: str
    confirmation: str


class ConfirmationService:
    def __init__(self, fernet_key: bytes, clock: Callable[[], datetime] | None = None) -> None:
        raw = base64.urlsafe_b64decode(fernet_key)
        self._key = hashlib.sha256(b"cpanel-admin-confirmation-v1\0" + raw).digest()
        self.clock = clock or (lambda: datetime.now(UTC))

    def _payload(self, profile: str, operation: str,
                 parameters: Mapping[str, object], expires_at: str) -> bytes:
        value = {"version": 1, "profile": profile, "operation": operation,
                 "parameters": parameters, "expires_at": expires_at}
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
```

`plan` sets expiry to five minutes, signs the canonical payload, and truncates hex output to 12 characters. `verify` parses the UTC timestamp, checks expiry first, recalculates the digest, and calls `hmac.compare_digest`.

- [ ] **Step 4: Add normalization and invalid timestamp tests**

Cover sorted mappings, booleans, integers, strings, lists, unsupported parameter types, malformed expiry, invalid Fernet key length, and exact five-minute boundary behavior.

- [ ] **Step 5: Run focused tests**

Run: `.venv/bin/python -m pytest tests/test_confirmation.py -v`

Expected: all tests pass.

- [ ] **Step 6: Commit confirmations**

```bash
git add src/cpanel_admin/confirmation.py tests/test_confirmation.py
git commit -m "feat: bind destructive confirmations to operations"
```

### Task 4: Verified UAPI Transport and Redaction

**Files:**
- Create: `src/cpanel_admin/redaction.py`
- Create: `src/cpanel_admin/transport.py`
- Create: `tests/test_redaction.py`
- Create: `tests/test_transport.py`

**Interfaces:**
- Produces: `redact(value, secrets=())` for strings and nested JSON-like objects.
- Produces: `UAPIResponse(data, warnings, messages)`.
- Produces: `UAPITransport.call(profile, token, module, function, parameters, timeout=30)`.

- [ ] **Step 1: Write transport success and failure tests**

Use a fake opener that records `urllib.request.Request` and returns a bounded fake response. Assert:

```python
response = transport.call(profile, "secret-token", "DomainInfo", "list_domains", {})
assert response.data == {"main_domain": "example.com"}
assert request.full_url == "https://cpanel.example.com:2083/execute/DomainInfo/list_domains"
assert request.headers["Authorization"] == "cpanel account:secret-token"
```

Add tests proving non-2xx, invalid JSON, non-object JSON, oversized responses, `status != 1`, TLS errors, timeouts, and cross-origin redirects raise typed safe exceptions without the token.

- [ ] **Step 2: Write nested redaction tests**

```python
def test_redact_removes_known_secrets_and_sensitive_keys() -> None:
    value = {"token": "abc", "nested": ["prefix abc suffix"], "safe": "ok"}
    assert redact(value, secrets=("abc",)) == {
        "token": "[REDACTED]",
        "nested": ["prefix [REDACTED] suffix"],
        "safe": "ok",
    }
```

- [ ] **Step 3: Run tests and verify missing modules fail**

Run: `.venv/bin/python -m pytest tests/test_redaction.py tests/test_transport.py -v`

Expected: collection fails because modules do not exist.

- [ ] **Step 4: Implement recursive redaction**

Redact case-insensitive keys `token`, `api_token`, `password`, `private_key`, `authorization`, and `encrypted_token`. Replace every non-empty known secret substring in string values. Preserve JSON-compatible container shapes.

- [ ] **Step 5: Implement HTTPS transport**

Use `urllib.request.HTTPSHandler(context=ssl.create_default_context())`, a redirect handler that permits only same-origin redirects, and chunked reads capped at `10 * 1024 * 1024` bytes. Build query parameters with `urlencode(..., doseq=True)`. Convert HTTP, URL, timeout, TLS, JSON, and UAPI failures into `TransportError` or `UAPIError` with redacted messages.

Required signature:

```python
@dataclass(frozen=True)
class UAPIResponse:
    data: object
    warnings: list[str]
    messages: list[str]


class UAPITransport:
    def call(self, profile: Profile, token: str, module: str, function: str,
             parameters: Mapping[str, object], timeout: int = 30) -> UAPIResponse: ...
```

- [ ] **Step 6: Run focused tests and lint**

Run: `.venv/bin/python -m pytest tests/test_redaction.py tests/test_transport.py -v`

Run: `.venv/bin/ruff check src/cpanel_admin/redaction.py src/cpanel_admin/transport.py tests/test_redaction.py tests/test_transport.py`

Expected: all commands pass.

- [ ] **Step 7: Commit transport**

```bash
git add src/cpanel_admin/redaction.py src/cpanel_admin/transport.py tests/test_redaction.py tests/test_transport.py
git commit -m "feat: add verified cPanel UAPI transport"
```

### Task 5: Fixed Operation Registry and Policy Execution

**Files:**
- Create: `src/cpanel_admin/operations.py`
- Create: `tests/test_operations.py`

**Interfaces:**
- Produces: `Risk` enum, `Parameter` and `Operation` dataclasses, `OPERATIONS`, `get_operation(name)`, and `validate_parameters(operation, values)`.
- Produces: fixed mappings for every operation in the approved specification.

- [ ] **Step 1: Write registry completeness tests**

```python
EXPECTED = {
    "domains.list", "domains.inspect", "domains.ssl-capable", "domains.add-subdomain",
    "files.list", "files.inspect", "files.read", "files.write", "files.upload",
    "files.empty-trash", "ssl.list", "ssl.hosts", "ssl.install", "ssl.remove",
    "databases.list", "databases.users", "databases.create", "databases.create-user",
    "databases.grant", "databases.remove", "databases.remove-user",
}


def test_registry_is_explicit_and_complete() -> None:
    assert set(OPERATIONS) == EXPECTED
    assert OPERATIONS["databases.remove"].risk is Risk.DESTRUCTIVE
    assert OPERATIONS["domains.list"].module == "DomainInfo"
    assert OPERATIONS["domains.list"].function == "list_domains"
```

Add parameter tests that reject unknown keys, missing required keys, invalid domains, unsafe paths, empty stdin values, invalid database privilege names, out-of-range trash ages, and PEM files above configured limits.

- [ ] **Step 2: Run tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_operations.py -v`

Expected: collection fails because `operations.py` does not exist.

- [ ] **Step 3: Implement operation metadata**

```python
class Risk(StrEnum):
    READ = "read"
    MUTATE = "mutate"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True)
class Operation:
    name: str
    module: str
    function: str
    risk: Risk
    required: frozenset[str]
    optional: frozenset[str] = frozenset()
    impact: str = ""
    recovery: str = ""
```

Create a literal `OPERATIONS` dictionary. No CLI input can override `module` or `function`. Mark file writes, empty-trash, SSL removal, database deletion, and database-user deletion destructive. Mark creates, uploads, grants, and SSL installs mutating. Profile deletion uses the same confirmation service but is handled by the profile command rather than the UAPI registry.

- [ ] **Step 4: Implement parameter normalization**

Return a new dictionary containing only known keys. Normalize domains to lowercase IDNA ASCII, preserve validated relative cPanel paths without `..`, normalize privilege lists against the documented allowed set, and restrict integer bounds. Separate local-only parameters such as input file paths from UAPI parameters in the operation definition.

- [ ] **Step 5: Run focused tests**

Run: `.venv/bin/python -m pytest tests/test_operations.py -v`

Expected: all tests pass.

- [ ] **Step 6: Commit operation policy**

```bash
git add src/cpanel_admin/operations.py tests/test_operations.py
git commit -m "feat: define safe cPanel operation registry"
```

### Task 6: Task-Oriented CLI and End-to-End Unit Flows

**Files:**
- Create: `src/cpanel_admin/cli.py`
- Create: `tests/conftest.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Produces: `build_parser() -> argparse.ArgumentParser` and injectable `main(argv=None, env=None, stdin=None, stdout=None, stderr=None, transport=None) -> int`.
- Consumes: profile store, secret codec, confirmation service, operation registry, and transport.

- [ ] **Step 1: Write CLI profile and read-operation tests**

Test `profiles add` reads the token from stdin, `profiles show` omits ciphertext, and `--profile production domains list` produces one JSON document with `ok`, `profile`, `operation`, `data`, `warnings`, and `summary`.

```python
code = main(
    ["--config", str(path), "--profile", "production", "domains", "list"],
    env={"CPANEL_ADMIN_FERNET_KEY": key.decode()},
    stdout=stdout,
    stderr=stderr,
    transport=fake_transport,
)
assert code == 0
assert json.loads(stdout.getvalue())["operation"] == "domains.list"
assert stderr.getvalue() == ""
```

- [ ] **Step 2: Write destructive two-step tests**

Call `databases remove --name account_db --dry-run`, capture its digest and expiry, rerun with `--confirm`, and assert the fake transport receives exactly `Mysql/delete_database`. Verify missing, expired, and changed digests return exit code `4` without transport mutation.

- [ ] **Step 3: Run tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_cli.py -v`

Expected: collection fails because `cli.py` does not exist.

- [ ] **Step 4: Build explicit argparse command tree**

Create subparsers for `profiles`, `domains`, `files`, `ssl`, and `databases`. Each leaf maps to an operation name constant. Do not accept module or function flags. Accept secrets only through stdin flags. Add global `--config`, `--profile`, `--timeout`, and `--pretty` options.

- [ ] **Step 5: Implement execution pipeline**

```python
def execute_operation(context: Context, operation_name: str,
                      values: Mapping[str, object], *, dry_run: bool,
                      confirmation: str | None, expires_at: str | None) -> dict[str, object]:
    operation = get_operation(operation_name)
    parameters = validate_parameters(operation, values)
    if dry_run:
        return plan_operation(context, operation, parameters)
    if operation.risk is Risk.DESTRUCTIVE:
        context.confirmations.verify(confirmation, context.profile.name,
                                     operation.name, parameters, expires_at)
    response = context.transport.call(context.profile, context.token,
                                      operation.module, operation.function,
                                      operation.to_uapi(parameters), context.timeout)
    return success_payload(context.profile.name, operation, response)
```

Catch only `CPanelAdminError` in `main`, redact the message, write it to stderr, and return its stable code. Unexpected errors return `1` with a generic message and are never serialized with traceback or secrets by default.

- [ ] **Step 6: Add command coverage and secret-leak regressions**

Cover every registered operation, JSON/pretty JSON, stdin closure, local file read errors, profile tests, key rotation, unsupported domain delete, timeout bounds, UAPI warnings, and output streams containing none of the dummy token/key/password/private-key values.

- [ ] **Step 7: Run CLI and full unit suite**

Run: `.venv/bin/python -m pytest -v`

Run: `.venv/bin/cpanel-admin --help`

Expected: all tests pass and help lists only task-oriented command groups.

- [ ] **Step 8: Commit CLI**

```bash
git add src/cpanel_admin/cli.py tests/conftest.py tests/test_cli.py
git commit -m "feat: add safe task-oriented cPanel CLI"
```

### Task 7: Agent Skill, References, and User Documentation

**Files:**
- Create: `SKILL.md`
- Create: `agents/openai.yaml`
- Create: `references/operations.md`
- Create: `references/safety.md`
- Modify: `README.md`
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: valid Agent Skills metadata with `name: cpanel-integration` matching the repository directory.
- Produces: exact CLI usage and safety instructions matching implemented commands.

- [ ] **Step 1: Write `SKILL.md`**

Frontmatter:

```yaml
---
name: cpanel-integration
description: Use this skill to inspect or administer an individual cPanel account through cPanel UAPI, including domains, website files, SSL certificates, and MySQL or MariaDB databases. Trigger for cPanel account tasks even when the user describes the website operation without naming UAPI. Do not use for WHM, root, reseller, server-service, email, DNS-zone, or unrestricted API tasks.
---
```

Body requirements:

- Check `CPANEL_ADMIN_FERNET_KEY` without printing it.
- List profiles when no profile is safely inferable.
- Read `references/operations.md` for commands.
- Read `references/safety.md` before any mutation.
- Dry-run every destructive operation, show impact and recovery, obtain explicit approval, then use the returned digest and expiry unchanged.
- Never ask users to paste tokens, Fernet keys, database passwords, or private keys into chat.
- Refuse unsupported tasks without offering deprecated or insecure fallbacks.

- [ ] **Step 2: Generate Agent UI metadata with the official helper**

Run:

```bash
python3 /Users/mwatsham/.codex/skills/.system/skill-creator/scripts/generate_openai_yaml.py . \
  --interface 'display_name=cPanel Account Admin' \
  --interface 'short_description=Safely administer individual cPanel accounts' \
  --interface 'default_prompt=Use $cpanel-integration to inspect or administer my cPanel account safely.'
```

Expected: `agents/openai.yaml` is created and contains those three values.

- [ ] **Step 3: Write exact operation and safety references**

`references/operations.md` must list every CLI command, required option, UAPI mapping, risk class, and expected output. `references/safety.md` must define profile secret handling, TLS rules, dry-run, destructive confirmation, live-test isolation, and recovery limitations.

- [ ] **Step 4: Reconcile README and AGENTS**

Replace design-phase language with implemented installation, profile creation, key generation, command examples, operation matrix, destructive flow, integration-test instructions, and troubleshooting. Update `AGENTS.md` commands to commands that have passed locally.

- [ ] **Step 5: Validate docs against CLI help**

Run: `.venv/bin/cpanel-admin --help`

Run: `rg -n 'WHM|CPANEL_ADMIN_FERNET_KEY|--dry-run|--confirm' SKILL.md README.md AGENTS.md references`

Expected: help succeeds and all safety concepts appear in the appropriate documents.

- [ ] **Step 6: Validate Agent Skill format**

Run: `skills-ref validate .`

If `skills-ref` is unavailable, install the official validator in the existing virtual environment only after obtaining approval, then rerun.

Expected: validation passes.

- [ ] **Step 7: Commit skill documentation**

```bash
git add SKILL.md agents/openai.yaml references/operations.md references/safety.md README.md AGENTS.md
git commit -m "docs: complete cPanel administration skill"
```

### Task 8: Live-Test Harness and Completion Verification

**Files:**
- Create: `tests/test_live_cpanel.py`
- Modify: `pyproject.toml`
- Modify: `README.md`

**Interfaces:**
- Produces: opt-in, serial live tests guarded by `CPANEL_ADMIN_RUN_LIVE_TESTS=1` and `CPANEL_ADMIN_LIVE_PROFILE`.
- Produces: final evidence for every acceptance criterion.

- [ ] **Step 1: Write guarded live tests**

At module import, skip unless `CPANEL_ADMIN_RUN_LIVE_TESTS == "1"`. Require the selected profile name to contain `disposable` or `test`. Use resource names beginning with `codex_mvp_` plus UTC timestamp and random hex. Test read-only domains/files/SSL/databases first, then create and remove an isolated database and user with exact confirmation plans. Refuse cleanup for any resource without the prefix.

- [ ] **Step 2: Run default suite and prove live tests skip**

Run: `.venv/bin/python -m pytest -v`

Expected: unit tests pass and live tests are reported skipped.

- [ ] **Step 3: Run coverage and quality gates**

Run: `.venv/bin/python -m pytest --cov=cpanel_admin --cov-report=term-missing --cov-fail-under=90`

Run: `.venv/bin/ruff check .`

Run: `.venv/bin/ruff format --check .`

Run: `skills-ref validate .`

Expected: every command exits `0`.

- [ ] **Step 4: Run live tests when credentials are available**

Set `CPANEL_ADMIN_FERNET_KEY`, `CPANEL_ADMIN_RUN_LIVE_TESTS=1`, and `CPANEL_ADMIN_LIVE_PROFILE` through the approved secret mechanism.

Run: `.venv/bin/python -m pytest tests/test_live_cpanel.py -m live -v`

Expected: supported capability tests pass; any server-disabled feature is reported as a capability skip, not hidden by weakening unit expectations.

- [ ] **Step 5: Audit requirements and secret leakage**

Run: `git grep -nE '(APITOKEN|BEGIN (RSA |EC |)PRIVATE KEY|CPANEL_ADMIN_FERNET_KEY=.{10})' -- ':!docs/superpowers'`

Run: `git status --short`

Review every objective and specification acceptance criterion against current files and fresh command output. Confirm no production credentials or unrelated files are staged.

- [ ] **Step 6: Commit live harness and final fixes**

```bash
git add tests/test_live_cpanel.py pyproject.toml README.md
git commit -m "test: verify cPanel admin MVP"
```

- [ ] **Step 7: Run final verification after the last commit**

Run all four quality gates again and record exact pass counts, coverage, skill validation output, and any live-server capability skips in the final handoff.
