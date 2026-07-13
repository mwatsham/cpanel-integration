# cPanel Account Administration MVP Design

## Status

Approved on 2026-07-13.

## Objective

Build a production-quality Agent Skill and Python CLI that lets an AI agent administer individual cPanel accounts through documented cPanel UAPI calls. The MVP must support named profiles, Fernet-encrypted API tokens, domains, files, SSL, and MySQL/MariaDB databases. It must support destructive operations only through an explicit, operation-bound confirmation flow.

## Users and Runtime

- Primary users: expert web administrators.
- Agent format: Agent Skills open standard.
- Runtime: Python 3.11 or newer.
- Runtime dependency: `cryptography` for Fernet encryption.
- Development dependencies: `pytest`, `pytest-cov`, and `ruff`.
- Network target: an individual cPanel account over verified HTTPS on port `2083`.
- Live validation target: a user-provided disposable cPanel account.

## Non-Goals

- WHM API, root, reseller, account provisioning, or server-service administration.
- Browser automation.
- Deprecated cPanel API 2 fallback.
- Arbitrary UAPI module/function passthrough.
- Email, DNS-zone, backup, deployment, CMS, or shell administration in the MVP.
- Background services or an MCP server.

## Architecture

```text
User request
    ↓
Agent Skill workflow and safety instructions
    ↓
Task-oriented cpanel-admin CLI
    ├── named profile store
    ├── Fernet secret codec
    ├── operation registry and policy engine
    ├── confirmation digest service
    └── UAPI HTTPS transport
            ↓
      cPanel UAPI :2083
            ↓
Structured JSON and redacted summary
```

The skill instructs the agent when and how to invoke the CLI. The CLI is the security and correctness boundary. It validates profiles and parameters, maps a fixed command to a fixed UAPI function, classifies risk, enforces confirmation, performs the request, normalizes the response, and redacts secrets.

## Repository Structure

```text
.
├── AGENTS.md
├── README.md
├── SKILL.md
├── pyproject.toml
├── agents/
│   └── openai.yaml
├── references/
│   ├── operations.md
│   └── safety.md
├── src/cpanel_admin/
│   ├── __init__.py
│   ├── cli.py
│   ├── confirmation.py
│   ├── errors.py
│   ├── operations.py
│   ├── profiles.py
│   ├── redaction.py
│   ├── secrets.py
│   └── transport.py
└── tests/
    ├── conftest.py
    ├── test_cli.py
    ├── test_confirmation.py
    ├── test_operations.py
    ├── test_profiles.py
    ├── test_redaction.py
    ├── test_secrets.py
    └── test_transport.py
```

## Named Profiles

The default profile store is `${XDG_CONFIG_HOME:-~/.config}/cpanel-admin/profiles.json`. Tests and callers can override it with `CPANEL_ADMIN_CONFIG`.

Schema version 1:

```json
{
  "version": 1,
  "profiles": {
    "production": {
      "host": "cpanel.example.com",
      "port": 2083,
      "username": "account",
      "encrypted_token": "gAAAAA..."
    }
  }
}
```

Rules:

- Profile names match `^[a-z][a-z0-9-]{0,62}$`.
- Hosts are DNS names or IP literals without a scheme, path, query, or fragment.
- Port `2083` is the only supported port.
- Usernames match cPanel-compatible alphanumeric and underscore syntax.
- The store is created with user-only permissions where the operating system supports them.
- Writes are atomic: write and fsync a sibling temporary file, then replace the target.
- Existing profiles require `--replace` before modification.
- Profile deletion is destructive and requires confirmation.

Profile commands:

```text
cpanel-admin profiles list
cpanel-admin profiles show NAME
cpanel-admin profiles add NAME --host HOST --username USER --api-token-stdin
cpanel-admin profiles remove NAME --dry-run
cpanel-admin profiles remove NAME --confirm DIGEST --expires-at TIMESTAMP
cpanel-admin profiles test NAME
cpanel-admin profiles rotate-key
```

`profiles show` never returns ciphertext or plaintext secrets.

## Secret Management

- `CPANEL_ADMIN_FERNET_KEY` is required for commands that encrypt, decrypt, test, or use a profile.
- The value must be a valid url-safe base64-encoded 32-byte Fernet key.
- API tokens enter only through standard input for `profiles add`; they are never command arguments.
- The profile store contains only Fernet ciphertext.
- Decrypted values exist only in local variables for the shortest practical time.
- Exceptions never include the token, key, or authorization header.
- Missing keys, malformed keys, invalid ciphertext, and mismatched keys have distinct safe error messages.
- `profiles rotate-key` reads the new key from `CPANEL_ADMIN_FERNET_KEY_NEW`, decrypts all tokens with the current key, re-encrypts all tokens with the new key, and atomically replaces the store.
- Rotation must be all-or-nothing; any failed decryption leaves the original file unchanged.

Environment variables make unattended execution possible but can be inherited by child processes. Documentation must instruct operators to inject the key through their secret manager and avoid logging process environments.

## UAPI Transport

- Base URL: `https://<host>:2083/execute/<Module>/<function>`.
- Authentication header: `Authorization: cpanel <username>:<token>`.
- TLS certificate and hostname verification are always enabled.
- Default timeout: 30 seconds, configurable down to 1 and up to 120 seconds.
- Parameters are encoded with `urllib.parse.urlencode`.
- The transport accepts a fixed operation definition, not raw module/function values from CLI users.
- It rejects redirects to another origin.
- It limits response bodies to 10 MiB before JSON parsing.
- It requires a JSON object response.
- It treats non-2xx HTTP responses as failures.
- It treats a UAPI result with `status != 1` as failure, even when HTTP succeeds.
- It preserves UAPI warnings and messages in structured output.
- It normalizes network, TLS, timeout, HTTP, JSON, and UAPI errors into typed safe exceptions.

## MVP Operation Registry

Every operation has a CLI name, UAPI module/function, parameter schema, risk class, and summary template. Unknown operations and unknown parameters are rejected.

### Domains

Read operations:

- `domains list` → `DomainInfo/list_domains`
- `domains inspect --domain DOMAIN` → `DomainInfo/single_domain_data`
- `domains ssl-capable` → `WebVhosts/list_ssl_capable_domains`

Mutating operations:

- `domains add-subdomain --domain LABEL --rootdomain DOMAIN --dir PATH` → `SubDomain/addsubdomain`

The current UAPI OpenAPI surface does not provide a general replacement for deprecated cPanel API 2 addon-domain create/delete functions. The MVP does not call deprecated API 2. Unsupported create/delete requests return a capability error that explains this limitation.

### Files

Read operations:

- `files list --path PATH` → `Fileman/list_files`
- `files inspect --path PATH` → `Fileman/get_file_information`
- `files read --directory PATH --filename NAME` → `Fileman/get_file_content`

Mutating operations:

- `files write --directory PATH --filename NAME --content-stdin` → `Fileman/save_file_content`
- `files upload --directory PATH --source LOCAL_PATH` → `Fileman/upload_files`

The official UAPI Fileman OpenAPI surface does not expose direct delete or move functions. They are excluded from the MVP. The client must not substitute shell, FTP, browser, or deprecated API calls. `files empty-trash --older-than DAYS` maps to `Fileman/empty_trash` and is destructive because it permanently purges recoverable content.

File writes are destructive when the remote target already exists. The planner must inspect the target first and include its size and modification metadata in the confirmation payload. The MVP does not download automatic backups unless a documented UAPI call supports it; the confirmation message must state when no automatic recovery artifact can be created.

### SSL

Read operations:

- `ssl list` → `SSL/list_certs`
- `ssl hosts` → `SSL/installed_hosts`

Mutating operations:

- `ssl install --domain DOMAIN --certificate FILE --private-key FILE [--cabundle FILE]` → `SSL/install_ssl`
- `ssl remove --domain DOMAIN` → `SSL/delete_ssl`

Certificate and key file contents must not appear in logs or confirmation output. Installation is mutating. Removal is destructive.

### MySQL/MariaDB Databases

Read operations:

- `databases list` → `Mysql/list_databases`
- `databases users` → `Mysql/list_users`

Mutating operations:

- `databases create --name NAME` → `Mysql/create_database`
- `databases create-user --name NAME --password-stdin` → `Mysql/create_user`
- `databases grant --database DB --user USER --privileges LIST` → `Mysql/set_privileges_on_database`

Destructive operations:

- `databases remove --name NAME` → `Mysql/delete_database`
- `databases remove-user --name NAME` → `Mysql/delete_user`

Database passwords enter only through standard input and are redacted like API tokens. The client
validates the local name format and documents server-specific prefixing, but it does not silently
rewrite explicit full names returned by cPanel.

## Risk and Confirmation Model

Risk classes:

- `read`: no confirmation.
- `mutate`: supports `--dry-run`; executes directly only when the operation is reversible and policy marks it non-destructive.
- `destructive`: requires a two-step confirmation.

For destructive operations, a dry-run returns a plan containing:

```json
{
  "profile": "production",
  "operation": "databases.remove",
  "parameters": {"name": "account_example"},
  "impact": "Permanently delete MySQL database account_example",
  "recovery": "Restore from an independently verified backup",
  "expires_at": "2026-07-13T12:05:00Z",
  "confirmation": "8f13c2d1b7e4"
}
```

The digest is an HMAC-SHA256 truncated to 12 hexadecimal characters. Its key is derived from the Fernet key with a domain-separated SHA-256 derivation. Its canonical input contains the schema version, profile, operation, normalized parameters, and expiry timestamp.

Execution rules:

- `--confirm DIGEST` is required for destructive execution.
- Confirmation expires after five minutes.
- Any change to profile, operation, or parameters invalidates it.
- Comparisons use `hmac.compare_digest`.
- Dry-run performs local validation and required read-only preflight calls but never invokes the mutation.
- Confirmation does not bypass validation, allowlisting, TLS, preflight, or UAPI error handling.

## Output Contract

Successful commands write one JSON document to stdout:

```json
{
  "ok": true,
  "profile": "production",
  "operation": "domains.list",
  "data": {},
  "warnings": [],
  "summary": "Returned domains for production"
}
```

Failures write a concise message to stderr and return a stable non-zero code:

- `2`: CLI usage or validation error.
- `3`: profile or configuration error.
- `4`: confirmation required, invalid, or expired.
- `5`: network, TLS, timeout, HTTP, or response-format error.
- `6`: UAPI application error.
- `7`: unsupported capability.

No output contains API tokens, Fernet keys, database passwords, authorization headers, private keys, or certificate bodies.

## Agent Skill

`SKILL.md` must:

- Trigger for individual cPanel account administration involving domains, files, SSL, or databases.
- Reject WHM and server-wide tasks.
- Read `references/operations.md` for supported commands and `references/safety.md` before mutations.
- Ask for the profile name when it cannot infer one safely.
- Use dry-run before every destructive action.
- Present the plan and obtain explicit user approval immediately before rerunning with the confirmation digest.
- Never request that the user paste a token, Fernet key, database password, or private key into chat.
- Explain capability errors without proposing deprecated or insecure fallbacks.

## Test Strategy

Unit tests use temporary profile stores, dummy Fernet keys, and mocked HTTPS transports. The default suite never accesses a live server.

Required unit coverage:

- Profile schema, validation, permissions, atomic writes, replacement, deletion, and selection.
- Fernet round trips, missing/malformed/wrong keys, corrupt ciphertext, stdin token ingestion, and atomic rotation.
- UAPI URL and header construction, parameter encoding, TLS defaults, timeouts, size limits, redirects, HTTP errors, invalid JSON, application errors, warnings, and redaction.
- Operation allowlist, parameter schemas, risk classes, and unsupported operations.
- Dry-run behavior, canonicalization, digest binding, expiry, constant-time comparison, and changed-parameter rejection.
- CLI JSON, stderr, exit codes, and secret-leak regression tests.

Integration tests:

- Require `CPANEL_ADMIN_RUN_LIVE_TESTS=1` and an explicitly named disposable profile.
- Use a unique prefix containing `codex_mvp_` and a timestamp/random suffix.
- Start with read-only discovery and capability checks.
- Create only isolated test resources.
- Verify every created resource before destructive cleanup.
- Refuse to run destructive cleanup when the target lacks the unique prefix.
- Run serially.
- Report leftover resources clearly if cleanup fails.

## Acceptance Criteria

- `pip install -e '.[dev]'` succeeds in a clean Python 3.11+ virtual environment.
- All unit tests pass with no live network access.
- Test coverage is at least 90% for `src/cpanel_admin`.
- `ruff check .` and `ruff format --check .` pass.
- `.venv/bin/agentskills validate "$PWD"` passes for the completed skill.
- The CLI never exposes an arbitrary UAPI passthrough.
- Profile tokens are encrypted at rest and decrypt only with `CPANEL_ADMIN_FERNET_KEY`.
- Secret-leak regression tests cover stdout, stderr, exceptions, and serialized profiles.
- Every destructive operation rejects missing, expired, or mismatched confirmation digests.
- WHM ports and endpoints are rejected.
- README, `SKILL.md`, and reference documents match actual commands.
- Opt-in integration tests either pass against the disposable account or report documented server capability gaps without weakening the unit-tested MVP.

## Authoritative References

- [Agent Skills specification](https://agentskills.io/specification)
- [cPanel UAPI introduction](https://api.docs.cpanel.net/cpanel/introduction)
- [cPanel UAPI OpenAPI](https://api.docs.cpanel.net/specifications/cpanel.openapi)
- [cPanel API tokens](https://api.docs.cpanel.net/cpanel/tokens)
- [Fileman operations](https://api.docs.cpanel.net/specifications/cpanel.openapi/manage-files/get_file_information)
- [SSL installation](https://api.docs.cpanel.net/specifications/cpanel.openapi/ssl-certificate-management/install_ssl)
- [MySQL database management](https://api.docs.cpanel.net/specifications/cpanel.openapi/database-management/create_database)
