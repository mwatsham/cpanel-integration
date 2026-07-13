# cPanel Account Administration Skill

## Overview

This project will provide an Agent Skills-compatible skill for administering individual cPanel accounts with AI assistance. It is intended for expert web administrators who want repeatable, auditable workflows without giving an agent server-wide WHM access.

The MVP design is approved. Implementation has not started yet.

## Recommended Approach

Build a concise `SKILL.md` backed by a deterministic Python command-line client for cPanel UAPI.

```text
User request
    ↓
SKILL.md workflow and safety policy
    ↓
Python UAPI client
    ↓ verified HTTPS on port 2083
cPanel UAPI
    ↓
Structured, redacted result
```

This approach is preferred over direct `curl` instructions because it centralizes validation, error handling, redaction, dry-run behavior, and policy enforcement. It is preferred over an MCP server for the first version because an Agent Skill plus a local Python script is simpler to install and more portable across skills-compatible agents.

## Scope

Version 1 will support multiple named cPanel profiles and one selected profile per command.

Planned capability groups:

- Account information, usage, and quota inspection
- Domain discovery and documented UAPI account-level domain operations
- File listing, transfer, and controlled editing
- MySQL/MariaDB database, user, and privilege administration
- SSL status, certificate installation, and supported certificate removal

The exact UAPI module/function allowlist is defined in the approved MVP specification. The client will not fall back to deprecated cPanel API 2 functions when UAPI does not expose an equivalent domain mutation.

The following are out of scope:

- WHM API 1
- Root and reseller administration
- cPanel account creation, suspension, or deletion
- Server configuration and service management
- Browser automation against cPanel interface pages
- Unrestricted arbitrary API passthrough

## Why UAPI

cPanel documents UAPI as the API for accessing and modifying cPanel account data and settings. Its supported HTTPS endpoint is:

```text
https://<host>:2083/execute/<Module>/<function>
```

The skill will use documented UAPI operations instead of interacting with cPanel HTML pages. This reduces brittleness and provides structured response data.

Official references:

- [Introduction to UAPI](https://api.docs.cpanel.net/cpanel/introduction)
- [cPanel UAPI OpenAPI documentation](https://api.docs.cpanel.net/specifications/cpanel.openapi/)
- [API tokens in cPanel](https://api.docs.cpanel.net/cpanel/tokens)
- [Guide to cPanel API authentication](https://api.docs.cpanel.net/guides/guide-to-api-authentication)

## Skill Format

The skill will follow the [Agent Skills specification](https://agentskills.io/specification):

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
│   ├── cli.py
│   ├── confirmation.py
│   ├── operations.py
│   ├── profiles.py
│   ├── secrets.py
│   └── transport.py
└── tests/
    └── test_*.py
```

- `SKILL.md` will contain the trigger description, core workflow, and safety gates.
- `src/cpanel_admin/` will provide deterministic profile, policy, and UAPI operations behind the `cpanel-admin` command.
- `references/operations.md` will document the reviewed operation allowlist and parameters.
- `references/safety.md` will document risk classes, confirmations, recovery, and redaction rules.
- `agents/openai.yaml` will provide user-facing skill metadata.
- `README.md` is repository documentation and is not required for the packaged skill runtime.

## Profiles and Authentication

The client will store multiple named profiles in a JSON configuration. Each profile contains its host, port, username, and Fernet-encrypted API token.

The Fernet master key must be supplied through the environment for unattended operation:

```bash
export CPANEL_ADMIN_FERNET_KEY="base64-url-safe-fernet-key"
```

New tokens will be accepted through standard input and encrypted before the profile configuration is written. Plaintext tokens and the Fernet key will never be stored.

The token will be sent in cPanel's documented request header:

```text
Authorization: cpanel <username>:<token>
```

Only HTTPS on port `2083` will be accepted by default. Certificate and hostname verification will remain enabled.

Do not place real values in shell history, committed `.env` files, command arguments, test fixtures, prompts, logs, screenshots, or issue reports. The implementation must redact tokens, Fernet keys, ciphertext where practical, and authorization headers from every user-visible error and diagnostic result.

## Safety Model

| Risk class | Examples | Default behavior |
|---|---|---|
| Read-only | List domains, inspect quota, check SSL status | May run immediately |
| Mutating | Create a mailbox, add a DNS record, upload a new file | Show target and effect; support dry-run |
| Destructive | Delete a database, remove DNS records, overwrite or delete files | Require immediate explicit confirmation and a recovery plan |

Additional safeguards:

- Permit only reviewed UAPI modules and functions.
- Reject WHM URLs, ports, and operations.
- Validate hostnames, modules, functions, paths, and parameters before sending a request.
- Check both HTTP status and UAPI's application-level status.
- Use bounded timeouts and actionable errors.
- Back up or snapshot remote files before overwriting or deletion.
- Return structured JSON plus a concise audit-safe summary.
- Never silently fall back to an insecure or broader operation.

cPanel account API tokens can authorize access to account data. The skill's allowlist and confirmation gates are application-level safeguards; they do not reduce the permissions of the underlying cPanel account token.

## Planned Python Interface

The implementation will use Python's standard library and the approved `cryptography` package. Commands will be task-oriented rather than exposing arbitrary UAPI calls:

```bash
cpanel-admin --profile production domains list
cpanel-admin --profile production files list --path public_html
cpanel-admin --profile production ssl list
cpanel-admin --profile production databases list
```

Mutating operations will accept `--dry-run`. Destructive operations will first emit a short-lived confirmation digest for the exact profile, operation, and parameters. Execution requires that digest and will fail if the operation changes.

## Testing Strategy

The default suite will use mocked network responses and must cover:

- Authentication-header construction with dummy credentials
- Fernet encryption, decryption, invalid-key handling, and key rotation
- Named profile creation, selection, replacement, and deletion
- Parameter and URL encoding
- TLS verification and port restrictions
- Request timeouts and transport errors
- HTTP failures and malformed JSON
- UAPI responses where `status != 1`
- Operation allowlist enforcement
- WHM endpoint rejection
- Dry-run and confirmation behavior
- Token and sensitive-field redaction

Live integration tests will be opt-in and will require a dedicated disposable cPanel test account. They must never target production by default.

## Delivery Plan

1. Scaffold the Agent Skill and Python package metadata.
2. Implement encrypted named profiles and the UAPI transport.
3. Implement the approved operation allowlist and risk classification.
4. Add mutation planning, dry-run, confirmation digests, and recovery controls.
5. Write `SKILL.md` and focused reference files.
6. Generate `agents/openai.yaml` and validate the skill.
7. Forward-test realistic read-only and mutating requests against mocks.
8. Run opt-in integration tests against the disposable cPanel account.

Each step should be delivered as a small, independently verified commit.

## Constraints and Risks

- UAPI availability depends on the cPanel version, enabled server profile, and account features.
- Some responses may omit fields even when the HTTP request succeeds.
- Account API tokens and the Fernet master key are sensitive and require independent storage and rotation.
- DNS, database, email, and file changes can interrupt live websites.
- AI-generated intent must be converted into explicit, validated parameters before execution.
- The operation catalog must be reviewed as cPanel's API evolves.

## Current Status

The account-only architecture, MVP scope, destructive-action policy, named-profile model, and Fernet key source are approved. The authoritative design is in `docs/superpowers/specs/2026-07-13-cpanel-account-admin-mvp-design.md`.
