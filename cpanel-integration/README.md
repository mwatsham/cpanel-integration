# cPanel Account Administration Skill

## Overview

This project will provide an Agent Skills-compatible skill for administering individual cPanel accounts with AI assistance. It is intended for expert web administrators who want repeatable, auditable workflows without giving an agent server-wide WHM access.

The project is currently in the design phase. No executable skill or cPanel client has been implemented yet.

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

Version 1 will support one authenticated cPanel account at a time.

Planned capability groups:

- Account information, usage, and quota inspection
- Domain discovery and account-level domain configuration
- File listing, transfer, and controlled editing
- Database and database-user administration
- Email-account, alias, and forwarding administration
- DNS record inspection and editing
- SSL and AutoSSL status inspection
- Backup discovery and supported account-level backup actions

The exact UAPI module/function allowlist will be reviewed and documented before implementation.

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
├── agents/
│   └── openai.yaml
├── scripts/
│   └── cpanel_uapi.py
├── references/
│   ├── operations.md
│   └── safety.md
└── tests/
    └── test_cpanel_uapi.py
```

- `SKILL.md` will contain the trigger description, core workflow, and safety gates.
- `scripts/cpanel_uapi.py` will provide deterministic UAPI operations.
- `references/operations.md` will document the reviewed operation allowlist and parameters.
- `references/safety.md` will document risk classes, confirmations, recovery, and redaction rules.
- `agents/openai.yaml` will provide user-facing skill metadata.
- `README.md` is repository documentation and is not required for the packaged skill runtime.

## Authentication

The client will read connection details from environment variables:

```bash
export CPANEL_HOST="cpanel.example.com"
export CPANEL_USERNAME="example"
export CPANEL_API_TOKEN="replace-with-token"
```

The token will be sent in cPanel's documented request header:

```text
Authorization: cpanel <username>:<token>
```

Only HTTPS on port `2083` will be accepted by default. Certificate and hostname verification will remain enabled.

Do not place real values in shell history, `.env` files committed to Git, command arguments, test fixtures, prompts, logs, screenshots, or issue reports. The eventual implementation must redact tokens and authorization headers from every user-visible error and diagnostic result.

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

The first implementation should use Python's standard library unless another dependency is approved. A command will follow this general form:

```bash
python scripts/cpanel_uapi.py \
  --module DomainInfo \
  --function list_domains \
  --params '{}'
```

Mutating operations will also accept `--dry-run`. Destructive operations will not execute without the confirmation mechanism defined during implementation.

An unrestricted module/function command is shown only to describe the transport boundary. The production CLI must expose reviewed operations or enforce an explicit allowlist before making a request.

## Testing Strategy

The default suite will use mocked network responses and must cover:

- Authentication-header construction with dummy credentials
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
2. Implement and test the read-only UAPI transport.
3. Define the initial operation allowlist and risk classification.
4. Add mutation planning, dry-run, confirmation, and recovery controls.
5. Write `SKILL.md` and focused reference files.
6. Generate `agents/openai.yaml` and validate the skill.
7. Forward-test realistic read-only and mutating requests against mocks.
8. Add optional integration testing with an approved test account.

Each step should be delivered as a small, independently verified commit.

## Constraints and Risks

- UAPI availability depends on the cPanel version, enabled server profile, and account features.
- Some responses may omit fields even when the HTTP request succeeds.
- Account API tokens are sensitive and require careful local storage and rotation.
- DNS, database, email, and file changes can interrupt live websites.
- AI-generated intent must be converted into explicit, validated parameters before execution.
- The operation catalog must be reviewed as cPanel's API evolves.

## Current Status

The architecture and account-only scope are approved. The next development task is to write and approve a detailed implementation plan before scaffolding the skill.
