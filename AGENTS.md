# AGENTS.md

## Project Overview

- **Project:** cPanel Integration
- **Purpose:** Build an Agent Skills-compatible skill that lets AI agents administer individual cPanel accounts through cPanel UAPI, plus a narrow reviewed cPanel API 2 Fileman fallback for file operations missing from UAPI.
- **Target users:** Expert web administrators.
- **Stack:** Python 3.11+.
- **Status:** MVP implementation complete; verification and live disposable-account testing remain.

## Scope

- Support individual cPanel accounts only.
- Use cPanel UAPI over verified HTTPS on port `2083` by default.
- Use cPanel API 2 only for the reviewed Fileman fallback commands that have no UAPI equivalent.
- Use documented API endpoints. Do not automate the cPanel web interface.
- Support an explicit allowlist for domains, files/directories, SSL, MySQL/MariaDB databases,
  email, FTP, and PHP/runtime account administration.
- Reject WHM API calls, root or reseller operations, account provisioning, and server-service administration.

## Structure

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

Keep `README.md` as repository-facing documentation. Keep agent instructions in `SKILL.md` and detailed operational material in focused files under `references/`.

## Commands

Use these commands and keep them current:

- **Install:** `python3 -m venv .venv` followed by `.venv/bin/python -m pip install -e '.[dev]'`
- **Dev:** `.venv/bin/cpanel-admin --help`
- **Build/validate:** `.venv/bin/agentskills validate "$PWD"`
- **Test:** `.venv/bin/python -m pytest`
- **Lint:** `.venv/bin/ruff check .`
- **Format check:** `.venv/bin/ruff format --check .`

Do not claim a command works until its configuration exists and the command has passed locally.

## Skill Standard

- Follow the current [Agent Skills specification](https://agentskills.io/specification).
- Use a valid lowercase, hyphenated skill name that matches its directory name.
- Include `name` and `description` in the `SKILL.md` YAML frontmatter.
- Make the description state what the skill does and when it should trigger.
- Keep `SKILL.md` concise and below 500 lines.
- Use progressive disclosure: workflow in `SKILL.md`, detailed API material in `references/`, and deterministic operations in `src/cpanel_admin/`.
- Use relative paths from the skill root when linking bundled resources.
- Validate the completed skill with `.venv/bin/agentskills validate "$PWD"`.

## API Design

- Send UAPI requests to `https://<host>:2083/execute/<Module>/<function>`.
- Send reviewed Fileman API 2 fallback requests to `https://<host>:2083/json-api/cpanel`.
- Authenticate using the documented `Authorization: cpanel <username>:<token>` request header.
- Read named profile metadata and encrypted API tokens from the profile configuration.
- Read the Fernet master key from `CPANEL_ADMIN_FERNET_KEY`, or from the permission-checked key
  file when the environment value is absent.
- Keep TLS certificate and hostname verification enabled.
- URI-encode all request parameters.
- Treat non-successful HTTP responses, UAPI responses with `status != 1`, and API 2 responses with
  unsuccessful event/item results as failures.
- Return structured JSON and concise, redacted summaries.
- Use a reviewed module/function allowlist. Never expose an unrestricted arbitrary-call mode by default.

## Safety Rules

- Never place credentials in command arguments, source files, fixtures, logs, prompts, error messages, or Git history.
- Never print the `Authorization` header or raw token.
- Encrypt stored API tokens with Fernet from the `cryptography` package.
- Never write decrypted tokens to disk. Store a Fernet master key only in the documented separate
  key file with user ownership and mode `0600`; never place it in the profile store.
- Accept new API tokens through standard input, not command arguments.
- Redact secrets and sensitive response fields before displaying or logging data.
- Allow read-only operations without confirmation.
- Show the exact target and intended effect before any mutation.
- Require explicit user confirmation immediately before destructive or difficult-to-reverse operations.
- Support `--dry-run` for every mutating operation.
- Run file preflight before overwriting remote files and clearly state that the CLI does not create an automatic backup.
- Default to the least destructive operation and the narrowest possible target.
- Do not silently disable TLS verification, widen the allowlist, or fall back to browser automation.
- Make clear that the local allowlist is an application safeguard, not a substitute for cPanel account permissions.

## Development Rules

### Do

- Read existing code before modifying anything.
- Match existing patterns, naming, types, and style.
- Keep changes small and scoped to the approved task.
- Use Python's standard library plus the approved `cryptography` runtime dependency.
- Separate request construction, transport, response validation, policy checks, and presentation.
- Use explicit exceptions and actionable error messages.
- Add type hints to public Python interfaces.
- Use test-driven development for new behavior.
- Run relevant tests, linting, formatting checks, and skill validation after changes.

### Don't

- Install or add dependencies other than the approved `cryptography` package without asking.
- Delete or overwrite local files without confirming.
- Hardcode hosts, usernames, secrets, API tokens, or credentials.
- Add WHM support or server-level operations.
- Add arbitrary UAPI passthrough without an explicit design review.
- Rewrite working code unless the approved change requires it.
- Suppress errors or convert failures into apparent success.
- Push, deploy, or force-push without permission.
- Make changes outside the request's scope.

## Testing

- Run existing tests after every code change.
- Add at least one focused test for each new behavior.
- Mock network access in unit tests. Never call a production cPanel account from the default test suite.
- Test authentication-header construction without exposing a real token.
- Test URL encoding, timeouts, TLS defaults, allowlist enforcement, dry-run behavior, confirmations, secret redaction, and error normalization.
- Test rejection of WHM ports and endpoints.
- Keep live integration tests opt-in and restricted to a disposable test account with uniquely prefixed resources.
- Never skip, weaken, or delete tests to make the suite pass.

## Git

- Confirm that Git is initialized before creating code.
- Use small, focused commits with descriptive messages.
- Stage and commit after each completed change.
- Stage only files that belong to the current task.
- Never force-push.

## When Stuck

- If a task is large, break it into steps and confirm the plan first.
- Ask one targeted question when critical context is missing.
- If an error remains after two evidence-based attempts, stop and explain the cause, evidence, and next options.

## Response Style

- Respond with clear, concise messages.
- Use plain English.
- Prefer short sentences and scannable sections.
- State assumptions, risks, and verification results.
- End with the next action or decision when work remains.
