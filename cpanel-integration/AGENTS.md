# AGENTS.md

## Project Overview

- **Project:** cPanel Integration
- **Purpose:** Build an Agent Skills-compatible skill that lets AI agents administer individual cPanel accounts through cPanel UAPI.
- **Target users:** Expert web administrators.
- **Stack:** Python 3.
- **Status:** Design phase. The skill and client have not been implemented yet.

## Scope

- Support individual cPanel accounts only.
- Use cPanel UAPI over verified HTTPS on port `2083`.
- Use documented API endpoints. Do not automate the cPanel web interface.
- Support an explicit allowlist of account-level operations for domains, files, databases, email, DNS, SSL, backups, quotas, and account inspection.
- Reject WHM API calls, root or reseller operations, account provisioning, and server-service administration.

## Planned Structure

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

Keep `README.md` as repository-facing documentation. Keep agent instructions in `SKILL.md` and detailed operational material in focused files under `references/`.

## Commands

The repository does not contain executable code yet. Introduce these commands with the initial implementation and keep them current:

- **Install:** `python3 -m venv .venv` followed by `.venv/bin/python -m pip install -e '.[dev]'`
- **Dev:** `.venv/bin/python scripts/cpanel_uapi.py --help`
- **Build/validate:** `skills-ref validate .`
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
- Use progressive disclosure: workflow in `SKILL.md`, detailed API material in `references/`, and deterministic operations in `scripts/`.
- Use relative paths from the skill root when linking bundled resources.
- Validate the completed skill with `skills-ref validate .`.

## API Design

- Send requests to `https://<host>:2083/execute/<Module>/<function>`.
- Authenticate using the documented `Authorization: cpanel <username>:<token>` request header.
- Read credentials only from `CPANEL_HOST`, `CPANEL_USERNAME`, and `CPANEL_API_TOKEN`.
- Keep TLS certificate and hostname verification enabled.
- URI-encode all request parameters.
- Treat both non-successful HTTP responses and UAPI responses with `status != 1` as failures.
- Return structured JSON and concise, redacted summaries.
- Use a reviewed module/function allowlist. Never expose an unrestricted arbitrary-call mode by default.

## Safety Rules

- Never place credentials in command arguments, source files, fixtures, logs, prompts, error messages, or Git history.
- Never print the `Authorization` header or raw token.
- Redact secrets and sensitive response fields before displaying or logging data.
- Allow read-only operations without confirmation.
- Show the exact target and intended effect before any mutation.
- Require explicit user confirmation immediately before destructive or difficult-to-reverse operations.
- Support `--dry-run` for every mutating operation.
- Create a backup or recoverable pre-change snapshot before overwriting or deleting remote files.
- Default to the least destructive operation and the narrowest possible target.
- Do not silently disable TLS verification, widen the allowlist, or fall back to browser automation.
- Make clear that the local allowlist is an application safeguard, not a substitute for cPanel account permissions.

## Development Rules

### Do

- Read existing code before modifying anything.
- Match existing patterns, naming, types, and style.
- Keep changes small and scoped to the approved task.
- Use Python's standard library for the initial client unless a dependency is approved.
- Separate request construction, transport, response validation, policy checks, and presentation.
- Use explicit exceptions and actionable error messages.
- Add type hints to public Python interfaces.
- Use test-driven development for new behavior.
- Run relevant tests, linting, formatting checks, and skill validation after changes.

### Don't

- Install or add dependencies without asking.
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
- Add opt-in integration tests only after a separate test-account strategy is approved.
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
