# Requirement-by-requirement completion audit

Audit date: 2026-07-14.

Source of requirements: `docs/superpowers/specs/2026-07-13-cpanel-production-expansion-design.md`.
This audit is evidence tracking, not a release declaration. Items marked `Gap` must be resolved
before the production expansion can be called complete.

## Summary

| Requirement | Status | Current evidence |
| --- | --- | --- |
| The official OpenAPI source is pinned and checksum verified. | Proven | `specifications/cpanel.openapi.json`, `specifications/cpanel.openapi.lock.json`, and `scripts/generate_catalog.py` enforce OpenAPI `3.0.2`, UAPI `11.136.0.25`, and SHA-256 `3d9ec80cd8d774312c4bb6b0dfdbc17e6e6ffc92a8f0c2cd88f01e32864fa2c6`. |
| Catalog generation is deterministic and committed output is current. | Proven | `scripts/generate_catalog.py` emits deterministic JSON/Markdown. `scripts/check_generated.py` verifies `src/cpanel_admin/data/operation_catalog.json` and `references/operation-support.md`. |
| Every candidate operation in scope has an explicit include or exclude policy record. | Proven | Current policy surface has 393 selected candidate operations, 393 policy records, 195 included, 198 excluded, 0 missing records, and 0 extra records. |
| Every included operation passes its operation-level contract tests. | Proven by default suite | `tests/test_policy.py` parameterizes included operations for metadata completeness, protected inputs, immutable lookup, command boundaries, and no raw `module`/`function` parameters. Capability-pack tests cover reviewed expansion contracts. |
| Unit, mocked integration, CLI, redaction, and documentation tests pass. | Proven by default suite | `tests/` includes audit, capabilities, catalog generation, CLI, confirmation, executor, inputs, operations, planner, policy, profiles, redaction, secrets, transport, live-harness, OpenAPI-reference, capability-reference, and release-audit tests. |
| Coverage remains at or above 90%. | Proven when coverage gate is run | Required command: `pytest --cov=cpanel_admin --cov-report=term-missing --cov-fail-under=90`. Recent evidence: total coverage `90.10%`. |
| Ruff lint and formatting checks pass. | Proven when Ruff gates are run | Required commands: `ruff check .` and `ruff format --check .`. |
| Both project skill validators pass. | Proven when validation gates are run | `agentskills validate "$PWD"` validates the Agent Skills standard. `scripts/validate_skill_bundle.py "$PWD"` validates project-specific bundle, link, capability-reference, and guardrail invariants. |
| `README.md`, `AGENTS.md`, `SKILL.md`, capability references, and support matrix match behavior. | Mostly proven | `README.md`, `SKILL.md`, `references/capabilities.md`, `references/capabilities/*.md`, `references/openapi-maintenance.md`, `references/live-testing.md`, and `references/operation-support.md` are present. Documentation contract tests cover the key references. A final manual consistency pass should still be done before release. |
| Disposable-account verification passes for every available capability pack, and all created resources are removed or explicitly reported. | Gap | Current live harness verifies representative read-only commands for available packs and has an isolated database lifecycle test. It does not yet exercise a live create/read/update/delete lifecycle for every supported capability pack. |
| A final requirement-by-requirement completion audit finds no missing or indirect evidence. | Gap | This audit records remaining gaps, so the completion condition is not yet satisfied. |

Exact documentation criterion tracked here: README.md, AGENTS.md, SKILL.md, capability references,
and support matrix must match behavior.

## Default-suite expectations

The approved design requires the default suite to have no live network dependency and to cover the
following areas:

| Expected area | Current evidence |
| --- | --- |
| Generator tests for checksum validation, normalization, duplicate detection, deterministic output, schema drift, and stale output. | `tests/test_catalog_generation.py` and `scripts/check_generated.py`. |
| Policy tests for complete classification, explicit exclusions, risk, elevated-impact operations, secret sources, redaction, confirmation, preflight, recovery, and verification metadata. | `tests/test_policy.py`, `tests/test_confirmation.py`, `tests/test_planner.py`, `tests/test_redaction.py`, and capability-pack policy tests. |
| Parameterized contract tests for every included operation. | `tests/test_policy.py` iterates `registry.included()` for operation metadata and boundary checks. |
| Negative tests for every excluded operation and arbitrary-passthrough attempt. | `tests/test_policy.py` covers excluded lookups and exact excluded-record shape; `tests/test_cli.py` verifies no raw UAPI passthrough appears in CLI help. |
| Unit tests for type coercion, enums, required parameters, arrays, bodies, files, protected input, confirmation binding, profiles, transport, audit, redaction, and structured errors. | Covered across `tests/test_inputs.py`, `tests/test_confirmation.py`, `tests/test_profiles.py`, `tests/test_transport.py`, `tests/test_audit.py`, `tests/test_errors.py`, and related files. |
| Mocked integration tests for GET, POST, multipart upload, timeouts, TLS failures, malformed responses, UAPI failures, partial failures, capability absence, and contradictory verification. | Covered across `tests/test_transport.py`, `tests/test_executor.py`, `tests/test_capabilities.py`, and planner/executor tests. |
| CLI tests covering every capability pack and stable exit-code category. | `tests/test_cli.py` plus capability-pack tests and `tests/test_live_harness.py`. |
| Documentation-generation checks and Agent Skills validation. | `scripts/check_generated.py`, documentation contract tests, `scripts/validate_skill_bundle.py "$PWD"`, and `agentskills validate "$PWD"`. |
| Secret-leak regression tests over stdout, stderr, exceptions, audit output, and generated plans. | `tests/test_redaction.py`, `tests/test_secrets.py`, `tests/test_audit.py`, `tests/test_cli.py`, and planner/confirmation tests. |

## Disposable-account verification

Current live verification is intentionally opt-in and gated by:

- `CPANEL_ADMIN_RUN_LIVE_TESTS=1`
- `CPANEL_ADMIN_LIVE_DISPOSABLE=I_UNDERSTAND_THIS_ACCOUNT_IS_DISPOSABLE`
- `CPANEL_ADMIN_LIVE_PROFILE`

Current evidence:

- Representative read-only matrix exists in `tests/test_live_cpanel.py`.
- Redacted JSON-lines reporting exists through `CPANEL_ADMIN_LIVE_REPORT`.
- `references/live-testing.md` documents gates, feature-unavailable skips, report handling, and the
  isolated database lifecycle.
- Recent disposable-account run against `test-123reg` passed read-only verification for available
  packs and skipped unsupported account features explicitly.

Remaining live verification gaps:

1. Expand from read-only coverage to a safe live create/read/update/delete lifecycle for every
   supported capability pack that the disposable account actually supports.
2. Verify each mutation through an independent read where possible.
3. Attempt cleanup in dependency-aware order for all created resources.
4. Persist a redacted evidence report that distinguishes unsupported capabilities from failures and
   explicitly reports cleanup failures.

## Remaining gaps

The production goal should remain open until these are resolved:

1. Extend disposable live tests beyond read-only/database lifecycle to the required live
   create/read/update/delete lifecycle for each supported capability pack.
2. Run the full live destructive/elevated-impact gate on a disposable account and record redacted
   evidence.
3. Perform a final manual documentation consistency pass across `README.md`, `AGENTS.md`,
   `SKILL.md`, capability references, and generated support matrix after the live lifecycle work.
4. Re-run the full verification set and update this audit so every criterion is `Proven`.
