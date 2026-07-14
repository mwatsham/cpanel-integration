# cPanel Production Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the cPanel account-admin MVP into the approved production-grade, OpenAPI-driven Agent Skill with complete policy coverage, broad website-administration capability packs, and disposable-account verification.

**Architecture:** Execute five ordered subplans. The first establishes the pinned OpenAPI catalog, fail-closed policy engine, generic execution pipeline, and security primitives. The next three add independently testable capability groups, and the final plan closes documentation, generated-support, coverage, live-test, and release gates.

**Tech Stack:** Python 3.11+, standard library, `cryptography`, argparse, JSON, pytest, pytest-cov, Ruff, Agent Skills validators, cPanel UAPI over verified HTTPS.

## Global Constraints

- Target individual cPanel accounts only; never add WHM, root, reseller, or server-administration calls.
- Use only documented cPanel UAPI operations from the pinned OpenAPI document.
- Preserve Fernet-encrypted named profiles and environment-or-protected-key-file master-key loading.
- Retain verified HTTPS and hostname verification on port `2083`.
- Keep the runtime dependency set to the Python standard library plus `cryptography>=42,<46`.
- Never expose arbitrary module/function passthrough.
- Never accept credentials, passwords, private keys, or passphrases as command arguments.
- Require dry-run for every agent-performed mutation and expiring confirmation for destructive or elevated-impact operations.
- Every selected OpenAPI operation must have an explicit included or excluded policy record.
- Preserve backward-compatible commands for existing MVP operations.
- Keep default tests offline and live tests opt-in against the disposable profile only.
- Maintain at least 90% line coverage.
- Use small TDD slices and focused commits.

---

## Ordered Plan Suite

Execute these documents in order:

1. `docs/superpowers/plans/2026-07-13-cpanel-production-foundation.md`
2. `docs/superpowers/plans/2026-07-13-cpanel-web-capabilities.md`
3. `docs/superpowers/plans/2026-07-13-cpanel-email-access-capabilities.md`
4. `docs/superpowers/plans/2026-07-13-cpanel-runtime-security-capabilities.md`
5. `docs/superpowers/plans/2026-07-13-cpanel-production-release.md`

Each plan must finish green before the next starts. A failed live feature probe does not authorize a
fallback; record it as unavailable and retain the local policy boundary.

## Cross-Plan Interfaces

The foundation plan establishes these stable interfaces for later plans:

```python
Catalog.load() -> Catalog
Catalog.get(identity: str) -> CatalogOperation
PolicyRegistry.load(catalog: Catalog, path: Path | None = None) -> PolicyRegistry
PolicyRegistry.get(name: str) -> PolicyOperation
PolicyRegistry.by_command(path: tuple[str, ...]) -> PolicyOperation
PolicyRegistry.included_identities(capability: str) -> set[str]
PolicyRegistry.exclusion(identity: str) -> PolicyOperation
InputResolver.resolve(operation, namespace, stdin, env) -> ResolvedInputs
OperationPlanner.dry_run(context, operation, inputs) -> ExecutionPlan
OperationExecutor.execute(context, operation, inputs, confirmation) -> ExecutionResult
CapabilityService.inspect(context) -> CapabilityReport
AuditWriter.write(event: AuditEvent, *, fail_closed: bool) -> None
```

Later capability plans add declarative policy records and narrowly scoped adapters. They must not
duplicate transport, profile, confirmation, redaction, or audit logic.

## Completion Sequence

- [ ] Complete and commit every task in the foundation plan.
- [ ] Complete and commit every task in the web-capabilities plan.
- [ ] Complete and commit every task in the email/access plan.
- [ ] Complete and commit every task in the runtime/security plan.
- [ ] Complete and commit every task in the release plan.
- [ ] Run the final requirement-by-requirement audit defined in the release plan.
- [ ] Mark the active goal complete only after every release-gate item has direct evidence.
