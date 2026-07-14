# cPanel Account Administration Production Expansion Design

## Status

Approved in conversation on 2026-07-13.

## Objective

Expand the working individual-account cPanel MVP into a production-grade Agent Skill and Python
CLI. The expanded system must provide broad website-administration coverage from the official
cPanel UAPI OpenAPI specification while retaining a fail-closed allowlist, explicit risk controls,
secure secret handling, generated operation metadata, comprehensive automated tests, and live
verification against a disposable cPanel account.

## Users and Operating Boundary

- Primary users are expert web administrators working directly or through Codex.
- The target is one named, individual cPanel account at a time over verified HTTPS on port `2083`.
- Authentication continues to use cPanel account API tokens stored in encrypted named profiles.
- The CLI remains the deterministic security boundary. Agent instructions cannot bypass CLI policy.
- The implementation targets Python 3.11 or newer.
- Runtime dependencies remain limited to the standard library and the already approved
  `cryptography` dependency unless the user separately approves another dependency.

## Approved Capability Scope

The production release organizes operations into these task-oriented capability packs:

1. Domains, subdomains, redirects, and DNS.
2. Files, directories, permissions, archives, and trash.
3. MySQL/MariaDB databases, users, grants, and remote hosts.
4. SSL certificates, AutoSSL, HTTPS, and email-authentication DNS.
5. Email accounts, quotas, passwords, forwarders, autoresponders, filters, spam controls, routing,
   MX, DKIM, SPF, DMARC, greylisting, and mail SNI.
6. FTP accounts and sessions.
7. Local backups and restores.
8. Git deployment, PHP settings, cron jobs, redirects, and generic application-runtime controls.
9. Security, statistics, resource usage, and diagnostics.

The implementation may divide a pack into focused subcommands and reference files. A pack is not
permission to expose every operation in a similarly named cPanel module. Every operation still
requires an explicit policy decision.

## Explicit Exclusions

The following remain outside the product boundary:

- WHM, root, reseller, server-wide, account-creation, account-suspension, and package operations.
- Browser automation, deprecated cPanel API 2, and undocumented endpoints.
- Arbitrary UAPI module/function calls, raw batch passthrough, and unrestricted raw DNS-zone edits.
- Mailbox browsing, message bodies, queued-message delivery or deletion, and mailbox expunge.
- Remote FTP or SCP backup destinations and their credentials.
- WordPress Toolkit, Sitejet, and other optional application-specific plugin APIs.
- Commerce, branding, themes, and unrelated interface-personalization operations.
- Private-key export and other unnecessary credential-extraction operations.
- Deprecated operations in the pinned OpenAPI document.

The generated support matrix must give an explicit exclusion reason for every candidate operation
within the reviewed module set. Excluded operations cannot be enabled by configuration or by an
agent prompt.

## Architectural Decision

Use a hybrid generated-catalog and hand-reviewed-policy architecture.

The official OpenAPI document supplies endpoint shapes and parameter metadata. A separate policy
manifest decides which operations this product permits and how each is controlled. This separation
is required because cPanel exposes most operations through HTTP `GET`, including many mutations;
HTTP method alone is not a safe risk signal. The OpenAPI `operationId` values are also not fully
unique, so the canonical operation identity is the UAPI `Module/function` pair.

The rejected alternatives are:

- A fully hand-authored registry, because it duplicates a large schema and drifts easily.
- A generic schema-driven executor controlled by a denylist, because one missed classification can
  expose a destructive operation.

## System Structure

```text
User or Codex request
    -> Agent Skill task workflow
    -> task-oriented cpanel-admin command
    -> CLI and input validation
    -> generated operation catalog lookup
    -> reviewed policy enforcement
    -> account capability and precondition checks
    -> dry-run plan for mutations
    -> operation-bound confirmation when required
    -> TLS-verified UAPI transport
    -> HTTP and UAPI response validation
    -> redaction and normalized result
    -> post-action verification
    -> redacted audit event and structured output
```

The generated catalog describes what the pinned cPanel API accepts. The policy manifest describes
what this product supports. User-facing commands map to fixed catalog entries; users cannot supply
module or function identifiers.

## Proposed Repository Additions

```text
specifications/
  cpanel.openapi.json
  cpanel.openapi.lock.json
policy/
  operations.json
scripts/
  generate_catalog.py
  check_generated.py
src/cpanel_admin/
  catalog.py
  policy.py
  planner.py
  audit.py
  capabilities/
    domains.py
    files.py
    databases.py
    ssl.py
    email.py
    ftp.py
    backups.py
    runtime.py
    diagnostics.py
  data/
    operation_catalog.json
references/
  capabilities/
    domains.md
    files.md
    databases.md
    ssl.md
    email.md
    ftp.md
    backups.md
    runtime.md
    diagnostics.md
  operation-support.md
```

Exact module boundaries may change during planning where existing code makes a smaller separation
clearer. The policy source, generated runtime catalog, and generated support matrix must remain
distinct artifacts.

## Pinned OpenAPI Input

The design uses the official cPanel OpenAPI document supplied by the user:

`https://api.docs.cpanel.net/_bundle/specifications/cpanel.openapi.json?download`

The reviewed source at design time identifies itself as OpenAPI 3.0.2 and cPanel UAPI version
11.136.0.25. Before implementation, the download must be captured as a pinned source artifact and
recorded in a lock file with:

- Source URL.
- OpenAPI version.
- cPanel API version.
- Retrieval timestamp.
- SHA-256 digest.
- Generator schema version.

Generation is deterministic from the pinned document. Updating the upstream document is a separate,
reviewed action. Normal builds do not silently download a newer specification.

## Catalog Generation

The generator must:

1. Validate the pinned document and lock-file checksum.
2. Enumerate operations by canonical `Module/function` identity.
3. Normalize path, HTTP method, tags, summary, parameter location, required status, scalar type,
   array shape, enum values, defaults, and request-body media types.
4. Detect duplicate or conflicting canonical identities.
5. Merge each selected operation with its reviewed policy record.
6. Validate that secret inputs, file inputs, risk, confirmation, preflight, recovery, and
   verification rules are complete.
7. Emit a deterministic packaged runtime catalog.
8. Emit a human-readable included/excluded support matrix.
9. Fail when generated files differ from committed output in check mode.

Generated artifacts carry the source API version, source checksum, generator schema version, and a
warning that they must not be edited manually.

## Policy Manifest

Each candidate operation record must contain, as applicable:

- Canonical `Module/function` identity.
- Stable internal operation name.
- User-facing command and capability pack.
- `included` or `excluded` status and rationale.
- Primary risk class.
- Elevated-impact flag.
- Secret-bearing and sensitive-output fields.
- Accepted secret source types.
- Parameter constraints stricter than the OpenAPI schema.
- Dry-run behavior.
- Read-only preflight operation and state fields.
- Impact and recovery templates.
- Confirmation requirements.
- Post-action verification operation and expected state.
- Feature or permission prerequisites.
- Audit-field allowlist.

Generation fails closed when an included operation lacks required policy. No wildcard policy entry
may include newly discovered operations automatically.

## Risk Model

Every operation has one primary risk class:

- `read`: no state mutation and no confirmation.
- `mutate`: changes account state and requires a dry-run before agent execution.
- `destructive`: deletes, overwrites, restores, revokes, or causes difficult-to-reverse state and
  requires a dry-run plus expiring confirmation.

`secret-bearing` and `elevated-impact` are orthogonal policy flags. Elevated-impact mutations use
the same confirmation flow as destructive operations even when the change is technically
reversible. Examples include:

- DNS and mail-routing changes.
- Password and authentication changes.
- Cron creation or modification.
- Git deployment.
- SSL private-key or certificate replacement.
- Database privilege and remote-host changes.
- File overwrite and permission changes.
- Backup restore.

The policy chooses the more restrictive control whenever classifications overlap.

## Planning and Confirmation

Every mutation supports `--dry-run`. The plan contains:

- Profile and cPanel account target.
- Stable operation name and canonical UAPI identity.
- Normalized, redacted parameters.
- Exact intended effect and risk classification.
- Preconditions and relevant current remote state.
- Recovery guidance and known limitations.
- Whether post-action verification is available.
- An expiry and confirmation digest when confirmation is required.

Confirmation is bound to the named profile, account, canonical operation identity, normalized
parameters, expiry, hashes of secret or local file inputs, and policy-defined preflight state. A
change to any bound value invalidates the confirmation. Execution repeats time-sensitive preflight
where possible and refuses the mutation if protected state has changed.

There is no blanket `--yes`, interactive-confirmation bypass, or reusable approval token.

## Secret and Sensitive-Data Handling

- API tokens remain Fernet encrypted in named profiles.
- The Fernet key continues to come from `CPANEL_ADMIN_FERNET_KEY` or a separate, permission-checked
  key file.
- Passwords, private keys, passphrases, and similar inputs enter only through standard input,
  protected regular files, environment references, or an explicit encrypted-profile reference.
- Secret values are never accepted as command arguments.
- Protected input files must be user-owned regular files, must not be symlinks, and must have
  policy-appropriate restrictive permissions.
- Decrypted secret values are never written to disk.
- Confirmation payloads contain only cryptographic hashes of secret or file contents.
- Redaction is recursive and covers success output, errors, diagnostics, audit records, and partial
  failure details.
- Certificate bodies, private keys, authorization headers, passwords, tokens, and raw encrypted
  profile fields never appear in user-facing output.

## Transport and Response Handling

The existing verified-HTTPS UAPI transport remains the only network execution path. Expansion must
add schema-driven support for the HTTP methods and body formats explicitly present in the pinned
catalog, including form and multipart upload where required.

Transport rules remain:

- HTTPS and hostname verification are mandatory.
- Port `2083` is mandatory.
- Cross-origin redirects are rejected.
- Timeouts and response-size limits are enforced.
- HTTP failures, malformed bodies, and UAPI `status != 1` responses are distinct failures.
- Multi-item or multi-stage partial failures are returned explicitly and never normalized to
  success.
- Raw request headers and secret parameters are unavailable to normal logging paths.

## Capability Discovery

cPanel versions, account plans, and installed features vary. The CLI must distinguish:

- Supported by the local skill and available to the account.
- Supported by the skill but unavailable or disabled on this server.
- Explicitly excluded by local policy.
- Unknown because feature discovery failed.

Feature discovery is read-only and cached only for a short, documented interval. A stale capability
result cannot bypass an execution-time policy or precondition check. Unsupported features produce
actionable structured errors and do not fall back to deprecated APIs, browser automation, or wider
privileges.

## CLI Contract

Commands remain task oriented, for example:

```text
cpanel-admin --profile production email accounts list
cpanel-admin --profile production dns records add ... --dry-run
cpanel-admin --profile production backups create-local --dry-run
cpanel-admin --profile production backups restore-files ... --dry-run
```

Common CLI behavior includes:

- Named profile selection.
- Structured JSON stdout and concise safe stderr.
- Stable exit codes for usage, configuration, policy, confirmation, transport, cPanel application,
  partial-failure, verification, and unsupported-capability errors.
- `--dry-run` on every mutation.
- `--confirm` and `--expires-at` for destructive or elevated-impact execution.
- Standard-input and protected-file options for secret and binary inputs.
- Local task and account-capability discovery commands.
- No command accepting raw module or function identifiers.

Complex workflows may orchestrate multiple independently checked CLI actions. The CLI does not
pretend multi-operation workflows are transactional when cPanel provides no transaction.

## Verification and Partial Failure

Mutations use a policy-defined read operation for post-action verification when a reliable one
exists. Verification compares only stable, meaningful fields. A successful mutation response
followed by failed or contradictory verification returns a verification failure, not ordinary
success.

Multi-step workflows report the status of every completed, failed, and unattempted step. Automatic
rollback is provided only when an operation has a specifically designed and tested rollback path.
Otherwise, output supplies recovery guidance and preserves evidence needed for safe manual repair.

## Audit Trail

The CLI writes redacted JSON Lines audit events by default to a user-owned file with mode `0600` in
the cPanel Admin configuration directory. Each event records only policy-approved fields such as:

- Timestamp.
- Profile name.
- Stable operation name.
- Risk and confirmation requirement.
- Redacted target summary.
- Confirmation digest where applicable.
- Outcome and stable error category.
- Verification outcome.

Audit records never contain decrypted credentials, authorization headers, private material, request
bodies, or unrestricted response payloads. Audit-write failures are reported; they are not silently
ignored. The implementation plan must define whether an audit failure blocks execution for each risk
class, with destructive and elevated-impact operations defaulting to fail closed.

## Agent Skill and Documentation

`SKILL.md` remains concise and contains the high-level selection, planning, approval, execution,
verification, and failure workflow. Detailed capability material uses progressive disclosure under
`references/capabilities/`.

Documentation deliverables include:

- Updated repository overview, installation, profile, and security guidance in `README.md`.
- Updated contributor scope, generation, policy, and validation commands in `AGENTS.md`.
- Capability-pack references with commands, risk notes, preconditions, and recovery guidance.
- A generated operation support matrix with explicit include/exclude reasons.
- OpenAPI pinning and reviewed-update instructions.
- Disposable-account live-test instructions and cleanup guidance.

Deterministic security rules live in code and policy data, not only in prose.

## Automated Test Strategy

The default test suite has no live network dependency. It includes:

- Generator tests for checksum validation, normalization, duplicate detection, deterministic output,
  schema drift, and stale output.
- Policy tests for complete classification, explicit exclusions, risk, elevated-impact operations,
  secret sources, redaction, confirmation, preflight, recovery, and verification metadata.
- Parameterized contract tests for every included operation.
- Negative tests for every excluded operation and arbitrary-passthrough attempt.
- Unit tests for type coercion, enums, required parameters, arrays, bodies, files, protected input,
  confirmation binding, profiles, transport, audit, redaction, and structured errors.
- Mocked integration tests for GET, POST, multipart upload, timeouts, TLS failures, malformed
  responses, UAPI failures, partial failures, capability absence, and contradictory verification.
- CLI tests covering every capability pack and stable exit-code category.
- Documentation-generation checks and Agent Skills validation.
- Secret-leak regression tests over stdout, stderr, exceptions, audit output, and generated plans.

The project retains a minimum 90% code-coverage gate. Coverage is supporting evidence, not a
substitute for operation-level contract coverage.

## Disposable-Account Live Verification

Live tests are opt-in, serial, and restricted to the named disposable profile. They must:

1. Perform profile and read-only capability discovery before mutations.
2. Generate a unique resource prefix for the test run.
3. Exercise a controlled create, read, update, and delete lifecycle for each capability pack that
   the account actually supports.
4. Require a second explicit environment gate for destructive and elevated-impact cases.
5. Verify every mutation through an independent read where possible.
6. Attempt cleanup in dependency-aware order.
7. Report unsupported capabilities and cleanup failures with evidence.
8. Emit a redacted machine-readable report.

Tests must never print API tokens, Fernet keys, passwords, certificate private keys, or sensitive
file contents. A skipped feature is acceptable only when the report records the server evidence that
made it unavailable.

## Release Gates

The production expansion is complete only when all of the following are true:

- The official OpenAPI source is pinned and checksum verified.
- Catalog generation is deterministic and committed output is current.
- Every candidate operation in scope has an explicit include or exclude policy record.
- Every included operation passes its operation-level contract tests.
- Unit, mocked integration, CLI, redaction, and documentation tests pass.
- Coverage remains at or above 90%.
- Ruff lint and formatting checks pass.
- Both project skill validators pass.
- `README.md`, `AGENTS.md`, `SKILL.md`, capability references, and support matrix match behavior.
- Disposable-account verification passes for every available capability pack, and all created
  resources are removed or explicitly reported.
- A final requirement-by-requirement completion audit finds no missing or indirect evidence.

## Implementation Sequencing Constraints

- Use test-driven development for generator, policy, and runtime changes.
- Land small, focused commits and keep the tree green at each completed slice.
- Establish the pin, generator, and fail-closed policy model before expanding CLI commands.
- Add capability packs incrementally with their documentation and tests.
- Do not add a dependency, broaden scope, or weaken a policy control without explicit approval.
- Do not run live destructive tests until their dry-run, confirmation, redaction, cleanup, and mocked
  tests pass locally.
