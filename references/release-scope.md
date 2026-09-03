# Release scope for live execution

This release supports broad cPanel account administration through the reviewed allowlist, but not
every mutable capability pack is executed live in destructive integration tests. The live test policy
is intentionally stricter than the product capability policy.

## Actual live execution

The disposable-account live suite executes reversible lifecycles for capability packs that have a
clear cleanup or rollback path:

- databases
- email
- FTP
- security

In short: actual live execution covers databases, email, FTP, and security.

These tests create disposable resources, verify them where the allowlist exposes an independent
read, run cleanup, and verify cleanup where possible.

## Dry-run-only live execution

The following packs remain dry-run-only for live mutation coverage in this release:

- backups
- domains
- files
- runtime
- SSL

They are still covered by policy tests, CLI tests, operation contract tests, generated metadata
checks, and live dry-run plan tests. They are not executed as live mutations because a safe automated
cleanup or rollback path is not available in the reviewed allowlist for this release.
Runtime now includes guarded PHP administration plus cPanel Git repository and deployment-task
mutations, but those runtime mutations remain dry-run-only in the disposable live suite until
cleanup and rollback can be proven safely for the test account.

Do not promote a dry-run-only pack to actual live execution until the test can prove all of these:

1. It creates only uniquely prefixed disposable resources.
2. It verifies the mutation through an independent read where the allowlist permits one.
3. It cleans up every created resource in dependency-aware order.
4. It reports cleanup failures with exact resource names.
5. It avoids irreversible production-like impact on files, certificates, backups, domains, or
   runtime/PHP/cache state.
