# cPanel OpenAPI maintenance

This project uses a pinned copy of the official cPanel UAPI OpenAPI bundle. The rule is:
normal builds must not download a newer specification or silently widen the operation surface.

## Pinned artifacts

- Source specification: `specifications/cpanel.openapi.json`
- Lock file: `specifications/cpanel.openapi.lock.json`
- Source URL:
  `https://api.docs.cpanel.net/_bundle/specifications/cpanel.openapi.json?download`
- Generated runtime catalog: `src/cpanel_admin/data/operation_catalog.json`
- Generated support matrix: `references/operation-support.md`

The current lock records OpenAPI `3.0.2`, cPanel UAPI `11.136.0.25`, generator schema `1`, and the
approved SHA-256 digest of the pinned source. `scripts/generate_catalog.py` verifies these values
before generating any output.

## Normal verification

Use the check script during development and release verification:

```bash
.venv/bin/python scripts/check_generated.py
```

This delegates to `scripts/generate_catalog.py --check` and fails when committed generated files do
not match the pinned specification, lock file, and reviewed policy.

## Reviewed update workflow

Updating the upstream cPanel specification is a separate review task:

1. Download the official bundle from the source URL into a temporary file.
2. Compare the upstream OpenAPI version, cPanel UAPI version, and SHA-256 against
   `specifications/cpanel.openapi.lock.json`.
3. Review added, changed, removed, deprecated, duplicate, and noncanonical operations.
4. Update `specifications/cpanel.openapi.json` and `specifications/cpanel.openapi.lock.json`
   together only after review.
5. Update `policy/operations.json` with explicit include or exclude decisions for every operation
   in the reviewed module set. The reviewed policy remains the allowlist boundary.
6. Run:

   ```bash
   .venv/bin/python scripts/generate_catalog.py
   .venv/bin/python scripts/check_generated.py
   ```

7. Review the diffs in `src/cpanel_admin/data/operation_catalog.json` and
   `references/operation-support.md`.
8. Run the default tests, coverage gate, Ruff checks, Agent Skill validation, and applicable
   disposable live tests before committing.

## Safety invariants

- Do not add an automatic download step to install, build, test, import, or CLI startup paths.
- Do not include newly discovered operations by wildcard, module name, tag, or HTTP method.
- Do not enable excluded operations by configuration.
- Do not treat HTTP `GET` as read-only; cPanel UAPI exposes mutating operations through `GET`.
- Do not bypass the reviewed policy manifest, risk classification, confirmation planner, audit
  writer, redaction layer, or capability checks.

If the generator rejects the lock, checksum, source version, or policy digest, stop and perform a
reviewed update. Do not patch generated files by hand.
