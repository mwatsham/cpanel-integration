# Foundation Task 6 report

## Changed files

- `src/cpanel_admin/planner.py` — added immutable execution plans, confirmation-bound values,
  adapter protocol/default adapter, reviewed adapter registry, and verification results.
- `src/cpanel_admin/confirmation.py` — added deterministic schema-v2 confirmation planning and
  verification bound to profile/account/identity/operation/parameters/preflight/policy digest,
  policy version, risk, elevated impact, and expiry.
- `tests/test_planner.py` — added planning, confirmation binding, contradictory verification, and
  immutability coverage.
- `tests/test_confirmation.py` — added schema-v2 binding coverage.

## RED/GREEN evidence

1. RED: `.venv/bin/python -m pytest tests/test_planner.py -v`
   - Result: collection failed with `ModuleNotFoundError: No module named 'cpanel_admin.planner'`.
2. GREEN: `.venv/bin/python -m pytest tests/test_planner.py tests/test_confirmation.py -v`
   - Result: `11 passed`.
3. RED: `.venv/bin/python -m pytest tests/test_confirmation.py::test_v2_digest_binds_account_identity_preflight_and_policy -v`
   - Result: failed with missing `ConfirmationService.plan_v2`.
4. GREEN: the same focused command passed after the schema-v2 implementation.
5. RED: the policy-version extension test failed with unexpected `policy_version` keyword.
6. GREEN: focused planner/confirmation tests passed after policy-version binding was added.

## Validation evidence

- `.venv/bin/python -m pytest tests/test_planner.py tests/test_confirmation.py tests/test_inputs.py tests/test_policy.py -v`
  - `237 passed`.
- `.venv/bin/python -m pytest --cov=cpanel_admin --cov-fail-under=90`
  - `365 passed, 2 skipped`; total coverage `90.48%`.
- `.venv/bin/ruff check .`
  - Passed.
- `.venv/bin/ruff format --check .`
  - Passed (`29 files already formatted`).
- `.venv/bin/agentskills validate "$PWD"`
  - `Valid skill`.
- `.venv/bin/python scripts/check_generated.py`
  - `generated catalog is current`.
- `git diff --check` and `git diff --cached --check`
  - Passed.

## Commit

- `a7655cc79825429f99e53f59a3e3980881ad3d65` — `feat: generalize cPanel operation planning`

## Assumptions

- `PolicyOperation.feature` is the reviewed adapter selector; absent feature metadata selects the
  immutable `default` adapter.
- The executor context supplied by the later execution task exposes a validated `profile` with
  `name` and `username` attributes.
- Current legacy CLI confirmations remain on their existing v1 service path to preserve MVP CLI
  behavior; all planner-created confirmations use v2.

## Residual risks

- The current reviewed policy declares no operation-specific preflight or verification adapter.
  The default adapter therefore has no preflight and returns `not_available` only for policies that
  explicitly declare no verification; declared verification without a dedicated adapter fails
  closed as category `verification`.
- The planner remains separate from the legacy CLI execution pipeline; destructive legacy CLI
  confirmations now use schema v2 directly until the later executor migration centralizes it.

## Important-finding remediation

### Changed files

- `src/cpanel_admin/planner.py` — rejects externally supplied missing, extra, and unnormalised
  inputs; requires a dedicated reviewed adapter and exact selector for declared preflight; and
  makes all public plan and verification data JSON-only, immutable, copied, and redacted.
- `tests/test_planner.py` — covers direct adapter/planner input rejection, default/missing/wrong
  preflight adapter rejection, direct public construction, and malicious adapter evidence.

### RED/GREEN evidence

- RED: `.venv/bin/python -m pytest tests/test_planner.py -q` returned four expected failures:
  missing/extra inputs were accepted, default/missing preflight adapters were accepted, and raw
  secrets/absolute paths were present in an execution plan representation.
- GREEN: `.venv/bin/python -m pytest tests/test_planner.py -q` returned `11 passed` after the
  remediation. The tests prove copied nested values cannot be mutated and raw secret/path values
  never appear in `ExecutionPlan`, preflight, or `VerificationResult` evidence.

### Verification evidence

- Focused: `.venv/bin/python -m pytest tests/test_planner.py tests/test_confirmation.py
  tests/test_cli.py tests/test_inputs.py tests/test_policy.py -q` — `264 passed`.
- Full offline: `.venv/bin/python -m pytest --cov=cpanel_admin --cov-fail-under=90` —
  `373 passed, 2 skipped`, total coverage `90.57%`.
- `.venv/bin/ruff check .`, `.venv/bin/ruff format --check .`,
  `.venv/bin/agentskills validate "$PWD"`, `.venv/bin/python scripts/check_generated.py`, and
  `git diff --check` all passed.

### Residual risk

- Adapter implementations remain trusted only for request execution; their preflight and
  verification outputs are treated as untrusted public evidence and fail closed if not JSON-safe.

## Remediation evidence

Reviewer remediation added strict v1 compatibility boundaries, registry-owned planner authority,
preflight gating, immutable/redacted verification evidence, an explicit confirmation interface,
and a contradictory-state adapter test. Legacy destructive CLI actions now create and verify v2
confirmations; only the existing `profiles.remove` shape remains on v1.

RED evidence:

- `.venv/bin/python -m pytest tests/test_confirmation.py::test_v1_confirmation_rejects_generalized_operations -v`
  initially failed because v1 accepted `databases.remove`.
- `.venv/bin/python -m pytest tests/test_planner.py::test_planner_rejects_caller_constructed_operation_before_adapter_resolution -v`
  initially failed because `OperationPlanner` had no registry authority boundary.
- `.venv/bin/python -m pytest tests/test_cli.py -q`
  initially showed five destructive legacy CLI flows failing after v1 was restricted, proving the
  migration requirement before CLI v2 confirmation support was added.

GREEN evidence:

- `.venv/bin/python -m pytest tests/test_cli.py tests/test_confirmation.py tests/test_planner.py -q`
  - `33 passed`.
- `.venv/bin/python -m pytest --cov=cpanel_admin --cov-fail-under=90`
  - `368 passed, 2 skipped`; total coverage `90.58%`.
- `ruff check`, format check, Agent Skills validation, generated metadata check, and `git diff --check`
  all passed.
