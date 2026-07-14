# cPanel Runtime, Security, and Diagnostics Capability Packs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add generic Git, deployment, PHP, Passenger, NGINX caching, account-security, malware, contact-notification, statistics, resource, log, and diagnostic capabilities while explicitly rejecting unsupported cron administration.

**Architecture:** Fixed policy commands use generated metadata for simple reads and mutations. Focused adapters protect remote Git destinations, deployment tasks, PHP content, dependency installation, IP controls, malware disinfection, contact changes, and asynchronous task state.

**Tech Stack:** Foundation catalog/policy/executor, Python 3.11+, cPanel UAPI, pytest, Ruff.

## Global Constraints

- Keep application management generic; exclude WordPress Toolkit, Sitejet, and optional CMS plugins.
- Cron is unsupported because official cPanel documentation states no UAPI equivalent exists; do not
  fall back to deprecated API 2.
- Treat Git clone/deployment, Passenger dependency installation, PHP changes, security controls,
  malware disinfection, and contact-notification changes as elevated or destructive.
- Reject Git remote URLs outside an explicit per-profile hostname allowlist.
- Never allow URL userinfo, literal private/link-local/loopback/reserved IPs, `file:` URLs, or local
  filesystem repository sources.
- Do not expose server-wide remediation or service control.

---

## File Structure

```text
src/cpanel_admin/capabilities/runtime.py       Git, PHP, Passenger, NGINX adapters
src/cpanel_admin/capabilities/security.py      block, ModSecurity, malware, contact adapters
src/cpanel_admin/capabilities/diagnostics.py   stats, quota, logs, feature adapters
references/capabilities/runtime.md
references/capabilities/security.md
references/capabilities/diagnostics.md
tests/test_runtime_capability.py
tests/test_security_capability.py
tests/test_diagnostics_capability.py
```

### Task 1: Add profile-scoped Git host allowlists

**Files:**
- Modify: `src/cpanel_admin/profiles.py`
- Modify: `src/cpanel_admin/cli.py`
- Modify: `tests/test_profiles.py`
- Modify: `tests/test_cli.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: profile schema version 1.
- Produces: backward-compatible schema version 2 with `allowed_git_hosts`.

- [ ] **Step 1: Write failing migration and validation tests**

```python
def test_v1_profile_loads_with_empty_git_allowlist(tmp_path: Path) -> None:
    store = write_v1_store(tmp_path)
    profile = ProfileStore(store).get("production")
    assert profile.allowed_git_hosts == ()


def test_git_hosts_are_normalized_sorted_and_persisted(tmp_path: Path) -> None:
    store = profile_store(tmp_path)
    profile = store.set_git_hosts("production", ["GitHub.com", "gitlab.example.test"])
    assert profile.allowed_git_hosts == ("github.com", "gitlab.example.test")


@pytest.mark.parametrize("host", ["127.0.0.1", "[::1]", "user@host", "host/path", "*.example.test"])
def test_git_host_allowlist_rejects_unsafe_values(host: str) -> None:
    with pytest.raises(ConfigError, match="Git host"):
        normalize_git_host(host)
```

- [ ] **Step 2: Run and verify failures**

Run: `.venv/bin/python -m pytest tests/test_profiles.py tests/test_cli.py -v`

Expected: FAIL because the profile has no Git allowlist support.

- [ ] **Step 3: Implement schema migration and commands**

Add immutable `allowed_git_hosts: tuple[str, ...] = ()` to `Profile`. `ProfileStore` reads v1 and v2,
writes v2 atomically, and preserves encrypted tokens unchanged during migration.

Add:

```text
cpanel-admin profiles git-hosts NAME list
cpanel-admin profiles git-hosts NAME set --host HOST_1 [--host HOST_2] --dry-run
cpanel-admin profiles git-hosts NAME set --host HOST_1 --confirm DIGEST --expires-at TIMESTAMP
```

Changing the allowlist is elevated local configuration and uses confirmation.

- [ ] **Step 4: Run tests and commit**

Run: `.venv/bin/python -m pytest tests/test_profiles.py tests/test_cli.py -v`

Expected: PASS.

```bash
git add src/cpanel_admin/profiles.py src/cpanel_admin/cli.py tests/test_profiles.py tests/test_cli.py README.md
git commit -m "feat: add profile Git host allowlists"
```

### Task 2: Git repositories, deployment, known hosts, and task queue

**Files:**
- Create: `src/cpanel_admin/capabilities/runtime.py`
- Create: `tests/test_runtime_capability.py`
- Create: `references/capabilities/runtime.md`
- Modify: `policy/operations.json`
- Modify: `src/cpanel_admin/capabilities/__init__.py`

**Interfaces:**
- Consumes: profile Git allowlist, planner, task discovery.
- Produces: reviewed Git and deployment commands with `GitAdapter`.

- [ ] **Step 1: Add failing exact-operation test**

```python
GIT_INCLUDED = {
    "KnownHosts/create", "KnownHosts/delete", "KnownHosts/update", "KnownHosts/verify",
    "SSH/get_port", "UserTasks/delete", "UserTasks/retrieve",
    "VersionControl/create", "VersionControl/delete", "VersionControl/retrieve",
    "VersionControl/update", "VersionControlDeployment/create",
    "VersionControlDeployment/delete", "VersionControlDeployment/retrieve",
}

def test_git_policy_matches_reviewed_operations(registry: PolicyRegistry) -> None:
    assert registry.included_identities("runtime-git") == GIT_INCLUDED
```

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_runtime_capability.py -v`

Expected: FAIL until Git records are reviewed.

- [ ] **Step 3: Add command families and risks**

```text
git repositories list|create|update|delete
git deploy start|status|cancel
git known-hosts verify|add|update|delete
git ssh-port
tasks list|delete
```

Create/update/delete, deployment start/cancel, known-host changes, and task deletion require
confirmation. Repository path stays relative to the account home. Remote URL hostname must appear in
the selected profile allowlist.

- [ ] **Step 4: Write failing Git safety tests**

```python
@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "https://user:pass@github.com/org/repo.git",
    "ssh://127.0.0.1/repo", "git://169.254.169.254/meta", "/home/user/repo",
])
def test_git_source_rejects_unsafe_or_credential_urls(url: str) -> None:
    with pytest.raises(UsageError, match="Git source URL"):
        validate_git_source(url, allowed_hosts=("github.com",))
```

Add concrete cases asserting an unlisted hostname fails, a deployment plan contains observed
repository head and `.cpanel.yml` SHA-256, and an unfinished task returns verification category
`pending`.

- [ ] **Step 5: Implement `GitAdapter` and `TaskAdapter`**

Support only `https` and `ssh` URLs with hostname allowlist matching. Reject URL userinfo and literal
non-public IPs before transport. Preflight repository metadata through `VersionControl/retrieve`,
bind current branch/head where returned, and use `VersionControlDeployment/retrieve` or
`UserTasks/retrieve` for task status.

- [ ] **Step 6: Document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_runtime_capability.py tests/test_profiles.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities/runtime.py references/capabilities/runtime.md references/operation-support.md tests/test_runtime_capability.py
git commit -m "feat: add protected Git deployment administration"
```

### Task 3: PHP, Passenger, and NGINX caching

**Files:**
- Modify: `src/cpanel_admin/capabilities/runtime.py`
- Modify: `tests/test_runtime_capability.py`
- Modify: `references/capabilities/runtime.md`
- Modify: `policy/operations.json`

**Interfaces:**
- Consumes: generic executor, local-file fingerprints, domain validation.
- Produces: complete LangPHP, PassengerApps, and NginxCaching packs.

- [ ] **Step 1: Add failing module-completeness test**

```python
def test_generic_runtime_modules_are_fully_reviewed(catalog, registry) -> None:
    expected = identities(catalog, {"LangPHP", "PassengerApps", "NginxCaching"})
    assert registry.included_identities("runtime-apps") == expected
    assert len(expected) == 22
```

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_runtime_capability.py -v`

Expected: FAIL until all 22 operations are reviewed.

- [ ] **Step 3: Add fixed task commands**

```text
php versions installed|default|domains|get|set|impacted
php ini paths|basic-get|basic-set|content-get|content-set
apps passenger list|register|edit|enable|disable|dependencies-install|unregister
cache nginx enable|disable|clear|reset
```

PHP version/INI changes, Passenger register/edit/enable/disable/unregister, dependency installation,
and NGINX configuration changes require confirmation. Cache clear is mutating and dry-run required.
Passenger dependency installation clearly reports supply-chain execution from the application's
manifest.

- [ ] **Step 4: Add failing adapter tests**

Add concrete fake-catalog cases that reject an uninstalled PHP version and unknown directive, assert
full INI content is represented only by hash/bytes, reject absolute and parent Passenger roots,
assert dependency installation has `requires_confirmation=True`, and assert NGINX clear returns a
request-completed result without claiming a durable cache-empty state.

- [ ] **Step 5: Implement runtime adapters**

Add `PHPAdapter`, `PassengerAdapter`, and `NginxCacheAdapter`. Validate versions against
`php_get_installed_versions`; restrict basic directives to the catalog schema; fingerprint full INI
content; bind existing application settings before edit/delete; and use list/status reads for
verification.

- [ ] **Step 6: Document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_runtime_capability.py tests/test_cli.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities/runtime.py references/capabilities/runtime.md references/operation-support.md tests/test_runtime_capability.py
git commit -m "feat: add PHP Passenger and NGINX controls"
```

### Task 4: IP blocks, ModSecurity, and malware scanning

**Files:**
- Create: `src/cpanel_admin/capabilities/security.py`
- Create: `tests/test_security_capability.py`
- Create: `references/capabilities/security.md`
- Modify: `policy/operations.json`
- Modify: `src/cpanel_admin/capabilities/__init__.py`

**Interfaces:**
- Consumes: IP/CIDR/path validators, planner, task status.
- Produces: BlockIP, ModSecurity, and ClamScanner tasks.

- [ ] **Step 1: Add failing exact-module test**

```python
def test_security_modules_are_fully_reviewed(catalog, registry) -> None:
    expected = identities(catalog, {"BlockIP", "ModSecurity", "ClamScanner"})
    assert registry.included_identities("security") == expected
    assert len(expected) == 14
```

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_security_capability.py -v`

Expected: FAIL until all records are reviewed.

- [ ] **Step 3: Add commands and risk metadata**

```text
security ip-blocks add|remove
security modsecurity status|list|enable|disable|enable-all|disable-all
security malware paths|scan-start|scan-status|infected-list|disinfect-start|disinfect-status
```

IP and ModSecurity changes are elevated. Disinfection is destructive. Scan starts are mutating and
must identify the documented scan path type; arbitrary absolute paths are rejected.

- [ ] **Step 4: Add failing safety tests**

Add concrete cases rejecting invalid IPs and the resolved profile host IP, asserting global
ModSecurity disable requires confirmation, rejecting scan path names absent from
`get_scan_paths`, asserting disinfection binds a sorted infected-file snapshot, and returning exit
code 8 when any per-file disinfection result fails.

- [ ] **Step 5: Implement security adapters**

Add exact IP/CIDR normalization, domain-list preflight, scan-path selection, infected-file snapshot
binding, asynchronous status reads, and per-file disinfection result normalization.

- [ ] **Step 6: Document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_security_capability.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities/security.py references/capabilities/security.md references/operation-support.md tests/test_security_capability.py
git commit -m "feat: add account security and malware controls"
```

### Task 5: Contact addresses and notification preferences

**Files:**
- Modify: `src/cpanel_admin/capabilities/security.py`
- Modify: `tests/test_security_capability.py`
- Modify: `references/capabilities/security.md`
- Modify: `policy/operations.json`

**Interfaces:**
- Consumes: protected planning and strict notification schema.
- Produces: contact/notification administration without Pushbullet token exposure.

- [ ] **Step 1: Add failing inclusion/exclusion tests**

```python
CONTACT_INCLUDED = {
    "ContactInformation/get_notification_preferences",
    "ContactInformation/set_email_addresses",
    "ContactInformation/set_notification_preferences",
    "ContactInformation/unset_email_addresses",
}

CONTACT_EXCLUDED = {
    "ContactInformation/get_pushbullet_access_token": "exports a reusable Pushbullet access token",
    "ContactInformation/set_pushbullet_access_token": "Pushbullet token management is outside approved scope",
}
```

Assert exact included/excluded sets and reasons.

- [ ] **Step 2: Add commands and tests**

```text
account contacts get|set|unset
account notifications get|set
```

All mutations require confirmation and bind current contact/preferences state. Tests reject unknown
preference keys, normalize email addresses, and assert Pushbullet operations cannot resolve.

- [ ] **Step 3: Implement, document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_security_capability.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities/security.py references/capabilities/security.md references/operation-support.md tests/test_security_capability.py
git commit -m "feat: add account contact and notification controls"
```

### Task 6: Statistics, quota, logs, resources, and diagnostics

**Files:**
- Create: `src/cpanel_admin/capabilities/diagnostics.py`
- Create: `tests/test_diagnostics_capability.py`
- Create: `references/capabilities/diagnostics.md`
- Modify: `policy/operations.json`
- Modify: `src/cpanel_admin/capabilities/__init__.py`

**Interfaces:**
- Consumes: generic executor.
- Produces: reviewed account diagnostics and stats-configuration tasks.

- [ ] **Step 1: Add failing exact-module test**

```python
DIAGNOSTIC_MODULES = {
    "AccountEnhancements", "Bandwidth", "Chkservd", "Features", "LastLogin", "LogManager",
    "Quota", "ResourceUsage", "ServerInformation", "Stats", "StatsBar", "StatsManager",
    "Variables",
}

def test_diagnostic_modules_are_fully_reviewed(catalog, registry) -> None:
    expected = identities(catalog, DIAGNOSTIC_MODULES)
    assert registry.included_identities("diagnostics") == expected
```

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_diagnostics_capability.py -v`

Expected: FAIL until all diagnostic records are reviewed.

- [ ] **Step 3: Add task families**

```text
diagnostics account|server|session|features|enhancements|last-login
diagnostics quota|resources|bandwidth|stats|site-errors|mail-ports
diagnostics logs settings-get|settings-set|archives-list|archive-delete
diagnostics analyzers get|set
```

Reads execute directly. Log/analyzer setting changes are elevated. Log archive deletion is
destructive. `Stats/get_site_errors` output is treated as sensitive operational data and excluded
from audit targets and summaries.

- [ ] **Step 4: Add failing normalization and redaction tests**

Add concrete cases asserting feature discovery calls `Features/list_features` without a caller
regex, invalid stats display names fail validation, a unique site-error marker is absent from audit,
archive deletion binds name/size/mtime, and `ServerInformation/get_information` remains risk `read`
with no server-control command generated.

- [ ] **Step 5: Implement, document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_diagnostics_capability.py tests/test_capabilities.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities/diagnostics.py references/capabilities/diagnostics.md references/operation-support.md tests/test_diagnostics_capability.py
git commit -m "feat: add account diagnostics and statistics"
```

### Task 7: Explicit unsupported cron behavior and plugin exclusions

**Files:**
- Modify: `src/cpanel_admin/cli.py`
- Modify: `src/cpanel_admin/capabilities.py`
- Modify: `tests/test_runtime_capability.py`
- Modify: `references/capabilities/runtime.md`
- Modify: `references/operation-support.md` generation input

**Interfaces:**
- Consumes: capability-error contract.
- Produces: actionable cron/plugin exclusions without deprecated fallback.

- [ ] **Step 1: Write failing unsupported-behavior tests**

```python
def test_cron_command_returns_capability_error() -> None:
    code, _stdout, stderr = invoke(["cron", "jobs", "list"])
    assert code == 7
    assert "no UAPI equivalent" in stderr
    assert "API 2" in stderr


@pytest.mark.parametrize("group", ["wordpress", "sitejet", "whm"])
def test_excluded_product_group_is_never_generated(group: str) -> None:
    assert group not in generated_top_level_groups()
```

- [ ] **Step 2: Run and verify failures**

Run: `.venv/bin/python -m pytest tests/test_runtime_capability.py -v`

Expected: cron is currently only an argparse usage error.

- [ ] **Step 3: Add explicit local exclusion command**

Create a fixed `cron jobs list|add|update|delete` parser group whose handler always raises:

```text
Cron administration is unsupported: cPanel documents no UAPI equivalent, and this skill does not use deprecated API 2.
```

This is not a UAPI passthrough and accepts no command payload or schedule arguments. Add a generated
support-matrix note for cron and permanent exclusions for plugin modules outside the selected
candidate set.

- [ ] **Step 4: Test and commit**

Run: `.venv/bin/python -m pytest tests/test_runtime_capability.py tests/test_cli.py -v`

Expected: PASS with exit code 7 for every cron action.

```bash
git add src/cpanel_admin/cli.py src/cpanel_admin/capabilities.py references/capabilities/runtime.md references/operation-support.md tests/test_runtime_capability.py
git commit -m "docs: report unsupported cron and plugin capabilities"
```

### Task 8: Runtime and security checkpoint

**Files:**
- Modify only files needed for review findings.

**Interfaces:**
- Consumes: Tasks 1-7.
- Produces: permanent classifications for all remaining selected modules.

- [ ] **Step 1: Verify no foundation-stage policy reasons remain**

Run:

```bash
rg -n "not enabled until|pending review" policy/operations.json
```

Expected: no matches anywhere. Every one of the 393 candidate operations now has a permanent include
or exclude reason.

- [ ] **Step 2: Run policy completeness and generated checks**

```bash
.venv/bin/python -m pytest tests/test_policy.py tests/test_runtime_capability.py tests/test_security_capability.py tests/test_diagnostics_capability.py -v
.venv/bin/python scripts/check_generated.py
```

Expected: PASS with 48 modules, 393 operations, zero missing, and zero pending review.

- [ ] **Step 3: Run all offline gates**

```bash
.venv/bin/python -m pytest --cov=cpanel_admin --cov-report=term-missing --cov-fail-under=90
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Expected: all exit 0.

- [ ] **Step 4: Commit review fixes when needed**

Stage each changed runtime/security path explicitly with `git add`, then commit with
`git commit -m "test: close runtime and security review findings"`.

Do not create an empty commit.
