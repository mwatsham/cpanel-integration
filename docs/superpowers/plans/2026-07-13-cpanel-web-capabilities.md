# cPanel Web Capability Packs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add production-grade domains, DNS, files, directory controls, redirects, MySQL/MariaDB, SSL, DNSSEC, DCV, and local backup/restore capability packs on the policy-driven foundation.

**Architecture:** Most operations use the generated catalog and declarative policy directly. Narrow adapters handle DNS atomic-record edits, file overwrite preflight, database privilege normalization, protected key/certificate inputs, multipart restore sources, and independent post-action verification.

**Tech Stack:** Foundation catalog/policy/executor interfaces, Python 3.11+, cPanel UAPI, pytest, Ruff.

## Global Constraints

- Target individual cPanel accounts only.
- Use only operations in pinned cPanel UAPI `11.136.0.25`.
- Keep every included operation behind a fixed task command and reviewed policy record.
- Reject unrestricted `DNS/mass_edit_zone`; expose only one-record atomic adapters.
- Treat overwrite, delete, restore, private-key, DNS, DNSSEC, grant, remote-host, and document-root changes as destructive or elevated impact.
- Read private keys and backup uploads only from protected `0600` files.
- Exclude private-key export, deprecated operations, bulk IP swaps, reseller restore-user discovery, and remote backup transports.
- Preserve every existing MVP command.

---

## File Structure

```text
src/cpanel_admin/capabilities/domains.py       DNS record and domain adapters
src/cpanel_admin/capabilities/files.py         file and directory adapters
src/cpanel_admin/capabilities/databases.py     MySQL adapters
src/cpanel_admin/capabilities/ssl.py           SSL, DNSSEC, and DCV adapters
src/cpanel_admin/capabilities/backups.py       local backup and restore adapters
src/cpanel_admin/capabilities/__init__.py      adapter registry
references/capabilities/domains.md             domain and DNS commands
references/capabilities/files.md               file, redirect, and privacy commands
references/capabilities/databases.md           database commands
references/capabilities/ssl.md                 SSL, DNSSEC, and DCV commands
references/capabilities/backups.md             local backup/restore commands
tests/test_domains_capability.py
tests/test_files_capability.py
tests/test_databases_capability.py
tests/test_ssl_capability.py
tests/test_backups_capability.py
```

### Task 1: Domains, subdomains, redirects, and read-only DNS

**Files:**
- Create: `src/cpanel_admin/capabilities/__init__.py`
- Create: `src/cpanel_admin/capabilities/domains.py`
- Create: `tests/test_domains_capability.py`
- Create: `references/capabilities/domains.md`
- Modify: `policy/operations.json`

**Interfaces:**
- Consumes: `PolicyRegistry`, `OperationPlanner`, `UAPITransport`.
- Produces: domain commands and `DNSRecordAdapter` for atomic edits.

- [ ] **Step 1: Add failing permanent-classification test**

```python
DOMAIN_INCLUDED = {
    "Domain/convert_temporary_to_registered",
    "Domain/is_temporary_domain",
    "Domain/temporary_domain_is_disabled",
    "DomainInfo/domains_data",
    "DomainInfo/list_domains",
    "DomainInfo/main_domain_builtin_subdomain_aliases",
    "DomainInfo/primary_domain",
    "DomainInfo/single_domain_data",
    "SubDomain/addsubdomain",
    "SubDomain/changedocroot",
    "WebVhosts/list_domains",
    "WebVhosts/list_ssl_capable_domains",
    "DNS/ensure_domains_reside_only_locally",
    "DNS/fetch_cpanel_generated_domains",
    "DNS/has_local_authority",
    "DNS/is_alias_available",
    "DNS/is_https_available",
    "DNS/is_svcb_available",
    "DNS/lookup",
    "DNS/mass_edit_zone",
    "DNS/parse_zone",
    "Mime/add_handler",
    "Mime/add_hotlink",
    "Mime/add_mime",
    "Mime/add_redirect",
    "Mime/delete_handler",
    "Mime/delete_hotlink",
    "Mime/delete_mime",
    "Mime/delete_redirect",
    "Mime/get_redirect",
    "Mime/list_handlers",
    "Mime/list_hotlinks",
    "Mime/list_mime",
    "Mime/list_redirects",
    "Mime/redirect_info",
}

DOMAIN_EXCLUDED = {
    "DNS/swap_ip_in_zones": "bulk multi-zone IP replacement is outside atomic DNS tasks",
    "DynamicDNS/create": "returns a reusable secret webcall URL",
    "DynamicDNS/delete": "dynamic DNS credential lifecycle is outside the approved pack",
    "DynamicDNS/list": "may disclose reusable secret webcall URLs",
    "DynamicDNS/recreate": "rotates and returns a reusable secret webcall URL",
    "DynamicDNS/set_description": "dynamic DNS credential lifecycle is outside the approved pack",
}

def test_domain_policy_is_permanently_classified(registry: PolicyRegistry) -> None:
    assert registry.included_identities("domains") == DOMAIN_INCLUDED
    for identity, reason in DOMAIN_EXCLUDED.items():
        assert registry.exclusion(identity).reason == reason
```

- [ ] **Step 2: Run the test and verify temporary-policy failure**

Run: `.venv/bin/python -m pytest tests/test_domains_capability.py -v`

Expected: FAIL because the domain records still have foundation-stage classifications.

- [ ] **Step 3: Add stable commands and permanent risk decisions**

Use these command families:

```text
domains list|inspect|primary|data|temporary-status|convert-temporary
domains subdomains add|change-root
dns inspect|parse|authority|generated-domains|record-support
dns records add|update|delete
redirects list|inspect|add|delete
mime types list|add|delete
mime handlers list|add|delete
hotlink list|enable|disable
```

All DNS record writes, redirects, handlers, hotlink rules, temporary-domain conversion, and document
root changes are elevated impact. Deletions are destructive. Read operations have no confirmation.

- [ ] **Step 4: Write failing atomic DNS adapter tests**

```python
def test_dns_add_builds_one_mass_edit_addition() -> None:
    values = DNSRecordAdapter().build_add(zone(), record(type="A", name="www", value="192.0.2.4"))
    assert values == {"zone": "example.test", "add": [EXPECTED_A_RECORD]}


def test_dns_update_binds_zone_serial_and_original_record() -> None:
    plan = adapter.preflight(context, update_request())
    assert plan["serial"] == 2026071301
    assert plan["original"]["line"] == 14


def test_dns_delete_rejects_wildcard_or_missing_exact_record() -> None:
    with pytest.raises(UsageError, match="exact existing record"):
        adapter.build_delete(zone(), wildcard_request())
```

- [ ] **Step 5: Implement `DNSRecordAdapter`**

```python
class DNSRecordAdapter(OperationAdapter):
    RECORD_TYPES = frozenset({"A", "AAAA", "CAA", "CNAME", "MX", "SRV", "TXT"})
    """Build one exact DNS zone edit and verify the resulting record set."""
```

Implement `preflight(context, operation, inputs) -> JsonValue`, `to_uapi(operation, inputs,
preflight) -> dict[str, object]`, and `verify(context, operation, inputs, response) ->
VerificationResult` with the rules below.

The adapter calls `DNS/parse_zone`, requires exactly one matching original record for update/delete,
binds the zone serial and normalized record to confirmation, escapes TXT values according to the
documented schema, and sends exactly one `add`, `edit`, or `remove` item to `DNS/mass_edit_zone`.

- [ ] **Step 6: Document and run tests**

Document every command, supported record type, confirmation behavior, and the exclusion of raw zone
and bulk-IP changes.

Run: `.venv/bin/python -m pytest tests/test_domains_capability.py tests/test_cli.py -v`

Expected: PASS.

- [ ] **Step 7: Regenerate and commit**

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy/operations.json src/cpanel_admin/capabilities references/capabilities/domains.md references/operation-support.md tests/test_domains_capability.py
git commit -m "feat: add domains and atomic DNS capability pack"
```

### Task 2: Files, indexes, privacy, and protected directories

**Files:**
- Create: `src/cpanel_admin/capabilities/files.py`
- Create: `tests/test_files_capability.py`
- Create: `references/capabilities/files.md`
- Modify: `policy/operations.json`
- Modify: `src/cpanel_admin/capabilities/__init__.py`

**Interfaces:**
- Consumes: `OperationAdapter`, `ResolvedInputs`, planner preflight.
- Produces: Fileman and directory-control commands with overwrite-state binding.

- [ ] **Step 1: Add failing exact-inclusion test**

```python
FILE_INCLUDED = {
    "Fileman/autocompletedir",
    "Fileman/empty_trash",
    "Fileman/get_file_content",
    "Fileman/get_file_information",
    "Fileman/list_files",
    "Fileman/save_file_content",
    "Fileman/transcode",
    "Fileman/upload_files",
    "DirectoryIndexes/get_indexing",
    "DirectoryIndexes/list_directories",
    "DirectoryIndexes/set_indexing",
    "DirectoryPrivacy/add_user",
    "DirectoryPrivacy/configure_directory_protection",
    "DirectoryPrivacy/delete_user",
    "DirectoryPrivacy/is_directory_protected",
    "DirectoryPrivacy/list_directories",
    "DirectoryPrivacy/list_users",
    "DirectoryProtection/list_directories",
}

def test_file_policy_exactly_matches_reviewed_set(registry: PolicyRegistry) -> None:
    assert registry.included_identities("files") == FILE_INCLUDED
```

- [ ] **Step 2: Run the test and verify failure**

Run: `.venv/bin/python -m pytest tests/test_files_capability.py -v`

Expected: FAIL until records are permanently classified.

- [ ] **Step 3: Add stable commands and risk metadata**

```text
files autocomplete|list|inspect|read|write|upload|transcode|empty-trash
directories indexes get|list|set
directories privacy inspect|list|enable|disable|users-list|users-add|users-delete
```

File write/upload remain destructive when an exact target exists and mutating when it does not; the
planner always produces a confirmation because the plan cannot guarantee the execution-time target
will remain absent. Index changes and privacy enable/disable are elevated. Privacy-user passwords
enter through stdin. Deleting a privacy user and emptying trash are destructive.

- [ ] **Step 4: Add failing file preflight and verification tests**

```python
def test_missing_upload_target_uses_parent_listing_preflight() -> None:
    preflight = adapter.preflight(context, upload("public_html", "index.html"))
    assert preflight == {"exists": False, "parent": "public_html"}


def test_existing_target_binds_stable_remote_metadata() -> None:
    preflight = adapter.preflight(context, write("public_html", "index.html"))
    assert set(preflight["metadata"]) >= {"file", "size", "mtime", "type"}


```

Add a concrete privacy-user fixture with password marker `privacy-secret-marker`; force a UAPI error
containing that marker and assert it is absent from the serialized plan, exception, stdout, and
stderr.

- [ ] **Step 5: Implement `FileAdapter` and `DirectoryPrivacyAdapter`**

Use `Fileman/list_files` for parent preflight, compare the exact filename, bind only stable metadata,
and verify through `Fileman/get_file_information`. For privacy users, force POST-form transport for
the password even when the catalog says GET.

- [ ] **Step 6: Document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_files_capability.py tests/test_cli.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities references/capabilities/files.md references/operation-support.md tests/test_files_capability.py
git commit -m "feat: expand files and directory controls"
```

### Task 3: Complete MySQL and MariaDB administration

**Files:**
- Create: `src/cpanel_admin/capabilities/databases.py`
- Create: `tests/test_databases_capability.py`
- Create: `references/capabilities/databases.md`
- Modify: `policy/operations.json`
- Modify: `src/cpanel_admin/capabilities/__init__.py`

**Interfaces:**
- Consumes: generic executor and protected stdin.
- Produces: complete reviewed `Mysql` operation set and preflight/verification adapters.

- [ ] **Step 1: Add failing all-operation policy test**

```python
MYSQL_INCLUDED = {
    "Mysql/add_host", "Mysql/add_host_note", "Mysql/check_database",
    "Mysql/create_database", "Mysql/create_user", "Mysql/delete_database",
    "Mysql/delete_host", "Mysql/delete_user", "Mysql/dump_database_schema",
    "Mysql/get_host_notes", "Mysql/get_privileges_on_database", "Mysql/get_restrictions",
    "Mysql/get_server_information", "Mysql/list_databases", "Mysql/list_routines",
    "Mysql/list_users", "Mysql/locate_server", "Mysql/rename_database", "Mysql/rename_user",
    "Mysql/repair_database", "Mysql/revoke_access_to_database", "Mysql/set_password",
    "Mysql/set_privileges_on_database", "Mysql/setup_db_and_user", "Mysql/update_privileges",
}

def test_mysql_policy_includes_all_reviewed_operations(registry: PolicyRegistry) -> None:
    assert registry.included_identities("databases") == MYSQL_INCLUDED
```

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_databases_capability.py -v`

Expected: FAIL until all MySQL records are reviewed.

- [ ] **Step 3: Add task commands and risk rules**

```text
databases list|inspect-schema|routines|check|repair|create|rename|remove
databases users list|create|rename|password-set|remove
databases grants inspect|set|revoke|refresh
databases remote-hosts list-notes|add|note|remove
databases server-info|restrictions
```

`setup_db_and_user` is exposed only as `databases bootstrap` with password stdin and explicit names;
ignore any OpenAPI wording about random names when the endpoint parameters require specific names.
Repair, rename, password, grant, revoke, privilege refresh, and remote-host changes are elevated.
Database/user delete is destructive.

- [ ] **Step 4: Add failing adapter tests**

```python
def test_grant_preflight_binds_current_privileges() -> None:
    assert adapter.preflight(context, grant_request())["current"] == ["SELECT"]


def test_remote_host_rejects_url_path_or_credentials() -> None:
    with pytest.raises(UsageError, match="IP address, CIDR, or hostname"):
        validate_remote_host("https://user:pass@example.test/path")


```

Add a fake transport assertion that `Mysql/set_password` uses POST data with no query secret, and a
delete response followed by `Mysql/list_users` still containing the user that must raise
`VerificationError`.

- [ ] **Step 5: Implement database adapters**

Implement stable name validation from `Mysql/get_restrictions`, privilege canonicalization, current
grant preflight, remote-host validation without URL syntax, and list-based existence/absence
verification. Secret-bearing calls use POST form and never query strings.

- [ ] **Step 6: Document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_databases_capability.py tests/test_operations.py tests/test_cli.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities references/capabilities/databases.md references/operation-support.md tests/test_databases_capability.py
git commit -m "feat: complete MySQL account administration"
```

### Task 4: SSL, AutoSSL, DNSSEC, DCV, and HTTPS controls

**Files:**
- Create: `src/cpanel_admin/capabilities/ssl.py`
- Create: `tests/test_ssl_capability.py`
- Create: `references/capabilities/ssl.md`
- Modify: `policy/operations.json`
- Modify: `src/cpanel_admin/capabilities/__init__.py`

**Interfaces:**
- Consumes: protected-file inputs and confirmation planner.
- Produces: reviewed SSL/DNSSEC/DCV operations without private-key export.

- [ ] **Step 1: Add failing include/exclude tests**

```python
SSL_EXCLUDED = {
    "DCV/ensure_domains_can_pass_dcv": "deprecated in the pinned OpenAPI document",
    "DNSSEC/export_zone_key": "exports private DNSSEC key material",
    "SSL/check_shared_cert": "deprecated in the pinned OpenAPI document",
    "SSL/fetch_key_and_cabundle_for_certificate": "exports stored private key material",
    "SSL/show_key": "exports stored private key material",
}

def test_ssl_pack_includes_every_nonexcluded_ssl_dnssec_dcv_operation(catalog, registry) -> None:
    candidates = identities(catalog, {"SSL", "DNSSEC", "DCV"})
    assert registry.included_identities("ssl") == candidates - set(SSL_EXCLUDED)
    for identity, reason in SSL_EXCLUDED.items():
        assert registry.exclusion(identity).reason == reason
```

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_ssl_capability.py -v`

Expected: FAIL until every operation is permanently classified.

- [ ] **Step 3: Add command families and risk controls**

```text
ssl certificates list|inspect|generate|upload|rename|delete|export
ssl keys list|generate|upload|rename|delete
ssl csrs list|generate|rename|delete|export
ssl hosts list|inspect|install|remove|primary-set
ssl autossl status|problems|renewal|start|exclude|include|set-exclusions
ssl redirects status|set
ssl mail-sni status|enable|disable|rebuild
dnssec status|enable|disable|keys-list|keys-add|keys-import|keys-remove|keys-activate|keys-deactivate|ds-records|dnskey-export|nsec3-set|nsec3-unset
dcv check-http|check-dns
```

All private-key input uses protected files. Private-key output fields are recursively redacted.
Install/remove, key/cert/CSR delete, key import/upload/generation, primary SSL, redirects, mail SNI,
AutoSSL exclusion, DNSSEC changes, and DCV DNS changes are confirmed.

- [ ] **Step 4: Add failing protected-material and verification tests**

Add concrete cases that assert PEM markers are replaced by SHA-256/byte-count objects, `SSL/show_key`
raises `CapabilityError`, DNSSEC import reads a `0600` file and POSTs without query material,
installed-host verification compares certificate fingerprints, and AutoSSL start returns
verification category `pending` while `is_autossl_check_in_progress` is true.

- [ ] **Step 5: Implement SSL adapters**

Create adapters for PEM fingerprinting, installed-host certificate verification, DNSSEC key-file
input, AutoSSL asynchronous status, and mail-SNI state. Server-generated private key data remains
redacted; the command reports the stored key identifier and verification state only.

- [ ] **Step 6: Document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_ssl_capability.py tests/test_cli.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities references/capabilities/ssl.md references/operation-support.md tests/test_ssl_capability.py
git commit -m "feat: add SSL DNSSEC and DCV administration"
```

### Task 5: Local backup creation and restore

**Files:**
- Create: `src/cpanel_admin/capabilities/backups.py`
- Create: `tests/test_backups_capability.py`
- Create: `references/capabilities/backups.md`
- Modify: `policy/operations.json`
- Modify: `src/cpanel_admin/capabilities/__init__.py`

**Interfaces:**
- Consumes: multipart transport, protected local files, confirmation planner.
- Produces: local-only backup and restore commands.

- [ ] **Step 1: Add failing exact-policy test**

```python
BACKUP_INCLUDED = {
    "Backup/fullbackup_to_homedir",
    "Backup/list_backups",
    "Backup/restore_databases",
    "Backup/restore_email_filters",
    "Backup/restore_email_forwarders",
    "Backup/restore_files",
    "Restore/directory_listing",
    "Restore/query_file_info",
    "Restore/restore_file",
}

BACKUP_EXCLUDED = {
    "Backup/fullbackup_to_ftp": "remote FTP backup transport is outside approved local-only scope",
    "Backup/fullbackup_to_scp_with_key": "remote SCP backup transport is outside approved local-only scope",
    "Backup/fullbackup_to_scp_with_password": "remote SCP backup transport is outside approved local-only scope",
    "Restore/get_users": "reseller multi-account discovery is outside individual-account scope",
}
```

Assert included and excluded identities and exact reasons.

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_backups_capability.py -v`

Expected: FAIL until local-only policy is permanent.

- [ ] **Step 3: Add commands and risk policy**

```text
backups list|create-local
backups browse|inspect
backups restore-file|restore-files|restore-databases|restore-email-filters|restore-email-forwarders
```

Backup creation is elevated because it consumes quota and may include sensitive account data.
Every restore is destructive. Restore sources accept either an exact server-side backup identifier
or a protected local file, never both.

- [ ] **Step 4: Add failing restore tests**

Add concrete table-driven cases for neither/both restore source selectors, assert multipart contains
only the backup basename and bytes, assert the plan contains backup hash/directory/overwrite, assert
post-restore `Fileman/get_file_information` matches expected metadata, and assert all three remote
backup stable names raise `CapabilityError`.

- [ ] **Step 5: Implement backup adapters**

Map POST request bodies from the catalog, use multipart for local uploads, query `Restore/query_file_info`
and `Restore/directory_listing` for server-side sources, bind overwrite and target state, and represent
asynchronous completion as pending until a reliable read confirms completion.

- [ ] **Step 6: Document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_backups_capability.py tests/test_transport.py tests/test_cli.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities references/capabilities/backups.md references/operation-support.md tests/test_backups_capability.py
git commit -m "feat: add local backup and restore capability"
```

### Task 6: Web capability checkpoint

**Files:**
- Modify only files required by review findings.

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces: green web packs and permanent policy classifications.

- [ ] **Step 1: Check no temporary web classifications remain**

Run:

```bash
rg -n "not enabled until the (domain|file|database|ssl|backup) capability review" policy/operations.json
```

Expected: no matches.

- [ ] **Step 2: Run exact policy and secret-leak tests**

```bash
.venv/bin/python -m pytest tests/test_domains_capability.py tests/test_files_capability.py tests/test_databases_capability.py tests/test_ssl_capability.py tests/test_backups_capability.py -v
.venv/bin/python scripts/check_generated.py
```

Expected: all pass.

- [ ] **Step 3: Run all offline quality gates**

```bash
.venv/bin/python -m pytest --cov=cpanel_admin --cov-report=term-missing --cov-fail-under=90
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Expected: all exit 0; live tests skip by default.

- [ ] **Step 4: Commit review fixes when needed**

Stage each changed web-capability path explicitly with `git add`, then commit with
`git commit -m "test: close web capability review findings"`.

Do not create an empty commit when no review changes are needed.
