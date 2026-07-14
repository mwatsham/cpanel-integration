# cPanel Email and Access Capability Packs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add administration-only email, email-authentication DNS, greylisting, spam, routing, and FTP capability packs without exposing mailbox contents or message-destructive operations.

**Architecture:** Declarative policy exposes fixed administrative tasks from the Email, EmailAuth, Mailboxes, SpamAssassin, cPGreyList, and Ftp modules. Focused adapters normalize addresses, quotas, filter structures, MX records, domain lists, and secrets while enforcing independent preflight and verification.

**Tech Stack:** Foundation policy/executor interfaces, Python 3.11+, cPanel UAPI, pytest, Ruff.

## Global Constraints

- Email scope is administration only: accounts, quotas, passwords, forwarders, autoresponders,
  filters, spam controls, routing, MX, DKIM, SPF, DMARC, greylisting, and mail SNI.
- Exclude mailbox browsing, message bodies, queued-message deletion, mailbox expunge, mailing-list
  administration, and reusable private-key export.
- Read all passwords and DKIM private-key imports through stdin or protected `0600` files.
- Treat password, suspension, routing, MX, DNS-authentication, filter-order, anonymous FTP, and FTP
  home-directory changes as elevated impact.
- Treat account, forwarder, autoresponder, filter, MX, spam-box, and FTP deletion as destructive.
- Never include email message data in plans, audit records, or summaries.

---

## File Structure

```text
src/cpanel_admin/capabilities/email.py       email administration adapters
src/cpanel_admin/capabilities/ftp.py         FTP administration adapters
references/capabilities/email.md             email commands and boundaries
references/capabilities/ftp.md               FTP commands and boundaries
tests/test_email_capability.py
tests/test_ftp_capability.py
```

### Task 1: Email accounts, quotas, passwords, and access state

**Files:**
- Create: `src/cpanel_admin/capabilities/email.py`
- Create: `tests/test_email_capability.py`
- Create: `references/capabilities/email.md`
- Modify: `policy/operations.json`
- Modify: `src/cpanel_admin/capabilities/__init__.py`

**Interfaces:**
- Consumes: protected stdin, policy planner, generic executor.
- Produces: account lifecycle and access-state commands plus `EmailAccountAdapter`.

- [ ] **Step 1: Add failing account-policy test**

```python
EMAIL_ACCOUNT_INCLUDED = {
    "Email/account_name", "Email/add_pop", "Email/count_pops", "Email/delete_pop",
    "Email/disable_mailbox_autocreate", "Email/edit_pop_quota",
    "Email/enable_mailbox_autocreate", "Email/get_default_email_quota",
    "Email/get_default_email_quota_mib", "Email/get_disk_usage",
    "Email/get_main_account_disk_usage", "Email/get_main_account_disk_usage_bytes",
    "Email/get_mailbox_autocreate", "Email/get_max_email_quota",
    "Email/get_max_email_quota_mib", "Email/get_pop_quota", "Email/hold_outgoing",
    "Email/list_mail_domains", "Email/list_pops", "Email/list_pops_with_disk",
    "Email/passwd_pop", "Email/release_outgoing", "Email/suspend_incoming",
    "Email/suspend_login", "Email/suspend_outgoing", "Email/terminate_mailbox_sessions",
    "Email/unsuspend_incoming", "Email/unsuspend_login", "Email/unsuspend_outgoing",
    "Email/verify_password", "Mailboxes/get_mailbox_status_list",
    "Mailboxes/has_utf8_mailbox_names", "Mailboxes/set_utf8_mailbox_names",
}

def test_email_account_policy_matches_review(registry: PolicyRegistry) -> None:
    assert EMAIL_ACCOUNT_INCLUDED <= registry.included_identities("email")
```

- [ ] **Step 2: Run and verify temporary-policy failure**

Run: `.venv/bin/python -m pytest tests/test_email_capability.py::test_email_account_policy_matches_review -v`

Expected: FAIL until account records are permanently reviewed.

- [ ] **Step 3: Add task commands and risk metadata**

```text
email accounts list|inspect|count|create|delete|quota-get|quota-set|password-set|password-verify
email accounts suspend-incoming|resume-incoming|suspend-outgoing|resume-outgoing
email accounts suspend-login|resume-login|hold-outgoing|release-outgoing|terminate-sessions
email mailbox-autocreate status|enable|disable
email mailbox-names status|utf8-enable|utf8-disable
email domains list
```

Passwords use `--password-stdin`; no password value option exists. Create and password-verify calls
are promoted to POST form. Delete is destructive. Quota, password, suspension, hold/release,
session termination, and mailbox behavior changes are elevated.

- [ ] **Step 4: Write failing account adapter tests**

```python
def test_email_address_is_split_into_user_and_domain() -> None:
    assert EmailAccountAdapter.split("admin@example.test") == ("admin", "example.test")


def test_main_account_cannot_be_deleted() -> None:
    with pytest.raises(UsageError, match="main cPanel account"):
        adapter.preflight(context, delete_request(context.profile.username))


```

Add concrete cases using password marker `mail-secret-marker`, asserting it is absent from request
URL, plan JSON, exception, and audit JSONL; table-test `0`, positive MiB integers, and the catalog's
unlimited sentinel; and make a post-delete `list_pops` fixture still contain the address so
`VerificationError` is required.

- [ ] **Step 5: Implement `EmailAccountAdapter`**

Normalize IDNA domains and local parts without silently rewriting the requested address. Query
`Email/list_pops_with_disk` for preflight and verification, protect the main account, canonicalize
quota units, and return separate incoming/outgoing/login suspension evidence.

- [ ] **Step 6: Document and test**

Document exact address syntax, quota units, password input, suspension effects, confirmations, and
the no-mailbox-content boundary.

Run: `.venv/bin/python -m pytest tests/test_email_capability.py tests/test_cli.py -v`

Expected: account tests pass.

- [ ] **Step 7: Generate and commit**

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities/email.py references/capabilities/email.md references/operation-support.md tests/test_email_capability.py
git commit -m "feat: add email account administration"
```

### Task 2: Forwarders, autoresponders, filters, default addresses, and routing

**Files:**
- Modify: `src/cpanel_admin/capabilities/email.py`
- Modify: `tests/test_email_capability.py`
- Modify: `references/capabilities/email.md`
- Modify: `policy/operations.json`

**Interfaces:**
- Consumes: email account normalization and generic executor.
- Produces: fixed forwarder, autoresponder, filter, default-address, MX, and routing tasks.

- [ ] **Step 1: Add failing exact operation-set test**

```python
EMAIL_ROUTING_INCLUDED = {
    "Email/add_auto_responder", "Email/add_domain_forwarder", "Email/add_forwarder",
    "Email/add_mx", "Email/change_mx", "Email/count_auto_responders",
    "Email/count_filters", "Email/count_forwarders", "Email/delete_auto_responder",
    "Email/delete_domain_forwarder", "Email/delete_filter", "Email/delete_forwarder",
    "Email/delete_mx", "Email/disable_filter", "Email/enable_filter",
    "Email/get_auto_responder", "Email/get_filter", "Email/list_auto_responders",
    "Email/list_default_address", "Email/list_domain_forwarders", "Email/list_filters",
    "Email/list_filters_backups", "Email/list_forwarders", "Email/list_forwarders_backups",
    "Email/list_mxs", "Email/list_system_filter_info", "Email/reorder_filters",
    "Email/set_always_accept", "Email/set_default_address", "Email/set_manual_mx_redirects",
    "Email/store_filter", "Email/trace_delivery", "Email/trace_filter",
    "Email/unset_manual_mx_redirects",
}

def test_email_routing_policy_matches_review(registry: PolicyRegistry) -> None:
    assert EMAIL_ROUTING_INCLUDED <= registry.included_identities("email")
```

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_email_capability.py -v`

Expected: FAIL until routing records are reviewed.

- [ ] **Step 3: Add task commands**

```text
email forwarders list|count|add|delete
email domain-forwarders list|add|delete
email autoresponders list|count|inspect|add|delete
email filters list|count|inspect|add|delete|enable|disable|reorder|trace
email default-address inspect|set
email routing mx-list|mx-add|mx-update|mx-delete|mode-set|manual-add|manual-remove|trace
```

All routing, default-address, filter creation/order, and MX changes are elevated. Delete operations
are destructive. Filter commands accept a reviewed JSON structure through a protected local file
when the OpenAPI shape cannot be represented by scalar flags; arbitrary UAPI parameter maps remain
forbidden.

- [ ] **Step 4: Add failing adapter tests**

Add concrete fixtures for malformed addresses, an unknown filter key, a pipe-to-command filter
action, current filter index/order binding, current MX priority/routing-mode binding, and a
post-delete forwarder list that still contains the exact source/destination pair.

- [ ] **Step 5: Implement strict email rule adapters**

Create `ForwarderAdapter`, `AutoresponderAdapter`, `FilterAdapter`, and `MailRoutingAdapter`. Filter
actions allow only OpenAPI-documented deliver, redirect, fail, and stop forms; reject shell-command
or pipe actions. Normalize MX priority as integer and bind current MX/routing state to confirmation.

- [ ] **Step 6: Document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_email_capability.py tests/test_cli.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities/email.py references/capabilities/email.md references/operation-support.md tests/test_email_capability.py
git commit -m "feat: add email routing and filter administration"
```

### Task 3: Spam controls, greylisting, DKIM, SPF, and DMARC

**Files:**
- Modify: `src/cpanel_admin/capabilities/email.py`
- Modify: `tests/test_email_capability.py`
- Modify: `references/capabilities/email.md`
- Modify: `policy/operations.json`

**Interfaces:**
- Consumes: domain normalization and protected-file input.
- Produces: spam, greylisting, and email-authentication DNS administration.

- [ ] **Step 1: Add failing include/exclude test**

```python
EMAIL_SECURITY_INCLUDED = {
    "Email/add_spam_filter", "Email/disable_spam_assassin",
    "Email/disable_spam_autodelete", "Email/disable_spam_box",
    "Email/enable_spam_assassin", "Email/enable_spam_box", "Email/get_spam_settings",
    "EmailAuth/apply_dmarc", "EmailAuth/disable_dkim", "EmailAuth/enable_dkim",
    "EmailAuth/ensure_dkim_keys_exist", "EmailAuth/install_dkim_private_keys",
    "EmailAuth/install_spf_records", "EmailAuth/remove_dmarc",
    "EmailAuth/validate_current_dkims", "EmailAuth/validate_current_dmarcs",
    "EmailAuth/validate_current_ptrs", "EmailAuth/validate_current_spfs",
    "SpamAssassin/clear_spam_box", "SpamAssassin/get_symbolic_test_names",
    "SpamAssassin/get_user_preferences", "SpamAssassin/update_user_preference",
    "cPGreyList/disable_all_domains", "cPGreyList/disable_domains",
    "cPGreyList/enable_all_domains", "cPGreyList/enable_domains",
    "cPGreyList/has_greylisting_enabled", "cPGreyList/list_domains",
}

EMAIL_SECURITY_EXCLUDED = {
    "EmailAuth/fetch_dkim_private_keys": "exports stored DKIM private key material",
}
```

Assert exact inclusion plus the permanent exclusion reason.

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_email_capability.py -v`

Expected: FAIL until security records are reviewed.

- [ ] **Step 3: Add command families and controls**

```text
email spam status|enable|disable|box-enable|box-disable|autodelete-disable|threshold-set
email spam preferences|get-tests|preference-set|clear-box
email greylisting status|list|enable|disable|enable-all|disable-all
email auth validate-dkim|validate-spf|validate-dmarc|validate-ptr
email auth dkim-enable|dkim-disable|dkim-ensure|dkim-import
email auth spf-install|dmarc-apply|dmarc-remove
```

Spam-box clear is destructive. Spam thresholds/preferences, greylisting, DKIM/SPF/DMARC, and DKIM
key import are elevated. DKIM imports use a protected `0600` file and POST body.

- [ ] **Step 4: Add failing safety tests**

Add table-driven spam-score boundary cases from the catalog, reject preference name
`arbitrary_command`, assert greylisting inputs normalize to sorted unique IDNA domains, inject a DKIM
private-key marker into a UAPI failure and assert complete redaction, and assert
`EmailAuth/fetch_dkim_private_keys` cannot resolve.

- [ ] **Step 5: Implement and verify adapters**

Implement strict preference-name and value validators, domain-list normalization, current-state
preflight, email-auth validation-based verification, and recursive key-field redaction.

- [ ] **Step 6: Document, test, generate, and commit**

Run: `.venv/bin/python -m pytest tests/test_email_capability.py tests/test_redaction.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities/email.py references/capabilities/email.md references/operation-support.md tests/test_email_capability.py
git commit -m "feat: add email security and authentication controls"
```

### Task 4: Permanently exclude message and mailing-list operations

**Files:**
- Modify: `policy/operations.json`
- Modify: `tests/test_email_capability.py`
- Modify: `references/capabilities/email.md`

**Interfaces:**
- Consumes: all remaining Email and Mailboxes candidate operations.
- Produces: complete permanent classification with no content-access path.

- [ ] **Step 1: Add failing exact-exclusion test**

```python
CONTENT_EXCLUDED = {
    "Email/browse_mailbox": "mailbox content access is outside administration-only scope",
    "Email/delete_held_messages": "queued-message deletion is outside administration-only scope",
    "Mailboxes/expunge_mailbox_messages": "mailbox message deletion is outside administration-only scope",
    "Mailboxes/expunge_messages_for_mailbox_guid": "mailbox message deletion is outside administration-only scope",
}

MAILING_LIST_EXCLUDED = {
    "Email/add_list", "Email/add_mailman_delegates", "Email/count_lists", "Email/delete_list",
    "Email/export_lists", "Email/generate_mailman_otp", "Email/get_lists_total_disk_usage",
    "Email/get_mailman_delegates", "Email/has_delegated_mailman_lists", "Email/list_lists",
    "Email/passwd_list", "Email/remove_mailman_delegates", "Email/set_list_privacy_options",
}

def test_no_message_or_mailing_list_operation_is_included(registry) -> None:
    assert not (set(CONTENT_EXCLUDED) | MAILING_LIST_EXCLUDED) & registry.included_identities("email")
```

- [ ] **Step 2: Classify all remaining Email operations permanently**

Include safe administrative diagnostics and maintenance:

```text
Email/check_fastmail Email/fetch_charmaps Email/fts_rescan_mailbox Email/get_charsets
Email/get_client_settings Email/get_held_message_count Email/get_webmail_settings
Email/has_plaintext_authentication Email/stats_db_status
```

Exclude `Email/dispatch_client_settings` because it sends external mail and is outside administration
tasks. Apply the explicit message and mailing-list reasons above. No Email or Mailboxes record may
retain a foundation-stage reason.

- [ ] **Step 3: Run permanent-boundary tests**

Run: `.venv/bin/python -m pytest tests/test_email_capability.py -v`

Expected: PASS and no message-content operation is resolvable.

- [ ] **Step 4: Generate and commit**

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy/operations.json references/capabilities/email.md references/operation-support.md tests/test_email_capability.py
git commit -m "security: enforce administration-only email boundary"
```

### Task 5: FTP accounts and sessions

**Files:**
- Create: `src/cpanel_admin/capabilities/ftp.py`
- Create: `tests/test_ftp_capability.py`
- Create: `references/capabilities/ftp.md`
- Modify: `policy/operations.json`
- Modify: `src/cpanel_admin/capabilities/__init__.py`

**Interfaces:**
- Consumes: protected stdin and generic executor.
- Produces: all 20 reviewed FTP administration operations.

- [ ] **Step 1: Add failing all-FTP test**

```python
def test_all_ftp_operations_are_reviewed_and_included(catalog, registry) -> None:
    assert registry.included_identities("ftp") == identities(catalog, {"Ftp"})
    assert len(registry.included_identities("ftp")) == 20
```

- [ ] **Step 2: Run and verify failure**

Run: `.venv/bin/python -m pytest tests/test_ftp_capability.py -v`

Expected: FAIL until FTP records are reviewed.

- [ ] **Step 3: Add fixed commands and risks**

```text
ftp accounts list|inspect|exists|create|delete|password-set|quota-get|quota-set|home-set
ftp sessions list|kill
ftp server info|port|welcome-get|welcome-set
ftp anonymous status|enable|disable|incoming-enable|incoming-disable
```

Passwords use stdin and POST. Account delete is destructive. Session kill, password, home, quota,
welcome, and anonymous FTP changes are elevated. Anonymous FTP help text must warn about public
access and default to disabled behavior.

- [ ] **Step 4: Add failing FTP adapter tests**

Add concrete cases for `/absolute`, `../escape`, and valid `public_ftp/client`; assert a password
marker exists only in POST data and never output; assert anonymous enable without confirmation fails;
assert deletion rejects the cPanel username/main account; and assert the session-kill plan includes
the exact session ID plus observed remote IP.

- [ ] **Step 5: Implement, document, test, generate, and commit**

Implement `FTPAccountAdapter` and `FTPSessionAdapter` with exact account/session preflight and
list-based verification.

Run: `.venv/bin/python -m pytest tests/test_ftp_capability.py tests/test_cli.py -v`

Expected: PASS.

```bash
.venv/bin/python scripts/generate_catalog.py
git add policy src/cpanel_admin/capabilities/ftp.py references/capabilities/ftp.md references/operation-support.md tests/test_ftp_capability.py
git commit -m "feat: add FTP account and session administration"
```

### Task 6: Email and access checkpoint

**Files:**
- Modify only files needed for review findings.

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces: permanent email/FTP classifications and green offline gates.

- [ ] **Step 1: Verify no temporary classifications remain**

Run:

```bash
rg -n "not enabled until the (email|ftp) capability review" policy/operations.json
```

Expected: no matches.

- [ ] **Step 2: Verify exclusions cannot resolve**

Run: `.venv/bin/python -m pytest tests/test_email_capability.py tests/test_ftp_capability.py -v`

Expected: PASS, including every content, mailing-list, private-key export, and message-delete negative
test.

- [ ] **Step 3: Run full offline gates**

```bash
.venv/bin/python scripts/check_generated.py
.venv/bin/python -m pytest --cov=cpanel_admin --cov-report=term-missing --cov-fail-under=90
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Expected: all exit 0.

- [ ] **Step 4: Commit review fixes when needed**

Stage each changed email/access path explicitly with `git add`, then commit with
`git commit -m "test: close email and access review findings"`.

Do not create an empty commit.
