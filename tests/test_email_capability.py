from __future__ import annotations

from pathlib import Path

from cpanel_admin.catalog import Catalog
from cpanel_admin.policy import PolicyRegistry, Risk

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "policy" / "operations.json"

EMAIL_ACCOUNT_ACCESS_INCLUDED = {
    "Email/account_name",
    "Email/count_pops",
    "Email/disable_mailbox_autocreate",
    "Email/edit_pop_quota",
    "Email/enable_mailbox_autocreate",
    "Email/get_default_email_quota",
    "Email/get_default_email_quota_mib",
    "Email/get_disk_usage",
    "Email/get_main_account_disk_usage",
    "Email/get_main_account_disk_usage_bytes",
    "Email/get_mailbox_autocreate",
    "Email/get_max_email_quota",
    "Email/get_max_email_quota_mib",
    "Email/get_pop_quota",
    "Email/hold_outgoing",
    "Email/list_mail_domains",
    "Email/list_pops",
    "Email/list_pops_with_disk",
    "Email/passwd_pop",
    "Email/release_outgoing",
    "Email/suspend_incoming",
    "Email/suspend_login",
    "Email/suspend_outgoing",
    "Email/terminate_mailbox_sessions",
    "Email/unsuspend_incoming",
    "Email/unsuspend_login",
    "Email/unsuspend_outgoing",
    "Email/verify_password",
    "Mailboxes/get_mailbox_status_list",
    "Mailboxes/has_utf8_mailbox_names",
    "Mailboxes/set_utf8_mailbox_names",
}


def registry() -> PolicyRegistry:
    return PolicyRegistry.load(Catalog.load(), POLICY_PATH)


def test_email_account_access_policy_matches_review() -> None:
    subject = registry()

    assert subject.included_identities("email") >= EMAIL_ACCOUNT_ACCESS_INCLUDED
    assert subject.get("email.verify-password").parameters["password"].secret is True
    assert subject.get("email.suspend-login").elevated_impact is True
    assert subject.get("email.terminate-sessions").risk is Risk.MUTATE
    assert subject.get("email.mailbox-names-set").elevated_impact is True
