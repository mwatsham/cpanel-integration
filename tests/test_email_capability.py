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
EMAIL_ROUTING_ADMIN_INCLUDED = {
    "Email/add_domain_forwarder",
    "Email/count_auto_responders",
    "Email/count_filters",
    "Email/count_forwarders",
    "Email/delete_domain_forwarder",
    "Email/get_auto_responder",
    "Email/get_filter",
    "Email/list_default_address",
    "Email/list_domain_forwarders",
    "Email/list_filters_backups",
    "Email/list_forwarders_backups",
    "Email/list_system_filter_info",
    "Email/set_always_accept",
    "Email/trace_delivery",
}
EMAIL_ROUTING_DEFERRED = {
    "Email/reorder_filters": "requires a structured adapter for wildcard filter order inputs",
    "Email/set_default_address": "requires an adapter to reject pipe-to-command destinations",
    "Email/store_filter": "requires a structured adapter for wildcard filter rule inputs",
    "Email/trace_filter": "requires a safe synthetic message adapter and no mailbox body exposure",
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


def test_email_routing_admin_policy_matches_review() -> None:
    subject = registry()

    assert subject.included_identities("email") >= EMAIL_ROUTING_ADMIN_INCLUDED
    assert subject.get("email.add-domain-forwarder").elevated_impact is True
    assert subject.get("email.delete-domain-forwarder").risk is Risk.DESTRUCTIVE
    assert subject.get("email.routing-mode").elevated_impact is True
    for identity, reason in EMAIL_ROUTING_DEFERRED.items():
        assert subject.exclusion(identity).reason == reason
