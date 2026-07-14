from __future__ import annotations

from pathlib import Path

from cpanel_admin.catalog import Catalog
from cpanel_admin.policy import PolicyRegistry, Risk

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "policy" / "operations.json"

SECURITY_INCLUDED = {
    "BlockIP/add_ip",
    "BlockIP/remove_ip",
    "ClamScanner/check_disinfection_status",
    "ClamScanner/get_scan_paths",
    "ClamScanner/get_scan_status",
    "ClamScanner/list_infected_files",
    "ContactInformation/get_notification_preferences",
    "KnownHosts/verify",
    "ModSecurity/disable_all_domains",
    "ModSecurity/disable_domains",
    "ModSecurity/enable_all_domains",
    "ModSecurity/enable_domains",
    "ModSecurity/has_modsecurity_installed",
    "ModSecurity/list_domains",
    "SSH/get_port",
    "UserTasks/retrieve",
}
SECURITY_EXCLUDED = {
    "ClamScanner/disinfect_files": (
        "file disinfection is destructive and needs a malware remediation adapter"
    ),
    "ClamScanner/start_scan": "virus scans can be long-running and need a task adapter",
    "ContactInformation/get_pushbullet_access_token": "returns a third-party access token",
    "ContactInformation/set_email_addresses": (
        "requires protected password input and contact-change review"
    ),
    "ContactInformation/set_notification_preferences": (
        "bulk notification preference changes need a structured preference adapter"
    ),
    "ContactInformation/set_pushbullet_access_token": "stores a third-party access token",
    "ContactInformation/unset_email_addresses": (
        "requires protected password input and contact-change review"
    ),
    "KnownHosts/create": "changes SSH known_hosts state and needs host-key fingerprint review",
    "KnownHosts/delete": "removes SSH known_hosts state and needs host-key fingerprint review",
    "KnownHosts/update": "changes SSH known_hosts state and needs host-key fingerprint review",
    "UserTasks/delete": "removes task queue entries and needs a task-management review",
}


def registry() -> PolicyRegistry:
    return PolicyRegistry.load(Catalog.load(), POLICY_PATH)


def test_security_policy_matches_review() -> None:
    subject = registry()

    assert subject.included_identities("security") == SECURITY_INCLUDED
    assert subject.get("security.block-ip").risk is Risk.MUTATE
    assert subject.get("security.unblock-ip").risk is Risk.MUTATE
    assert subject.get("security.disable-modsec-all").elevated_impact is True
    assert subject.get("security.block-ip").parameters["ip"].validator == "ip_cidr"
    assert subject.get("security.known-host-verify").parameters["port"].validator == "integer"
    for identity, reason in SECURITY_EXCLUDED.items():
        assert subject.exclusion(identity).reason == reason
