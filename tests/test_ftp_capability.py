from __future__ import annotations

from pathlib import Path

from cpanel_admin.catalog import Catalog
from cpanel_admin.policy import PolicyRegistry, Risk

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "policy" / "operations.json"

FTP_INCLUDED = {
    "Ftp/add_ftp",
    "Ftp/allows_anonymous_ftp",
    "Ftp/allows_anonymous_ftp_incoming",
    "Ftp/delete_ftp",
    "Ftp/ftp_exists",
    "Ftp/get_ftp_daemon_info",
    "Ftp/get_port",
    "Ftp/get_quota",
    "Ftp/get_welcome_message",
    "Ftp/kill_session",
    "Ftp/list_ftp",
    "Ftp/list_ftp_with_disk",
    "Ftp/list_sessions",
    "Ftp/passwd",
    "Ftp/server_name",
    "Ftp/set_homedir",
    "Ftp/set_quota",
    "Ftp/set_welcome_message",
}
FTP_EXCLUDED = {
    "Ftp/set_anonymous_ftp": "anonymous FTP access changes are too broad for default automation",
    "Ftp/set_anonymous_ftp_incoming": (
        "anonymous incoming FTP transfer changes are too broad for default automation"
    ),
}


def registry() -> PolicyRegistry:
    return PolicyRegistry.load(Catalog.load(), POLICY_PATH)


def test_ftp_policy_matches_review() -> None:
    subject = registry()

    assert subject.included_identities("ftp") == FTP_INCLUDED
    assert subject.get("ftp.create").parameters["password"].secret is True
    assert subject.get("ftp.create").parameters["password"].uapi_name == "pass"
    assert subject.get("ftp.set-password").parameters["password"].secret is True
    assert subject.get("ftp.delete").risk is Risk.DESTRUCTIVE
    assert subject.get("ftp.kill-session").elevated_impact is True
    for identity, reason in FTP_EXCLUDED.items():
        assert subject.exclusion(identity).reason == reason
