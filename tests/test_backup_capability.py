from __future__ import annotations

from pathlib import Path

from cpanel_admin.catalog import Catalog
from cpanel_admin.policy import PolicyRegistry, Risk

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "policy" / "operations.json"

BACKUP_INCLUDED = {
    "Backup/fullbackup_to_homedir",
    "Backup/list_backups",
    "Restore/directory_listing",
    "Restore/get_users",
    "Restore/query_file_info",
}
BACKUP_EXCLUDED = {
    "Backup/fullbackup_to_ftp": "remote FTP backup requires protected destination secret handling",
    "Backup/fullbackup_to_scp_with_key": (
        "remote SCP key backup requires key and passphrase handling"
    ),
    "Backup/fullbackup_to_scp_with_password": (
        "remote SCP password backup requires protected destination secret handling"
    ),
    "Backup/restore_databases": "database restore is destructive and needs archive preflight",
    "Backup/restore_email_filters": (
        "email filter restore is destructive and needs archive preflight"
    ),
    "Backup/restore_email_forwarders": (
        "email forwarder restore is destructive and needs archive preflight"
    ),
    "Backup/restore_files": "file restore is destructive and needs archive and overwrite preflight",
    "Restore/restore_file": "file restore is destructive and needs archive and overwrite preflight",
}


def registry() -> PolicyRegistry:
    return PolicyRegistry.load(Catalog.load(), POLICY_PATH)


def test_backup_policy_matches_review() -> None:
    subject = registry()

    assert subject.included_identities("backups") == BACKUP_INCLUDED
    assert subject.get("backups.list").risk is Risk.READ
    assert subject.get("backups.full-to-home").risk is Risk.MUTATE
    assert subject.get("backups.full-to-home").elevated_impact is True
    assert subject.get("backups.directory").parameters["path"].validator == "path"
    assert subject.get("backups.file-info").parameters["exists"].validator == "integer"
    for identity, reason in BACKUP_EXCLUDED.items():
        assert subject.exclusion(identity).reason == reason
