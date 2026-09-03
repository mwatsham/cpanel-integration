from __future__ import annotations

from pathlib import Path

from cpanel_admin.catalog import Catalog
from cpanel_admin.policy import InputSource, PolicyRegistry, Risk

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "policy" / "operations.json"

FILES_INCLUDED = {
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
    "Fileman/autocompletedir",
    "Fileman/empty_trash",
    "Fileman/get_file_content",
    "Fileman/get_file_information",
    "Fileman/list_files",
    "Fileman/save_file_content",
    "Fileman/upload_files",
}
FILES_EXCLUDED = {
    "Fileman/transcode": "encoding transforms need an explicit charset/content review",
}


def registry() -> PolicyRegistry:
    return PolicyRegistry.load(Catalog.load(), POLICY_PATH)


def test_files_policy_includes_reviewed_directory_administration() -> None:
    subject = registry()

    assert subject.included_identities("files") == FILES_INCLUDED
    assert subject.get("files.autocomplete").risk is Risk.READ
    assert subject.get("files.directory-indexing").risk is Risk.READ
    assert subject.get("files.directory-indexing-list").risk is Risk.READ
    assert subject.get("files.set-directory-indexing").risk is Risk.MUTATE
    assert subject.get("files.directory-privacy-status").risk is Risk.READ
    assert subject.get("files.directory-privacy-list").risk is Risk.READ
    assert subject.get("files.directory-privacy-users").risk is Risk.READ
    assert subject.get("files.directory-protection-list").risk is Risk.READ
    assert subject.get("files.protect-directory").risk is Risk.MUTATE
    assert subject.get("files.protect-directory").elevated_impact is True
    add_user = subject.get("files.add-directory-user")
    assert add_user.risk is Risk.MUTATE
    assert add_user.parameters["password"].sources == (InputSource.STDIN,)
    assert add_user.parameters["password"].secret is True
    assert subject.get("files.delete-directory-user").risk is Risk.MUTATE
    assert subject.get("files.delete-directory-user").elevated_impact is True
    for identity, reason in FILES_EXCLUDED.items():
        assert subject.exclusion(identity).reason == reason
