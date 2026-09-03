from __future__ import annotations

from pathlib import Path

from cpanel_admin.catalog import Catalog
from cpanel_admin.policy import PolicyRegistry, Risk

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "policy" / "operations.json"

RUNTIME_INCLUDED = {
    "LangPHP/php_get_domain_handler",
    "LangPHP/php_get_impacted_domains",
    "LangPHP/php_get_installed_versions",
    "LangPHP/php_get_system_default_version",
    "LangPHP/php_get_vhost_versions",
    "LangPHP/php_ini_get_user_basic_directives",
    "LangPHP/php_ini_get_user_content",
    "LangPHP/php_ini_get_user_paths",
    "LangPHP/php_ini_set_user_basic_directives",
    "LangPHP/php_ini_set_user_content",
    "LangPHP/php_set_vhost_versions",
    "NginxCaching/clear_cache",
    "NginxCaching/disable_cache",
    "NginxCaching/enable_cache",
    "NginxCaching/reset_cache_config",
    "PassengerApps/list_applications",
    "VersionControl/create",
    "VersionControl/delete",
    "VersionControl/retrieve",
    "VersionControl/update",
    "VersionControlDeployment/create",
    "VersionControlDeployment/delete",
    "VersionControlDeployment/retrieve",
}
RUNTIME_EXCLUDED = {
    "PassengerApps/disable_application": "Passenger lifecycle changes need app-state preflight",
    "PassengerApps/edit_application": "Passenger edits need structured app and env var adapters",
    "PassengerApps/enable_application": "Passenger lifecycle changes need app-state preflight",
    "PassengerApps/ensure_deps": "dependency installation can execute package manager code",
    "PassengerApps/register_application": "Passenger registration needs path and env var adapters",
    "PassengerApps/unregister_application": "Passenger removal needs app-state preflight",
}


def registry() -> PolicyRegistry:
    return PolicyRegistry.load(Catalog.load(), POLICY_PATH)


def test_runtime_policy_matches_review() -> None:
    subject = registry()

    assert subject.included_identities("runtime") == RUNTIME_INCLUDED
    assert subject.get("runtime.php-installed").risk is Risk.READ
    assert subject.get("runtime.nginx-clear-cache").risk is Risk.MUTATE
    assert subject.get("runtime.nginx-reset-cache").elevated_impact is True
    assert subject.get("runtime.php-domain-handler").parameters["type"].required is True
    assert subject.get("runtime.php-set-vhost-version").risk is Risk.MUTATE
    assert subject.get("runtime.php-set-vhost-version").elevated_impact is True
    assert subject.get("runtime.php-set-directives").risk is Risk.MUTATE
    assert (
        subject.get("runtime.php-set-directives").parameters["directive"].sensitive_output is True
    )
    assert subject.get("runtime.php-set-ini-content").risk is Risk.MUTATE
    assert subject.get("runtime.php-set-ini-content").elevated_impact is True
    assert subject.get("runtime.version-control").parameters["fields"].required is False
    assert subject.get("runtime.git-create").risk is Risk.MUTATE
    assert subject.get("runtime.git-create").parameters["source_repository"].required is False
    assert (
        subject.get("runtime.git-create").parameters["repository_root"].validator == "absolute_path"
    )
    assert subject.get("runtime.git-update").risk is Risk.MUTATE
    assert (
        subject.get("runtime.git-update").parameters["repository_root"].validator == "absolute_path"
    )
    assert subject.get("runtime.git-delete").risk is Risk.MUTATE
    assert (
        subject.get("runtime.git-delete").parameters["repository_root"].validator == "absolute_path"
    )
    assert subject.get("runtime.git-delete").elevated_impact is True
    assert subject.get("runtime.deployment-create").risk is Risk.MUTATE
    assert (
        subject.get("runtime.deployment-create").parameters["repository_root"].validator
        == "absolute_path"
    )
    assert subject.get("runtime.deployment-delete").risk is Risk.MUTATE
    assert subject.get("runtime.deployment-delete").elevated_impact is True
    for identity, reason in RUNTIME_EXCLUDED.items():
        assert subject.exclusion(identity).reason == reason
