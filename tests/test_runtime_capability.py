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
    "NginxCaching/clear_cache",
    "NginxCaching/disable_cache",
    "NginxCaching/enable_cache",
    "NginxCaching/reset_cache_config",
    "PassengerApps/list_applications",
    "VersionControl/retrieve",
    "VersionControlDeployment/retrieve",
}
RUNTIME_EXCLUDED = {
    "LangPHP/php_ini_set_user_basic_directives": (
        "PHP directive writes need a structured directive adapter"
    ),
    "LangPHP/php_ini_set_user_content": "raw php.ini writes need protected content input review",
    "LangPHP/php_set_vhost_versions": "PHP version changes need domain impact preflight",
    "PassengerApps/disable_application": "Passenger lifecycle changes need app-state preflight",
    "PassengerApps/edit_application": "Passenger edits need structured app and env var adapters",
    "PassengerApps/enable_application": "Passenger lifecycle changes need app-state preflight",
    "PassengerApps/ensure_deps": "dependency installation can execute package manager code",
    "PassengerApps/register_application": "Passenger registration needs path and env var adapters",
    "PassengerApps/unregister_application": "Passenger removal needs app-state preflight",
    "VersionControl/create": "Git repository creation needs source repository adapter review",
    "VersionControl/delete": (
        "Git repository deletion is destructive and needs repository preflight"
    ),
    "VersionControl/update": "Git repository updates need source repository adapter review",
    "VersionControlDeployment/create": "deployment task creation needs repository state preflight",
    "VersionControlDeployment/delete": "deployment task deletion needs task-state preflight",
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
    assert subject.get("runtime.version-control").parameters["fields"].required is False
    for identity, reason in RUNTIME_EXCLUDED.items():
        assert subject.exclusion(identity).reason == reason
