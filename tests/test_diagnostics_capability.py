from __future__ import annotations

from pathlib import Path

from cpanel_admin.catalog import Catalog
from cpanel_admin.policy import PolicyRegistry, Risk

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "policy" / "operations.json"

DIAGNOSTICS_INCLUDED = {
    "AccountEnhancements/has_enhancement",
    "AccountEnhancements/list",
    "Bandwidth/get_enabled_protocols",
    "Bandwidth/get_retention_periods",
    "Bandwidth/query",
    "Chkservd/get_exim_ports",
    "Chkservd/get_exim_ports_ssl",
    "Features/get_feature_metadata",
    "Features/has_feature",
    "Features/has_features_like",
    "Features/list_features",
    "Features/list_features_like",
    "LastLogin/get_last_or_current_logged_in_ip",
    "LogManager/get_settings",
    "LogManager/list_archives",
    "Quota/get_local_quota_info",
    "Quota/get_quota_info",
    "ResourceUsage/get_usages",
    "ServerInformation/get_information",
    "Stats/get_bandwidth",
    "Stats/get_site_errors",
    "Stats/get_stats_daily",
    "Stats/list_sites",
    "Stats/list_stats_by_domain",
    "StatsBar/get_stats",
    "StatsManager/get_configuration",
    "Variables/get_server_information",
    "Variables/get_session_information",
    "Variables/get_user_information",
}
DIAGNOSTICS_EXCLUDED = {
    "LogManager/delete_archive": (
        "deletes archived logs and needs a destructive log-management review"
    ),
    "LogManager/set_settings": "changes log retention settings and needs a log-management review",
    "StatsManager/save_configuration": (
        "changes weblog analyzer configuration and needs a diagnostics settings review"
    ),
}


def registry() -> PolicyRegistry:
    return PolicyRegistry.load(Catalog.load(), POLICY_PATH)


def test_diagnostics_policy_matches_review() -> None:
    subject = registry()

    assert subject.included_identities("diagnostics") == DIAGNOSTICS_INCLUDED
    assert all(
        subject.get(operation.name).risk is Risk.READ
        for operation in subject.included()
        if operation.capability == "diagnostics"
    )
    assert subject.get("diagnostics.bandwidth-query").parameters["grouping"].required is True
    assert subject.get("diagnostics.site-errors").parameters["domain"].validator == "domain"
    for identity, reason in DIAGNOSTICS_EXCLUDED.items():
        assert subject.exclusion(identity).reason == reason
