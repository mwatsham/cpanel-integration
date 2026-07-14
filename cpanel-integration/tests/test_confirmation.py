from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.confirmation import ConfirmationService
from cpanel_admin.errors import ConfigError, ConfirmationError


def test_v1_profile_removal_digest_is_bound_to_normalized_operation() -> None:
    now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    service = ConfirmationService(Fernet.generate_key(), clock=lambda: now)
    plan = service.plan(
        "production",
        "profiles.remove",
        {"host": "panel.example.test", "name": "production", "port": 2083, "username": "acct"},
        "Delete profile",
        "Recreate profile",
    )
    service.verify(
        plan.confirmation,
        "production",
        "profiles.remove",
        {"host": "panel.example.test", "name": "production", "port": 2083, "username": "acct"},
        plan.expires_at,
    )
    with pytest.raises(ConfirmationError, match="does not match"):
        service.verify(
            plan.confirmation,
            "production",
            "profiles.remove",
            {"host": "panel.example.test", "name": "production", "port": 2083, "username": "other"},
            plan.expires_at,
        )


def test_expired_digest_is_rejected() -> None:
    now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    current = [now]
    service = ConfirmationService(Fernet.generate_key(), clock=lambda: current[0])
    plan = service.plan(
        "production",
        "profiles.remove",
        {"name": "production", "host": "panel.example.test", "port": 2083, "username": "acct"},
        "Delete profile",
        "Recreate profile",
    )
    current[0] = now + timedelta(minutes=6)
    with pytest.raises(ConfirmationError, match="expired"):
        service.verify(
            plan.confirmation,
            "production",
            "profiles.remove",
            {"name": "production", "host": "panel.example.test", "port": 2083, "username": "acct"},
            plan.expires_at,
        )


def test_digest_is_stable_for_equivalent_mapping_order() -> None:
    now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    service = ConfirmationService(Fernet.generate_key(), clock=lambda: now)
    first = service.plan(
        "p",
        "profiles.remove",
        {"username": "u", "port": 2083, "host": "panel.example.test", "name": "p"},
        "impact",
        "recovery",
    )
    service.verify(
        first.confirmation,
        "p",
        "profiles.remove",
        {"name": "p", "host": "panel.example.test", "port": 2083, "username": "u"},
        first.expires_at,
    )


def test_missing_and_malformed_confirmation_values_are_safe() -> None:
    service = ConfirmationService(Fernet.generate_key())
    with pytest.raises(ConfirmationError, match="required"):
        service.verify(
            None,
            "p",
            "profiles.remove",
            {"name": "p", "host": "h", "port": 2083, "username": "u"},
            None,
        )
    with pytest.raises(ConfirmationError, match="expiry timestamp"):
        service.verify(
            "0123456789ab",
            "p",
            "profiles.remove",
            {"name": "p", "host": "h", "port": 2083, "username": "u"},
            "not-a-time",
        )


def test_unsupported_parameter_type_is_rejected() -> None:
    service = ConfirmationService(Fernet.generate_key())
    with pytest.raises(ConfirmationError, match="JSON-compatible"):
        service.plan(
            "p",
            "profiles.remove",
            {"name": "p", "host": object(), "port": 2083, "username": "u"},
            "impact",
            "recovery",
        )


def test_invalid_fernet_key_is_rejected() -> None:
    with pytest.raises(ConfigError, match="valid Fernet key"):
        ConfirmationService(b"not-a-key")


def test_v1_confirmation_rejects_generalized_operations() -> None:
    service = ConfirmationService(Fernet.generate_key())

    with pytest.raises(ConfirmationError, match=r"only supports profiles\.remove"):
        service.plan("production", "databases.remove", {"name": "acct_db"}, "Delete", "Restore")


def test_v2_digest_binds_account_identity_preflight_and_policy() -> None:
    now = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    service = ConfirmationService(Fernet.generate_key(), clock=lambda: now)
    plan = service.plan_v2(
        profile="production",
        account="acct",
        identity="Fileman/save_file_content",
        operation="files.write",
        parameters={"directory": "public_html", "content": {"sha256": "a", "bytes": 1}},
        preflight={"etag": "stable"},
        policy_digest="reviewed-policy",
        policy_version="1",
    )

    service.verify_v2(
        plan.confirmation,
        profile="production",
        account="acct",
        identity="Fileman/save_file_content",
        operation="files.write",
        parameters={"directory": "public_html", "content": {"bytes": 1, "sha256": "a"}},
        preflight={"etag": "stable"},
        policy_digest="reviewed-policy",
        policy_version="1",
        expires_at=plan.expires_at,
    )
    with pytest.raises(ConfirmationError, match="does not match"):
        service.verify_v2(
            plan.confirmation,
            profile="production",
            account="acct",
            identity="Fileman/save_file_content",
            operation="files.write",
            parameters={"directory": "public_html", "content": {"bytes": 1, "sha256": "a"}},
            preflight={"etag": "changed"},
            policy_digest="reviewed-policy",
            policy_version="2",
            expires_at=plan.expires_at,
        )
