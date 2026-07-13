from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.confirmation import ConfirmationService
from cpanel_admin.errors import ConfigError, ConfirmationError


def test_digest_is_bound_to_normalized_operation() -> None:
    now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    service = ConfirmationService(Fernet.generate_key(), clock=lambda: now)
    plan = service.plan(
        "production",
        "databases.remove",
        {"name": "acct_db"},
        "Delete acct_db",
        "Restore a backup",
    )
    service.verify(
        plan.confirmation,
        "production",
        "databases.remove",
        {"name": "acct_db"},
        plan.expires_at,
    )
    with pytest.raises(ConfirmationError, match="does not match"):
        service.verify(
            plan.confirmation,
            "production",
            "databases.remove",
            {"name": "acct_other"},
            plan.expires_at,
        )


def test_expired_digest_is_rejected() -> None:
    now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    current = [now]
    service = ConfirmationService(Fernet.generate_key(), clock=lambda: current[0])
    plan = service.plan(
        "production",
        "ssl.remove",
        {"domain": "example.com"},
        "Remove SSL",
        "Reinstall certificate",
    )
    current[0] = now + timedelta(minutes=6)
    with pytest.raises(ConfirmationError, match="expired"):
        service.verify(
            plan.confirmation,
            "production",
            "ssl.remove",
            {"domain": "example.com"},
            plan.expires_at,
        )


def test_digest_is_stable_for_equivalent_mapping_order() -> None:
    now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    service = ConfirmationService(Fernet.generate_key(), clock=lambda: now)
    first = service.plan("p", "op", {"b": 2, "a": [True, "x"]}, "impact", "recovery")
    service.verify(
        first.confirmation,
        "p",
        "op",
        {"a": [True, "x"], "b": 2},
        first.expires_at,
    )


def test_missing_and_malformed_confirmation_values_are_safe() -> None:
    service = ConfirmationService(Fernet.generate_key())
    with pytest.raises(ConfirmationError, match="required"):
        service.verify(None, "p", "op", {}, None)
    with pytest.raises(ConfirmationError, match="expiry timestamp"):
        service.verify("0123456789ab", "p", "op", {}, "not-a-time")


def test_unsupported_parameter_type_is_rejected() -> None:
    service = ConfirmationService(Fernet.generate_key())
    with pytest.raises(ConfirmationError, match="JSON-compatible"):
        service.plan("p", "op", {"bad": object()}, "impact", "recovery")


def test_invalid_fernet_key_is_rejected() -> None:
    with pytest.raises(ConfigError, match="valid Fernet key"):
        ConfirmationService(b"not-a-key")
