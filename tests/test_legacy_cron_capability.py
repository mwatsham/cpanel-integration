from __future__ import annotations

from dataclasses import dataclass

import pytest

from cpanel_admin.errors import UsageError
from cpanel_admin.legacy_cron import (
    LEGACY_CRON_OPERATIONS,
    LegacyCronExecutor,
    resolve_legacy_cron_inputs,
    safe_legacy_cron_parameters,
)
from cpanel_admin.profiles import Profile
from cpanel_admin.transport import UAPIResponse


@dataclass
class API2Call:
    module: str
    function: str
    parameters: dict[str, object]


class FakeTransport:
    def __init__(self) -> None:
        self.api2_calls: list[API2Call] = []

    def call_api2(self, profile, token, module, function, parameters, timeout=30, **kwargs):
        del profile, token, timeout, kwargs
        self.api2_calls.append(API2Call(module, function, dict(parameters)))
        return UAPIResponse(data=[{"result": 1}], warnings=[], messages=[])


def profile() -> Profile:
    return Profile("test", "cpanel.example.test", 2083, "account", "encrypted")


def test_legacy_cron_operations_are_a_fixed_reviewed_allowlist() -> None:
    assert set(LEGACY_CRON_OPERATIONS) == {
        "cron.list",
        "cron.get-email",
        "cron.set-email",
        "cron.add",
        "cron.edit",
        "cron.remove",
    }
    assert LEGACY_CRON_OPERATIONS["cron.list"].requires_confirmation is False
    assert LEGACY_CRON_OPERATIONS["cron.add"].requires_confirmation is False
    assert LEGACY_CRON_OPERATIONS["cron.edit"].requires_confirmation is True
    assert LEGACY_CRON_OPERATIONS["cron.remove"].requires_confirmation is True


def test_resolve_legacy_cron_inputs_builds_fixed_add_payload() -> None:
    operation = LEGACY_CRON_OPERATIONS["cron.add"]

    resolved = resolve_legacy_cron_inputs(
        operation,
        {
            "minute": "*/15",
            "hour": "0,12",
            "day": "*",
            "month": "*",
            "weekday": "1-5",
            "command": "/usr/local/bin/php /home/account/public_html/artisan schedule:run",
        },
    )

    assert resolved == {
        "minute": "*/15",
        "hour": "0,12",
        "day": "*",
        "month": "*",
        "weekday": "1-5",
        "command": "/usr/local/bin/php /home/account/public_html/artisan schedule:run",
    }


def test_safe_legacy_cron_parameters_fingerprint_command_text() -> None:
    operation = LEGACY_CRON_OPERATIONS["cron.add"]
    parameters = resolve_legacy_cron_inputs(
        operation,
        {
            "minute": "0",
            "hour": "2",
            "day": "*",
            "month": "*",
            "weekday": "*",
            "command": "php /home/account/secret-token.php",
        },
    )

    safe = safe_legacy_cron_parameters(operation, parameters)

    assert safe["command"]["bytes"] == len("php /home/account/secret-token.php")
    assert len(safe["command"]["sha256"]) == 64
    assert "secret-token" not in str(safe)


@pytest.mark.parametrize(
    ("operation", "values", "message"),
    [
        (
            "cron.add",
            {
                "minute": "60",
                "hour": "0",
                "day": "*",
                "month": "*",
                "weekday": "*",
                "command": "php script.php",
            },
            "Invalid cron minute",
        ),
        (
            "cron.add",
            {
                "minute": "0",
                "hour": "24",
                "day": "*",
                "month": "*",
                "weekday": "*",
                "command": "php script.php",
            },
            "Invalid cron hour",
        ),
        (
            "cron.add",
            {
                "minute": "0 1",
                "hour": "*",
                "day": "*",
                "month": "*",
                "weekday": "*",
                "command": "php script.php",
            },
            "Invalid cron minute",
        ),
        (
            "cron.add",
            {
                "minute": "0",
                "hour": "*",
                "day": "*",
                "month": "*",
                "weekday": "*",
                "command": "php script.php\nrm -rf /",
            },
            "Cron command must be one line",
        ),
        (
            "cron.remove",
            {"linekey": "../not-a-line-key"},
            "Invalid cron line key",
        ),
    ],
)
def test_resolve_legacy_cron_inputs_rejects_unsafe_values(
    operation: str, values: dict[str, object], message: str
) -> None:
    with pytest.raises(UsageError, match=message):
        resolve_legacy_cron_inputs(LEGACY_CRON_OPERATIONS[operation], values)


def test_legacy_cron_executor_calls_api2_not_uapi() -> None:
    transport = FakeTransport()
    operation = LEGACY_CRON_OPERATIONS["cron.remove"]

    response = LegacyCronExecutor(transport).execute(
        profile(),
        "token",
        operation,
        {"linekey": "f32e3d460c179443e5f772359c7954ec"},
    )

    assert response.data == [{"result": 1}]
    assert transport.api2_calls == [
        API2Call(
            "Cron",
            "remove_line",
            {"linekey": "f32e3d460c179443e5f772359c7954ec"},
        )
    ]
