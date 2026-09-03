from __future__ import annotations

from dataclasses import dataclass

import pytest

from cpanel_admin.errors import UsageError
from cpanel_admin.legacy_api2 import (
    LEGACY_FILE_OPERATIONS,
    LegacyFileExecutor,
    resolve_legacy_file_inputs,
)
from cpanel_admin.operations import validate_value
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


def test_legacy_file_operations_are_a_fixed_reviewed_allowlist() -> None:
    assert set(LEGACY_FILE_OPERATIONS) == {
        "files.create-directory",
        "files.delete-path",
        "files.rename-path",
        "files.copy-path",
        "files.move-path",
        "files.chmod-path",
        "files.compress",
        "files.extract",
    }
    assert LEGACY_FILE_OPERATIONS["files.delete-path"].requires_confirmation is True
    assert LEGACY_FILE_OPERATIONS["files.chmod-path"].requires_confirmation is True
    assert LEGACY_FILE_OPERATIONS["files.compress"].api2_parameters["op"] == "compress"
    assert LEGACY_FILE_OPERATIONS["files.extract"].api2_parameters["op"] == "extract"


@pytest.mark.parametrize("value", ["0644", "0755", "0700", "644", "755"])
def test_permission_validator_accepts_octal_modes(value: str) -> None:
    assert validate_value("permissions", value) == value.zfill(4)


@pytest.mark.parametrize("value", ["888", "abcd", "17777", "", "06449"])
def test_permission_validator_rejects_invalid_modes(value: str) -> None:
    with pytest.raises(UsageError, match="permissions"):
        validate_value("permissions", value)


def test_resolve_legacy_inputs_builds_fixed_fileop_payload() -> None:
    operation = LEGACY_FILE_OPERATIONS["files.chmod-path"]

    resolved = resolve_legacy_file_inputs(
        operation,
        {
            "source": "public_html/index.php",
            "permissions": "644",
        },
    )

    assert resolved == {
        "op": "chmod",
        "sourcefiles": "public_html/index.php",
        "metadata": "0644",
        "doubledecode": 0,
    }


@pytest.mark.parametrize(
    ("operation", "values", "message"),
    [
        (
            "files.chmod-path",
            {"source": "../outside", "permissions": "0644"},
            "Invalid cPanel path",
        ),
        (
            "files.compress",
            {
                "source": "public_html/assets",
                "destination": "public_html/assets.rar",
                "archive_type": "rar",
            },
            "Invalid archive type",
        ),
        ("files.extract", {"source": "public_html/assets.zip"}, "Missing legacy file parameter"),
    ],
)
def test_resolve_legacy_inputs_rejects_unsafe_values(
    operation: str, values: dict[str, object], message: str
) -> None:
    with pytest.raises(UsageError, match=message):
        resolve_legacy_file_inputs(LEGACY_FILE_OPERATIONS[operation], values)


def test_legacy_file_executor_calls_api2_not_uapi() -> None:
    transport = FakeTransport()
    operation = LEGACY_FILE_OPERATIONS["files.create-directory"]

    response = LegacyFileExecutor(transport).execute(
        profile(),
        "token",
        operation,
        {"directory": "public_html", "name": "assets", "permissions": "0755"},
    )

    assert response.data == [{"result": 1}]
    assert transport.api2_calls == [
        API2Call(
            "Fileman",
            "mkdir",
            {"path": "public_html", "name": "assets", "permissions": "0755"},
        )
    ]
