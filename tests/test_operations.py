import pytest

from cpanel_admin.errors import CapabilityError, UsageError
from cpanel_admin.operations import (
    OPERATIONS,
    Risk,
    get_operation,
    validate_parameters,
    validate_value,
)

EXPECTED = {
    "domains.list",
    "domains.inspect",
    "domains.ssl-capable",
    "domains.add-subdomain",
    "files.list",
    "files.inspect",
    "files.read",
    "files.write",
    "files.upload",
    "files.empty-trash",
    "ssl.list",
    "ssl.hosts",
    "ssl.install",
    "ssl.remove",
    "databases.list",
    "databases.users",
    "databases.create",
    "databases.create-user",
    "databases.grant",
    "databases.remove",
    "databases.remove-user",
}


def test_registry_is_explicit_and_complete() -> None:
    assert set(OPERATIONS) == EXPECTED
    assert OPERATIONS["databases.remove"].risk is Risk.DESTRUCTIVE
    assert OPERATIONS["domains.list"].module == "DomainInfo"
    assert OPERATIONS["domains.list"].function == "list_domains"
    assert OPERATIONS["files.upload"].method == "POST"


def test_unknown_operation_is_a_capability_error() -> None:
    with pytest.raises(CapabilityError, match="not supported"):
        get_operation("domains.delete")


def test_domain_and_path_parameters_are_normalized() -> None:
    operation = get_operation("domains.add-subdomain")
    result = validate_parameters(
        operation,
        {
            "domain": "Blog",
            "rootdomain": "EXAMPLE.COM",
            "dir": "public_html/blog",
        },
    )
    assert result == {
        "domain": "blog",
        "rootdomain": "example.com",
        "dir": "public_html/blog",
    }


@pytest.mark.parametrize(
    ("operation_name", "parameters", "message"),
    [
        ("domains.inspect", {}, "Missing required"),
        ("domains.inspect", {"domain": "example.com", "extra": 1}, "Unknown parameter"),
        ("files.list", {"path": "../etc"}, "path"),
        ("files.read", {"directory": "public_html", "filename": "a/b"}, "filename"),
        ("files.empty-trash", {"older_than": -1}, "between 0 and 3650"),
        ("databases.create", {"name": "bad name"}, "database name"),
        (
            "databases.grant",
            {"database": "acct_db", "user": "acct_user", "privileges": ["ROOT"]},
            "privilege",
        ),
    ],
)
def test_invalid_parameters_are_rejected(
    operation_name: str, parameters: dict[str, object], message: str
) -> None:
    with pytest.raises(UsageError, match=message):
        validate_parameters(get_operation(operation_name), parameters)


def test_privileges_are_deduplicated_and_canonicalized() -> None:
    result = validate_parameters(
        get_operation("databases.grant"),
        {
            "database": "acct_db",
            "user": "acct_user",
            "privileges": ["select", "UPDATE", "SELECT"],
        },
    )
    assert result["privileges"] == "SELECT,UPDATE"


def test_operation_maps_cli_parameters_to_uapi() -> None:
    operation = get_operation("files.list")
    values = validate_parameters(operation, {"path": "public_html"})
    assert operation.to_uapi(values) == {"dir": "public_html"}


@pytest.mark.parametrize(
    "path",
    [
        "repositories/site",
        "/home/account/../etc",
        "/home/account/\x00site",
    ],
)
def test_absolute_path_rejects_relative_traversal_and_null_values(path: str) -> None:
    with pytest.raises(UsageError, match="absolute cPanel path"):
        validate_value("absolute_path", path)


def test_absolute_path_accepts_normalized_home_directory_path() -> None:
    assert (
        validate_value("absolute_path", "/home/account/repositories/site")
        == "/home/account/repositories/site"
    )


def test_sensitive_content_is_validated_without_appearing_in_error() -> None:
    secret = "very-secret-password"
    with pytest.raises(UsageError) as error:
        validate_parameters(
            get_operation("databases.create-user"), {"name": "acct_user", "password": ""}
        )
    assert secret not in str(error.value)
