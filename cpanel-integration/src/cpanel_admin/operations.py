"""Fixed cPanel UAPI operation registry and parameter validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from .errors import CapabilityError, UsageError

MAX_TEXT_BYTES = 10 * 1024 * 1024
MAX_PEM_BYTES = 1024 * 1024
DATABASE_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
SUBDOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

MYSQL_PRIVILEGES = frozenset(
    {
        "ALL PRIVILEGES",
        "ALTER",
        "ALTER ROUTINE",
        "CREATE",
        "CREATE ROUTINE",
        "CREATE TEMPORARY TABLES",
        "CREATE VIEW",
        "DELETE",
        "DROP",
        "EVENT",
        "EXECUTE",
        "INDEX",
        "INSERT",
        "LOCK TABLES",
        "REFERENCES",
        "SELECT",
        "SHOW VIEW",
        "TRIGGER",
        "UPDATE",
    }
)


class Risk(StrEnum):
    READ = "read"
    MUTATE = "mutate"
    DESTRUCTIVE = "destructive"


class Kind(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    PATH = "path"
    FILENAME = "filename"
    DATABASE = "database"
    SECRET = "secret"
    CONTENT = "content"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    PRIVILEGES = "privileges"
    TRASH_AGE = "trash_age"
    LOCAL_FILE = "local_file"


@dataclass(frozen=True)
class Parameter:
    kind: Kind
    required: bool = True
    uapi_name: str | None = None
    local_only: bool = False


@dataclass(frozen=True)
class Operation:
    name: str
    module: str
    function: str
    risk: Risk
    parameters: dict[str, Parameter] = field(default_factory=dict)
    method: str = "GET"
    impact: str = "Apply cPanel account change"
    recovery: str = "Reverse the change through a separately verified operation"

    def to_uapi(self, values: dict[str, object]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in values.items():
            parameter = self.parameters[name]
            if not parameter.local_only:
                result[parameter.uapi_name or name] = value
        return result


def _parameters(**values: Parameter) -> dict[str, Parameter]:
    return values


OPERATIONS: dict[str, Operation] = {
    "domains.list": Operation("domains.list", "DomainInfo", "list_domains", Risk.READ),
    "domains.inspect": Operation(
        "domains.inspect",
        "DomainInfo",
        "single_domain_data",
        Risk.READ,
        _parameters(domain=Parameter(Kind.DOMAIN)),
    ),
    "domains.ssl-capable": Operation(
        "domains.ssl-capable", "WebVhosts", "list_ssl_capable_domains", Risk.READ
    ),
    "domains.add-subdomain": Operation(
        "domains.add-subdomain",
        "SubDomain",
        "addsubdomain",
        Risk.MUTATE,
        _parameters(
            domain=Parameter(Kind.SUBDOMAIN),
            rootdomain=Parameter(Kind.DOMAIN),
            dir=Parameter(Kind.PATH),
        ),
        impact="Create a subdomain and document root mapping",
        recovery=(
            "Remove the subdomain manually in cPanel if no documented UAPI removal is available"
        ),
    ),
    "files.list": Operation(
        "files.list",
        "Fileman",
        "list_files",
        Risk.READ,
        _parameters(path=Parameter(Kind.PATH, uapi_name="dir")),
    ),
    "files.inspect": Operation(
        "files.inspect",
        "Fileman",
        "get_file_information",
        Risk.READ,
        _parameters(path=Parameter(Kind.PATH)),
    ),
    "files.read": Operation(
        "files.read",
        "Fileman",
        "get_file_content",
        Risk.READ,
        _parameters(
            directory=Parameter(Kind.PATH, uapi_name="dir"),
            filename=Parameter(Kind.FILENAME, uapi_name="file"),
        ),
    ),
    "files.write": Operation(
        "files.write",
        "Fileman",
        "save_file_content",
        Risk.DESTRUCTIVE,
        _parameters(
            directory=Parameter(Kind.PATH, uapi_name="dir"),
            filename=Parameter(Kind.FILENAME, uapi_name="file"),
            content=Parameter(Kind.CONTENT),
        ),
        method="POST",
        impact="Create or overwrite a remote file",
        recovery="Restore the previous file from an independently verified backup",
    ),
    "files.upload": Operation(
        "files.upload",
        "Fileman",
        "upload_files",
        Risk.DESTRUCTIVE,
        _parameters(
            directory=Parameter(Kind.PATH, uapi_name="dir"),
            source=Parameter(Kind.LOCAL_FILE, local_only=True),
        ),
        method="POST",
        impact="Upload a local file and potentially overwrite a same-named remote file",
        recovery="Restore the previous remote file from an independently verified backup",
    ),
    "files.empty-trash": Operation(
        "files.empty-trash",
        "Fileman",
        "empty_trash",
        Risk.DESTRUCTIVE,
        _parameters(older_than=Parameter(Kind.TRASH_AGE)),
        impact="Permanently purge files from the cPanel trash",
        recovery="No automatic recovery; restore from an independent backup",
    ),
    "ssl.list": Operation("ssl.list", "SSL", "list_certs", Risk.READ),
    "ssl.hosts": Operation("ssl.hosts", "SSL", "installed_hosts", Risk.READ),
    "ssl.install": Operation(
        "ssl.install",
        "SSL",
        "install_ssl",
        Risk.DESTRUCTIVE,
        _parameters(
            domain=Parameter(Kind.DOMAIN),
            certificate=Parameter(Kind.CERTIFICATE, uapi_name="cert"),
            private_key=Parameter(Kind.PRIVATE_KEY, uapi_name="key"),
            cabundle=Parameter(Kind.CERTIFICATE, required=False),
        ),
        method="POST",
        impact="Install or replace SSL coverage for a domain",
        recovery="Reinstall the previous certificate, key, and CA bundle",
    ),
    "ssl.remove": Operation(
        "ssl.remove",
        "SSL",
        "delete_ssl",
        Risk.DESTRUCTIVE,
        _parameters(domain=Parameter(Kind.DOMAIN)),
        impact="Remove SSL coverage from a domain",
        recovery="Reinstall a valid certificate and private key",
    ),
    "databases.list": Operation("databases.list", "Mysql", "list_databases", Risk.READ),
    "databases.users": Operation("databases.users", "Mysql", "list_users", Risk.READ),
    "databases.create": Operation(
        "databases.create",
        "Mysql",
        "create_database",
        Risk.MUTATE,
        _parameters(name=Parameter(Kind.DATABASE)),
        impact="Create a MySQL or MariaDB database",
        recovery="Remove the newly created empty database",
    ),
    "databases.create-user": Operation(
        "databases.create-user",
        "Mysql",
        "create_user",
        Risk.MUTATE,
        _parameters(
            name=Parameter(Kind.DATABASE),
            password=Parameter(Kind.SECRET),
        ),
        method="POST",
        impact="Create a database user",
        recovery="Remove the newly created database user",
    ),
    "databases.grant": Operation(
        "databases.grant",
        "Mysql",
        "set_privileges_on_database",
        Risk.MUTATE,
        _parameters(
            database=Parameter(Kind.DATABASE),
            user=Parameter(Kind.DATABASE),
            privileges=Parameter(Kind.PRIVILEGES),
        ),
        impact="Replace a database user's privileges",
        recovery="Restore the previous privilege set",
    ),
    "databases.remove": Operation(
        "databases.remove",
        "Mysql",
        "delete_database",
        Risk.DESTRUCTIVE,
        _parameters(name=Parameter(Kind.DATABASE)),
        impact="Permanently delete a database",
        recovery="Restore the database from an independently verified backup",
    ),
    "databases.remove-user": Operation(
        "databases.remove-user",
        "Mysql",
        "delete_user",
        Risk.DESTRUCTIVE,
        _parameters(name=Parameter(Kind.DATABASE)),
        impact="Permanently delete a database user",
        recovery="Recreate the user and restore its grants",
    ),
}


def get_operation(name: str) -> Operation:
    try:
        return OPERATIONS[name]
    except KeyError as exc:
        raise CapabilityError(f"cPanel operation {name!r} is not supported by this MVP") from exc


def _domain(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise UsageError("Invalid domain name")
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UsageError("Invalid domain name") from exc
    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        )
    ):
        raise UsageError("Invalid domain name")
    return domain


def _subdomain(value: object) -> str:
    if not isinstance(value, str) or not SUBDOMAIN_RE.fullmatch(value):
        raise UsageError("Invalid subdomain label")
    return value.lower()


def _path(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\0" in value:
        raise UsageError("Invalid cPanel path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or len(value) > 4096:
        raise UsageError("Invalid cPanel path; use a relative path without '..'")
    return str(path)


def _filename(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or len(value) > 255
        or any(character in value for character in "/\\\0")
    ):
        raise UsageError("Invalid filename")
    return value


def _database(value: object) -> str:
    if not isinstance(value, str) or not DATABASE_RE.fullmatch(value):
        raise UsageError("Invalid database name or user name")
    return value


def _bounded_text(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value:
        raise UsageError(f"{label} must not be empty")
    if len(value.encode("utf-8")) > maximum:
        raise UsageError(f"{label} exceeds the allowed size")
    return value


def _certificate(value: object) -> str:
    content = _bounded_text(value, label="Certificate content", maximum=MAX_PEM_BYTES)
    if "-----BEGIN CERTIFICATE-----" not in content or "-----END CERTIFICATE-----" not in content:
        raise UsageError("Certificate content is not PEM encoded")
    return content


def _private_key(value: object) -> str:
    content = _bounded_text(value, label="Private key content", maximum=MAX_PEM_BYTES)
    if "PRIVATE KEY-----" not in content:
        raise UsageError("Private key content is not PEM encoded")
    return content


def _privileges(value: object) -> str:
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, list | tuple):
        items = value
    else:
        raise UsageError("Database privileges must be a comma-separated list")
    normalized = sorted({str(item).strip().upper() for item in items if str(item).strip()})
    if not normalized or any(item not in MYSQL_PRIVILEGES for item in normalized):
        raise UsageError("Invalid database privilege")
    if "ALL PRIVILEGES" in normalized and len(normalized) != 1:
        raise UsageError("ALL PRIVILEGES cannot be combined with individual privileges")
    return ",".join(normalized)


def _normalize(kind: Kind, value: object) -> object:
    validators: dict[Kind, Any] = {
        Kind.DOMAIN: _domain,
        Kind.SUBDOMAIN: _subdomain,
        Kind.PATH: _path,
        Kind.FILENAME: _filename,
        Kind.DATABASE: _database,
        Kind.SECRET: lambda item: _bounded_text(item, label="Secret", maximum=4096),
        Kind.CONTENT: lambda item: _bounded_text(
            item, label="File content", maximum=MAX_TEXT_BYTES
        ),
        Kind.CERTIFICATE: _certificate,
        Kind.PRIVATE_KEY: _private_key,
        Kind.PRIVILEGES: _privileges,
        Kind.LOCAL_FILE: lambda item: _bounded_text(item, label="Local file path", maximum=4096),
    }
    if kind is Kind.TRASH_AGE:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 3650:
            raise UsageError("Trash age must be between 0 and 3650 days")
        return value
    return validators[kind](value)


def validate_parameters(operation: Operation, values: dict[str, object]) -> dict[str, object]:
    unknown = sorted(set(values) - set(operation.parameters))
    if unknown:
        raise UsageError(f"Unknown parameter for {operation.name}: {', '.join(unknown)}")
    missing = sorted(
        name
        for name, parameter in operation.parameters.items()
        if parameter.required and (name not in values or values[name] is None)
    )
    if missing:
        raise UsageError(f"Missing required parameter for {operation.name}: {', '.join(missing)}")
    normalized: dict[str, object] = {}
    for name, value in values.items():
        if value is None and not operation.parameters[name].required:
            continue
        normalized[name] = _normalize(operation.parameters[name].kind, value)
    return normalized
