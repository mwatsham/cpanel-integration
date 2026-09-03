"""Narrow, reviewed cPanel API 2 bridge for Fileman operations missing from UAPI."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from .errors import UsageError
from .operations import validate_value
from .profiles import Profile
from .transport import UAPIResponse

ARCHIVE_TYPES = frozenset({"zip", "tar.gz", "tar.bz2", "tar", "gz", "bz2"})


class API2TransportLike(Protocol):
    def call_api2(
        self,
        profile: Profile,
        token: str,
        module: str,
        function: str,
        parameters: Mapping[str, object],
        timeout: int = 30,
        **kwargs: object,
    ) -> UAPIResponse: ...


@dataclass(frozen=True)
class LegacyFileOperation:
    name: str
    command: tuple[str, ...]
    module: str
    function: str
    risk: str
    elevated_impact: bool
    impact: str
    recovery: str
    fields: Mapping[str, str]
    required: tuple[str, ...]
    api2_parameters: Mapping[str, object]

    @property
    def identity(self) -> str:
        return f"cpanel-api-2/{self.module}/{self.function}"

    @property
    def requires_confirmation(self) -> bool:
        return self.risk == "destructive" or self.elevated_impact


def _operation(
    name: str,
    action: str,
    function: str,
    *,
    risk: str = "mutate",
    elevated_impact: bool = True,
    impact: str,
    recovery: str,
    fields: Mapping[str, str],
    required: tuple[str, ...],
    api2_parameters: Mapping[str, object] | None = None,
) -> LegacyFileOperation:
    return LegacyFileOperation(
        name=name,
        command=("files", action),
        module="Fileman",
        function=function,
        risk=risk,
        elevated_impact=elevated_impact,
        impact=impact,
        recovery=recovery,
        fields=MappingProxyType(dict(fields)),
        required=required,
        api2_parameters=MappingProxyType(dict(api2_parameters or {})),
    )


LEGACY_FILE_OPERATIONS = MappingProxyType(
    {
        "files.create-directory": _operation(
            "files.create-directory",
            "create-directory",
            "mkdir",
            elevated_impact=False,
            impact="Create a directory through cPanel API 2 Fileman::mkdir.",
            recovery="Remove the directory after confirming its contents are disposable.",
            fields={"directory": "path", "name": "name", "permissions": "permissions"},
            required=("directory", "name"),
        ),
        "files.delete-path": _operation(
            "files.delete-path",
            "delete-path",
            "fileop",
            risk="destructive",
            impact="Move a file or directory to the account .trash folder through cPanel API 2.",
            recovery="Restore the path from .trash before emptying trash.",
            fields={"source": "sourcefiles"},
            required=("source",),
            api2_parameters={"op": "trash", "doubledecode": 0},
        ),
        "files.rename-path": _operation(
            "files.rename-path",
            "rename-path",
            "fileop",
            impact="Rename a file or directory through cPanel API 2.",
            recovery="Rename the path back to its previous name.",
            fields={"source": "sourcefiles", "destination": "destfiles"},
            required=("source", "destination"),
            api2_parameters={"op": "rename", "doubledecode": 0},
        ),
        "files.copy-path": _operation(
            "files.copy-path",
            "copy-path",
            "fileop",
            elevated_impact=False,
            impact="Copy a file or directory through cPanel API 2.",
            recovery="Delete the copied destination if it was created incorrectly.",
            fields={"source": "sourcefiles", "destination": "destfiles"},
            required=("source", "destination"),
            api2_parameters={"op": "copy", "doubledecode": 0},
        ),
        "files.move-path": _operation(
            "files.move-path",
            "move-path",
            "fileop",
            impact="Move a file or directory through cPanel API 2.",
            recovery="Move the path back to its previous location.",
            fields={"source": "sourcefiles", "destination": "destfiles"},
            required=("source", "destination"),
            api2_parameters={"op": "move", "doubledecode": 0},
        ),
        "files.chmod-path": _operation(
            "files.chmod-path",
            "chmod-path",
            "fileop",
            impact="Change permissions for a file or directory through cPanel API 2.",
            recovery="Restore the previous permissions after inspecting them.",
            fields={"source": "sourcefiles", "permissions": "metadata"},
            required=("source", "permissions"),
            api2_parameters={"op": "chmod", "doubledecode": 0},
        ),
        "files.compress": _operation(
            "files.compress",
            "compress",
            "fileop",
            impact="Create an archive from a file or directory through cPanel API 2.",
            recovery="Delete the generated archive if it was created incorrectly.",
            fields={
                "source": "sourcefiles",
                "destination": "destfiles",
                "archive_type": "metadata",
            },
            required=("source", "destination", "archive_type"),
            api2_parameters={"op": "compress", "doubledecode": 0},
        ),
        "files.extract": _operation(
            "files.extract",
            "extract",
            "fileop",
            impact="Extract an archive into a destination directory through cPanel API 2.",
            recovery="Restore from backup or remove extracted files after confirming the result.",
            fields={"source": "sourcefiles", "destination": "destfiles"},
            required=("source", "destination"),
            api2_parameters={"op": "extract", "doubledecode": 0},
        ),
    }
)


def _single_path(value: object) -> str:
    path = validate_value("path", value)
    if not isinstance(path, str) or "," in path:
        raise UsageError("Invalid cPanel path")
    return path


def _archive_type(value: object) -> str:
    archive_type = validate_value("enum", value)
    if not isinstance(archive_type, str) or archive_type not in ARCHIVE_TYPES:
        raise UsageError("Invalid archive type")
    return archive_type


def _field_value(name: str, value: object) -> object:
    if name in {"directory", "source", "destination"}:
        return _single_path(value)
    if name == "name":
        return validate_value("filename", value)
    if name == "permissions":
        return validate_value("permissions", value)
    if name == "archive_type":
        return _archive_type(value)
    return validate_value("bounded_text", value)


def resolve_legacy_file_inputs(
    operation: LegacyFileOperation, values: Mapping[str, object]
) -> dict[str, object]:
    missing = [name for name in operation.required if values.get(name) is None]
    if missing:
        raise UsageError(f"Missing legacy file parameter: {', '.join(missing)}")
    parameters = dict(operation.api2_parameters)
    for name, api2_name in operation.fields.items():
        value = values.get(name)
        if value is None:
            continue
        parameters[api2_name] = _field_value(name, value)
    return parameters


class LegacyFileExecutor:
    """Execute one fixed cPanel API 2 Fileman operation."""

    def __init__(self, transport: API2TransportLike) -> None:
        self._transport = transport

    def execute(
        self,
        profile: Profile,
        token: str,
        operation: LegacyFileOperation,
        values: Mapping[str, object],
        *,
        timeout: int = 30,
    ) -> UAPIResponse:
        parameters = resolve_legacy_file_inputs(operation, values)
        return self._transport.call_api2(
            profile,
            token,
            operation.module,
            operation.function,
            parameters,
            timeout,
        )
