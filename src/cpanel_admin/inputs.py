"""Fail-closed resolution of policy-approved runtime inputs."""

from __future__ import annotations

import argparse
import hashlib
import mimetypes
import os
import re
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn, TextIO, TypeVar, cast

from .catalog import JsonValue
from .errors import ConfigError, UsageError
from .operations import MAX_PEM_BYTES, MAX_TEXT_BYTES, validate_value
from .policy import InputSource, PolicyError, PolicyOperation, PolicyParameter, SupportStatus
from .profiles import ProfileStore, default_profile_path
from .secrets import SecretCodec
from .transport import Upload

MAX_LOCAL_FILE_BYTES = 10 * 1024 * 1024
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ENCRYPTED_PROFILE_FIELDS = frozenset({"encrypted_token"})
_KeyT = TypeVar("_KeyT")
_ValueT = TypeVar("_ValueT")


class _FrozenDict(dict[_KeyT, _ValueT]):
    """Copied dict shape with every normal mutation entry point disabled."""

    def __init__(self, values: Mapping[_KeyT, _ValueT]) -> None:
        dict.__init__(self, values)

    def _reject_mutation(self, *args: object, **kwargs: object) -> NoReturn:
        raise TypeError("resolved input mappings are immutable")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    clear = _reject_mutation
    pop = _reject_mutation
    popitem = _reject_mutation
    setdefault = _reject_mutation
    update = _reject_mutation
    __ior__ = _reject_mutation


class _FrozenList(list[_ValueT]):
    """Copied list shape with every normal mutation entry point disabled."""

    def _reject_mutation(self, *args: object, **kwargs: object) -> NoReturn:
        raise TypeError("resolved input lists are immutable")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    append = _reject_mutation
    clear = _reject_mutation
    extend = _reject_mutation
    insert = _reject_mutation
    pop = _reject_mutation
    remove = _reject_mutation
    reverse = _reject_mutation
    sort = _reject_mutation
    __iadd__ = _reject_mutation
    __imul__ = _reject_mutation


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return _FrozenDict({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class ResolvedInputs:
    values: dict[str, object] = field(repr=False)
    safe_values: dict[str, JsonValue]
    uploads: dict[str, Upload] = field(repr=False)
    secrets: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        values = _FrozenDict({name: _freeze(value) for name, value in dict(self.values).items()})
        safe_values = _FrozenDict(
            {name: _freeze(value) for name, value in dict(self.safe_values).items()}
        )
        uploads = _FrozenDict(
            {
                name: Upload(upload.filename, bytes(upload.content), str(upload.content_type))
                for name, upload in dict(self.uploads).items()
            }
        )
        object.__setattr__(self, "values", values)
        object.__setattr__(self, "safe_values", safe_values)
        object.__setattr__(self, "uploads", uploads)
        object.__setattr__(self, "secrets", tuple(str(secret) for secret in self.secrets))


def fingerprint(content: bytes) -> dict[str, JsonValue]:
    """Return the non-reversible metadata allowed in plans and audit records."""

    if not isinstance(content, bytes):
        raise TypeError("fingerprint content must be bytes")
    return {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def _initial_metadata(path: Path, label: str) -> os.stat_result:
    metadata: os.stat_result | None = None
    with suppress(OSError):
        metadata = path.lstat()
    if metadata is None:
        if label == "upload source":
            raise UsageError("Unable to read upload source file")
        raise UsageError(f"Unable to inspect {label}")
    if stat.S_ISLNK(metadata.st_mode):
        raise UsageError(f"{label.capitalize()} must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise UsageError(f"{label.capitalize()} must be a regular file")
    return metadata


def _open_readonly(path: Path, label: str) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    with suppress(OSError):
        descriptor = os.open(path, flags)
    if descriptor is None:
        raise UsageError(f"Unable to open {label} securely")
    return descriptor


def _descriptor_metadata(descriptor: int, label: str) -> os.stat_result:
    metadata: os.stat_result | None = None
    with suppress(OSError):
        metadata = os.fstat(descriptor)
    if metadata is None:
        raise UsageError(f"Unable to inspect {label} securely")
    return metadata


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return before.st_dev == after.st_dev and before.st_ino == after.st_ino


def _unchanged_file(before: os.stat_result, after: os.stat_result) -> bool:
    return _same_file(before, after) and (
        before.st_mode,
        before.st_uid,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_mode,
        after.st_uid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _bounded_descriptor_read(descriptor: int, maximum: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    read_failed = False
    try:
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        read_failed = True
    if read_failed:
        raise UsageError(f"Unable to read {label} securely")
    content = b"".join(chunks)
    if len(content) > maximum:
        raise UsageError(f"{label.capitalize()} exceeds the allowed size")
    return content


def read_protected_file(path: Path, maximum: int) -> bytes:
    """Read an exact-mode, user-owned regular file without following links."""

    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
        raise UsageError("Protected input size limit must be a non-negative integer")
    file_path = Path(path)
    before = _initial_metadata(file_path, "protected input file")
    descriptor = _open_readonly(file_path, "protected input file")
    try:
        opened = _descriptor_metadata(descriptor, "protected input file")
        if not _same_file(before, opened):
            raise UsageError("Protected input file changed while being opened")
        if not stat.S_ISREG(opened.st_mode):
            raise UsageError("Protected input file must be a regular file")
        if hasattr(os, "getuid") and opened.st_uid != os.getuid():
            raise UsageError("Protected input file must be owned by the current user")
        if stat.S_IMODE(opened.st_mode) != 0o600:
            raise UsageError("Protected input file permissions must be 0600")
        content = _bounded_descriptor_read(descriptor, maximum, "protected input file")
        finished = _descriptor_metadata(descriptor, "protected input file")
        if not _unchanged_file(opened, finished):
            raise UsageError("Protected input file changed while being read")
        return content
    finally:
        os.close(descriptor)


def _read_local_file(path: Path) -> bytes:
    before = _initial_metadata(path, "upload source")
    descriptor = _open_readonly(path, "upload source")
    try:
        opened = _descriptor_metadata(descriptor, "upload source")
        if not _same_file(before, opened):
            raise UsageError("Upload source changed while being opened")
        if not stat.S_ISREG(opened.st_mode):
            raise UsageError("Upload source must be a regular file")
        content = _bounded_descriptor_read(descriptor, MAX_LOCAL_FILE_BYTES, "upload source")
        finished = _descriptor_metadata(descriptor, "upload source")
        if not _unchanged_file(opened, finished):
            raise UsageError("Upload source changed while being read")
        return content
    finally:
        os.close(descriptor)


def _missing(operation: PolicyOperation, parameter: PolicyParameter) -> UsageError:
    return UsageError(f"Missing required parameter for {operation.name}: {parameter.name}")


def _argument_value(namespace: argparse.Namespace, name: str) -> object | None:
    return getattr(namespace, name, None)


def _decode(content: bytes, label: str) -> str:
    decoded: str | None = None
    with suppress(UnicodeDecodeError):
        decoded = content.decode("utf-8")
    if decoded is None:
        raise UsageError(f"{label} must contain UTF-8 text")
    return decoded


def _maximum_for(parameter: PolicyParameter) -> int:
    if parameter.validator in {"certificate", "pem", "private_key"}:
        return MAX_PEM_BYTES
    if parameter.validator == "secret":
        return 4096
    return MAX_TEXT_BYTES


def _read_encrypted_profile(
    operation: PolicyOperation,
    parameter: PolicyParameter,
    namespace: argparse.Namespace,
    env: Mapping[str, str],
) -> str:
    if parameter.name not in _ENCRYPTED_PROFILE_FIELDS or not parameter.secret:
        raise UsageError(f"Parameter {parameter.name} is not an approved encrypted profile field")
    profile_name = getattr(namespace, "profile", None)
    if not isinstance(profile_name, str) or not profile_name:
        raise _missing(operation, parameter)
    value: str | None = None
    failed = False
    try:
        profile = ProfileStore(default_profile_path(env)).get(profile_name)
        ciphertext = profile.encrypted_token
        value = SecretCodec.from_environment(env).decrypt(ciphertext)
    except ConfigError:
        failed = True
    if failed or value is None:
        raise UsageError("Unable to resolve encrypted profile field")
    return value


def _validate_parameter_value(parameter: PolicyParameter, raw: object) -> object:
    if not parameter.secret:
        return validate_value(parameter.validator, raw)
    normalized: object | None = None
    failed = False
    try:
        normalized = validate_value(parameter.validator, raw)
    except Exception:
        failed = True
    if failed or not isinstance(normalized, str):
        raise UsageError(f"Invalid protected value for {parameter.name}")
    return str(normalized)


class InputResolver:
    """Resolve one fixed policy operation from approved input sources."""

    def resolve(
        self,
        operation: PolicyOperation,
        namespace: argparse.Namespace,
        stdin: TextIO,
        env: Mapping[str, str],
    ) -> ResolvedInputs:
        if operation.status is not SupportStatus.INCLUDED:
            raise PolicyError(f"operation is not included: {operation.identity}")
        parameters = [operation.parameters[name] for name in sorted(operation.parameters)]
        for parameter in parameters:
            if len(parameter.sources) != 1:
                raise PolicyError(
                    f"parameter must declare exactly one input source: "
                    f"{operation.identity}:{parameter.name}"
                )
        if sum(parameter.sources[0] is InputSource.STDIN for parameter in parameters) > 1:
            raise UsageError("An operation may consume standard input at most once")

        values: dict[str, object] = {}
        safe_values: dict[str, JsonValue] = {}
        uploads: dict[str, Upload] = {}
        secrets: list[str] = []
        upload_index = 0

        for parameter in parameters:
            source = parameter.sources[0]
            raw: object | None
            protected_content: bytes | None = None

            if source is InputSource.ARGUMENT:
                raw = _argument_value(namespace, parameter.name)
            elif source is InputSource.STDIN:
                stdin_failed = False
                try:
                    raw = stdin.read()
                except OSError:
                    stdin_failed = True
                    raw = None
                if stdin_failed:
                    raise UsageError("Unable to read approved standard input")
                if parameter.validator != "content":
                    raw = cast(str, raw).rstrip("\r\n")
            elif source is InputSource.PROTECTED_FILE:
                supplied = _argument_value(namespace, parameter.name)
                raw = supplied
                if supplied is not None:
                    if not isinstance(supplied, str) or not supplied:
                        raise UsageError(f"Invalid protected file input for {parameter.name}")
                    protected_content = read_protected_file(
                        Path(supplied), maximum=_maximum_for(parameter)
                    )
                    raw = _decode(protected_content, "Protected input file")
            elif source is InputSource.LOCAL_FILE:
                raw = _argument_value(namespace, parameter.name)
            elif source is InputSource.ENVIRONMENT:
                variable_name = _argument_value(namespace, parameter.name)
                if variable_name is None:
                    raw = None
                else:
                    if (
                        not parameter.secret
                        or not isinstance(variable_name, str)
                        or not ENVIRONMENT_NAME_RE.fullmatch(variable_name)
                    ):
                        raise UsageError("Invalid environment variable name for protected input")
                    if variable_name not in env:
                        raise UsageError("Approved environment variable is not set")
                    raw = env[variable_name]
            elif source is InputSource.ENCRYPTED_PROFILE:
                raw = _read_encrypted_profile(operation, parameter, namespace, env)
            else:  # pragma: no cover - InputSource is exhaustive, defensive against tampering
                raise PolicyError(f"unsupported input source: {source}")

            if raw is None:
                if parameter.required:
                    raise _missing(operation, parameter)
                continue

            normalized = _validate_parameter_value(parameter, raw)
            values[parameter.name] = normalized

            if source is InputSource.LOCAL_FILE:
                local_path = Path(cast(str, normalized))
                content = _read_local_file(local_path)
                upload_index += 1
                upload_name = local_path.name
                uploads[f"file-{upload_index}"] = Upload(
                    upload_name,
                    content,
                    mimetypes.guess_type(upload_name)[0] or "application/octet-stream",
                )
                safe_values[parameter.name] = {
                    "name": upload_name,
                    **fingerprint(content),
                }
                continue

            if (
                parameter.secret
                or parameter.sensitive_output
                or source
                in {
                    InputSource.STDIN,
                    InputSource.PROTECTED_FILE,
                    InputSource.ENVIRONMENT,
                    InputSource.ENCRYPTED_PROFILE,
                }
            ):
                encoded = str(normalized).encode("utf-8")
                safe_values[parameter.name] = fingerprint(encoded)
            else:
                safe_values[parameter.name] = cast(JsonValue, normalized)
            if parameter.secret:
                secrets.append(str(normalized))

        return ResolvedInputs(values, safe_values, uploads, tuple(secrets))
