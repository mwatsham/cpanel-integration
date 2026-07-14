import argparse
import io
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.errors import UsageError
from cpanel_admin.inputs import InputResolver, fingerprint, read_protected_file
from cpanel_admin.operations import validate_value
from cpanel_admin.policy import (
    InputSource,
    PolicyError,
    PolicyOperation,
    PolicyParameter,
    Risk,
    SupportStatus,
)
from cpanel_admin.profiles import ProfileStore, default_profile_path
from cpanel_admin.secrets import SecretCodec


def parameter(
    name: str,
    source: InputSource,
    validator: str,
    *,
    required: bool = True,
    secret: bool = False,
) -> PolicyParameter:
    return PolicyParameter(name, name, (source,), validator, required, secret, secret)


def operation(*parameters: PolicyParameter) -> PolicyOperation:
    return PolicyOperation(
        name="test.operation",
        identity="Test/operation",
        command=("test", "operation"),
        capability="test",
        status=SupportStatus.INCLUDED,
        reason="covered by a unit test",
        risk=Risk.READ,
        elevated_impact=False,
        parameters={item.name: item for item in parameters},
        impact="Inspect test data",
        recovery="No change is made",
        preflight=None,
        verification=None,
        feature=None,
        audit_fields=(),
    )


def test_secret_parameter_reads_stdin_and_fingerprints_plan() -> None:
    runtime_value = "".join(("s3", "cret"))
    resolved = InputResolver().resolve(
        operation(parameter("password", InputSource.STDIN, "secret", secret=True)),
        argparse.Namespace(),
        io.StringIO(runtime_value + "\n"),
        {},
    )

    assert resolved.values["password"] == runtime_value
    assert resolved.safe_values["password"] == fingerprint(runtime_value.encode())
    assert resolved.secrets == (runtime_value,)


def test_protected_file_parameter_is_validated_then_fingerprinted(tmp_path: Path) -> None:
    content = "".join(("test-private-material ", "PRIVATE KEY-----"))
    path = tmp_path / "private.pem"
    path.write_text(content)
    path.chmod(0o600)
    subject = operation(
        parameter("private_key", InputSource.PROTECTED_FILE, "private_key", secret=True)
    )

    resolved = InputResolver().resolve(
        subject, argparse.Namespace(private_key=str(path)), io.StringIO(), {}
    )

    assert resolved.values == {"private_key": content}
    assert resolved.safe_values == {"private_key": fingerprint(content.encode())}
    assert resolved.secrets == (content,)


def test_multiple_stdin_consumers_are_rejected_before_reading() -> None:
    stream = io.StringIO("runtime-input")
    subject = operation(
        parameter("first", InputSource.STDIN, "secret", secret=True),
        parameter("second", InputSource.STDIN, "secret", secret=True),
    )

    with pytest.raises(UsageError, match="standard input at most once"):
        InputResolver().resolve(subject, argparse.Namespace(), stream, {})
    assert stream.tell() == 0


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o400])
def test_protected_file_requires_mode_0600(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "private.pem"
    path.write_text("test material")
    path.chmod(mode)

    with pytest.raises(UsageError, match="permissions must be 0600"):
        read_protected_file(path, maximum=1024 * 1024)


def test_protected_file_rejects_symlink_and_wrong_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "private.pem"
    path.write_text("test material")
    path.chmod(0o600)
    symlink = tmp_path / "linked.pem"
    symlink.symlink_to(path)

    with pytest.raises(UsageError, match="symbolic link"):
        read_protected_file(symlink, maximum=1024)

    monkeypatch.setattr(os, "getuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(UsageError, match="owned by the current user"):
        read_protected_file(path, maximum=1024)


def test_protected_file_rejects_non_regular_and_oversize_without_path_in_error(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "not-a-file"
    directory.mkdir()
    directory.chmod(0o600)
    with pytest.raises(UsageError, match="regular file"):
        read_protected_file(directory, maximum=1024)

    path = tmp_path / "private-material.pem"
    path.write_bytes(b"x" * 4)
    path.chmod(0o600)
    with pytest.raises(UsageError, match="allowed size") as error:
        read_protected_file(path, maximum=3)
    assert str(path) not in str(error.value)


def test_protected_file_rejects_invalid_limit_and_non_utf8_input(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="non-negative integer"):
        read_protected_file(tmp_path / "unused", maximum=-1)

    path = tmp_path / "private.pem"
    path.write_bytes(b"\xff")
    path.chmod(0o600)
    subject = operation(parameter("certificate", InputSource.PROTECTED_FILE, "certificate"))
    with pytest.raises(UsageError, match="UTF-8 text"):
        InputResolver().resolve(
            subject, argparse.Namespace(certificate=str(path)), io.StringIO(), {}
        )


def test_local_file_upload_has_only_safe_basename_and_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / "site.zip"
    path.write_bytes(b"abc")

    resolved = InputResolver().resolve(
        operation(parameter("source", InputSource.LOCAL_FILE, "local_file")),
        argparse.Namespace(source=str(path)),
        io.StringIO(),
        {},
    )

    assert resolved.safe_values["source"] == {
        "name": "site.zip",
        "bytes": 3,
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    }
    assert resolved.uploads["file-1"].filename == "site.zip"
    assert resolved.uploads["file-1"].content == b"abc"
    assert str(path) not in repr(resolved.safe_values)


def test_resolved_input_representation_exposes_only_safe_values(tmp_path: Path) -> None:
    runtime_value = "".join(("runtime", "-material"))
    path = tmp_path / "site.zip"
    path.write_bytes(b"abc")
    resolved = InputResolver().resolve(
        operation(
            parameter("password", InputSource.STDIN, "secret", secret=True),
            parameter("source", InputSource.LOCAL_FILE, "local_file"),
        ),
        argparse.Namespace(source=str(path)),
        io.StringIO(runtime_value),
        {},
    )

    representation = repr(resolved)
    assert runtime_value not in representation
    assert str(path) not in representation
    assert "safe_values" in representation


def test_local_file_rejects_symlink_and_oversize_without_exposing_path(tmp_path: Path) -> None:
    path = tmp_path / "upload.bin"
    path.write_bytes(b"x" * (10 * 1024 * 1024 + 1))
    symlink = tmp_path / "upload-link.bin"
    symlink.symlink_to(path)
    subject = operation(parameter("source", InputSource.LOCAL_FILE, "local_file"))

    for source in (path, symlink):
        with pytest.raises(UsageError) as error:
            InputResolver().resolve(
                subject, argparse.Namespace(source=str(source)), io.StringIO(), {}
            )
        assert str(source) not in str(error.value)

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(UsageError, match="regular file"):
        InputResolver().resolve(
            subject, argparse.Namespace(source=str(directory)), io.StringIO(), {}
        )


def test_file_errors_do_not_retain_path_bearing_os_error_causes(tmp_path: Path) -> None:
    missing = tmp_path / "missing.pem"

    with pytest.raises(UsageError) as error:
        read_protected_file(missing, maximum=1024)

    assert str(missing) not in str(error.value)
    assert error.value.__cause__ is None


def test_protected_file_detects_change_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "private.pem"
    path.write_bytes(b"abc")
    path.chmod(0o600)
    real_fstat = os.fstat
    calls = 0

    def changed_fstat(descriptor: int) -> object:
        nonlocal calls
        calls += 1
        current = real_fstat(descriptor)
        if calls == 1:
            return current
        return SimpleNamespace(
            st_dev=current.st_dev,
            st_ino=current.st_ino,
            st_mode=current.st_mode,
            st_uid=current.st_uid,
            st_size=current.st_size + 1,
            st_mtime_ns=current.st_mtime_ns,
            st_ctime_ns=current.st_ctime_ns,
        )

    monkeypatch.setattr(os, "fstat", changed_fstat)
    with pytest.raises(UsageError, match="changed while being read"):
        read_protected_file(path, maximum=1024)


def test_environment_source_accepts_only_name_indirection_and_fingerprints() -> None:
    runtime_value = "".join(("environment", "-value"))
    subject = operation(parameter("password", InputSource.ENVIRONMENT, "secret", secret=True))

    resolved = InputResolver().resolve(
        subject,
        argparse.Namespace(password="APP_PASSWORD"),
        io.StringIO(),
        {"APP_PASSWORD": runtime_value},
    )

    assert resolved.values == {"password": runtime_value}
    assert resolved.safe_values == {"password": fingerprint(runtime_value.encode())}
    assert resolved.secrets == (runtime_value,)

    for invalid in (runtime_value, "app_password", "1PASSWORD", "A" * 129):
        with pytest.raises(UsageError, match="environment variable name") as error:
            InputResolver().resolve(
                subject, argparse.Namespace(password=invalid), io.StringIO(), {}
            )
        assert runtime_value not in str(error.value)

    with pytest.raises(UsageError, match="is not set"):
        InputResolver().resolve(
            subject, argparse.Namespace(password="APP_PASSWORD"), io.StringIO(), {}
        )


def test_encrypted_profile_uses_only_declared_existing_field(tmp_path: Path) -> None:
    runtime_value = "".join(("profile", "-value"))
    key = Fernet.generate_key()
    env = {
        "XDG_CONFIG_HOME": str(tmp_path),
        "CPANEL_ADMIN_FERNET_KEY": key.decode(),
    }
    store = ProfileStore(default_profile_path(env))
    store.add("production", "cpanel.example.com", "account", runtime_value, SecretCodec(key))
    approved = parameter("encrypted_token", InputSource.ENCRYPTED_PROFILE, "secret", secret=True)

    resolved = InputResolver().resolve(
        operation(approved), argparse.Namespace(profile="production"), io.StringIO(), env
    )

    assert resolved.values == {"encrypted_token": runtime_value}
    assert resolved.safe_values == {"encrypted_token": fingerprint(runtime_value.encode())}
    assert resolved.secrets == (runtime_value,)

    arbitrary = parameter("custom_path", InputSource.ENCRYPTED_PROFILE, "secret", secret=True)
    with pytest.raises(UsageError, match="not an approved encrypted profile field"):
        InputResolver().resolve(
            operation(arbitrary),
            argparse.Namespace(profile="production", custom_path="profiles.production.token"),
            io.StringIO(),
            env,
        )

    with pytest.raises(UsageError, match="Missing required parameter"):
        InputResolver().resolve(operation(approved), argparse.Namespace(), io.StringIO(), env)

    with pytest.raises(UsageError, match="Unable to resolve"):
        InputResolver().resolve(
            operation(approved), argparse.Namespace(profile="missing"), io.StringIO(), env
        )


def test_values_are_validated_and_returned_in_parameter_name_order() -> None:
    subject = operation(
        parameter("zeta", InputSource.ARGUMENT, "boolean"),
        parameter("alpha", InputSource.ARGUMENT, "domain"),
    )

    resolved = InputResolver().resolve(
        subject,
        argparse.Namespace(alpha="EXAMPLE.COM", zeta=True),
        io.StringIO(),
        {},
    )

    assert tuple(resolved.values) == ("alpha", "zeta")
    assert resolved.values == {"alpha": "example.com", "zeta": True}
    assert resolved.safe_values == resolved.values


def test_existing_trash_age_validator_is_available_to_policy_resolver() -> None:
    subject = operation(parameter("older_than", InputSource.ARGUMENT, "trash_age"))

    resolved = InputResolver().resolve(
        subject, argparse.Namespace(older_than=30), io.StringIO(), {}
    )

    assert resolved.values == {"older_than": 30}


def test_optional_missing_input_is_omitted_deterministically() -> None:
    optional = parameter("password", InputSource.ENVIRONMENT, "secret", required=False, secret=True)

    resolved = InputResolver().resolve(operation(optional), argparse.Namespace(), io.StringIO(), {})

    assert resolved.values == {}
    assert resolved.safe_values == {}
    assert resolved.uploads == {}
    assert resolved.secrets == ()


def test_resolver_rejects_excluded_operations_and_ambiguous_sources() -> None:
    included = operation(parameter("domain", InputSource.ARGUMENT, "domain"))
    excluded = replace(included, status=SupportStatus.EXCLUDED, risk=None)
    with pytest.raises(PolicyError, match="operation is not included"):
        InputResolver().resolve(excluded, argparse.Namespace(), io.StringIO(), {})

    ambiguous = PolicyParameter(
        "domain",
        "domain",
        (InputSource.ARGUMENT, InputSource.ENVIRONMENT),
        "domain",
        True,
    )
    with pytest.raises(PolicyError, match="exactly one input source"):
        InputResolver().resolve(
            operation(ambiguous), argparse.Namespace(domain="example.com"), io.StringIO(), {}
        )


def test_missing_required_argument_and_unknown_validator_fail_closed() -> None:
    required = operation(parameter("domain", InputSource.ARGUMENT, "domain"))
    with pytest.raises(UsageError, match="Missing required parameter"):
        InputResolver().resolve(required, argparse.Namespace(), io.StringIO(), {})

    with pytest.raises(PolicyError, match=r"^unknown validator: unknown$"):
        validate_value("unknown", "anything")

    with pytest.raises(TypeError, match="must be bytes"):
        fingerprint("not-bytes")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("validator", "value", "expected"),
    [
        ("integer", 7, 7),
        ("boolean", True, True),
        ("email", "Admin@Example.COM", "Admin@example.com"),
        ("ip_cidr", "192.0.2.1/24", "192.0.2.0/24"),
        ("url", "https://example.com/path", "https://example.com/path"),
        ("bounded_text", "value", "value"),
        (
            "pem",
            "-----BEGIN TEST-----\nQQ==\n-----END TEST-----",
            "-----BEGIN TEST-----\nQQ==\n-----END TEST-----",
        ),
    ],
)
def test_reusable_validator_registry(validator: str, value: object, expected: object) -> None:
    assert validate_value(validator, value) == expected


def test_cron_validator_reports_unsupported_capability() -> None:
    with pytest.raises(PolicyError, match="cron expressions are not supported"):
        validate_value("cron_expression", "0 0 * * *")
