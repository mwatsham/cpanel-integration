from __future__ import annotations

import base64
import io
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.cli import build_parser, main
from cpanel_admin.policy import PolicyError, PolicyOperation, PolicyRegistry, Risk, SupportStatus
from cpanel_admin.profiles import ProfileStore
from cpanel_admin.secrets import SecretCodec
from cpanel_admin.transport import UAPIResponse, Upload


class FakeTransport:
    def __init__(self, responses: list[UAPIResponse] | None = None) -> None:
        self.calls: list[dict[str, object]] = []
        self.responses = list(responses or [])

    def call(self, profile, token, module, function, parameters, timeout=30, **kwargs):
        self.calls.append(
            {
                "profile": profile.name,
                "token": token,
                "module": module,
                "function": function,
                "parameters": dict(parameters),
                "timeout": timeout,
                **kwargs,
            }
        )
        if self.responses:
            return self.responses.pop(0)
        return UAPIResponse(data={"result": "ok"}, warnings=[], messages=[])


@pytest.fixture
def cli_env(tmp_path: Path) -> tuple[dict[str, str], str]:
    key = Fernet.generate_key().decode("ascii")
    return {
        "CPANEL_ADMIN_FERNET_KEY": key,
        "CPANEL_ADMIN_CONFIG": str(tmp_path / "profiles.json"),
    }, key


def invoke(args, *, env, stdin="", transport=None):
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(
        args,
        env=env,
        stdin=io.StringIO(stdin),
        stdout=stdout,
        stderr=stderr,
        transport=transport,
    )
    payload = json.loads(stdout.getvalue()) if stdout.getvalue() else None
    return code, payload, stderr.getvalue()


def add_profile(env: dict[str, str], key: str, token: str = "api-secret") -> None:
    ProfileStore(Path(env["CPANEL_ADMIN_CONFIG"])).add(
        "test",
        "cpanel.example.com",
        "account",
        token,
        SecretCodec(key.encode("ascii")),
    )


def test_profile_add_reads_token_from_stdin_and_never_outputs_it(cli_env) -> None:
    env, _ = cli_env
    code, payload, stderr = invoke(
        [
            "profiles",
            "add",
            "test",
            "--host",
            "cpanel.example.com",
            "--username",
            "account",
            "--api-token-stdin",
        ],
        env=env,
        stdin="api-secret\n",
    )

    assert code == 0
    assert payload["data"] == {
        "host": "cpanel.example.com",
        "name": "test",
        "port": 2083,
        "username": "account",
    }
    assert "api-secret" not in json.dumps(payload)
    assert "api-secret" not in stderr
    assert "api-secret" not in Path(env["CPANEL_ADMIN_CONFIG"]).read_text()


def test_read_operation_calls_fixed_uapi_and_returns_json(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport([UAPIResponse(["example.com"], ["notice"], [])])

    code, payload, stderr = invoke(
        ["--profile", "test", "domains", "list"], env=env, transport=transport
    )

    assert code == 0
    assert stderr == ""
    assert payload["ok"] is True
    assert payload["operation"] == "domains.list"
    assert payload["data"] == ["example.com"]
    assert (transport.calls[0]["module"], transport.calls[0]["function"]) == (
        "DomainInfo",
        "list_domains",
    )


def test_no_raw_module_function_parser_exists() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["call", "Email", "list_pops"])


def test_secret_parameters_have_source_selectors_not_value_options() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--profile",
                "test",
                "databases",
                "create-user",
                "--name",
                "account_user",
                "--password",
                "secret-value",
            ]
        )

    args = parser.parse_args(
        [
            "--profile",
            "test",
            "databases",
            "create-user",
            "--name",
            "account_user",
            "--password-stdin",
        ]
    )
    assert args.operation == "databases.create-user"

    args = parser.parse_args(
        [
            "--profile",
            "test",
            "ssl",
            "install",
            "--domain",
            "example.com",
            "--certificate-file",
            "cert.pem",
            "--private-key-file",
            "key.pem",
        ]
    )
    assert args.operation == "ssl.install"

    args = parser.parse_args(
        [
            "--profile",
            "test",
            "ssl",
            "install",
            "--domain",
            "example.com",
            "--certificate",
            "cert.pem",
            "--private-key",
            "key.pem",
        ]
    )
    assert args.operation == "ssl.install"
    assert args.certificate == "cert.pem"
    assert args.private_key == "key.pem"


def test_operations_list_discovers_included_policy_commands(cli_env) -> None:
    env, _ = cli_env

    code, payload, stderr = invoke(
        ["operations", "list", "--capability", "domains", "--status", "included"],
        env=env,
    )

    assert code == 0
    assert stderr == ""
    names = {item["name"] for item in payload["data"]}
    assert "domains.list" in names
    assert all(item["capability"] == "domains" for item in payload["data"])
    assert all(item["status"] == "included" for item in payload["data"])


def test_capabilities_inspect_uses_profile_and_transport(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport([UAPIResponse({"features": [{"name": "domains"}]}, [], [])])

    code, payload, stderr = invoke(
        ["--profile", "test", "capabilities", "inspect"],
        env=env,
        transport=transport,
    )

    assert code == 0
    assert stderr == ""
    assert payload["operation"] == "capabilities.inspect"
    assert payload["data"]["profile"] == "test"
    assert transport.calls[0]["function"] == "list_features"


def test_mutation_operations_use_executor_audit_pipeline(cli_env, tmp_path: Path) -> None:
    env, key = cli_env
    add_profile(env, key)
    audit_file = tmp_path / "audit.jsonl"
    transport = FakeTransport()

    code, payload, stderr = invoke(
        [
            "--profile",
            "test",
            "--audit-file",
            str(audit_file),
            "databases",
            "create",
            "--name",
            "account_demo",
        ],
        env=env,
        transport=transport,
    )

    assert code == 0
    assert stderr == ""
    assert payload["operation"] == "databases.create"
    assert transport.calls[0]["function"] == "create_database"
    records = [json.loads(line) for line in audit_file.read_text().splitlines()]
    assert [record["outcome"] for record in records] == ["intent", "success"]
    assert all(record["operation"] == "databases.create" for record in records)


def test_destructive_operation_requires_bound_confirmation(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport()

    code, plan, _ = invoke(
        ["--profile", "test", "databases", "remove", "--name", "account_demo", "--dry-run"],
        env=env,
        transport=transport,
    )
    assert code == 0
    assert plan["dry_run"] is True
    assert len(plan["confirmation"]) == 12
    assert transport.calls == []

    code, result, stderr = invoke(
        [
            "--profile",
            "test",
            "databases",
            "remove",
            "--name",
            "account_demo",
            "--confirm",
            plan["confirmation"],
            "--expires-at",
            plan["expires_at"],
        ],
        env=env,
        transport=transport,
    )
    assert code == 0
    assert result["operation"] == "databases.remove"
    assert stderr == ""
    assert transport.calls[-1]["function"] == "delete_database"

    code, _, stderr = invoke(
        [
            "--profile",
            "test",
            "databases",
            "remove",
            "--name",
            "account_changed",
            "--confirm",
            plan["confirmation"],
            "--expires-at",
            plan["expires_at"],
        ],
        env=env,
        transport=transport,
    )
    assert code == 4
    assert "does not match" in stderr
    assert len(transport.calls) == 1


def test_destructive_operation_without_confirmation_fails_before_network(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport()
    code, payload, stderr = invoke(
        ["--profile", "test", "ssl", "remove", "--domain", "example.com"],
        env=env,
        transport=transport,
    )
    assert code == 4
    assert payload is None
    assert "required" in stderr.lower()
    assert transport.calls == []


def test_upload_uses_multipart_and_binds_file_hash_not_contents(cli_env, tmp_path: Path) -> None:
    env, key = cli_env
    add_profile(env, key)
    audit_file = tmp_path / "audit.jsonl"
    source = tmp_path / "index.html"
    source.write_text("private-upload-content")
    transport = FakeTransport([UAPIResponse([{"file": "home.html"}], [], [])])

    code, plan, stderr = invoke(
        [
            "--profile",
            "test",
            "--audit-file",
            str(audit_file),
            "files",
            "upload",
            "--directory",
            "public_html",
            "--source",
            str(source),
            "--dry-run",
        ],
        env=env,
        transport=transport,
    )
    assert code == 0
    assert stderr == ""
    assert "private-upload-content" not in json.dumps(plan)
    assert plan["parameters"]["source"]["name"] == "index.html"
    assert plan["parameters"]["preflight"] == {"exists": False}
    assert transport.calls[0]["function"] == "list_files"
    assert transport.calls[0]["parameters"] == {"dir": "public_html"}

    transport.responses.append(UAPIResponse([{"file": "home.html"}], [], []))
    code, _, _ = invoke(
        [
            "--profile",
            "test",
            "--audit-file",
            str(audit_file),
            "files",
            "upload",
            "--directory",
            "public_html",
            "--source",
            str(source),
            "--confirm",
            plan["confirmation"],
            "--expires-at",
            plan["expires_at"],
        ],
        env=env,
        transport=transport,
    )
    assert code == 0
    upload_call = transport.calls[-1]
    assert upload_call["method"] == "POST"
    assert isinstance(upload_call["files"]["file-1"], Upload)
    assert upload_call["files"]["file-1"].content == b"private-upload-content"
    records = [json.loads(line) for line in audit_file.read_text().splitlines()]
    assert [record["outcome"] for record in records] == ["intent", "success"]
    assert all(record["operation"] == "files.upload" for record in records)


def test_database_password_and_private_key_never_appear_in_output(cli_env, tmp_path: Path) -> None:
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport()

    code, plan, stderr = invoke(
        [
            "--profile",
            "test",
            "databases",
            "create-user",
            "--name",
            "account_user",
            "--password-stdin",
            "--dry-run",
        ],
        env=env,
        stdin="db-super-secret\n",
        transport=transport,
    )
    assert code == 0
    assert "db-super-secret" not in json.dumps(plan)
    assert "db-super-secret" not in stderr

    code, payload, stderr = invoke(
        [
            "--profile",
            "test",
            "databases",
            "create-user",
            "--name",
            "account_user",
            "--password-stdin",
            "--confirm",
            plan["confirmation"],
            "--expires-at",
            plan["expires_at"],
        ],
        env=env,
        stdin="db-super-secret\n",
        transport=transport,
    )
    assert code == 0
    assert "db-super-secret" not in json.dumps(payload)
    assert "db-super-secret" not in stderr

    certificate = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    certificate_marker = "certificate-runtime-marker"
    key_marker = "private-key-runtime-marker"
    key_label = "PRIVATE KEY"
    certificate_body = base64.b64encode(certificate_marker.encode()).decode()
    key_body = base64.b64encode(key_marker.encode()).decode()
    certificate.write_text(
        f"-----BEGIN CERTIFICATE-----\n{certificate_body}\n-----END CERTIFICATE-----\n"
    )
    key_file.write_text(f"-----BEGIN {key_label}-----\n{key_body}\n-----END {key_label}-----\n")
    certificate.chmod(0o600)
    key_file.chmod(0o600)
    code, plan, _ = invoke(
        [
            "--profile",
            "test",
            "ssl",
            "install",
            "--domain",
            "example.com",
            "--certificate-file",
            str(certificate),
            "--private-key-file",
            str(key_file),
            "--dry-run",
        ],
        env=env,
        transport=transport,
    )
    serialized = json.dumps(plan)
    assert code == 0
    assert key_marker not in serialized
    assert certificate_marker not in serialized


def test_legacy_ssl_install_path_selectors_remain_supported(cli_env, tmp_path: Path) -> None:
    env, key = cli_env
    add_profile(env, key)
    certificate = tmp_path / "legacy-cert.pem"
    key_file = tmp_path / "legacy-key.pem"
    certificate_marker = "legacy-certificate-runtime-marker"
    key_marker = "legacy-private-key-runtime-marker"
    certificate.write_text(
        "-----BEGIN CERTIFICATE-----\n"
        f"{base64.b64encode(certificate_marker.encode()).decode()}\n"
        "-----END CERTIFICATE-----\n"
    )
    key_file.write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        f"{base64.b64encode(key_marker.encode()).decode()}\n"
        "-----END PRIVATE KEY-----\n"
    )
    certificate.chmod(0o600)
    key_file.chmod(0o600)

    code, plan, stderr = invoke(
        [
            "--profile",
            "test",
            "ssl",
            "install",
            "--domain",
            "example.com",
            "--certificate",
            str(certificate),
            "--private-key",
            str(key_file),
            "--dry-run",
        ],
        env=env,
        transport=FakeTransport(),
    )

    serialized = json.dumps(plan)
    assert code == 0
    assert stderr == ""
    assert str(certificate) not in serialized
    assert str(key_file) not in serialized
    assert certificate_marker not in serialized
    assert key_marker not in serialized


def test_email_account_creation_uses_protected_password_stdin(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--profile",
                "test",
                "email",
                "create-account",
                "--email",
                "admin",
                "--domain",
                "example.com",
                "--password",
                "plain-secret",
            ]
        )

    transport = FakeTransport()
    code, payload, stderr = invoke(
        [
            "--profile",
            "test",
            "email",
            "create-account",
            "--email",
            "admin",
            "--domain",
            "example.com",
            "--password-stdin",
        ],
        env=env,
        stdin="plain-secret\n",
        transport=transport,
    )

    serialized = json.dumps(payload)
    assert code == 0
    assert stderr == ""
    assert payload["operation"] == "email.create-account"
    assert (transport.calls[0]["module"], transport.calls[0]["function"]) == (
        "Email",
        "add_pop",
    )
    assert transport.calls[0]["parameters"]["password"] == "plain-secret"
    assert "plain-secret" not in serialized


def test_email_password_verification_uses_protected_password_stdin(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)

    transport = FakeTransport([UAPIResponse({"valid": True}, [], [])])
    code, payload, stderr = invoke(
        [
            "--profile",
            "test",
            "email",
            "verify-password",
            "--email",
            "admin@example.com",
            "--password-stdin",
        ],
        env=env,
        stdin="mail-secret-marker\n",
        transport=transport,
    )

    serialized = json.dumps(payload)
    assert code == 0
    assert stderr == ""
    assert payload["operation"] == "email.verify-password"
    assert (transport.calls[0]["module"], transport.calls[0]["function"]) == (
        "Email",
        "verify_password",
    )
    assert transport.calls[0]["parameters"] == {
        "email": "admin@example.com",
        "password": "mail-secret-marker",
    }
    assert "mail-secret-marker" not in serialized


def test_dynamic_policy_parser_fails_closed_for_malformed_command_path() -> None:
    malformed = PolicyOperation(
        name="bad.command",
        identity="DomainInfo/list_domains",
        command=("domains", "list", "extra"),
        capability="domains",
        status=SupportStatus.INCLUDED,
        reason="unit test malformed command path",
        risk=Risk.READ,
        elevated_impact=False,
        parameters={},
        impact="",
        recovery="",
        preflight=None,
        verification=None,
        feature=None,
        audit_fields=(),
    )

    with pytest.raises(PolicyError, match="command path"):
        build_parser(PolicyRegistry((malformed,), (), ()))


def test_uapi_response_cannot_echo_submitted_database_password(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    secret = "db-super-secret"
    transport = FakeTransport()

    code, plan, stderr = invoke(
        [
            "--profile",
            "test",
            "databases",
            "create-user",
            "--name",
            "account_user",
            "--password-stdin",
            "--dry-run",
        ],
        env=env,
        stdin=secret,
        transport=transport,
    )
    assert code == 0
    assert secret not in json.dumps(plan)
    assert secret not in stderr

    transport.responses.append(
        UAPIResponse({"password": secret, "message": f"received {secret}"}, [secret], [secret])
    )
    code, payload, stderr = invoke(
        [
            "--profile",
            "test",
            "databases",
            "create-user",
            "--name",
            "account_user",
            "--password-stdin",
            "--confirm",
            plan["confirmation"],
            "--expires-at",
            plan["expires_at"],
        ],
        env=env,
        stdin=secret,
        transport=transport,
    )
    assert code == 0
    assert secret not in json.dumps(payload)
    assert secret not in stderr


def test_profile_removal_uses_confirmation(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    code, plan, _ = invoke(["profiles", "remove", "test", "--dry-run"], env=env)
    assert code == 0

    code, payload, _ = invoke(
        [
            "profiles",
            "remove",
            "test",
            "--confirm",
            plan["confirmation"],
            "--expires-at",
            plan["expires_at"],
        ],
        env=env,
    )
    assert code == 0
    assert payload["data"]["name"] == "test"
    assert ProfileStore(Path(env["CPANEL_ADMIN_CONFIG"])).list() == []


def test_config_error_has_stable_exit_code_and_no_key_leak(cli_env) -> None:
    env, key = cli_env
    env["CPANEL_ADMIN_FERNET_KEY"] = "invalid-secret-key"
    code, payload, stderr = invoke(["profiles", "list"], env=env)
    assert code == 0  # Listing public profile metadata does not require a key.
    assert payload["data"] == []

    code, payload, stderr = invoke(
        [
            "profiles",
            "add",
            "test",
            "--host",
            "cpanel.example.com",
            "--username",
            "account",
            "--api-token-stdin",
        ],
        env=env,
        stdin="api-token",
    )
    assert code == 3
    assert payload is None
    assert key not in stderr
    assert "invalid-secret-key" not in stderr


def test_help_exposes_tasks_but_no_raw_uapi_passthrough(cli_env) -> None:
    env, _ = cli_env
    stdout = io.StringIO()
    code = main(["--help"], env=env, stdout=stdout, stderr=io.StringIO())
    help_text = stdout.getvalue().lower()
    assert code == 0
    assert "domains" in help_text
    assert "files" in help_text
    assert "ssl" in help_text
    assert "databases" in help_text
    assert "module" not in help_text
    assert "function" not in help_text


def test_profile_show_test_and_atomic_key_rotation(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport([UAPIResponse(["example.com"], [], [])])

    code, shown, _ = invoke(["profiles", "show", "test"], env=env)
    assert code == 0
    assert shown["data"]["username"] == "account"
    assert "encrypted_token" not in shown["data"]

    code, tested, _ = invoke(["profiles", "test", "test"], env=env, transport=transport)
    assert code == 0
    assert tested["data"] == ["example.com"]

    new_key = Fernet.generate_key().decode("ascii")
    env["CPANEL_ADMIN_FERNET_KEY_NEW"] = new_key
    code, rotated, _ = invoke(["profiles", "rotate-key"], env=env)
    assert code == 0
    assert rotated["data"] == {"rotated": 1}
    profile = ProfileStore(Path(env["CPANEL_ADMIN_CONFIG"])).get("test")
    assert SecretCodec(new_key.encode()).decrypt(profile.encrypted_token) == "api-secret"


def test_cli_uses_default_secure_key_file_without_exported_key(tmp_path: Path) -> None:
    key = Fernet.generate_key()
    config_root = tmp_path / "config"
    key_path = config_root / "cpanel-admin" / "fernet.key"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(key + b"\n")
    key_path.chmod(0o600)
    env = {"XDG_CONFIG_HOME": str(config_root)}
    ProfileStore(config_root / "cpanel-admin" / "profiles.json").add(
        "test",
        "cpanel.example.com",
        "account",
        "api-secret",
        SecretCodec(key),
    )

    code, payload, stderr = invoke(
        ["profiles", "test", "test"],
        env=env,
        transport=FakeTransport([UAPIResponse([], [], [])]),
    )

    assert code == 0
    assert payload["ok"] is True
    assert stderr == ""


def test_mutation_dry_run_and_execution(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport()

    code, plan, _ = invoke(
        [
            "--profile",
            "test",
            "domains",
            "add-subdomain",
            "--domain",
            "docs",
            "--rootdomain",
            "example.com",
            "--dir",
            "public_html/docs",
            "--dry-run",
        ],
        env=env,
        transport=transport,
    )
    assert code == 0
    assert plan["risk"] == "mutate"
    assert transport.calls == []

    code, result, _ = invoke(
        [
            "--profile",
            "test",
            "domains",
            "add-subdomain",
            "--domain",
            "docs",
            "--rootdomain",
            "example.com",
            "--dir",
            "public_html/docs",
        ],
        env=env,
        transport=transport,
    )
    assert code == 0
    assert result["operation"] == "domains.add-subdomain"
    assert transport.calls[0]["parameters"] == {
        "dir": "public_html/docs",
        "domain": "docs",
        "rootdomain": "example.com",
    }


def test_file_write_preflight_binds_content_and_target(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    audit_file = Path(env["CPANEL_ADMIN_CONFIG"]).with_name("file-write-audit.jsonl")
    metadata = {"file": "index.html", "size": 12, "mtime": 10.5, "tags": ["file"]}
    transport = FakeTransport([UAPIResponse([metadata], [], [])])
    args = [
        "--profile",
        "test",
        "--audit-file",
        str(audit_file),
        "files",
        "write",
        "--directory",
        "public_html",
        "--filename",
        "index.html",
    ]
    code, plan, _ = invoke(
        [*args, "--content-stdin", "--dry-run"],
        env=env,
        stdin="new",
        transport=transport,
    )
    assert code == 0
    assert plan["parameters"]["preflight"]["metadata"]["mtime"] == "10.5"
    assert plan["parameters"]["content"]["bytes"] == 3

    transport.responses.append(UAPIResponse([metadata], [], []))
    code, _, _ = invoke(
        [
            *args,
            "--content-stdin",
            "--confirm",
            plan["confirmation"],
            "--expires-at",
            plan["expires_at"],
        ],
        env=env,
        stdin="new",
        transport=transport,
    )
    assert code == 0
    assert transport.calls[-1]["method"] == "POST"
    assert transport.calls[-1]["parameters"]["content"] == "new"
    records = [json.loads(line) for line in audit_file.read_text().splitlines()]
    assert [record["outcome"] for record in records] == ["intent", "success"]
    assert all(record["operation"] == "files.write" for record in records)


@pytest.mark.parametrize(
    ("args", "stdin", "message"),
    [
        (["--timeout", "0", "profiles", "list"], "", "between 1 and 120"),
        (["domains", "list"], "", "--profile is required"),
        (
            [
                "profiles",
                "add",
                "test",
                "--host",
                "cpanel.example.com",
                "--username",
                "account",
                "--api-token-stdin",
            ],
            "",
            "must not be empty",
        ),
    ],
)
def test_cli_validation_failures_are_stable(cli_env, args, stdin, message) -> None:
    env, _ = cli_env
    code, payload, stderr = invoke(args, env=env, stdin=stdin)
    assert code == 2
    assert payload is None
    assert message in stderr


def test_missing_local_files_fail_safely(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)
    code, payload, stderr = invoke(
        [
            "--profile",
            "test",
            "files",
            "upload",
            "--directory",
            "public_html",
            "--source",
            "/does/not/exist",
            "--dry-run",
        ],
        env=env,
        transport=FakeTransport(),
    )
    assert code == 2
    assert payload is None
    assert "Unable to read upload source" in stderr

    code, _, stderr = invoke(
        [
            "--profile",
            "test",
            "ssl",
            "install",
            "--domain",
            "example.com",
            "--certificate-file",
            "/does/not/exist",
            "--private-key-file",
            "/also/missing",
            "--dry-run",
        ],
        env=env,
        transport=FakeTransport(),
    )
    assert code == 2
    assert "protected input file" in stderr


def test_unexpected_exception_is_generic_and_pretty_output_is_valid(cli_env) -> None:
    env, key = cli_env
    add_profile(env, key)

    class BrokenTransport(FakeTransport):
        def call(self, *args, **kwargs):
            raise ValueError("api-secret should never escape")

    code, payload, stderr = invoke(
        ["--profile", "test", "domains", "list"], env=env, transport=BrokenTransport()
    )
    assert code == 1
    assert payload is None
    assert stderr == "Error: unexpected internal failure\n"

    stdout = io.StringIO()
    code = main(
        ["--pretty", "profiles", "list"],
        env=env,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    assert code == 0
    assert '\n  "data"' in stdout.getvalue()
