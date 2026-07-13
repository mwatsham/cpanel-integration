from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from cpanel_admin.cli import main
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
    source = tmp_path / "index.html"
    source.write_text("private-upload-content")
    transport = FakeTransport([UAPIResponse({"exists": False}, [], [])])

    code, plan, stderr = invoke(
        [
            "--profile",
            "test",
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
    assert transport.calls[0]["function"] == "get_file_information"

    transport.responses.append(UAPIResponse({"exists": False}, [], []))
    code, _, _ = invoke(
        [
            "--profile",
            "test",
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


def test_database_password_and_private_key_never_appear_in_output(cli_env, tmp_path: Path) -> None:
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport()

    code, payload, stderr = invoke(
        [
            "--profile",
            "test",
            "databases",
            "create-user",
            "--name",
            "account_user",
            "--password-stdin",
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
    certificate.write_text("-----BEGIN CERTIFICATE-----\nCERTBODY\n-----END CERTIFICATE-----\n")
    key_file.write_text("-----BEGIN PRIVATE KEY-----\nKEYBODY\n-----END PRIVATE KEY-----\n")
    code, plan, _ = invoke(
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
        transport=transport,
    )
    serialized = json.dumps(plan)
    assert code == 0
    assert "KEYBODY" not in serialized
    assert "CERTBODY" not in serialized


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
    metadata = {"size": 12, "mtime": 10.5, "tags": ["file"]}
    transport = FakeTransport([UAPIResponse(metadata, [], [])])
    args = [
        "--profile",
        "test",
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
    assert plan["parameters"]["preflight"]["mtime"] == "10.5"
    assert plan["parameters"]["content"]["bytes"] == 3

    transport.responses.append(UAPIResponse(metadata, [], []))
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
            "--certificate",
            "/does/not/exist",
            "--private-key",
            "/also/missing",
            "--dry-run",
        ],
        env=env,
        transport=FakeTransport(),
    )
    assert code == 2
    assert "Unable to read certificate file" in stderr


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
