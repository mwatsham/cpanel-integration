"""Software commands exercise the real CLI with an isolated cPanel transport."""

import json

import pytest
from cryptography.fernet import Fernet
from test_cli import FakeTransport, add_profile, invoke

from cpanel_admin.transport import UAPIResponse


@pytest.fixture
def cli_env(tmp_path):
    key = Fernet.generate_key().decode("ascii")
    return {
        "CPANEL_ADMIN_FERNET_KEY": key,
        "CPANEL_ADMIN_CONFIG": str(tmp_path / "profiles.json"),
    }, key


def response(data):
    return UAPIResponse(data=data, warnings=[], messages=[])


APP = {
    "name": "demo",
    "path": "/home/account/apps/demo",
    "domain": "example.com",
    "enabled": 1,
    "deployment_mode": "production",
    "base_uri": "/",
    "envvars": {"CUSTOM": "hidden-secret"},
    "deps": {"npm": "npm install"},
}


@pytest.mark.parametrize("action", ["enable", "disable", "unregister"])
def test_application_mutations_bind_state_and_require_confirmation(cli_env, action):
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport([response({"demo": APP})])
    args = ["--profile", "test", "software", action, "--name", "demo"]
    code, plan, error = invoke([*args, "--dry-run"], env=env, transport=transport)
    assert code == 0, error
    assert plan["requires_confirmation"]
    assert "hidden-secret" not in json.dumps(plan)
    assert transport.calls[-1]["function"] == "list_applications"
    transport = FakeTransport([response({"demo": APP})])
    code, _, _ = invoke(args, env=env, transport=transport)
    assert code != 0
    assert not transport.calls


def test_software_list_hides_environment_values(cli_env):
    env, key = cli_env
    add_profile(env, key)
    code, result, error = invoke(
        ["--profile", "test", "software", "list"],
        env=env,
        transport=FakeTransport([response({"demo": APP})]),
    )
    assert code == 0, error
    assert "hidden-secret" not in json.dumps(result)
    assert result["data"]["demo"]["name"] == "demo"


def test_software_edit_uses_protected_environment_and_verifies(cli_env, tmp_path):
    env, key = cli_env
    add_profile(env, key)
    source = tmp_path / "environment.json"
    source.write_text('{"CUSTOM":"new-hidden-secret"}')
    source.chmod(0o600)
    args = [
        "--profile",
        "test",
        "software",
        "edit",
        "--name",
        "demo",
        "--environment-file",
        str(source),
        "--deployment-mode",
        "development",
    ]
    disabled = {**APP, "enabled": 0}
    code, plan, error = invoke(
        [*args, "--dry-run"], env=env, transport=FakeTransport([response({"demo": disabled})])
    )
    assert code == 0, error
    assert "new-hidden-secret" not in json.dumps(plan)
    updated = {
        **disabled,
        "deployment_mode": "development",
        "envvars": {"CUSTOM": "new-hidden-secret"},
    }
    transport = FakeTransport(
        [response({"demo": disabled}), response({}), response({"demo": updated})]
    )
    code, result, error = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=env,
        transport=transport,
    )
    assert code == 0, error
    assert result["verification"]["ok"]
    assert transport.calls[1]["parameters"]["envvar_name"] == ["CUSTOM"]
    assert transport.calls[1]["parameters"]["envvar_value"] == ["new-hidden-secret"]
    assert transport.calls[1]["parameters"]["enabled"] == 0
    assert "new-hidden-secret" not in json.dumps(result)
    assert "new-hidden-secret" not in (tmp_path / "audit.jsonl").read_text()


def test_register_and_verify_application(cli_env):
    env, key = cli_env
    add_profile(env, key)
    info = {"home": "/home/account", "domains": ["example.com"]}
    args = [
        "--profile",
        "test",
        "software",
        "register",
        "--name",
        "demo",
        "--path",
        "apps/demo",
        "--domain",
        "example.com",
    ]
    code, plan, error = invoke(
        [*args, "--dry-run"], env=env, transport=FakeTransport([response({}), response(info)])
    )
    assert code == 0, error
    transport = FakeTransport(
        [response({}), response(info), response({}), response({"demo": APP}), response(info)]
    )
    code, result, error = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=env,
        transport=transport,
    )
    assert code == 0, error
    assert result["verification"]["ok"]
    assert transport.calls[2]["parameters"]["path"] == "apps/demo"


@pytest.mark.parametrize(
    "action,after",
    [
        ("enable", {"demo": APP}),
        ("disable", {"demo": {**APP, "enabled": 0}}),
        ("unregister", {}),
    ],
)
def test_lifecycle_execution_verifies_remote_state(cli_env, action, after):
    env, key = cli_env
    add_profile(env, key)
    args = ["--profile", "test", "software", action, "--name", "demo"]
    code, plan, error = invoke(
        [*args, "--dry-run"], env=env, transport=FakeTransport([response({"demo": APP})])
    )
    assert code == 0, error
    transport = FakeTransport([response({"demo": APP}), response({}), response(after)])
    code, result, error = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=env,
        transport=transport,
    )
    assert code == 0, error
    assert result["verification"]["ok"]
    assert transport.calls[1]["function"] == action + "_application"


def test_failed_remote_verification_is_not_success(cli_env):
    env, key = cli_env
    add_profile(env, key)
    args = ["--profile", "test", "software", "disable", "--name", "demo"]
    _, plan, _ = invoke(
        [*args, "--dry-run"], env=env, transport=FakeTransport([response({"demo": APP})])
    )
    code, _, error = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=env,
        transport=FakeTransport([response({"demo": APP}), response({}), response({"demo": APP})]),
    )
    assert code != 0
    assert "verification failed" in error


@pytest.mark.parametrize(
    "contents", ['{"A":"x","A":"y"}', '{"1BAD":"x"}', '{"A":1}', '{"A":"line\\nfeed"}', "{}"]
)
def test_invalid_environment_rejected_before_network(cli_env, tmp_path, contents):
    env, key = cli_env
    add_profile(env, key)
    source = tmp_path / "env.json"
    source.write_text(contents)
    source.chmod(0o600)
    transport = FakeTransport()
    code, _, _ = invoke(
        [
            "--profile",
            "test",
            "software",
            "edit",
            "--name",
            "demo",
            "--environment-file",
            str(source),
            "--dry-run",
        ],
        env=env,
        transport=transport,
    )
    assert code != 0
    assert not transport.calls


def test_unsafe_environment_file_permissions_rejected(cli_env, tmp_path):
    env, key = cli_env
    add_profile(env, key)
    source = tmp_path / "env.json"
    source.write_text('{"A":"secret"}')
    source.chmod(0o644)
    transport = FakeTransport()
    code, _, _ = invoke(
        [
            "--profile",
            "test",
            "software",
            "edit",
            "--name",
            "demo",
            "--environment-file",
            str(source),
            "--dry-run",
        ],
        env=env,
        transport=transport,
    )
    assert code != 0
    assert not transport.calls


@pytest.mark.parametrize("path", ["../escape", "/etc/app", "apps/../escape"])
def test_registration_rejects_unsafe_relative_paths(cli_env, path):
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport()
    code, _, _ = invoke(
        [
            "--profile",
            "test",
            "software",
            "register",
            "--name",
            "demo",
            "--domain",
            "example.com",
            "--path",
            path,
            "--dry-run",
        ],
        env=env,
        transport=transport,
    )
    assert code != 0
    assert not transport.calls


def test_dependencies_are_reported_as_started_not_finished(cli_env):
    env, key = cli_env
    add_profile(env, key)
    args = [
        "--profile",
        "test",
        "software",
        "dependencies",
        "--app-path",
        "/home/account/apps/demo",
        "--type",
        "npm",
    ]
    code, plan, error = invoke(
        [*args, "--dry-run"], env=env, transport=FakeTransport([response({"demo": APP})])
    )
    assert code == 0, error
    transport = FakeTransport([response({"demo": APP}), response({"task_id": "task-1"})])
    code, result, error = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=env,
        transport=transport,
    )
    assert code == 0, error
    assert result["verification"]["category"] == "started"
    assert result["data"]["task_id"] == "task-1"


def test_confirmation_rejects_changed_remote_application(cli_env):
    env, key = cli_env
    add_profile(env, key)
    args = ["--profile", "test", "software", "disable", "--name", "demo"]
    code, plan, error = invoke(
        [*args, "--dry-run"], env=env, transport=FakeTransport([response({"demo": APP})])
    )
    assert code == 0, error
    transport = FakeTransport([response({"demo": {**APP, "domain": "changed.example"}})])
    code, _, _ = invoke(
        [*args, "--confirm", plan["confirmation"], "--expires-at", plan["expires_at"]],
        env=env,
        transport=transport,
    )
    assert code != 0
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "args",
    [
        ["dependencies", "--app-path", "/home/account/apps/demo", "--type", "shell"],
        ["edit", "--name", "demo", "--deployment-mode", "unknown"],
        ["edit", "--name", "demo", "--path", "/home/account/bad\npath"],
        ["edit", "--name", "demo"],
    ],
)
def test_invalid_changes_are_rejected_before_preflight(cli_env, args):
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport()
    code, _, _ = invoke(
        ["--profile", "test", "software", *args, "--dry-run"], env=env, transport=transport
    )
    assert code != 0
    assert not transport.calls


def test_edit_cannot_escape_account_home(cli_env):
    env, key = cli_env
    add_profile(env, key)
    transport = FakeTransport([response({"demo": APP}), response({"home": "/home/account"})])
    code, _, error = invoke(
        [
            "--profile",
            "test",
            "software",
            "edit",
            "--name",
            "demo",
            "--path",
            "/home/other/app",
            "--dry-run",
        ],
        env=env,
        transport=transport,
    )
    assert code != 0
    assert "below the account home" in error


def test_confirmation_binds_redacted_absolute_path(cli_env):
    env, key = cli_env
    add_profile(env, key)
    info = {"home": "/home/account"}
    args = ["--profile", "test", "software", "edit", "--name", "demo", "--path"]
    code, plan, error = invoke(
        [*args, "/home/account/first", "--dry-run"],
        env=env,
        transport=FakeTransport([response({"demo": APP}), response(info)]),
    )
    assert code == 0, error
    transport = FakeTransport([response({"demo": APP}), response(info)])
    code, _, _ = invoke(
        [
            *args,
            "/home/account/second",
            "--confirm",
            plan["confirmation"],
            "--expires-at",
            plan["expires_at"],
        ],
        env=env,
        transport=transport,
    )
    assert code != 0
    assert len(transport.calls) == 2
