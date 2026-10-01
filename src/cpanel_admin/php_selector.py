"""Fixed CloudLinux PHP Selector operations over account-only OpenSSH."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import stat
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from .audit import AuditEvent, AuditWriter
from .confirmation import ConfirmationService
from .errors import ConfigError, TransportError, UsageError, VerificationError
from .profiles import Profile, ProfileStore
from .secrets import SecretCodec

READ_ACTIONS = ("versions", "current", "extensions", "options")
MUTATIONS = ("set-version", "enable-extensions", "disable-extensions", "set-option")
_VERSION = re.compile(r"(?:native|[0-9]{1,2}\.[0-9]{1,2})\Z")
_EXTENSION = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_POLICY = "cloudlinux-selectorctl-account-v1"
_BOOLEANS = {
    "display_errors",
    "log_errors",
    "allow_url_fopen",
    "file_uploads",
    "display_startup_errors",
    "session.use_strict_mode",
}
_SIZES = {"memory_limit", "upload_max_filesize", "post_max_size"}
_INTEGERS = {"max_execution_time", "max_input_time", "max_input_vars", "max_file_uploads"}
OPTIONS = frozenset(_BOOLEANS | _SIZES | _INTEGERS)


def _version(value: object, *, native: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not _VERSION.fullmatch(value)
        or (value == "native" and not native)
    ):
        raise UsageError(
            "Use a PHP major.minor version; native is allowed only for version selection"
        )
    return value


def option_value(name: str, value: str) -> str:
    """Validate only reviewed, non-secret scalar PHP option values."""
    if name in _BOOLEANS and value.lower() in {"on", "off", "1", "0"}:
        return "on" if value.lower() in {"on", "1"} else "off"
    if name in _SIZES and re.fullmatch(r"[0-9]{1,10}[KMGkmg]?", value):
        return value.upper()
    if name == "memory_limit" and value == "-1":
        return value
    if name in _INTEGERS and re.fullmatch(r"[0-9]{1,10}", value):
        return str(int(value))
    if name == "max_input_time" and value == "-1":
        return value
    raise UsageError("Unsupported PHP option or value; use a reviewed boolean, limit, or timeout")


def normalized(action: str, values: Mapping[str, object]) -> dict[str, str]:
    """Reject undeclared parameters and normalize the fixed command surface."""
    fields = {
        "versions": set(),
        "current": set(),
        "extensions": {"version"},
        "options": {"version"},
        "set-version": {"version"},
        "enable-extensions": {"version", "extensions"},
        "disable-extensions": {"version", "extensions"},
        "set-option": {"version", "option", "value"},
    }
    if action not in fields or set(values) != fields[action]:
        raise UsageError("Unknown PHP Selector operation or parameters")
    result = {key: str(value) for key, value in values.items()}
    if "version" in result:
        result["version"] = _version(values["version"], native=action == "set-version")
    if "extensions" in result:
        extensions = result["extensions"].split(",")
        if not 1 <= len(extensions) <= 128 or not all(_EXTENSION.fullmatch(x) for x in extensions):
            raise UsageError("Extensions must be comma-separated PHP extension names")
        result["extensions"] = ",".join(sorted(set(extensions)))
    if action == "set-option":
        result["value"] = option_value(result["option"], result["value"])
    return result


def command(action: str, values: Mapping[str, object]) -> list[str]:
    """Build an allowlisted selectorctl command with no cross-account switches."""
    values = normalized(action, values)
    args = ["/usr/bin/selectorctl", "--interpreter=php"]
    flags = {
        "versions": "--user-summary",
        "current": "--user-current",
        "extensions": "--list-user-extensions",
        "options": "--print-options",
    }
    if action in flags:
        args.append(flags[action])
    elif action == "set-version":
        args.append("--set-user-current=" + values["version"])
    elif action in {"enable-extensions", "disable-extensions"}:
        flag = (
            "--enable-user-extensions="
            if action == "enable-extensions"
            else "--disable-user-extensions="
        )
        args.append(flag + values["extensions"])
    else:
        args.append("--add-options=" + values["option"] + ":" + values["value"])
    if "version" in values and action != "set-version":
        args.append("--version=" + values["version"])
    if action == "extensions":
        args.append("--all")
    return args


def _ssh(profile: Profile, action: str, values: Mapping[str, object], timeout: int) -> str:
    remote = command(action, values)
    if profile.ssh is None:
        raise ConfigError(
            "Configure this profile with profiles configure-ssh before using PHP Selector"
        )
    if profile.username == "root":
        raise ConfigError("PHP Selector cannot connect as root")
    settings = profile.ssh
    args = [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=2",
        "-p",
        str(settings.port),
        "-l",
        profile.username,
    ]
    if settings.identity_file:
        path = Path(settings.identity_file)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ConfigError("Cannot inspect the configured SSH identity file") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
        ):
            raise ConfigError("SSH identity must be an owned regular file with mode 0400 or 0600")
        args.extend(["-o", "IdentitiesOnly=yes", "-i", str(path)])
    args.extend(["--", settings.host, shlex.join(remote)])
    # API credentials and the Fernet key must never reach the SSH child environment.
    child_env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LANG": "C", "LC_ALL": "C"}
    if os.environ.get("SSH_AUTH_SOCK"):
        child_env["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    try:
        completed = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            env=child_env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TransportError(
            "PHP Selector SSH timed out; inspect state before retrying a change"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise TransportError("Unable to run PHP Selector through OpenSSH") from exc
    if completed.returncode == 255:
        raise TransportError(
            "SSH connection failed; check host trust, account key access, and SSH port"
        )
    if completed.returncode != 0:
        raise TransportError(
            "PHP Selector command failed; check account access and CageFS 7.6.17+ support"
        )
    if len(completed.stdout.encode()) > 1024 * 1024:
        raise TransportError("PHP Selector output exceeds the size limit")
    return completed.stdout


def _parse(action: str, output: str) -> dict:
    result = {}
    if action == "current":
        fields = output.strip().split()
        if len(fields) != 3 or not _VERSION.fullmatch(fields[0]):
            raise TransportError("Unrecognized PHP Selector current-version response")
        return {"version": fields[0]}
    if action in {"versions", "extensions"}:
        for line in output.splitlines():
            if not line.strip():
                continue
            fields = line.split()
            if action == "versions":
                if (
                    len(fields) != 4
                    or not _VERSION.fullmatch(fields[0])
                    or fields[1] not in {"e", "-"}
                    or fields[2] not in {"d", "-"}
                    or fields[3] not in {"s", "-"}
                    or fields[0] in result
                ):
                    raise TransportError("Unrecognized PHP Selector versions response")
                result[fields[0]] = {
                    "enabled": fields[1] == "e",
                    "default": fields[2] == "d",
                    "selected": fields[3] == "s",
                }
            else:
                if (
                    len(fields) != 2
                    or fields[0] not in {"+", "-", "~"}
                    or not _EXTENSION.fullmatch(fields[1])
                    or fields[1] in result
                ):
                    raise TransportError("Unrecognized PHP Selector extensions response")
                result[fields[1]] = {
                    "enabled": fields[0] in {"+", "~"},
                    "builtin": fields[0] == "~",
                }
        if not result:
            raise TransportError("PHP Selector returned an empty inventory")
        return result
    # selectorctl's documented text format uses TITLE and DEFAULT for effective options.
    title = None
    for line in output.splitlines():
        if line.startswith("TITLE:"):
            title = line.partition(":")[2].strip()
        elif line.startswith("DEFAULT:") and title in OPTIONS:
            if title in result:
                raise TransportError("PHP Selector returned duplicate options")
            try:
                result[title] = option_value(title, line.partition(":")[2].strip())
            except UsageError as exc:
                raise TransportError("PHP Selector returned an unsupported option value") from exc
    if not result:
        raise TransportError("Unrecognized PHP Selector options response")
    return result


def read(profile: Profile, action: str, values: Mapping[str, object], timeout: int) -> dict:
    """Read and validate one fixed account PHP Selector inventory."""
    if action not in READ_ACTIONS:
        raise UsageError("Not a PHP Selector read operation")
    return _parse(action, _ssh(profile, action, values, timeout))


def add_parsers(groups: argparse._SubParsersAction) -> None:
    """Install fixed PHP Selector subcommands."""
    group = groups.add_parser("php-selector", help="CloudLinux PHP Selector over account SSH")
    actions = group.add_subparsers(dest="selector_action", required=True)
    for action in (*READ_ACTIONS, *MUTATIONS):
        parser = actions.add_parser(action, allow_abbrev=False)
        if action not in {"versions", "current"}:
            parser.add_argument("--version", required=True)
        if action.endswith("-extensions"):
            parser.add_argument("--extensions", required=True)
        if action == "set-option":
            parser.add_argument("--option", required=True, choices=sorted(OPTIONS))
            parser.add_argument("--value", required=True)
        if action in MUTATIONS:
            parser.add_argument("--dry-run", action="store_true")
            parser.add_argument("--confirm")
            parser.add_argument("--expires-at")


def run(args: argparse.Namespace, env: Mapping[str, str], store: ProfileStore) -> dict:
    """Plan, audit, execute, and independently verify the reviewed SSH operation."""
    if not args.profile:
        raise UsageError("--profile is required for PHP Selector")
    profile = store.get(args.profile)
    if profile.ssh is None:
        raise ConfigError(
            "Configure this profile with profiles configure-ssh before using PHP Selector"
        )
    action = args.selector_action
    values = normalized(
        action,
        {
            key: getattr(args, key)
            for key in ("version", "extensions", "option", "value")
            if hasattr(args, key)
        },
    )
    operation = "php-selector." + action
    identity = "ssh/selectorctl/" + action
    audit = AuditWriter(args.audit_file or store.path.with_name("audit.jsonl"))

    def record(outcome: str, *, confirmed: bool, verification: str | None = None) -> bool:
        return audit.write(
            AuditEvent.from_policy(
                timestamp=datetime.now(UTC).isoformat(),
                profile=profile.name,
                operation=operation,
                identity=identity,
                risk="read" if action in READ_ACTIONS else "mutate",
                confirmed=confirmed,
                safe_values=values,
                audit_fields=tuple(values),
                outcome=outcome,
                error_category="selector" if outcome == "failure" else None,
                verification=verification,
            ),
            fail_closed=action in MUTATIONS,
        )

    if action in READ_ACTIONS:
        data = read(profile, action, values, args.timeout)
        audited = record("success", confirmed=False)
        result = {"ok": True, "profile": profile.name, "operation": operation, "data": data}
        if not audited:
            result["warnings"] = ["Unable to write protected audit record"]
        return result
    if not args.dry_run and (not args.confirm or not args.expires_at):
        raise UsageError("Run --dry-run and approve its confirmation digest and expiry first")
    service = ConfirmationService(SecretCodec.from_environment(env).key)
    versions = read(profile, "versions", {}, args.timeout)
    if values["version"] not in versions or not versions[values["version"]]["enabled"]:
        raise UsageError("The requested PHP version is not available for this account")
    state_action = (
        "current"
        if action == "set-version"
        else ("options" if action == "set-option" else "extensions")
    )
    state_values = {} if state_action == "current" else {"version": values["version"]}
    before = read(profile, state_action, state_values, args.timeout)
    if "extensions" in values:
        for name in values["extensions"].split(","):
            if name not in before or before[name]["builtin"]:
                raise UsageError("Extension is unavailable or compiled in and cannot be toggled")
    if action == "set-option" and values["option"] not in before:
        raise UsageError("The hosting provider does not expose this PHP option")
    endpoint = {"host": profile.ssh.host, "port": profile.ssh.port, "username": profile.username}
    preflight = {"state": before, "versions": versions, "endpoint": endpoint}
    bound = dict(
        profile=profile.name,
        account=profile.username,
        identity=identity,
        operation=operation,
        parameters=values,
        preflight=preflight,
        policy_digest=_POLICY,
        risk="mutate",
        elevated_impact=True,
    )
    if args.dry_run:
        plan = service.plan_v2(**bound)
        return {
            "ok": True,
            "dry_run": True,
            "operation": operation,
            "profile": profile.name,
            "target": endpoint,
            "parameters": values,
            "before": before,
            "requires_confirmation": True,
            "confirmation": plan.confirmation,
            "expires_at": plan.expires_at,
            "impact": "Change account PHP settings; affected websites may change behavior.",
            "recovery": "Reapply the previous settings shown in this plan.",
        }
    service.verify_v2(args.confirm, expires_at=args.expires_at, **bound)
    record("intent", confirmed=True)
    try:
        _ssh(profile, action, values, args.timeout)
        after = read(profile, state_action, state_values, args.timeout)
        if action == "set-version":
            verified = after["version"] == values["version"]
        elif action == "set-option":
            verified = after.get(values["option"]) == values["value"]
        else:
            verified = all(
                after.get(name, {}).get("enabled") == (action == "enable-extensions")
                for name in values["extensions"].split(",")
            )
        if not verified:
            raise VerificationError("PHP Selector change did not match the requested state")
    except Exception:
        record("failure", confirmed=True)
        raise
    record("success", confirmed=True, verification="selector_state")
    return {
        "ok": True,
        "operation": operation,
        "profile": profile.name,
        "verified": True,
        "data": after,
    }
