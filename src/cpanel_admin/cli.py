"""Task-oriented command-line interface for safe cPanel account administration."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from .audit import AuditEvent, AuditWriter
from .capabilities import CapabilityService
from .catalog import Catalog
from .confirmation import ConfirmationService
from .errors import ConfigError, ConfirmationError, CPanelAdminError, UsageError
from .executor import ExecutionContext, ExecutionResult, OperationExecutor
from .inputs import InputResolver
from .legacy_api2 import LEGACY_FILE_OPERATIONS, LegacyFileExecutor, resolve_legacy_file_inputs
from .planner import ExecutionPlan, OperationPlanner
from .policy import (
    InputSource,
    PolicyError,
    PolicyOperation,
    PolicyRegistry,
    SupportStatus,
    canonical_policy_sha256,
    policy_operation_to_dict,
)
from .policy import (
    Risk as PolicyRisk,
)
from .profiles import ProfileStore, default_profile_path
from .redaction import redact
from .secrets import SecretCodec
from .transport import UAPIResponse, UAPITransport


def _confirmation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dry-run", action="store_true", help="validate and return a plan")
    parser.add_argument("--confirm", help="operation-bound confirmation digest")
    parser.add_argument("--expires-at", help="expiry from the dry-run plan")


def _operation_parser(
    subparsers: Any,
    command: str,
    operation: str,
    arguments: Sequence[tuple[tuple[str, ...], dict[str, object]]] = (),
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(command)
    parser.set_defaults(operation=operation)
    for flags, options in arguments:
        parser.add_argument(*flags, **options)
    _confirmation_options(parser)
    return parser


def _default_policy_registry() -> PolicyRegistry:
    catalog = Catalog.load()
    operations = tuple(
        operation.policy
        for operation in catalog.operations.values()
        if operation.policy is not None
    )
    return PolicyRegistry(operations, (), ())


def _audit_path(args: argparse.Namespace, env: Mapping[str, str]) -> Path:
    if args.audit_file is not None:
        return args.audit_file
    return default_profile_path(env).with_name("audit.jsonl")


def _flag_name(name: str) -> str:
    return "--" + name.replace("_", "-")


def _add_policy_parameter(parser: argparse.ArgumentParser, parameter: object) -> None:
    source = parameter.sources[0]
    flag = _flag_name(parameter.name)
    kwargs: dict[str, object] = {"dest": parameter.name, "required": parameter.required}
    if parameter.validator in {"integer", "trash_age"}:
        kwargs["type"] = int
    if source is InputSource.ARGUMENT:
        parser.add_argument(flag, **kwargs)
        return
    if source is InputSource.STDIN:
        parser.add_argument(f"{flag}-stdin", action="store_true", **kwargs)
        return
    if source is InputSource.PROTECTED_FILE:
        parser.add_argument(f"{flag}-file", flag, **kwargs)
        return
    if source in {InputSource.LOCAL_FILE, InputSource.JSON_FILE}:
        parser.add_argument(flag, **kwargs)
        return
    if source is InputSource.ENVIRONMENT:
        parser.add_argument(f"{flag}-env", **kwargs)
        return
    if source is InputSource.ENCRYPTED_PROFILE:
        parser.add_argument(f"{flag}-profile", action="store_true", **kwargs)
        return
    raise UsageError(f"Unsupported input source for {parameter.name}")


def _add_policy_operation(
    root_subparsers: Any,
    groups_by_name: dict[str, argparse.ArgumentParser],
    operation: PolicyOperation,
) -> None:
    if len(operation.command) != 2:
        raise PolicyError(f"included operation has invalid command path: {operation.identity}")
    group_name, action = operation.command
    group = groups_by_name.get(group_name)
    if group is None:
        group = root_subparsers.add_parser(group_name)
        group.set_defaults(group=group_name)
        group.add_subparsers(dest="action", required=True)
        groups_by_name[group_name] = group
    action_subparsers = next(
        action for action in group._actions if isinstance(action, argparse._SubParsersAction)
    )
    parser = action_subparsers.add_parser(action, allow_abbrev=False)
    parser.set_defaults(
        operation=operation.name,
        dry_run=False,
        confirm=None,
        expires_at=None,
    )
    for parameter in operation.parameters.values():
        _add_policy_parameter(parser, parameter)
    if operation.risk is not None and operation.risk is not PolicyRisk.READ:
        _confirmation_options(parser)


def _action_subparsers(group: argparse.ArgumentParser) -> Any:
    return next(
        action for action in group._actions if isinstance(action, argparse._SubParsersAction)
    )


def _add_policy_operation_alias(
    groups_by_name: dict[str, argparse.ArgumentParser],
    operation: PolicyOperation,
    alias: str,
) -> None:
    group = groups_by_name["files"]
    parser = _action_subparsers(group).add_parser(alias, allow_abbrev=False)
    parser.set_defaults(
        operation=operation.name,
        dry_run=False,
        confirm=None,
        expires_at=None,
    )
    for parameter in operation.parameters.values():
        _add_policy_parameter(parser, parameter)
    _confirmation_options(parser)


def _add_legacy_file_operations(groups_by_name: dict[str, argparse.ArgumentParser]) -> None:
    group = groups_by_name["files"]
    subparsers = _action_subparsers(group)
    for operation in sorted(LEGACY_FILE_OPERATIONS.values(), key=lambda item: item.command):
        _add_legacy_file_operation(subparsers, operation.name, operation.command[1])


def _add_legacy_file_operation(subparsers: Any, operation_name: str, action: str) -> None:
    parser = subparsers.add_parser(action, allow_abbrev=False)
    parser.set_defaults(
        legacy_api2_operation=operation_name,
        dry_run=False,
        confirm=None,
        expires_at=None,
    )
    if action == "create-directory":
        parser.add_argument("--directory", required=True)
        parser.add_argument("--name", required=True)
        parser.add_argument("--permissions")
    elif action in {"delete-path"}:
        parser.add_argument("--source", required=True)
    elif action in {"rename-path", "copy-path", "move-path", "extract"}:
        parser.add_argument("--source", required=True)
        parser.add_argument("--destination", required=True)
    elif action == "chmod-path":
        parser.add_argument("--source", required=True)
        parser.add_argument("--permissions", required=True)
    elif action == "compress":
        parser.add_argument("--source", required=True)
        parser.add_argument("--destination", required=True)
        parser.add_argument("--archive-type", required=True)
    else:  # pragma: no cover - registry and parser additions are intentionally locked together
        raise UsageError(f"Unsupported legacy file command: {action}")
    _confirmation_options(parser)


def build_parser(registry: PolicyRegistry | None = None) -> argparse.ArgumentParser:
    policy = registry or _default_policy_registry()
    parser = argparse.ArgumentParser(
        prog="cpanel-admin",
        description="Safe task-oriented administration for individual cPanel accounts",
        allow_abbrev=False,
    )
    parser.add_argument("--profile", help="named cPanel profile")
    parser.add_argument("--config", type=Path, help="override the profile store path")
    parser.add_argument("--timeout", type=int, default=30, help="request timeout (1-120 seconds)")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    parser.add_argument("--audit-file", type=Path, help="override the audit JSONL path")
    groups = parser.add_subparsers(dest="group", required=True)

    profiles = groups.add_parser("profiles", help="manage encrypted named profiles")
    profile_commands = profiles.add_subparsers(dest="profile_command", required=True)
    profile_commands.add_parser("list")
    show = profile_commands.add_parser("show")
    show.add_argument("name")
    add = profile_commands.add_parser("add")
    add.add_argument("name")
    add.add_argument("--host", required=True)
    add.add_argument("--username", required=True)
    add.add_argument("--api-token-stdin", action="store_true", required=True)
    add.add_argument("--replace", action="store_true")
    remove = profile_commands.add_parser("remove")
    remove.add_argument("name")
    _confirmation_options(remove)
    test = profile_commands.add_parser("test")
    test.add_argument("name")
    profile_commands.add_parser("rotate-key")

    operation_groups: dict[str, argparse.ArgumentParser] = {}
    for operation in sorted(policy.included(), key=lambda item: item.command):
        _add_policy_operation(groups, operation_groups, operation)
    write_operation = policy.get("files.write")
    _add_policy_operation_alias(operation_groups, write_operation, "create-file")
    _add_policy_operation_alias(operation_groups, write_operation, "update-file")
    _add_legacy_file_operations(operation_groups)

    operations = groups.add_parser("operations", help="discover reviewed operation policy")
    operation_commands = operations.add_subparsers(dest="operations_command", required=True)
    operation_list = operation_commands.add_parser("list")
    operation_list.add_argument("--capability")
    operation_list.add_argument("--status", choices=[status.value for status in SupportStatus])

    capabilities = groups.add_parser("capabilities", help="inspect server capability availability")
    capability_commands = capabilities.add_subparsers(dest="capability_command", required=True)
    capability_commands.add_parser("inspect")
    return parser


def _write_json(stream: TextIO, value: object, pretty: bool = False) -> None:
    json.dump(value, stream, indent=2 if pretty else None, sort_keys=True)
    stream.write("\n")


def _read_secret(stdin: TextIO, label: str) -> str:
    value = stdin.read().rstrip("\r\n")
    if not value:
        raise UsageError(f"{label} supplied on standard input must not be empty")
    return value


def _json_safe(value: object) -> object:
    if value is None or isinstance(value, str | int | bool):
        return value
    if isinstance(value, float):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in sorted(value.items())}
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    return str(value)


def _success(profile: str, operation: str, response: UAPIResponse) -> dict[str, object]:
    return {
        "ok": True,
        "profile": profile,
        "operation": operation,
        "data": response.data,
        "warnings": response.warnings,
        "messages": response.messages,
        "summary": f"Completed {operation} for {profile}",
    }


def _run_operation(
    args: argparse.Namespace,
    env: Mapping[str, str],
    stdin: TextIO,
    store: ProfileStore,
    transport: UAPITransport,
) -> dict[str, object]:
    if not args.profile:
        raise UsageError("--profile is required for cPanel operations")
    return _run_policy_operation(args, env, stdin, store, transport)


def _plan_result(plan: ExecutionPlan) -> dict[str, object]:
    parameters = _json_safe(plan.parameters)
    if plan.operation in {"files.write", "files.upload"} and plan.preflight is not None:
        parameters = dict(parameters)
        parameters["preflight"] = _json_safe(plan.preflight)
    return {
        "ok": True,
        "dry_run": True,
        "profile": plan.profile,
        "operation": plan.operation,
        "identity": plan.identity,
        "risk": plan.risk.value,
        "elevated_impact": plan.elevated_impact,
        "parameters": parameters,
        "preflight": _json_safe(plan.preflight),
        "impact": plan.impact,
        "recovery": plan.recovery,
        "verification_available": plan.verification_available,
        "requires_confirmation": plan.requires_confirmation,
        "expires_at": plan.expires_at,
        "confirmation": plan.confirmation,
    }


def _execution_result(result: ExecutionResult) -> dict[str, object]:
    return {
        "ok": result.ok,
        "profile": result.profile,
        "operation": result.operation,
        "identity": result.identity,
        "data": _json_safe(result.data),
        "warnings": list(result.warnings),
        "messages": list(result.messages),
        "verification": None
        if result.verification is None
        else {
            "ok": result.verification.ok,
            "category": result.verification.category,
            "evidence": _json_safe(result.verification.evidence),
        },
        "summary": f"Completed {result.operation} for {result.profile}",
    }


def _legacy_values(args: argparse.Namespace) -> dict[str, object]:
    return {
        name: value
        for name in ("directory", "name", "permissions", "source", "destination", "archive_type")
        if (value := getattr(args, name, None)) is not None
    }


def _legacy_plan(
    profile: str,
    account: str,
    operation,
    parameters: Mapping[str, object],
    confirmation: ConfirmationService,
) -> dict[str, object]:
    expires_at = None
    digest = None
    if operation.requires_confirmation:
        plan = confirmation.plan_v2(
            profile=profile,
            account=account,
            identity=operation.identity,
            operation=operation.name,
            parameters=parameters,
            preflight=None,
            policy_digest="legacy-cpanel-api-2-fileman",
            risk=operation.risk,
            elevated_impact=operation.elevated_impact,
        )
        expires_at = plan.expires_at
        digest = plan.confirmation
    return {
        "ok": True,
        "dry_run": True,
        "profile": profile,
        "operation": operation.name,
        "identity": operation.identity,
        "legacy_api": "cpanel-api-2",
        "risk": operation.risk,
        "elevated_impact": operation.elevated_impact,
        "parameters": dict(parameters),
        "impact": operation.impact,
        "recovery": operation.recovery,
        "requires_confirmation": operation.requires_confirmation,
        "expires_at": expires_at,
        "confirmation": digest,
    }


def _run_legacy_api2_operation(
    args: argparse.Namespace,
    env: Mapping[str, str],
    store: ProfileStore,
    transport: UAPITransport,
) -> dict[str, object]:
    if not args.profile:
        raise UsageError("--profile is required for cPanel operations")
    try:
        operation = LEGACY_FILE_OPERATIONS[args.legacy_api2_operation]
    except KeyError as exc:
        raise UsageError("Unknown legacy cPanel API 2 file operation") from exc
    profile = store.get(args.profile)
    codec = SecretCodec.from_environment(env)
    token = codec.decrypt(profile.encrypted_token)
    command_values = _legacy_values(args)
    parameters = resolve_legacy_file_inputs(operation, command_values)
    confirmation = ConfirmationService(codec.key)
    if args.dry_run:
        return _legacy_plan(profile.name, profile.username, operation, parameters, confirmation)
    if operation.requires_confirmation:
        confirmation.verify_v2(
            args.confirm,
            profile=profile.name,
            account=profile.username,
            identity=operation.identity,
            operation=operation.name,
            parameters=parameters,
            preflight=None,
            policy_digest="legacy-cpanel-api-2-fileman",
            expires_at=args.expires_at,
            risk=operation.risk,
            elevated_impact=operation.elevated_impact,
        )
    audit = AuditWriter(_audit_path(args, env))
    event = AuditEvent.from_policy(
        timestamp=datetime.now(UTC).isoformat(),
        profile=profile.name,
        operation=operation.name,
        identity=operation.identity,
        risk=operation.risk,
        confirmed=operation.requires_confirmation,
        safe_values=command_values,
        audit_fields=tuple(command_values),
        outcome="intent",
        error_category=None,
        verification=None,
    )
    audit.write(event, fail_closed=True)
    response = LegacyFileExecutor(transport).execute(
        profile, token, operation, command_values, timeout=args.timeout
    )
    audit.write(
        AuditEvent.from_policy(
            timestamp=datetime.now(UTC).isoformat(),
            profile=profile.name,
            operation=operation.name,
            identity=operation.identity,
            risk=operation.risk,
            confirmed=operation.requires_confirmation,
            safe_values=command_values,
            audit_fields=tuple(command_values),
            outcome="success",
            error_category=None,
            verification=None,
        ),
        fail_closed=True,
    )
    return {
        "ok": True,
        "profile": profile.name,
        "operation": operation.name,
        "identity": operation.identity,
        "legacy_api": "cpanel-api-2",
        "data": _json_safe(response.data),
        "warnings": response.warnings,
        "messages": response.messages,
        "summary": f"Completed {operation.name} for {profile.name}",
    }


def _run_policy_operation(
    args: argparse.Namespace,
    env: Mapping[str, str],
    stdin: TextIO,
    store: ProfileStore,
    transport: UAPITransport,
) -> dict[str, object]:
    registry = _default_policy_registry()
    operation = registry.get(args.operation)
    profile = store.get(args.profile)
    codec = SecretCodec.from_environment(env)
    token = codec.decrypt(profile.encrypted_token)
    inputs = InputResolver().resolve(operation, args, stdin, env)
    context = ExecutionContext(
        profile=profile,
        token=token,
        timeout=args.timeout,
        transport=transport,
        audit=AuditWriter(_audit_path(args, env)),
        policy=registry,
    )
    executor = OperationExecutor(
        registry=registry,
        planner=OperationPlanner(
            ConfirmationService(codec.key),
            registry=registry,
            policy_digest=canonical_policy_sha256(registry),
        ),
    )
    if args.dry_run:
        return _plan_result(executor.dry_run(context, operation, inputs))
    if operation.requires_confirmation and args.confirm is None:
        raise ConfirmationError("Confirmation is required for this operation")
    return _execution_result(
        executor.execute(context, operation, inputs, args.confirm, expires_at=args.expires_at)
    )


def _profile_result(operation: str, data: object) -> dict[str, object]:
    return {"ok": True, "operation": operation, "data": data}


def _run_operations_discovery(
    args: argparse.Namespace, registry: PolicyRegistry
) -> dict[str, object]:
    status = args.status
    if status == SupportStatus.INCLUDED.value:
        operations = registry.included()
    elif status == SupportStatus.EXCLUDED.value:
        operations = registry.excluded()
    else:
        operations = registry.all()
    if args.capability:
        operations = tuple(
            operation for operation in operations if operation.capability == args.capability
        )
    return _profile_result(
        "operations.list",
        [policy_operation_to_dict(operation) for operation in operations],
    )


def _run_capabilities(
    args: argparse.Namespace,
    env: Mapping[str, str],
    store: ProfileStore,
    transport: UAPITransport,
    registry: PolicyRegistry,
) -> dict[str, object]:
    if args.capability_command != "inspect":
        raise UsageError("Unknown capability command")
    if not args.profile:
        raise UsageError("--profile is required for capability inspection")
    profile = store.get(args.profile)
    token = SecretCodec.from_environment(env).decrypt(profile.encrypted_token)
    context = type(
        "CapabilityContext",
        (),
        {
            "profile": profile,
            "token": token,
            "transport": transport,
            "policy": registry,
        },
    )()
    report = CapabilityService().inspect(context)
    return _profile_result(
        "capabilities.inspect",
        {
            "profile": report.profile,
            "observed_at": report.observed_at,
            "operations": {
                name: {
                    "operation": item.operation,
                    "status": item.status.value,
                    "feature": item.feature,
                    "reason": item.reason,
                }
                for name, item in sorted(report.operations.items())
            },
        },
    )


def _run_profiles(
    args: argparse.Namespace,
    env: Mapping[str, str],
    stdin: TextIO,
    store: ProfileStore,
    transport: UAPITransport,
) -> dict[str, object]:
    command = args.profile_command
    if command == "list":
        return _profile_result("profiles.list", [profile.public_dict() for profile in store.list()])
    if command == "show":
        return _profile_result("profiles.show", store.get(args.name).public_dict())
    if command == "add":
        codec = SecretCodec.from_environment(env)
        token = _read_secret(stdin, "API token")
        profile = store.add(args.name, args.host, args.username, token, codec, replace=args.replace)
        return _profile_result("profiles.add", profile.public_dict())
    if command == "remove":
        codec = SecretCodec.from_environment(env)
        profile = store.get(args.name)
        parameters = profile.public_dict()
        service = ConfirmationService(codec.key)
        if args.dry_run:
            plan = service.plan(
                profile.name,
                "profiles.remove",
                parameters,
                "Delete the local encrypted cPanel profile",
                "Recreate the profile with a new API token",
            )
            return {"ok": True, "dry_run": True, **plan.to_dict()}
        service.verify(args.confirm, profile.name, "profiles.remove", parameters, args.expires_at)
        return _profile_result("profiles.remove", store.remove(args.name).public_dict())
    if command == "test":
        codec = SecretCodec.from_environment(env)
        profile = store.get(args.name)
        token = codec.decrypt(profile.encrypted_token)
        response = transport.call(profile, token, "DomainInfo", "list_domains", {}, args.timeout)
        return redact(_success(profile.name, "profiles.test", response), secrets=(token,))
    if command == "rotate-key":
        codec = SecretCodec.from_environment(env)
        new_value = env.get("CPANEL_ADMIN_FERNET_KEY_NEW")
        if not new_value:
            raise ConfigError("CPANEL_ADMIN_FERNET_KEY_NEW is required")
        try:
            new_codec = SecretCodec(new_value.encode("ascii"))
        except UnicodeEncodeError as exc:
            raise ConfigError("CPANEL_ADMIN_FERNET_KEY_NEW is not a valid Fernet key") from exc
        return _profile_result("profiles.rotate-key", {"rotated": store.rotate(codec, new_codec)})
    raise UsageError("Unknown profile command")


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    transport: UAPITransport | None = None,
) -> int:
    """Run the CLI and return a stable process exit code."""
    values = os.environ if env is None else env
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    error_stream = sys.stderr if stderr is None else stderr
    parser = build_parser()
    try:
        with redirect_stdout(output_stream), redirect_stderr(error_stream):
            try:
                args = parser.parse_args(argv)
            except SystemExit as exc:
                return int(exc.code)
        if not 1 <= args.timeout <= 120:
            raise UsageError("Timeout must be between 1 and 120 seconds")
        store_path = args.config or default_profile_path(values)
        store = ProfileStore(store_path)
        client = transport or UAPITransport()
        registry = _default_policy_registry()
        if args.group == "profiles":
            result = _run_profiles(args, values, input_stream, store, client)
        elif args.group == "operations":
            result = _run_operations_discovery(args, registry)
        elif args.group == "capabilities":
            result = _run_capabilities(args, values, store, client, registry)
        elif hasattr(args, "legacy_api2_operation"):
            result = _run_legacy_api2_operation(args, values, store, client)
        else:
            result = _run_operation(args, values, input_stream, store, client)
        _write_json(output_stream, result, args.pretty)
        return 0
    except CPanelAdminError as exc:
        error_stream.write(f"Error: {exc}\n")
        return exc.exit_code
    except Exception:
        error_stream.write("Error: unexpected internal failure\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
