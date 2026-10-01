"""Reviewed Passenger application validation, planning, and verification."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING

from .errors import UsageError

if TYPE_CHECKING:
    from .executor import ExecutionContext
    from .inputs import ResolvedInputs
    from .planner import VerificationResult
    from .policy import PolicyOperation


def application_name(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 50 or value != value.strip():
        raise UsageError("Application names must contain 1 to 50 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise UsageError("Application name contains control characters")
    return value


def relative_application_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise UsageError("Application path must be a relative path below the account home")
    return value


def base_uri(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"/(?:[A-Za-z0-9_.~-]+/?)*", value):
        raise UsageError("Base URI must be an absolute URL path without query or fragment")
    if any(part in {".", ".."} for part in value.split("/")):
        raise UsageError("Base URI must not contain traversal")
    return value


def environment_json(value: object) -> str:
    try:

        def unique(pairs):
            result = {}
            for name, item in pairs:
                if name in result:
                    raise ValueError("duplicate")
                result[name] = item
            return result

        data = json.loads(value, object_pairs_hook=unique) if isinstance(value, str) else None
        if not isinstance(data, dict) or not data or len(data) > 256:
            raise ValueError("object")
        for name, item in data.items():
            if not re.fullmatch(r"[A-Za-z_-][A-Za-z0-9_-]{0,255}", name):
                raise ValueError("name")
            if (
                not isinstance(item, str)
                or len(item) > 1024
                or any(not 32 <= ord(char) <= 126 for char in item)
            ):
                raise ValueError("value")
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
    except (ValueError, TypeError):
        raise UsageError(
            "Environment file must contain unique valid names and printable string values"
        ) from None


def _call(context: ExecutionContext, module: str, function: str, parameters: dict) -> object:
    return context.transport.call(
        context.profile, context.token, module, function, parameters, context.timeout
    ).data


def applications(context: ExecutionContext) -> dict:
    data = _call(context, "PassengerApps", "list_applications", {})
    if not isinstance(data, dict) or not all(
        isinstance(name, str) and isinstance(app, dict) for name, app in data.items()
    ):
        raise UsageError("cPanel returned an invalid application inventory")
    return data


def preflight(
    context: ExecutionContext, operation: PolicyOperation, inputs: ResolvedInputs
) -> dict:
    values = inputs.values
    action = operation.command[1]
    for field in ("path", "app_path"):
        value = values.get(field)
        if isinstance(value, str) and (
            "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise UsageError("Application paths must not contain control characters or backslashes")
    if "deployment_mode" in values and values["deployment_mode"] not in {
        "production",
        "development",
    }:
        raise UsageError("Deployment mode must be production or development")
    if "type" in values and values["type"] not in {"npm", "pip", "gem"}:
        raise UsageError("Dependency type must be npm, pip, or gem")
    if values.get("clear_envvars") and "environment" in values:
        raise UsageError("Choose environment replacement or clear-envvars, not both")
    if action == "edit" and set(values) == {"name"}:
        raise UsageError("Application edit requires at least one change")
    apps = applications(context)
    name = values.get("name")
    app = apps.get(name)
    if action == "register":
        if app is not None:
            raise UsageError("An application with this name already exists")
    elif action == "dependencies":
        matches = [item for item in apps.values() if item.get("path") == values["app_path"]]
        if len(matches) != 1:
            raise UsageError("Dependency path must identify exactly one registered application")
        app = matches[0]
        if (
            not isinstance(app.get("deps"), dict)
            or not app["deps"].get(values["type"])
            or app["deps"][values["type"]] == "0"
        ):
            raise UsageError("The application has no detected manifest for that dependency type")
    elif app is None:
        raise UsageError("The named application does not exist")
    if "new_name" in values and values["new_name"] != name and values["new_name"] in apps:
        raise UsageError("The new application name already exists")
    if "domain" in values or "path" in values:
        info = _call(context, "Variables", "get_user_information", {})
        if not isinstance(info, dict):
            raise UsageError("Unable to inspect account paths and domains")
        if "domain" in values and values["domain"] not in info.get("domains", []):
            raise UsageError("Application domain does not belong to the account")
        if action == "edit" and "path" in values:
            home = info.get("home")
            if not isinstance(home, str) or not values["path"].startswith(home.rstrip("/") + "/"):
                raise UsageError("Application path must remain below the account home")
    # Bind the complete remote state, including environment values, without exposing it.
    state = hashlib.sha256(
        json.dumps(app, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    request_digest = hashlib.sha256(
        json.dumps(dict(values), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    result = {"state_sha256": state, "request_sha256": request_digest, "exists": app is not None}
    if action == "edit":
        enabled = app.get("enabled")
        if enabled not in (0, 1, "0", "1"):
            raise UsageError("Application enabled state is invalid")
        result["enabled"] = int(enabled)
    return result


def parameters(
    operation: PolicyOperation, inputs: ResolvedInputs, preflight_data: Mapping, result: dict
) -> dict:
    for name in ("enabled", "clear_envvars"):
        if name in result:
            result[name] = int(result[name])
    if "environment" in inputs.values:
        env = json.loads(inputs.values["environment"])
        result["envvar_name"] = list(env)
        result["envvar_value"] = list(env.values())
    if operation.command[1] == "edit":
        # cPanel otherwise defaults enabled to 1, even for a configuration-only edit.
        result.setdefault("enabled", preflight_data["enabled"])
    return result


def verify(
    context: ExecutionContext, operation: PolicyOperation, inputs: ResolvedInputs, response: object
) -> VerificationResult:
    from .planner import VerificationResult

    action = operation.command[1]
    if action == "dependencies":
        ok = (
            isinstance(response, Mapping)
            and isinstance(response.get("task_id"), str)
            and bool(response["task_id"])
        )
        return VerificationResult(ok, "started" if ok else "verification", {})
    apps = applications(context)
    values = inputs.values
    name = values.get("new_name", values["name"])
    app = apps.get(name)
    if action == "unregister":
        return VerificationResult(app is None, "application_state", {"exists": app is not None})
    ok = app is not None
    if app is not None:
        expected = {
            key: values[key]
            for key in ("domain", "deployment_mode", "base_uri", "enabled")
            if key in values
        }
        if action in {"enable", "disable"}:
            expected["enabled"] = int(action == "enable")
        if action == "register":
            expected.setdefault("enabled", 1)
            expected.setdefault("deployment_mode", "production")
            expected.setdefault("base_uri", "/")
        ok = all(
            str(app.get(key)) == str(int(value) if isinstance(value, bool) else value)
            for key, value in expected.items()
        )
        if "path" in values:
            if action == "register":
                info = _call(context, "Variables", "get_user_information", {})
                home = info.get("home") if isinstance(info, dict) else None
                ok = (
                    ok
                    and isinstance(home, str)
                    and app.get("path") == posixpath.join(home, values["path"])
                )
            else:
                ok = ok and app.get("path") == values["path"]
        if "environment" in values:
            ok = ok and app.get("envvars") == json.loads(values["environment"])
        if values.get("clear_envvars"):
            ok = ok and not app.get("envvars")
        if "new_name" in values and name != values["name"]:
            ok = ok and values["name"] not in apps
    return VerificationResult(ok, "application_state", {"exists": app is not None})
