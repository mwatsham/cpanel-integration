"""Short-lived confirmations bound to exact destructive operations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import TypeAlias

from .errors import ConfigError, ConfirmationError

JsonScalar: TypeAlias = str | int | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
CONFIRMATION_RE = re.compile(r"^[0-9a-f]{12}$")


@dataclass(frozen=True)
class ConfirmationPlan:
    profile: str
    operation: str
    parameters: dict[str, JsonValue]
    impact: str
    recovery: str
    expires_at: str
    confirmation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _normalize(value: object) -> JsonValue:
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, list | tuple):
        return [_normalize(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, JsonValue] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise ConfirmationError("Confirmation parameters must be JSON-compatible")
            normalized[key] = _normalize(value[key])
        return normalized
    raise ConfirmationError("Confirmation parameters must be JSON-compatible")


class ConfirmationService:
    """Create and verify five-minute operation-bound HMAC digests."""

    def __init__(
        self,
        fernet_key: bytes,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        try:
            raw_key = base64.urlsafe_b64decode(fernet_key)
        except (ValueError, TypeError) as exc:
            raise ConfigError("Confirmation service requires a valid Fernet key") from exc
        if len(raw_key) != 32:
            raise ConfigError("Confirmation service requires a valid Fernet key")
        self._key = hashlib.sha256(b"cpanel-admin-confirmation-v1\0" + raw_key).digest()
        self.clock = clock or (lambda: datetime.now(UTC))

    def _payload(
        self,
        profile: str,
        operation: str,
        parameters: Mapping[str, object],
        expires_at: str,
    ) -> bytes:
        normalized = _normalize(parameters)
        value = {
            "version": 1,
            "profile": profile,
            "operation": operation,
            "parameters": normalized,
            "expires_at": expires_at,
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()[:12]

    def _v2_payload(
        self,
        *,
        profile: str,
        account: str,
        identity: str,
        operation: str,
        parameters: Mapping[str, object],
        preflight: object,
        policy_digest: str,
        expires_at: str,
        risk: str = "",
        elevated_impact: bool = False,
        policy_version: str = "1",
    ) -> bytes:
        strings = {
            "profile": profile,
            "account": account,
            "identity": identity,
            "operation": operation,
            "policy_digest": policy_digest,
            "expires_at": expires_at,
            "risk": risk,
            "policy_version": policy_version,
        }
        if not all(isinstance(value, str) for value in strings.values()):
            raise ConfirmationError("Confirmation payload has invalid identity fields")
        required_fields = (
            "profile",
            "account",
            "identity",
            "operation",
            "policy_digest",
            "expires_at",
        )
        if not all(
            strings[name] for name in (*required_fields, "policy_version")
        ) or not isinstance(elevated_impact, bool):
            raise ConfirmationError("Confirmation payload has invalid identity fields")
        normalized = _normalize(parameters)
        if not isinstance(normalized, dict):
            raise ConfirmationError("Confirmation parameters must be a mapping")
        return json.dumps(
            {
                "version": 2,
                **strings,
                "parameters": normalized,
                "preflight": _normalize(preflight),
                "elevated_impact": elevated_impact,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def plan_v2(
        self,
        *,
        profile: str,
        account: str,
        identity: str,
        operation: str,
        parameters: Mapping[str, object],
        preflight: object,
        policy_digest: str,
        risk: str = "",
        elevated_impact: bool = False,
        policy_version: str = "1",
    ) -> ConfirmationPlan:
        now = self.clock()
        if now.tzinfo is None:
            raise ConfigError("Confirmation clock must return a timezone-aware time")
        expires_at = (now.astimezone(UTC) + timedelta(minutes=5)).isoformat()
        normalized = _normalize(parameters)
        if not isinstance(normalized, dict):
            raise ConfirmationError("Confirmation parameters must be a mapping")
        confirmation = self._sign(
            self._v2_payload(
                profile=profile,
                account=account,
                identity=identity,
                operation=operation,
                parameters=normalized,
                preflight=preflight,
                policy_digest=policy_digest,
                expires_at=expires_at,
                risk=risk,
                elevated_impact=elevated_impact,
                policy_version=policy_version,
            )
        )
        return ConfirmationPlan(
            profile=profile,
            operation=operation,
            parameters=normalized,
            impact="",
            recovery="",
            expires_at=expires_at,
            confirmation=confirmation,
        )

    def verify_v2(
        self,
        confirmation: str | None,
        *,
        profile: str,
        account: str,
        identity: str,
        operation: str,
        parameters: Mapping[str, object],
        preflight: object,
        policy_digest: str,
        expires_at: str | None,
        risk: str = "",
        elevated_impact: bool = False,
        policy_version: str = "1",
    ) -> None:
        if not confirmation or not expires_at:
            raise ConfirmationError("Confirmation digest and expiry are required")
        if not CONFIRMATION_RE.fullmatch(confirmation):
            raise ConfirmationError("Confirmation digest has an invalid format")
        try:
            expiry = datetime.fromisoformat(expires_at)
        except (TypeError, ValueError) as exc:
            raise ConfirmationError("Confirmation expiry timestamp is invalid") from exc
        if expiry.tzinfo is None or expiry.isoformat() != expires_at:
            raise ConfirmationError("Confirmation expiry timestamp is invalid")
        now = self.clock()
        if now.tzinfo is None:
            raise ConfigError("Confirmation clock must return a timezone-aware time")
        if now.astimezone(UTC) > expiry.astimezone(UTC):
            raise ConfirmationError("Confirmation digest has expired")
        expected = self._sign(
            self._v2_payload(
                profile=profile,
                account=account,
                identity=identity,
                operation=operation,
                parameters=parameters,
                preflight=preflight,
                policy_digest=policy_digest,
                expires_at=expires_at,
                risk=risk,
                elevated_impact=elevated_impact,
                policy_version=policy_version,
            )
        )
        if not hmac.compare_digest(expected, confirmation):
            raise ConfirmationError("Confirmation digest does not match this operation")

    def plan(
        self,
        profile: str,
        operation: str,
        parameters: Mapping[str, object],
        impact: str,
        recovery: str,
    ) -> ConfirmationPlan:
        now = self.clock()
        if now.tzinfo is None:
            raise ConfigError("Confirmation clock must return a timezone-aware time")
        expires_at = (now.astimezone(UTC) + timedelta(minutes=5)).isoformat()
        normalized = _normalize(parameters)
        if not isinstance(normalized, dict):
            raise ConfirmationError("Confirmation parameters must be a mapping")
        confirmation = self._sign(self._payload(profile, operation, normalized, expires_at))
        return ConfirmationPlan(
            profile=profile,
            operation=operation,
            parameters=normalized,
            impact=impact,
            recovery=recovery,
            expires_at=expires_at,
            confirmation=confirmation,
        )

    def verify(
        self,
        confirmation: str | None,
        profile: str,
        operation: str,
        parameters: Mapping[str, object],
        expires_at: str | None,
    ) -> None:
        if not confirmation or not expires_at:
            raise ConfirmationError("Confirmation digest and expiry are required")
        if not CONFIRMATION_RE.fullmatch(confirmation):
            raise ConfirmationError("Confirmation digest has an invalid format")
        try:
            expiry = datetime.fromisoformat(expires_at)
        except (TypeError, ValueError) as exc:
            raise ConfirmationError("Confirmation expiry timestamp is invalid") from exc
        if expiry.tzinfo is None:
            raise ConfirmationError("Confirmation expiry timestamp must include a timezone")
        now = self.clock()
        if now.tzinfo is None:
            raise ConfigError("Confirmation clock must return a timezone-aware time")
        if now.astimezone(UTC) > expiry.astimezone(UTC):
            raise ConfirmationError("Confirmation digest has expired")
        expected = self._sign(self._payload(profile, operation, parameters, expires_at))
        if not hmac.compare_digest(expected, confirmation):
            raise ConfirmationError("Confirmation digest does not match this operation")
