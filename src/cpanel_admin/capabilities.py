"""Account capability discovery constrained by reviewed policy."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast

from .catalog import Catalog
from .errors import CapabilityDiscoveryError, CapabilityError
from .policy import PolicyOperation, PolicyRegistry, SupportStatus
from .profiles import Profile
from .transport import UAPIResponse

_CACHE_TTL = timedelta(seconds=60)


class Availability(StrEnum):
    """Policy-and-server availability for a reviewed operation."""

    AVAILABLE = "available"
    SERVER_UNAVAILABLE = "server_unavailable"
    POLICY_EXCLUDED = "excluded"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OperationAvailability:
    """Availability for one reviewed policy operation."""

    operation: str
    status: Availability
    feature: str | None
    reason: str | None


@dataclass(frozen=True)
class CapabilityReport:
    """Snapshot of reviewed operations for a profile."""

    profile: str
    observed_at: str
    operations: dict[str, OperationAvailability]


class TransportLike(Protocol):
    """Transport boundary used for feature discovery."""

    def call(
        self,
        profile: Profile,
        token: str,
        module: str,
        function: str,
        parameters: dict[str, object],
    ) -> UAPIResponse: ...


@dataclass(frozen=True)
class _FeatureObservation:
    features: frozenset[str]
    observed_at: datetime


class CapabilityService:
    """Inspect and enforce account feature prerequisites without widening policy."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._cache: dict[tuple[str, str, int, str], _FeatureObservation] = {}

    def inspect(self, context: object) -> CapabilityReport:
        """Return availability for reviewed operations in ``context``.

        ``context`` follows the planner convention: it exposes ``profile`` and,
        for this service, also exposes ``policy``, ``transport``, and ``token``.
        ``catalog`` may be supplied instead of ``policy`` when its operations
        already carry attached ``PolicyOperation`` instances.
        """

        profile = _profile(context)
        observed_at = _aware(self._clock())
        operations = _operations(context)
        features, discovery_error = self._features(context, profile, observed_at)
        availability = {
            operation.name: _operation_availability(operation, features, discovery_error)
            for operation in operations
        }
        return CapabilityReport(
            profile=profile.name,
            observed_at=observed_at.isoformat(),
            operations=availability,
        )

    def require(self, context: object, operation: PolicyOperation) -> None:
        """Raise a safe error unless policy and discovered server state allow ``operation``."""

        reviewed = _reviewed_operation(context, operation.name)
        if reviewed.status is not SupportStatus.INCLUDED:
            raise CapabilityError(
                f"operation excluded by policy: {reviewed.name}: {reviewed.reason}"
            )
        if reviewed.feature is None:
            return
        availability = self.inspect(context).operations.get(reviewed.name)
        if availability is None or availability.status is Availability.UNKNOWN:
            raise CapabilityDiscoveryError(
                f"operation capability could not be confirmed: {reviewed.name}"
            )
        if availability.status is Availability.SERVER_UNAVAILABLE:
            raise CapabilityError(
                f"operation feature is not available on this server: "
                f"{reviewed.name}: {reviewed.feature}"
            )
        if availability.status is Availability.POLICY_EXCLUDED:
            raise CapabilityError(
                f"operation excluded by policy: {reviewed.name}: {availability.reason}"
            )

    def _features(
        self, context: object, profile: Profile, observed_at: datetime
    ) -> tuple[frozenset[str] | None, Exception | None]:
        key = (profile.name, profile.host, profile.port, profile.username)
        cached = self._cache.get(key)
        if cached is not None and observed_at - cached.observed_at <= _CACHE_TTL:
            return cached.features, None
        try:
            transport = cast(TransportLike, context.transport)
            token = context.token
            if not isinstance(token, str) or not token:
                raise TypeError("capability context token must be a non-empty string")
            response = transport.call(profile, token, "Features", "list_features", {})
            features = _parse_features(response.data)
        except Exception as exc:
            return None, exc
        self._cache[key] = _FeatureObservation(features, observed_at)
        return features, None


def _operation_availability(
    operation: PolicyOperation, features: frozenset[str] | None, discovery_error: Exception | None
) -> OperationAvailability:
    if operation.status is not SupportStatus.INCLUDED:
        return OperationAvailability(
            operation=operation.name,
            status=Availability.POLICY_EXCLUDED,
            feature=operation.feature,
            reason=operation.reason,
        )
    if operation.feature is None:
        return OperationAvailability(
            operation=operation.name,
            status=Availability.AVAILABLE,
            feature=None,
            reason=None,
        )
    if discovery_error is not None or features is None:
        return OperationAvailability(
            operation=operation.name,
            status=Availability.UNKNOWN,
            feature=operation.feature,
            reason="feature discovery failed",
        )
    if operation.feature not in features:
        return OperationAvailability(
            operation=operation.name,
            status=Availability.SERVER_UNAVAILABLE,
            feature=operation.feature,
            reason=f"required account feature is unavailable: {operation.feature}",
        )
    return OperationAvailability(
        operation=operation.name,
        status=Availability.AVAILABLE,
        feature=operation.feature,
        reason=None,
    )


def _profile(context: object) -> Profile:
    profile = getattr(context, "profile", None)
    if not isinstance(profile, Profile):
        raise CapabilityDiscoveryError("capability context must contain a validated profile")
    return profile


def _operations(context: object) -> tuple[PolicyOperation, ...]:
    policy = getattr(context, "policy", None)
    if isinstance(policy, PolicyRegistry):
        return policy.all()
    catalog = getattr(context, "catalog", None)
    if isinstance(catalog, Catalog):
        operations = tuple(
            operation.policy
            for operation in catalog.operations.values()
            if operation.policy is not None
        )
        if operations:
            return operations
    raise CapabilityDiscoveryError("capability context must contain reviewed policy operations")


def _reviewed_operation(context: object, name: str) -> PolicyOperation:
    for operation in _operations(context):
        if operation.name == name:
            return operation
    raise CapabilityError(f"operation missing from reviewed policy: {name}")


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_features(data: object) -> frozenset[str]:
    if isinstance(data, Mapping):
        if isinstance(data.get("features"), list | tuple):
            return _parse_feature_list(data["features"])
        return frozenset(
            str(name) for name, enabled in data.items() if _enabled(enabled, missing_default=False)
        )
    if isinstance(data, list | tuple):
        return _parse_feature_list(data)
    raise ValueError("feature discovery returned an unsupported payload")


def _parse_feature_list(items: object) -> frozenset[str]:
    if not isinstance(items, list | tuple):
        raise ValueError("feature list must be a sequence")
    features: set[str] = set()
    for item in items:
        if isinstance(item, str):
            if item:
                features.add(item)
            continue
        if not isinstance(item, Mapping):
            raise ValueError("feature list entries must be strings or objects")
        name = item.get("id", item.get("name", item.get("feature")))
        if not isinstance(name, str) or not name:
            raise ValueError("feature list entry is missing a feature name")
        if _enabled(item.get("enabled"), missing_default=True):
            features.add(name)
    return frozenset(features)


def _enabled(value: object, *, missing_default: bool) -> bool:
    if value is None:
        return missing_default
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled"}:
            return False
    raise ValueError("feature enabled value is invalid")
