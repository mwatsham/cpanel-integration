from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from cpanel_admin.capabilities import (
    Availability,
    CapabilityDiscoveryError,
    CapabilityService,
)
from cpanel_admin.errors import CapabilityError
from cpanel_admin.policy import PolicyOperation, PolicyRegistry, Risk, SupportStatus
from cpanel_admin.profiles import Profile
from cpanel_admin.transport import UAPIResponse


@dataclass(frozen=True)
class Context:
    profile: Profile
    token: str
    transport: FakeTransport
    policy: PolicyRegistry


class FakeTransport:
    def __init__(self, data: object | Exception) -> None:
        self.data = data
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def call(
        self,
        profile: Profile,
        token: str,
        module: str,
        function: str,
        parameters: dict[str, object],
    ) -> UAPIResponse:
        del profile, token
        self.calls.append((module, function, parameters))
        if isinstance(self.data, Exception):
            raise self.data
        return UAPIResponse(self.data, [], [])


def operation(
    *,
    name: str,
    identity: str,
    status: SupportStatus = SupportStatus.INCLUDED,
    feature: str | None = None,
    reason: str = "covered by test policy",
) -> PolicyOperation:
    return PolicyOperation(
        name=name,
        identity=identity,
        command=tuple(name.split(".")),
        capability=name.split(".")[0],
        status=status,
        reason=reason,
        risk=Risk.READ if status is SupportStatus.INCLUDED else None,
        elevated_impact=False,
        parameters={},
        impact="Read account state" if status is SupportStatus.INCLUDED else "",
        recovery="No recovery needed" if status is SupportStatus.INCLUDED else "",
        preflight=None,
        verification=None,
        feature=feature if status is SupportStatus.INCLUDED else None,
        audit_fields=(),
    )


def profile() -> Profile:
    return Profile("production", "cpanel.example.test", 2083, "acct", "ciphertext")


def context(transport: FakeTransport, *operations: PolicyOperation) -> Context:
    return Context(profile(), "secret-token", transport, PolicyRegistry(tuple(operations), (), ()))


def test_capability_report_distinguishes_policy_and_server_availability() -> None:
    email = operation(name="email.accounts.list", identity="Email/list_pops", feature="popaccts")
    cron = operation(
        name="cron.jobs.list",
        identity="Cron/listcron",
        status=SupportStatus.EXCLUDED,
        reason="not in reviewed MVP scope",
    )
    passenger = operation(
        name="passenger.apps.list", identity="PassengerApps/list", feature="passengerapps"
    )
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))

    report = service.inspect(
        context(
            FakeTransport(
                [
                    {"id": "popaccts", "enabled": 1},
                    {"id": "passengerapps", "enabled": 0},
                ]
            ),
            email,
            cron,
            passenger,
        )
    )

    assert report.profile == "production"
    assert report.observed_at == "2026-07-14T00:00:00+00:00"
    assert report.operations["email.accounts.list"].status is Availability.AVAILABLE
    assert report.operations["cron.jobs.list"].status is Availability.POLICY_EXCLUDED
    assert report.operations["cron.jobs.list"].reason == "not in reviewed MVP scope"
    assert report.operations["passenger.apps.list"].status is Availability.SERVER_UNAVAILABLE


def test_discovery_failure_is_unknown_not_available() -> None:
    email = operation(name="email.accounts.list", identity="Email/list_pops", feature="popaccts")
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))

    report = service.inspect(context(FakeTransport(RuntimeError("boom")), email))

    assert report.operations["email.accounts.list"].status is Availability.UNKNOWN
    assert report.operations["email.accounts.list"].reason == "feature discovery failed"


def test_require_fails_closed_for_policy_exclusion_server_absence_and_unknown_state() -> None:
    email = operation(name="email.accounts.list", identity="Email/list_pops", feature="popaccts")
    cron = operation(
        name="cron.jobs.list",
        identity="Cron/listcron",
        status=SupportStatus.EXCLUDED,
        reason="not in reviewed MVP scope",
    )
    unavailable = replace(email, name="passenger.apps.list", feature="passengerapps")
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))

    subject = context(FakeTransport([{"id": "popaccts", "enabled": 1}]), email, cron, unavailable)

    service.require(subject, email)
    with pytest.raises(CapabilityError, match="excluded by policy"):
        service.require(subject, cron)
    with pytest.raises(CapabilityError, match="not available on this server"):
        service.require(subject, unavailable)
    failing_service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))
    with pytest.raises(CapabilityDiscoveryError, match="could not be confirmed"):
        failing_service.require(context(FakeTransport(RuntimeError("boom")), email), email)


def test_only_successful_feature_lists_are_cached_for_sixty_seconds() -> None:
    email = operation(name="email.accounts.list", identity="Email/list_pops", feature="popaccts")
    now = datetime(2026, 7, 14, tzinfo=UTC)
    current_time = now
    service = CapabilityService(clock=lambda: current_time)
    transport = FakeTransport([{"id": "popaccts", "enabled": 1}])
    subject = context(transport, email)

    assert service.inspect(subject).operations[email.name].status is Availability.AVAILABLE
    transport.data = [{"id": "popaccts", "enabled": 0}]
    assert service.inspect(subject).operations[email.name].status is Availability.AVAILABLE
    assert len(transport.calls) == 1
    current_time = now + timedelta(seconds=61)
    assert service.inspect(subject).operations[email.name].status is Availability.SERVER_UNAVAILABLE
    assert len(transport.calls) == 2

    service = CapabilityService(clock=lambda: now + timedelta(seconds=61))
    failing = FakeTransport(RuntimeError("boom"))
    failing_subject = context(failing, email)
    assert service.inspect(failing_subject).operations[email.name].status is Availability.UNKNOWN
    failing.data = [{"id": "popaccts", "enabled": 1}]
    assert service.inspect(failing_subject).operations[email.name].status is Availability.AVAILABLE
    assert len(failing.calls) == 2
