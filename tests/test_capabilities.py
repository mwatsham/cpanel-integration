from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from cpanel_admin.capabilities import (
    Availability,
    CapabilityDiscoveryError,
    CapabilityService,
)
from cpanel_admin.catalog import Catalog, CatalogOperation
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


@dataclass(frozen=True)
class CatalogContext:
    profile: Profile
    token: str
    transport: FakeTransport
    catalog: Catalog


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


def catalog_context(transport: FakeTransport, *operations: PolicyOperation) -> CatalogContext:
    catalog_operations = {
        item.identity: CatalogOperation(
            identity=item.identity,
            module=item.identity.split("/", 1)[0],
            function=item.identity.split("/", 1)[1],
            method="GET",
            summary=f"Test operation for {item.name}",
            deprecated=False,
            parameters={},
            policy=item,
        )
        for item in operations
    }
    return CatalogContext(
        profile(),
        "secret-token",
        transport,
        Catalog(1, "test", "0" * 64, catalog_operations, ()),
    )


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


def test_require_allows_no_feature_reviewed_operation_without_discovery() -> None:
    domains = operation(name="domains.list", identity="DomainInfo/list_domains", feature=None)
    transport = FakeTransport(RuntimeError("discovery should not run"))
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))
    subject = context(transport, domains)

    service.require(subject, domains)

    assert transport.calls == []


def test_inspect_marks_no_feature_operation_available_and_normalizes_naive_clock() -> None:
    domains = operation(name="domains.list", identity="DomainInfo/list_domains", feature=None)
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, 12, 30))

    report = service.inspect(context(FakeTransport([]), domains))

    assert report.observed_at == "2026-07-14T12:30:00+00:00"
    assert report.operations[domains.name].status is Availability.AVAILABLE
    assert report.operations[domains.name].feature is None


def test_require_fails_closed_when_discovery_observes_policy_exclusion() -> None:
    included = operation(
        name="email.accounts.list",
        identity="Email/list_pops",
        feature="popaccts",
    )
    excluded = operation(
        name="email.accounts.list",
        identity="Email/list_pops",
        status=SupportStatus.EXCLUDED,
        reason="removed during policy refresh",
    )

    class RefreshingContext:
        profile = globals()["profile"]()
        token = "secret-token"
        transport = FakeTransport([{"id": "popaccts", "enabled": 1}])

        def __init__(self) -> None:
            self.policy_reads = 0

        @property
        def policy(self) -> PolicyRegistry:
            self.policy_reads += 1
            if self.policy_reads == 1:
                return PolicyRegistry((included,), (), ())
            return PolicyRegistry((excluded,), (), ())

    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))

    with pytest.raises(CapabilityError, match="excluded by policy"):
        service.require(RefreshingContext(), included)


@pytest.mark.parametrize("reviewed_operations", ["excluded", "missing"])
def test_require_checks_reviewed_policy_before_caller_operation(
    reviewed_operations: str,
) -> None:
    reviewed_email = operation(
        name="email.accounts.list",
        identity="Email/list_pops",
        feature="popaccts",
    )
    excluded_cron = operation(
        name="cron.jobs.list",
        identity="Cron/listcron",
        status=SupportStatus.EXCLUDED,
        reason="not in reviewed MVP scope",
    )
    caller_supplied_cron = operation(
        name="cron.jobs.list",
        identity="Cron/listcron",
        status=SupportStatus.INCLUDED,
        feature=None,
    )
    policy_operations = (
        (reviewed_email, excluded_cron) if reviewed_operations == "excluded" else (reviewed_email,)
    )
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))
    subject = context(
        FakeTransport([{"id": "popaccts", "enabled": 1}]),
        *policy_operations,
    )

    with pytest.raises(CapabilityError, match="policy"):
        service.require(subject, caller_supplied_cron)


def test_catalog_backed_policy_operations_are_reviewed_and_enforced() -> None:
    email = operation(name="email.accounts.list", identity="Email/list_pops", feature="popaccts")
    cron = operation(
        name="cron.jobs.list",
        identity="Cron/listcron",
        status=SupportStatus.EXCLUDED,
        reason="not in reviewed MVP scope",
    )
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))
    subject = catalog_context(FakeTransport({"features": ["popaccts"]}), email, cron)

    report = service.inspect(subject)

    assert report.operations[email.name].status is Availability.AVAILABLE
    assert report.operations[cron.name].status is Availability.POLICY_EXCLUDED
    service.require(subject, email)
    with pytest.raises(CapabilityError, match="excluded by policy"):
        service.require(subject, cron)


def test_invalid_or_missing_context_paths_fail_safely() -> None:
    email = operation(name="email.accounts.list", identity="Email/list_pops", feature="popaccts")
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))

    with pytest.raises(CapabilityDiscoveryError, match="validated profile"):
        service.inspect(object())

    @dataclass(frozen=True)
    class MissingPolicyContext:
        profile: Profile
        token: str
        transport: FakeTransport

    with pytest.raises(CapabilityDiscoveryError, match="reviewed policy operations"):
        service.inspect(MissingPolicyContext(profile(), "secret-token", FakeTransport([])))

    no_token_subject = Context(
        profile(),
        "",
        FakeTransport([{"id": "popaccts"}]),
        PolicyRegistry((email,), (), ()),
    )
    report = service.inspect(no_token_subject)
    assert report.operations[email.name].status is Availability.UNKNOWN


def test_feature_parser_accepts_supported_payload_variants() -> None:
    email = operation(name="email.accounts.list", identity="Email/list_pops", feature="popaccts")
    ssh = operation(name="ssh.keys.list", identity="SSH/list_keys", feature="ssh")
    ftp = operation(name="ftp.accounts.list", identity="Ftp/list_ftp", feature="ftp")
    passenger = operation(
        name="passenger.apps.list", identity="PassengerApps/list", feature="passengerapps"
    )
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))

    nested_report = service.inspect(
        context(
            FakeTransport(
                {
                    "features": [
                        {"id": "popaccts", "enabled": "yes"},
                        {"name": "ssh", "enabled": None},
                        {"id": "disabled_bool", "enabled": False},
                        {"feature": "passengerapps", "enabled": "disabled"},
                        "ftp",
                        "",
                    ]
                }
            ),
            email,
            ssh,
            ftp,
            passenger,
        )
    )
    mapping_report = service.inspect(
        context(
            FakeTransport(
                {
                    "popaccts": True,
                    "ssh": 1,
                    "ftp": "enabled",
                    "passengerapps": "off",
                }
            ),
            email,
            ssh,
            ftp,
            passenger,
        )
    )

    assert nested_report.operations[email.name].status is Availability.AVAILABLE
    assert nested_report.operations[ssh.name].status is Availability.AVAILABLE
    assert nested_report.operations[ftp.name].status is Availability.AVAILABLE
    assert nested_report.operations[passenger.name].status is Availability.SERVER_UNAVAILABLE
    assert mapping_report.operations[email.name].status is Availability.AVAILABLE
    assert mapping_report.operations[ssh.name].status is Availability.AVAILABLE
    assert mapping_report.operations[ftp.name].status is Availability.AVAILABLE
    assert mapping_report.operations[passenger.name].status is Availability.SERVER_UNAVAILABLE


@pytest.mark.parametrize(
    "payload",
    [
        {"features": [object()]},
        {"features": [{"enabled": True}]},
        {"features": [{"id": "", "enabled": True}]},
        {"features": [{"id": "popaccts", "enabled": object()}]},
        {"popaccts": object()},
        object(),
    ],
)
def test_feature_parser_rejects_invalid_payload_variants(payload: object) -> None:
    email = operation(name="email.accounts.list", identity="Email/list_pops", feature="popaccts")
    service = CapabilityService(clock=lambda: datetime(2026, 7, 14, tzinfo=UTC))

    report = service.inspect(context(FakeTransport(payload), email))

    assert report.operations[email.name].status is Availability.UNKNOWN
    assert report.operations[email.name].reason == "feature discovery failed"


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
