from cpanel_admin.errors import (
    AuditError,
    CapabilityError,
    ConfigError,
    PartialFailure,
    VerificationError,
)


def test_error_subclasses_have_stable_exit_codes() -> None:
    assert ConfigError("bad config").exit_code == 3
    assert AuditError("audit unavailable").exit_code == 3
    assert CapabilityError("not supported").exit_code == 7
    assert PartialFailure("partial result").exit_code == 8
    assert VerificationError("verification failed").exit_code == 9
