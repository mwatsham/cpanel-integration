from cpanel_admin.errors import CapabilityError, ConfigError


def test_error_subclasses_have_stable_exit_codes() -> None:
    assert ConfigError("bad config").exit_code == 3
    assert CapabilityError("not supported").exit_code == 7
