"""Stable, user-facing errors for the cPanel administration CLI."""


class CPanelAdminError(Exception):
    """Base class for expected failures that are safe to show to users."""

    exit_code = 1


class UsageError(CPanelAdminError):
    """Invalid command usage or input."""

    exit_code = 2


class ConfigError(CPanelAdminError):
    """Invalid or unavailable local configuration."""

    exit_code = 3


class AuditError(CPanelAdminError):
    """A protected local audit record could not be written safely."""

    exit_code = 3


class ConfirmationError(CPanelAdminError):
    """Missing, expired, or mismatched destructive confirmation."""

    exit_code = 4


class TransportError(CPanelAdminError):
    """Network, TLS, HTTP, or response-format failure."""

    exit_code = 5


class UAPIError(CPanelAdminError):
    """cPanel UAPI application-level failure."""

    exit_code = 6


class CapabilityError(CPanelAdminError):
    """Requested functionality is outside the supported UAPI surface."""

    exit_code = 7


class CapabilityDiscoveryError(CapabilityError):
    """Requested functionality could not be confirmed from server capabilities."""


class PartialFailure(CPanelAdminError):
    """A multi-item UAPI operation completed only partially."""

    exit_code = 8


class VerificationError(CPanelAdminError):
    """A completed mutation did not produce the expected state."""

    exit_code = 9
