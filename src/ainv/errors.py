"""Safe, typed errors returned by credential providers.

Messages in this module are deliberately static.  Native providers can return
item attributes and other content that must never reach user-facing errors.
"""

from __future__ import annotations


class ProviderError(Exception):
    """Base class for expected provider failures safe to show to a user."""

    message = "credential provider operation failed"

    def __init__(self) -> None:
        super().__init__(self.message)


class InvalidReferenceError(ProviderError, ValueError):
    """A reference is not a canonical reference understood by the provider."""

    message = "credential ID or reference is invalid or unsupported"


class CredentialNotFoundError(ProviderError):
    """The selected credential no longer exists."""

    message = "credential was not found"


class CredentialAlreadyExistsError(ProviderError):
    """Creation would overwrite an existing provider credential."""

    message = "credential already exists; existing values are never overwritten"


class InvalidCredentialMetadataError(ProviderError, ValueError):
    """Creation metadata is missing or unsafe for the selected provider."""

    message = "credential service, account, or label is invalid"


class CredentialAmbiguousError(ProviderError):
    """A supposedly exact native lookup did not identify one item."""

    message = "credential ID or reference did not identify exactly one item"


class ProviderUnavailableError(ProviderError):
    """The provider or its backing store is unavailable."""

    message = "credential provider is unavailable"


class ProviderLockedError(ProviderError):
    """The provider is locked or interaction is not currently possible."""

    message = "credential provider is locked or unavailable"


class ProviderAccessDeniedError(ProviderError):
    """The user denied, cancelled, or cannot approve secret access."""

    message = "credential access was denied or cancelled"


class ProviderOperationError(ProviderError):
    """An unexpected provider failure with no safe native detail to expose."""

    message = "credential provider operation failed"
