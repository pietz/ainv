"""Provider-neutral values handled by the ainv core."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class ProviderCapability(StrEnum):
    """Operations a provider explicitly supports."""

    SEARCH = "search"
    RESOLVE = "resolve"
    CREATE = "create"


class ProviderState(StrEnum):
    """The non-secret availability state of a credential provider."""

    READY = "ready"
    LOCKED = "locked"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ProviderStatus:
    """A provider health result suitable for the ``providers`` command."""

    provider: str
    state: ProviderState
    source: str = "built-in"
    capabilities: frozenset[ProviderCapability] = frozenset()


@dataclass(frozen=True, slots=True)
class CredentialMetadata:
    """Canonical non-secret description of one credential.

    These fields intentionally retain provider metadata unchanged.  Terminal
    escaping and any other presentation sanitization belong at the rendering
    boundary, not in the provider's data model.
    """

    reference: str
    provider: str
    name: str | None
    account: str | None
    label: str | None
    kind: str
    modified_at: datetime | None
    description: str | None = None
    created_at: datetime | None = None
    item_type: str | None = None
    keychain: str | None = None

    @property
    def ref(self) -> str:
        """The JSON-facing spelling of :attr:`reference`."""
        return self.reference


@dataclass(frozen=True, slots=True, repr=False)
class Secret:
    """Secret bytes whose textual representations never disclose their value."""

    _bytes: bytes

    def __init__(self, value: bytes | bytearray | memoryview) -> None:
        object.__setattr__(self, "_bytes", bytes(value))

    def reveal(self) -> bytes:
        """Return secret bytes to an explicit delivery operation only."""
        return self._bytes

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"
