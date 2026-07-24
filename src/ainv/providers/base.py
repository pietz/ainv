"""Private, deliberately small provider protocol."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ainv.models import CredentialMetadata, ProviderCapability, ProviderStatus, Secret


class CredentialProvider(Protocol):
    """The internal contract shared by built-in credential providers."""

    name: str
    capabilities: frozenset[ProviderCapability]

    def status(self) -> ProviderStatus:
        """Return availability without retrieving credential data."""

    def search(self, query: str, *, limit: int = 20) -> list[CredentialMetadata]:
        """Return matching non-secret metadata in deterministic order."""

    def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
        """Resolve exactly one canonical reference for an explicit delivery."""


@runtime_checkable
class CredentialCreator(Protocol):
    """Optional capability for providers that can create credentials."""

    def create(
        self,
        service: str,
        *,
        account: str,
        secret: Secret,
        label: str | None = None,
        no_input: bool = False,
    ) -> CredentialMetadata:
        """Create one credential without replacing an existing value."""
