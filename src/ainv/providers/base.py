"""Private, deliberately small provider protocol."""

from __future__ import annotations

from typing import Protocol

from ainv.models import CredentialMetadata, ProviderStatus, Secret


class CredentialProvider(Protocol):
    """The internal contract shared by built-in credential providers."""

    name: str

    def status(self) -> ProviderStatus:
        """Return availability without retrieving credential data."""

    def search(self, query: str, *, limit: int = 20) -> list[CredentialMetadata]:
        """Return matching non-secret metadata in deterministic order."""

    def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
        """Resolve exactly one canonical reference for an explicit delivery."""
