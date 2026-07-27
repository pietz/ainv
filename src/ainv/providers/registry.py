"""Internal provider registry and reference routing."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from ainv.errors import InvalidReferenceError, ProviderUnavailableError
from ainv.providers.base import CredentialProvider

ProviderFactory = Callable[[], CredentialProvider]


class ProviderRegistry:
    """Register provider factories and their non-overlapping reference prefixes."""

    def __init__(self) -> None:
        self._factories: dict[str, ProviderFactory] = {}
        self._prefixes: dict[str, str] = {}

    def register(
        self,
        name: str,
        factory: ProviderFactory,
        *,
        reference_prefixes: Iterable[str],
    ) -> None:
        """Register one trusted provider in the internal registry."""
        if not name or name in self._factories:
            raise ValueError("provider name is empty or already registered")
        prefixes = tuple(reference_prefixes)
        if not prefixes or any(not prefix for prefix in prefixes):
            raise ValueError("provider must declare a reference prefix")
        if any(
            left != right and (left.startswith(right) or right.startswith(left))
            for index, left in enumerate(prefixes)
            for right in prefixes[index + 1 :]
        ) or any(
            prefix.startswith(existing) or existing.startswith(prefix)
            for prefix in prefixes
            for existing in self._prefixes
        ):
            raise ValueError("provider reference prefix overlaps another prefix")
        self._factories[name] = factory
        for prefix in prefixes:
            self._prefixes[prefix] = name

    def get(self, name: str) -> CredentialProvider:
        """Construct one registered provider without retaining secret state."""
        try:
            factory = self._factories[name]
        except KeyError:
            raise ProviderUnavailableError() from None
        return factory()

    def provider_name_for_reference(self, reference: str) -> str:
        """Route a credential identity by its registered canonical prefix."""
        matches = [
            name
            for prefix, name in self._prefixes.items()
            if reference.startswith(prefix)
        ]
        if len(matches) != 1:
            raise InvalidReferenceError()
        return matches[0]

    def names(self) -> tuple[str, ...]:
        """Return registered provider names in deterministic order."""
        return tuple(sorted(self._factories))
