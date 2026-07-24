from __future__ import annotations

import pytest

from ainv.errors import InvalidReferenceError, ProviderUnavailableError
from ainv.providers.registry import ProviderRegistry


class FakeProvider:
    name = "fake"


def test_registry_constructs_and_routes_registered_provider() -> None:
    registry = ProviderRegistry()
    registry.register("fake", FakeProvider, reference_prefixes=("fake://v1/",))  # type: ignore[arg-type]

    assert isinstance(registry.get("fake"), FakeProvider)
    assert registry.provider_name_for_reference("fake://v1/item") == "fake"
    assert registry.names() == ("fake",)


def test_registry_rejects_unknown_provider_and_reference() -> None:
    registry = ProviderRegistry()

    with pytest.raises(ProviderUnavailableError):
        registry.get("missing")
    with pytest.raises(InvalidReferenceError):
        registry.provider_name_for_reference("missing://item")


def test_registry_rejects_duplicate_names_and_prefixes() -> None:
    registry = ProviderRegistry()
    registry.register("one", FakeProvider, reference_prefixes=("one://",))  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        registry.register("one", FakeProvider, reference_prefixes=("other://",))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        registry.register("two", FakeProvider, reference_prefixes=("one://",))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        registry.register(
            "nested",
            FakeProvider,
            reference_prefixes=("one://v2/",),  # type: ignore[arg-type]
        )
