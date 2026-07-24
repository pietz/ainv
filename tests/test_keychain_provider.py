from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

import pytest

from ainv.errors import (
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    InvalidCredentialMetadataError,
    InvalidReferenceError,
    ProviderAccessDeniedError,
    ProviderLockedError,
    ProviderUnavailableError,
)
from ainv.models import ProviderCapability, ProviderState, Secret
from ainv.providers.keychain import (
    KeychainConstants,
    KeychainProvider,
    format_persistent_reference,
    parse_persistent_reference,
)


class FakeBackend:
    """Spy backend: it has no native bindings and never accesses Keychain."""

    constants = KeychainConstants(
        item_class="class",
        generic_password="generic-password",
        synchronizable="synchronizable",
        match_search_list="search-list",
        return_attributes="return-attributes",
        return_persistent_ref="return-persistent-ref",
        return_data="return-data",
        value_data="value-data",
        use_keychain="use-keychain",
        match_limit="match-limit",
        match_limit_all="all",
        match_limit_one="one",
        use_authentication_ui="authentication-ui",
        authentication_ui_fail="fail",
        authentication_ui_allow="allow",
        value_persistent_ref="persistent-ref",
        attr_service="service",
        attr_account="account",
        attr_label="label",
        attr_description="description",
        attr_creation_date="created",
        attr_modification_date="modified",
        attr_type="type",
    )

    def __init__(
        self,
        responses: list[tuple[int, object | None]],
        *,
        default_status: int = 0,
        default_result: object | None = "fake-default-keychain",
    ) -> None:
        self.responses = responses
        self.default_status = default_status
        self.default_result = default_result
        self.default_calls = 0
        self.queries: list[Mapping[object, object]] = []
        self.added_items: list[Mapping[object, object]] = []

    def default_keychain(self) -> tuple[int, object | None]:
        self.default_calls += 1
        return self.default_status, self.default_result

    def copy_matching(
        self, query: Mapping[object, object]
    ) -> tuple[int, object | None]:
        self.queries.append(dict(query))
        return self.responses.pop(0)

    def add_item(
        self, attributes: Mapping[object, object]
    ) -> tuple[int, object | None]:
        self.added_items.append(dict(attributes))
        return self.responses.pop(0)


def test_search_uses_attribute_only_match_all_query_and_sorts_results() -> None:
    backend = FakeBackend(
        [
            (
                0,
                [
                    {
                        "persistent-ref": b"b",
                        "service": "Zulu",
                        "account": "z-account",
                        "label": "z-label",
                    },
                    {
                        "persistent-ref": b"a",
                        "service": "alpha",
                        "account": "a-account",
                        "label": "\x1b[31mkeep raw metadata",
                        "modified": datetime(2025, 1, 1, tzinfo=UTC),
                    },
                ],
            )
        ]
    )

    results = KeychainProvider(backend).search("a", limit=20)

    assert [result.name for result in results] == ["alpha", "Zulu"]
    assert results[0].label == "\x1b[31mkeep raw metadata"
    assert results[0].keychain == "default"
    assert results[0].modified_at == datetime(2025, 1, 1, tzinfo=UTC)
    query = backend.queries[0]
    assert query == {
        "class": "generic-password",
        "synchronizable": False,
        "search-list": ["fake-default-keychain"],
        "return-attributes": True,
        "return-persistent-ref": True,
        "match-limit": "all",
        "authentication-ui": "fail",
    }
    assert "return-data" not in query


def test_search_requires_query_and_strict_limit_before_native_calls() -> None:
    backend = FakeBackend([])
    provider = KeychainProvider(backend)

    for query in ("", " \t"):
        with pytest.raises(ValueError):
            provider.search(query)
    for limit in (0, 101, True):
        with pytest.raises(ValueError):
            provider.search("service", limit=limit)  # type: ignore[arg-type]

    assert backend.default_calls == 0
    assert backend.queries == []


def test_search_not_found_is_empty_result() -> None:
    backend = FakeBackend([(-25300, None)])

    assert KeychainProvider(backend).search("service") == []


def test_create_targets_default_keychain_and_returns_reference() -> None:
    backend = FakeBackend([(0, b"new-persistent-reference")])
    provider = KeychainProvider(backend)

    metadata = provider.create(
        "OPENAI_API_KEY",
        account="personal",
        label=None,
        secret=Secret(b"synthetic-create-canary"),
        no_input=True,
    )

    assert metadata.name == "OPENAI_API_KEY"
    assert metadata.account == "personal"
    assert metadata.label == "OPENAI_API_KEY"
    assert parse_persistent_reference(metadata.reference) == b"new-persistent-reference"
    attributes = backend.added_items[0]
    assert attributes["class"] == "generic-password"
    assert attributes["synchronizable"] is False
    assert attributes["use-keychain"] == "fake-default-keychain"
    assert attributes["service"] == "OPENAI_API_KEY"
    assert attributes["account"] == "personal"
    assert attributes["label"] == "OPENAI_API_KEY"
    assert attributes["value-data"] == b"synthetic-create-canary"
    assert attributes["return-persistent-ref"] is True
    assert attributes["authentication-ui"] == "fail"


def test_create_refuses_duplicates_and_invalid_metadata_without_leaking() -> None:
    backend = FakeBackend([(-25299, None)])
    provider = KeychainProvider(backend)
    canary = b"synthetic-create-canary"

    with pytest.raises(CredentialAlreadyExistsError) as raised:
        provider.create("SERVICE", account="personal", secret=Secret(canary))
    assert canary.decode() not in str(raised.value)

    for invalid in ("", " ", "bad\nmetadata", "bad\x00metadata"):
        with pytest.raises(InvalidCredentialMetadataError):
            provider.create(invalid, account="personal", secret=Secret(canary))


def test_capabilities_are_explicit() -> None:
    assert KeychainProvider.capabilities == frozenset(
        {
            ProviderCapability.SEARCH,
            ProviderCapability.RESOLVE,
            ProviderCapability.CREATE,
        }
    )


def test_resolution_uses_exact_persistent_reference_and_no_input_fails_ui() -> None:
    persistent_ref = b"opaque-item-identity"
    reference = format_persistent_reference(persistent_ref)
    backend = FakeBackend([(0, b"resolution-canary")])

    secret = KeychainProvider(backend).resolve(reference, no_input=True)

    assert secret.reveal() == b"resolution-canary"
    query = backend.queries[0]
    assert query == {
        "class": "generic-password",
        "synchronizable": False,
        "search-list": ["fake-default-keychain"],
        "persistent-ref": persistent_ref,
        "return-data": True,
        "match-limit": "one",
        "authentication-ui": "fail",
    }
    assert "service" not in query
    assert "account" not in query
    assert "resolution-canary" not in repr(secret)


def test_resolution_allows_native_authentication_only_when_input_is_allowed() -> None:
    backend = FakeBackend([(0, b"value")])

    KeychainProvider(backend).resolve(format_persistent_reference(b"item"))

    assert backend.queries[0]["authentication-ui"] == "allow"


@pytest.mark.parametrize(
    "reference",
    [
        "keychain://v1/item/",
        "keychain://v1/item/a=",
        "keychain://v1/item/abc/def",
        "keychain://v1/item/YQ==",
        "keychain://v1/item/YQ?x=1",
        "keychain://v1/ITEM/YQ",
        "KEYCHAIN://v1/item/YQ",
    ],
)
def test_only_exact_canonical_references_are_accepted(reference: str) -> None:
    with pytest.raises(InvalidReferenceError):
        parse_persistent_reference(reference)


def test_reference_round_trip_is_unpadded_base64url() -> None:
    reference = format_persistent_reference(b"\xfb\xff")

    assert reference == "keychain://v1/item/-_8"
    assert parse_persistent_reference(reference) == b"\xfb\xff"


def test_pyobjc_nsdata_results_are_accepted_without_native_queries() -> None:
    from Foundation import NSData

    persistent_ref = NSData.dataWithBytes_length_(b"opaque", 6)
    secret_value = NSData.dataWithBytes_length_(b"synthetic", 9)
    backend = FakeBackend(
        [
            (
                0,
                [{"persistent-ref": persistent_ref, "service": "Synthetic"}],
            ),
            (0, secret_value),
        ]
    )
    provider = KeychainProvider(backend)

    metadata = provider.search("synthetic")
    secret = provider.resolve(metadata[0].reference)

    assert secret.reveal() == b"synthetic"


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (-25300, CredentialNotFoundError),
        (-25293, ProviderAccessDeniedError),
        (-128, ProviderAccessDeniedError),
        (-25308, ProviderLockedError),
        (-25291, ProviderUnavailableError),
    ],
)
def test_osstatus_errors_are_typed_and_static(
    status: int, error: type[Exception]
) -> None:
    backend = FakeBackend([(status, None)])

    with pytest.raises(error) as raised:
        KeychainProvider(backend).resolve(format_persistent_reference(b"item"))

    assert "item" not in str(raised.value)


def test_status_only_opens_default_keychain() -> None:
    backend = FakeBackend([], default_status=-25308)

    status = KeychainProvider(backend).status()

    assert status.state is ProviderState.LOCKED
    assert backend.default_calls == 1
    assert backend.queries == []
