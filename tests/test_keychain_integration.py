"""Opt-in native tests using only a temporary synthetic file Keychain."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ainv.errors import CredentialNotFoundError
from ainv.models import Secret
from ainv.providers.keychain import (
    KeychainProvider,
    PyObjCSecurityBackend,
    parse_persistent_reference,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("AINV_KEYCHAIN_INTEGRATION") != "1",
    reason="set AINV_KEYCHAIN_INTEGRATION=1 to run isolated native tests",
)


def test_synthetic_persistent_reference_round_trip(tmp_path: Path) -> None:
    import Security

    keychain_password = b"ainv-test-keychain-password"
    service = "AINV SYNTHETIC@SERVICE"
    account = "ainv-synthetic/account"
    value = b"ainv-synthetic-value"
    keychain_path = os.fsencode(tmp_path / "synthetic.keychain-db")

    status, keychain = Security.SecKeychainCreate(
        keychain_path,
        len(keychain_password),
        keychain_password,
        False,
        None,
        None,
    )
    assert status == 0

    try:

        class IsolatedBackend(PyObjCSecurityBackend):
            def default_keychain(self) -> tuple[int, object | None]:
                return 0, keychain

        provider = KeychainProvider(IsolatedBackend())
        created = provider.create(
            service,
            account=account,
            secret=Secret(value),
            no_input=True,
        )
        matches = provider.search("AINV SYNTHETIC")

        assert len(matches) == 1
        assert created.reference == matches[0].reference
        assert matches[0].name == service
        assert matches[0].identifier == (
            "keychain:AINV%20SYNTHETIC%40SERVICE@ainv-synthetic%2Faccount"
        )
        resolved = provider.resolve(matches[0].reference, no_input=True)
        assert resolved.reveal() == value
        readable_resolved = provider.resolve(matches[0].credential_id, no_input=True)
        assert readable_resolved.reveal() == value
    finally:
        Security.SecKeychainDelete(keychain)


def test_persistent_reference_lifecycle_in_isolated_keychain(tmp_path: Path) -> None:
    """Exercise native persistent-reference behavior without a default Keychain."""
    import Security

    keychain_password = b"ainv-lifecycle-keychain-password"
    service = "AINV_LIFECYCLE_SERVICE"
    account = "ainv-lifecycle-account"
    label = "AINV lifecycle label"
    updated_service = "AINV_LIFECYCLE_SERVICE_UPDATED"
    updated_account = "ainv-lifecycle-account-updated"
    updated_label = "AINV lifecycle label updated"
    initial_value = b"ainv-lifecycle-initial-value"
    updated_value = b"ainv-lifecycle-updated-value"
    recreated_value = b"ainv-lifecycle-recreated-value"
    keychain_path = os.fsencode(tmp_path / "persistent-reference-lifecycle.keychain-db")

    status, keychain = Security.SecKeychainCreate(
        keychain_path,
        len(keychain_password),
        keychain_password,
        False,
        None,
        None,
    )
    assert status == 0

    try:

        class IsolatedBackend(PyObjCSecurityBackend):
            def default_keychain(self) -> tuple[int, object | None]:
                return 0, keychain

        provider = KeychainProvider(IsolatedBackend())
        created = provider.create(
            service,
            account=account,
            label=label,
            secret=Secret(initial_value),
            no_input=True,
        )
        persistent_ref = parse_persistent_reference(created.reference)
        item_query = {
            Security.kSecClass: Security.kSecClassGenericPassword,
            Security.kSecAttrSynchronizable: False,
            Security.kSecMatchSearchList: [keychain],
            Security.kSecValuePersistentRef: persistent_ref,
            Security.kSecUseAuthenticationUI: Security.kSecUseAuthenticationUIFail,
        }

        assert (
            Security.SecItemUpdate(item_query, {Security.kSecValueData: updated_value})
            == 0
        )
        value_updated = provider.search(service)
        assert [metadata.reference for metadata in value_updated] == [created.reference]
        assert (
            provider.resolve(created.reference, no_input=True).reveal() == updated_value
        )

        assert (
            Security.SecItemUpdate(item_query, {Security.kSecAttrLabel: updated_label})
            == 0
        )
        label_updated = provider.search(updated_label)
        assert [metadata.reference for metadata in label_updated] == [created.reference]
        assert label_updated[0].label == updated_label
        assert (
            provider.resolve(created.reference, no_input=True).reveal() == updated_value
        )

        assert (
            Security.SecItemUpdate(
                item_query, {Security.kSecAttrService: updated_service}
            )
            == 0
        )
        service_updated = provider.search(updated_service)
        assert len(service_updated) == 1
        service_updated_reference = service_updated[0].reference
        assert service_updated_reference != created.reference
        assert service_updated[0].name == updated_service
        assert service_updated[0].account == account
        with pytest.raises(CredentialNotFoundError):
            provider.resolve(created.reference, no_input=True)
        assert (
            provider.resolve(service_updated_reference, no_input=True).reveal()
            == updated_value
        )

        account_item_query = {
            **item_query,
            Security.kSecValuePersistentRef: parse_persistent_reference(
                service_updated_reference
            ),
        }
        assert (
            Security.SecItemUpdate(
                account_item_query, {Security.kSecAttrAccount: updated_account}
            )
            == 0
        )
        identity_updated = provider.search(updated_service)
        assert len(identity_updated) == 1
        updated_reference = identity_updated[0].reference
        assert updated_reference != service_updated_reference
        assert identity_updated[0].name == updated_service
        assert identity_updated[0].account == updated_account
        with pytest.raises(CredentialNotFoundError):
            provider.resolve(service_updated_reference, no_input=True)
        assert (
            provider.resolve(updated_reference, no_input=True).reveal() == updated_value
        )

        assert (
            Security.SecItemDelete(
                {
                    Security.kSecClass: Security.kSecClassGenericPassword,
                    Security.kSecAttrSynchronizable: False,
                    Security.kSecMatchSearchList: [keychain],
                    Security.kSecMatchItemList: [
                        parse_persistent_reference(updated_reference)
                    ],
                    Security.kSecUseAuthenticationUI: Security.kSecUseAuthenticationUIFail,
                }
            )
            == 0
        )
        with pytest.raises(CredentialNotFoundError):
            provider.resolve(updated_reference, no_input=True)

        recreated = provider.create(
            updated_service,
            account=updated_account,
            label=updated_label,
            secret=Secret(recreated_value),
            no_input=True,
        )
        assert recreated.reference == updated_reference
        with pytest.raises(CredentialNotFoundError):
            provider.resolve(created.reference, no_input=True)
        assert (
            provider.resolve(updated_reference, no_input=True).reveal()
            == recreated_value
        )
    finally:
        Security.SecKeychainDelete(keychain)
