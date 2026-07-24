"""macOS Keychain provider for legacy generic-password items.

The native boundary is intentionally narrow.  Tests inject ``KeychainBackend``
implementations and never need to load Security.framework or access a user's
Keychain.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from unicodedata import normalize

from ainv.errors import (
    CredentialAmbiguousError,
    CredentialNotFoundError,
    InvalidReferenceError,
    ProviderAccessDeniedError,
    ProviderError,
    ProviderLockedError,
    ProviderOperationError,
    ProviderUnavailableError,
)
from ainv.models import CredentialMetadata, ProviderState, ProviderStatus, Secret

_REFERENCE_PREFIX = "keychain://v1/item/"

# Values are stable OSStatus constants from Security/SecBase.h.  Keeping them
# here avoids exposing native error text, which can contain provider details.
_ERR_SEC_SUCCESS = 0
_ERR_SEC_USER_CANCELED = -128
_ERR_SEC_PARAM = -50
_ERR_SEC_AUTH_FAILED = -25293
_ERR_SEC_NOT_AVAILABLE = -25291
_ERR_SEC_NO_SUCH_KEYCHAIN = -25294
_ERR_SEC_INVALID_KEYCHAIN = -25295
_ERR_SEC_ITEM_NOT_FOUND = -25300
_ERR_SEC_INTERACTION_NOT_ALLOWED = -25308


@dataclass(frozen=True, slots=True)
class KeychainConstants:
    """Security.framework query constants required by the narrow backend."""

    item_class: object
    generic_password: object
    synchronizable: object
    match_search_list: object
    return_attributes: object
    return_persistent_ref: object
    return_data: object
    match_limit: object
    match_limit_all: object
    match_limit_one: object
    use_authentication_ui: object
    authentication_ui_fail: object
    authentication_ui_allow: object
    value_persistent_ref: object
    attr_service: object
    attr_account: object
    attr_label: object
    attr_description: object
    attr_creation_date: object
    attr_modification_date: object
    attr_type: object


class KeychainBackend(Protocol):
    """Minimal native boundary.  It neither exposes shells nor item helpers."""

    constants: KeychainConstants

    def default_keychain(self) -> tuple[int, object | None]:
        """Return the user's default legacy ``SecKeychainRef``."""

    def copy_matching(
        self, query: Mapping[object, object]
    ) -> tuple[int, object | None]:
        """Run one Security.framework item query."""


class PyObjCSecurityBackend:
    """Production backend implemented directly with PyObjC Security bindings."""

    def __init__(self) -> None:
        try:
            import Security  # type: ignore[import-not-found]
        except ImportError:
            raise ProviderUnavailableError() from None

        self._security = Security
        self.constants = KeychainConstants(
            item_class=Security.kSecClass,
            generic_password=Security.kSecClassGenericPassword,
            synchronizable=Security.kSecAttrSynchronizable,
            match_search_list=Security.kSecMatchSearchList,
            return_attributes=Security.kSecReturnAttributes,
            return_persistent_ref=Security.kSecReturnPersistentRef,
            return_data=Security.kSecReturnData,
            match_limit=Security.kSecMatchLimit,
            match_limit_all=Security.kSecMatchLimitAll,
            match_limit_one=Security.kSecMatchLimitOne,
            use_authentication_ui=Security.kSecUseAuthenticationUI,
            authentication_ui_fail=Security.kSecUseAuthenticationUIFail,
            authentication_ui_allow=Security.kSecUseAuthenticationUIAllow,
            value_persistent_ref=Security.kSecValuePersistentRef,
            attr_service=Security.kSecAttrService,
            attr_account=Security.kSecAttrAccount,
            attr_label=Security.kSecAttrLabel,
            attr_description=Security.kSecAttrDescription,
            attr_creation_date=Security.kSecAttrCreationDate,
            attr_modification_date=Security.kSecAttrModificationDate,
            attr_type=Security.kSecAttrType,
        )

    def default_keychain(self) -> tuple[int, object | None]:
        # PyObjC exposes this out-parameter call as (status, keychain).
        try:
            result = self._security.SecKeychainCopyDefault(None)
        except (AttributeError, TypeError):
            return _ERR_SEC_NOT_AVAILABLE, None
        return _native_result(result)

    def copy_matching(
        self, query: Mapping[object, object]
    ) -> tuple[int, object | None]:
        # Passing None for the out parameter lets PyObjC return (status, item).
        try:
            result = self._security.SecItemCopyMatching(dict(query), None)
        except (AttributeError, TypeError):
            return _ERR_SEC_NOT_AVAILABLE, None
        return _native_result(result)


def _native_result(result: object) -> tuple[int, object | None]:
    """Normalize PyObjC's ``(OSStatus, out_value)`` convention safely."""
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], int):
        return result[0], result[1]
    return _ERR_SEC_NOT_AVAILABLE, None


class KeychainProvider:
    """Search and resolve non-synchronizable legacy generic passwords only."""

    name = "keychain"

    def __init__(self, backend: KeychainBackend | None = None) -> None:
        self._backend = backend

    def status(self) -> ProviderStatus:
        try:
            backend = self._get_backend()
            status, _keychain = backend.default_keychain()
            self._raise_for_status(status)
        except ProviderLockedError:
            return ProviderStatus(self.name, ProviderState.LOCKED)
        except ProviderError:
            return ProviderStatus(self.name, ProviderState.UNAVAILABLE)
        return ProviderStatus(self.name, ProviderState.READY)

    def search(self, query: str, *, limit: int = 20) -> list[CredentialMetadata]:
        """Find matching metadata without ever requesting ``kSecReturnData``."""
        if not isinstance(query, str) or not query.strip():
            raise ValueError("search query must not be empty")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("search limit must be between 1 and 100")

        backend = self._get_backend()
        keychain = self._default_keychain(backend)
        constants = backend.constants
        native_query: dict[object, object] = {
            constants.item_class: constants.generic_password,
            constants.synchronizable: False,
            constants.match_search_list: [keychain],
            constants.return_attributes: True,
            constants.return_persistent_ref: True,
            constants.match_limit: constants.match_limit_all,
            constants.use_authentication_ui: constants.authentication_ui_fail,
        }
        status, result = backend.copy_matching(native_query)
        if status == _ERR_SEC_ITEM_NOT_FOUND:
            return []
        self._raise_for_status(status)

        needle = _normalized(query)
        matches = [
            metadata
            for attributes in _attribute_results(result)
            if (metadata := self._metadata_from_attributes(attributes, constants))
            is not None
            and _metadata_matches(metadata, needle)
        ]
        matches.sort(key=_metadata_sort_key)
        return matches[:limit]

    def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
        """Resolve by persistent reference only, never service/account fallback."""
        persistent_ref = parse_persistent_reference(reference)
        backend = self._get_backend()
        keychain = self._default_keychain(backend)
        constants = backend.constants
        native_query: dict[object, object] = {
            constants.item_class: constants.generic_password,
            constants.synchronizable: False,
            constants.match_search_list: [keychain],
            constants.value_persistent_ref: persistent_ref,
            constants.return_data: True,
            constants.match_limit: constants.match_limit_one,
            constants.use_authentication_ui: (
                constants.authentication_ui_fail
                if no_input
                else constants.authentication_ui_allow
            ),
        }
        status, result = backend.copy_matching(native_query)
        self._raise_for_status(status)

        # SecItemCopyMatching with MatchLimitOne must return one bytes value.
        # Treat every other shape as a closed failure rather than guessing.
        if isinstance(result, (list, tuple)):
            if len(result) != 1:
                raise CredentialAmbiguousError()
            result = result[0]
        secret_data = _data_bytes(result)
        if secret_data is None:
            raise ProviderOperationError()
        return Secret(secret_data)

    def _get_backend(self) -> KeychainBackend:
        if self._backend is None:
            self._backend = PyObjCSecurityBackend()
        return self._backend

    @staticmethod
    def _default_keychain(backend: KeychainBackend) -> object:
        status, keychain = backend.default_keychain()
        KeychainProvider._raise_for_status(status)
        if keychain is None:
            raise ProviderUnavailableError()
        return keychain

    @staticmethod
    def _raise_for_status(status: int) -> None:
        if status == _ERR_SEC_SUCCESS:
            return
        if status == _ERR_SEC_ITEM_NOT_FOUND:
            raise CredentialNotFoundError()
        if status in (_ERR_SEC_USER_CANCELED, _ERR_SEC_AUTH_FAILED):
            raise ProviderAccessDeniedError()
        if status == _ERR_SEC_INTERACTION_NOT_ALLOWED:
            raise ProviderLockedError()
        if status in (
            _ERR_SEC_NOT_AVAILABLE,
            _ERR_SEC_NO_SUCH_KEYCHAIN,
            _ERR_SEC_INVALID_KEYCHAIN,
        ):
            raise ProviderUnavailableError()
        if status == _ERR_SEC_PARAM:
            raise InvalidReferenceError()
        raise ProviderOperationError()

    @staticmethod
    def _metadata_from_attributes(
        attributes: Mapping[object, object], constants: KeychainConstants
    ) -> CredentialMetadata | None:
        persistent_ref = _data_bytes(attributes.get(constants.value_persistent_ref))
        if not persistent_ref:
            # An item without a stable persistent reference cannot safely be
            # selected later, so it is not a discovery result.
            return None
        return CredentialMetadata(
            reference=format_persistent_reference(persistent_ref),
            provider="keychain",
            name=_string_attribute(attributes, constants.attr_service),
            account=_string_attribute(attributes, constants.attr_account),
            label=_string_attribute(attributes, constants.attr_label),
            kind="generic-password",
            modified_at=_date_attribute(attributes, constants.attr_modification_date),
            description=_string_attribute(attributes, constants.attr_description),
            created_at=_date_attribute(attributes, constants.attr_creation_date),
            item_type=_string_attribute(attributes, constants.attr_type),
            keychain="default",
        )


def format_persistent_reference(persistent_ref: bytes) -> str:
    """Encode native persistent-reference bytes in the canonical MVP URI."""
    if not isinstance(persistent_ref, bytes) or not persistent_ref:
        raise InvalidReferenceError()
    token = base64.urlsafe_b64encode(persistent_ref).rstrip(b"=").decode("ascii")
    return _REFERENCE_PREFIX + token


def parse_persistent_reference(reference: str) -> bytes:
    """Parse only the exact, canonical keychain persistent-reference URI."""
    if not isinstance(reference, str) or not reference.startswith(_REFERENCE_PREFIX):
        raise InvalidReferenceError()
    token = reference[len(_REFERENCE_PREFIX) :]
    if not token or any(
        char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for char in token
    ):
        raise InvalidReferenceError()
    try:
        value = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except (ValueError, binascii.Error):
        raise InvalidReferenceError() from None
    if not value or format_persistent_reference(value) != reference:
        raise InvalidReferenceError()
    return value


def _data_bytes(value: object | None) -> bytes | None:
    """Copy a CFData/NSData-compatible buffer into Python bytes."""
    if isinstance(value, str) or value is None:
        return None
    try:
        return memoryview(value).tobytes()  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _attribute_results(result: object | None) -> list[Mapping[object, object]]:
    if isinstance(result, Mapping):
        return [result]
    if not isinstance(result, Sequence) or isinstance(
        result, (str, bytes, bytearray, memoryview)
    ):
        raise ProviderOperationError()
    if not all(isinstance(item, Mapping) for item in result):
        raise ProviderOperationError()
    return list(result)


def _string_attribute(attributes: Mapping[object, object], key: object) -> str | None:
    value = attributes.get(key)
    return value if isinstance(value, str) else None


def _date_attribute(
    attributes: Mapping[object, object], key: object
) -> datetime | None:
    value = attributes.get(key)
    return value if isinstance(value, datetime) else None


def _metadata_matches(metadata: CredentialMetadata, needle: str) -> bool:
    fields = (
        metadata.name,
        metadata.account,
        metadata.label,
        metadata.description,
        metadata.item_type,
    )
    return any(field is not None and needle in _normalized(field) for field in fields)


def _metadata_sort_key(metadata: CredentialMetadata) -> tuple[str, str, str, str]:
    return (
        _normalized(metadata.provider),
        _normalized(metadata.name or ""),
        _normalized(metadata.account or ""),
        metadata.reference,
    )


def _normalized(value: str) -> str:
    """Normalize only for comparisons, preserving stored metadata verbatim."""
    return normalize("NFKC", value).casefold()
