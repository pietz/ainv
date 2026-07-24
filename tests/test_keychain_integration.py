"""Opt-in native tests using only a temporary synthetic file Keychain."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AINV_KEYCHAIN_INTEGRATION") != "1",
    reason="set AINV_KEYCHAIN_INTEGRATION=1 to run isolated native tests",
)


def test_synthetic_persistent_reference_round_trip(tmp_path: Path) -> None:
    import Security

    from ainv.models import Secret
    from ainv.providers.keychain import KeychainProvider, PyObjCSecurityBackend

    keychain_password = b"ainv-test-keychain-password"
    service = "AINV_SYNTHETIC_SERVICE"
    account = "ainv-synthetic-account"
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
        matches = provider.search("AINV_SYNTHETIC_SERVICE")

        assert len(matches) == 1
        assert created.reference == matches[0].reference
        assert matches[0].name == "AINV_SYNTHETIC_SERVICE"
        resolved = provider.resolve(matches[0].reference, no_input=True)
        assert resolved.reveal() == value
    finally:
        Security.SecKeychainDelete(keychain)
