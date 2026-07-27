"""Test-suite guardrails against accidental access to a developer's Keychain."""

from __future__ import annotations

import os

import pytest

from ainv.config import Config


@pytest.fixture(autouse=True)
def forbid_real_keychain_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """Require explicit opt-in before any test can construct the native backend."""
    if os.environ.get("AINV_KEYCHAIN_INTEGRATION") == "1":
        return

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError(
            "real Keychain access is forbidden in the default test suite"
        )

    monkeypatch.setattr(
        "ainv.providers.keychain.PyObjCSecurityBackend.__init__",
        forbidden,
    )
    monkeypatch.setattr("ainv.cli._get_config", lambda: Config())

    def forbid_approval_popup(*args: object, **kwargs: object) -> None:
        raise AssertionError("native approval popups are forbidden in tests")

    monkeypatch.setattr("ainv.cli._get_approver", forbid_approval_popup)
