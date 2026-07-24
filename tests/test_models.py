from __future__ import annotations

from ainv.models import CredentialMetadata, Secret


def test_secret_representations_redact_value() -> None:
    secret = Secret(b"model-canary-never-rendered")

    assert repr(secret) == "Secret(<redacted>)"
    assert str(secret) == "<redacted>"
    assert "model-canary-never-rendered" not in repr(secret)


def test_metadata_ref_is_canonical_reference_alias() -> None:
    metadata = CredentialMetadata(
        reference="keychain://v1/item/YWJj",
        provider="keychain",
        name="service",
        account=None,
        label=None,
        kind="generic-password",
        modified_at=None,
    )

    assert metadata.ref == metadata.reference
