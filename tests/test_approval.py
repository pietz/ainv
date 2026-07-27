from __future__ import annotations

import pytest

from ainv.approval import (
    ApprovalBinding,
    ApprovalRequest,
    ApprovalUnavailableError,
    DeliveryAction,
    _request_text,
)
from ainv.approval import test_request as _test_request


def test_request_text_contains_only_value_free_context() -> None:
    request = ApprovalRequest(
        action=DeliveryAction.RUN,
        bindings=(
            ApprovalBinding(
                credential="keychain:OPENAI_API_KEY@personal",
                variable="OPENAI_API_KEY",
            ),
        ),
        destination="uv run app.py",
        working_directory="/tmp/project",
    )

    text = _request_text(request)

    assert "Run a command" in text
    assert "keychain:OPENAI_API_KEY@personal → OPENAI_API_KEY" in text
    assert "uv run app.py" in text
    assert "/tmp/project" in text
    assert "No credential values are shown" in text


def test_request_text_escapes_controls_and_unicode_line_separators() -> None:
    request = ApprovalRequest(
        action=DeliveryAction.SET,
        bindings=(
            ApprovalBinding(
                credential="keychain:TOKEN@bad\n\x1b",
                variable="TOKEN\tNAME",
            ),
        ),
        destination="/tmp/.env\rspoof\u2028fake\u2029line",
        working_directory="/tmp/project",
    )

    text = _request_text(request)

    assert "\x1b" not in text
    assert "\u2028" not in text
    assert "\u2029" not in text
    assert "bad\\n\\x1b" in text
    assert "TOKEN\\tNAME" in text
    assert "/tmp/.env\\rspoof\\u2028fake\\u2029line" in text


def test_request_text_rejects_context_that_would_be_truncated() -> None:
    request = ApprovalRequest(
        action=DeliveryAction.RUN,
        bindings=(
            ApprovalBinding(
                credential="keychain:" + "x" * 200,
                variable="TOKEN",
            ),
        ),
        destination="command",
        working_directory="/tmp/project",
    )

    with pytest.raises(
        ApprovalUnavailableError,
        match="too long to display safely",
    ):
        _request_text(request)


def test_harmless_test_request_has_no_bindings() -> None:
    request = _test_request()

    assert request.action is DeliveryAction.TEST
    assert request.bindings == ()
    assert request.destination == "No credential will be accessed."
