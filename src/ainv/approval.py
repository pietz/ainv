"""Native human-consent prompt for credential delivery."""

from __future__ import annotations

import os
import sys
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

MAX_APPROVAL_BINDINGS = 10
_MAX_APPROVAL_TEXT = 4_000


class DeliveryAction(StrEnum):
    """Credential delivery operations shown to the human."""

    RUN = "Run a command"
    SET = "Update a dotenv file"
    TEST = "Test the approval popup"


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    """One value-free credential-to-destination mapping."""

    credential: str
    variable: str


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Value-free context displayed before credential resolution."""

    action: DeliveryAction
    bindings: tuple[ApprovalBinding, ...]
    destination: str
    working_directory: str


class ApprovalUnavailableError(Exception):
    """Native approval cannot be requested safely."""


class Approver(Protocol):
    """A human-consent boundary injectable for tests."""

    def approve(self, request: ApprovalRequest) -> bool:
        """Return whether the human selected Allow Once."""


class MacOSApprover:
    """Display one native AppKit alert without handling credential values."""

    def approve(self, request: ApprovalRequest) -> bool:
        if sys.platform != "darwin":
            raise ApprovalUnavailableError("native approval is unavailable")
        if len(request.bindings) > MAX_APPROVAL_BINDINGS:
            raise ApprovalUnavailableError("too many credentials for native approval")
        informative_text = _request_text(request)
        try:
            import AppKit  # type: ignore[import-not-found]

            application = AppKit.NSApplication.sharedApplication()
            application.setActivationPolicy_(
                AppKit.NSApplicationActivationPolicyAccessory
            )
            alert = AppKit.NSAlert.alloc().init()
            alert.setAlertStyle_(AppKit.NSAlertStyleInformational)
            alert.setMessageText_("Allow credential delivery?")
            alert.setInformativeText_(informative_text)
            allow_button = alert.addButtonWithTitle_("Allow Once")
            deny_button = alert.addButtonWithTitle_("Deny")
            allow_button.setKeyEquivalent_("")
            deny_button.setKeyEquivalent_("\x1b")
            alert.window().setDefaultButtonCell_(None)
            application.activateIgnoringOtherApps_(True)
            response = alert.runModal()
        except Exception:  # noqa: BLE001 - native details stay private
            raise ApprovalUnavailableError("native approval is unavailable") from None
        return bool(response == AppKit.NSAlertFirstButtonReturn)


def test_request() -> ApprovalRequest:
    """Return a harmless request that accesses no credential provider."""
    return ApprovalRequest(
        action=DeliveryAction.TEST,
        bindings=(),
        destination="No credential will be accessed.",
        working_directory=os.getcwd(),
    )


def _request_text(request: ApprovalRequest) -> str:
    lines = [f"Action: {_display_safe(request.action.value, 80)}"]
    if request.bindings:
        lines.extend(("", "Credentials:"))
        lines.extend(
            f"• {_display_safe(binding.credential, 200)} → "
            f"{_display_safe(binding.variable, 100)}"
            for binding in request.bindings
        )
    lines.extend(
        (
            "",
            f"Destination: {_display_safe(request.destination, 500)}",
            f"Working directory: {_display_safe(request.working_directory, 500)}",
            "",
            "No credential values are shown in this dialog.",
        )
    )
    text = "\n".join(lines)
    if len(text) > _MAX_APPROVAL_TEXT:
        raise ApprovalUnavailableError("approval context is too long to display safely")
    return text


def _display_safe(value: str, limit: int) -> str:
    safe: list[str] = []
    for character in value:
        category = unicodedata.category(character)
        if category.startswith("C") or category in {"Zl", "Zp"}:
            safe.append(character.encode("unicode_escape").decode("ascii"))
        else:
            safe.append(character)
    rendered = "".join(safe)
    if len(rendered) > limit:
        raise ApprovalUnavailableError("approval context is too long to display safely")
    return rendered
