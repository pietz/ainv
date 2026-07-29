"""Native human-consent prompt for credential delivery."""

from __future__ import annotations

import ctypes
import os
import sys
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Any, Protocol

MAX_APPROVAL_BINDINGS = 10
_MAX_APPROVAL_TEXT = 4_000
_MAX_ANCESTRY_DEPTH = 64
_PROC_PIDT_SHORTBSDINFO = 13


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


@dataclass(frozen=True, slots=True)
class _RequestingApplication:
    """Best-effort native identity and icon for the app behind the request."""

    name: str
    icon: object | None


class _ProcBSDShortInfo(ctypes.Structure):
    """Exact Darwin ``proc_bsdshortinfo`` layout from ``sys/proc_info.h``."""

    _fields_ = [
        ("pbsi_pid", ctypes.c_uint32),
        ("pbsi_ppid", ctypes.c_uint32),
        ("pbsi_pgid", ctypes.c_uint32),
        ("pbsi_status", ctypes.c_uint32),
        ("pbsi_comm", ctypes.c_char * 16),
        ("pbsi_flags", ctypes.c_uint32),
        ("pbsi_uid", ctypes.c_uint32),
        ("pbsi_gid", ctypes.c_uint32),
        ("pbsi_ruid", ctypes.c_uint32),
        ("pbsi_rgid", ctypes.c_uint32),
        ("pbsi_svuid", ctypes.c_uint32),
        ("pbsi_svgid", ctypes.c_uint32),
        ("pbsi_rfu", ctypes.c_uint32),
    ]


class MacOSApprover:
    """Display one native AppKit alert without handling credential values."""

    def approve(self, request: ApprovalRequest) -> bool:
        if sys.platform != "darwin":
            raise ApprovalUnavailableError("native approval is unavailable")
        if len(request.bindings) > MAX_APPROVAL_BINDINGS:
            raise ApprovalUnavailableError("too many credentials for native approval")
        try:
            import AppKit  # type: ignore[import-not-found]

            requester = _requesting_application(AppKit)
            informative_text = _request_text(
                request,
                requester_name=requester.name if requester is not None else None,
            )
            application = AppKit.NSApplication.sharedApplication()
            application.setActivationPolicy_(
                AppKit.NSApplicationActivationPolicyAccessory
            )
            alert = AppKit.NSAlert.alloc().init()
            alert.setAlertStyle_(AppKit.NSAlertStyleInformational)
            alert.setMessageText_("ainv Access Requested")
            alert.setInformativeText_(informative_text)
            if requester is not None and requester.icon is not None:
                alert.setIcon_(requester.icon)
            allow_button = alert.addButtonWithTitle_("Allow Once")
            deny_button = alert.addButtonWithTitle_("Deny")
            allow_button.setKeyEquivalent_("")
            deny_button.setKeyEquivalent_("\x1b")
            alert.window().setDefaultButtonCell_(None)
            application.activateIgnoringOtherApps_(True)
            response = alert.runModal()
        except ApprovalUnavailableError:
            raise
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


def _request_text(
    request: ApprovalRequest,
    *,
    requester_name: str | None = None,
) -> str:
    if requester_name is None:
        requester = "Unidentified application"
        explanation = (
            "No bundled application could be identified from native process ancestry."
        )
    else:
        requester = _display_safe(requester_name, 100)
        explanation = (
            "Best-effort process ancestry; this identity is not authenticated."
        )

    lines = [f"Requesting app (informational): {requester}", explanation]
    if request.action is DeliveryAction.TEST:
        lines.append("This is a harmless popup test. No credential will be accessed.")
    lines.extend(("", f"Action: {_display_safe(request.action.value, 80)}"))
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


def _requesting_application(
    appkit: Any,
    *,
    start_pid: int | None = None,
    parent_process_id: Callable[[int], int] | None = None,
) -> _RequestingApplication | None:
    """Return the nearest bundled app found in native process ancestry."""
    current_pid = os.getpid() if start_pid is None else start_pid
    parent_lookup = (
        _native_parent_process_id if parent_process_id is None else parent_process_id
    )
    seen = {current_pid}

    for _ in range(_MAX_ANCESTRY_DEPTH):
        try:
            current_pid = parent_lookup(current_pid)
        except Exception:  # noqa: BLE001 - requester identity is best effort
            break
        if current_pid <= 1 or current_pid in seen:
            break
        seen.add(current_pid)
        requester = _application_identity(_running_application(appkit, current_pid))
        if requester is not None:
            return requester
    return None


def _running_application(appkit: Any, process_identifier: int) -> object | None:
    try:
        return appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_(
            process_identifier
        )
    except Exception:  # noqa: BLE001 - native lookup is best effort
        return None


def _application_identity(
    application: object | None,
) -> _RequestingApplication | None:
    if application is None:
        return None
    try:
        name = application.localizedName()  # type: ignore[attr-defined]
        bundle_identifier = application.bundleIdentifier()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - requester identity is best effort
        return None
    if (
        not isinstance(name, str)
        or not name.strip()
        or not isinstance(bundle_identifier, str)
        or not bundle_identifier.strip()
    ):
        return None
    try:
        _display_safe(name, 100)
    except ApprovalUnavailableError:
        return None
    try:
        icon = application.icon()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - icon absence does not hide identity
        icon = None
    return _RequestingApplication(name=name, icon=icon)


@cache
def _proc_pidinfo_function() -> Any:
    library = ctypes.CDLL("/usr/lib/libproc.dylib")
    function = library.proc_pidinfo
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    function.restype = ctypes.c_int
    return function


def _native_parent_process_id(process_identifier: int) -> int:
    if sys.platform != "darwin" or process_identifier <= 0:
        raise OSError("process ancestry is unavailable")
    information = _ProcBSDShortInfo()
    information_size = ctypes.sizeof(information)
    result = _proc_pidinfo_function()(
        process_identifier,
        _PROC_PIDT_SHORTBSDINFO,
        0,
        ctypes.byref(information),
        information_size,
    )
    if result != information_size:
        raise OSError("process ancestry is unavailable")
    return int(information.pbsi_ppid)


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
