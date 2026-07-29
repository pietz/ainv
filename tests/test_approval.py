from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from types import SimpleNamespace
from typing import ClassVar

import pytest

from ainv.approval import (
    _MAX_ANCESTRY_DEPTH,
    _PROC_PIDT_SHORTBSDINFO,
    ApprovalBinding,
    ApprovalRequest,
    ApprovalUnavailableError,
    DeliveryAction,
    MacOSApprover,
    RequestingApplication,
    _native_parent_process_id,
    _ProcBSDShortInfo,
    _request_text,
    _requesting_application,
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

    text = _request_text(request, requester_name="Ghostty")

    assert "Requesting app (informational): Ghostty" in text
    assert "Best-effort process ancestry; this identity is not authenticated." in text
    assert "Run a command" in text
    assert "keychain:OPENAI_API_KEY@personal → OPENAI_API_KEY" in text
    assert "uv run app.py" in text
    assert "/tmp/project" in text
    assert "No credential values are shown" in text


def test_request_text_uses_neutral_requester_fallback() -> None:
    request = ApprovalRequest(
        action=DeliveryAction.RUN,
        bindings=(),
        destination="command",
        working_directory="/tmp/project",
    )

    text = _request_text(request)

    assert "Requesting app (informational): Unidentified application" in text
    assert "No bundled application could be identified" in text


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

    text = _request_text(request, requester_name="Ghostty\nSpoof")

    assert "\x1b" not in text
    assert "\u2028" not in text
    assert "\u2029" not in text
    assert "Requesting app (informational): Ghostty\\nSpoof" in text
    assert "bad\\n\\x1b" in text
    assert "TOKEN\\tNAME" in text
    assert "/tmp/.env\\rspoof\\u2028fake\\u2029line" in text


def test_request_text_rejects_overlong_field_instead_of_truncating() -> None:
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


def test_request_text_fails_closed_when_aggregate_context_is_overlong() -> None:
    request = ApprovalRequest(
        action=DeliveryAction.RUN,
        bindings=tuple(
            ApprovalBinding(credential="c" * 190, variable="v" * 90) for _ in range(10)
        ),
        destination="d" * 500,
        working_directory="w" * 500,
    )

    with pytest.raises(
        ApprovalUnavailableError,
        match="too long to display safely",
    ):
        _request_text(request, requester_name="r" * 100)


def test_harmless_test_request_has_no_bindings() -> None:
    request = _test_request()

    assert request.action is DeliveryAction.TEST
    assert request.bindings == ()
    assert request.destination == "No credential will be accessed."
    text = _request_text(request, requester_name="Terminal")
    assert "This is a harmless popup test. No credential will be accessed." in text
    assert "identity is not authenticated" in text
    assert "requested" not in text


def test_proc_bsdshortinfo_matches_documented_darwin_layout() -> None:
    expected_offsets = {
        "pbsi_pid": 0,
        "pbsi_ppid": 4,
        "pbsi_pgid": 8,
        "pbsi_status": 12,
        "pbsi_comm": 16,
        "pbsi_flags": 32,
        "pbsi_uid": 36,
        "pbsi_gid": 40,
        "pbsi_ruid": 44,
        "pbsi_rgid": 48,
        "pbsi_svuid": 52,
        "pbsi_svgid": 56,
        "pbsi_rfu": 60,
    }

    assert ctypes.sizeof(_ProcBSDShortInfo) == 64
    assert {
        name: getattr(_ProcBSDShortInfo, name).offset for name in expected_offsets
    } == expected_offsets


def test_native_parent_lookup_uses_shortbsdinfo_and_exact_buffer_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int, int, int]] = []

    def proc_pidinfo(
        process_identifier: int,
        flavor: int,
        argument: int,
        buffer: object,
        buffer_size: int,
    ) -> int:
        calls.append((process_identifier, flavor, argument, buffer_size))
        information = ctypes.cast(buffer, ctypes.POINTER(_ProcBSDShortInfo)).contents
        information.pbsi_ppid = 456
        return buffer_size

    monkeypatch.setattr("ainv.approval.sys.platform", "darwin")
    monkeypatch.setattr("ainv.approval._proc_pidinfo_function", lambda: proc_pidinfo)

    assert _native_parent_process_id(123) == 456
    assert calls == [(123, _PROC_PIDT_SHORTBSDINFO, 0, 64)]


@pytest.mark.parametrize("returned_size", [0, 63, 65])
def test_native_parent_lookup_rejects_nonexact_return_size(
    monkeypatch: pytest.MonkeyPatch, returned_size: int
) -> None:
    monkeypatch.setattr("ainv.approval.sys.platform", "darwin")
    monkeypatch.setattr(
        "ainv.approval._proc_pidinfo_function",
        lambda: lambda *_args: returned_size,
    )

    with pytest.raises(OSError, match="process ancestry is unavailable"):
        _native_parent_process_id(123)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin libproc test")
def test_native_parent_lookup_matches_current_process_parent() -> None:
    assert _native_parent_process_id(os.getpid()) == os.getppid()


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin libproc test")
def test_native_parent_lookup_crosses_differently_owned_ancestor_when_present() -> None:
    process_rows = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,uid="],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    processes = {
        int(pid): (int(parent), int(uid))
        for row in process_rows
        if len(parts := row.split()) == 3
        for pid, parent, uid in [parts]
    }
    process_identifier = os.getpid()
    candidate: tuple[int, int] | None = None
    for _ in range(_MAX_ANCESTRY_DEPTH):
        process = processes.get(process_identifier)
        if process is None:
            break
        parent_identifier, uid = process
        if uid != os.getuid() and parent_identifier > 1:
            candidate = (process_identifier, parent_identifier)
            break
        if parent_identifier <= 1 or parent_identifier == process_identifier:
            break
        process_identifier = parent_identifier
    if candidate is None:
        pytest.skip("no differently owned intermediate ancestor in this test session")

    assert _native_parent_process_id(candidate[0]) == candidate[1]


class FakeRunningApplication:
    def __init__(
        self,
        name: str,
        bundle_identifier: str | None,
        icon: object | None = None,
    ) -> None:
        self._name = name
        self._bundle_identifier = bundle_identifier
        self._icon = icon

    def localizedName(self) -> str:
        return self._name

    def bundleIdentifier(self) -> str | None:
        return self._bundle_identifier

    def icon(self) -> object | None:
        return self._icon


class FakeRunningApplicationAPI:
    by_pid: ClassVar[dict[int, FakeRunningApplication]] = {}

    @classmethod
    def runningApplicationWithProcessIdentifier_(
        cls, process_identifier: int
    ) -> FakeRunningApplication | None:
        return cls.by_pid.get(process_identifier)


def fake_appkit() -> SimpleNamespace:
    return SimpleNamespace(NSRunningApplication=FakeRunningApplicationAPI)


def test_requester_returns_nearest_bundled_ancestor() -> None:
    pi_icon = object()
    terminal_icon = object()
    FakeRunningApplicationAPI.by_pid = {
        90: FakeRunningApplication("pi", "dev.pi", pi_icon),
        70: FakeRunningApplication("Terminal", "com.apple.Terminal", terminal_icon),
    }
    parents = {100: 90, 90: 80, 80: 70, 70: 1}

    requester = _requesting_application(
        fake_appkit(),
        start_pid=100,
        parent_process_id=parents.__getitem__,
    )

    assert requester is not None
    assert requester.name == "pi"
    assert requester.icon is pi_icon


def test_requester_skips_ancestor_with_nil_bundle_identifier() -> None:
    terminal_icon = object()
    FakeRunningApplicationAPI.by_pid = {
        90: FakeRunningApplication("Python", None),
        80: FakeRunningApplication("Terminal", "com.apple.Terminal", terminal_icon),
    }
    parents = {100: 90, 90: 80, 80: 1}

    requester = _requesting_application(
        fake_appkit(),
        start_pid=100,
        parent_process_id=parents.__getitem__,
    )

    assert requester is not None
    assert requester.name == "Terminal"
    assert requester.icon is terminal_icon


def test_requester_does_not_use_term_program_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeRunningApplicationAPI.by_pid = {}
    monkeypatch.setenv("TERM_PROGRAM", "ghostty")

    requester = _requesting_application(
        fake_appkit(),
        start_pid=100,
        parent_process_id=lambda _pid: 1,
    )

    assert requester is None


def test_requester_escapes_unsafe_native_name_when_displayed() -> None:
    FakeRunningApplicationAPI.by_pid = {
        90: FakeRunningApplication("Ghostty\nSpoof", "com.example.ghostty")
    }
    requester = _requesting_application(
        fake_appkit(),
        start_pid=100,
        parent_process_id=lambda _pid: 90,
    )

    assert requester is not None
    text = _request_text(_test_request(), requester_name=requester.name)
    assert "Ghostty\\nSpoof" in text
    assert "Ghostty\nSpoof" not in text


def test_requester_stops_on_parent_cycle() -> None:
    FakeRunningApplicationAPI.by_pid = {}
    looked_up: list[int] = []
    parents = {100: 90, 90: 100}

    def parent(process_identifier: int) -> int:
        looked_up.append(process_identifier)
        return parents[process_identifier]

    assert (
        _requesting_application(fake_appkit(), start_pid=100, parent_process_id=parent)
        is None
    )
    assert looked_up == [100, 90]


def test_requester_stops_on_parent_lookup_error() -> None:
    FakeRunningApplicationAPI.by_pid = {}

    def unavailable(_process_identifier: int) -> int:
        raise OSError("gone")

    assert (
        _requesting_application(
            fake_appkit(), start_pid=100, parent_process_id=unavailable
        )
        is None
    )


def test_requester_enforces_ancestry_depth_limit() -> None:
    FakeRunningApplicationAPI.by_pid = {
        1_000 - _MAX_ANCESTRY_DEPTH - 1: FakeRunningApplication(
            "Too far", "com.example.too-far"
        )
    }
    looked_up: list[int] = []

    def parent(process_identifier: int) -> int:
        looked_up.append(process_identifier)
        return process_identifier - 1

    requester = _requesting_application(
        fake_appkit(), start_pid=1_000, parent_process_id=parent
    )

    assert requester is None
    assert len(looked_up) == _MAX_ANCESTRY_DEPTH


def test_requester_skips_overlong_native_name() -> None:
    FakeRunningApplicationAPI.by_pid = {
        90: FakeRunningApplication("x" * 101, "com.example.too-long")
    }

    requester = _requesting_application(
        fake_appkit(), start_pid=100, parent_process_id=lambda _pid: 90
    )

    assert requester is None


class FakeButton:
    def __init__(self, title: str) -> None:
        self.title = title
        self.key_equivalent: str | None = None

    def setKeyEquivalent_(self, value: str) -> None:
        self.key_equivalent = value


class FakeWindow:
    def setDefaultButtonCell_(self, _value: object) -> None:
        pass


class FakeAlert:
    latest: FakeAlert
    response = 1_000

    def __init__(self) -> None:
        self.message: str | None = None
        self.informative_text: str | None = None
        self.icon: object | None = None
        self.buttons: list[FakeButton] = []
        self._window = FakeWindow()

    @classmethod
    def alloc(cls) -> FakeAlert:
        cls.latest = cls()
        return cls.latest

    def init(self) -> FakeAlert:
        return self

    def setAlertStyle_(self, _style: object) -> None:
        pass

    def setMessageText_(self, value: str) -> None:
        self.message = value

    def setInformativeText_(self, value: str) -> None:
        self.informative_text = value

    def setIcon_(self, value: object) -> None:
        self.icon = value

    def addButtonWithTitle_(self, title: str) -> FakeButton:
        button = FakeButton(title)
        self.buttons.append(button)
        return button

    def window(self) -> FakeWindow:
        return self._window

    def runModal(self) -> int:
        return self.response


class FakeApplication:
    def __init__(self) -> None:
        self.activation_policy: object | None = None
        self.activated = False

    def setActivationPolicy_(self, value: object) -> None:
        self.activation_policy = value

    def activateIgnoringOtherApps_(self, value: bool) -> None:
        self.activated = value


class FakeApplicationAPI:
    application = FakeApplication()

    @classmethod
    def sharedApplication(cls) -> FakeApplication:
        return cls.application


def approval_appkit() -> SimpleNamespace:
    return SimpleNamespace(
        NSApplication=FakeApplicationAPI,
        NSApplicationActivationPolicyAccessory="accessory",
        NSAlert=FakeAlert,
        NSAlertStyleInformational="informational",
        NSAlertFirstButtonReturn=1_000,
    )


def test_native_alert_clears_return_key_and_maps_only_allow_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appkit = approval_appkit()
    icon = object()
    requester = RequestingApplication(name="iTerm2", icon=icon)
    monkeypatch.setattr("ainv.approval.sys.platform", "darwin")
    monkeypatch.setitem(sys.modules, "AppKit", appkit)
    request = ApprovalRequest(
        action=DeliveryAction.RUN,
        bindings=(),
        destination="command",
        working_directory="/tmp/project",
        requester=requester,
    )

    FakeAlert.response = 1_000
    assert MacOSApprover().approve(request) is True

    alert = FakeAlert.latest
    assert alert.message == "ainv Access Requested"
    assert alert.informative_text is not None
    assert "Requesting app (informational): iTerm2" in alert.informative_text
    assert "identity is not authenticated" in alert.informative_text
    assert alert.icon is icon
    assert [button.title for button in alert.buttons] == ["Allow Once", "Deny"]
    assert [button.key_equivalent for button in alert.buttons] == ["", "\x1b"]

    FakeAlert.response = 1_001
    assert MacOSApprover().approve(request) is False


def test_native_alert_uses_no_requester_icon_for_unknown_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appkit = approval_appkit()
    monkeypatch.setattr("ainv.approval.sys.platform", "darwin")
    monkeypatch.setitem(sys.modules, "AppKit", appkit)

    FakeAlert.response = 1_001
    assert MacOSApprover().approve(_test_request()) is False

    alert = FakeAlert.latest
    assert alert.icon is None
    assert alert.informative_text is not None
    assert "Unidentified application" in alert.informative_text
