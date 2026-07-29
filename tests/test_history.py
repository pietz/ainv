from __future__ import annotations

import errno
import fcntl
import json
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ainv import history
from ainv.history import (
    MAX_HISTORY_BYTES,
    MAX_RECORD_BYTES,
    MAX_STORED_BINDINGS,
    HistoryDecision,
    HistoryError,
    HistoryRecord,
    append_history,
    bounded_history_record,
    history_path,
    read_history,
    utc_timestamp,
)


def record(index: int = 1) -> HistoryRecord:
    return bounded_history_record(
        timestamp=utc_timestamp(datetime(2025, 1, index, 12, 0, tzinfo=UTC)),
        action="run",
        decision=HistoryDecision.NOT_REQUESTED,
        reason="approval_disabled",
        bindings=[("TOKEN", "keychain:TOKEN@personal")],
        destination={
            "kind": "command",
            "executable": "/usr/bin/example",
            "argument_count": index,
        },
        working_directory="/safe/project",
        requester_app="Terminal",
    )


def private_file(path: Path, contents: bytes) -> None:
    path.write_bytes(contents)
    path.chmod(0o600)


def encoded(item: HistoryRecord) -> bytes:
    return (
        json.dumps(
            item.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
        + b"\n"
    )


def test_history_path_ignores_home_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", "/tmp/agent-controlled-home")

    assert history_path() != Path(
        "/tmp/agent-controlled-home/Library/Application Support/ainv/history.jsonl"
    )


def test_append_and_read_history_with_private_permissions(tmp_path: Path) -> None:
    path = tmp_path / "ainv" / "history.jsonl"

    append_history(record(), path)

    result = read_history(path=path)
    assert result.records == (record(),)
    assert result.invalid_record_count == 0
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes().endswith(b"\n")


def test_read_limit_returns_newest_records(tmp_path: Path) -> None:
    path = tmp_path / "ainv" / "history.jsonl"
    for index in range(1, 4):
        append_history(record(index), path)

    assert read_history(path=path, limit=2).records == (record(2), record(3))


@pytest.mark.parametrize(
    ("access", "lock_mode"),
    [("append", fcntl.LOCK_EX), ("read", fcntl.LOCK_SH)],
)
def test_history_lock_retries_then_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    access: str,
    lock_mode: int,
) -> None:
    path = tmp_path / "ainv" / "history.jsonl"
    path.parent.mkdir(mode=0o700)
    private_file(path, encoded(record(1)))
    attempts: list[int] = []
    sleeps: list[float] = []

    def contend_then_succeed(_fd: int, operation: int) -> None:
        attempts.append(operation)
        if len(attempts) <= 3:
            raise BlockingIOError(errno.EAGAIN, "lock is contended")

    monkeypatch.setattr(history, "_flock", contend_then_succeed)
    monkeypatch.setattr(history, "_sleep", sleeps.append)

    if access == "append":
        append_history(record(2), path)
        assert path.read_bytes().endswith(encoded(record(2)))
    else:
        assert read_history(path=path).records == (record(1),)

    assert attempts == [lock_mode | fcntl.LOCK_NB] * 4
    assert sleeps == list(history._LOCK_RETRY_DELAYS_SECONDS[:3])


@pytest.mark.parametrize(
    ("access", "lock_mode", "message"),
    [
        ("append", fcntl.LOCK_EX, "could not write"),
        ("read", fcntl.LOCK_SH, "could not read"),
    ],
)
def test_history_lock_contention_fails_after_bounded_retry_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    access: str,
    lock_mode: int,
    message: str,
) -> None:
    path = tmp_path / "ainv" / "history.jsonl"
    path.parent.mkdir(mode=0o700)
    private_file(path, encoded(record()))
    attempts: list[int] = []
    sleeps: list[float] = []

    def always_contended(_fd: int, operation: int) -> None:
        attempts.append(operation)
        raise BlockingIOError(errno.EAGAIN, "lock is contended")

    monkeypatch.setattr(history, "_flock", always_contended)
    monkeypatch.setattr(history, "_sleep", sleeps.append)

    with pytest.raises(HistoryError, match=message):
        if access == "append":
            append_history(record(2), path)
        else:
            read_history(path=path)

    assert attempts == [lock_mode | fcntl.LOCK_NB] * (
        len(history._LOCK_RETRY_DELAYS_SECONDS) + 1
    )
    assert sleeps == list(history._LOCK_RETRY_DELAYS_SECONDS)
    assert sum(sleeps) == pytest.approx(0.007)


@pytest.mark.parametrize("access", ["append", "read"])
def test_history_lock_recovers_from_real_transient_contention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    access: str,
) -> None:
    path = tmp_path / "ainv" / "history.jsonl"
    path.parent.mkdir(mode=0o700)
    private_file(path, encoded(record(1)))
    lock_fd = os.open(path.parent, os.O_RDONLY)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    retry_started = threading.Event()
    real_sleep = history._sleep

    def observed_sleep(delay: float) -> None:
        retry_started.set()
        real_sleep(delay)

    def access_history() -> None:
        if access == "append":
            append_history(record(2), path)
        else:
            read_history(path=path)

    monkeypatch.setattr(history, "_sleep", observed_sleep)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(access_history)
        try:
            assert retry_started.wait(timeout=1)
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            future.result(timeout=1)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    if access == "append":
        assert path.read_bytes().endswith(encoded(record(2)))


@pytest.mark.parametrize("mode", [0o750, 0o705, 0o770, 0o707])
def test_group_or_world_accessible_directory_is_rejected(
    tmp_path: Path, mode: int
) -> None:
    directory = tmp_path / "ainv"
    directory.mkdir()
    directory.chmod(mode)

    with pytest.raises(HistoryError, match="unsafe"):
        append_history(record(), directory / "history.jsonl")


def test_opened_history_directory_is_validated_from_fstat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "ainv"
    directory.mkdir(mode=0o700)
    original_fstat = history.os.fstat

    def unsafe_opened_directory(fd: int) -> os.stat_result:
        result = original_fstat(fd)
        if stat.S_ISDIR(result.st_mode):
            fields = list(result)
            fields[0] = stat.S_IFDIR | 0o755
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(history.os, "fstat", unsafe_opened_directory)

    with pytest.raises(HistoryError, match="safely"):
        append_history(record(), directory / "history.jsonl")


def test_symlinked_history_directory_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    directory = tmp_path / "ainv"
    directory.symlink_to(target, target_is_directory=True)

    with pytest.raises(HistoryError):
        append_history(record(), directory / "history.jsonl")


def test_symlink_hard_link_and_non_private_history_files_are_rejected(
    tmp_path: Path,
) -> None:
    for kind in ("symlink", "hardlink", "permissions"):
        directory = tmp_path / kind
        directory.mkdir(mode=0o700)
        path = directory / "history.jsonl"
        target = directory / "target"
        private_file(target, b"{}\n")
        if kind == "symlink":
            path.symlink_to(target)
        elif kind == "hardlink":
            os.link(target, path)
        else:
            path.write_bytes(b"{}\n")
            path.chmod(0o640)

        with pytest.raises(HistoryError):
            append_history(record(), path)
        with pytest.raises(HistoryError):
            read_history(path=path)


def test_wrong_owner_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "ainv"
    directory.mkdir(mode=0o700)
    current_uid = os.getuid()
    monkeypatch.setattr(history.os, "getuid", lambda: current_uid + 1)

    with pytest.raises(HistoryError, match="unsafe"):
        append_history(record(), directory / "history.jsonl")


def test_rotation_preserves_one_private_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ainv" / "history.jsonl"
    encoded_size = len(encoded(record()))
    monkeypatch.setattr(history, "MAX_HISTORY_BYTES", encoded_size * 2 + 1)

    append_history(record(1), path)
    append_history(record(2), path)
    append_history(record(3), path)

    backup = path.with_name("history.jsonl.1")
    assert backup.exists()
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert read_history(path=path, limit=3).records == (
        record(1),
        record(2),
        record(3),
    )

    append_history(record(4), path)
    append_history(record(5), path)
    assert len(list(path.parent.glob("history.jsonl*"))) == 2
    assert read_history(path=path, limit=10).records == (
        record(3),
        record(4),
        record(5),
    )


@pytest.mark.parametrize(
    ("decision", "reason"),
    [
        (HistoryDecision.ALLOWED, "user_allowed"),
        (HistoryDecision.DENIED, "user_denied"),
        (HistoryDecision.NOT_REQUESTED, "approval_disabled"),
        (HistoryDecision.ERROR, "approval_unavailable"),
        (HistoryDecision.ERROR, "interactive_input_disabled"),
        (HistoryDecision.ERROR, "too_many_bindings"),
        (HistoryDecision.ERROR, "working_directory_unavailable"),
    ],
)
def test_parser_accepts_every_authorization_outcome_and_reason(
    tmp_path: Path, decision: HistoryDecision, reason: str
) -> None:
    path = tmp_path / "history.jsonl"
    item = bounded_history_record(
        timestamp=record().timestamp,
        action="run",
        decision=decision,
        reason=reason,
        bindings=[("TOKEN", "keychain:TOKEN@personal")],
        destination={
            "kind": "command",
            "executable": "example-command",
            "argument_count": 0,
        },
        working_directory="/safe/project",
        requester_app=None,
    )

    append_history(item, path)

    assert read_history(path=path).records == (item,)


def test_mismatched_outcome_and_reason_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    document = record().to_dict()
    document["decision"] = "denied"
    document["reason"] = "approval_unavailable"
    private_file(path, json.dumps(document).encode() + b"\n" + encoded(record(2)))

    result = read_history(path=path)

    assert result.records == (record(2),)
    assert result.invalid_record_count == 1


def test_corrupt_and_partial_lines_are_skipped_without_hiding_valid_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "history.jsonl"
    attacker_text = b"ATTACKER-CONTROLLED-CONTENT"
    private_file(
        path,
        encoded(record(1))
        + attacker_text
        + b"\n"
        + encoded(record(2))
        + b'{"partial":',
    )

    result = read_history(path=path)

    assert result.records == (record(1), record(2))
    assert result.invalid_record_count == 2


def test_append_repairs_partial_tail_for_future_valid_records(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    private_file(path, encoded(record(1)) + b'{"partial":')

    append_history(record(2), path)
    result = read_history(path=path)

    assert result.records == (record(1), record(2))
    assert result.invalid_record_count == 1
    assert path.read_bytes().endswith(encoded(record(2)))


def test_oversized_line_is_skipped_and_counted(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    private_file(path, b"x" * MAX_RECORD_BYTES + b"\n" + encoded(record()))

    result = read_history(path=path)

    assert result.records == (record(),)
    assert result.invalid_record_count == 1


def test_oversized_backup_does_not_hide_valid_current_history(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    backup = path.with_name("history.jsonl.1")
    private_file(backup, b"x" * (MAX_HISTORY_BYTES + 1))
    private_file(path, encoded(record()))

    result = read_history(path=path)

    assert result.records == (record(),)
    assert result.invalid_record_count == 1


def test_bounded_record_retains_counts_and_explicit_truncation_metadata() -> None:
    bindings = [
        (f"TOKEN_{index}", f"keychain:{'x' * 1000}@account-{index}")
        for index in range(MAX_STORED_BINDINGS + 5)
    ]

    item = bounded_history_record(
        timestamp=record().timestamp,
        action="run",
        decision=HistoryDecision.NOT_REQUESTED,
        reason="approval_disabled",
        bindings=bindings,
        destination={
            "kind": "command",
            "executable": "/" + "e" * 10_000,
            "argument_count": 100_000,
        },
        working_directory="/" + "w" * 10_000,
        requester_app="r" * 10_000,
    )

    assert item.binding_count == len(bindings)
    assert len(item.bindings) == MAX_STORED_BINDINGS
    assert item.bindings_omitted == 5
    assert "bindings[0].reference" in item.truncated_fields
    assert "destination.executable" in item.truncated_fields
    assert "working_directory" in item.truncated_fields
    assert "requester_app" in item.truncated_fields
    assert len(encoded(item)) < MAX_RECORD_BYTES


def test_oversized_manual_record_is_rejected_before_file_creation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ainv" / "history.jsonl"
    base = record()
    oversized = HistoryRecord(
        timestamp=base.timestamp,
        action="set",
        decision=HistoryDecision.ALLOWED,
        reason="user_allowed",
        binding_count=1,
        bindings=base.bindings,
        bindings_omitted=0,
        destination={"kind": "dotenv_file", "path": "/" + "x" * MAX_RECORD_BYTES},
        working_directory="/safe/project",
    )

    with pytest.raises(HistoryError):
        append_history(oversized, path)
    assert not path.exists()
