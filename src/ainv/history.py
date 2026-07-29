"""Private, bounded local activity history for credential delivery decisions."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import pwd
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

RECORD_VERSION = 1
MAX_RECORD_BYTES = 16 * 1024
MAX_HISTORY_BYTES = 1024 * 1024
MAX_STORED_BINDINGS = 8
MAX_REFERENCE_BYTES = 256
MAX_VARIABLE_BYTES = 128
MAX_PATH_BYTES = 512
MAX_EXECUTABLE_BYTES = 512
MAX_REQUESTER_BYTES = 128
MAX_BINDING_COUNT = 1_000_000
MAX_ARGUMENT_COUNT = 1_000_000
_BACKUP_SUFFIX = ".1"
_MAX_TIMESTAMP_BYTES = 40
_MAX_ACTION_BYTES = 8
_MAX_REASON_BYTES = 64
_LOCK_RETRY_DELAYS_SECONDS = (0.0005, 0.001, 0.0015, 0.002, 0.002)
_LOCK_CONTENTION_ERRNOS = {errno.EACCES, errno.EAGAIN}
_flock = fcntl.flock
_sleep = time.sleep


class HistoryDecision(StrEnum):
    """Authorization outcomes recorded before credential resolution."""

    ALLOWED = "allowed"
    DENIED = "denied"
    NOT_REQUESTED = "not_requested"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class HistoryBinding:
    """One bounded, value-free credential reference and destination variable."""

    reference: str
    variable: str


@dataclass(frozen=True, slots=True)
class HistoryRecord:
    """One bounded, value-free delivery authorization decision."""

    timestamp: str
    action: str
    decision: HistoryDecision
    reason: str
    binding_count: int
    bindings: tuple[HistoryBinding, ...]
    bindings_omitted: int
    destination: dict[str, str | int]
    working_directory: str
    requester_app: str | None = None
    truncated_fields: tuple[str, ...] = ()
    escaped_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_version": RECORD_VERSION,
            "timestamp": self.timestamp,
            "action": self.action,
            "decision": self.decision.value,
            "reason": self.reason,
            "binding_count": self.binding_count,
            "bindings": [
                {"reference": binding.reference, "variable": binding.variable}
                for binding in self.bindings
            ],
            "bindings_omitted": self.bindings_omitted,
            "destination": self.destination,
            "working_directory": self.working_directory,
            "requester_app": self.requester_app,
            "truncated_fields": list(self.truncated_fields),
            "escaped_fields": list(self.escaped_fields),
        }


@dataclass(frozen=True, slots=True)
class HistoryReadResult:
    """Valid records and a value-free count of skipped malformed records."""

    records: tuple[HistoryRecord, ...]
    invalid_record_count: int = 0


class HistoryError(Exception):
    """Activity history could not be accessed or interpreted safely."""


def history_path() -> Path:
    """Return the fixed account-home path without trusting ``HOME``."""
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError):
        raise HistoryError("could not determine the ainv history path") from None
    return home / "Library" / "Application Support" / "ainv" / "history.jsonl"


def utc_timestamp(value: datetime | None = None) -> str:
    """Render one UTC timestamp with an explicit ``Z`` suffix."""
    current = datetime.now(UTC) if value is None else value
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("history timestamps must be timezone-aware")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")


def bounded_history_record(
    *,
    timestamp: str,
    action: str,
    decision: HistoryDecision,
    reason: str,
    bindings: list[tuple[str, str]],
    destination: dict[str, str | int],
    working_directory: str,
    requester_app: str | None,
) -> HistoryRecord:
    """Build a small record while retaining explicit truncation metadata."""
    truncated: list[str] = []
    escaped: list[str] = []
    stored_bindings: list[HistoryBinding] = []
    for index, (variable, reference) in enumerate(bindings[:MAX_STORED_BINDINGS]):
        bounded_reference, reference_truncated, reference_escaped = _bounded_text(
            reference, MAX_REFERENCE_BYTES
        )
        bounded_variable, variable_truncated, variable_escaped = _bounded_text(
            variable, MAX_VARIABLE_BYTES
        )
        if reference_truncated:
            truncated.append(f"bindings[{index}].reference")
        if reference_escaped:
            escaped.append(f"bindings[{index}].reference")
        if variable_truncated:
            truncated.append(f"bindings[{index}].variable")
        if variable_escaped:
            escaped.append(f"bindings[{index}].variable")
        stored_bindings.append(
            HistoryBinding(reference=bounded_reference, variable=bounded_variable)
        )

    bounded_destination = dict(destination)
    if action == "run":
        executable = destination.get("executable")
        if not isinstance(executable, str):
            raise HistoryError("ainv activity history record is invalid")
        bounded_executable, was_truncated, was_escaped = _bounded_text(
            executable, MAX_EXECUTABLE_BYTES
        )
        bounded_destination["executable"] = bounded_executable
        if was_truncated:
            truncated.append("destination.executable")
        if was_escaped:
            escaped.append("destination.executable")
    elif action == "set":
        path = destination.get("path")
        if not isinstance(path, str):
            raise HistoryError("ainv activity history record is invalid")
        bounded_path, was_truncated, was_escaped = _bounded_text(path, MAX_PATH_BYTES)
        bounded_destination["path"] = bounded_path
        if was_truncated:
            truncated.append("destination.path")
        if was_escaped:
            escaped.append("destination.path")
    else:
        raise HistoryError("ainv activity history record is invalid")

    bounded_working_directory, was_truncated, was_escaped = _bounded_text(
        working_directory, MAX_PATH_BYTES
    )
    if was_truncated:
        truncated.append("working_directory")
    if was_escaped:
        escaped.append("working_directory")

    bounded_requester: str | None = None
    if requester_app:
        bounded_requester, was_truncated, was_escaped = _bounded_text(
            requester_app, MAX_REQUESTER_BYTES
        )
        if was_truncated:
            truncated.append("requester_app")
        if was_escaped:
            escaped.append("requester_app")

    if not 1 <= len(bindings) <= MAX_BINDING_COUNT:
        raise HistoryError("ainv activity history record is invalid")
    argument_count = bounded_destination.get("argument_count")
    if action == "run" and (
        isinstance(argument_count, bool)
        or not isinstance(argument_count, int)
        or not 0 <= argument_count <= MAX_ARGUMENT_COUNT
    ):
        raise HistoryError("ainv activity history record is invalid")

    result = HistoryRecord(
        timestamp=timestamp,
        action=action,
        decision=decision,
        reason=reason,
        binding_count=len(bindings),
        bindings=tuple(stored_bindings),
        bindings_omitted=max(0, len(bindings) - len(stored_bindings)),
        destination=bounded_destination,
        working_directory=bounded_working_directory,
        requester_app=bounded_requester,
        truncated_fields=tuple(sorted(truncated)),
        escaped_fields=tuple(sorted(escaped)),
    )
    _serialize(result)
    return result


def append_history(record: HistoryRecord, path: Path | None = None) -> None:
    """Safely append one bounded record, rotating to one private backup."""
    target = history_path() if path is None else path
    contents = _serialize(record)
    directory_fd = _open_history_directory(target.parent, create=True)
    try:
        _acquire_directory_lock(directory_fd, fcntl.LOCK_EX)
        current = _entry_stat(directory_fd, target.name)
        backup_name = target.name + _BACKUP_SUFFIX
        backup = _entry_stat(directory_fd, backup_name)
        if current is not None:
            _validate_history_file(current)
        if backup is not None:
            _validate_history_file(backup)

        # Reserve one byte for repairing a partial final JSONL line. Slightly early
        # rotation is preferable to allowing a corrupt tail to absorb a new event.
        if (
            current is not None
            and current.st_size + len(contents) + 1 > MAX_HISTORY_BYTES
        ):
            if backup is not None:
                os.unlink(backup_name, dir_fd=directory_fd)
            os.replace(
                target.name,
                backup_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
            current = None

        file_fd = _open_history_file(directory_fd, target.name, current)
        try:
            opened = os.fstat(file_fd)
            if opened.st_size:
                final_byte = os.pread(file_fd, 1, opened.st_size - 1)
                if final_byte != b"\n":
                    _write_all(file_fd, b"\n")
            _write_all(file_fd, contents)
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        os.fsync(directory_fd)
    except (OSError, HistoryError):
        raise HistoryError("could not write ainv activity history") from None
    finally:
        os.close(directory_fd)


def read_history(*, limit: int = 20, path: Path | None = None) -> HistoryReadResult:
    """Read valid newest records, counting malformed lines without echoing them."""
    if limit < 1:
        raise ValueError("history limit must be positive")
    target = history_path() if path is None else path
    try:
        directory_fd = _open_history_directory(target.parent, create=False)
    except FileNotFoundError:
        return HistoryReadResult(records=())
    records: list[HistoryRecord] = []
    invalid_record_count = 0
    try:
        _acquire_directory_lock(directory_fd, fcntl.LOCK_SH)
        for name in (target.name + _BACKUP_SUFFIX, target.name):
            entry = _entry_stat(directory_fd, name)
            if entry is None:
                continue
            _validate_history_file(entry)
            file_records, invalid_count = _read_file(directory_fd, name, entry)
            records.extend(file_records)
            invalid_record_count += invalid_count
    except (OSError, HistoryError):
        raise HistoryError("could not read ainv activity history") from None
    finally:
        os.close(directory_fd)
    return HistoryReadResult(
        records=tuple(records[-limit:]),
        invalid_record_count=invalid_record_count,
    )


def _acquire_directory_lock(directory_fd: int, mode: int) -> None:
    """Acquire a nonblocking lock with a bounded seven-millisecond retry budget."""
    for delay in (*_LOCK_RETRY_DELAYS_SECONDS, None):
        try:
            _flock(directory_fd, mode | fcntl.LOCK_NB)
            return
        except OSError as error:
            if error.errno not in _LOCK_CONTENTION_ERRNOS or delay is None:
                raise
            _sleep(delay)


def _serialize(record: HistoryRecord) -> bytes:
    try:
        contents = (
            json.dumps(
                record.to_dict(),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8", "strict")
            + b"\n"
        )
    except (TypeError, UnicodeEncodeError, ValueError):
        raise HistoryError("ainv activity history record is invalid") from None
    if len(contents) > MAX_RECORD_BYTES:
        raise HistoryError("ainv activity history record is too large")
    _parse_record(contents)
    return contents


def _open_history_directory(directory: Path, *, create: bool) -> int:
    if create:
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            raise HistoryError("could not prepare ainv activity history") from None
    try:
        before = directory.lstat()
    except FileNotFoundError:
        raise
    except OSError:
        raise HistoryError("could not inspect ainv activity history") from None
    _validate_history_directory(before)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd: int | None = None
    try:
        directory_fd = os.open(directory, flags)
        after = os.fstat(directory_fd)
        _validate_history_directory(after)
    except (OSError, HistoryError):
        if directory_fd is not None:
            os.close(directory_fd)
        raise HistoryError("could not open ainv activity history safely") from None
    assert directory_fd is not None
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        os.close(directory_fd)
        raise HistoryError("ainv activity history directory is unsafe")
    return directory_fd


def _open_history_file(
    directory_fd: int, name: str, existing: os.stat_result | None
) -> int:
    flags = os.O_RDWR | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if existing is None:
        flags |= os.O_CREAT | os.O_EXCL
    file_fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        opened = os.fstat(file_fd)
        _validate_history_file(opened)
        if existing is not None and (existing.st_dev, existing.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise HistoryError("ainv activity history file changed while opening")
    except (OSError, HistoryError):
        os.close(file_fd)
        raise
    return file_fd


def _read_file(
    directory_fd: int, name: str, expected: os.stat_result
) -> tuple[list[HistoryRecord], int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    file_fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(file_fd)
        _validate_history_file(opened)
        if (expected.st_dev, expected.st_ino) != (opened.st_dev, opened.st_ino):
            raise HistoryError("ainv activity history file changed while opening")
        # Do not allocate attacker-sized private files. Treat one oversized file
        # as one invalid segment so a valid rotated/current peer remains readable.
        if opened.st_size > MAX_HISTORY_BYTES:
            return [], 1
        contents = bytearray()
        while len(contents) <= MAX_HISTORY_BYTES:
            chunk = os.read(
                file_fd, min(64 * 1024, MAX_HISTORY_BYTES + 1 - len(contents))
            )
            if not chunk:
                break
            contents.extend(chunk)
        if len(contents) > MAX_HISTORY_BYTES:
            return [], 1
    finally:
        os.close(file_fd)

    records: list[HistoryRecord] = []
    invalid_record_count = 0
    for line in contents.splitlines(keepends=True):
        if len(line) > MAX_RECORD_BYTES or not line.endswith(b"\n"):
            invalid_record_count += 1
            continue
        try:
            records.append(_parse_record(line))
        except HistoryError:
            invalid_record_count += 1
    return records, invalid_record_count


def _parse_record(contents: bytes) -> HistoryRecord:
    if not contents.endswith(b"\n"):
        raise HistoryError("ainv activity history is malformed")

    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(
            contents.decode("utf-8", "strict"),
            object_pairs_hook=object_from_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise HistoryError("ainv activity history is malformed") from None
    expected_keys = {
        "record_version",
        "timestamp",
        "action",
        "decision",
        "reason",
        "binding_count",
        "bindings",
        "bindings_omitted",
        "destination",
        "working_directory",
        "requester_app",
        "truncated_fields",
        "escaped_fields",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise HistoryError("ainv activity history is malformed")
    if (
        isinstance(document["record_version"], bool)
        or document["record_version"] != RECORD_VERSION
    ):
        raise HistoryError("ainv activity history version is unsupported")

    timestamp = document["timestamp"]
    action = document["action"]
    reason = document["reason"]
    working_directory = document["working_directory"]
    requester_app = document["requester_app"]
    if not all(
        isinstance(value, str)
        for value in (timestamp, action, reason, working_directory)
    ):
        raise HistoryError("ainv activity history is malformed")
    if not _fits(timestamp, _MAX_TIMESTAMP_BYTES) or not timestamp.endswith("Z"):
        raise HistoryError("ainv activity history is malformed")
    if action not in {"run", "set"} or not _fits(action, _MAX_ACTION_BYTES):
        raise HistoryError("ainv activity history is malformed")
    if not reason or not _fits(reason, _MAX_REASON_BYTES):
        raise HistoryError("ainv activity history is malformed")
    if not working_directory or not _fits(working_directory, MAX_PATH_BYTES):
        raise HistoryError("ainv activity history is malformed")
    if requester_app is not None and (
        not isinstance(requester_app, str)
        or not requester_app
        or not _fits(requester_app, MAX_REQUESTER_BYTES)
    ):
        raise HistoryError("ainv activity history is malformed")
    try:
        parsed_time = datetime.fromisoformat(timestamp)
    except ValueError:
        raise HistoryError("ainv activity history is malformed") from None
    if (
        parsed_time.tzinfo is None
        or parsed_time.utcoffset() is None
        or utc_timestamp(parsed_time) != timestamp
    ):
        raise HistoryError("ainv activity history is malformed")
    try:
        decision = HistoryDecision(document["decision"])
    except (TypeError, ValueError):
        raise HistoryError("ainv activity history is malformed") from None
    valid_reasons = {
        HistoryDecision.ALLOWED: {"user_allowed"},
        HistoryDecision.NOT_REQUESTED: {"approval_disabled"},
        HistoryDecision.DENIED: {"user_denied"},
        HistoryDecision.ERROR: {
            "approval_unavailable",
            "interactive_input_disabled",
            "too_many_bindings",
            "working_directory_unavailable",
        },
    }
    if reason not in valid_reasons[decision]:
        raise HistoryError("ainv activity history is malformed")

    binding_count = document["binding_count"]
    bindings_omitted = document["bindings_omitted"]
    if (
        isinstance(binding_count, bool)
        or not isinstance(binding_count, int)
        or not 1 <= binding_count <= MAX_BINDING_COUNT
        or isinstance(bindings_omitted, bool)
        or not isinstance(bindings_omitted, int)
        or not 0 <= bindings_omitted <= MAX_BINDING_COUNT
    ):
        raise HistoryError("ainv activity history is malformed")
    raw_bindings = document["bindings"]
    if (
        not isinstance(raw_bindings, list)
        or not raw_bindings
        or len(raw_bindings) > MAX_STORED_BINDINGS
        or binding_count != len(raw_bindings) + bindings_omitted
    ):
        raise HistoryError("ainv activity history is malformed")
    bindings: list[HistoryBinding] = []
    for item in raw_bindings:
        if (
            not isinstance(item, dict)
            or set(item) != {"reference", "variable"}
            or not isinstance(item["reference"], str)
            or not isinstance(item["variable"], str)
            or not item["reference"]
            or not item["variable"]
            or not _fits(item["reference"], MAX_REFERENCE_BYTES)
            or not _fits(item["variable"], MAX_VARIABLE_BYTES)
        ):
            raise HistoryError("ainv activity history is malformed")
        bindings.append(HistoryBinding(item["reference"], item["variable"]))

    destination = document["destination"]
    if not isinstance(destination, dict):
        raise HistoryError("ainv activity history is malformed")
    if action == "run":
        argument_count = destination.get("argument_count")
        executable = destination.get("executable")
        if (
            set(destination) != {"kind", "executable", "argument_count"}
            or destination["kind"] != "command"
            or not isinstance(executable, str)
            or not executable
            or not _fits(executable, MAX_EXECUTABLE_BYTES)
            or isinstance(argument_count, bool)
            or not isinstance(argument_count, int)
            or not 0 <= argument_count <= MAX_ARGUMENT_COUNT
        ):
            raise HistoryError("ainv activity history is malformed")
    else:
        path = destination.get("path")
        if (
            set(destination) != {"kind", "path"}
            or destination["kind"] != "dotenv_file"
            or not isinstance(path, str)
            or not path
            or not _fits(path, MAX_PATH_BYTES)
        ):
            raise HistoryError("ainv activity history is malformed")

    raw_truncated_fields = document["truncated_fields"]
    raw_escaped_fields = document["escaped_fields"]
    allowed_transformed_fields = {
        "destination.executable" if action == "run" else "destination.path",
        "requester_app",
        "working_directory",
        *{
            f"bindings[{index}].{field}"
            for index in range(len(bindings))
            for field in ("reference", "variable")
        },
    }
    if (
        not isinstance(raw_truncated_fields, list)
        or any(not isinstance(item, str) for item in raw_truncated_fields)
        or raw_truncated_fields != sorted(set(raw_truncated_fields))
        or not set(raw_truncated_fields) <= allowed_transformed_fields
        or not isinstance(raw_escaped_fields, list)
        or any(not isinstance(item, str) for item in raw_escaped_fields)
        or raw_escaped_fields != sorted(set(raw_escaped_fields))
        or not set(raw_escaped_fields) <= allowed_transformed_fields
    ):
        raise HistoryError("ainv activity history is malformed")

    return HistoryRecord(
        timestamp=timestamp,
        action=action,
        decision=decision,
        reason=reason,
        binding_count=binding_count,
        bindings=tuple(bindings),
        bindings_omitted=bindings_omitted,
        destination=destination,
        working_directory=working_directory,
        requester_app=requester_app,
        truncated_fields=tuple(raw_truncated_fields),
        escaped_fields=tuple(raw_escaped_fields),
    )


def _bounded_text(value: str, max_bytes: int) -> tuple[str, bool, bool]:
    if not isinstance(value, str):
        raise HistoryError("ainv activity history record is invalid")
    try:
        encoded = value.encode("utf-8", "strict")
        was_escaped = False
    except UnicodeEncodeError:
        encoded = value.encode("utf-8", "backslashreplace")
        was_escaped = True
    if len(encoded) <= max_bytes:
        return encoded.decode("utf-8", "strict"), False, was_escaped
    marker = "…"
    prefix = encoded[: max_bytes - len(marker.encode())]
    while True:
        try:
            return prefix.decode("utf-8", "strict") + marker, True, was_escaped
        except UnicodeDecodeError:
            prefix = prefix[:-1]


def _fits(value: str, max_bytes: int) -> bool:
    try:
        return 0 < len(value.encode("utf-8", "strict")) <= max_bytes
    except UnicodeEncodeError:
        return False


def _entry_stat(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _validate_history_directory(directory_stat: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or stat.S_ISLNK(directory_stat.st_mode)
        or directory_stat.st_uid != os.getuid()
        or stat.S_IMODE(directory_stat.st_mode) & 0o077
    ):
        raise HistoryError("ainv activity history directory is unsafe")


def _validate_history_file(file_stat: os.stat_result) -> None:
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or stat.S_ISLNK(file_stat.st_mode)
        or file_stat.st_nlink != 1
        or file_stat.st_uid != os.getuid()
        or stat.S_IMODE(file_stat.st_mode) & 0o077
    ):
        raise HistoryError("ainv activity history file is unsafe")


def _write_all(fd: int, contents: bytes) -> None:
    view = memoryview(contents)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("could not write history")
        view = view[written:]
