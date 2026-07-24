"""Safe, minimal mutation of dotenv files.

This module deliberately recognizes only assignment *lines*.  It does not try to
interpret dotenv values, so comments and all non-target text remain byte-for-byte
unchanged.
"""

from __future__ import annotations

import codecs
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

try:  # ``fcntl`` is available on the supported Unix platforms.
    import fcntl
except ImportError:  # pragma: no cover - kept so importing the module is safe.
    fcntl = None  # type: ignore[assignment]


type Pathish = str | os.PathLike[str]

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
# Values in this set have no whitespace, comment, quote, escape, or expansion
# syntax in common dotenv implementations.  ``=`` is safe after the first
# assignment delimiter and is common in tokens and URLs.
_UNQUOTED_VALUE = re.compile(r"[A-Za-z0-9_@%+.,/:=\-]+\Z")
_ASSIGNMENT = re.compile(
    r"^(?P<indent>[ \t]*)(?:export[ \t]+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:[ \t]*)=(?P<value>.*)$"
)


class DotenvError(Exception):
    """Base class for errors that are safe to show to a user."""


class InvalidVariableNameError(DotenvError, ValueError):
    """The requested environment variable name is not portable."""


class InvalidSecretValueError(DotenvError, ValueError):
    """The resolved value cannot be represented safely as one dotenv line."""


class DotenvFormatError(DotenvError):
    """The destination is not a supported text dotenv file."""


class UnsafeDotenvFileError(DotenvError):
    """The destination is not a safe regular file to replace."""


def validate_variable_name(name: str) -> None:
    """Validate an environment variable name without accepting prefixes."""
    if not isinstance(name, str) or _NAME.fullmatch(name) is None:
        raise InvalidVariableNameError("invalid environment variable name")


def encode_value(value: str) -> str:
    """Return a conservative, single-line dotenv representation of *value*.

    The caller must pass a resolved string.  Errors deliberately do not repeat
    it, because callers commonly send these messages straight to stderr.
    """
    if not isinstance(value, str):
        raise InvalidSecretValueError("resolved value must be a string")
    if "\x00" in value:
        raise InvalidSecretValueError("resolved value cannot contain a NUL byte")
    if "\r" in value or "\n" in value:
        raise InvalidSecretValueError("resolved value must be single-line")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise InvalidSecretValueError("resolved value is not valid UTF-8 text") from None

    if _UNQUOTED_VALUE.fullmatch(value) is not None:
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def mutate_dotenv(path: Pathish, name: str, value: str) -> None:
    """Atomically insert or replace ``name`` in a dotenv file.

    Only regular, single-link files are accepted.  The destination directory is
    advisory-locked for the complete read-modify-replace operation, which
    serializes cooperating ``ainv`` writers even though a replacement changes
    the destination inode.
    """
    validate_variable_name(name)
    encoded_value = encode_value(value)  # Validate before opening the file.
    destination = Path(path)
    parent = destination.parent

    with _directory_lock(parent):
        original, original_stat = _read_destination(destination)
        replacement = _mutated_bytes(original, name, encoded_value)
        _atomic_replace(destination, replacement, original_stat)


# A descriptive alias makes the operation easy to discover for callers that
# think of this as an update rather than a mutation.
update_dotenv = mutate_dotenv


def _read_destination(path: Path) -> tuple[bytes, os.stat_result | None]:
    """Read one safe regular destination, or return an empty new destination."""
    try:
        listed = os.lstat(path)
    except FileNotFoundError:
        return b"", None
    except OSError:
        raise UnsafeDotenvFileError("could not inspect dotenv destination") from None

    _validate_regular_single_link(listed)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        raise UnsafeDotenvFileError("could not open dotenv destination safely") from None

    try:
        opened = os.fstat(fd)
        _validate_regular_single_link(opened)
        # Detect a path replacement between lstat and open.  The open file is
        # safe, but replacing a different path would violate caller intent.
        if (opened.st_dev, opened.st_ino) != (listed.st_dev, listed.st_ino):
            raise UnsafeDotenvFileError("dotenv destination changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as source:
            contents = source.read()
    except UnsafeDotenvFileError:
        raise
    except OSError:
        raise UnsafeDotenvFileError("could not read dotenv destination") from None
    finally:
        os.close(fd)

    if b"\x00" in contents:
        raise DotenvFormatError("dotenv destination contains a NUL byte")
    # Validate now, rather than allowing decoding errors to include a nearby
    # secret-bearing byte sequence in a default exception message.
    try:
        _decode_dotenv(contents)
    except UnicodeDecodeError:
        raise DotenvFormatError("dotenv destination is not valid UTF-8") from None
    return contents, opened


def _validate_regular_single_link(file_stat: os.stat_result) -> None:
    if not stat.S_ISREG(file_stat.st_mode):
        raise UnsafeDotenvFileError("dotenv destination must be a regular file")
    if file_stat.st_nlink != 1:
        raise UnsafeDotenvFileError("dotenv destination must not have hard links")


def _decode_dotenv(contents: bytes) -> tuple[str, bytes]:
    """Strictly decode UTF-8 while retaining an optional initial BOM."""
    bom = codecs.BOM_UTF8 if contents.startswith(codecs.BOM_UTF8) else b""
    return contents[len(bom) :].decode("utf-8", "strict"), bom


def _mutated_bytes(contents: bytes, name: str, encoded_value: str) -> bytes:
    try:
        text, bom = _decode_dotenv(contents)
    except UnicodeDecodeError:
        raise DotenvFormatError("dotenv destination is not valid UTF-8") from None

    matches: list[int] = []
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        body, _ending = _split_line_ending(line)
        assignment = _ASSIGNMENT.fullmatch(body)
        if assignment is not None and assignment.group("name") == name:
            matches.append(index)
        elif _is_malformed_target_line(body, name):
            raise DotenvFormatError("target assignment is malformed")

    if len(matches) > 1:
        raise DotenvFormatError("target assignment appears more than once")

    assignment_text = f"{name}={encoded_value}"
    if matches:
        index = matches[0]
        _body, ending = _split_line_ending(lines[index])
        lines[index] = assignment_text + ending
        output = "".join(lines)
    else:
        output = _append_assignment(text, assignment_text)

    try:
        return bom + output.encode("utf-8", "strict")
    except UnicodeEncodeError:
        # The source was decoded strictly, but this keeps a safe failure mode if
        # a future caller changes the text construction above.
        raise DotenvFormatError("dotenv destination cannot be encoded as UTF-8") from None


def _split_line_ending(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith(("\n", "\r")):
        return line[:-1], line[-1:]
    return line, ""


def _is_malformed_target_line(line: str, name: str) -> bool:
    """Whether a line names the target but is not a supported assignment."""
    prefix = r"[ \t]*(?:export[ \t]+)?" + re.escape(name)
    # The negative lookahead is essential: TARGET_SUFFIX is unrelated, not a
    # malformed spelling of TARGET.
    return re.match(prefix + r"(?![A-Za-z0-9_])", line) is not None


def _append_assignment(text: str, assignment: str) -> str:
    if not text:
        return assignment + "\n"
    line_ending = "\r\n" if "\r\n" in text else "\n"
    if text.endswith(("\n", "\r")):
        return text + assignment + line_ending
    # Do not merge the new assignment into an unterminated final line, but do
    # preserve the source's absence of a final newline.
    return text + line_ending + assignment


@contextmanager
def _directory_lock(directory: Path) -> Iterator[None]:
    """Hold an advisory lock on the destination directory when supported."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(directory, flags)
    except OSError:
        raise UnsafeDotenvFileError("could not open dotenv destination directory") from None

    try:
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                raise UnsafeDotenvFileError("could not lock dotenv destination directory") from None
        yield
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _atomic_replace(path: Path, contents: bytes, original: os.stat_result | None) -> None:
    """Write protected temporary contents, sync, and atomically replace *path*."""
    mode = 0o600 if original is None else stat.S_IMODE(original.st_mode) & 0o700
    temporary: str | None = None
    fd: int | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        os.fchmod(fd, mode)
        _write_all(fd, contents)
        os.fsync(fd)
        os.close(fd)
        fd = None

        _destination_is_unchanged(path, original)
        os.replace(temporary, path)
        temporary = None
        _sync_directory(path.parent)
    except DotenvError:
        raise
    except OSError:
        raise DotenvError("could not atomically replace dotenv destination") from None
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _write_all(fd: int, contents: bytes) -> None:
    view = memoryview(contents)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("could not write dotenv temporary file")
        view = view[written:]


def _destination_is_unchanged(path: Path, original: os.stat_result | None) -> None:
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        if original is None:
            return
        raise UnsafeDotenvFileError("dotenv destination changed during mutation") from None
    except OSError:
        raise UnsafeDotenvFileError("could not recheck dotenv destination") from None

    if original is None:
        raise UnsafeDotenvFileError("dotenv destination appeared during mutation")
    _validate_regular_single_link(current)
    if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
        raise UnsafeDotenvFileError("dotenv destination changed during mutation")


def _sync_directory(directory: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
