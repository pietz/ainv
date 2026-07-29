"""Small, fail-closed user configuration for ainv."""

from __future__ import annotations

import os
import pwd
import stat
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from secrets import token_hex

_MAX_CONFIG_BYTES = 64 * 1024


class ApprovalMode(StrEnum):
    """When ainv asks for human consent before credential delivery."""

    OFF = "off"
    ALWAYS = "always"


class HistoryMode(StrEnum):
    """Whether ainv records local value-free delivery activity."""

    ON = "on"
    OFF = "off"


@dataclass(frozen=True, slots=True)
class Config:
    """Supported user-controlled behavior."""

    approval: ApprovalMode = ApprovalMode.OFF
    history: HistoryMode = HistoryMode.ON


class ConfigurationError(Exception):
    """A configuration cannot be trusted or interpreted safely."""


def config_path() -> Path:
    """Return the fixed account-home path without trusting ``HOME``."""
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError):
        raise ConfigurationError(
            "could not determine the user configuration path"
        ) from None
    return home / "Library" / "Application Support" / "ainv" / "config.toml"


def load_config(path: Path | None = None) -> Config:
    """Load strict configuration, defaulting to approvals off when absent."""
    path = config_path() if path is None else path
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        try:
            directory_stat = path.parent.lstat()
        except FileNotFoundError:
            return Config()
        except OSError:
            raise ConfigurationError("could not inspect ainv configuration") from None
        _validate_config_directory(directory_stat)

        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        try:
            directory_fd = os.open(path.parent, directory_flags)
            opened_directory = os.fstat(directory_fd)
        except OSError:
            raise ConfigurationError("could not inspect ainv configuration") from None
        _validate_config_directory(opened_directory)
        if (directory_stat.st_dev, directory_stat.st_ino) != (
            opened_directory.st_dev,
            opened_directory.st_ino,
        ):
            raise ConfigurationError("ainv configuration directory is unsafe")

        try:
            file_stat = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return Config()
        except OSError:
            raise ConfigurationError("could not inspect ainv configuration") from None
        _validate_config_file(file_stat)

        file_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        try:
            file_fd = os.open(path.name, file_flags, dir_fd=directory_fd)
            opened_file = os.fstat(file_fd)
        except OSError:
            raise ConfigurationError("could not read ainv configuration") from None
        _validate_config_file(opened_file)
        if (file_stat.st_dev, file_stat.st_ino) != (
            opened_file.st_dev,
            opened_file.st_ino,
        ):
            raise ConfigurationError("ainv configuration file is unsafe")

        contents = bytearray()
        try:
            while len(contents) <= _MAX_CONFIG_BYTES:
                chunk = os.read(
                    file_fd,
                    min(16 * 1024, _MAX_CONFIG_BYTES + 1 - len(contents)),
                )
                if not chunk:
                    break
                contents.extend(chunk)
        except OSError:
            raise ConfigurationError("could not read ainv configuration") from None
        if len(contents) > _MAX_CONFIG_BYTES:
            raise ConfigurationError("ainv configuration is unexpectedly large")
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)
    try:
        document = tomllib.loads(contents.decode("utf-8", "strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise ConfigurationError("ainv configuration is invalid") from None
    if set(document) - {"approval", "history"}:
        raise ConfigurationError("ainv configuration contains unsupported settings")
    approval = document.get("approval", ApprovalMode.OFF.value)
    history = document.get("history", HistoryMode.ON.value)
    if not isinstance(approval, str):
        raise ConfigurationError("ainv approval setting is invalid")
    if not isinstance(history, str):
        raise ConfigurationError("ainv history setting is invalid")
    try:
        approval_mode = ApprovalMode(approval)
    except ValueError:
        raise ConfigurationError("ainv approval setting is invalid") from None
    try:
        history_mode = HistoryMode(history)
    except ValueError:
        raise ConfigurationError("ainv history setting is invalid") from None
    return Config(approval=approval_mode, history=history_mode)


def save_config(config: Config, path: Path | None = None) -> Path:
    """Atomically save configuration with user-only write permissions."""
    path = config_path() if path is None else path
    directory = path.parent
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_stat = directory.lstat()
    except OSError:
        raise ConfigurationError("could not prepare ainv configuration") from None
    _validate_config_directory(directory_stat)

    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError:
        raise ConfigurationError("could not inspect ainv configuration") from None
    if existing is not None:
        _validate_config_file(existing)

    lines = [f'approval = "{config.approval.value}"']
    if config.history is not HistoryMode.ON:
        lines.append(f'history = "{config.history.value}"')
    contents = ("\n".join(lines) + "\n").encode()
    temporary = f".{path.name}.{token_hex(8)}.tmp"
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        directory_fd = os.open(directory, flags)
        opened_directory = os.fstat(directory_fd)
        _validate_config_directory(opened_directory)
        if (directory_stat.st_dev, directory_stat.st_ino) != (
            opened_directory.st_dev,
            opened_directory.st_ino,
        ):
            raise ConfigurationError("ainv configuration directory is unsafe")
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        file_fd = os.open(temporary, create_flags, 0o600, dir_fd=directory_fd)
        _write_all(file_fd, contents)
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        os.replace(
            temporary,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary = ""
        os.fsync(directory_fd)
    except (OSError, ConfigurationError):
        raise ConfigurationError("could not save ainv configuration") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if temporary and directory_fd is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_fd is not None:
            os.close(directory_fd)
    return path


def _validate_config_directory(directory_stat: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or stat.S_ISLNK(directory_stat.st_mode)
        or directory_stat.st_uid != os.getuid()
        or stat.S_IMODE(directory_stat.st_mode) & 0o077
    ):
        raise ConfigurationError("ainv configuration directory is unsafe")


def _validate_config_file(file_stat: os.stat_result) -> None:
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or stat.S_ISLNK(file_stat.st_mode)
        or file_stat.st_nlink != 1
        or file_stat.st_uid != os.getuid()
        or stat.S_IMODE(file_stat.st_mode) & 0o077
    ):
        raise ConfigurationError("ainv configuration file is unsafe")


def _write_all(fd: int, contents: bytes) -> None:
    view = memoryview(contents)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("could not write configuration")
        view = view[written:]
