from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from ainv.config import (
    ApprovalMode,
    Config,
    ConfigurationError,
    config_path,
    load_config,
    save_config,
)


def test_config_path_ignores_home_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/tmp/agent-controlled-home")

    assert config_path() != Path(
        "/tmp/agent-controlled-home/Library/Application Support/ainv/config.toml"
    )


def test_missing_config_defaults_to_approval_off(tmp_path: Path) -> None:
    assert load_config(tmp_path / "config.toml") == Config()


def test_config_round_trip_is_private_and_atomic(tmp_path: Path) -> None:
    path = tmp_path / "ainv" / "config.toml"

    saved = save_config(Config(approval=ApprovalMode.ALWAYS), path)

    assert saved == path
    assert load_config(path).approval is ApprovalMode.ALWAYS
    assert path.read_text() == 'approval = "always"\n'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert not list(path.parent.glob(".*.tmp"))


def test_config_update_replaces_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "ainv" / "config.toml"
    save_config(Config(approval=ApprovalMode.ALWAYS), path)

    save_config(Config(approval=ApprovalMode.OFF), path)

    assert load_config(path).approval is ApprovalMode.OFF
    assert path.read_text() == 'approval = "off"\n'


@pytest.mark.parametrize(
    "contents",
    [
        b"not toml =",
        b'approval = "sometimes"\n',
        b"approval = true\n",
        b'approval = "off"\nunknown = true\n',
        b"\xff",
    ],
)
def test_invalid_configuration_fails_closed(tmp_path: Path, contents: bytes) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(contents)

    with pytest.raises(ConfigurationError):
        load_config(path)


def test_unsafe_config_directory_fails_closed_even_without_file(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "ainv"
    directory.mkdir()
    directory.chmod(0o777)
    path = directory / "config.toml"

    with pytest.raises(ConfigurationError, match="directory is unsafe"):
        load_config(path)

    path.write_text('approval = "always"\n')
    with pytest.raises(ConfigurationError, match="directory is unsafe"):
        load_config(path)


def test_unsafe_config_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('approval = "always"\n')
    path.chmod(0o622)

    with pytest.raises(ConfigurationError, match="unsafe"):
        load_config(path)


def test_symlink_config_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text('approval = "always"\n')
    path = tmp_path / "config.toml"
    path.symlink_to(target)

    with pytest.raises(ConfigurationError, match="unsafe"):
        load_config(path)


def test_hard_linked_config_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('approval = "always"\n')
    os.link(path, tmp_path / "other")

    with pytest.raises(ConfigurationError, match="unsafe"):
        load_config(path)
