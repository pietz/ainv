from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from ainv.dotenv import (
    DotenvFormatError,
    InvalidSecretValueError,
    InvalidVariableNameError,
    UnsafeDotenvFileError,
    encode_value,
    mutate_dotenv,
    validate_dotenv_destination,
)


def test_replaces_exact_assignment_and_preserves_unrelated_utf8_bytes(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "settings"
    original = (
        b"\xef\xbb\xbf# keep\r\n export TOKEN = old value\r\nTOKEN_EXTRA=unchanged\r\n"
    )
    destination.write_bytes(original)

    mutate_dotenv(destination, "TOKEN", "new=value")

    assert destination.read_bytes() == (
        b"\xef\xbb\xbf# keep\r\nTOKEN=new=value\r\nTOKEN_EXTRA=unchanged\r\n"
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (b"", b"TOKEN=value\n"),
        (b"OTHER=one\n", b"OTHER=one\nTOKEN=value\n"),
        (b"OTHER=one", b"OTHER=one\nTOKEN=value"),
        (b"OTHER=one\r\n", b"OTHER=one\r\nTOKEN=value\r\n"),
    ],
)
def test_appends_without_disturbing_existing_newline_convention(
    tmp_path: Path, source: bytes, expected: bytes
) -> None:
    destination = tmp_path / "dotenv"
    destination.write_bytes(source)

    mutate_dotenv(destination, "TOKEN", "value")

    assert destination.read_bytes() == expected


@pytest.mark.parametrize(
    "value",
    [
        "plain-token_123",
        "a=b",
        "",
        "https://example.test/path?one=1&two=2",
    ],
)
def test_safe_unquoted_value_encoding_is_exact(value: str) -> None:
    assert encode_value(value) == value


@pytest.mark.parametrize("value", ["has space", 'a"b', "a\\b", "# comment", "${OTHER}"])
def test_values_requiring_ambiguous_dotenv_quoting_are_rejected(value: str) -> None:
    with pytest.raises(InvalidSecretValueError):
        encode_value(value)


def test_replacement_canonicalizes_only_target_assignment(tmp_path: Path) -> None:
    destination = tmp_path / "dotenv"
    destination.write_text(
        "  export TOKEN = ignored # remains only when unrelated\nOTHER = keep\n"
    )

    mutate_dotenv(destination, "TOKEN", "canonical-value")

    assert destination.read_text() == "TOKEN=canonical-value\nOTHER = keep\n"


@pytest.mark.parametrize(
    "source", [b"TOKEN=one\nTOKEN=two\n", b"TOKEN\n", b" export TOKEN # no equals\n"]
)
def test_duplicate_or_malformed_target_fails_without_modifying_file(
    tmp_path: Path, source: bytes
) -> None:
    destination = tmp_path / "dotenv"
    destination.write_bytes(source)

    with pytest.raises(DotenvFormatError):
        mutate_dotenv(destination, "TOKEN", "synthetic-canary")

    assert destination.read_bytes() == source


def test_target_prefix_is_not_mistaken_for_assignment(tmp_path: Path) -> None:
    destination = tmp_path / "dotenv"
    destination.write_text("TOKEN_EXTRA=keep\n")

    mutate_dotenv(destination, "TOKEN", "value")

    assert destination.read_text() == "TOKEN_EXTRA=keep\nTOKEN=value\n"


def test_mixed_line_endings_are_rejected(tmp_path: Path) -> None:
    destination = tmp_path / "dotenv"
    original = b"ONE=1\r\nTWO=2\n"
    destination.write_bytes(original)

    with pytest.raises(DotenvFormatError):
        mutate_dotenv(destination, "TOKEN", "synthetic-canary")

    assert destination.read_bytes() == original


def test_preflight_validates_before_a_secret_is_resolved(tmp_path: Path) -> None:
    destination = tmp_path / "dotenv"
    destination.write_text("TOKEN=one\nTOKEN=two\n")

    with pytest.raises(DotenvFormatError):
        validate_dotenv_destination(destination, "TOKEN")


@pytest.mark.parametrize("source", [b"TOKEN=\x00", b"TOKEN=\xff"])
def test_invalid_destination_bytes_fail_without_modification(
    tmp_path: Path, source: bytes
) -> None:
    destination = tmp_path / "dotenv"
    destination.write_bytes(source)

    with pytest.raises(DotenvFormatError) as raised:
        mutate_dotenv(destination, "TOKEN", "synthetic-canary")

    assert "synthetic-canary" not in str(raised.value)
    assert destination.read_bytes() == source


@pytest.mark.parametrize(
    "value",
    [
        None,
        b"bytes",
        "secret-canary-7f\x00",
        "secret-canary-7f\n",
        "secret-canary-7f\r",
    ],
)
def test_invalid_resolved_values_are_rejected_without_leaking(
    tmp_path: Path, value: object
) -> None:
    destination = tmp_path / "dotenv"
    destination.write_text("OTHER=keep\n")
    canary = "secret-canary-7f"

    with pytest.raises(InvalidSecretValueError) as raised:
        mutate_dotenv(destination, "TOKEN", value)  # type: ignore[arg-type]

    assert canary not in str(raised.value)
    assert destination.read_text() == "OTHER=keep\n"


@pytest.mark.parametrize(
    "name", ["", "1TOKEN", "TOKEN-NAME", "TOKEN value", "TOKEN\nOTHER"]
)
def test_invalid_variable_names_are_rejected(tmp_path: Path, name: str) -> None:
    destination = tmp_path / "dotenv"

    with pytest.raises(InvalidVariableNameError):
        mutate_dotenv(destination, name, "value")

    assert not destination.exists()


def test_new_destination_is_private(tmp_path: Path) -> None:
    destination = tmp_path / "dotenv"

    mutate_dotenv(destination, "TOKEN", "value")

    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_existing_destination_removes_group_and_world_bits(tmp_path: Path) -> None:
    destination = tmp_path / "dotenv"
    destination.write_text("TOKEN=old\n")
    destination.chmod(0o754)

    mutate_dotenv(destination, "TOKEN", "value")

    assert stat.S_IMODE(destination.stat().st_mode) == 0o700


def test_rejects_symlink_hardlink_and_non_regular_destinations(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_text("TOKEN=old\n")
    symlink = tmp_path / "symlink"
    symlink.symlink_to(source)
    hardlink = tmp_path / "hardlink"
    os.link(source, hardlink)
    directory = tmp_path / "directory"
    directory.mkdir()

    for destination in (symlink, hardlink, directory):
        with pytest.raises(UnsafeDotenvFileError):
            mutate_dotenv(destination, "TOKEN", "synthetic-canary")

    assert source.read_text() == "TOKEN=old\n"
    assert not list(tmp_path.glob(".*.tmp"))


def test_parent_symlink_retarget_cannot_redirect_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    safe = tmp_path / "safe"
    other = tmp_path / "other"
    safe.mkdir()
    other.mkdir()
    (safe / ".env").write_text("TOKEN=old\n")
    (other / ".env").write_text("TOKEN=other\n")
    alias = tmp_path / "alias"
    alias.symlink_to(safe, target_is_directory=True)

    from ainv import dotenv

    original_create = dotenv._create_temporary

    def retarget(directory_fd: int, leaf: str) -> tuple[int, str]:
        alias.unlink()
        alias.symlink_to(other, target_is_directory=True)
        return original_create(directory_fd, leaf)

    monkeypatch.setattr(dotenv, "_create_temporary", retarget)

    mutate_dotenv(alias / ".env", "TOKEN", "synthetic-canary")

    assert (safe / ".env").read_text() == "TOKEN=synthetic-canary\n"
    assert (other / ".env").read_text() == "TOKEN=other\n"


def test_destination_replacement_during_mutation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / ".env"
    destination.write_text("TOKEN=old\n")

    from ainv import dotenv

    original_create = dotenv._create_temporary

    def replace_destination(directory_fd: int, leaf: str) -> tuple[int, str]:
        result = original_create(directory_fd, leaf)
        replacement = tmp_path / "replacement"
        replacement.write_text("TOKEN=attacker\n")
        os.replace(replacement, destination)
        return result

    monkeypatch.setattr(dotenv, "_create_temporary", replace_destination)

    with pytest.raises(UnsafeDotenvFileError):
        mutate_dotenv(destination, "TOKEN", "synthetic-canary")

    assert destination.read_text() == "TOKEN=attacker\n"
    assert not list(tmp_path.glob(".*.tmp"))


def test_atomic_failure_leaves_original_and_cleans_temporary_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "dotenv"
    original = b"TOKEN=old\n"
    destination.write_bytes(original)

    def fail_replace(source: str, target: str) -> None:
        raise OSError("injected failure")

    monkeypatch.setattr("ainv.dotenv.os.replace", fail_replace)

    with pytest.raises(Exception) as raised:
        mutate_dotenv(destination, "TOKEN", "synthetic-canary")

    assert "synthetic-canary" not in str(raised.value)
    assert destination.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp"))
