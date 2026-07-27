from __future__ import annotations

import errno
import json
import os
import pty
import select
import signal
import sys
import termios
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from ainv.cli import _prompt_new_secret, app
from ainv.models import (
    CredentialMetadata,
    ProviderCapability,
    ProviderState,
    ProviderStatus,
    Secret,
)

runner = CliRunner()
CANARY = "ainv-test-canary-4f91"


@dataclass
class FakeProvider:
    matches: list[CredentialMetadata]
    value: bytes = CANARY.encode()

    name = "keychain"
    capabilities = frozenset({ProviderCapability.SEARCH, ProviderCapability.RESOLVE})

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            "keychain", ProviderState.READY, capabilities=self.capabilities
        )

    def search(self, query: str, *, limit: int = 20) -> list[CredentialMetadata]:
        return self.matches[:limit]

    def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
        return Secret(self.value)


class FakeCreator(FakeProvider):
    capabilities = FakeProvider.capabilities | {ProviderCapability.CREATE}
    created_secret: bytes | None = None

    def create(
        self,
        service: str,
        *,
        account: str,
        secret: Secret,
        label: str | None = None,
        no_input: bool = False,
    ) -> CredentialMetadata:
        self.created_secret = secret.reveal()
        return CredentialMetadata(
            reference="keychain://v1/item/bmV3LWl0ZW0",
            provider="keychain",
            name=service,
            account=account,
            label=label or service,
            kind="generic-password",
            modified_at=None,
            identifier=f"keychain:{service}@{account}",
        )


def metadata(
    *,
    label: str = "Synthetic credential",
    reference: str = "keychain://v1/item/c3ludGhldGlj",
    identifier: str = "keychain:OPENAI_API_KEY@personal",
) -> CredentialMetadata:
    return CredentialMetadata(
        reference=reference,
        provider="keychain",
        name="OPENAI_API_KEY",
        account="personal",
        label=label,
        kind="generic-password",
        modified_at=None,
        identifier=identifier,
    )


def install_provider(monkeypatch: pytest.MonkeyPatch, provider: FakeProvider) -> None:
    monkeypatch.setattr("ainv.cli._get_provider", lambda name: provider)


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == "ainv 0.2.0\n"


def test_no_args_shows_help() -> None:
    result = runner.invoke(app)

    assert result.exit_code == 0
    assert "Deliver credentials from providers" in result.stdout


def test_providers_renders_rounded_table(monkeypatch: pytest.MonkeyPatch) -> None:
    install_provider(monkeypatch, FakeCreator([]))

    result = runner.invoke(app, ["providers"])

    assert result.exit_code == 0
    assert "╭" in result.stdout
    assert "╰" in result.stdout
    assert "Provider" in result.stdout
    assert "Status" in result.stdout
    assert "create, resolve, search" in result.stdout


def test_find_json_returns_complete_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "keychain://v1/item/" + "a" * 64
    install_provider(monkeypatch, FakeProvider([metadata(reference=reference)]))

    result = runner.invoke(app, ["find", "openai", "--json"])

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["schema_version"] == 2
    assert document["matches"][0]["name"] == "OPENAI_API_KEY"
    assert document["matches"][0]["id"] == "keychain:OPENAI_API_KEY@personal"
    assert document["matches"][0]["ref"] == reference
    assert CANARY not in result.stdout


def test_find_renders_readable_credential_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_provider(monkeypatch, FakeProvider([metadata()]))

    result = runner.invoke(app, ["find", "openai"])

    assert result.exit_code == 0
    assert "╭" in result.stdout
    assert "╰" in result.stdout
    assert "Credential ID" in result.stdout
    assert "Provider" in result.stdout
    assert "keychain:OPENAI_API_KEY@personal" in result.stdout
    assert "Use --json" not in result.stdout


def test_find_abbreviates_legacy_reference_and_points_to_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "keychain://v1/item/" + "a" * 48 + "tailend8"
    item = metadata(reference=reference)
    item = CredentialMetadata(
        reference=item.reference,
        provider=item.provider,
        name=item.name,
        account=item.account,
        label=item.label,
        kind=item.kind,
        modified_at=item.modified_at,
    )
    install_provider(monkeypatch, FakeProvider([item]))

    result = runner.invoke(app, ["find", "openai"])

    assert result.exit_code == 0
    assert "keychain://v1/item/aaaa...tailend8" in result.stdout
    assert reference not in result.stdout
    assert (
        "Use --json for complete credential IDs and legacy references." in result.stdout
    )


def test_find_abbreviates_long_readable_id_with_recovery_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identifier = "keychain:OPENAI_API_KEY@" + "account-" * 8
    install_provider(monkeypatch, FakeProvider([metadata(identifier=identifier)]))

    result = runner.invoke(app, ["find", "openai"])

    assert result.exit_code == 0
    assert identifier not in result.stdout
    assert "..." in result.stdout
    assert (
        "Use --json for complete credential IDs and legacy references." in result.stdout
    )


def test_find_sanitizes_terminal_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    install_provider(
        monkeypatch,
        FakeProvider(
            [metadata(label="[b]\n\x1b", identifier="keychain:TOKEN@bad\n\x1b")]
        ),
    )

    result = runner.invoke(app, ["find", "openai"])

    assert result.exit_code == 0
    assert "[b]\\n" in result.stdout
    assert "bad\\n\\x1b" in result.stdout
    assert "\x1b" not in result.stdout


def test_find_no_matches_has_distinct_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_provider(monkeypatch, FakeProvider([]))

    result = runner.invoke(app, ["find", "missing", "--json"])

    assert result.exit_code == 3
    assert json.loads(result.stdout)["matches"] == []


def test_add_uses_hidden_secret_and_outputs_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = FakeCreator([metadata()])
    install_provider(monkeypatch, provider)
    monkeypatch.setattr("ainv.cli._prompt_new_secret", lambda: Secret(CANARY.encode()))

    def must_not_construct_native_backend(*args: object, **kwargs: object) -> None:
        raise AssertionError("the real Keychain backend must not be constructed")

    monkeypatch.setattr(
        "ainv.providers.keychain.PyObjCSecurityBackend.__init__",
        must_not_construct_native_backend,
    )

    result = runner.invoke(
        app,
        [
            "add",
            "OPENAI_API_KEY",
            "--provider",
            "keychain",
            "--account",
            "personal",
        ],
    )

    assert result.exit_code == 0
    assert provider.created_secret == CANARY.encode()
    assert (
        "Credential ID (non-secret): keychain:OPENAI_API_KEY@personal" in result.stdout
    )
    assert CANARY not in result.stdout
    assert CANARY not in result.stderr


class TTY:
    def __init__(self) -> None:
        self.output = ""

    def isatty(self) -> bool:
        return True

    def write(self, value: str) -> int:
        self.output += value
        return len(value)

    def flush(self) -> None:
        pass


class NonTTY:
    def isatty(self) -> bool:
        return False


def test_hidden_prompt_reads_once_and_never_writes_canary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prompts: list[str] = []
    terminal = TTY()
    monkeypatch.setattr("ainv.cli.sys.stdin", TTY())
    monkeypatch.setattr("ainv.cli.sys.stderr", terminal)
    monkeypatch.setattr(
        "ainv.cli._read_hidden_input",
        lambda prompt: prompts.append(prompt) or CANARY,
    )

    secret = _prompt_new_secret()

    captured = capsys.readouterr()
    assert secret.reveal() == CANARY.encode()
    assert prompts == ["Secret value: "]
    assert CANARY not in captured.out
    assert CANARY not in captured.err
    assert CANARY not in terminal.output


def test_hidden_prompt_rejects_empty_input(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    terminal = TTY()
    monkeypatch.setattr("ainv.cli.sys.stdin", TTY())
    monkeypatch.setattr("ainv.cli.sys.stderr", terminal)
    monkeypatch.setattr("ainv.cli._read_hidden_input", lambda prompt: "")

    with pytest.raises(typer.Exit) as error:
        _prompt_new_secret()

    captured = capsys.readouterr()
    assert error.value.exit_code == 2
    assert CANARY not in captured.out
    assert CANARY not in captured.err
    assert CANARY not in terminal.output


def test_hidden_prompt_rejects_noninteractive_stdin_before_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ainv.cli.sys.stdin", NonTTY())
    monkeypatch.setattr("ainv.cli.sys.stderr", TTY())

    def must_not_read(prompt: str) -> str:
        raise AssertionError("hidden input must not be read from a pipe")

    monkeypatch.setattr("ainv.cli._read_hidden_input", must_not_read)

    with pytest.raises(typer.Exit) as error:
        _prompt_new_secret()

    assert error.value.exit_code == 5


def test_hidden_prompt_fails_closed_when_echo_cannot_be_disabled(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    terminal = TTY()
    closed: list[int] = []
    monkeypatch.setattr("ainv.cli.sys.stdin", TTY())
    monkeypatch.setattr("ainv.cli.sys.stderr", terminal)
    monkeypatch.setattr("ainv.cli.os.open", lambda path, flags: 42)
    monkeypatch.setattr("ainv.cli.os.close", closed.append)
    monkeypatch.setattr("ainv.cli.termios.tcgetattr", lambda fd: [0, 0, 0, 0])

    def cannot_disable_echo(fd: int, when: int, attributes: list[int]) -> None:
        raise termios.error("terminal settings unavailable")

    def must_not_read(fd: int) -> bytes:
        raise AssertionError("input must not be read with echo enabled")

    monkeypatch.setattr("ainv.cli.termios.tcsetattr", cannot_disable_echo)
    monkeypatch.setattr("ainv.cli._read_terminal_line", must_not_read)

    with pytest.raises(typer.Exit) as error:
        _prompt_new_secret()

    captured = capsys.readouterr()
    assert error.value.exit_code == 5
    assert closed == [42]
    assert CANARY not in captured.out
    assert CANARY not in captured.err
    assert CANARY not in terminal.output


def test_hidden_prompt_rejects_invalid_utf8(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    terminal = TTY()
    monkeypatch.setattr("ainv.cli.sys.stdin", TTY())
    monkeypatch.setattr("ainv.cli.sys.stderr", terminal)

    def invalid_utf8(prompt: str) -> str:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr("ainv.cli._read_hidden_input", invalid_utf8)

    with pytest.raises(typer.Exit) as error:
        _prompt_new_secret()

    captured = capsys.readouterr()
    assert error.value.exit_code == 7
    assert CANARY not in captured.out
    assert CANARY not in captured.err
    assert CANARY not in terminal.output


def _read_pty_until(fd: int, marker: bytes, timeout: float) -> bytearray:
    output = bytearray()
    deadline = time.monotonic() + timeout
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("hidden-input prompt did not arrive")
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        output.extend(chunk)
    return output


def _wait_for_pty_child(pid: int, fd: int, output: bytearray, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    while True:
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            while True:
                readable, _, _ = select.select([fd], [], [], 0)
                if not readable:
                    return status
                try:
                    chunk = os.read(fd, 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        return status
                    raise
                if not chunk:
                    return status
                output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("hidden-input child did not exit")
        readable, _, _ = select.select([fd], [], [], remaining)
        if readable:
            try:
                chunk = os.read(fd, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    continue
                raise
            if chunk:
                output.extend(chunk)


@pytest.mark.skipif(sys.platform == "win32", reason="PTYs require a POSIX terminal")
def test_hidden_prompt_does_not_echo_pasted_canary_in_a_pty() -> None:
    canary = b"AINV_PTY_SYNTHETIC_CANARY_8D31"
    pid, fd = pty.fork()
    if pid == 0:
        try:
            sys.stdin = os.fdopen(os.dup(0), "r", encoding="utf-8")
            sys.stderr = os.fdopen(os.dup(2), "w", encoding="utf-8")
            secret = _prompt_new_secret()
        except (EOFError, OSError, UnicodeError, termios.error, typer.Exit):
            os._exit(1)
        os._exit(0 if secret.reveal() == canary else 1)

    reaped = False
    try:
        output = _read_pty_until(fd, b"Secret value: ", timeout=5)
        assert b"Secret value: " in output
        os.write(fd, canary + b"\n")
        status = _wait_for_pty_child(pid, fd, output, timeout=5)
        reaped = True

        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 0
        assert canary not in output
    finally:
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        os.close(fd)


def test_add_unknown_provider_fails_before_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_prompt() -> Secret:
        raise AssertionError("prompt must not run")

    monkeypatch.setattr("ainv.cli._prompt_new_secret", must_not_prompt)

    result = runner.invoke(
        app,
        [
            "add",
            "TOKEN",
            "--provider",
            "missing",
            "--account",
            "personal",
        ],
    )

    assert result.exit_code == 4
    assert result.stdout == ""
    assert "credential provider is unavailable" in result.stderr


def test_add_no_input_fails_before_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = FakeCreator([metadata()])
    install_provider(monkeypatch, provider)

    def must_not_prompt() -> Secret:
        raise AssertionError("prompt must not run")

    monkeypatch.setattr("ainv.cli._prompt_new_secret", must_not_prompt)

    result = runner.invoke(
        app,
        [
            "--no-input",
            "add",
            "TOKEN",
            "--provider",
            "keychain",
            "--account",
            "personal",
        ],
    )

    assert result.exit_code == 5
    assert provider.created_secret is None


def test_set_writes_canary_only_to_ignored_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    install_provider(monkeypatch, FakeProvider([metadata()]))
    destination = tmp_path / ".env"

    result = runner.invoke(
        app,
        [
            "set",
            "keychain://v1/item/c3ludGhldGlj",
            "--as",
            "OPENAI_API_KEY",
            "--file",
            str(destination),
        ],
    )

    assert result.exit_code == 0
    assert destination.read_text() == f"OPENAI_API_KEY={CANARY}\n"
    assert CANARY not in result.stdout
    assert CANARY not in result.stderr


def test_set_refuses_unignored_destination_before_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)

    class MustNotResolve(FakeProvider):
        def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
            raise AssertionError("resolution must happen after destination validation")

    install_provider(monkeypatch, MustNotResolve([metadata()]))
    destination = tmp_path / ".env"

    result = runner.invoke(
        app,
        [
            "set",
            "keychain://v1/item/c3ludGhldGlj",
            "--as",
            "TOKEN",
            "--file",
            str(destination),
        ],
    )

    assert result.exit_code == 6
    assert not destination.exists()


def test_set_rechecks_git_policy_after_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    ignore_file = tmp_path / ".gitignore"
    ignore_file.write_text(".env\n")

    class ChangesGitPolicy(FakeProvider):
        def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
            ignore_file.write_text("")
            return Secret(self.value)

    install_provider(monkeypatch, ChangesGitPolicy([metadata()]))
    destination = tmp_path / ".env"

    result = runner.invoke(
        app,
        [
            "set",
            "keychain://v1/item/c3ludGhldGlj",
            "--as",
            "TOKEN",
            "--file",
            str(destination),
        ],
    )

    assert result.exit_code == 6
    assert not destination.exists()
    assert CANARY not in result.stdout
    assert CANARY not in result.stderr


def test_run_injects_without_rendering_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_provider(monkeypatch, FakeProvider([metadata()]))
    captured: dict[str, object] = {}

    def fake_exec(file: str, args: list[str], env: dict[str, str]) -> None:
        captured.update(file=file, args=args, value=env["TOKEN"])
        raise RuntimeError("exec intercepted")

    monkeypatch.setattr(os, "execvpe", fake_exec)

    with pytest.raises(RuntimeError, match="exec intercepted"):
        runner.invoke(
            app,
            [
                "run",
                "TOKEN=keychain://v1/item/c3ludGhldGlj",
                "--",
                "example-command",
            ],
            catch_exceptions=False,
        )

    assert captured == {
        "file": "example-command",
        "args": ["example-command"],
        "value": CANARY,
    }


def test_run_infers_variable_from_readable_credential_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_provider(monkeypatch, FakeProvider([metadata()]))
    captured: dict[str, str] = {}

    def fake_exec(file: str, args: list[str], env: dict[str, str]) -> None:
        captured["value"] = env["OPENAI_API_KEY"]
        raise RuntimeError("exec intercepted")

    monkeypatch.setattr(os, "execvpe", fake_exec)

    with pytest.raises(RuntimeError, match="exec intercepted"):
        runner.invoke(
            app,
            [
                "run",
                "keychain:OPENAI_API_KEY@personal",
                "--",
                "example-command",
            ],
            catch_exceptions=False,
        )

    assert captured == {"value": CANARY}


@pytest.mark.parametrize("variable", ["PATH", "NODE_OPTIONS", "DYLD_INSERT_LIBRARIES"])
def test_inference_refuses_execution_sensitive_variables(
    variable: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_provider(monkeypatch, FakeProvider([metadata()]))

    result = runner.invoke(
        app,
        ["run", f"keychain:{variable}@personal", "--", "example-command"],
    )

    assert result.exit_code == 2
    assert "execution-sensitive variable requires an explicit NAME=" in result.stderr
    assert CANARY not in result.stdout
    assert CANARY not in result.stderr


def test_duplicate_inferred_names_fail_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MustNotResolve(FakeProvider):
        def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
            raise AssertionError("duplicate bindings must fail before resolution")

    install_provider(monkeypatch, MustNotResolve([metadata()]))

    result = runner.invoke(
        app,
        [
            "run",
            "keychain:TOKEN@personal",
            "keychain:TOKEN@work",
            "--",
            "example-command",
        ],
    )

    assert result.exit_code == 2
    assert "duplicate destination environment variable" in result.stderr


def test_run_resolves_all_bindings_before_starting_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailsSecond(FakeProvider):
        calls = 0

        def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
            self.calls += 1
            if self.calls == 2:
                from ainv.errors import CredentialNotFoundError

                raise CredentialNotFoundError()
            return Secret(CANARY.encode())

    provider = FailsSecond([metadata()])
    install_provider(monkeypatch, provider)

    def must_not_exec(file: str, args: list[str], env: dict[str, str]) -> None:
        raise AssertionError("command must not start after partial resolution")

    monkeypatch.setattr(os, "execvpe", must_not_exec)

    result = runner.invoke(
        app,
        [
            "run",
            "FIRST=keychain:FIRST@personal",
            "SECOND=keychain:SECOND@personal",
            "--",
            "example-command",
        ],
    )

    assert result.exit_code == 3
    assert provider.calls == 2
    assert CANARY not in result.stdout
    assert CANARY not in result.stderr


def test_set_infers_names_and_writes_multiple_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")

    class MappingProvider(FakeProvider):
        def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
            return Secret(b"first" if ":FIRST@" in reference else b"second")

    install_provider(monkeypatch, MappingProvider([metadata()]))
    destination = tmp_path / ".env"

    result = runner.invoke(
        app,
        [
            "set",
            "keychain:FIRST@personal",
            "SECOND_VALUE=keychain:SECOND@personal",
            "--file",
            str(destination),
        ],
    )

    assert result.exit_code == 0
    assert destination.read_text() == "FIRST=first\nSECOND_VALUE=second\n"
    assert "Set FIRST, SECOND_VALUE" in result.stdout
    assert "first" not in result.stdout
    assert "second" not in result.stdout


def test_set_does_not_write_when_later_binding_cannot_be_materialized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    destination = tmp_path / ".env"
    original = "FIRST=\nSECOND=\n"
    destination.write_text(original)

    class InvalidSecond(FakeProvider):
        def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
            return Secret(b"valid" if ":FIRST@" in reference else b"invalid\nvalue")

    install_provider(monkeypatch, InvalidSecond([metadata()]))

    result = runner.invoke(
        app,
        [
            "set",
            "keychain:FIRST@personal",
            "keychain:SECOND@personal",
            "--file",
            str(destination),
        ],
    )

    assert result.exit_code == 7
    assert destination.read_text() == original
    assert "valid" not in result.stdout
    assert "invalid" not in result.stdout
    assert "invalid" not in result.stderr


def test_set_rechecks_populated_assignment_after_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    destination = tmp_path / ".env"
    destination.write_text("TOKEN=\n")

    class PopulatesDuringResolution(FakeProvider):
        def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
            destination.write_text("TOKEN=attacker\n")
            return Secret(CANARY.encode())

    install_provider(monkeypatch, PopulatesDuringResolution([metadata()]))

    result = runner.invoke(
        app,
        [
            "set",
            "keychain:TOKEN@personal",
            "--file",
            str(destination),
        ],
    )

    assert result.exit_code == 6
    assert "already has a value" in result.stderr
    assert destination.read_text() == "TOKEN=attacker\n"
    assert CANARY not in result.stdout
    assert CANARY not in result.stderr


def test_set_refuses_populated_value_before_resolution_and_force_replaces_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    destination = tmp_path / ".env"
    destination.write_text("TOKEN=old\n")

    class CountsResolution(FakeProvider):
        calls = 0

        def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
            self.calls += 1
            return super().resolve(reference, no_input=no_input)

    provider = CountsResolution([metadata()])
    install_provider(monkeypatch, provider)
    arguments = [
        "set",
        "TOKEN=keychain:TOKEN@personal",
        "--file",
        str(destination),
    ]

    refused = runner.invoke(app, arguments)

    assert refused.exit_code == 6
    assert "already has a value" in refused.stderr
    assert provider.calls == 0
    assert destination.read_text() == "TOKEN=old\n"

    replaced = runner.invoke(app, [*arguments, "--force"])

    assert replaced.exit_code == 0
    assert provider.calls == 1
    assert destination.read_text() == f"TOKEN={CANARY}\n"
    assert CANARY not in replaced.stdout
    assert CANARY not in replaced.stderr
