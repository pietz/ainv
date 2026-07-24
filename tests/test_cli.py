from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ainv.cli import app
from ainv.models import (
    CredentialMetadata,
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

    def status(self) -> ProviderStatus:
        return ProviderStatus("keychain", ProviderState.READY)

    def search(self, query: str, *, limit: int = 20) -> list[CredentialMetadata]:
        return self.matches[:limit]

    def resolve(self, reference: str, *, no_input: bool = False) -> Secret:
        return Secret(self.value)


def metadata(*, label: str = "Synthetic credential") -> CredentialMetadata:
    return CredentialMetadata(
        reference="keychain://v1/item/c3ludGhldGlj",
        provider="keychain",
        name="OPENAI_API_KEY",
        account="personal",
        label=label,
        kind="generic-password",
        modified_at=None,
    )


def install_provider(monkeypatch: pytest.MonkeyPatch, provider: FakeProvider) -> None:
    monkeypatch.setattr("ainv.cli._get_provider", lambda name: provider)


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == "ainv 0.1.0\n"


def test_no_args_shows_help() -> None:
    result = runner.invoke(app)

    assert result.exit_code == 0
    assert "Move secrets from credential providers" in result.stdout


def test_find_json_returns_metadata_only(monkeypatch: pytest.MonkeyPatch) -> None:
    install_provider(monkeypatch, FakeProvider([metadata()]))

    result = runner.invoke(app, ["find", "openai", "--json"])

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["schema_version"] == 1
    assert document["matches"][0]["name"] == "OPENAI_API_KEY"
    assert CANARY not in result.stdout


def test_find_sanitizes_terminal_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    install_provider(monkeypatch, FakeProvider([metadata(label="safe\n\x1b[31mspoof")]))

    result = runner.invoke(app, ["find", "openai"])

    assert result.exit_code == 0
    assert "safe\\n\\x1b[31mspoof" in result.stdout
    assert "\x1b" not in result.stdout


def test_find_no_matches_has_distinct_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_provider(monkeypatch, FakeProvider([]))

    result = runner.invoke(app, ["find", "missing", "--json"])

    assert result.exit_code == 3
    assert json.loads(result.stdout)["matches"] == []


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
