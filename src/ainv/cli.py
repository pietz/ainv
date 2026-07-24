"""Command-line interface for ainv."""

from __future__ import annotations

import getpass
import json
import os
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Annotated, Never

import typer

from ainv import __version__
from ainv.dotenv import (
    DotenvError,
    InvalidSecretValueError,
    mutate_dotenv,
    validate_dotenv_destination,
)
from ainv.errors import (
    CredentialNotFoundError,
    InvalidCredentialMetadataError,
    ProviderAccessDeniedError,
    ProviderError,
    ProviderLockedError,
    ProviderUnavailableError,
)
from ainv.git import (
    GitDestinationStatus,
    GitSafetyError,
    destination_status,
    enforce_destination_policy,
)
from ainv.models import CredentialMetadata, ProviderCapability, Secret
from ainv.providers.base import CredentialCreator, CredentialProvider
from ainv.providers.keychain import KeychainProvider, parse_persistent_reference
from ainv.providers.registry import ProviderRegistry

_PROVIDER_REGISTRY = ProviderRegistry()
_PROVIDER_REGISTRY.register(
    "keychain",
    KeychainProvider,
    reference_prefixes=("keychain://v1/item/",),
)

_SCHEMA_VERSION = 1

app = typer.Typer(
    name="ainv",
    help="Move secrets from credential providers without printing them.",
    invoke_without_command=True,
    no_args_is_help=False,
)


def version_callback(value: bool) -> None:
    """Print the installed version and exit."""
    if value:
        typer.echo(f"ainv {__version__}")
        raise typer.Exit()


@app.callback()
def cli(
    ctx: typer.Context,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = None,
    no_input: Annotated[
        bool,
        typer.Option(
            "--no-input",
            help="Fail instead of allowing authentication or approval prompts.",
        ),
    ] = False,
) -> None:
    """Move secrets from credential providers without printing them."""
    ctx.ensure_object(dict)
    ctx.obj["no_input"] = no_input
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command("providers")
def providers_command(
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit structured JSON.")
    ] = False,
) -> None:
    """Show available credential providers without accessing secret values."""
    statuses = [_get_provider(name).status() for name in _PROVIDER_REGISTRY.names()]
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "providers": [
                        {
                            "provider": status.provider,
                            "state": status.state.value,
                            "source": status.source,
                            "capabilities": sorted(
                                capability.value for capability in status.capabilities
                            ),
                        }
                        for status in statuses
                    ],
                },
                sort_keys=True,
            )
        )
        return
    typer.echo("PROVIDER  STATUS  SOURCE  CAPABILITIES")
    for status in statuses:
        capabilities = ",".join(
            sorted(capability.value for capability in status.capabilities)
        )
        typer.echo(
            f"{_terminal_safe(status.provider)}  "
            f"{_terminal_safe(status.state.value)}  "
            f"{_terminal_safe(status.source)}  "
            f"{_terminal_safe(capabilities)}"
        )


@app.command("find")
def find_command(
    query: Annotated[str, typer.Argument(help="Nonempty metadata search query.")],
    provider_name: Annotated[
        str, typer.Option("--provider", help="Credential provider to search.")
    ] = "keychain",
    limit: Annotated[
        int, typer.Option(min=1, max=100, help="Maximum number of matches.")
    ] = 20,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit structured JSON.")
    ] = False,
) -> None:
    """Search credential metadata without retrieving secret values."""
    if not query.strip():
        _fail("search query must not be empty", 2, as_json=as_json)
    try:
        matches = _get_provider(provider_name).search(query, limit=limit)
    except ProviderError as error:
        _fail_provider(error, as_json=as_json)

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "query": query,
                    "partial": False,
                    "matches": [_metadata_json(item) for item in matches],
                },
                sort_keys=True,
            )
        )
    else:
        if matches:
            typer.echo("REF  PROVIDER  SERVICE  ACCOUNT  LABEL")
        for item in matches:
            typer.echo(
                "  ".join(
                    _terminal_safe(value)
                    for value in (
                        item.reference,
                        item.provider,
                        item.name,
                        item.account,
                        item.label,
                    )
                )
            )
    if not matches:
        raise typer.Exit(3)


@app.command("add")
def add_command(
    ctx: typer.Context,
    service: Annotated[str, typer.Argument(help="Native credential service name.")],
    provider_name: Annotated[
        str, typer.Option("--provider", help="Credential provider to add to.")
    ],
    account: Annotated[
        str, typer.Option("--account", help="Native credential account or scope.")
    ],
    label: Annotated[
        str | None, typer.Option("--label", help="Optional human-readable label.")
    ] = None,
) -> None:
    """Add one credential through confirmed hidden human input."""
    if _no_input(ctx):
        _fail("adding a credential requires interactive human input", 5)
    try:
        provider = _get_provider(provider_name)
    except ProviderError as error:
        _fail_provider(error)
    if ProviderCapability.CREATE not in provider.capabilities or not isinstance(
        provider, CredentialCreator
    ):
        _fail("credential provider does not support adding credentials", 1)

    secret = _prompt_new_secret()
    try:
        metadata = provider.create(
            service,
            account=account,
            label=label,
            secret=secret,
            no_input=False,
        )
    except InvalidCredentialMetadataError as error:
        _fail(str(error), 2)
    except ProviderError as error:
        _fail_provider(error)

    typer.echo(
        f"Added {_terminal_safe(metadata.name)} to "
        f"{_terminal_safe(metadata.provider)} for account "
        f"{_terminal_safe(metadata.account)}."
    )
    typer.echo(f"Reference: {_terminal_safe(metadata.reference)}")


@app.command("set")
def set_command(
    ctx: typer.Context,
    reference: Annotated[str, typer.Argument(help="Canonical credential reference.")],
    variable: Annotated[
        str, typer.Option("--as", help="Destination environment-variable name.")
    ],
    file: Annotated[
        Path, typer.Option("--file", help="Dotenv destination file.")
    ] = Path(".env"),
    allow_unignored: Annotated[
        bool, typer.Option(help="Allow an untracked destination not ignored by Git.")
    ] = False,
    allow_tracked: Annotated[
        bool, typer.Option(help="Allow writing plaintext into a Git-tracked file.")
    ] = False,
) -> None:
    """Set one dotenv entry directly from a credential reference."""
    if str(file) == "-":
        _fail("dotenv destination must be a regular file", 6)
    try:
        validate_dotenv_destination(file, variable)
        git_status = destination_status(file)
        enforce_destination_policy(
            git_status,
            allow_tracked=allow_tracked,
            allow_unignored=allow_unignored,
        )
        secret = _provider_for_reference(reference).resolve(
            reference, no_input=_no_input(ctx)
        )
        value = _secret_text(secret, dotenv=True)
        git_status = destination_status(file)
        enforce_destination_policy(
            git_status,
            allow_tracked=allow_tracked,
            allow_unignored=allow_unignored,
        )
        mutate_dotenv(file, variable, value)
    except ProviderError as error:
        _fail_provider(error)
    except GitSafetyError as error:
        _fail(str(error), 6)
    except InvalidSecretValueError as error:
        _fail(str(error), 7)
    except DotenvError as error:
        _fail(str(error), 6)

    if git_status is GitDestinationStatus.OUTSIDE_WORKTREE:
        typer.echo(
            "Warning: destination contains plaintext credentials and is outside Git checks.",
            err=True,
        )
    typer.echo(
        f"Set {_terminal_safe(variable)} in {_terminal_safe(str(file))} "
        "from keychain (value hidden)."
    )


@app.command(
    "run",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def run_command(ctx: typer.Context) -> None:
    """Inject referenced credentials into one child process."""
    bindings, command = _parse_run_arguments(ctx.args)
    environment = os.environ.copy()
    resolved: dict[str, str] = {}
    try:
        provider_bindings = [
            (variable, reference, _provider_for_reference(reference))
            for variable, reference in bindings
        ]
        for variable, reference, provider in provider_bindings:
            secret = provider.resolve(reference, no_input=_no_input(ctx))
            resolved[variable] = _secret_text(secret, dotenv=False)
    except ProviderError as error:
        _fail_provider(error)
    except InvalidSecretValueError as error:
        _fail(str(error), 7)

    environment.update(resolved)
    try:
        os.execvpe(command[0], command, environment)
    except (OSError, ValueError):
        _fail("could not start child command", 1)


def _get_provider(name: str) -> CredentialProvider:
    return _PROVIDER_REGISTRY.get(name)


def _provider_for_reference(reference: str) -> CredentialProvider:
    provider_name = _PROVIDER_REGISTRY.provider_name_for_reference(reference)
    if provider_name == "keychain":
        parse_persistent_reference(reference)
    return _get_provider(provider_name)


def _parse_run_arguments(
    arguments: list[str],
) -> tuple[list[tuple[str, str]], list[str]]:
    bindings: list[tuple[str, str]] = []
    seen: set[str] = set()
    command_index = 0
    for command_index, argument in enumerate(arguments):
        if "=" not in argument:
            break
        variable, reference = argument.split("=", 1)
        from ainv.dotenv import validate_variable_name

        try:
            validate_variable_name(variable)
        except DotenvError as error:
            _fail(str(error), 2)
        if not reference:
            _fail("credential reference must not be empty", 2)
        if variable in seen:
            _fail("duplicate destination environment variable", 2)
        seen.add(variable)
        bindings.append((variable, reference))
    else:
        command_index = len(arguments)

    command = arguments[command_index:]
    if not bindings:
        _fail("run requires at least one NAME=REF binding", 2)
    if not command:
        _fail("run requires a child command", 2)
    return bindings, command


def _prompt_new_secret() -> Secret:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        _fail("adding a credential requires an interactive terminal", 5)
    try:
        value = getpass.getpass("Secret value: ")
        confirmation = getpass.getpass("Confirm secret value: ")
    except (EOFError, OSError):
        _fail("secure credential input was cancelled or unavailable", 5)
    if not value:
        _fail("secret value must not be empty", 2)
    if value != confirmation:
        _fail("secret values did not match", 2)
    try:
        return Secret(value.encode("utf-8", "strict"))
    except UnicodeEncodeError:
        _fail("secret value is not valid UTF-8 text", 7)


def _secret_text(secret: Secret, *, dotenv: bool) -> str:
    try:
        value = secret.reveal().decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise InvalidSecretValueError(
            "resolved value is not valid UTF-8 text"
        ) from None
    if "\x00" in value:
        raise InvalidSecretValueError("resolved value cannot contain a NUL byte")
    if dotenv and ("\r" in value or "\n" in value):
        raise InvalidSecretValueError("resolved value must be single-line")
    return value


def _metadata_json(metadata: CredentialMetadata) -> dict[str, str | None]:
    return {
        "ref": metadata.reference,
        "provider": metadata.provider,
        "name": metadata.name,
        "account": metadata.account,
        "label": metadata.label,
        "kind": metadata.kind,
        "modified_at": _isoformat(metadata.modified_at),
    }


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _terminal_safe(value: str | None) -> str:
    if value is None:
        return ""
    safe: list[str] = []
    for character in value:
        category = unicodedata.category(character)
        if category.startswith("C") or character in {"\t", "\n", "\r"}:
            safe.append(character.encode("unicode_escape").decode("ascii"))
        else:
            safe.append(character)
    return "".join(safe)


def _no_input(ctx: typer.Context) -> bool:
    root = ctx.find_root()
    return bool(root.obj.get("no_input", False))


def _fail_provider(error: ProviderError, *, as_json: bool = False) -> Never:
    if isinstance(error, CredentialNotFoundError):
        code = 3
    elif isinstance(error, (ProviderUnavailableError, ProviderLockedError)):
        code = 4
    elif isinstance(error, ProviderAccessDeniedError):
        code = 5
    else:
        code = 1
    _fail(str(error), code, as_json=as_json)


def _fail(message: str, code: int, *, as_json: bool = False) -> Never:
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "error": {"code": code, "message": message},
                },
                sort_keys=True,
            )
        )
    else:
        typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code)


def main() -> None:
    """Run the CLI."""
    app()
