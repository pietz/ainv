"""Command-line interface for ainv."""

from __future__ import annotations

import json
import os
import shlex
import sys
import termios
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Annotated, Never

import typer
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ainv import __version__
from ainv.approval import (
    MAX_APPROVAL_BINDINGS,
    ApprovalBinding,
    ApprovalRequest,
    ApprovalUnavailableError,
    Approver,
    DeliveryAction,
    MacOSApprover,
    test_request,
)
from ainv.config import (
    ApprovalMode,
    Config,
    ConfigurationError,
    config_path,
    load_config,
    save_config,
)
from ainv.dotenv import (
    DotenvError,
    InvalidSecretValueError,
    mutate_dotenv_many,
    validate_dotenv_destinations,
    validate_variable_name,
)
from ainv.errors import (
    CredentialNotFoundError,
    InvalidCredentialMetadataError,
    InvalidReferenceError,
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
from ainv.providers.keychain import (
    KeychainProvider,
    parse_readable_reference,
    validate_keychain_reference,
)
from ainv.providers.registry import ProviderRegistry

_PROVIDER_REGISTRY = ProviderRegistry()
_PROVIDER_REGISTRY.register(
    "keychain",
    KeychainProvider,
    reference_prefixes=("keychain:",),
)

_SCHEMA_VERSION = 2
_EXECUTION_SENSITIVE_VARIABLES = frozenset(
    {
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GCONV_PATH",
        "HOME",
        "IFS",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "PATH",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYOPT",
        "SHELLOPTS",
        "TMPDIR",
        "_JAVA_OPTIONS",
    }
)
_EXECUTION_SENSITIVE_PREFIXES = ("DYLD_",)

app = typer.Typer(
    name="ainv",
    help="Deliver credentials from providers without printing their values.",
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
    """Deliver credentials from providers without printing their values."""
    ctx.ensure_object(dict)
    ctx.obj["no_input"] = no_input
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command("config")
def config_command(
    ctx: typer.Context,
    approval: Annotated[
        ApprovalMode | None,
        typer.Option(help="Set delivery approval behavior."),
    ] = None,
    test_popup: Annotated[
        bool,
        typer.Option("--test-popup", help="Show a harmless approval test."),
    ] = False,
) -> None:
    """Show or update human-consent configuration."""
    try:
        configuration_path = config_path()
        if approval is not None:
            save_config(Config(approval=approval), configuration_path)
        current = load_config(configuration_path)
    except ConfigurationError as error:
        _fail(str(error), 1)

    typer.echo(f"Approval: {current.approval.value}")
    typer.echo(f"Config: {_terminal_safe(str(configuration_path))}")
    if not test_popup:
        return
    if _no_input(ctx):
        _fail("approval popup requires interactive input", 5)
    try:
        allowed = _get_approver().approve(test_request())
    except ApprovalUnavailableError as error:
        _fail(str(error), 5)
    result = "allowed" if allowed else "denied"
    typer.echo(f"Approval popup result: {result}.")


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
    console = _console()
    table = _table()
    table.add_column("Provider", no_wrap=True, overflow="ellipsis")
    table.add_column("Status", no_wrap=True, overflow="ellipsis")
    table.add_column("Source", no_wrap=True, overflow="ellipsis")
    table.add_column("Capabilities", no_wrap=True, overflow="ellipsis")
    for status in statuses:
        capabilities = ", ".join(
            sorted(capability.value for capability in status.capabilities)
        )
        state = Text(_terminal_safe(status.state.value))
        if status.state.value == "ready":
            state.stylize("green")
        table.add_row(
            Text(_terminal_safe(status.provider)),
            state,
            Text(_terminal_safe(status.source)),
            Text(_terminal_safe(capabilities)),
        )
    console.print(table)


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
    elif matches:
        _render_metadata_table(matches)
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
    """Add one credential through one hidden human input prompt."""
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
    typer.echo(f"Credential ID (non-secret): {_terminal_safe(metadata.credential_id)}")


@app.command("set")
def set_command(
    ctx: typer.Context,
    binding_arguments: Annotated[
        list[str],
        typer.Argument(help="Credential IDs, or NAME=CREDENTIAL bindings, to write."),
    ],
    variable: Annotated[
        str | None,
        typer.Option(
            "--as", help="Destination name for one legacy credential argument."
        ),
    ] = None,
    file: Annotated[
        Path, typer.Option("--file", help="Dotenv destination file.")
    ] = Path(".env"),
    force: Annotated[
        bool, typer.Option(help="Replace populated dotenv assignments.")
    ] = False,
    allow_unignored: Annotated[
        bool, typer.Option(help="Allow an untracked destination not ignored by Git.")
    ] = False,
    allow_tracked: Annotated[
        bool, typer.Option(help="Allow writing plaintext into a Git-tracked file.")
    ] = False,
) -> None:
    """Set one or more dotenv entries without printing credential values."""
    if str(file) == "-":
        _fail("dotenv destination must be a regular file", 6)
    bindings = _parse_set_bindings(binding_arguments, variable)
    values: dict[str, str] = {}
    try:
        validate_dotenv_destinations(
            file, [name for name, _reference in bindings], force=force
        )
        git_status = destination_status(file)
        enforce_destination_policy(
            git_status,
            allow_tracked=allow_tracked,
            allow_unignored=allow_unignored,
        )
        _request_approval(
            ctx,
            action=DeliveryAction.SET,
            bindings=bindings,
            destination=_approval_file_destination(file),
        )
        provider_bindings = [
            (name, reference, _provider_for_reference(reference))
            for name, reference in bindings
        ]
        for name, reference, provider in provider_bindings:
            secret = provider.resolve(reference, no_input=_no_input(ctx))
            values[name] = _secret_text(secret, dotenv=True)
        git_status = destination_status(file)
        enforce_destination_policy(
            git_status,
            allow_tracked=allow_tracked,
            allow_unignored=allow_unignored,
        )
        mutate_dotenv_many(file, values, force=force)
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
    names = ", ".join(_terminal_safe(name) for name in values)
    typer.echo(
        f"Set {names} in {_terminal_safe(str(file))} from keychain (values hidden)."
    )


@app.command(
    "run",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    epilog=(
        "Place one or more CREDENTIAL or NAME=CREDENTIAL bindings before the "
        "required -- delimiter. A bare readable ID infers its service as the "
        "destination name. Examples: ainv run keychain:TOKEN@personal -- "
        "command | ainv run API_KEY=keychain:TOKEN@personal -- command"
    ),
)
def run_command(ctx: typer.Context) -> None:
    """Inject selected credentials into one child process."""
    bindings, command = _parse_run_arguments(ctx.args)
    _request_approval(
        ctx,
        action=DeliveryAction.RUN,
        bindings=bindings,
        destination=shlex.join(command),
    )
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


def _approval_file_destination(file: Path) -> str:
    try:
        return str(file.parent.resolve(strict=True) / file.name)
    except OSError:
        _fail("could not resolve dotenv destination directory", 6)


def _get_provider(name: str) -> CredentialProvider:
    return _PROVIDER_REGISTRY.get(name)


def _get_config() -> Config:
    return load_config()


def _get_approver() -> Approver:
    return MacOSApprover()


def _request_approval(
    ctx: typer.Context,
    *,
    action: DeliveryAction,
    bindings: list[tuple[str, str]],
    destination: str,
) -> None:
    try:
        configuration = _get_config()
    except ConfigurationError as error:
        _fail(str(error), 5)
    if configuration.approval is ApprovalMode.OFF:
        return
    if len(bindings) > MAX_APPROVAL_BINDINGS:
        _fail("too many credentials for native approval", 5)
    if _no_input(ctx):
        _fail("credential delivery approval requires interactive input", 5)
    try:
        working_directory = os.getcwd()
    except OSError:
        _fail("could not determine working directory for approval", 5)
    request = ApprovalRequest(
        action=action,
        bindings=tuple(
            ApprovalBinding(credential=reference, variable=variable)
            for variable, reference in bindings
        ),
        destination=destination,
        working_directory=working_directory,
    )
    try:
        allowed = _get_approver().approve(request)
    except ApprovalUnavailableError as error:
        _fail(str(error), 5)
    if not allowed:
        _fail("credential delivery was denied", 5)


def _provider_for_reference(reference: str) -> CredentialProvider:
    provider_name = _PROVIDER_REGISTRY.provider_name_for_reference(reference)
    return _get_provider(provider_name)


def _parse_set_bindings(
    arguments: list[str], legacy_variable: str | None
) -> list[tuple[str, str]]:
    if not arguments:
        _fail("set requires at least one credential", 2)
    if legacy_variable is not None:
        if len(arguments) != 1 or "=" in arguments[0]:
            _fail("--as requires exactly one credential reference", 2)
        return [_validated_binding(legacy_variable, arguments[0], set())]
    return _parse_bindings(arguments)


def _parse_run_arguments(
    arguments: list[str],
) -> tuple[list[tuple[str, str]], list[str]]:
    binding_arguments: list[str] = []
    command_index = 0
    for command_index, argument in enumerate(arguments):
        if "=" in argument or _looks_like_reference(argument):
            binding_arguments.append(argument)
            continue
        break
    else:
        command_index = len(arguments)

    command = arguments[command_index:]
    if not binding_arguments:
        _fail("run requires at least one credential binding", 2)
    if not command:
        _fail("run requires a child command", 2)
    return _parse_bindings(binding_arguments), command


def _parse_bindings(arguments: list[str]) -> list[tuple[str, str]]:
    bindings: list[tuple[str, str]] = []
    seen: set[str] = set()
    for argument in arguments:
        if "=" in argument:
            variable, reference = argument.split("=", 1)
        else:
            reference = argument
            variable = _infer_variable(reference)
        bindings.append(_validated_binding(variable, reference, seen))
    return bindings


def _validated_binding(
    variable: str, reference: str, seen: set[str]
) -> tuple[str, str]:
    try:
        validate_variable_name(variable)
    except DotenvError as error:
        _fail(str(error), 2)
    if not reference:
        _fail("credential reference must not be empty", 2)
    try:
        provider_name = _PROVIDER_REGISTRY.provider_name_for_reference(reference)
        if provider_name == "keychain":
            validate_keychain_reference(reference)
    except ProviderError as error:
        _fail_provider(error)
    if variable in seen:
        _fail("duplicate destination environment variable", 2)
    seen.add(variable)
    return variable, reference


def _infer_variable(reference: str) -> str:
    try:
        provider_name = _PROVIDER_REGISTRY.provider_name_for_reference(reference)
        if provider_name != "keychain":
            raise ValueError
        service, _account = parse_readable_reference(reference)
        validate_variable_name(service)
    except (ProviderError, DotenvError, ValueError):
        _fail("credential requires an explicit NAME= binding", 2)
    if service in _EXECUTION_SENSITIVE_VARIABLES or service.startswith(
        _EXECUTION_SENSITIVE_PREFIXES
    ):
        _fail("execution-sensitive variable requires an explicit NAME= binding", 2)
    return service


def _looks_like_reference(value: str) -> bool:
    try:
        _PROVIDER_REGISTRY.provider_name_for_reference(value)
    except ProviderError:
        return False
    return True


def _prompt_new_secret() -> Secret:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        _fail("adding a credential requires an interactive terminal", 5)
    try:
        value = _read_hidden_input("Secret value: ")
    except UnicodeDecodeError:
        _fail("secret value is not valid UTF-8 text", 7)
    except (EOFError, OSError, termios.error):
        _fail("secure credential input was cancelled or unavailable", 5)
    if not value:
        _fail("secret value must not be empty", 2)
    try:
        return Secret(value.encode("utf-8", "strict"))
    except UnicodeEncodeError:
        _fail("secret value is not valid UTF-8 text", 7)


def _read_hidden_input(prompt: str) -> str:
    """Read one UTF-8 terminal line with echo disabled, or fail closed.

    ``getpass`` can fall back to visible input after it cannot disable echo. This
    implementation opens the controlling terminal directly and has no fallback.
    """
    fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    try:
        original = termios.tcgetattr(fd)
        hidden = original[:]
        hidden[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
        try:
            _write_terminal(fd, prompt.encode("ascii"))
            value = _read_terminal_line(fd)
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, original)
            _write_terminal(fd, b"\n")
    finally:
        os.close(fd)
    return value.decode("utf-8", "strict")


def _read_terminal_line(fd: int) -> bytes:
    """Read through one newline, discarding any input already read after it."""
    value = bytearray()
    while True:
        chunk = os.read(fd, 4096)
        if not chunk:
            raise EOFError
        newline = chunk.find(b"\n")
        if newline >= 0:
            value.extend(chunk[:newline])
            return bytes(value)
        value.extend(chunk)


def _write_terminal(fd: int, value: bytes) -> None:
    """Write all terminal output without routing it through stdout or stderr."""
    while value:
        written = os.write(fd, value)
        if written == 0:
            raise OSError("could not write to terminal")
        value = value[written:]


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


def _console() -> Console:
    return Console(file=sys.stdout, highlight=False)


def _table() -> Table:
    return Table(
        box=box.ROUNDED,
        header_style="bold",
        pad_edge=True,
        padding=(0, 1),
    )


def _render_metadata_table(matches: list[CredentialMetadata]) -> None:
    console = _console()
    table = _table()
    table.add_column("Credential ID", min_width=34, no_wrap=True)
    table.add_column(
        "Provider", min_width=8, max_width=8, no_wrap=True, overflow="ellipsis"
    )
    table.add_column("Service", min_width=7, no_wrap=True, overflow="ellipsis")
    table.add_column("Account", min_width=7, no_wrap=True, overflow="ellipsis")
    table.add_column("Label", min_width=5, no_wrap=True, overflow="ellipsis")
    for item in matches:
        table.add_row(
            Text(_abbreviate_reference(_terminal_safe(item.credential_id))),
            Text(_terminal_safe(item.provider)),
            Text(_terminal_safe(item.name)),
            Text(_terminal_safe(item.account)),
            Text(_terminal_safe(item.label)),
        )
    console.print(table)
    if any(
        item.identifier is None or len(_terminal_safe(item.credential_id)) > 34
        for item in matches
    ):
        console.print(
            Text("Use --json for complete credential IDs and legacy references."),
            style="dim",
        )


def _abbreviate_reference(reference: str) -> str:
    max_length = 34
    head_length = 23
    tail_length = max_length - head_length - len("...")
    if len(reference) <= max_length:
        return reference
    return f"{reference[:head_length]}...{reference[-tail_length:]}"


def _metadata_json(metadata: CredentialMetadata) -> dict[str, str | None]:
    return {
        "id": metadata.credential_id,
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
    if isinstance(error, InvalidReferenceError):
        code = 2
    elif isinstance(error, CredentialNotFoundError):
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
