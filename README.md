# ainv

`ainv` is a small, provider-neutral CLI for moving secrets without printing them.
It is intended for humans and shell-capable coding agents that need to:

- add credentials to an existing provider through hidden human input;
- search credential stores using non-sensitive metadata;
- write a selected credential directly into an environment file; and
- inject selected credentials into one child process.

`ainv` is not a vault, daemon, cloud service, or MCP server. Credential providers
remain the source of truth.

> [!IMPORTANT]
> This project is an early development preview. The current release supports
> non-synchronizable generic passwords in the default macOS Keychain only.

The proposed product and security contract is documented in [SPEC.md](SPEC.md).

## Installation

The package is not published to PyPI yet. From a local checkout:

```console
uv tool install .
```

## Usage

Add a native Keychain credential through confirmed hidden input:

```console
ainv add OPENAI_API_KEY --provider keychain --account personal
```

`--label` is optional. Existing credentials are never overwritten.

Search Keychain metadata without retrieving secret values:

```console
ainv find openai
ainv find openai --json
```

Use the opaque reference returned by `find` to set one dotenv entry:

```console
ainv set 'keychain://v1/item/REFERENCE' --as OPENAI_API_KEY --file .env
```

Or inject it into one child process without touching disk:

```console
ainv run 'OPENAI_API_KEY=keychain://v1/item/REFERENCE' -- command
```

`set` refuses tracked or non-ignored Git destinations unless explicitly
overridden. Run `ainv <command> --help` for all options.

The command surface will not include a generic operation that prints a resolved
secret.

## Agent skill

The repository includes an optional agent skill at [`skills/ainv`](skills/ainv).
Install it into the shared skills directory with:

```console
ln -s "$(pwd)/skills/ainv" ~/.agents/skills/ainv
```

## Development

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

```console
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

## Security model

`ainv` does not write resolved values to its own output, diagnostics, command
arguments, or the clipboard. Once a secret is written to a file or injected into
a child process, any process with sufficient access may still read, print, or
transmit it. Child stdout and stderr pass through unchanged.

## License

License to be selected before the first stable release.
