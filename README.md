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

This is a pre-alpha work in progress. Install the published package with:

```console
uv tool install ainv
```

For development from a local checkout:

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

> [!WARNING]
> `ainv run` keeps resolved values out of its normal arguments and output, but
> it gives them to the selected process. That process, its descendants,
> dependencies, crash reporters, telemetry, and anything it invokes can read,
> retain, transmit, or expose them. Use it only for an intended, trusted
> consumer and avoid debug or environment-dumping modes. This is guidance, not
> an enforcement boundary: `ainv` does not make untrusted agents, repositories,
> dependencies, or commands safe.

The command surface will not include a generic operation that prints a resolved
secret.

## References and cleanup

A Keychain reference is an opaque local locator, not portable project
configuration or a unique identifier for one immutable credential incarnation.
It may become stale after identity metadata changes or deletion. If it no
longer resolves, search again rather than reconstructing it from metadata.

For private dogfood, remove an `ainv`-created Keychain item manually in Keychain
Access by its service, account, and label. Remove a materialized dotenv entry
manually without asking an agent to read the file. If a credential is exposed,
revoke or rotate it with its remote issuer first. Removing the local Keychain
item does not revoke it remotely.

## Agent skill

The repository includes an optional agent skill at [`skills/ainv`](skills/ainv).
Install it into the canonical shared skills directory with:

```console
mkdir -p ~/.agents/skills
ditto skills/ainv ~/.agents/skills/ainv
```

Claude Code additionally needs a discovery symlink:

```console
ln -s ~/.agents/skills/ainv ~/.claude/skills/ainv
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

`ainv` reduces accidental credential exposure by keeping resolved values out of
its normal arguments and output. Once a secret is written to a file or injected
into a child process, it can be read, retained, printed, transmitted, or exposed
by that process, its descendants, dependencies, crash reporters, telemetry, or
anything it invokes. Child stdout and stderr pass through unchanged. `ainv`
does not make untrusted agents, repositories, dependencies, or commands safe.

## License

No license has been granted yet. The published pre-alpha package is available
for evaluation, but permission to copy, modify, or redistribute it has not been
granted.
