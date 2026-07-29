# ainv

`ainv` is a small, agent-operated credential handoff utility for macOS:

> Give agents the environment they need, not the secrets behind it.

An agent can discover Keychain credentials through value-free metadata, ask a
human to resolve ambiguity or enter a missing value, and deliver the credential
to one trusted process or a conventional dotenv file without returning the
value through `ainv`'s normal interface.

No project manifest, custom vault, cloud service, daemon, or MCP server is
required. The macOS Keychain remains the source of truth.

> [!IMPORTANT]
> `ainv` provides context hygiene and reduces accidental exposure. It does not
> contain a malicious agent or process. A selected process can expose injected
> values, and an agent or process with file access can read materialized dotenv
> values.

The current preview supports non-synchronizable generic passwords in the
default legacy macOS Keychain only.

## Installation

> [!WARNING]
> Version 0.3.0 remains pre-alpha. In the current `uv tool` distribution,
> Keychain authorizes the uv-managed Python interpreter rather than a stable,
> signed `ainv` executable. Read [SECURITY.md](SECURITY.md) before approving
> Keychain access.

```console
uv tool install ainv
```

For development from a checkout:

```console
uv tool install .
```

## Discover a credential

Search metadata without retrieving secret values:

```console
ainv find openai
ainv find openai --json
```

Results prefer readable, value-free credential IDs:

```text
keychain:OPENAI_API_KEY@personal
```

Service or account characters outside the safe identifier set are
percent-encoded. JSON also includes the legacy opaque persistent reference for
compatibility and rare disambiguation.

## Add a missing credential

```console
ainv add OPENAI_API_KEY --provider keychain --account personal
```

`--label` is optional. The human enters the value through one fail-closed hidden
TTY prompt. Values are never accepted through arguments, pipes, or chat, and
existing credentials are never overwritten.

## Inject credentials into one process

When the Keychain service is a valid, non-sensitive environment-variable name,
`ainv` infers the destination:

```console
ainv run keychain:OPENAI_API_KEY@personal -- command
```

An explicit destination and multiple all-or-nothing bindings are also
supported:

```console
ainv run \
  API_KEY=keychain:OPENAI_API_KEY@personal \
  keychain:DATABASE_URL@work \
  -- command
```

Execution-sensitive names such as `PATH`, language startup hooks, and dynamic
loader variables require an explicit `NAME=CREDENTIAL` binding. Every
credential resolves before the command starts. The selected process and its
descendants receive plaintext values and are trusted recipients. Child stdout
and stderr pass through unchanged.

## Set dotenv entries

Use `set` only when the consumer requires a physical dotenv file:

```console
ainv set keychain:OPENAI_API_KEY@personal --file .env
```

Multiple bindings are committed in one atomic replacement:

```console
ainv set \
  keychain:OPENAI_API_KEY@personal \
  DATABASE_URL=keychain:POSTGRES_URL@work \
  --file .env
```

Default behavior is deliberately conservative:

- create a missing file with restricted permissions;
- append an absent assignment at the bottom;
- fill `NAME=`, `NAME =`, `NAME=""`, or `NAME=''` placeholders;
- conservatively treat comment-bearing assignments as populated;
- refuse duplicate or populated assignments before resolving credentials;
- refuse tracked or non-ignored Git destinations unless explicitly approved;
- preserve unrelated content and replace the file atomically.

Replacing a populated assignment requires informed approval:

```console
ainv set keychain:OPENAI_API_KEY@personal --file .env --force
```

`--force` does not bypass Git, ownership, symlink, hard-link, or permission
protections. Legacy `ainv set REF --as NAME` syntax remains supported.

## Optional approval popup

Require one native macOS consent dialog before every `run` or `set` delivery:

```console
ainv config --approval always
```

Turn it off or inspect the current setting:

```console
ainv config --approval off
ainv config
```

Test the popup without accessing any credential:

```console
ainv config --test-popup
```

The **ainv Access Requested** dialog shows the nearest bundled application found
in native process ancestry and uses its icon when available. This best-effort
requester context is informational, not authenticated; the dialog uses a neutral
unidentified label and no requester icon when ancestry does not provide one. The
dialog also shows value-free credential IDs, destination variables, the target
command or file, and working directory. It offers
**Deny** and **Allow Once**. One dialog covers up to ten bindings in an
invocation and appears after destination validation but before any credential
resolution. Review context is escaped and must fit completely in the dialog; it
is never silently truncated. When approval is enabled, `--no-input` fails
closed instead of displaying UI.

Configuration lives at
`~/Library/Application Support/ainv/config.toml`. Parsing is strict: malformed
TOML and unknown settings fail instead of being ignored. Inspect and repair the
file manually when settings must be preserved, or explicitly replace it with
safe defaults using `ainv config --reset`. Reset cannot be combined with other
config changes and does not override ownership, link, or permission checks.
Default `history = "on"` is omitted when writing so approval-only configuration
remains readable by older strict versions where possible.

This popup adds human oversight and reduces unnoticed use. It is not a hard
permission boundary: a shell-capable process running as the same user can edit
configuration, bypass `ainv`, or invoke provider-native tools. Keychain may show
its own separate system authorization dialog after ainv approval.

## Local activity history

`run` and `set` authorization decisions are recorded locally by default:

```console
ainv history
ainv history --limit 50
ainv history --json
```

This is value-free **activity history**, not a security audit and not proof that
a credential was delivered or a recipient completed successfully. A record is
written after destination validation and before provider resolution. It includes
the time, action, authorization outcome and reason, credential references,
destination variable names, working directory, safe destination summary, and a
best-effort requester application when available. Outcomes distinguish an
explicit user denial from approval errors. Command records contain only the
executable name or path and argument count, never argument contents. Secret
values, resolved environments, and child output are never recorded.

Every metadata field is byte-bounded. Large requests retain the total binding
count, a bounded subset, the omitted count, and explicit field-truncation or
filesystem-text escaping metadata, so extreme valid invocation metadata cannot
suppress its event.

History metadata can itself reveal credential names, accounts, project paths,
executables, requester context, authorization reasons, and usage patterns to
someone with local account access. It is kept in a private, size-bounded JSONL
file with at most one rotated backup at
`~/Library/Application Support/ainv/history.jsonl`. Records are append-written,
but the file is not immutable or tamper-evident. Disable future recording when
this local metadata is not wanted:

```console
ainv config --history off
ainv config --history on
```

Writers and readers retry a contended advisory lock within a bounded 7 ms sleep
budget. If contention remains, a write emits a generic warning without blocking
an otherwise approved delivery, while a read fails cleanly through the normal
CLI error contract. Reads strictly validate each JSONL line, skip malformed and
partial records, and report only a value-free invalid-record count. A later
append starts on a fresh line after a partial tail, so valid future activity
remains readable. Unsafe paths, ownership, links, and permissions still fail the
whole read. `config --test-popup` is never recorded.

## Deliberate omissions

There is no generic `get`, `print`, clipboard, export, shell-session, vault,
manifest, provider plugin system, or MCP command. Existing native sessions such
as SSH agents, cloud CLIs, and provider authentication remain preferable when
they already solve the task.

For recurring schema-driven project environments, consider a declarative tool
such as Varlock. `ainv` focuses on ad hoc agent work, initial onboarding, and
safe conventional dotenv materialization.

## Development

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

```console
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

The detailed product and security contract is in [SPEC.md](SPEC.md).

## License

No license has been granted yet. The published pre-alpha package is available
for evaluation, but permission to copy, modify, or redistribute it has not been
granted.
