---
name: ainv
description: Deliver credentials from existing providers to intended processes without exposing values in routine agent context. Use when a task needs a credential, authenticated command, dotenv file, macOS Keychain item, or help with a missing credential.
---

# ainv

Use `ainv` for declaration-free Keychain discovery and credential delivery while
keeping values out of routine agent context. Treat `ainv --help` as the syntax
source of truth.

## Choose the least-exposing path

1. Prefer native authenticated sessions such as `gh`, SSH agent, cloud workload
   identity, `pg_service.conf`/`.pgpass`, or a provider CLI.
2. Prefer `ainv run` when one trusted process needs environment variables.
3. Use `ainv set` only when the consumer requires a physical dotenv file.

`ainv` currently supports non-synchronizable generic passwords in the default
legacy macOS Keychain only.

## Find and select

Search metadata without retrieving values:

```console
ainv find openai
ainv find openai --json
```

Prefer readable credential IDs returned by discovery:

```text
keychain:OPENAI_API_KEY@personal
```

Use service as the credential or destination name and account as an explicit
scope such as `personal`, `work`, or a client name. Ask the user when multiple
accounts or credentials are plausible. Never guess between personal, work,
production, or client scopes.

JSON also contains legacy opaque references. Treat either form as non-secret
local metadata, not portable project configuration. Search again if an identity
stops resolving.

## Add a missing credential

Prepare this command for the user:

```console
ainv add OPENAI_API_KEY --provider keychain --account personal
```

The user must enter the value through the hidden interactive prompt. Never ask
for a credential in chat, accept it as an argument, pipe it into `ainv`, or
read/manipulate the clipboard.

## Inject into one trusted command

Allow destination-name inference when the service is already the required,
non-sensitive environment variable:

```console
ainv run keychain:OPENAI_API_KEY@personal -- command
```

Otherwise bind it explicitly:

```console
ainv run API_KEY=keychain:OPENAI_API_KEY@personal -- command
```

Execution-sensitive names such as `PATH`, language startup hooks, and dynamic
loader variables require explicit `NAME=CREDENTIAL` bindings. Multiple
bindings resolve before anything executes. Use only an intended, trusted
consumer and avoid debug or environment-dumping modes. The process,
its descendants, dependencies, telemetry, and anything it invokes can expose
received values. This is hygiene, not containment.

## Set dotenv entries

```console
ainv set keychain:OPENAI_API_KEY@personal --file .env
```

Multiple bindings are atomic:

```console
ainv set \
  keychain:OPENAI_API_KEY@personal \
  DATABASE_URL=keychain:POSTGRES_URL@work \
  --file .env
```

A missing variable is appended and a syntactically empty placeholder is filled.
Comment-bearing assignments are conservatively treated as populated. A
populated assignment fails before credential resolution. `--force` permits replacement,
but use it only after the user explicitly agrees to replace the named existing
assignments. It does not override Git or filesystem safety. Do not use
`--allow-tracked` or `--allow-unignored` without informed user approval.

The destination contains plaintext afterward. Never read, display, grep,
summarize, or otherwise inspect it.

## ainv approval dialogs

When approval is configured as `always`, `run` and `set` show one native macOS
dialog before resolving any credential. Stop and let the human review the
credential IDs, destination variables, command or file, and working directory.
Never click, automate, suppress, or bypass this dialog. Continue only when the
human selects **Allow Once**. Denial ends the operation.

Inspect or change the setting with:

```console
ainv config
ainv config --approval always
ainv config --approval off
```

`ainv config --test-popup` tests the UI without accessing credentials. This
consent gate provides human oversight, not containment against a shell-capable
agent running as the same user.

## Local activity history

`ainv history` shows value-free local authorization activity for `run` and
`set`; use `--limit N` or `--json` when needed. History is enabled by default
and can be changed with `ainv config --history on|off`. It records credential
references, destination variable names, file or executable paths, working
directories, outcomes and reasons, and best-effort requester context before
secret resolution. It never records secret values or full command arguments.
Large or non-UTF-8 filesystem metadata is represented with bounded fields,
binding counts, and explicit omission, truncation, or escaping metadata.
Malformed or partial lines are skipped with a value-free warning/count so later
valid records remain usable. Readers and writers retry brief lock contention
within a bounded 7 ms sleep budget; residual write contention only warns, while
residual read contention fails cleanly.

Treat this operational metadata as private. Records are append-written, but
history is not immutable, tamper-evident, or a security audit, and it does not
prove delivery or command completion. Do not infer successful recipient
behavior from an `allowed` event.

## Keychain dialogs

With the current Python distribution, a dialog may identify `python3.13` rather
than `ainv`. Stop for the human to verify that the operation is expected and
instruct them to choose **Allow Once**, not **Always Allow**. Never approve,
suppress, bypass, or alter Keychain prompts. `find` is metadata-only and cannot
prompt; `run` and `set` can prompt while resolving.

## Hard guardrails

- There is intentionally no generic plaintext retrieval command.
- Never invoke provider-native plaintext retrieval as a workaround, including
  `security ... -w`, `gh auth token`, `op read`, token-printing commands, `env`,
  or `printenv`.
- Never place a secret in arguments, chat, shell history, clipboard, or
  agent-visible output.
- Never read files whose purpose is holding credentials, including `.env`,
  `.pgpass`, agent auth files, and SSH private keys.
- If a value appears in output or conversation context, stop without repeating
  it and tell the user to revoke or rotate it.

For cleanup, the user can remove Keychain items in Keychain Access and dotenv
entries manually. Removing a local item does not revoke the remote credential.
