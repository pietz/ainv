---
name: ainv
description: Deliver credentials from existing providers to intended processes without exposing values in routine agent context. Use when a task needs a credential, authenticated command, dotenv file, macOS Keychain item, 1Password secret, or help with a missing credential.
---

# ainv

Keep credential values out of routine agent context, shell arguments, and
`ainv`'s normal output. Child output can still expose them. Prefer an existing
native login when one works; use `ainv` for macOS Keychain discovery, creation,
and delivery. Treat `ainv --help` and `ainv <command> --help` as the syntax
source of truth.

## Choose the least-exposing path

1. Prefer native authenticated sessions such as `gh`, SSH agent, cloud workload
   identity, `pg_service.conf`/`.pgpass`, or a provider CLI.
2. Prefer `ainv run` when a child process needs a Keychain value in its
   environment.
3. Use `ainv set` only when the consumer requires a dotenv file.

`ainv` currently supports non-synchronizable generic passwords in the default
macOS Keychain. It does not yet deliver 1Password credentials. For a 1Password
credential, prefer existing native authentication or a documented mechanism
that resolves the value outside agent-visible output. Never use `op read` as a
workaround; pause and involve the user if no safe delivery path is available.

## Keychain convention

When adding credentials, use the target environment-variable name as the
Keychain service and an explicit scope such as `personal`, `workgenius`, or a
client name as the account. Discovery returns an opaque persistent reference,
which avoids ambiguous service-only retrieval. Treat it as a local Keychain
locator, not portable project configuration or an immutable credential ID. If it
stops resolving, search again rather than reconstructing it from metadata.

## Find an existing credential

Search metadata without retrieving secret values:

```console
ainv find openai
ainv find openai --json
```

Use the exact opaque reference returned by `find`. Narrow broad queries rather
than enumerating unrelated metadata.

## Add a missing credential

Prepare the interactive command for the user:

```console
ainv add OPENAI_API_KEY --provider keychain --account personal
```

`--label` is optional. The user must run or complete this command in an
interactive terminal and enter the value through its one hidden prompt. A human
may safely paste a newly issued credential from a browser into that prompt.
Agents must never read, inspect, or manipulate the clipboard. Never request a
credential in chat, accept it as a command argument, or pipe it into `ainv`.
The complete opaque reference in success output is labeled `Reference
(non-secret identifier)`. It is usable for later `ainv` commands and is not the
credential value.

## Keychain authorization dialogs

With the current `uv tool` Python distribution, a Keychain dialog may identify
`python3.13` rather than `ainv`; this is possible, not confirmed dialog wording.
When a dialog appears, stop for the human to verify that the requested operation
is expected. Instruct them to choose **Allow Once**, not **Always Allow**. Do
not coach around, suppress, bypass, or alter Keychain prompts or access controls.
`ainv find` is metadata-only and cannot prompt. Resolving a pre-existing item
for `ainv set` or `ainv run` can prompt.

The dialog authorizes the uv-managed Python interpreter rather than the `ainv`
console script. An `ainv`-created item already trusts its creator interpreter,
so Allow Once does not make this distribution a stable, least-privilege identity
for unattended high-value credentials.

## Inject into one command

Prefer process injection when the consumer supports environment variables:

```console
ainv run 'OPENAI_API_KEY=keychain://v1/item/REFERENCE' -- command
```

Use `ainv run` only for an intended, trusted consumer. Avoid debug or
environment-dumping modes. The selected process, its descendants, dependencies,
crash reporters, telemetry, and anything it invokes receive or can access the
plaintext value and can retain, print, transmit, or expose it. These
instructions are not an enforcement boundary: `ainv` does not make untrusted
agents, repositories, dependencies, or commands safe.

## Write one dotenv entry

```console
ainv set 'keychain://v1/item/REFERENCE' \
  --as OPENAI_API_KEY --file .env
```

The destination contains plaintext after this operation. Do not read, display,
grep, summarize, or otherwise inspect it afterward. `ainv` refuses unsafe Git
destinations unless an explicit override is given; do not use an override
without the user's informed approval.

## Cleanup and exposure recovery

For private dogfood, a user can remove an `ainv`-created item manually in
Keychain Access by its service, account, and label. A user may manually remove
a materialized dotenv entry, but never ask an agent to read the dotenv file to
do so. There is no `ainv replace` or `ainv remove` command.

If a credential is exposed, stop and have the user revoke or rotate it with the
remote issuer first. Removing the local Keychain item does not revoke it
remotely.

## Hard guardrails

- There is intentionally no command that prints a resolved credential.
- Never invoke provider-native plaintext retrieval as a workaround, including
  standalone `security ... -w`, `gh auth token`, `op read`, access-token print
  commands, `env`, or `printenv`.
- Never place a secret in command arguments, chat, shell history, clipboard, or
  agent-visible tool output.
- Never read files whose purpose is holding credentials, including `.env`,
  `.pgpass`, agent auth files, and SSH private keys.
- If a value appears in agent output or conversation context, stop, report the
  exposure without repeating it, and tell the user to rotate it.
