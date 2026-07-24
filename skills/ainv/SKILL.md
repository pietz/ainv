---
name: ainv
description: Use ainv when credentials from macOS Keychain are needed in a dotenv file or child command, when searching existing credential metadata, or when helping a user add a new local credential without exposing its value.
---

# ainv

Use `ainv` as the safe interface to macOS Keychain credentials. Treat
`ainv --help` and `ainv <command> --help` as the syntax source of truth.

## Choose the least-exposing authentication path

Prefer a tool's native authenticated session when it already works, such as
`gh`, SSH agent, cloud workload identity, or a provider CLI. Use `ainv` when a
consumer specifically needs an environment variable or dotenv entry.

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
interactive terminal and enter the value through its hidden confirmation
prompts. Never request a credential in chat, accept it as a command argument, or
pipe it into `ainv`.

## Write one dotenv entry

```console
ainv set 'keychain://v1/item/REFERENCE' \
  --as OPENAI_API_KEY --file .env
```

The destination contains plaintext after this operation. Do not read, display,
grep, summarize, or otherwise inspect it afterward. `ainv` refuses unsafe Git
destinations unless an explicit override is given; do not use an override
without the user's informed approval.

## Inject into one command

Prefer process injection when the consumer supports environment variables:

```console
ainv run 'OPENAI_API_KEY=keychain://v1/item/REFERENCE' -- command
```

Do not run environment-dumping or debug commands inside `ainv run`. The child
process receives the plaintext value and can print or transmit it.

## Hard guardrails

- There is intentionally no command that prints a resolved credential.
- Never invoke provider-native plaintext retrieval as a workaround.
- Never place a secret in command arguments, chat, shell history, or clipboard.
- If a value appears in agent output or conversation context, stop, report the
  exposure without repeating it, and tell the user to rotate it.
- Current provider support is limited to non-synchronizable generic passwords in
  the default macOS Keychain.
