# ainv specification

Status: Draft 0.1

Target: Initial public development release

## 1. Purpose

`ainv` is a small, stateless CLI that moves secrets from existing credential
providers to an explicit destination without printing the secret value.

It is designed for humans and shell-capable coding agents. The initial workflow
is deliberately ad hoc and requires no project initialization or manifest:

```console
ainv find openai
ainv set 'keychain://v1/item/PERSISTENT_REF' \
  --as OPENAI_API_KEY --file .env
ainv run 'OPENAI_API_KEY=keychain://v1/item/PERSISTENT_REF' \
  -- command
```

Credential providers remain the source of truth. `ainv` owns neither secret
storage nor encryption.

## 2. Product principles

1. **Safe by default.** `ainv` never writes resolved values to its own stdout,
   stderr, logs, diagnostics, or arguments. Child output remains outside this
   guarantee.
2. **Stateless by default.** Discovery and delivery require no project files.
3. **Provider neutral.** Providers expose a common CLI shape, while
   authentication, metadata, approval behavior, and failures remain
   provider-specific.
4. **Explicit delivery.** Every operation names its destination and variable.
5. **Agent legible.** Help text, structured output, and errors explain the next
   valid action without requiring a large prompt or skill.
6. **Unix compatible.** Commands compose naturally, preserve TTY behavior, and
   use meaningful exit codes.
7. **Honest security.** `ainv` prevents accidental disclosure, not deliberate
   exfiltration by a process that receives or can read a secret.
8. **Small trusted core.** The project does not implement a vault, cryptography,
   cloud service, daemon, or synchronization system.

## 3. Non-goals

The initial product will not provide:

- a password manager or custom secret store;
- cloud synchronization, team sharing, RBAC, or rotation;
- a project manifest or required configuration file;
- an MCP server;
- browser autofill or session-cookie management;
- a clipboard workflow;
- a generic command that returns a plaintext secret;
- protection from a malicious command after it receives a secret;
- transparent network credential brokering;
- support for editing arbitrary configuration formats beyond dotenv files.

## 4. Terminology

- **Provider:** An existing credential system, such as macOS Keychain or
  1Password.
- **Reference:** A stable, non-secret provider identifier for one credential or
  field.
- **Metadata:** Non-secret descriptive attributes such as provider, service,
  account, label, type, and modification time.
- **Binding:** A destination environment-variable name paired with a reference.
- **Materialization:** Resolving a reference and writing its value to a file.
- **Injection:** Resolving a reference and adding its value only to a child
  process environment.

Metadata and references are not secret values, but they may still reveal
sensitive operational information. Output should contain only what is useful.

## 5. Primary workflows

### 5.1 Discover credentials

```console
ainv find openai
```

The query must be nonempty. Full metadata enumeration is not supported in the
MVP. Results use a conservative default limit of 20, with a maximum of 100,
and are ordered by provider, normalized service/name, account, and canonical
reference for deterministic output. Provider metadata is escaped before human
terminal rendering to prevent control-character or terminal-sequence injection.

Example human-readable output:

```text
REF                                                        PROVIDER  SERVICE         ACCOUNT
keychain://v1/item/PERSISTENT_REF                                keychain  OPENAI_API_KEY  personal
```

Search is case-insensitive across provider-approved metadata fields. It never
requests or returns secret data.

Machine-readable output:

```console
ainv find openai --json
```

```json
{
  "schema_version": 1,
  "query": "openai",
  "partial": false,
  "matches": [
    {
      "ref": "keychain://v1/item/PERSISTENT_REF",
      "provider": "keychain",
      "name": "OPENAI_API_KEY",
      "account": "personal",
      "label": "OpenAI API key",
      "kind": "generic-password",
      "modified_at": null
    }
  ]
}
```

JSON output must have a versioned, documented schema before it is declared
stable. Fields unavailable from a provider are `null`, not guessed.

Useful options:

```console
ainv find openai --provider keychain
ainv find openai --limit 20
ainv find openai --json
```

An empty result returns valid empty output and exit code 3. When multiple
providers are selected, discovery is all-or-nothing: any provider failure
returns exit code 4 and no matches. Partial results are reserved for a future
explicit mode and are never silently presented as complete.

### 5.2 Materialize one secret into a dotenv file

The default destination is `.env` in the current working directory:

```console
ainv set 'keychain://v1/item/PERSISTENT_REF' --as OPENAI_API_KEY
```

An explicit destination can be supplied:

```console
ainv set 'keychain://v1/item/PERSISTENT_REF' \
  --as OPENAI_API_KEY --file .env.local
```

Behavior:

- Variable names use `[A-Za-z_][A-Za-z0-9_]*` in both `set` and `run`.
- Require a UTF-8 destination, optionally with a UTF-8 BOM.
- If exactly one `OPENAI_API_KEY` assignment exists, replace that complete line
  with a canonical assignment.
- If none exists, append one assignment with a separating newline when needed.
- Reject duplicate target assignments and malformed target lines before
  resolving the credential.
- Preserve all unrelated text, comments, ordering, and the dominant line ending.
- Never display the resolved value or include it in an argument.
- Create new files with mode `0600`.
- Remove group or world permissions from an existing destination unless the
  user explicitly opts out.
- Open and lock the canonical destination directory, then perform reads,
  temporary-file creation, revalidation, replacement, and directory sync
  relative to that directory descriptor. This prevents parent-path retargeting.
- Never create a plaintext backup.
- Refuse symbolic links, hard-linked files, directories, FIFOs, devices, and
  `--file -` unconditionally in the MVP.
- Require existing destinations to be regular files owned by the current user.
- In a Git worktree, always refuse a tracked destination unless
  `--allow-tracked` is passed. Refuse an untracked, non-ignored destination
  unless `--allow-unignored` is passed. Git inspection uses literal paths and
  fails closed on execution errors or timeouts. Policy is checked before and
  immediately after credential resolution.
- Outside Git, warn that the destination contains plaintext credentials.
- Use an advisory directory lock and revalidate the destination inode before
  replacement to prevent silent lost updates between cooperating `ainv`
  processes.
- Preserve owner and tightened mode. ACLs, extended attributes, file flags, and
  hard-link relationships are not preserved; unsupported destinations are
  rejected rather than silently weakening them where detectable.

Success output contains metadata only:

```text
Set OPENAI_API_KEY in .env from keychain (value hidden).
```

The direct `set` command is intentionally singular. Bulk or manifest-driven
materialization is deferred until real usage demonstrates a need.

### 5.3 Inject selected secrets into one child process

```console
ainv run \
  'OPENAI_API_KEY=keychain://v1/item/PERSISTENT_REF' \
  -- npm run dev
```

Multiple bindings are accepted:

```console
ainv run \
  'OPENAI_API_KEY=keychain://v1/item/PERSISTENT_REF' \
  'DATABASE_URL=keychain://v1/item/ANOTHER_PERSISTENT_REF' \
  -- npm run dev
```

Behavior:

- Resolve every binding before starting the command.
- If any resolution fails, start nothing.
- Add resolved values to a copy of the current environment.
- Refuse duplicate destination names.
- Refuse invalid environment-variable names.
- Require resolved environment values to be valid UTF-8 and reject NUL bytes.
  Empty values, `=`, CR, and LF are valid for `run`, subject to operating-system
  behavior. Dotenv delivery is intentionally stricter.
- Replace `ainv` with the target process using an exec-style launch where the
  platform permits it, preserving signals, exit behavior, and TTY access.
- Do not capture, inspect, redact, or transform child stdout/stderr.

The final point is important: child output cannot be reliably redacted without
breaking terminal behavior or providing a false security guarantee. A child
process can print or transmit any secret it receives.

### 5.4 Inspect available providers

```console
ainv providers
```

```text
PROVIDER  STATUS  SOURCE
keychain  ready   built-in
```

Machine-readable output is available through `--json`.

## 6. CLI contract

Initial command surface:

```text
ainv [--no-input] find QUERY [--provider NAME] [--limit N] [--json]
ainv [--no-input] set REF --as NAME [--file PATH] [--allow-unignored] [--allow-tracked]
ainv [--no-input] run NAME=REF [NAME=REF ...] [--] COMMAND [ARG ...]
ainv providers [--json]
ainv --help
ainv --version
```

### 6.1 Commands intentionally omitted

There will be no:

```text
ainv get REF
ainv read REF
ainv print REF
ainv copy REF
```

Humans who need plaintext retrieval can use their provider's native interface.
The absence of these commands makes the default `ainv` surface suitable for
agent instructions.

### 6.2 Global behavior

- Human output goes to stdout; warnings and errors go to stderr.
- `--json` emits one JSON document and no decorations or progress indicators.
  It is initially supported by `find` and `providers` only.
- JSON success documents include `schema_version: 1`. Runtime JSON failures use
  `{\"schema_version\": 1, \"error\": {\"code\": ..., \"message\": ...}}`.
  Typer/Click usage errors occur before command execution and retain their
  normal human-readable form in the MVP.
- Prompts are forbidden in `--json` mode.
- Global `--no-input` fails rather than triggering CLI confirmation or
  provider-controlled authentication/approval UI. `ainv` never reads secret
  values from stdin. A piped or non-TTY stdin does not implicitly disable native
  Keychain approval UI because coding-agent subprocesses commonly lack a TTY;
  automation that forbids UI must pass `--no-input` explicitly.
- Metadata discovery must never request secret data or trigger Keychain approval
  UI, including outside `--json` mode.
- A locked or unavailable provider exits 4. Explicitly denied or cancelled
  secret access exits 5.
- Debug logging must never include resolved values, child environments, or
  credential-bearing temporary-file contents.
- Secret references may appear in output and logs because they are the tool's
  non-secret handles.

## 7. References

References are provider-owned opaque strings. The core identifies the provider
from the URI scheme but must not reinterpret provider-specific components.

Examples:

```text
keychain://v1/item/PERSISTENT_REF
```

Requirements:

- A reference must never contain the secret value.
- A provider must return canonical references from discovery.
- References must identify exactly one provider item and field where fields
  exist. Descriptive service/account pairs are insufficient when duplicates are
  possible.
- References should remain valid when display labels change, where the provider
  offers a stable identifier.
- Human-readable references are preferred, but stability takes priority.
- URI components must be percent-encoded where required.
- The core must preserve reference case and encoding exactly.

The canonical MVP format is
`keychain://v1/item/<base64url-unpadded-persistent-reference>`. The opaque token
comes from Apple's persistent item reference and contains no descriptive
service/account fields. The provider parses this exact prefix itself rather than
using a normalizing URL parser. Resolution requests exactly that persistent
reference and never falls back to service/account matching.

## 8. Provider model

### 8.1 Required provider capabilities

Every provider implements:

1. `status`: Report whether the provider is installed, authenticated, locked, or
   unavailable without returning credentials.
2. `search`: Return metadata and canonical references without requesting secret
   data.
3. `resolve`: Resolve one canonical reference to secret bytes for an explicit
   delivery operation.

Providers may support optional capabilities later, but `ainv` will not initially
store, update, delete, rotate, or synchronize credentials.

### 8.2 Initial providers

#### macOS Keychain

The first provider targets non-synchronizable generic-password entries in the
user's default legacy file Keychain. The provider calls this scope `default`
unless macOS can establish a more specific name. Discovery uses PyObjC's native
Security framework binding, requests attributes and persistent references, and
must not request `kSecReturnData`. It scopes queries to the selected
`SecKeychainRef` and disables authentication UI.

Initial searchable metadata:

- service;
- account;
- label;
- description/type when present;
- creation and modification dates when available;
- containing keychain identifier where available.

Resolution must use the persistent identity returned by discovery with
`kSecMatchLimitOne` and produce exactly one item. Service/account metadata may be
used for display, never as an arbitrary first-match selector. Explicit `set`
and `run` operations may allow native Keychain approval UI; global `--no-input`
disables it and fails closed.

Synchronizable/iCloud items are excluded because Apple does not support
persistent references for them. Internet-password and certificate/private-key
records are also deferred. Their identity, approval behavior, and delivery
semantics differ from legacy generic-password entries.

#### Deferred: 1Password

1Password is not part of the normative MVP. A later adapter should delegate to
the official `op` CLI, pin a documented supported version range, use exact
metadata-only discovery and field-only resolution commands, invoke no shell,
capture stdout internally, sanitize provider stderr, and reject duplicate or
ambiguous fields. Its authentication, network access, locking, and prompts are
provider-controlled and must be documented explicitly.

### 8.3 Extension strategy

The core will use a small in-process internal provider protocol with typed
results, cancellation behavior, and sanitized exceptions. It remains private
and unstable until two real adapters validate it. A public third-party plugin
API and external provider executables are deferred because their discovery,
trust, versioning, timeout, and secret-transport model require a separate
security design.

Likely future distribution model:

```text
ainv                         core CLI
ainv-provider-keychain       macOS provider, possibly bundled on macOS
ainv-provider-1password      optional provider
ainv-provider-bitwarden      future third-party provider
```

Possible plugin mechanisms include Python entry points and isolated provider
executables. The choice remains open. The design must account for the fact that
provider code is security-sensitive and will handle plaintext during
resolution. Installing a provider is equivalent to trusting it with any secret
it is allowed to resolve.

## 9. Dotenv mutation rules

The mutation engine must parse assignments rather than use regular-expression
line deletion alone.

Initial syntax to recognize:

```dotenv
NAME=value
NAME = value
export NAME=value
```

Requirements:

- Use variable grammar `[A-Za-z_][A-Za-z0-9_]*`.
- Match the complete variable name, never a prefix.
- Require UTF-8 and preserve an optional UTF-8 BOM.
- Reject mixed line endings; otherwise preserve CRLF or LF exactly.
- Preserve all unrelated text exactly.
- Reject duplicate target assignments and malformed target lines.
- Canonicalize only the assignment being inserted or replaced.
- Reject NUL, CR, and LF in a dotenv value; permit empty values and `=`.
- Handle an absent final newline safely.
- Reject malformed destinations before resolving the secret when possible.
- Resolve as late as possible and retain secret bytes for the shortest practical
  period.

### 9.1 Value encoding

Dotenv parsers disagree on multiline and escape semantics. The MVP will support
single-line values safely and reject values containing newlines with an
explanation rather than silently changing them.

For the MVP, write values only when they match the documented conservative
unquoted ASCII set. Reject values containing whitespace, quotes, backslashes,
comment markers, interpolation markers, or other characters requiring dotenv
quoting. Different dotenv implementations disagree on quoting and expansion;
silently changing a credential is worse than rejecting it.

Quoted, multiline, binary, and file-valued credentials are deferred until
compatibility tests against common Python and Node dotenv parsers define their
semantics explicitly. `ainv run` remains available for UTF-8 values that dotenv
materialization rejects.

## 10. Security model

### 10.1 Protected against by `ainv` itself

For successful built-in operations, `ainv` must not write resolved values to:

- its own stdout, stderr, logs, diagnostics, or tracebacks;
- command-line arguments;
- shell history generated by documented usage;
- clipboard contents;
- `ainv` logs, progress output, exceptions, or tracebacks;
- committed project configuration;
- plaintext backup files created by `ainv`.

Metadata-only discovery must not access secret data at all.

### 10.2 Explicitly not protected against

`ainv` does not prevent:

- an agent or process reading a materialized `.env` file;
- `ainv run` passing through child stdout/stderr containing the secret;
- a child process reading or printing its injected environment;
- a child process transmitting credentials over the network;
- another process with sufficient user privileges inspecting memory or files;
- a malicious or compromised provider adapter;
- provider-native tools being invoked directly by an agent;
- disclosure through application logs after delivery;
- metadata disclosure through search output;
- operating-system compromise.

### 10.3 Security boundary

The primary guarantee is:

> `ainv` delivers a selected secret to an explicit file or process without
> returning the value through its normal user-facing interface.

It does not guarantee:

> An arbitrary shell-capable agent can use a plaintext credential but cannot
> deliberately recover or misuse it.

A future proxy or capability broker would be a different product tier and is
outside the initial scope.

## 11. Failure behavior

Resolution and mutation should fail closed.

- Do not create or modify the destination when provider resolution fails.
- Do not start a child command unless all bindings resolve successfully.
- Delete temporary files after any pre-rename failure.
- Never include provider-returned values in error messages.
- Convert provider failures into typed, actionable errors.
- Before rename, failures preserve the original. After rename, a durability
  failure is reported but rollback is not guaranteed.

Suggested exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | Unexpected operational failure |
| 2 | Invalid CLI usage |
| 3 | No matching credential |
| 4 | Provider unavailable, locked, or unauthenticated |
| 5 | Access denied or approval cancelled |
| 6 | Unsafe or invalid destination |
| 7 | Invalid or unsupported secret value |

For `ainv run`, once the child starts, its exit code becomes the command's exit
code.

## 12. Privacy and telemetry

`ainv` will not include telemetry in the initial release. It must not send
queries, references, provider metadata, paths, command arguments, or usage data
to a project-operated service.

Provider-native tools may have their own telemetry and policies; documentation
should link to them without implying control by `ainv`.

## 13. Testing strategy

### 13.1 Unit tests

- metadata search and ranking;
- reference routing and validation;
- dotenv parsing, replacement, appending, permissions, and newline handling;
- atomic-write rollback paths;
- binding parsing and environment construction;
- JSON schemas and exit-code mapping;
- secret canaries absent from every captured output and exception.

Unit tests use fake providers and synthetic canary values.

### 13.2 Integration tests

Opt-in integration tests will cover:

- synthetic generic-password items in a temporary/test Keychain;
- locked, missing, duplicate, and denied Keychain items;
- a fake `op` executable before testing against a real throwaway 1Password vault;
- subprocess environment injection;
- Git ignored, tracked, and unignored destinations;
- interruption during atomic file replacement.

Integration tests must never access or enumerate the developer's real secret
values.

### 13.3 Adversarial tests

Maintain a canary-based leakage suite that searches stdout, stderr, exceptions,
logs, temporary files, process arguments, and generated artifacts for exact and
encoded secret values.

Document expected failures of the threat model, including that a child command
can execute `printenv` and that an agent can read a materialized `.env` file.
Those demonstrations prevent accidental overclaiming.

## 14. Implementation phases

### Phase 0: Package foundation

- Typer application, packaging, linting, tests, and release automation.
- Public documentation and explicit pre-alpha status.

### Phase 1: Keychain discovery

- Internal provider protocol.
- Attribute-only generic-password enumeration.
- `ainv providers` and `ainv find`.
- Human and JSON output.
- No secret resolution yet.

### Phase 2: Dotenv materialization

- Exact Keychain reference resolution.
- Safe dotenv parser and encoder.
- Atomic `ainv set` with permission and Git checks.
- Canary leakage tests.

### Phase 3: Process injection

- Binding parser and all-or-nothing resolution.
- Exec-style `ainv run`.
- Signal, TTY, and child-exit behavior tests.

### Phase 4: 1Password provider

- Optional provider distribution or extra.
- Metadata discovery through the official CLI.
- `op://` reference resolution.
- Locked and unauthenticated state handling.

### Phase 5: Extension API

- Stabilize the smallest provider contract supported by two real adapters.
- Choose entry points or executable plugins after a security review.
- Publish provider-author guidance and conformance tests.

## 15. Acceptance criteria for the first functional release

The first functional release is complete when:

1. A user can find an existing synthetic Keychain generic password from metadata
   alone.
2. `ainv` output and diagnostics contain no secret value; tests separately
   demonstrate that child output and materialized files are outside the
   guarantee.
3. A user can select the returned reference and atomically set one `.env`
   assignment without displaying the value.
4. A user can inject the same reference into one child process.
5. Denied, missing, malformed, duplicate, and interrupted operations fail
   without partial output or destination corruption.
6. Documentation states the security boundary and demonstrates its limitations.
7. The package installs and runs through `uv tool install ainv` on supported
   macOS versions.

## 16. Open decisions

The following should be resolved through prototypes rather than speculation:

1. Whether Keychain support remains in the core package after other platforms
   or providers are supported.
2. Exact dotenv compatibility targets beyond the documented MVP grammar.
3. Whether Git overrides should require interactive approval in addition to an
   explicit flag.
4. Minimum supported macOS version.
5. Package license and public author identity.
6. Third-party provider mechanism, deferred until after 1Password validates the
   internal abstraction.
