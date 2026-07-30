# ainv specification

Status: Draft 0.4.0 pre-alpha

Target: Narrow public dogfood release with a hard validation threshold

## 1. Purpose

`ainv` is an agent-operated credential handoff utility: agents select readable,
value-free credential IDs, and intended processes or dotenv files receive
credential values. It is a small, stateless CLI that delivers credentials from
existing providers to an explicit destination without printing the value.

It is designed for ad hoc work, initial project onboarding, and conventional
dotenv materialization. No project initialization or manifest is required:

```console
ainv find openai
ainv set keychain:OPENAI_API_KEY@personal --file .env
ainv run keychain:OPENAI_API_KEY@personal -- command
```

Credential providers remain the source of truth. `ainv` owns neither secret
storage nor encryption.

## 2. Product principles

1. **Safe by default.** `ainv` reduces accidental credential exposure by never
   writing resolved values to its own stdout, stderr, logs, diagnostics, or
   arguments. Child output remains outside this guarantee.
2. **No project state.** Discovery and delivery require no project files.
   Optional user-level controls and default local activity history remain outside
   projects.
3. **Provider-owned values.** Providers remain the source of truth, while
   authentication, metadata, approval behavior, and failures remain
   provider-specific. Provider breadth is not a product goal.
4. **Explicit delivery.** Every operation names its destination and variable.
5. **Agent legible.** Help text, structured output, and errors explain the next
   valid action without requiring a large prompt or skill.
6. **Unix compatible.** Commands compose naturally, preserve TTY behavior, and
   use meaningful exit codes.
7. **Honest security.** `ainv` prevents accidental disclosure, not deliberate
   exfiltration by a process that receives or can read a secret.
8. **Small trusted core.** The project does not implement a vault, cryptography,
   cloud service, daemon, or synchronization system.
9. **Optional human oversight.** A user may require one value-free native
   consent dialog before each delivery. This is an accidental-use control, not
   containment against a shell-capable process.
10. **Honest local history.** Default value-free activity history describes an
    authorization decision, not completed delivery and not a security audit.

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
- **Credential ID:** A readable, non-secret provider/service/account identity
  used for normal selection and delivery.
- **Legacy reference:** An opaque provider locator retained for compatibility
  and rare disambiguation. Its scope and lifecycle are provider-specific.
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
terminal rendering to prevent control-character, terminal-sequence, or Rich
markup injection. The human table prefers readable credential IDs and
abbreviates unusually long IDs by preserving a substantial prefix and final
characters. JSON retains the exact readable ID and legacy opaque reference.

Example human-readable output:

```text
CREDENTIAL ID                       PROVIDER  SERVICE         ACCOUNT   LABEL
──────────────────────────────────  ────────  ──────────────  ────────  ──────────────
keychain:OPENAI_API_KEY@personal    keychain  OPENAI_API_KEY  personal  OpenAI API key
```

Search is case-insensitive across provider-approved metadata fields. It never
requests or returns secret data.

Machine-readable output:

```console
ainv find openai --json
```

```json
{
  "schema_version": 2,
  "query": "openai",
  "partial": false,
  "matches": [
    {
      "id": "keychain:OPENAI_API_KEY@personal",
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

### 5.2 Add one credential to a provider

```console
ainv add OPENAI_API_KEY --provider keychain --account personal
```

`OPENAI_API_KEY` maps to the native Keychain service field. `--account` maps to
its account field, and optional `--label` maps to its display label. The command
accepts the secret only through exactly one hidden prompt in an interactive
terminal. It provides no value option and reads no secret from stdin. A human
may paste a newly issued credential from a browser into that prompt. Agents
must never read, inspect, or manipulate the clipboard. The prompt fails closed
instead of accepting input if it cannot disable terminal echo.

Creation is an optional provider capability. The Keychain provider creates one
non-synchronizable generic-password item in the default legacy Keychain,
returns both readable and persistent identities, and never replaces a
duplicate. Success output labels the readable credential ID as non-secret to
distinguish it from a credential value. Global `--no-input` fails before
prompting.

### 5.3 Materialize credentials into a dotenv file

The default destination is `.env` in the current working directory. A readable
Keychain service that is a valid environment-variable name is inferred:

```console
ainv set keychain:OPENAI_API_KEY@personal
```

Explicit destination names and multiple all-or-nothing bindings are supported:

```console
ainv set \
  API_KEY=keychain:OPENAI_API_KEY@personal \
  keychain:DATABASE_URL@work \
  --file .env.local
```

Behavior:

- Variable names use `[A-Za-z_][A-Za-z0-9_]*` in both `set` and `run`.
- Require a UTF-8 destination, optionally with a UTF-8 BOM.
- If no target assignment exists, append it at the bottom.
- Treat `NAME=`, whitespace-only values, `NAME=""`, and `NAME=''` as empty
  placeholders and fill them without an override. Treat comment-bearing
  assignments conservatively as populated.
- Refuse a populated target before resolving any credential unless `--force`
  is passed. Agents require informed user approval before using `--force`.
- Reject duplicate target assignments and malformed target lines before
  resolving any credential.
- Resolve every binding before mutation and replace the destination exactly
  once. Any failure leaves all target assignments unchanged.
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

`--force` only permits replacement of populated assignments. It never bypasses
Git, ownership, link, destination-type, or permission protections. Legacy
`ainv set REF --as NAME` syntax remains accepted during the pre-alpha period.

### 5.4 Inject selected secrets into one child process

```console
ainv run keychain:OPENAI_API_KEY@personal -- npm run dev
```

Multiple bindings are accepted:

```console
ainv run \
  API_KEY=keychain:OPENAI_API_KEY@personal \
  keychain:DATABASE_URL@work \
  -- npm run dev
```

Behavior:

- Infer a destination only from readable IDs whose service is a valid,
  non-sensitive environment-variable name. Require explicit `NAME=CREDENTIAL`
  syntax for execution-sensitive names such as `PATH`, language startup hooks,
  and dynamic-loader variables.
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
breaking terminal behavior or providing a false security guarantee. The selected
process, its descendants, dependencies, crash reporters, telemetry, and anything
it invokes can read, retain, print, transmit, or otherwise expose any secret it
receives. Users and agents should provide credentials only to an intended,
trusted consumer and avoid debug or environment-dumping modes. This guidance is
not an enforcement boundary.

### 5.5 Inspect available providers

```console
ainv providers
```

```text
PROVIDER  STATUS  SOURCE
keychain  ready   built-in
```

Machine-readable output is available through `--json`.

### 5.6 Configure human approval

```console
ainv config --approval always
ainv config --approval off
ainv config
ainv config --test-popup
```

Configuration is stored at
`~/Library/Application Support/ainv/config.toml`. `off` is the default. In
`always` mode, `run` and `set` display one AppKit dialog after destination
validation and before provider resolution. The dialog is titled **ainv Access
Requested**. It walks native process ancestry and shows the nearest bundled
application reported by `NSRunningApplication`, with that application's icon
when available. It does not use environment claims for requester attribution.
Failure to find a bundled ancestor produces a neutral unidentified-application
label and no custom requester icon. This best-effort context is informational,
not an authenticated process identity, and may be absent or inaccurate.

One dialog covers up to ten bindings and shows credential IDs, destination
variables, target command or file, and working directory without secret values.
Control characters and Unicode line separators are escaped. Context that cannot
be displayed completely within strict bounds fails closed rather than being
truncated. The only decisions are **Deny** and **Allow Once**. The Return key
equivalent and default button cell are cleared for **Allow Once**, Escape
selects denial, and every response other
than an explicit **Allow Once** denies. Denial starts no command, resolves no
credential, and mutates no file.

`--no-input`, malformed or unsafe configuration, and unavailable graphical UI
fail closed. `--test-popup` exercises only the dialog and accesses no provider.
The configuration file and its directory require user-only permissions and
reject unsafe ownership and links; writes are atomic. Parsing remains strict.
Malformed TOML and unknown settings are never silently discarded by an update.
`ainv config --reset` is the narrow, explicit repair path: it replaces the file
with safe defaults, cannot be combined with other config options, and does not
weaken filesystem checks. Writers omit the default `history = "on"` key so
approval-only files remain compatible with older strict versions where
possible. This improves human oversight but is not a hard boundary because a
same-user shell process can edit configuration or bypass `ainv` entirely.

### 5.7 Inspect local activity history

```console
ainv history
ainv history --limit 50
ainv history --json
ainv config --history on
ainv config --history off
```

History is enabled by default. For every `run` and `set` request that passes
destination validation, record the authorization outcome before provider secret
resolution: `allowed`, explicit `denied`, `not_requested` when approval is
disabled, or `error` when authorization could not be completed. Reasons include
`user_allowed`, `user_denied`, `approval_disabled`, `approval_unavailable`,
`interactive_input_disabled`, `too_many_bindings`, and
`working_directory_unavailable`. `config --test-popup` is excluded.

Each versioned JSONL record contains the timestamp, action, outcome and reason,
credential references and destination variable names, working directory, a safe
destination summary, and best-effort requester application identity when
available. Resolve requester identity once per authorization; the dialog and
record use that same result. Every metadata field is byte-bounded. A large
binding set retains its total count, a bounded subset, an omitted count, and
explicit field-truncation or filesystem-text escaping metadata. A run summary
stores only `command[0]` and
the count of remaining arguments. It must never store argument contents,
resolved values or environments, child stdout or stderr, or any claim that
resolution, delivery, execution, or recipient behavior completed. Set records
use the canonical destination file path.

The fixed passwd-derived location is
`~/Library/Application Support/ainv/history.jsonl`; `HOME` is never trusted.
Create its directory and file with modes `0700` and `0600`. Reject unsafe
ownership, symlinks, hard links, group/world permissions, and non-regular files.
Append-write one bounded record under an advisory lock acquired with
nonblocking attempts and a bounded 7 ms retry sleep budget. Shared read-lock
acquisition uses the same budget. Cap the active file at 1 MiB and retain at most
one private rotated backup. Append-writing and rotation do not provide
immutability or tamper evidence. Reads strictly validate each JSONL line,
skip malformed, oversized, or partial records, and expose only a count of
invalid records. A future append starts on a new line after a partial tail.
Unsafe paths, ownership, links, permissions, or file types remain hard errors.

History write failure, including contention after bounded retries, is non-fatal
to credential delivery: emit only a generic stderr warning, without native
exception details, and continue an otherwise authorized operation. Read
contention after bounded retries fails through the normal generic read error. The
human view is compact and emits a generic malformed-record
warning when needed. JSON output has the normal CLI schema version, includes
independently versioned records, and exposes `invalid_record_count`. History is local
operational metadata, not a security audit: a same-user process can disable,
edit, delete, or bypass it. Documentation must call out that references,
accounts, paths, executables, requester context, and usage patterns may be
private even without secret values.

## 6. CLI contract

Initial command surface:

```text
ainv [--no-input] find QUERY [--provider NAME] [--limit N] [--json]
ainv [--no-input] add SERVICE --provider NAME --account ACCOUNT [--label LABEL]
ainv [--no-input] set [NAME=]CREDENTIAL... [--file PATH] [--force] [--allow-unignored] [--allow-tracked]
ainv [--no-input] run [NAME=]CREDENTIAL... [--] COMMAND [ARG ...]
ainv providers [--json]
ainv history [--limit N] [--json]
ainv config [--approval off|always] [--history on|off] [--test-popup] [--reset]
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
  It is supported by `find`, `providers`, and `history`.
- JSON success documents include `schema_version: 2`. Runtime JSON failures use
  `{\"schema_version\": 2, \"error\": {\"code\": ..., \"message\": ...}}`.
  Typer/Click usage errors occur before command execution and retain their
  normal human-readable form in the MVP.
- Prompts are forbidden in `--json` mode.
- Global `--no-input` fails rather than triggering the hidden `add` prompt,
  `ainv` consent UI, or provider-controlled authentication/approval UI. `ainv` never reads secret
  values from stdin. A piped or non-TTY stdin does not implicitly disable native
  Keychain approval UI because coding-agent subprocesses commonly lack a TTY;
  automation that forbids UI must pass `--no-input` explicitly.
- Metadata discovery must never request secret data or trigger Keychain approval
  UI, including outside `--json` mode.
- A locked or unavailable provider exits 4. Explicitly denied or cancelled
  secret access exits 5.
- Debug logging must never include resolved values, child environments, or
  credential-bearing temporary-file contents.
- Credential IDs and legacy references may appear in output and logs because
  they are non-secret handles, although they can disclose operational metadata.

## 7. Credential identities

The normal Keychain ID is:

```text
keychain:<percent-encoded-service>@<percent-encoded-account>
```

For example:

```text
keychain:OPENAI_API_KEY@personal
```

Resolution first performs an exact metadata-only service/account lookup with
Keychain authentication UI disabled. It proceeds only when exactly one
persistent reference is returned, then resolves that opaque locator through the
normal delivery path. It never chooses an arbitrary first match. Components are
strict UTF-8 and canonical percent encoding; malformed or non-canonical IDs are
rejected.

Legacy references remain accepted:

```text
keychain://v1/item/PERSISTENT_REF
```

The opaque token is Apple's persistent item reference encoded as unpadded
base64url. It contains no descriptive service/account fields. Both identity
forms are non-secret metadata, but neither is portable project configuration or
a unique identifier for one immutable credential incarnation.

### 7.1 macOS Keychain reference lifecycle

A canonical Keychain reference is an opaque local Keychain locator. Apple
documents persistent references as `CFData` that may be stored and passed
between processes. Apple does not promise portability across Keychains,
machines, migration, restore, sync, app identities, or access groups, and does
not promise stability across updates.

The following behavior was observed, not guaranteed, on macOS 15.7.7 arm64 in
an isolated temporary file Keychain:

- Updating secret data or the label preserved the reference, and the reference
  resolved the updated data.
- Updating service or account changed the reference and invalidated the prior
  reference.
- Deletion invalidated the current reference at that time.
- Recreating a generic-password item with the same final service and account
  produced the same reference bytes, so an old reference could resolve the
  recreated item.

Consequently, a reference can become stale after identity metadata changes or
deletion, and it must not be treated as a permanent identity for one credential
instance. On resolution failure, search again and use the newly returned
canonical reference. `ainv` has no `replace` or `remove` command in the MVP.

### 7.2 Manual cleanup and exposure recovery

For private dogfood, cleanup is manual through Keychain Access. A user can
identify an `ainv`-created item by its service, account, and label and remove it
there. A user can also manually remove a materialized dotenv entry, but agents
must not read the dotenv file to do so.

If a credential is exposed, revoke or rotate it at the remote issuer first.
Removing the local Keychain item does not revoke the credential remotely.

## 8. Provider model

### 8.1 Required provider capabilities

Every provider declares explicit capabilities. The common operations are:

1. `status`: Report whether the provider is installed, authenticated, locked, or
   unavailable without returning credentials.
2. `search`: Return metadata, readable IDs, and legacy references without
   requesting secret data.
3. `resolve`: Resolve one exact credential identity to secret bytes for an
   explicit delivery operation.
4. Optional `create`: Store one new credential through secure human input.

The internal registry maps provider names and credential prefixes to trusted
factories. Version 0.4.0 ships only the Keychain provider and loads no third-party
code. `ainv` owns no credential storage and does not update, delete, rotate, or
synchronize credentials.

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

##### Current distribution authorization limitation

Version 0.4.0 remains a pre-alpha evaluation release. In the current `uv tool`
Python distribution, Keychain authorizes the uv-managed Python
interpreter executable, not the `ainv` console script or terminal. An
`ainv`-created generic-password item receives the interpreter's default creator
ACL. An unrelated script using that exact interpreter was observed to retrieve a
synthetic item without a prompt. For a pre-existing item, **Always Allow** is
expected to authorize the shared interpreter for future retrieval without
further notice. **Allow Once** is the interim guidance for an expected prompt,
but it does not remove the creator interpreter's access or make the distribution
a stable, least-privilege identity.

The current interpreter is ad-hoc signed with a cdhash-based designated
requirement. A different Python patch version was denied during testing, so
upgrades can cause authorization failures or renewed prompts. A Keychain dialog
may identify `python3.13` rather than `ainv`; exact wording has not been
observed. Metadata-only `find` cannot prompt, while resolution can prompt.

Before a stable release, the project must investigate and adopt a stable,
least-privilege, Developer ID-signed native Keychain authorization identity.
Whether that takes the form of a native executable, helper, or another
architecture remains open. No implementation language or packaging approach is
selected by this requirement.

Synchronizable/iCloud items are excluded because Apple does not support
persistent references for them. Internet-password and certificate/private-key
records are also deferred. Their identity, approval behavior, and delivery
semantics differ from legacy generic-password entries.

### 8.3 Provider scope

Provider breadth is explicitly deferred. `ainv` will not compete with fnox,
Varlock, SecretSpec, or vault products on integrations. The private protocol
remains only an internal boundary. A second provider requires demonstrated
repeated demand and a separate security review because provider code handles
plaintext during resolution.

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
- the selected process, its descendants, dependencies, crash reporters,
  telemetry, or anything it invokes reading, retaining, printing, transmitting,
  or otherwise exposing its injected environment;
- another process with sufficient user privileges inspecting memory or files;
- a malicious or compromised provider adapter;
- provider-native tools being invoked directly by an agent;
- a same-user process editing approval configuration or bypassing `ainv`;
- ordinary approval UI being automated by a process with Accessibility access;
- disclosure through application logs after delivery;
- metadata disclosure through search output;
- operating-system compromise.

### 10.3 Security boundary

The primary guarantee is:

> `ainv` delivers a selected secret to an explicit file or process without
> returning the value through its normal user-facing interface.

It does not guarantee:

> An arbitrary shell-capable agent, repository, dependency, or command can use
> a plaintext credential but cannot deliberately recover, retain, transmit, or
> misuse it.

A future proxy or capability broker would be a different product tier and is
outside the initial scope.

## 11. Failure behavior

Resolution and mutation should fail closed.

- Do not resolve credentials, create or modify the destination, or start a
  child command when configured human approval is denied or unavailable.
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
to a project-operated service. Default local activity history remains on the
user's machine and is subject to the privacy and integrity limits in section
5.7.

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
- enabled and disabled history, all authorization outcomes, ordering, privacy,
  path safety, permissions, rotation, corruption, bounded records, bounded lock
  retries, and non-blocking-delivery write failures;
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

### Phase 2: Keychain creation

- Provider registry and explicit capabilities.
- One hidden interactive input prompt.
- Native generic-password creation with duplicate refusal.
- Readable service/account ID output plus legacy persistent references.
- Isolated integration tests.

### Phase 3: Dotenv materialization

- Exact readable-ID and legacy-reference Keychain resolution.
- Safe dotenv parser and encoder.
- Atomic `ainv set` with permission and Git checks.
- Canary leakage tests.

### Phase 4: Process injection

- Binding parser and all-or-nothing resolution.
- Exec-style `ainv run`.
- Signal, TTY, and child-exit behavior tests.

### Phase 5: Narrow product validation

- Dogfood readable discovery, optional native approval, and delivery across ad
  hoc tasks.
- Validate repeated external use before adding destinations or providers.
- Keep shell sessions, MCP, manifests, policy engines, and provider plugins out
  of scope.
- Investigate a stable signed native identity only if usage justifies broader
  public promotion.

## 15. Acceptance criteria for the first functional release

The first functional release is complete when:

1. A user can add and find a synthetic Keychain generic password without
   exposing its value through CLI output.
2. `ainv` output and diagnostics contain no secret value; tests separately
   demonstrate that child output and materialized files are outside the
   guarantee.
3. A user can select a returned readable ID and atomically set one or more
   `.env` assignments without displaying values.
4. A user can inject the same readable ID into one child process.
5. Denied, missing, malformed, duplicate, and interrupted operations fail
   without partial output or destination corruption.
6. Documentation states the security boundary and demonstrates its limitations.
7. The package installs and runs through `uv tool install ainv` on supported
   macOS versions.

## 16. Open decisions

The following should be resolved through prototypes rather than speculation:

1. Exact dotenv compatibility targets beyond the documented grammar.
2. Whether Git or populated-value overrides should require interactive approval
   in addition to explicit flags.
3. Minimum supported macOS version.
4. Package license and public author identity.
5. Whether repeated usage justifies moving approval and delivery into a stable,
   signed native broker.
