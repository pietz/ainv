# Security policy

`ainv` handles credentials and should be treated as security-sensitive software.
It is currently a pre-alpha development project and has not received an
independent security audit.

## Reporting a vulnerability

Please do not open a public issue containing credential material or exploit
details. Contact the maintainer privately through the security-reporting method
listed on the GitHub repository.

Never include real credentials in a report. Use synthetic canary values and
rotate any credential that may have been exposed.

## Security boundary

`ainv` reduces accidental credential exposure by keeping resolved values out of
its normal output, diagnostics, command arguments, and clipboard workflows. A
value written to a file can be read by processes with access to that file. A
value injected with `ainv run` can be read, retained, printed, transmitted, or
otherwise exposed by the selected process, its descendants, dependencies, crash
reporters, telemetry, or anything it invokes. `ainv` does not make untrusted
agents, repositories, dependencies, or commands safe. Use `ainv run` only for
an intended, trusted consumer and avoid debug or environment-dumping modes;
this guidance is not an enforcement boundary.

## Optional human-consent popup

When `approval = "always"`, `ainv run` and `ainv set` display one native AppKit
dialog after destination validation and before secret resolution. The dialog
contains only credential metadata and delivery context. It uses native process
ancestry and running-application metadata to show the nearest bundled ancestor,
with a neutral fallback otherwise. This best-effort context may be absent or
inaccurate and is not authenticated identity. Denial prevents Keychain
resolution and delivery. `--no-input`, invalid configuration, and an unavailable
graphical session fail closed.

This is an oversight and accidental-use control, not an authorization boundary.
A shell-capable process running as the user can edit the configuration, bypass
`ainv`, invoke provider-native tools, or potentially automate ordinary UI when
it has Accessibility privileges. The Python-hosted dialog is also not a stable,
signed application identity. A hard permission boundary would require a signed
native broker that owns both approval and delivery.

## Local activity-history privacy

Activity history is enabled by default and records the authorization decision
for each validated `run` and `set` request before any provider resolves a
secret. It is explicitly not a security audit: records are append-written, but
a same-user process can disable, modify, delete, replace, or bypass the history;
it is neither immutable nor tamper-evident. A record does not claim that
resolution, delivery, command execution, or recipient behavior completed.
Readers and writers retry advisory-lock contention within a bounded 7 ms sleep
budget. Residual write contention warns without preventing an otherwise approved
delivery; residual read contention fails through the normal generic read error.

Records contain no secret values, resolved environments, child output, or full
command arguments. A command destination contains only its executable name or
path and argument count. Records do contain credential references, destination
variable names, file or executable paths, working directories, outcomes,
reasons, truncation metadata, and best-effort requester application identity.
This operational metadata may reveal accounts, tools, projects, and usage
patterns to another process with local account access. Every field is bounded;
large binding sets retain the total count, a bounded subset, and explicit
omission, truncation, and filesystem-text escaping metadata.

The fixed passwd-derived path is
`~/Library/Application Support/ainv/history.jsonl`; `HOME` is not trusted. The
private file and directory reject unsafe ownership, symlinks, hard links, and
permissions. Size-bounded rotation preserves at most one private backup. Reads
validate every line independently. Malformed and partial lines are skipped with
only a value-free count exposed, and appends recover a partial tail by starting
the next record on a fresh line. Filesystem safety failures remain hard errors.
`ainv config --history off` disables future records. The harmless
`config --test-popup` operation is excluded.

## Current macOS Keychain authorization limitation

In the current `uv tool` Python distribution, macOS Keychain authorizes the
uv-managed Python interpreter executable, not the `ainv` console script or the
terminal. An `ainv`-created generic-password item receives the default creator
ACL for that interpreter. Therefore, another script using that exact interpreter
may retrieve such an item without a new Keychain prompt. This was observed with
a synthetic item and is broader access than the `ainv` command name suggests.

For a pre-existing item, choosing **Always Allow** is expected to authorize the
shared interpreter for future retrieval without further notice. Choose **Allow
Once**, not **Always Allow**, when an expected operation prompts. Allow Once
does not make the current distribution a stable or least-privilege Keychain
identity, and it does not remove the creator interpreter's access to an
`ainv`-created item.

The current interpreter is ad-hoc signed with a cdhash-based designated
requirement. A different Python patch version was denied access in testing, so
upgrades can cause authorization failures or renewed prompts. A dialog may
identify `python3.13` rather than `ainv`; exact dialog wording has not been
observed. `ainv find` is metadata-only and cannot prompt, while secret
resolution for `ainv set` or `ainv run` can prompt.

Version 0.3.0 remains a pre-alpha evaluation release. Do not use the current
Python distribution as a stable, least-privilege Keychain identity for
unattended high-value credentials. A stable Developer ID-signed native identity
is required before a stable release.

## Hidden credential entry

`ainv add` accepts a value through exactly one hidden interactive terminal
prompt. A human may paste a newly issued credential from a browser into that
prompt. It fails closed if it cannot disable terminal echo. Success output
labels a readable service/account credential ID as non-secret metadata, not a
credential value. Agents must never read, inspect, or manipulate the clipboard,
and must never provide a credential through stdin, arguments, chat, or tool
output.

## Recovery and cleanup

If a credential is exposed, revoke or rotate it with the remote issuer first.
Removing its local Keychain item does not revoke it remotely. For private
dogfood, remove `ainv`-created items manually in Keychain Access by their
service, account, and label. A materialized dotenv entry may also be removed
manually, but an agent must not read the dotenv file to do so.

A readable Keychain ID contains service and account metadata and resolves only
when that pair identifies exactly one item. It is not portable project
configuration and may disclose operational metadata. Legacy opaque references
remain local locators and can become stale after identity metadata changes or
deletion. Search again if an identity no longer resolves.

See [SPEC.md](SPEC.md) for the complete security model and reference lifecycle.
