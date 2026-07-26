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

## Recovery and cleanup

If a credential is exposed, revoke or rotate it with the remote issuer first.
Removing its local Keychain item does not revoke it remotely. For private
dogfood, remove `ainv`-created items manually in Keychain Access by their
service, account, and label. A materialized dotenv entry may also be removed
manually, but an agent must not read the dotenv file to do so.

A Keychain reference is an opaque local locator, not portable project
configuration. It can become stale after identity metadata changes or deletion;
search again if it no longer resolves.

See [SPEC.md](SPEC.md) for the complete security model and reference lifecycle.
