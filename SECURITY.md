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

`ainv` is intended to keep resolved values out of its own output, diagnostics,
command arguments, and clipboard workflows. A value written to a file can be
read by processes with access to that file. A value injected into a child
process can be read, printed, or transmitted by that process.

See [SPEC.md](SPEC.md) for the complete security model.
