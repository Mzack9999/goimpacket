# Contributing to goimpacket

Contributions are welcome. This document covers what you need to know before
opening an issue or pull request.

## Reporting Bugs

Before filing a bug report, please run the same operation with
[Impacket](https://github.com/fortra/impacket) side by side. Because goimpacket
implements the same wire protocols, many apparent bugs turn out to be
**environmental** — patched DCs, LDAP signing, EPA, PKT_INTEGRITY, NTLM MIC
validation, missing SPNs, time skew, DNS issues, and so on.

- **If Impacket fails the same way**, the issue is almost certainly
  environmental. Check [KNOWN_ISSUES.md](KNOWN_ISSUES.md) before filing.
- **If Impacket succeeds where goimpacket fails**, that's a real bug and
  exactly what we want to hear about.

### What to include in a bug report

1. Both outputs (goimpacket with `-debug` and Impacket), as **text** not
   screenshots
2. The exact command line you ran
3. Target OS, AD functional level, and any relevant hardening (signing,
   EPA, channel binding, patch level)
4. goimpacket version or commit hash

### Anonymize sensitive data

GitHub issues are public. Before posting, strip or replace real hostnames,
IP addresses, usernames, password hashes, Kerberos tickets, domain names,
SIDs, and anything that could be tied back to a real engagement. Replacing
`corp.internal` with `example.local` is fine — keep the structure, just
not the identifying values. **If in doubt, redact it.**

[Open a bug report](https://github.com/Mzack9999/goimpacket/issues/new)

## Feature Requests

Open a [GitHub issue](https://github.com/Mzack9999/goimpacket/issues/new)
describing the use case and the Impacket equivalent (if any). If the feature
is on the "Missing Features" list in the README, mention which one — it
helps us prioritize.

## Pull Requests

### Before you start

- For non-trivial changes, open an issue first to discuss the approach.
  This avoids wasted effort if the design needs adjustment.
- Keep changes focused — separate refactors from feature work and bug fixes.

### Requirements

Before opening a PR, make sure all of the following pass cleanly:

```bash
go build ./...
go vet ./...
gofmt -l .
go test ./...
```

### Style guidelines

- Match the existing code style in the package you're touching.
- Don't add unrelated formatting changes, import reordering, or
  comment rewrites to a functional PR — it makes review harder.
- Keep error messages lowercase and without trailing punctuation,
  per Go convention.
- Use `build.Debugf()` for debug output, not `fmt.Println`.

### Commit messages

- Use a short, imperative subject line (under 50 characters if possible).
- Explain *why* in the body, not *what* — the diff shows the what.
- Reference the GitHub issue number if one exists (e.g. `Fixes #42`).

### Review process

All PRs are reviewed before merge. Expect feedback on correctness,
style, and security implications — this is a security tool, so edge
cases in protocol handling matter.

## Security Vulnerabilities

If you find a security vulnerability **in goimpacket itself** (not a protocol
limitation), please report it responsibly. Do **not** open a public GitHub
issue. Instead, use GitHub's private vulnerability reporting:

https://github.com/Mzack9999/goimpacket/security/advisories/new

## License

By contributing to goimpacket, you agree that your contributions will be
licensed under the [Apache License 2.0](LICENSE).
