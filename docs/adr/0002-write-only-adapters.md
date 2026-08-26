# ADR-0002: Vault adapters are write-only

Status: accepted (2026-08-26)

## Context

An intercepted value has to go somewhere the user can reach later. Every convenient design
for that (a local file, the macOS Keychain, a `get()` on the adapter) creates a read path
that the agent, running under the user's UID, can call as easily as the user.

Measured on macOS: `security find-generic-password -w` returns an item's value without any
consent dialog, even for an item created with `-T ''` or with a foreign trusted
application. The Keychain is not a vault against a same-UID process.

## Decision

The `VaultAdapter` protocol exposes `available()` and `store(name, value)`. Nothing else.
A test (`NoReadPathInvariant`) fails if any adapter class grows a method named `get`,
`read`, `fetch`, `load`, `reveal`, `export` or `dump`, or if adapter source code mentions a
vault read command.

Values are passed to vault CLIs on stdin, never on argv, so they never show in `ps`.
Error messages are redacted of the value before they surface.

## Consequences

- OhMyPrivacy cannot help the agent use a secret. That is the point: consumption happens by
  injection (`doppler run -- <binary>`) or by the user, never by reading.
- A vault whose CLI can read (Doppler on a logged-in machine) is still readable through the
  CLI. ADR-0006 narrows that; ADR-0003 explains why `age` is safer on a workstation.
