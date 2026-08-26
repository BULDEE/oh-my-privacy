# ADR-0003: Three storage levels, discard by default, age recommended on workstations

Status: accepted (2026-08-26)

## Context

Users run OhMyPrivacy on machines the plugin knows nothing about: some have a secrets
manager CLI logged in, some have nothing. A fallback that is weaker than "no storage" (a
plaintext file, the Keychain) would turn a block into a delayed leak.

## Decision

| Level | `vault` | Behaviour |
|---|---|---|
| 3 | `discard` | Default. The value lives in the hook's memory and dies with the process. Nothing on disk. |
| 2 | `age` | Public-key encryption at write time; the private identity is passphrase-encrypted and decryption prompts on `/dev/tty`. |
| 1 | `doppler` | `doppler secrets set NAME`, value on stdin, silent output. |

Any misconfiguration (unknown vault, missing option, CLI not installed, unreadable config
file) degrades to `discard`, never to pass-through.

`python3 -m omp.setup` recommends `age` first when the CLI is present. Choosing `doppler`
prints a warning that a logged-in CLI can read the vault back.

## Rationale

The agent's shell tool has no terminal. A passphrase prompt on `/dev/tty` is therefore the
only local lock that holds against a process running under the user's own UID without
relying on a denylist. That makes level 2 strictly safer than level 1 on a workstation.
Level 1 exists for what has to be shared with a team or a deployment.

## Consequences

- No credential is ever written by OhMyPrivacy: Doppler authentication stays with
  `doppler login`, the age identity is protected by a passphrase the user types at setup.
- Adding a vault means one class with `available()` and `store()`, registered in
  `omp/adapters/__init__.py`, plus a conformance run of `NoReadPathInvariant`.
