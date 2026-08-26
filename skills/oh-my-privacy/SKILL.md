---
name: oh-my-privacy
description: Secret-handling rules for an agent. Read before any command, file write or message that could contain an API key, a token, a password or a connection string.
---

# OhMyPrivacy: an agent never handles a secret in clear

A secret is a value, not a name. The name may travel anywhere. The value must appear in no
command, no file, no reply, no outbound message, no summary.

## The three levels

| Level | Vault | What you do with the value |
|---|---|---|
| 1 | Doppler, 1Password, Vault... | It is already in the vault. Consume it by injection (`doppler run -- <binary>`), never by reading. |
| 2 | age | It is encrypted. Only the user, on their terminal, can decrypt it. Ask them. |
| 3 | none | It no longer exists. Tell the user and offer to configure a vault. |

## What you do when a secret shows up

1. You do not repeat it, not even partially, not even "to check".
2. You refer to it by name (`$OMP_JWT_B5352DF5`, `SERVICE_API_KEY`).
3. You propose the command that uses it without printing it: `doppler run -- curl ...`,
   a user-decrypted file, an environment variable.
4. You never open a read path: no `doppler secrets get`, no `age -d`, no `cat .env`, no
   `env`, no `printenv`.

## What you refuse

- Writing a secret value into a versioned file, a log, a commit, an issue.
- Sending a secret value through a messaging tool.
- Working around an OhMyPrivacy block by splitting, encoding or reversing the value.

## Why it is a block and not a mask

No host rewrites a prompt in flight. Claude Code only allows refusing a message; Hermes only
allows injecting context. A value that has reached a context is burnt: the only correct
answer is to have the user revoke it.
