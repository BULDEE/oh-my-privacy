# ADR-0005: Tamper resistance through Claude Code managed settings

Status: accepted (2026-08-26)

## Context

A hook declared in `~/.claude/settings.json` is only as durable as that file. The agent
runs under the user's UID and can edit it, delete the plugin directory, or set
`disableAllHooks: true`. A client-side guard that the guarded process can switch off
protects against accidents only.

Two facts were verified in Claude Code 2.1.246:

1. The hook resolution function returns the managed `hooks` even when the user's settings
   set `disableAllHooks: true`.
2. Managed settings are read from `/Library/Application Support/ClaudeCode/managed-settings.json`
   and `managed-settings.d/*.json` (Linux: `/etc/claude-code/`), directories writable by
   root only. `sudo` without a terminal fails, so the agent's shell cannot write there.

## Decision

`install/install-managed.sh` (run with `sudo`) copies `omp/` and `hooks/` to
`/usr/local/lib/oh-my-privacy` owned by `root:wheel`, read-only for the user, and writes a
drop-in `50-oh-my-privacy.json` declaring both hooks plus `disableAllHooks: false`.

The user-level configuration (`~/.claude/omp.json`) stays user-writable: it only chooses the
vault, it never decides whether a block happens.

## Consequences

- With the managed installation, the agent can neither remove nor edit the guard.
- The user-level entries must be removed after the managed install, or the hooks run twice.
- A local administrator can still undo the policy, by design: that is the user, not the agent.
