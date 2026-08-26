# ADR-0007: Hermes integration through a native plugin, not the portable package

Status: accepted (2026-08-26)

## Context

Hermes Agent loads two kinds of extensions. Portable "Agent Plugins v1" packages
(`plugin.json`, `skills/`, `mcp.json`) are host-agnostic but carry no execution hooks.
Native plugins (`plugin.yaml` + `register(ctx)`) can subscribe to lifecycle hooks, of which
only `pre_tool_call` has veto power (`{"action": "block"}`); `pre_llm_call` can inject
context but cannot refuse or rewrite the user message; `post_llm_call` is observe-only.

Hermes already strips environment variables from subprocesses and redacts logs and tool
outputs (`agent/redact.py`). What it lacks is a check on what the agent is about to do.

## Decision

Ship both, with distinct promises:

- `hermes/` is a native plugin. `pre_tool_call` refuses any tool call whose arguments
  contain a secret in clear (command, code, file content, outbound message) after storing
  the value through the configured level. `pre_llm_call` stores a secret pasted by the
  user and injects a strict do-not-repeat instruction with the cleaned message.
- The repository root `plugin.json` + `skills/oh-my-privacy/SKILL.md` form the portable
  package: rules for the agent, no enforcement.

Configuration uses the plugin's own settings namespace (`vault`, `doppler_project`,
`doppler_config`, `age_recipient`, `age_store_dir`, `scan_tools`).

## Consequences

- On Hermes, a secret pasted by the user reaches the model for that turn. This is a host
  limit and is documented as such wherever the plugin is described.
- The core (`omp/`) stays host-free: both hosts call `usecase.intercept(text, adapter)`.
- Validation on a real Hermes (`hermes plugins doctor --ci`) is part of the release
  checklist; unit tests exercise the hooks through a simulated context only.
