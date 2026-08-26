# ADR-0001: Block the message, never mask it in flight

Status: accepted (2026-08-26)

## Context

The first implementation returned `hookSpecificOutput.updatedInput` from the Claude Code
`UserPromptSubmit` hook, expecting the prompt to be rewritten with placeholders before it
reached the model. Manual tests that piped JSON into the script showed the placeholders and
were taken as proof that the guard worked.

Reading the hook schema straight from the Claude Code binary (2.1.246) showed that
`UserPromptSubmit` accepts only `additionalContext`, `sessionTitle` and
`suppressOriginalPrompt`. `updatedInput` belongs to `PreToolUse` and expects a tool input
object. The field was silently dropped and every prompt reached the model intact.

Hermes Agent offers the same shape: `pre_llm_call` can inject context, it cannot rewrite or
refuse the user message.

## Decision

A message that contains a secret is **refused**, not rewritten:

- Claude Code: `decision: "block"` plus `suppressOriginalPrompt: true`. The cleaned message
  is handed back through the block reason, the clipboard and a private file, so the user can
  paste it as is.
- Hermes: `pre_tool_call` returns `{"action": "block"}` for tool calls. For inbound user
  messages, where no veto exists, the value is stored and a strict instruction is injected.

## Consequences

- The user retypes nothing: one paste of the cleaned message continues the conversation.
- A blocked prompt still lands in `~/.claude/history.jsonl`; ADR-0004 covers that.
- Every host integration must be validated against the real host, not against the script in
  isolation. A hook whose output is ignored looks identical to a working one from the inside.
