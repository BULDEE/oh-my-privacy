# ADR-0010: Mask what the agent reads, not only what the user types

Status: accepted (2026-08-26)

## Context

The first release guarded the user prompt and refused a handful of shell commands. A
measured review showed that the dominant path for a secret into the model is the agent
reading it: the `Read` tool on a `.env`, `cat`/`sort`/`awk`/`python -c` on the same file,
`Grep` in content mode, environment dumps, tool results from MCP servers. Thirteen of
fifteen read forms passed the guard, and `Read` was not covered at all.

Claude Code offers no hook that rewrites a tool result. It does let a `PreToolUse` hook
replace the tool input (`updatedInput`), deny a call with a reason the model reads, and it
hands `PostToolUse` the full `tool_response`.

## Decision

Masking moves to the source, per tool:

- **Bash**: the command is wrapped so stdout and stderr are captured to private temp files,
  passed through the detector, then printed. Braces keep it in the calling shell (`cd`
  persists); an EXIT trap keeps an inner `exit` from skipping the masking; the exit status
  survives. Another rewriting hook can be chained through `OMP_CHAIN_HOOK`, since Claude
  Code keeps the last `updatedInput` only.
- **Read**: when the file contains secrets, a masked copy is written under
  `~/.claude/omp/masked/` (0600) and the call is redirected to it. The model reads the
  file with placeholders; the original is untouched.
- **Grep** in content mode: the hook runs the same search, and when the matches contain
  secrets it denies the call with the masked matches in the reason.
- **Everything else** (MCP tools, WebFetch): a `PostToolUse` hook re-detects secrets in
  `tool_response` and in `tool_input`; when it finds some it scrubs the transcript tail, the
  paste cache and, on request, file-history snapshots, and injects a burnt-value warning.
- The `PreToolUse` guard shrinks to explicit vault reads (`doppler secrets get`, `age -d`,
  whole-environment dumps) and judges each segment of a compound command separately.

Validated in a live Claude Code session: `cat .env` and `Read .env` both showed
`$OMP_*` placeholders; the transcript, history and paste cache held no trace afterwards.

## Consequences

- Every Bash call costs one extra interpreter start (about 60 ms) and loses streaming
  output; background commands are unaffected.
- An `Edit` whose `old_string` spans a masked line cannot match the real file. The
  additional context tells the model so.
- File-history scrubbing stays opt-in (`OMP_SCRUB_FILE_HISTORY=1`): snapshots feed
  `/rewind`, and a masked snapshot restored over a real file would erase its secrets.
- Tool results that cannot be masked at the source still reach the model for that turn.
  The plugin says so and scrubs the disk; it does not pretend otherwise.
