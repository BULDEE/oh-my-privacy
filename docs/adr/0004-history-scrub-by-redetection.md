# ADR-0004: Scrub the prompt history by re-detection, never by passing values

Status: accepted (2026-08-26)

## Context

A prompt refused by the `UserPromptSubmit` hook does not enter the session transcript, but
Claude Code still appends it, in clear, to `~/.claude/history.jsonl` (the up-arrow history,
including `pastedContents`). An exhaustive search of `~/.claude` found no other copy.

The write order between the hook and the history file is not guaranteed, so a single
synchronous pass can miss the entry.

The first fix handed the intercepted values to a background process over stdin so it could
replace them. That kept plaintext secrets in a second process's memory for fifteen seconds.

## Decision

The scrubber receives no value. It re-reads history entries newer than a timestamp window
and applies the same `detect()` as the hook to every string in each entry, replacing what it
finds with the placeholders. It runs once synchronously, then in a detached background
process for fifteen seconds at one-second intervals.

Files are rewritten atomically with their original permissions. The history path is
overridable through `OMP_HISTORY` so tests never touch the real file.

## Consequences

- The background process holds a secret only for the duration of one line's processing.
- Detection and scrubbing can never disagree: they are the same function.
- Cost: one detector pass over recent entries per second, bounded by the window.
