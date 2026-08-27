# Local telemetry (volume + friction) - design

Date: 2026-08-27
Status: approved for planning

## Context

OhMyPrivacy blocks prompts and tool calls that carry secrets, but the project has never
measured its own impact: how often it fires, on what kind of secret, in which host, at
what latency cost, and how often a user disputes the block as a false positive. Without
that data the friction-first design (ADR-0008: block outright, never mask silently) is an
assumption, not a measurement.

This came out of a brainstorm that first scoped a much larger ask (make OhMyPrivacy
available on claude.ai and Claude Cowork). Research against Anthropic's official docs
found the only cross-surface governance point, Inference Hooks (beta, Claude Enterprise),
is allow/deny only - no rewrite or redact - and requires a self-hosted public HTTPS
server. That is incompatible with the mask+vault model this project is built on, and
Cowork's plugin docs document no pre-inference interception point at all. The user chose
to keep scope to Claude Code and Hermes and prioritize measuring real impact first.

## Goal

Add local, opt-out telemetry that answers, from real usage: how many interceptions, of
what kind, in what host, at what latency cost, and what share are disputed as false
positives - without ever storing a secret value or leaving the machine.

## Non-goals

- No network transmission, ever. This is a local instrument, not analytics.
- No new detection logic. Telemetry observes `detect()`/`intercept()` outcomes; it does
  not change what counts as a secret.
- No claude.ai / Cowork integration. Out of scope per the brainstorm decision above.
- No inter-process locking. Two concurrent Claude Code sessions can each lose an
  increment on a simultaneous write; documented as a known limitation (see Testing),
  not fixed, consistent with `tests/test_known_limits.py`'s existing entries.

## Architecture

New infrastructure module, same layer as `omp/adapters/`:

```
omp/telemetry.py   record(), mark_false_positive(), report(), __main__ CLI
```

Hosts stay composition roots (architecture.md's existing rule): each one times its own
call to `detect()`/`intercept()` and calls `telemetry.record(...)` right before returning
its decision. Touched hosts: `omp/hook.py`, `hermes/__init__.py`, `omp/mask.py` (the actual
`detect()` call site for Bash output, spawned by `omp/pre_bash.py`'s wrapper - not
`pre_bash.py` itself, which never calls `detect()`), `omp/pre_grep.py`, `omp/pre_read.py`,
`omp/post_scrub.py`.

`action` values: `block` (`hook.py`, `hermes` `pre_tool_call`), `mask` (`omp/mask.py`,
`pre_grep.py`, `pre_read.py` - the model still receives content, masked), `scrub`
(`post_scrub.py`), and `context` (`hermes` `pre_llm_call` - Hermes can neither block nor
rewrite the user message, ADR already documents this host limit; the secret still reaches
the model for that turn, so this is friction of a different kind than a block and must be
countable separately).

## Storage

`~/.claude/omp-stats.json` (flat, alongside the existing `omp.json` and
`omp-last-prompt.txt` - not under `~/.claude/omp/`, already reserved for the age vault
store). Written with the same `os.open(O_WRONLY | O_CREAT | O_TRUNC, 0o600)` pattern
`config.py` already uses.

Schema:

```json
{
  "version": 1,
  "counters": {
    "<host>.<tool>.<kind>.<action>": {
      "count": 0,
      "latency_ms_total": 0,
      "false_positive_count": 0
    }
  },
  "recent_events": [
    {
      "id": "a1b2c3d4",
      "ts": "2026-08-27T10:00:00Z",
      "host": "claude_code",
      "tool": "prompt",
      "kinds": ["anthropic"],
      "action": "block",
      "latency_ms": 4,
      "false_positive": false
    }
  ]
}
```

- `counters` is the aggregate source of truth for `--report`, keyed per finding (a single
  intercept call touching two kinds increments two counter buckets).
- `recent_events` is a ring buffer (cap 50, oldest evicted first) of whole intercept
  calls, each carrying a short random `id` (not derived from any secret value) - the only
  thing a user can reference to mark a false positive after the fact.
- `id` and `kinds` never carry a secret value: each entry in `kinds` is one
  `Finding.kind` category label (`anthropic`, `github`, `aws`, ...), never `Finding.value`.
- `action` is one of `block` (`UserPromptSubmit`/`PreToolUse` refusal), `scrub`
  (`PostToolUse` re-detection cleanup), or `mask` (`pre_read.py` serving a masked copy).
- Marking an event false positive increments `false_positive_count` on every
  `(host, tool, kind, action)` bucket listed in that event's `kinds` - an event covering
  two kinds credits both buckets.

## Config

`omp/config.py`: new field `telemetry: bool = True` on `Config`, read from the
`"telemetry"` key in `omp.json`. Default **on**: everything stays local, so the privacy
posture that justifies opt-in elsewhere (vault choice, clipboard) doesn't apply here - an
instrument that can't leak has no downside to being on by default.

## Host integration

Each host wraps its existing `detect()`/`intercept()` call with a timer and calls
`telemetry.record(host, tool, kind, action, latency_ms)` immediately after, before
formatting its own answer. `hook.py`'s block message gains one line:

```
False positive? python3 -m omp.telemetry --false-positive <id>
```

`record()` returns `None` when telemetry is disabled or the write fails; hosts omit the
line when the id is `None`.

## CLI

`omp/telemetry.py` doubles as a `__main__` entry point, same pattern as `omp/setup.py`:

- `python3 -m omp.telemetry --false-positive <id>`: marks the matching `recent_events`
  entry and increments that bucket's `false_positive_count`.
- `python3 -m omp.telemetry --report`: prints counts by host/tool/kind, average latency,
  and false-positive rate, as plain text.

## Error handling

`record()` and `mark_false_positive()` never raise: any `OSError` or JSON failure is
caught and swallowed, returning `None` / `False`. The block/refuse decision the host is
already committed to never depends on telemetry succeeding - matches `config.load()`'s
existing philosophy of failing to the safe state, not failing loud.

## Testing

- `tests/test_telemetry.py`: counters increment correctly across repeated `record()`
  calls; `record()` is a no-op returning `None` when `config.telemetry` is `False`;
  `mark_false_positive()` updates the right ring-buffer entry and counter;
  `--report` runs clean on an empty or missing store file.
- Extend `tests/test_hook.py` and `tests/test_hermes_plugin.py`: a block response
  contains the false-positive id line, and a new entry lands in `recent_events` after the
  call.
- `tests/test_known_limits.py`: document the missing inter-process lock as an accepted
  limitation (two concurrent sessions racing a write can each lose one increment).

## Extension points touched

Adds one row-equivalent to `architecture.md`'s existing "Extension points" table: a new
host wraps its own `detect()`/`intercept()` call and calls `telemetry.record(...)` once,
proven by an updated composition-root test - same shape as the existing "add a host"
entry, not a new pattern.
