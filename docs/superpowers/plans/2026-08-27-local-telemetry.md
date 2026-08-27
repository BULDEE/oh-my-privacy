# Local Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add local, opt-out telemetry (volume + friction) to OhMyPrivacy so the project can, for the first time, measure its own impact from real usage, without ever storing a secret value or leaving the machine.

**Architecture:** One new infrastructure module, `omp/telemetry.py`, at the same layer as `omp/adapters/`. Every host that already calls `detect()`/`intercept()` times that call and adds a single `telemetry.record(...)` line before returning its decision - no new pattern, the same "host is a composition root" rule `architecture.md` already documents. Storage is a flat JSON file (`~/.claude/omp-stats.json`), same write pattern as `omp/config.py`.

**Tech Stack:** Python 3.11+ stdlib only (no new dependency: `pyproject.toml` pins `dependencies = []`). `unittest` (project convention, not pytest).

**Spec:** `docs/superpowers/specs/2026-08-27-local-telemetry-design.md`

## Global Constraints

- Python >= 3.11, zero new dependencies (stdlib only: `json`, `os`, `secrets`, `time`, `argparse`, `pathlib`, `datetime`).
- `mypy --strict` covers `omp/` and `hermes/` (`pyproject.toml`'s `[tool.mypy]`); every new/changed function keeps full type annotations.
- `ruff` line length 160, rule set `E, F, W, I, B, UP, S, N` (`pyproject.toml`'s `[tool.ruff.lint]`).
- Every file write uses `os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)` then `os.fdopen` - the exact pattern `omp/config.py:save()` already uses. Never a bare `Path.write_text`.
- `Finding.value` (the actual secret) must never be written to the telemetry store or printed. Only `Finding.kind` (a category label like `anthropic`, `github`, `aws`) is ever recorded.
- Telemetry recording must never be able to change a host's block/deny/mask decision: `telemetry.record()` and `telemetry.mark_false_positive()` catch every failure and degrade to `None`/`False`, never raise.
- All user-facing strings (hook messages, CLI output) are in English, matching every existing string in the codebase.
- Tests are `unittest.TestCase` subclasses, following the exact style already in `tests/test_hook.py`, `tests/test_hermes_plugin.py`, `tests/test_coverage_hooks.py`: subprocess-driven for Claude Code hook entry points, in-process for the Hermes plugin.
- Two corrections to the spec, found during planning, apply throughout this plan (both already folded into the spec doc): the Bash-output `detect()` call site is `omp/mask.py`, not `omp/pre_bash.py` (which never calls `detect()` itself, only wraps the command); and Hermes' `pre_llm_call` needs a fourth `action` value, `"context"`, alongside `block`/`mask`/`scrub`, because that hook can only inject context, never block (a pre-existing, documented host limit).

---

### Task 1: `Config.telemetry` field

**Files:**
- Modify: `omp/config.py`

**Interfaces:**
- Produces: `Config.telemetry: bool` (default `True`), read from the `"telemetry"` key of `omp.json` by `load()`, written unconditionally by `save()`.

- [ ] **Step 1: Add the field and wire it through `load()`/`save()`**

In `omp/config.py`, add `telemetry: bool = True` to the `Config` dataclass, right after `clipboard`:

```python
@dataclass(frozen=True)
class Config:
    vault: str = DEFAULT_VAULT
    options: dict[str, str] = field(default_factory=dict)
    clipboard: bool = True
    telemetry: bool = True
    prompt_file: Path | None = Path.home() / ".claude" / "omp-last-prompt.txt"
```

In `load()`, add the field to the returned `Config(...)` call, right after `clipboard=...`:

```python
    return Config(
        vault=vault,
        options=options,
        clipboard=bool(raw.get("clipboard", True)),
        telemetry=bool(raw.get("telemetry", True)),
        prompt_file=_prompt_file(raw.get("prompt_file", True)),
    )
```

In `save()`, write it unconditionally next to `clipboard`, in the `payload` dict:

```python
    payload: dict[str, object] = {"vault": config.vault, "clipboard": config.clipboard, "telemetry": config.telemetry}
```

- [ ] **Step 2: Smoke-check by hand**

Run:

```bash
python3 -c "
from omp.config import Config, load, save
from pathlib import Path
import tempfile, os
with tempfile.TemporaryDirectory() as d:
    p = Path(d) / 'omp.json'
    save(Config(telemetry=False), p)
    assert load(p).telemetry is False
    save(Config(), p)
    assert load(p).telemetry is True
    print('OK')
"
```

Expected output: `OK`. There is no dedicated `tests/test_config.py` in this project (config is exercised indirectly through `tests/test_hook.py`); Task 3 will add a subprocess-level assertion that a `"telemetry": false` config actually silences recording, which is the behavior that matters.

- [ ] **Step 3: Run the full existing suite to confirm nothing broke**

Run: `python3 -m unittest discover -s tests -v`
Expected: all currently-passing tests still pass (the new field has a default, so every existing call site of `Config(...)` and every existing `omp.json` fixture stays valid).

- [ ] **Step 4: Commit**

```bash
git add omp/config.py
git commit -m "feat(config): add telemetry opt-out field"
```

---

### Task 2: `omp/telemetry.py` - store, recording, false-positive marking, report, CLI

**Files:**
- Create: `omp/telemetry.py`
- Test: `tests/test_telemetry.py`

**Interfaces:**
- Consumes: `omp.config.load(path: Path | None = None) -> Config` (from Task 1, `Config.telemetry: bool`).
- Produces (used by Tasks 3-8):
  - `record(host: str, tool: str, kinds: list[str], action: str, latency_ms: float, path: Path | None = None) -> str | None`
  - `mark_false_positive(event_id: str, path: Path | None = None) -> bool`
  - `load(path: Path | None = None) -> dict[str, object]`
  - `format_report(store: dict[str, object]) -> str`
  - `stats_path() -> Path`
  - `VALID_ACTIONS: frozenset[str]` = `{"block", "mask", "scrub", "context"}`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_telemetry.py`:

```python
"""Local telemetry: volume and friction, never a secret value."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import telemetry  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class Recording(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.TemporaryDirectory()
        self.stats_path = Path(self.workdir.name) / "stats.json"

    def tearDown(self) -> None:
        self.workdir.cleanup()

    def test_record_creates_store_and_returns_an_id(self) -> None:
        event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 4.2, path=self.stats_path)
        self.assertIsNotNone(event_id)
        store = telemetry.load(self.stats_path)
        counters = store["counters"]
        assert isinstance(counters, dict)
        bucket = counters["claude_code.prompt.anthropic.block"]
        self.assertEqual(bucket["count"], 1)

    def test_repeated_records_accumulate_the_same_bucket(self) -> None:
        telemetry.record("claude_code", "prompt", ["anthropic"], "block", 2.0, path=self.stats_path)
        telemetry.record("claude_code", "prompt", ["anthropic"], "block", 3.0, path=self.stats_path)
        store = telemetry.load(self.stats_path)
        counters = store["counters"]
        assert isinstance(counters, dict)
        bucket = counters["claude_code.prompt.anthropic.block"]
        self.assertEqual(bucket["count"], 2)
        self.assertEqual(bucket["latency_ms_total"], 5.0)

    def test_two_kinds_in_one_event_bump_two_buckets(self) -> None:
        telemetry.record("claude_code", "prompt", ["anthropic", "github"], "block", 1.0, path=self.stats_path)
        store = telemetry.load(self.stats_path)
        counters = store["counters"]
        assert isinstance(counters, dict)
        self.assertIn("claude_code.prompt.anthropic.block", counters)
        self.assertIn("claude_code.prompt.github.block", counters)

    def test_ring_buffer_caps_at_fifty(self) -> None:
        for _ in range(60):
            telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        store = telemetry.load(self.stats_path)
        events = store["recent_events"]
        assert isinstance(events, list)
        self.assertEqual(len(events), 50)

    def test_invalid_action_is_rejected(self) -> None:
        event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "bogus", 1.0, path=self.stats_path)
        self.assertIsNone(event_id)
        self.assertFalse(self.stats_path.exists())

    def test_no_kinds_records_nothing(self) -> None:
        event_id = telemetry.record("claude_code", "prompt", [], "block", 1.0, path=self.stats_path)
        self.assertIsNone(event_id)

    def test_no_secret_value_ever_reaches_the_store(self) -> None:
        telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        raw = self.stats_path.read_text()
        self.assertNotIn("sk-ant", raw)


class Disabled(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.TemporaryDirectory()
        self.stats_path = Path(self.workdir.name) / "stats.json"
        self.config_path = Path(self.workdir.name) / "omp.json"
        self.config_path.write_text(json.dumps({"telemetry": False}))
        self.previous_config = os.environ.get("OMP_CONFIG")
        os.environ["OMP_CONFIG"] = str(self.config_path)

    def tearDown(self) -> None:
        if self.previous_config is None:
            del os.environ["OMP_CONFIG"]
        else:
            os.environ["OMP_CONFIG"] = self.previous_config
        self.workdir.cleanup()

    def test_record_is_a_no_op_when_telemetry_is_off(self) -> None:
        event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        self.assertIsNone(event_id)
        self.assertFalse(self.stats_path.exists())


class FalsePositive(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.TemporaryDirectory()
        self.stats_path = Path(self.workdir.name) / "stats.json"

    def tearDown(self) -> None:
        self.workdir.cleanup()

    def test_marking_a_known_event_updates_the_bucket_and_the_event(self) -> None:
        event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        assert event_id is not None
        self.assertTrue(telemetry.mark_false_positive(event_id, path=self.stats_path))
        store = telemetry.load(self.stats_path)
        counters = store["counters"]
        events = store["recent_events"]
        assert isinstance(counters, dict) and isinstance(events, list)
        bucket = counters["claude_code.prompt.anthropic.block"]
        self.assertEqual(bucket["false_positive_count"], 1)
        self.assertTrue(events[0]["false_positive"])

    def test_marking_an_unknown_id_returns_false(self) -> None:
        self.assertFalse(telemetry.mark_false_positive("deadbeef", path=self.stats_path))

    def test_marking_twice_is_idempotent(self) -> None:
        event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        assert event_id is not None
        telemetry.mark_false_positive(event_id, path=self.stats_path)
        telemetry.mark_false_positive(event_id, path=self.stats_path)
        store = telemetry.load(self.stats_path)
        counters = store["counters"]
        assert isinstance(counters, dict)
        bucket = counters["claude_code.prompt.anthropic.block"]
        self.assertEqual(bucket["false_positive_count"], 1)


class Report(unittest.TestCase):
    def test_empty_store_reports_no_data(self) -> None:
        empty: dict[str, object] = {"version": 1, "counters": {}, "recent_events": []}
        self.assertEqual(telemetry.format_report(empty), "No telemetry recorded yet.")

    def test_report_lists_the_bucket_and_the_false_positive_rate(self) -> None:
        store: dict[str, object] = {
            "version": 1,
            "counters": {"claude_code.prompt.anthropic.block": {"count": 2, "latency_ms_total": 10.0, "false_positive_count": 1}},
            "recent_events": [],
        }
        report = telemetry.format_report(store)
        self.assertIn("claude_code.prompt.anthropic.block", report)
        self.assertIn("50.0%", report)


class Cli(unittest.TestCase):
    def test_report_flag_runs_clean_on_missing_store(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            stats_path = Path(workdir) / "stats.json"
            completed = subprocess.run(
                [sys.executable, "-m", "omp.telemetry", "--report"],
                cwd=str(ROOT), capture_output=True, text=True, check=False,
                env={**os.environ, "OMP_STATS": str(stats_path)},
            )
            self.assertEqual(completed.returncode, 0)
            self.assertIn("No telemetry recorded yet.", completed.stdout)

    def test_false_positive_flag_on_unknown_id_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            stats_path = Path(workdir) / "stats.json"
            completed = subprocess.run(
                [sys.executable, "-m", "omp.telemetry", "--false-positive", "deadbeef"],
                cwd=str(ROOT), capture_output=True, text=True, check=False,
                env={**os.environ, "OMP_STATS": str(stats_path)},
            )
            self.assertEqual(completed.returncode, 1)

    def test_false_positive_flag_on_known_id_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            stats_path = Path(workdir) / "stats.json"
            event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=stats_path)
            assert event_id is not None
            completed = subprocess.run(
                [sys.executable, "-m", "omp.telemetry", "--false-positive", event_id],
                cwd=str(ROOT), capture_output=True, text=True, check=False,
                env={**os.environ, "OMP_STATS": str(stats_path)},
            )
            self.assertEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_telemetry -v`
Expected: `ModuleNotFoundError: No module named 'omp.telemetry'` (or every test erroring the same way).

- [ ] **Step 3: Write `omp/telemetry.py`**

```python
"""Local, opt-out telemetry: volume and friction, never a secret value.

Every host times its own `detect()`/`intercept()` call and records the outcome here: how
many interceptions, of what kind, at what latency, and whether the user later disputed one
as a false positive. Nothing leaves the machine; the store lives next to `omp.json`. A
value never reaches this module: only `Finding.kind` (a category label) is ever recorded.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import config as config_module  # noqa: E402

DEFAULT_STATS_PATH = Path.home() / ".claude" / "omp-stats.json"
RING_BUFFER_SIZE = 50
VALID_ACTIONS: frozenset[str] = frozenset({"block", "mask", "scrub", "context"})


def stats_path() -> Path:
    override = os.environ.get("OMP_STATS")
    return Path(override).expanduser() if override else DEFAULT_STATS_PATH


def load(path: Path | None = None) -> dict[str, object]:
    target = path or stats_path()
    try:
        raw = json.loads(target.read_text())
    except (OSError, ValueError):
        raw = None
    if not isinstance(raw, dict):
        raw = {}
    raw.setdefault("version", 1)
    raw.setdefault("counters", {})
    raw.setdefault("recent_events", [])
    return raw


def _save(path: Path, store: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(store, handle, indent=2)
        handle.write("\n")


def _bucket_key(host: str, tool: str, kind: str, action: str) -> str:
    return f"{host}.{tool}.{kind}.{action}"


def _bump(counters: dict[str, object], key: str, latency_ms: float) -> None:
    raw_bucket = counters.get(key)
    bucket = raw_bucket if isinstance(raw_bucket, dict) else {"count": 0, "latency_ms_total": 0.0, "false_positive_count": 0}
    bucket["count"] = int(bucket.get("count", 0)) + 1
    bucket["latency_ms_total"] = float(bucket.get("latency_ms_total", 0.0)) + latency_ms
    counters[key] = bucket


def record(host: str, tool: str, kinds: list[str], action: str, latency_ms: float, path: Path | None = None) -> str | None:
    """Best-effort: never raises. Returns None when telemetry is off, the input is invalid, or the write fails."""
    if action not in VALID_ACTIONS or not kinds:
        return None
    try:
        config = config_module.load()
        if not config.telemetry:
            return None
        target = path or stats_path()
        store = load(target)
        counters = store["counters"]
        if not isinstance(counters, dict):
            counters = {}
            store["counters"] = counters
        for kind in kinds:
            _bump(counters, _bucket_key(host, tool, kind, action), latency_ms)
        events = store["recent_events"]
        if not isinstance(events, list):
            events = []
            store["recent_events"] = events
        event_id = secrets.token_hex(4)
        events.append(
            {
                "id": event_id,
                "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "host": host,
                "tool": tool,
                "kinds": list(kinds),
                "action": action,
                "latency_ms": latency_ms,
                "false_positive": False,
            }
        )
        del events[:-RING_BUFFER_SIZE]
        _save(target, store)
        return event_id
    except (OSError, ValueError, TypeError):
        return None


def mark_false_positive(event_id: str, path: Path | None = None) -> bool:
    try:
        target = path or stats_path()
        store = load(target)
        events = store.get("recent_events")
        counters = store.get("counters")
        if not isinstance(events, list) or not isinstance(counters, dict):
            return False
        matched = False
        for event in events:
            if not isinstance(event, dict) or event.get("id") != event_id:
                continue
            matched = True
            if event.get("false_positive"):
                break
            event["false_positive"] = True
            host, tool, action = str(event.get("host")), str(event.get("tool")), str(event.get("action"))
            for kind in event.get("kinds", []):
                bucket = counters.get(_bucket_key(host, tool, str(kind), action))
                if isinstance(bucket, dict):
                    bucket["false_positive_count"] = int(bucket.get("false_positive_count", 0)) + 1
            break
        if matched:
            _save(target, store)
        return matched
    except (OSError, ValueError, TypeError):
        return False


def format_report(store: dict[str, object]) -> str:
    counters = store.get("counters")
    if not isinstance(counters, dict) or not counters:
        return "No telemetry recorded yet."
    lines = [f"{'bucket':<45} {'count':>6} {'avg_ms':>8} {'false_positive':>15}"]
    for key in sorted(counters):
        bucket = counters[key]
        if not isinstance(bucket, dict):
            continue
        count = int(bucket.get("count", 0))
        total_latency = float(bucket.get("latency_ms_total", 0.0))
        false_positives = int(bucket.get("false_positive_count", 0))
        average = total_latency / count if count else 0.0
        rate = (false_positives / count * 100) if count else 0.0
        lines.append(f"{key:<45} {count:>6} {average:>7.1f}ms {rate:>14.1f}%")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OhMyPrivacy local telemetry: report usage or mark a false positive.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--false-positive", metavar="ID", help="mark a recent interception id as a false positive")
    group.add_argument("--report", action="store_true", help="print counts, latency and false-positive rate by bucket")
    arguments = parser.parse_args(argv)
    if arguments.report:
        print(format_report(load()))
        return 0
    marked = mark_false_positive(arguments.false_positive)
    print("Marked." if marked else f"No event {arguments.false_positive} found in the last {RING_BUFFER_SIZE} interceptions.")
    return 0 if marked else 1


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_telemetry -v`
Expected: all tests `PASS` (0 failures, 0 errors).

- [ ] **Step 5: Lint and type-check**

Run: `ruff check omp/telemetry.py tests/test_telemetry.py && mypy omp/telemetry.py`
Expected: no errors from either command.

- [ ] **Step 6: Commit**

```bash
git add omp/telemetry.py tests/test_telemetry.py
git commit -m "feat(telemetry): add local store, recording, false-positive marking, report CLI"
```

---

### Task 3: Integrate into `omp/hook.py` (Claude Code `UserPromptSubmit`)

**Files:**
- Modify: `omp/hook.py`
- Modify: `tests/test_hook.py`

**Interfaces:**
- Consumes: `omp.telemetry.record(host, tool, kinds, action, latency_ms) -> str | None` (Task 2).

- [ ] **Step 1: Write the failing tests**

In `tests/test_hook.py`, add a `stats: str` field to `HookRun`, wire `OMP_STATS` through `run_hook()`, and add three test methods.

Replace the `HookRun` dataclass and `run_hook` function:

```python
@dataclass(frozen=True)
class HookRun:
    response: dict[str, object] | None
    handed: str
    history: str
    stats: str


def run_hook(prompt: str, config: dict[str, object] | None = None, raw_config: str | None = None) -> HookRun:
    with tempfile.TemporaryDirectory() as workdir:
        config_path = Path(workdir) / "omp.json"
        prompt_file = Path(workdir) / "last.txt"
        history_path = Path(workdir) / "history.jsonl"
        stats_path = Path(workdir) / "stats.json"
        history_path.write_text(json.dumps({"display": prompt}) + "\n")
        payload: dict[str, object] = {"vault": "discard", "clipboard": False, "prompt_file": str(prompt_file)}
        payload.update(config or {})
        config_path.write_text(raw_config if raw_config is not None else json.dumps(payload))
        completed = subprocess.run(
            [sys.executable, str(HOOK)],
            input=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": prompt}),
            capture_output=True, text=True, timeout=30, check=False,
            env={**os.environ, "OMP_CONFIG": str(config_path), "OMP_HISTORY": str(history_path), "OMP_CLIPBOARD": "0", "OMP_STATS": str(stats_path)},
        )
        output = completed.stdout.strip()
        return HookRun(
            response=json.loads(output) if output else None,
            handed=prompt_file.read_text() if prompt_file.exists() else "",
            history=history_path.read_text(),
            stats=stats_path.read_text() if stats_path.exists() else "",
        )
```

Add these three test methods to the `Blocking` class:

```python
    def test_block_message_includes_the_false_positive_hint(self) -> None:
        run = run_hook(f"test {FAKE_ANTHROPIC} end")
        assert run.response is not None
        self.assertIn("python3 -m omp.telemetry --false-positive", str(run.response["reason"]))

    def test_block_records_a_telemetry_event(self) -> None:
        run = run_hook(f"test {FAKE_ANTHROPIC} end")
        self.assertIn('"host": "claude_code"', run.stats)
        self.assertIn('"tool": "prompt"', run.stats)
        self.assertIn('"action": "block"', run.stats)

    def test_telemetry_disabled_records_nothing(self) -> None:
        run = run_hook(f"test {FAKE_ANTHROPIC} end", {"telemetry": False})
        self.assertEqual(run.stats, "")
```

- [ ] **Step 2: Run the tests to verify the new ones fail**

Run: `python3 -m unittest tests.test_hook -v`
Expected: `test_block_message_includes_the_false_positive_hint` and `test_block_records_a_telemetry_event` FAIL (no hint, no stats file); the rest still pass.

- [ ] **Step 3: Implement in `omp/hook.py`**

Add the import (after the existing `from omp.usecase import ...` line):

```python
from omp import config as config_module  # noqa: E402
from omp import history, paste_cache, telemetry  # noqa: E402
from omp.adapters import build  # noqa: E402
from omp.usecase import Interception, intercept  # noqa: E402
```

Add `import time` to the top-level stdlib imports:

```python
import json
import os
import subprocess
import sys
import time
from pathlib import Path
```

Change `block_response` to accept and use an `event_id`:

```python
def block_response(interception: Interception, channels: list[str], event_id: str | None) -> dict[str, object]:
    count = len(interception.outcomes)
    where = " and ".join(channels) if channels else "below only"
    reason = (
        f"OhMyPrivacy intercepted {count} secret(s). The message is BLOCKED: it never reached the model.\n"
        f"Vault: {interception.vault}.\n{describe(interception)}\n\n"
        f"Your cleaned message is available via {where}. Paste it as is to continue:\n\n"
        f"--- cleaned message ---\n{interception.cleaned}"
    )
    if event_id:
        reason += f"\n\nFalse positive? python3 -m omp.telemetry --false-positive {event_id}"
    return {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
        "systemMessage": f"OhMyPrivacy: {count} secret(s) intercepted, message blocked ({', '.join(interception.names)}).",
    }
```

Change `main`:

```python
def main() -> int:
    prompt = read_prompt()
    if not prompt:
        return 0
    config = config_module.load()
    started = time.perf_counter()
    interception = intercept(expand_pastes(prompt), build(config))
    latency_ms = (time.perf_counter() - started) * 1000
    del prompt
    if interception is None:
        return 0
    since_ms = history.recent_window_start()
    history.scrub(since_ms)
    history.spawn_background(since_ms)
    paste_cache.scrub_recent()
    kinds = [outcome.kind for outcome in interception.outcomes]
    event_id = telemetry.record("claude_code", "prompt", kinds, "block", latency_ms)
    print(json.dumps(block_response(interception, hand_back(config, interception.cleaned, interception.vault), event_id)))
    return 0
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_hook -v`
Expected: all tests `PASS`.

- [ ] **Step 5: Lint and type-check**

Run: `ruff check omp/hook.py tests/test_hook.py && mypy omp/hook.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add omp/hook.py tests/test_hook.py
git commit -m "feat(hook): record telemetry on every UserPromptSubmit block"
```

---

### Task 4: Integrate into `hermes/__init__.py` (`pre_tool_call` and `pre_llm_call`)

**Files:**
- Modify: `hermes/__init__.py`
- Modify: `tests/test_hermes_plugin.py`

**Interfaces:**
- Consumes: `omp.telemetry.record(...)` (Task 2).

- [ ] **Step 1: Write the failing tests**

In `tests/test_hermes_plugin.py`, add `os` and `tempfile` imports, isolate `OMP_STATS`/`OMP_CONFIG` per test, and add two test methods.

Replace the import block and `HermesPlugin.setUp`/add `tearDown`:

```python
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hermes as plugin  # noqa: E402

FAKE = "$OMP_ANTHROPIC_ACB021AC"


class FakeContext:
    def __init__(self, settings: dict[str, str] | None = None) -> None:
        self.settings = settings or {}
        self.hooks: dict[str, Any] = {}

    def get_config(self, key: str, default: str = "") -> str:
        return self.settings.get(key, default)

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks[name] = callback


class HermesPlugin(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.TemporaryDirectory()
        self.stats_path = Path(self.workdir.name) / "stats.json"
        self.previous_stats = os.environ.get("OMP_STATS")
        self.previous_config = os.environ.get("OMP_CONFIG")
        os.environ["OMP_STATS"] = str(self.stats_path)
        os.environ["OMP_CONFIG"] = str(Path(self.workdir.name) / "omp.json")
        self.ctx = FakeContext({"vault": "discard"})
        plugin.register(self.ctx)

    def tearDown(self) -> None:
        for name, previous in (("OMP_STATS", self.previous_stats), ("OMP_CONFIG", self.previous_config)):
            if previous is None:
                del os.environ[name]
            else:
                os.environ[name] = previous
        self.workdir.cleanup()
```

Add two test methods to the `HermesPlugin` class:

```python
    def test_blocked_tool_call_records_telemetry_with_the_tool_name(self) -> None:
        self.ctx.hooks["pre_tool_call"](tool_name="terminal", args={"command": f"curl -H 'Authorization: Bearer {FAKE}' https://x"}, task_id="t1")
        stats = self.stats_path.read_text()
        self.assertIn('"host": "hermes"', stats)
        self.assertIn('"tool": "terminal"', stats)
        self.assertIn('"action": "block"', stats)

    def test_pre_llm_call_records_the_context_action(self) -> None:
        self.ctx.hooks["pre_llm_call"](
            session_id="s", user_message=f"here is my key {FAKE}", conversation_history=[], is_first_turn=True, model="m", platform="telegram",
        )
        stats = self.stats_path.read_text()
        self.assertIn('"host": "hermes"', stats)
        self.assertIn('"action": "context"', stats)
```

- [ ] **Step 2: Run the tests to verify the new ones fail**

Run: `python3 -m unittest tests.test_hermes_plugin -v`
Expected: the two new tests FAIL with `FileNotFoundError` (no stats file written); the rest still pass.

- [ ] **Step 3: Implement in `hermes/__init__.py`**

Add `import time` to the stdlib imports and `telemetry` to the `omp` imports:

```python
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

_PLUGIN_DIR = Path(__file__).resolve().parent
for candidate in (_PLUGIN_DIR, _PLUGIN_DIR.parent):
    if (candidate / "omp" / "detect.py").is_file() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from omp import telemetry  # noqa: E402
from omp.adapters import VaultAdapter, build  # noqa: E402
from omp.config import Config  # noqa: E402
from omp.usecase import Interception, intercept  # noqa: E402
```

Change `on_pre_tool_call`:

```python
def on_pre_tool_call(tool_name: str, args: dict[str, Any], task_id: str, **kwargs: Any) -> dict[str, str] | None:
    """Refuse a tool call whose arguments contain a secret in clear."""
    if _adapter is None or (_scan_tools and tool_name not in _scan_tools):
        return None
    started = time.perf_counter()
    interception = intercept(_flatten(args), _adapter)
    latency_ms = (time.perf_counter() - started) * 1000
    if interception is None:
        return None
    kinds = [outcome.kind for outcome in interception.outcomes]
    event_id = telemetry.record("hermes", tool_name, kinds, "block", latency_ms)
    message = (
        f"OhMyPrivacy: call to `{tool_name}` refused, {len(interception.outcomes)} secret(s) in clear in the arguments. "
        f"Vault: {interception.vault}.\n{_describe(interception)}\n"
        "Never copy a secret value into a command, a file or a message. "
        "Reference it by name, or ask the user to consume it themselves."
    )
    if event_id:
        message += f"\n\nFalse positive? python3 -m omp.telemetry --false-positive {event_id}"
    return {"action": "block", "message": message}
```

Change `on_pre_llm_call`:

```python
def on_pre_llm_call(session_id: str, user_message: str, **kwargs: Any) -> dict[str, str] | None:
    """Store a secret pasted by the user and forbid the model from repeating it."""
    if _adapter is None or not user_message:
        return None
    started = time.perf_counter()
    interception = intercept(user_message, _adapter)
    latency_ms = (time.perf_counter() - started) * 1000
    if interception is None:
        return None
    kinds = [outcome.kind for outcome in interception.outcomes]
    telemetry.record("hermes", "prompt", kinds, "context", latency_ms)
    return {
        "context": (
            f"[OhMyPrivacy] The user's message contained {len(interception.outcomes)} secret(s), "
            f"stored in the {interception.vault} vault:\n{_describe(interception)}\n"
            "Never repeat, quote, summarize or transform these values, in whole or in part, "
            "in a reply, a tool call, a file or an outbound message. Refer to them only by their $OMP_* name. "
            "Cleaned version of the message:\n" + interception.cleaned
        )
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_hermes_plugin -v`
Expected: all tests `PASS`.

- [ ] **Step 5: Lint and type-check**

Run: `ruff check hermes/__init__.py tests/test_hermes_plugin.py && mypy hermes/__init__.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add hermes/__init__.py tests/test_hermes_plugin.py
git commit -m "feat(hermes): record telemetry on pre_tool_call block and pre_llm_call context"
```

---

### Task 5: Integrate into `omp/mask.py` (Bash output masking)

**Files:**
- Modify: `omp/mask.py`
- Modify: `tests/test_coverage_hooks.py`

**Interfaces:**
- Consumes: `omp.telemetry.record(...)` (Task 2).
- Changes: `mask(text: str) -> tuple[str, list[str]]` and `mask_file(path: Path) -> tuple[str, list[str]]` now return the list of `Finding.kind` values instead of a bare count (grepped: no other module imports `omp.mask`, so this is a contained, non-breaking change within the file).

- [ ] **Step 1: Write the failing test**

In `tests/test_coverage_hooks.py`, add one test method to the `BashOutputMasking` class:

```python
    def test_masking_records_telemetry(self) -> None:
        stats_path = self.work / "stats.json"
        command = self.wrapped("cat .env; echo TOKEN=" + FAKE + " >&2; false")
        subprocess.run(
            ["bash", "-c", command], capture_output=True, text=True, cwd=self.work,
            env={**os.environ, "OMP_STATS": str(stats_path)},
        )
        stats = stats_path.read_text()
        self.assertIn('"host": "claude_code"', stats)
        self.assertIn('"tool": "Bash"', stats)
        self.assertIn('"action": "mask"', stats)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_coverage_hooks.BashOutputMasking.test_masking_records_telemetry -v`
Expected: FAIL (`stats_path` never created, `FileNotFoundError` on `read_text()`).

- [ ] **Step 3: Implement in `omp/mask.py`**

Replace the whole file:

```python
"""Output masking for tool results.

`mask(text)` replaces every detected secret with its placeholder. As a CLI it reads one or
two files (stdout capture, stderr capture) produced by the Bash wrapper and prints their
masked content on the matching descriptors, so the model sees `$OMP_KIND_HASH` instead of
the value. Placeholders derive from the value's hash, so the same secret keeps the same
name across a prompt, a file read and a command output.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import telemetry  # noqa: E402
from omp.detect import detect  # noqa: E402

MAX_BYTES = 8_000_000


def mask(text: str) -> tuple[str, list[str]]:
    cleaned, findings = detect(text)
    return cleaned, [finding.kind for finding in findings]


def mask_file(path: Path) -> tuple[str, list[str]]:
    try:
        raw = path.read_bytes()
    except OSError:
        return "", []
    if len(raw) > MAX_BYTES:
        return f"[OhMyPrivacy: output of {len(raw)} bytes exceeds the {MAX_BYTES} byte masking limit and was withheld]\n", []
    return mask(raw.decode("utf-8", errors="replace"))


def main() -> int:
    if len(sys.argv) == 1:
        started = time.perf_counter()
        cleaned, kinds = mask(sys.stdin.read())
        latency_ms = (time.perf_counter() - started) * 1000
        sys.stdout.write(cleaned)
        if kinds:
            telemetry.record("claude_code", "Bash", kinds, "mask", latency_ms)
        return 0
    started = time.perf_counter()
    out_text, out_kinds = mask_file(Path(sys.argv[1]))
    sys.stdout.write(out_text)
    err_kinds: list[str] = []
    if len(sys.argv) > 2:
        err_text, err_kinds = mask_file(Path(sys.argv[2]))
        sys.stderr.write(err_text)
    latency_ms = (time.perf_counter() - started) * 1000
    kinds = out_kinds + err_kinds
    if kinds:
        telemetry.record("claude_code", "Bash", kinds, "mask", latency_ms)
        sys.stderr.write(f"[OhMyPrivacy: {len(kinds)} secret(s) masked in this output; refer to them by their $OMP_* name]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m unittest tests.test_coverage_hooks.BashOutputMasking -v`
Expected: all tests in the class `PASS`, including the new one and the pre-existing ones (`test_stdout_and_stderr_are_masked_and_status_kept` etc., which don't set `OMP_STATS` and so telemetry silently no-ops to the real `~/.claude/omp-stats.json` path - harmless, matches the "opt-out is a config file, not an env var most tests set" reality; add `"OMP_STATS": "/dev/null/unwritable"` is unnecessary since a failed write is swallowed).

- [ ] **Step 5: Lint and type-check**

Run: `ruff check omp/mask.py tests/test_coverage_hooks.py && mypy omp/mask.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add omp/mask.py tests/test_coverage_hooks.py
git commit -m "feat(mask): record telemetry on Bash output masking"
```

---

### Task 6: Integrate into `omp/pre_grep.py`

**Files:**
- Modify: `omp/pre_grep.py`
- Modify: `tests/test_coverage_hooks.py`

**Interfaces:**
- Consumes: `omp.telemetry.record(...)` (Task 2).

- [ ] **Step 1: Write the failing test**

Add one test method to the `GrepContent` class in `tests/test_coverage_hooks.py`:

```python
    def test_masking_records_telemetry(self) -> None:
        stats_path = self.work / "stats.json"
        payload = {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": str(self.work), "output_mode": "content"}}
        run_hook("pre_grep.py", payload, {"CLAUDE_CODE_EXECPATH": str(CLAUDE), "OMP_STATS": str(stats_path)})
        stats = stats_path.read_text()
        self.assertIn('"host": "claude_code"', stats)
        self.assertIn('"tool": "Grep"', stats)
        self.assertIn('"action": "mask"', stats)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_coverage_hooks.GrepContent.test_masking_records_telemetry -v`
Expected: FAIL (`FileNotFoundError` on `stats_path.read_text()`), or SKIPPED if no `claude` binary is on this machine - in that case still proceed with the implementation, it will be exercised in CI.

- [ ] **Step 3: Implement in `omp/pre_grep.py`**

Add `import time` and the `telemetry` import:

```python
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import telemetry  # noqa: E402
from omp.detect import detect  # noqa: E402
```

Change `main`:

```python
def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (OSError, ValueError):
        return 0
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    if not isinstance(tool_input, dict) or tool_input.get("output_mode", "files_with_matches") != "content":
        return 0
    started = time.perf_counter()
    output = run_search(tool_input)
    if not output:
        return 0
    cleaned, findings = detect(output)
    latency_ms = (time.perf_counter() - started) * 1000
    if not findings:
        return 0
    head_limit = tool_input.get("head_limit")
    if isinstance(head_limit, int) and head_limit > 0:
        cleaned = "\n".join(cleaned.splitlines()[:head_limit])
    telemetry.record("claude_code", "Grep", [finding.kind for finding in findings], "mask", latency_ms)
    print(json.dumps(deny_with(cleaned, len(findings))))
    return 0
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m unittest tests.test_coverage_hooks.GrepContent -v`
Expected: all tests in the class `PASS` (or SKIPPED as a whole if no `claude` binary is available, per the class's existing `@unittest.skipUnless`).

- [ ] **Step 5: Lint and type-check**

Run: `ruff check omp/pre_grep.py tests/test_coverage_hooks.py && mypy omp/pre_grep.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add omp/pre_grep.py tests/test_coverage_hooks.py
git commit -m "feat(grep): record telemetry on masked content search"
```

---

### Task 7: Integrate into `omp/pre_read.py`

**Files:**
- Modify: `omp/pre_read.py`
- Modify: `tests/test_coverage_hooks.py`

**Interfaces:**
- Consumes: `omp.telemetry.record(...)` (Task 2).
- Changes: `mask_file(original: Path) -> tuple[Path | None, list[str]]` now returns the list of `Finding.kind` values instead of a bare count (this is a different function from `omp/mask.py`'s `mask_file`, same name, no shared caller - grepped in the spec's research step).

- [ ] **Step 1: Write the failing test**

Add one test method to the `ReadRedirection` class:

```python
    def test_masking_records_telemetry(self) -> None:
        stats_path = self.work / "stats.json"
        payload = {"tool_name": "Read", "tool_input": {"file_path": str(self.env_file)}}
        run_hook("pre_read.py", payload, {"OMP_MASKED_DIR": str(self.work / "masked"), "OMP_STATS": str(stats_path)})
        stats = stats_path.read_text()
        self.assertIn('"host": "claude_code"', stats)
        self.assertIn('"tool": "Read"', stats)
        self.assertIn('"action": "mask"', stats)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_coverage_hooks.ReadRedirection.test_masking_records_telemetry -v`
Expected: FAIL (`FileNotFoundError` on `stats_path.read_text()`).

- [ ] **Step 3: Implement in `omp/pre_read.py`**

Add `import time` and the `telemetry` import:

```python
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import telemetry  # noqa: E402
from omp.detect import detect  # noqa: E402
```

Change `mask_file`:

```python
def mask_file(original: Path) -> tuple[Path | None, list[str]]:
    """Return the masked copy path and the kinds found, or (None, []) when nothing to mask."""
    try:
        raw = original.read_bytes()
    except OSError:
        return None, []
    if len(raw) > MAX_BYTES or b"\x00" in raw[:4096]:
        return None, []
    cleaned, findings = detect(raw.decode("utf-8", errors="replace"))
    if not findings:
        return None, []
    target = masked_copy_path(original)
    write_private(target, cleaned)
    return target, [finding.kind for finding in findings]
```

Change `main`:

```python
def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (OSError, ValueError):
        return 0
    request = requested_file(payload)
    if request is None:
        return 0
    tool_input, original = request
    started = time.perf_counter()
    target, kinds = mask_file(original)
    latency_ms = (time.perf_counter() - started) * 1000
    if target is None:
        return 0
    telemetry.record("claude_code", "Read", kinds, "mask", latency_ms)
    updated = dict(tool_input)
    updated["file_path"] = str(target)
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated,
            "additionalContext": (
                f"OhMyPrivacy masked {len(kinds)} secret(s) in {original}. You are reading a masked copy; "
                f"$OMP_* placeholders stand for the values. Never reconstruct them. An Edit whose old_string "
                f"spans a masked line will not match the real file."
            ),
        },
    }))
    return 0
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m unittest tests.test_coverage_hooks.ReadRedirection -v`
Expected: all tests in the class `PASS`.

- [ ] **Step 5: Lint and type-check**

Run: `ruff check omp/pre_read.py tests/test_coverage_hooks.py && mypy omp/pre_read.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add omp/pre_read.py tests/test_coverage_hooks.py
git commit -m "feat(read): record telemetry on masked file redirection"
```

---

### Task 8: Integrate into `omp/post_scrub.py`

**Files:**
- Modify: `omp/post_scrub.py`
- Modify: `tests/test_coverage_hooks.py`

**Interfaces:**
- Consumes: `omp.telemetry.record(...)` (Task 2).
- Changes: `response_has_secrets(tool_response: object) -> int` is replaced by `response_kinds(tool_response: object) -> list[str]`; call sites in `main()` adapt (`len(kinds)` replaces the old count).

- [ ] **Step 1: Write the failing test**

Add one test method to the `PostToolScrub` class:

```python
    def test_scrub_records_telemetry(self) -> None:
        stats_path = self.work / "stats.json"
        transcript = self.work / "t.jsonl"
        transcript.write_text(json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "content": f"token {FAKE}"}]}}) + "\n")
        run_hook(
            "post_scrub.py",
            {"tool_name": "mcp__x__vars", "tool_input": {}, "tool_response": {"K": FAKE}, "session_id": "s1", "transcript_path": str(transcript)},
            {"OMP_FILE_HISTORY": str(self.work / "file-history"), "OMP_PASTE_CACHE": str(self.work / "nocache"), "OMP_STATS": str(stats_path)},
        )
        stats = stats_path.read_text()
        self.assertIn('"host": "claude_code"', stats)
        self.assertIn('"action": "scrub"', stats)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_coverage_hooks.PostToolScrub.test_scrub_records_telemetry -v`
Expected: FAIL (`FileNotFoundError` on `stats_path.read_text()`).

- [ ] **Step 3: Implement in `omp/post_scrub.py`**

Add the `telemetry` import (next to the existing `omp` imports):

```python
from omp import history, paste_cache, telemetry  # noqa: E402
from omp.detect import detect  # noqa: E402
from omp.pre_read import MASKED_ROOT  # noqa: E402
```

(`import time` is already present in this file.)

Replace `response_has_secrets` with `response_kinds`:

```python
def response_kinds(value: object) -> list[str]:
    kinds: list[str] = []
    for text in _iter_strings(value):
        _, findings = detect(text)
        kinds += [finding.kind for finding in findings]
    return kinds
```

Change `main`:

```python
def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (OSError, ValueError):
        return 0
    if not isinstance(payload, dict):
        return 0
    tool_name = str(payload.get("tool_name", ""))
    started = time.perf_counter()
    leaked_kinds = response_kinds(payload.get("tool_response"))
    typed_kinds = response_kinds(payload.get("tool_input"))
    latency_ms = (time.perf_counter() - started) * 1000
    if not leaked_kinds and not typed_kinds and tool_name not in EDIT_TOOLS:
        return 0
    scrubbed = scrub_traces(payload, len(leaked_kinds) + len(typed_kinds))
    all_kinds = leaked_kinds + typed_kinds
    if all_kinds:
        telemetry.record("claude_code", tool_name or "unknown", all_kinds, "scrub", latency_ms)
    if leaked_kinds:
        print(json.dumps(warning(tool_name, len(leaked_kinds), scrubbed)))
    return 0
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m unittest tests.test_coverage_hooks.PostToolScrub -v`
Expected: all tests in the class `PASS`.

- [ ] **Step 5: Lint and type-check**

Run: `ruff check omp/post_scrub.py tests/test_coverage_hooks.py && mypy omp/post_scrub.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add omp/post_scrub.py tests/test_coverage_hooks.py
git commit -m "feat(post-scrub): record telemetry on re-detection scrub"
```

---

### Task 9: Known limitation, architecture doc, full suite

**Files:**
- Modify: `tests/test_known_limits.py`
- Modify: `docs/architecture.md`

**Interfaces:**
- None produced; this task only documents and verifies.

- [ ] **Step 1: Add the concurrency limitation test**

In `tests/test_known_limits.py`, add the import and a new test:

```python
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import telemetry  # noqa: E402
from omp.detect import detect  # noqa: E402

FAKE_ANTHROPIC = "$OMP_ANTHROPIC_ACB021AC"


class KnownLimits(unittest.TestCase):
    @unittest.expectedFailure
    def test_reversed_key(self) -> None:
        _, findings = detect(FAKE_ANTHROPIC[::-1])
        self.assertTrue(findings)

    @unittest.expectedFailure
    def test_homoglyph_prefix(self) -> None:
        _, findings = detect(FAKE_ANTHROPIC.replace("sk-ant", "sk-аnt"))
        self.assertTrue(findings)

    @unittest.expectedFailure
    def test_password_in_prose(self) -> None:
        _, findings = detect("my wifi password is Sunflower-2026-Sun")
        self.assertTrue(findings)

    @unittest.expectedFailure
    def test_key_spaced_every_eight_chars_is_fully_masked(self) -> None:
        spaced = " ".join(FAKE_ANTHROPIC[index:index + 8] for index in range(0, len(FAKE_ANTHROPIC), 8))
        cleaned, _ = detect(spaced)
        self.assertNotIn("ESTINGON", cleaned)

    @unittest.expectedFailure
    def test_concurrent_writers_can_lose_an_increment(self) -> None:
        """telemetry.record() is read-modify-write with no lock: two writers that both read the
        store before either saves will each commit from the same stale state, and the second
        save overwrites the first's increment. Reproduced deterministically, without real
        threads: two independent `load()` calls stand in for two racing processes that both
        read before either writes back, which is the actual hazard, not a timing accident.
        Accepted (ADR-0008's threat model is the accident, not an adversary), not fixed.
        """
        with tempfile.TemporaryDirectory() as workdir:
            stats_path = Path(workdir) / "stats.json"
            telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=stats_path)  # seeds count=1

            store_a = telemetry.load(stats_path)
            store_b = telemetry.load(stats_path)  # both read the same count=1 before either writes back
            counters_a = store_a["counters"]
            counters_b = store_b["counters"]
            assert isinstance(counters_a, dict) and isinstance(counters_b, dict)
            telemetry._bump(counters_a, "claude_code.prompt.anthropic.block", 1.0)  # noqa: SLF001
            telemetry._bump(counters_b, "claude_code.prompt.anthropic.block", 1.0)  # noqa: SLF001
            telemetry._save(stats_path, store_a)  # noqa: SLF001
            telemetry._save(stats_path, store_b)  # noqa: SLF001 -- overwrites store_a's increment

            final_store = telemetry.load(stats_path)
            final_counters = final_store["counters"]
            assert isinstance(final_counters, dict)
            bucket = final_counters["claude_code.prompt.anthropic.block"]
            # Correct, lock-protected behavior would total 3 (1 seed + 2 real increments).
            self.assertEqual(bucket["count"], 3)


if __name__ == "__main__":
    unittest.main()
```

Unlike a thread-timing race, this reproduction is deterministic: it does not rely on scheduling luck, so it cannot be flaky, yet it exercises the exact hazard (two reads of the same stale state, two saves, one lost) a real inter-process race would hit. `ruff`'s selected rule set (`E, F, W, I, B, UP, S, N`) does not include `SLF001` (flake8-self), so the `# noqa: SLF001` comments are inert but harmless; they document intent for a human reader crossing the module boundary in a test.

- [ ] **Step 2: Run it to verify it is an expected failure, not a silent pass**

Run: `python3 -m unittest tests.test_known_limits -v`
Expected: `test_concurrent_writers_can_lose_an_increment ... expected failure` (actual count is 2, not the asserted 3 - one increment was lost, exactly as documented), alongside the four pre-existing ones. If it reports `ok` (unexpected success), the reproduction stopped exercising the race - fix the test until it genuinely fails as documented, never widen `record()`'s behavior to make it pass.

- [ ] **Step 3: Extend `docs/architecture.md`**

In the "Extension points" table, add one row:

```markdown
| To add | Touch | Prove with |
|---|---|---|
| A vault | one class in `omp/adapters/`, one line in `REGISTRY` | `NoReadPathInvariant` still green, a store round-trip test |
| A secret format | one tuple in `PREFIX_PATTERNS` or `FRAGMENT_PATTERNS` | a detection test and a precision test on prose |
| A host | one composition root calling `usecase.intercept` | a simulated-context test plus a real-host validation |
| Telemetry on a new host | time the `detect()`/`intercept()` call, one `telemetry.record(...)` line | a subprocess or in-process test asserting the bucket appears in the stats file |
```

- [ ] **Step 4: Run the full suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: every test passes or is a documented `expected failure` (the four pre-existing ones plus the new one); zero unexpected failures or errors.

- [ ] **Step 5: Full lint and type-check**

Run: `ruff check omp hermes tests && mypy omp hermes`
Expected: no errors from either command.

- [ ] **Step 6: Commit**

```bash
git add tests/test_known_limits.py docs/architecture.md
git commit -m "docs: document telemetry's no-lock limit and extension point"
```
