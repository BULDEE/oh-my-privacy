from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "omp" / "hook.py"
FAKE_ANTHROPIC = "sk-ant-api03-FAKEKEYFORTESTINGONLY0000000000"


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


class Blocking(unittest.TestCase):
    def test_secret_blocks_and_suppresses_original(self) -> None:
        run = run_hook(f"test {FAKE_ANTHROPIC} end")
        assert run.response is not None
        self.assertEqual(run.response["decision"], "block")
        specific = run.response["hookSpecificOutput"]
        assert isinstance(specific, dict)
        self.assertTrue(specific["suppressOriginalPrompt"])
        self.assertEqual(specific["hookEventName"], "UserPromptSubmit")
        self.assertNotIn("updatedInput", specific)

    def test_output_never_contains_the_secret(self) -> None:
        run = run_hook(f"test {FAKE_ANTHROPIC} end")
        self.assertNotIn(FAKE_ANTHROPIC, json.dumps(run.response))
        self.assertNotIn(FAKE_ANTHROPIC, run.handed)
        self.assertIn("$OMP_ANTHROPIC_", run.handed)

    def test_history_is_scrubbed_synchronously(self) -> None:
        run = run_hook(f"test {FAKE_ANTHROPIC} end")
        self.assertNotIn(FAKE_ANTHROPIC, run.history)
        self.assertIn("$OMP_ANTHROPIC_", run.history)

    def test_clean_prompt_is_silent(self) -> None:
        run = run_hook("explain the repository pattern")
        self.assertIsNone(run.response)
        self.assertEqual(run.handed, "")

    def test_malformed_stdin_is_silent(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(HOOK)], input="not json", capture_output=True, text=True, check=False,
            env={**os.environ, "OMP_HISTORY": "/nonexistent/history.jsonl"},
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.strip(), "")

    def test_broken_config_still_blocks(self) -> None:
        run = run_hook(f"x {FAKE_ANTHROPIC}", raw_config="{this is not json")
        assert run.response is not None
        self.assertEqual(run.response["decision"], "block")
        self.assertIn("discard", str(run.response["reason"]))

    def test_unavailable_vault_degrades_to_discard_and_still_blocks(self) -> None:
        run = run_hook(f"x {FAKE_ANTHROPIC}", {"vault": "doppler", "doppler": {"project": "", "config": ""}})
        assert run.response is not None
        self.assertEqual(run.response["decision"], "block")
        self.assertIn("Vault: discard", str(run.response["reason"]))

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

    def test_block_message_still_carries_the_hint_when_telemetry_is_disabled(self) -> None:
        """The hint is unconditional: at worst `--false-positive <id>` reports the id as unknown, which is harmless."""
        run = run_hook(f"test {FAKE_ANTHROPIC} end", {"telemetry": False})
        assert run.response is not None
        self.assertEqual(run.response["decision"], "block")
        self.assertIn("python3 -m omp.telemetry --false-positive", str(run.response["reason"]))


class PoisonedStatsStore(unittest.TestCase):
    """Anything on this machine can write `~/.claude/omp-stats.json`; nothing there may suppress a block decision."""

    def test_a_store_that_crashes_the_recorder_never_suppresses_the_block(self) -> None:
        poisoned = (
            '{"version":1,"counters":{"claude_code.prompt.anthropic.block":'
            '{"count":1e400,"latency_ms_total":1.0,"false_positive_count":0}},"recent_events":[]}'
        )
        with tempfile.TemporaryDirectory() as workdir:
            config_path = Path(workdir) / "omp.json"
            stats_path = Path(workdir) / "stats.json"
            history_path = Path(workdir) / "history.jsonl"
            stats_path.write_text(poisoned)
            history_path.write_text("")
            config_path.write_text(json.dumps({"vault": "discard", "clipboard": False, "prompt_file": str(Path(workdir) / "last.txt")}))
            completed = subprocess.run(
                [sys.executable, str(HOOK)],
                input=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": f"test {FAKE_ANTHROPIC} end"}),
                capture_output=True, text=True, timeout=30, check=False,
                env={**os.environ, "OMP_CONFIG": str(config_path), "OMP_HISTORY": str(history_path), "OMP_CLIPBOARD": "0", "OMP_STATS": str(stats_path)},
            )
            self.assertNotIn("Traceback", completed.stderr)
            self.assertEqual(completed.returncode, 0)
            response = json.loads(completed.stdout)
            self.assertEqual(response["decision"], "block")
            self.assertIn("python3 -m omp.telemetry --false-positive", str(response["reason"]))


if __name__ == "__main__":
    unittest.main()
