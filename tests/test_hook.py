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


def run_hook(prompt: str, config: dict[str, object] | None = None, raw_config: str | None = None) -> HookRun:
    with tempfile.TemporaryDirectory() as workdir:
        config_path = Path(workdir) / "omp.json"
        prompt_file = Path(workdir) / "last.txt"
        history_path = Path(workdir) / "history.jsonl"
        history_path.write_text(json.dumps({"display": prompt}) + "\n")
        payload: dict[str, object] = {"vault": "discard", "clipboard": False, "prompt_file": str(prompt_file)}
        payload.update(config or {})
        config_path.write_text(raw_config if raw_config is not None else json.dumps(payload))
        completed = subprocess.run(
            [sys.executable, str(HOOK)],
            input=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": prompt}),
            capture_output=True, text=True, timeout=30, check=False,
            env={**os.environ, "OMP_CONFIG": str(config_path), "OMP_HISTORY": str(history_path), "OMP_CLIPBOARD": "0"},
        )
        output = completed.stdout.strip()
        return HookRun(
            response=json.loads(output) if output else None,
            handed=prompt_file.read_text() if prompt_file.exists() else "",
            history=history_path.read_text(),
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


if __name__ == "__main__":
    unittest.main()
