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
