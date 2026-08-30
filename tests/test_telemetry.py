"""Local telemetry: volume and friction, never a secret value."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import telemetry  # noqa: E402
from omp.adapters import build  # noqa: E402
from omp.config import Config  # noqa: E402
from omp.usecase import intercept  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# Synthetic, never a real credential: built by concatenation so this file itself carries no matchable literal.
FAKE_AWS_KEY = "AKIA" + "FAKENOTAREALKEY0"
POISONED_STORE = (
    '{"version":1,"counters":{"claude_code.prompt.anthropic.block":'
    '{"count":1e400,"latency_ms_total":1.0,"false_positive_count":0}},"recent_events":[]}'
)


@contextlib.contextmanager
def bounded(seconds: int = 5) -> Iterator[None]:
    """A FIFO-hang regression must fail loudly, not hang the whole suite (or CI) forever."""
    previous = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError(f"hung past {seconds}s")))
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


@dataclass(frozen=True)
class NotALabel:
    """Stands in for `Finding`: a dataclass whose auto-generated repr carries the value."""

    kind: str
    value: str


class Recording(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.TemporaryDirectory()
        self.stats_path = Path(self.workdir.name) / "stats.json"
        self.previous_config = os.environ.get("OMP_CONFIG")
        os.environ["OMP_CONFIG"] = str(Path(self.workdir.name) / "omp.json")

    def tearDown(self) -> None:
        if self.previous_config is None:
            del os.environ["OMP_CONFIG"]
        else:
            os.environ["OMP_CONFIG"] = self.previous_config
        self.workdir.cleanup()

    def test_deny_cli_records_a_block_event_for_the_rule(self) -> None:
        previous_stats = os.environ.get("OMP_STATS")
        os.environ["OMP_STATS"] = str(self.stats_path)
        try:
            telemetry.main(["--deny", "doppler_read"])
        finally:
            if previous_stats is None:
                os.environ.pop("OMP_STATS", None)
            else:
                os.environ["OMP_STATS"] = previous_stats
        events = telemetry.load(self.stats_path)["recent_events"]
        self.assertTrue(
            any(item["action"] == "block" and item["kinds"] == ["doppler_read"] and item["tool"] == "Bash" for item in events),
            events,
        )

    def test_a_fifo_at_omp_config_does_not_hang_record(self) -> None:
        """record() reads omp.json on every call (the telemetry on/off flag) via omp.config.load(),
        a path four of the six hosts never touched before telemetry existed. The same FIFO hang
        this module hardened its own store against applies one file over unless config.py's own
        reader is hardened too - it now is (see omp/config.py's _read_json)."""
        config_path = Path(os.environ["OMP_CONFIG"])
        os.mkfifo(config_path)
        try:
            with bounded():
                event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        finally:
            config_path.unlink()
        self.assertIsNotNone(event_id)

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
        """The whole reason this module exists: run a real secret through the real pipeline, then look for it on disk."""
        adapter = build(Config(vault="discard", clipboard=False, prompt_file=None))
        interception = intercept(f"deploy with {FAKE_AWS_KEY} now", adapter)
        assert interception is not None
        kinds = [outcome.kind for outcome in interception.outcomes]
        self.assertEqual(kinds, ["aws"])
        event_id = telemetry.record("claude_code", "prompt", kinds, "block", 1.0, path=self.stats_path)
        self.assertIsNotNone(event_id)
        raw = self.stats_path.read_text()
        self.assertIn("aws", raw)
        self.assertNotIn(FAKE_AWS_KEY, raw)

    def test_a_finding_shaped_object_is_refused_before_anything_is_written(self) -> None:
        """The mistake `architecture.md`'s extension-points row invites: pass Findings, not `.kind` labels."""
        disguised = NotALabel(kind="aws", value=FAKE_AWS_KEY)
        event_id = telemetry.record("claude_code", "prompt", [disguised], "block", 1.0, path=self.stats_path)
        self.assertIsNone(event_id)
        self.assertFalse(self.stats_path.exists())
        # The store is not the only file on this path: a half-written temp file would carry the repr just as well.
        for leftover in Path(self.workdir.name).iterdir():
            self.assertNotIn(FAKE_AWS_KEY, leftover.read_text(errors="replace"), f"the value reached {leftover}")

    def test_a_non_string_kind_is_rejected_and_nothing_is_written(self) -> None:
        event_id = telemetry.record("claude_code", "prompt", [123], "block", 1.0, path=self.stats_path)
        self.assertIsNone(event_id)
        self.assertFalse(self.stats_path.exists())

    def test_hostile_argument_types_are_refused_without_raising(self) -> None:
        """The `never raises` contract has to hold for a caller that ignores the signature entirely."""
        for host, tool, kinds in ((123, "prompt", ["aws"]), ("hermes", None, ["aws"]), ("hermes", "terminal", [b"aws"])):
            self.assertIsNone(telemetry.record(host, tool, kinds, "block", 1.0, path=self.stats_path))
        self.assertFalse(self.stats_path.exists())

    def test_an_infinite_counter_in_the_store_never_raises(self) -> None:
        """`1e400` is valid JSON and parses to inf: `int(inf)` raises OverflowError, not ValueError."""
        self.stats_path.write_text(POISONED_STORE)
        event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path, event_id="feedface")
        self.assertEqual(event_id, "feedface")
        store = telemetry.load(self.stats_path)
        counters = store["counters"]
        assert isinstance(counters, dict)
        self.assertEqual(counters["claude_code.prompt.anthropic.block"]["count"], 1)

    def test_a_huge_integer_latency_in_the_store_never_raises_and_the_bucket_still_heals(self) -> None:
        """A 400-digit integer is valid JSON `int()` accepts without raising, but `float()` on it does
        (`OverflowError`, converting to a C double) - the same failure mode as `1e400`, different literal
        form. Unlike the `1e400` case, this one used to escape `_bump` and abort `record()` before
        `_save()`, leaving the bucket permanently un-healed even though `record()` itself never raised."""
        huge = "9" * 400
        poisoned = (
            '{"version":1,"counters":{"claude_code.prompt.anthropic.block":'
            f'{{"count":1,"latency_ms_total":{huge},"false_positive_count":0}}}},"recent_events":[]}}'
        )
        self.stats_path.write_text(poisoned)
        event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        self.assertIsNotNone(event_id)
        store = telemetry.load(self.stats_path)
        counters = store["counters"]
        assert isinstance(counters, dict)
        bucket = counters["claude_code.prompt.anthropic.block"]
        self.assertEqual(bucket["count"], 2)
        self.assertEqual(bucket["latency_ms_total"], 1.0)

    def test_a_supplied_event_id_is_used_verbatim(self) -> None:
        event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path, event_id="cafebabe")
        self.assertEqual(event_id, "cafebabe")
        self.assertIn('"id": "cafebabe"', self.stats_path.read_text())

    def test_an_oversized_store_is_treated_as_missing(self) -> None:
        """Parseable but far past the cap: the size check must fire before the parse, not after it."""
        padded = '{"version":1,"counters":{"claude_code.prompt.anthropic.block":{"count":7}},"recent_events":[]}' + " " * telemetry.MAX_STATS_BYTES
        self.stats_path.write_text(padded)
        self.assertGreater(self.stats_path.stat().st_size, telemetry.MAX_STATS_BYTES)
        store = telemetry.load(self.stats_path)
        self.assertEqual(store["counters"], {})

    def test_bucket_creation_stops_at_the_cap(self) -> None:
        seed = {"count": 1, "latency_ms_total": 1.0, "false_positive_count": 0}
        counters: dict[str, object] = {f"bucket{index}": dict(seed) for index in range(telemetry.MAX_BUCKETS)}
        telemetry._bump(counters, "brand.new.bucket.block", 1.0)  # noqa: SLF001
        self.assertNotIn("brand.new.bucket.block", counters)
        telemetry._bump(counters, "bucket0", 1.0)  # noqa: SLF001
        bucket = counters["bucket0"]
        assert isinstance(bucket, dict)
        self.assertEqual(bucket["count"], 2)

    def test_unsafe_kind_characters_are_sanitized_in_the_bucket_key(self) -> None:
        telemetry.record("claude_code", "prompt", ["evil\nkind; rm -rf $(whoami)"], "block", 1.0, path=self.stats_path)
        store = telemetry.load(self.stats_path)
        counters = store["counters"]
        assert isinstance(counters, dict)
        self.assertIn("claude_code.prompt.evil_kind__rm_-rf___whoami_.block", counters)
        raw = self.stats_path.read_text()
        self.assertNotIn("$(whoami)", raw)

    def test_unsafe_tool_characters_are_sanitized_in_the_bucket_key(self) -> None:
        telemetry.record("claude_code", "evil\ntool; rm -rf $(whoami)", ["anthropic"], "block", 1.0, path=self.stats_path)
        store = telemetry.load(self.stats_path)
        counters = store["counters"]
        assert isinstance(counters, dict)
        self.assertIn("claude_code.evil_tool__rm_-rf___whoami_.anthropic.block", counters)
        for key in counters:
            self.assertNotIn("\n", key)
            self.assertNotIn(";", key)
            self.assertNotIn("$", key)


class SaveHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.TemporaryDirectory()
        self.stats_path = Path(self.workdir.name) / "stats.json"
        self.previous_config = os.environ.get("OMP_CONFIG")
        os.environ["OMP_CONFIG"] = str(Path(self.workdir.name) / "omp.json")

    def tearDown(self) -> None:
        if self.previous_config is None:
            del os.environ["OMP_CONFIG"]
        else:
            os.environ["OMP_CONFIG"] = self.previous_config
        self.workdir.cleanup()

    def test_a_symlinked_store_is_replaced_never_written_through(self) -> None:
        """An attacker who pre-plants the store as a symlink must not get the target truncated."""
        sensitive = Path(self.workdir.name) / "sensitive.txt"
        sensitive.write_text("do not truncate me")
        self.stats_path.symlink_to(sensitive)
        telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        self.assertEqual(sensitive.read_text(), "do not truncate me")
        self.assertFalse(self.stats_path.is_symlink())
        self.assertIn("anthropic", self.stats_path.read_text())

    def test_an_existing_store_with_loose_permissions_is_replaced_by_a_private_one(self) -> None:
        self.stats_path.write_text("{}")
        self.stats_path.chmod(0o644)
        telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        self.assertEqual(self.stats_path.stat().st_mode & 0o777, 0o600)

    def test_the_write_is_a_rename_so_the_store_is_valid_json_at_rest(self) -> None:
        """The swap is atomic: a reader never sees a partial store, and no temp file survives the call.

        The temp filename embeds the writer's pid and a random suffix (so concurrent writers never
        collide on the same path), so this checks for any leftover `*.tmp` sibling, not one fixed name.
        """
        for _ in range(3):
            telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
            json.loads(self.stats_path.read_text())
        self.assertEqual(list(Path(self.workdir.name).glob("*.tmp")), [])

    def test_a_fifo_at_the_store_path_is_healed_instead_of_hanging(self) -> None:
        """A hostile local process can `mkfifo` the store path. `load()` refuses to open it for read
        (never blocks), and `_save()`'s unpredictable, per-call temp filename means the write side
        never touches the FIFO either - it writes a fresh regular file elsewhere and `rename()`s over
        the FIFO, which POSIX allows unconditionally regardless of the target's type. Net effect:
        the call still succeeds and the FIFO is gone, replaced by a real store - never a hang."""
        os.mkfifo(self.stats_path)
        with bounded():
            event_id = telemetry.record("claude_code", "prompt", ["anthropic"], "block", 1.0, path=self.stats_path)
        self.assertIsNotNone(event_id)
        self.assertFalse(stat.S_ISFIFO(self.stats_path.lstat().st_mode))
        self.assertIn("anthropic", self.stats_path.read_text())

    def test_a_fifo_at_the_store_path_makes_load_return_the_empty_store_instead_of_hanging(self) -> None:
        os.mkfifo(self.stats_path)
        try:
            with bounded():
                store = telemetry.load(self.stats_path)
        finally:
            self.stats_path.unlink()
        self.assertEqual(store["counters"], {})


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

    def test_mark_false_positive_is_a_no_op_when_telemetry_is_off(self) -> None:
        """The opt-out covers the whole module: a disabled store is never read back nor rewritten."""
        seeded = json.dumps(
            {
                "version": 1,
                "counters": {"claude_code.prompt.anthropic.block": {"count": 1, "latency_ms_total": 1.0, "false_positive_count": 0}},
                "recent_events": [
                    {"id": "abcd1234", "host": "claude_code", "tool": "prompt", "kinds": ["anthropic"], "action": "block", "false_positive": False},
                ],
            }
        )
        self.stats_path.write_text(seeded)
        self.assertFalse(telemetry.mark_false_positive("abcd1234", path=self.stats_path))
        self.assertEqual(self.stats_path.read_text(), seeded)


class FalsePositive(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.TemporaryDirectory()
        self.stats_path = Path(self.workdir.name) / "stats.json"
        self.previous_config = os.environ.get("OMP_CONFIG")
        os.environ["OMP_CONFIG"] = str(Path(self.workdir.name) / "omp.json")

    def tearDown(self) -> None:
        if self.previous_config is None:
            del os.environ["OMP_CONFIG"]
        else:
            os.environ["OMP_CONFIG"] = self.previous_config
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

    def test_a_malformed_bucket_is_skipped_instead_of_crashing_the_report(self) -> None:
        store: dict[str, object] = {
            "version": 1,
            "counters": {
                "claude_code.prompt.anthropic.block": {"count": 2, "latency_ms_total": 10.0, "false_positive_count": 1},
                "claude_code.prompt.infinite.block": {"count": float("inf"), "latency_ms_total": 1.0, "false_positive_count": 0},
                "claude_code.prompt.nan.block": {"count": 1, "latency_ms_total": float("nan"), "false_positive_count": 0},
                "claude_code.prompt.textual.block": {"count": "many", "latency_ms_total": 1.0, "false_positive_count": 0},
            },
            "recent_events": [],
        }
        report = telemetry.format_report(store)
        self.assertIn("claude_code.prompt.anthropic.block", report)
        self.assertNotIn("infinite", report)
        self.assertNotIn("nan", report)
        self.assertNotIn("textual", report)

    def test_a_huge_integer_count_does_not_crash_the_average_calculation(self) -> None:
        """`count` survives `int()` unraised (ints have no size limit), but `total_latency / count` then
        converts `count` to a C double for the division, which raises `OverflowError` past ~1.8e308 -
        arithmetic that used to sit outside the try/except guarding the type coercions above it."""
        store: dict[str, object] = {
            "version": 1,
            "counters": {"claude_code.prompt.anthropic.block": {"count": int("9" * 400), "latency_ms_total": 1.0, "false_positive_count": 0}},
            "recent_events": [],
        }
        report = telemetry.format_report(store)
        self.assertNotIn("anthropic", report)

    def test_a_hostile_bucket_key_is_sanitized_before_it_reaches_the_terminal(self) -> None:
        store: dict[str, object] = {
            "version": 1,
            "counters": {"claude_code.\x1b[31mevil\r.anthropic.block": {"count": 1, "latency_ms_total": 1.0, "false_positive_count": 0}},
            "recent_events": [],
        }
        report = telemetry.format_report(store)
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\r", report)
        self.assertIn("claude_code.__31mevil_.anthropic.block", report)


class Cli(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.TemporaryDirectory()
        self.previous_config = os.environ.get("OMP_CONFIG")
        os.environ["OMP_CONFIG"] = str(Path(self.workdir.name) / "omp.json")

    def tearDown(self) -> None:
        if self.previous_config is None:
            del os.environ["OMP_CONFIG"]
        else:
            os.environ["OMP_CONFIG"] = self.previous_config
        self.workdir.cleanup()

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
