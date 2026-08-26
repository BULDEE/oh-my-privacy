from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp.history import scrub  # noqa: E402

FAKE = "sk-ant-api03-FAKEKEYFORTESTINGONLY0000000000"
NOW_MS = 1_800_000_000_000


def history_with(lines: list[dict[str, object]]) -> Path:
    workdir = tempfile.mkdtemp()
    path = Path(workdir) / "history.jsonl"
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    os.chmod(path, 0o600)
    return path


class Scrub(unittest.TestCase):
    def test_recent_secret_is_replaced_without_being_told_the_value(self) -> None:
        path = history_with([
            {"display": "hello", "timestamp": NOW_MS - 10},
            {"display": f"test {FAKE} end", "pastedContents": {"1": {"content": FAKE}}, "timestamp": NOW_MS},
            {"display": "goodbye", "timestamp": NOW_MS + 10},
        ])
        touched = scrub(NOW_MS - 1000, path)
        self.assertEqual(touched, 1)
        text = path.read_text()
        self.assertNotIn(FAKE, text)
        self.assertIn("test $OMP_ANTHROPIC_", text)
        self.assertEqual(text.count("$OMP_ANTHROPIC_"), 2)
        self.assertEqual(text.count("\n"), 3)
        self.assertIn("hello", text)
        self.assertIn("goodbye", text)

    def test_old_entries_are_left_alone(self) -> None:
        path = history_with([{"display": FAKE, "timestamp": NOW_MS - 10_000_000}])
        self.assertEqual(scrub(NOW_MS, path), 0)
        self.assertIn(FAKE, path.read_text())

    def test_entry_without_timestamp_is_treated_as_recent(self) -> None:
        path = history_with([{"display": FAKE}])
        self.assertEqual(scrub(NOW_MS, path), 1)

    def test_permissions_are_preserved(self) -> None:
        path = history_with([{"display": FAKE, "timestamp": NOW_MS}])
        scrub(0, path)
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")

    def test_clean_history_is_left_alone(self) -> None:
        path = history_with([{"display": "nothing", "timestamp": NOW_MS}])
        before = path.stat().st_mtime_ns
        self.assertEqual(scrub(0, path), 0)
        self.assertEqual(path.stat().st_mtime_ns, before)

    def test_missing_history_is_not_an_error(self) -> None:
        self.assertEqual(scrub(0, Path("/nonexistent/history.jsonl")), 0)

    def test_unicode_survives(self) -> None:
        path = history_with([{"display": f"key 🔑 {FAKE} naïve", "timestamp": NOW_MS}])
        scrub(0, path)
        self.assertIn("key 🔑 $OMP_ANTHROPIC_", path.read_text())
        self.assertIn("naïve", path.read_text())


if __name__ == "__main__":
    unittest.main()
