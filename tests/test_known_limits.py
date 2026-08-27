"""Known and accepted bypasses. The threat model is the accident, not the adversary.

Every test here is marked expectedFailure: it documents a limit. The day one of them passes,
the limit is lifted and the marker must go.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import telemetry  # noqa: E402
from omp.detect import detect  # noqa: E402

FAKE_ANTHROPIC = "sk-ant-api03-FAKEKEYFORTESTINGONLY0000000000"


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
    # craftsman-ignore: PY002 (brief-specified implementation, kept as one unit to mirror the exact race reproduction)
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
