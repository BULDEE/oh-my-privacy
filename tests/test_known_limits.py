"""Known and accepted bypasses. The threat model is the accident, not the adversary.

Every test here is marked expectedFailure: it documents a limit. The day one of them passes,
the limit is lifted and the marker must go.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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


if __name__ == "__main__":
    unittest.main()
