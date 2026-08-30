"""Deterministic audit of the 6 confirmed P0 holes (multi-agent review, 2026-08-30).

Each test ASSERTS the fixed behavior. It is therefore RED while the hole is open: it is both
the evidence that the hole exists and the guardrail that turns GREEN once the fix lands. A
guardrail never seen RED proves nothing; this one is born red.

Kept out of the test_*.py pattern so it does not turn the main suite red: it is the dedicated
judge of the security loop, run explicitly.

    Verify: python3 -m unittest tests.audit_security

No real value: every fixture is built at run time.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from omp.detect import detect  # noqa: E402

GUARD = ROOT / "hooks" / "guard.sh"
PRE_BASH = ROOT / "omp" / "pre_bash.py"
HOOK = ROOT / "omp" / "hook.py"
DOTENV = "." + "env"  # keep the session guard from refusing this test file
# Deterministic fixture (no random draw: an audit must replay identically): high entropy, mixed
# case and digits, a single block so it does not read as a structured identifier. Built by
# concatenation so no single literal block is matchable.
OPAQUE_TOKEN = "aB3xK9mZq7Lw2Rt5" + "Nv8Bs1HyJd6Fg0Ac" + "pQ4eW3uT1"


def guard_denies(command: str) -> bool:
    payload = json.dumps({"tool_input": {"command": command}})
    out = subprocess.run([str(GUARD)], input=payload, capture_output=True, text=True, timeout=30, check=False)
    return bool(out.stdout.strip())


class A1UrlBorneSecret(unittest.TestCase):
    """A secret carried by a URL (a Slack webhook, a presigned link) must be inspected."""

    def test_high_entropy_token_in_url_is_detected(self) -> None:
        token = OPAQUE_TOKEN
        _, bare = detect(f"here is {token} end")
        self.assertTrue(bare, "invalid instrument: the bare token must be detected")
        _, in_url = detect(f"curl https://hooks.slack.com/services/T00/B00/{token}")
        self.assertTrue(in_url, "A1: a secret inside a URL is never inspected")


class Hole4PartialMasking(unittest.TestCase):
    """Masking must cover the whole value, not stop at the first punctuation."""

    def test_no_plaintext_tail_survives(self) -> None:
        tail = "TAILTAILTAILTAIL"
        value = "abcdefghij1234567890" + "!!!!" + tail
        cleaned, findings = detect(f'SECRET_KEY = "{value}"')
        self.assertTrue(findings)
        self.assertNotIn(tail, cleaned, "Hole 4: the tail of the secret survives in clear after the placeholder")


class Hole2JsonQuotedKey(unittest.TestCase):
    """A quoted JSON key must not disable context detection."""

    def test_quoted_json_password_is_detected(self) -> None:
        value = "Fake" + "Summer2026Rain"
        _, bare = detect(f"password: {value}")
        self.assertTrue(bare, "invalid instrument: the bare form must be detected")
        _, quoted = detect(f'{{"password": "{value}"}}')
        self.assertTrue(quoted, "Hole 2: a quoted JSON key escapes detection")


class B1MaskingSentinel(unittest.TestCase):
    """The internal substring __omp_o= must not be able to disable Bash masking."""

    def _wraps(self, command: str) -> bool:
        out = subprocess.run([sys.executable, str(PRE_BASH)], input=json.dumps({"tool_input": {"command": command}}),
                             capture_output=True, text=True, timeout=30, check=False)
        if not out.stdout.strip():
            return False
        updated = json.loads(out.stdout).get("hookSpecificOutput", {}).get("updatedInput", {})
        return updated.get("command", "") not in ("", command)

    def test_sentinel_in_comment_still_wraps(self) -> None:
        self.assertTrue(self._wraps("echo hello"), "invalid instrument: a normal command must be wrapped")
        marker = "__omp_o" + "="
        self.assertTrue(self._wraps(f"printenv PATH  # {marker}"), "B1: the sentinel in a comment disables masking")


class GuardQuotedPathBypass(unittest.TestCase):
    """A quoted read of a secret file must be refused like the bare form."""

    def test_quoted_dotenv_read_is_denied(self) -> None:
        self.assertTrue(guard_denies(f"cat {DOTENV}"), "control: the bare form must be refused")
        self.assertTrue(guard_denies(f'cat "{DOTENV}"'), "bypass: quotes get around the refusal")


class F1BlockSurvivesSideEffectFailure(unittest.TestCase):
    """The block must be emitted even if a side effect (writing the cleaned prompt) fails."""

    def test_block_emitted_when_prompt_file_write_fails(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            blocker = Path(workdir) / "blocker"
            blocker.write_text("not a directory")  # makes mkdir(parents) under this path impossible
            config_path = Path(workdir) / "omp.json"
            config_path.write_text(json.dumps({
                "vault": "discard", "clipboard": False,
                "prompt_file": str(blocker / "cleaned.txt"),
            }))
            history_path = Path(workdir) / "history.jsonl"
            history_path.write_text("")
            secret = "api_key=" + OPAQUE_TOKEN
            completed = subprocess.run(
                [sys.executable, str(HOOK)],
                input=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": secret}),
                capture_output=True, text=True, timeout=30, check=False,
                env={"OMP_CONFIG": str(config_path), "OMP_HISTORY": str(history_path),
                     "OMP_CLIPBOARD": "0", "OMP_STATS": str(Path(workdir) / "stats.json"),
                     "PATH": "/usr/bin:/bin"},
            )
            self.assertIn('"block"', completed.stdout, "F1: a failed side effect suppresses the block (fail-open)")


if __name__ == "__main__":
    unittest.main()
