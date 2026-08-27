"""The four agent-side vectors: Bash output, Read, Grep content, and tool results left on disk."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE = "sk-ant-api03-FAKEKEYFORTESTINGONLY0000000000"
CLAUDE = os.environ.get("CLAUDE_CODE_EXECPATH") or shutil.which("claude")


def run_hook(script: str, payload: dict[str, object], env: dict[str, str] | None = None) -> dict[str, object] | None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "omp" / script)], input=json.dumps(payload),
        capture_output=True, text=True, timeout=60, env={**os.environ, **(env or {})},
    )
    return json.loads(completed.stdout) if completed.stdout.strip() else None


class Workspace(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.env_file = self.work / ".env"
        self.env_file.write_text(f"DEBUG=1\nANTHROPIC_API_KEY={FAKE}\n")

    def bash_payload(self, command: str) -> dict[str, object]:
        return {"tool_name": "Bash", "tool_input": {"command": command}}


class BashOutputMasking(Workspace):
    def wrapped(self, command: str) -> str:
        response = run_hook("pre_bash.py", self.bash_payload(command), {"OMP_CHAIN_HOOK": ""})
        assert response is not None
        specific = response["hookSpecificOutput"]
        assert isinstance(specific, dict)
        updated = specific["updatedInput"]
        assert isinstance(updated, dict)
        return str(updated["command"])

    def test_stdout_and_stderr_are_masked_and_status_kept(self) -> None:
        command = self.wrapped("cat .env; echo TOKEN=" + FAKE + " >&2; false")
        shell = subprocess.run(["bash", "-c", command], capture_output=True, text=True, cwd=self.work)
        self.assertNotIn(FAKE, shell.stdout + shell.stderr)
        self.assertIn("$OMP_ANTHROPIC_", shell.stdout)
        self.assertIn("[OhMyPrivacy", shell.stderr)
        self.assertEqual(shell.returncode, 1)

    def test_exit_inside_the_command_still_masks(self) -> None:
        shell = subprocess.run(["bash", "-c", self.wrapped("cat .env; exit 3")], capture_output=True, text=True, cwd=self.work)
        self.assertNotIn(FAKE, shell.stdout)
        self.assertIn("$OMP_ANTHROPIC_", shell.stdout)
        self.assertEqual(shell.returncode, 3)

    def test_cd_persists_in_the_calling_shell(self) -> None:
        (self.work / "sub").mkdir()
        shell = subprocess.run(["bash", "-c", self.wrapped("cd sub") + "; pwd"], capture_output=True, text=True, cwd=self.work)
        self.assertTrue(shell.stdout.strip().endswith("/sub"))

    def test_clean_output_is_unchanged(self) -> None:
        shell = subprocess.run(["bash", "-c", self.wrapped("printf 'a\\nb\\n'")], capture_output=True, text=True, cwd=self.work)
        self.assertEqual(shell.stdout, "a\nb\n")
        self.assertEqual(shell.stderr, "")

    def test_already_wrapped_command_is_left_alone(self) -> None:
        self.assertIsNone(run_hook("pre_bash.py", self.bash_payload("__omp_o=1; true"), {"OMP_CHAIN_HOOK": ""}))

    def test_chained_hook_rewrite_is_wrapped(self) -> None:
        chain = self.work / "chain.py"
        chain.write_text(
            "import json,sys; d=json.load(sys.stdin); "
            "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'updatedInput': {'command': 'echo chained'}}}))\n"
        )
        response = run_hook("pre_bash.py", self.bash_payload("echo original"), {"OMP_CHAIN_HOOK": f"{sys.executable} {chain}"})
        assert response is not None
        command = str(response["hookSpecificOutput"]["updatedInput"]["command"])  # type: ignore[index]
        self.assertIn("echo chained", command)
        self.assertNotIn("echo original", command)

    def test_chained_deny_passes_through(self) -> None:
        chain = self.work / "deny.py"
        chain.write_text(
            "import json; "
            "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecisionReason': 'no'}}))\n"
        )
        response = run_hook("pre_bash.py", self.bash_payload("echo x"), {"OMP_CHAIN_HOOK": f"{sys.executable} {chain}"})
        assert response is not None
        self.assertEqual(response["hookSpecificOutput"]["permissionDecision"], "deny")  # type: ignore[index]

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


class ReadRedirection(Workspace):
    def test_secret_file_is_read_through_a_masked_copy(self) -> None:
        payload = {"tool_name": "Read", "tool_input": {"file_path": str(self.env_file)}}
        response = run_hook("pre_read.py", payload, {"OMP_MASKED_DIR": str(self.work / "masked")})
        assert response is not None
        updated = response["hookSpecificOutput"]["updatedInput"]  # type: ignore[index]
        copy = Path(updated["file_path"])
        self.assertTrue(str(copy).startswith(str(self.work / "masked")))
        self.assertNotIn(FAKE, copy.read_text())
        self.assertIn("$OMP_ANTHROPIC_", copy.read_text())
        self.assertEqual(oct(copy.stat().st_mode & 0o777), "0o600")
        self.assertIn(FAKE, self.env_file.read_text())

    def test_clean_file_is_not_redirected(self) -> None:
        clean = self.work / "clean.txt"
        clean.write_text("nothing here\n")
        self.assertIsNone(run_hook("pre_read.py", {"tool_name": "Read", "tool_input": {"file_path": str(clean)}}))

    def test_binary_file_is_left_alone(self) -> None:
        binary = self.work / "blob.bin"
        binary.write_bytes(b"\x00\x01" + FAKE.encode())
        self.assertIsNone(run_hook("pre_read.py", {"tool_name": "Read", "tool_input": {"file_path": str(binary)}}))

    def test_masking_records_telemetry(self) -> None:
        stats_path = self.work / "stats.json"
        payload = {"tool_name": "Read", "tool_input": {"file_path": str(self.env_file)}}
        run_hook("pre_read.py", payload, {"OMP_MASKED_DIR": str(self.work / "masked"), "OMP_STATS": str(stats_path)})
        stats = stats_path.read_text()
        self.assertIn('"host": "claude_code"', stats)
        self.assertIn('"tool": "Read"', stats)
        self.assertIn('"action": "mask"', stats)


@unittest.skipUnless(CLAUDE, "claude binary not found (ripgrep host)")
class GrepContent(Workspace):
    def test_content_mode_with_secret_is_denied_with_masked_matches(self) -> None:
        payload = {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": str(self.work), "output_mode": "content"}}
        response = run_hook("pre_grep.py", payload, {"CLAUDE_CODE_EXECPATH": str(CLAUDE)})
        assert response is not None
        specific = response["hookSpecificOutput"]
        assert isinstance(specific, dict)
        self.assertEqual(specific["permissionDecision"], "deny")
        self.assertNotIn(FAKE, str(specific["permissionDecisionReason"]))
        self.assertIn("$OMP_ANTHROPIC_", str(specific["permissionDecisionReason"]))

    def test_files_with_matches_mode_is_untouched(self) -> None:
        self.assertIsNone(run_hook("pre_grep.py", {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": str(self.work)}}))

    def test_masking_records_telemetry(self) -> None:
        stats_path = self.work / "stats.json"
        payload = {"tool_name": "Grep", "tool_input": {"pattern": "KEY", "path": str(self.work), "output_mode": "content"}}
        run_hook("pre_grep.py", payload, {"CLAUDE_CODE_EXECPATH": str(CLAUDE), "OMP_STATS": str(stats_path)})
        stats = stats_path.read_text()
        self.assertIn('"host": "claude_code"', stats)
        self.assertIn('"tool": "Grep"', stats)
        self.assertIn('"action": "mask"', stats)


class PostToolScrub(Workspace):
    def test_leaked_response_scrubs_transcript_and_snapshots_and_warns(self) -> None:
        transcript = self.work / "t.jsonl"
        transcript.write_text(json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "content": f"token {FAKE}"}]}}) + "\n")
        snapshots = self.work / "file-history" / "s1"
        snapshots.mkdir(parents=True)
        (snapshots / "snap@v1").write_text(f"KEY={FAKE}\n")
        response = run_hook(
            "post_scrub.py",
            {"tool_name": "mcp__x__vars", "tool_input": {}, "tool_response": {"K": FAKE}, "session_id": "s1", "transcript_path": str(transcript)},
            {"OMP_FILE_HISTORY": str(self.work / "file-history"), "OMP_PASTE_CACHE": str(self.work / "nocache"), "OMP_SCRUB_FILE_HISTORY": "1"},
        )
        assert response is not None
        self.assertIn("could not be masked", str(response["hookSpecificOutput"]["additionalContext"]))  # type: ignore[index]
        self.assertNotIn(FAKE, transcript.read_text())
        self.assertNotIn(FAKE, (snapshots / "snap@v1").read_text())

    def test_clean_response_is_silent(self) -> None:
        payload = {"tool_name": "Bash", "tool_input": {}, "tool_response": "ok", "session_id": "s", "transcript_path": "/nonexistent"}
        self.assertIsNone(run_hook("post_scrub.py", payload))

    def test_own_masked_copy_path_in_response_metadata_is_not_a_leak(self) -> None:
        """Read's tool_response echoes back the redirected file_path pre_read.py chose.

        The default root is `~/.claude/omp/masked/`: the dot right before `claude` breaks the
        entropy regex there, so the match starts at `claude`, not at the leading `/`, and the
        `/`-prefix exclusion never applies. The path then mixes lowercase, uppercase (the
        original filename) and a hex digest, which is enough on its own to pass the entropy
        heuristic: the plugin flagged its own bookkeeping as the secret it exists to prevent.
        A masked root with no dotfile segment would not reproduce this.
        """
        masked_root = self.work / ".claude" / "omp" / "masked"
        own_path = str(masked_root / "abcdef0123456789" / "README.md")
        payload = {
            "tool_name": "Read",
            "tool_input": {"file_path": own_path},
            "tool_response": {"type": "text", "file": {"filePath": own_path, "content": "nothing secret here\n"}},
            "session_id": "s",
            "transcript_path": "/nonexistent",
        }
        self.assertIsNone(run_hook("post_scrub.py", payload, {"OMP_MASKED_DIR": str(masked_root)}))

    def test_real_secret_next_to_own_masked_copy_path_still_warns(self) -> None:
        masked_root = self.work / "masked"
        own_path = str(masked_root / "abcdef0123456789" / "README.md")
        payload = {
            "tool_name": "Read",
            "tool_input": {"file_path": own_path},
            "tool_response": {"filePath": own_path, "content": f"token {FAKE}"},
            "session_id": "s",
            "transcript_path": "/nonexistent",
        }
        response = run_hook("post_scrub.py", payload, {"OMP_MASKED_DIR": str(masked_root)})
        assert response is not None
        self.assertIn("could not be masked", str(response["hookSpecificOutput"]["additionalContext"]))  # type: ignore[index]


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

if __name__ == "__main__":
    unittest.main()
