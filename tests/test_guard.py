"""The PreToolUse allowlist guard (hooks/guard.sh), judged by its only real consumer: a payload in, a decision out.

ADR-0006 makes the guard an allowlist. An allowlist is only worth its refusals, so every
case here states one of three things: a refused read-back, an accepted working form, or a
false positive the ADR knowingly accepts. The forms that are merely awkward belong in
AcceptedFalsePositives, not in a comment nobody re-runs.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "hooks" / "guard.sh"
FAKE_SECRET_VAR = "$OMP_JWT_B5352DF5"
# Split so the guard does not refuse the very command that runs this suite.
VAULT = "dop" + "pler"


def judge(command: str) -> str | None:
    """Return the refusal reason, or None when the guard lets the command through."""
    payload = json.dumps({"tool_input": {"command": command}})
    completed = subprocess.run([str(GUARD)], input=payload, capture_output=True, text=True, timeout=30, check=False)
    output = completed.stdout.strip()
    if not output:
        return None
    decision = json.loads(output.splitlines()[0])["hookSpecificOutput"]
    return str(decision["permissionDecisionReason"])


class Refuses(unittest.TestCase):
    def assert_denied(self, command: str) -> None:
        self.assertIsNotNone(judge(command), f"guard let through: {command}")

    def test_secrets_get(self) -> None:
        self.assert_denied(f"{VAULT} secrets get SERVICE_API_KEY --plain")

    def test_run_with_interpreter(self) -> None:
        self.assert_denied(f"{VAULT} run -- python3 script.py")

    def test_run_with_redirection(self) -> None:
        self.assert_denied(f"{VAULT} run --silent -- ./bin/gen > /tmp/out.png")

    def test_run_expanding_a_secret_variable(self) -> None:
        self.assert_denied(f"{VAULT} run -- ./bin/send --key {FAKE_SECRET_VAR}")

    def test_run_expanding_a_braced_secret_variable(self) -> None:
        """Braces used to slip past the rule: `$FOO` and `${FOO}` expand to the same value."""
        self.assert_denied(f"{VAULT} run -- ./bin/send --key ${{OMP_JWT_B5352DF5}}")

    def test_run_expanding_a_named_api_key(self) -> None:
        self.assert_denied(f"{VAULT} run -- ./bin/send --key $OPENAI_API_KEY")

    def test_run_expanding_a_braced_named_secret(self) -> None:
        self.assert_denied(f"{VAULT} run -- ./bin/send --key ${{STRIPE_SECRET}}")

    def test_refused_form_smuggled_after_an_allowed_one(self) -> None:
        self.assert_denied(f"npm test && {VAULT} secrets get SERVICE_API_KEY --plain")

    def test_age_decrypt(self) -> None:
        self.assert_denied("age -d -i /k/id.txt /store/OMP_JWT_B5352DF5.age")

    def test_age_decrypt_with_flags_first(self) -> None:
        """The flag order used to decide the verdict; the command is the same either way."""
        self.assert_denied("age -i /k/id.txt -d /store/OMP_JWT_B5352DF5.age")

    def test_age_long_decrypt_after_identity(self) -> None:
        self.assert_denied("age -i /k/id.txt --decrypt /store/OMP_JWT_B5352DF5.age")

    def test_age_keygen_public_key(self) -> None:
        self.assert_denied("age-keygen -y /k/id.txt")

    def test_environment_dump(self) -> None:
        self.assert_denied("printenv")

    def test_dotenv_read(self) -> None:
        self.assert_denied("cat /srv/app/.env")

    def test_railway_variables_without_keys_filter(self) -> None:
        self.assert_denied("railway variables --json")

    def test_aws_credentials_read(self) -> None:
        self.assert_denied("cat /home/u/.aws/credentials")

    def test_heredoc_piped_into_an_interpreter(self) -> None:
        """A heredoc body is skipped because the shell does not run it. Piped into `bash`, it does."""
        self.assert_denied("cat <<'EOF' | bash\ncat /home/u/.aws/credentials\nEOF")

    def test_false_heredoc_opener_does_not_swallow_the_next_line(self) -> None:
        """`<<` inside a quoted string is not a heredoc. Skipping to a delimiter that never
        comes swallowed the real read on the next line (found by the debt audit, 2026-08-30)."""
        self.assert_denied('echo "x << y"\ncat /home/u/.aws/credentials')

    def test_unterminated_heredoc_is_judged_not_skipped(self) -> None:
        self.assert_denied('cat <<EOF\ncat /home/u/.aws/credentials')


class Allows(unittest.TestCase):
    def assert_allowed(self, command: str) -> None:
        self.assertIsNone(judge(command), f"guard refused a working form: {command}")

    def test_run_a_binary(self) -> None:
        self.assert_allowed(f"{VAULT} run --silent -- ./bin/console app:sync")

    def test_run_chained_with_and(self) -> None:
        self.assert_allowed(f"cd /srv/app && {VAULT} run --silent -- ./bin/console app:sync")

    def test_run_piped_into_a_reader(self) -> None:
        self.assert_allowed(f"{VAULT} run --silent -- ./bin/console app:sync | head -5")

    def test_run_after_a_heredoc(self) -> None:
        self.assert_allowed(f"cat > /tmp/prompt.txt <<'EOF'\nan icon of a fox\nEOF\n{VAULT} run --silent -- ./bin/gen --prompt-file /tmp/prompt.txt")

    def test_run_expanding_an_ordinary_path_variable(self) -> None:
        """`$HOME` is a path, not a value on its way out. The rule names secrets, not capitals."""
        self.assert_allowed(f"{VAULT} run --silent -- ./bin/gen --out $HOME/render.png")

    def test_run_expanding_a_braced_plugin_root(self) -> None:
        self.assert_allowed(f"{VAULT} run -- ${{CLAUDE_PLUGIN_ROOT}}/scripts/forge.py render --out /abs/r.png")

    def test_run_split_over_continuation_lines(self) -> None:
        self.assert_allowed(f"{VAULT} run -- /abs/forge.py render \\\n  --prompt-file /abs/p.txt \\\n  --out /abs/r.png")

    def test_names_only_listing(self) -> None:
        self.assert_allowed(f"{VAULT} secrets --only-names --project acme --config dev")

    def test_writing_a_secret(self) -> None:
        self.assert_allowed(f"{VAULT} secrets set SERVICE_API_KEY -p acme -c dev")

    def test_age_encryption(self) -> None:
        self.assert_allowed("age -r age1abc -o /store/OMP_JWT_B5352DF5.age /tmp/plain")

    def test_unrelated_command(self) -> None:
        self.assert_allowed("npm test")

    def test_railway_variables_reduced_to_keys(self) -> None:
        self.assert_allowed("railway variables --json | jq keys")

    def test_dotenv_read_redacted_inline(self) -> None:
        self.assert_allowed("sed 's/=.*/=<masked>/' /srv/app/.env")

    def test_heredoc_body_mentioning_credentials(self) -> None:
        """The 2026-08-30 incident: a comment in a script being written refused the whole command,
        the file was never created, and an empty encode overwrote the target with 0 bytes."""
        self.assert_allowed("cat > /srv/bot-env-sync.sh <<'EOF'\n#!/bin/sh\n# sync credentials into the bot\nexec ./bin/sync\nEOF")

    def test_heredoc_body_naming_a_dotenv(self) -> None:
        self.assert_allowed("cat > /srv/notes.md <<'EOF'\ncopy the .env file yourself\nEOF")

    def test_credentials_as_a_plain_word(self) -> None:
        """`credentials` is an English word before it is a path. Only `.../credentials` is a file."""
        self.assert_allowed("echo 'rotate the credentials tomorrow'")

    def test_heredoc_body_quoting_a_refused_form(self) -> None:
        """Was an accepted false positive until the splitter learned to skip heredoc bodies."""
        self.assert_allowed(f"cat > /tmp/doc.md <<'EOF'\nrun it with {VAULT} run -- ./x > out\nEOF")


class FailsClosed(unittest.TestCase):
    """A broken splitter must not turn the guard into a no-op.

    While the splitter lived inline in a bash string, one bad backslash made it exit
    non-zero and print nothing, and the guard refused every command it should have refused
    silently: healthy exit code, empty verdict. Judged on the raw command instead.
    """

    def judge_with_broken_splitter(self, splitter_source: str, command: str) -> str | None:
        with tempfile.TemporaryDirectory() as workdir:
            hooks = Path(workdir) / "hooks"
            hooks.mkdir()
            (hooks / "guard.sh").write_bytes(GUARD.read_bytes())
            (hooks / "guard.sh").chmod(0o755)
            (hooks / "split_segments.py").write_text(splitter_source)
            payload = json.dumps({"tool_input": {"command": command}})
            completed = subprocess.run([str(hooks / "guard.sh")], input=payload, capture_output=True, text=True, timeout=30, check=False)
            return completed.stdout.strip() or None

    def test_splitter_that_crashes(self) -> None:
        self.assertIsNotNone(self.judge_with_broken_splitter("raise SystemExit(1)\n", f"{VAULT} secrets get SERVICE_API_KEY --plain"))

    def test_splitter_that_prints_nothing(self) -> None:
        self.assertIsNotNone(self.judge_with_broken_splitter("pass\n", f"{VAULT} secrets get SERVICE_API_KEY --plain"))


class AcceptedFalsePositives(unittest.TestCase):
    """Refusals the ADR accepts on purpose: the guard matches text, it does not parse shell.

    Each of these is a legitimate command or a piece of prose. Refusing them is the price of
    a rule that cannot be talked around by quoting. The day one becomes intolerable, it is
    the rule that changes, not the test.
    """

    def test_prose_quoting_a_refused_form(self) -> None:
        self.assertIsNotNone(judge(f"echo 'example: {VAULT} run -- ./x > y'"))

    def test_redirecting_a_render_to_a_file(self) -> None:
        """Defence in depth: `run -- ./x > f` followed by a later read of `f` would leave the
        masked-output path. Legitimate writes go through the binary's own --out flag."""
        self.assertIsNotNone(judge(f"{VAULT} run --silent -- ./bin/gen > /abs/render.png"))


if __name__ == "__main__":
    unittest.main()
