from __future__ import annotations

import inspect
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp.adapters import FORBIDDEN_METHODS, REGISTRY, StoreError, build  # noqa: E402
from omp.adapters.age import AgeAdapter  # noqa: E402
from omp.adapters.base import run_quiet  # noqa: E402
from omp.adapters.discard import DiscardAdapter  # noqa: E402
from omp.adapters.doppler import DopplerAdapter  # noqa: E402
from omp.config import Config  # noqa: E402

FAKE_VALUE = "FAKE_VALUE_for_tests_0123456789"


class NoReadPathInvariant(unittest.TestCase):
    def test_no_adapter_exposes_a_read_method(self) -> None:
        for adapter_class in REGISTRY.values():
            public = [name for name, _ in inspect.getmembers(adapter_class) if not name.startswith("_")]
            for forbidden in FORBIDDEN_METHODS:
                self.assertNotIn(forbidden, public, f"{adapter_class.__name__} exposes {forbidden}")

    def test_adapter_source_never_reads_back(self) -> None:
        adapters_dir = Path(__file__).resolve().parent.parent / "omp" / "adapters"
        for source in adapters_dir.glob("*.py"):
            text = source.read_text()
            self.assertNotIn("secrets get", text, source.name)
            self.assertNotIn("secrets download", text, source.name)
            self.assertNotIn('"--decrypt"', text, source.name)
            self.assertNotIn('"-d"', text, source.name)


class Fallbacks(unittest.TestCase):
    def test_unknown_vault_falls_back_to_discard(self) -> None:
        self.assertIsInstance(build(Config(vault="unknown")), DiscardAdapter)

    def test_missing_options_fall_back_to_discard(self) -> None:
        self.assertIsInstance(build(Config(vault="doppler")), DiscardAdapter)
        self.assertIsInstance(build(Config(vault="age")), DiscardAdapter)

    def test_invalid_age_recipient_is_refused(self) -> None:
        with self.assertRaises(StoreError):
            AgeAdapter(recipient="not-a-key")

    def test_doppler_refuses_invalid_secret_name(self) -> None:
        adapter = DopplerAdapter(project="p", config="c")
        with self.assertRaises(StoreError):
            adapter.store("invalid-name; rm -rf /", FAKE_VALUE)


class RunQuiet(unittest.TestCase):
    def test_value_is_passed_on_stdin_not_argv(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            capture = Path(workdir) / "stdin.txt"
            run_quiet(["sh", "-c", f"cat > {capture}"], FAKE_VALUE)
            self.assertEqual(capture.read_text(), FAKE_VALUE)

    def test_failure_message_never_contains_the_value(self) -> None:
        with self.assertRaises(StoreError) as caught:
            run_quiet(["sh", "-c", "read v; echo \"error with $v\" >&2; exit 3"], FAKE_VALUE)
        self.assertNotIn(FAKE_VALUE, str(caught.exception))
        self.assertIn("code 3", str(caught.exception))

    def test_missing_cli_is_a_store_error(self) -> None:
        with self.assertRaises(StoreError):
            run_quiet(["omp-nonexistent-cli"], FAKE_VALUE)


@unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "age not installed")
class AgeRoundTrip(unittest.TestCase):
    def test_ciphertext_is_written_and_not_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            keygen = subprocess.run(["age-keygen"], capture_output=True, text=True, check=True)
            recipient = next(line.split(":", 1)[1].strip() for line in keygen.stdout.splitlines() if line.startswith("# public key:"))
            adapter = AgeAdapter(recipient=recipient, store_dir=workdir)
            result = adapter.store("OMP_TEST_00000000", FAKE_VALUE)
            target = Path(workdir) / "store" / "OMP_TEST_00000000.age"
            self.assertTrue(target.exists())
            self.assertEqual(oct(target.stat().st_mode & 0o777), "0o600")
            self.assertNotIn(FAKE_VALUE.encode(), target.read_bytes())
            self.assertIn("age -d", result.retrieve_hint)
            identity = Path(workdir) / "id.txt"
            identity.write_text(keygen.stdout)
            decrypted = subprocess.run(["age", "-d", "-i", str(identity), str(target)], capture_output=True, text=True, check=True)
            self.assertEqual(decrypted.stdout, FAKE_VALUE)

    def test_decrypt_without_tty_fails_on_passphrase_identity(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            protected = Path(workdir) / "identity.age"
            probe = subprocess.run(
                ["age", "-d", "-i", str(protected), "/dev/null"],
                capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=10, check=False,
                env={**os.environ, "TERM": "dumb"},
            )
            self.assertNotEqual(probe.returncode, 0)


if __name__ == "__main__":
    unittest.main()
