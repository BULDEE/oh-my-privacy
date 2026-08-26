"""Level 2: age, public-key encryption, passphrase-gated decryption.

The hook encrypts with the recipient's public key: no secret is needed to write, so nothing
to protect on the hook side. The private identity is itself passphrase-encrypted at setup
time (`age -p`), and age prompts for that passphrase on /dev/tty when decrypting. The agent's
shell tool has no terminal: `age -d` fails for it and succeeds for you. It is the only local
lock that holds against a process running under your own UID, and it holds without relying
on any denylist.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from omp.adapters.base import StoreError, StoreResult, run_quiet

DEFAULT_STORE_DIR = Path.home() / ".claude" / "omp"
IDENTITY_FILE = "identity.age"


class AgeAdapter:
    name = "age"

    def __init__(self, recipient: str, store_dir: str = "") -> None:
        if not recipient.startswith("age1"):
            raise StoreError("age: recipient missing or invalid (python3 -m omp.setup)")
        self._recipient = recipient
        self._store_dir = Path(store_dir).expanduser() if store_dir else DEFAULT_STORE_DIR

    def available(self) -> bool:
        return shutil.which("age") is not None

    def store(self, name: str, value: str) -> StoreResult:
        target_dir = self._store_dir / "store"
        target_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(target_dir, 0o700)
        target = target_dir / f"{name}.age"
        run_quiet(["age", "--encrypt", "--recipient", self._recipient, "--output", str(target)], value)
        os.chmod(target, 0o600)
        identity = self._store_dir / IDENTITY_FILE
        return StoreResult(
            reference=f"encrypted at {target}",
            retrieve_hint=f"age -d -i {identity} {target}  (asks for your passphrase, impossible without a terminal)",
        )
