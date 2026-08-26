"""Vault adapter contract.

Design invariant: an adapter exposes `store`, never a read. OhMyPrivacy builds no path back
to the value. What does not exist cannot be exfiltrated, and that is the only guarantee that
does not rest on the discipline of a denylist.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol

FORBIDDEN_METHODS = ("get", "read", "fetch", "load", "reveal", "export", "dump")
SUBPROCESS_TIMEOUT_SECONDS = 20


class StoreError(Exception):
    """The vault refused the value. The message never contains the value."""


@dataclass(frozen=True)
class StoreResult:
    reference: str
    retrieve_hint: str


class VaultAdapter(Protocol):
    name: str

    def available(self) -> bool: ...

    def store(self, name: str, value: str) -> StoreResult: ...


def run_quiet(argv: list[str], value: str) -> None:
    """Run a CLI, passing the value on stdin, never on argv.

    argv is visible to every process on the machine (`ps`); stdin is not. Output is captured
    and the value is redacted from it before it surfaces in an error.
    """
    try:
        completed = subprocess.run(
            argv,
            input=value,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as error:
        raise StoreError(f"CLI not found: {argv[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise StoreError(f"{argv[0]} did not answer within {SUBPROCESS_TIMEOUT_SECONDS}s") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        first_line = detail[0] if detail else "no detail"
        raise StoreError(f"{argv[0]} failed (exit code {completed.returncode}): {first_line.replace(value, '<value>')}")
