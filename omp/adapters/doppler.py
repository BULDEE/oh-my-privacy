"""Level 1: Doppler. Written with `doppler secrets set NAME`, value on stdin, silent output.

Known limit: an authenticated Doppler CLI can also READ. On a development machine the agent
can therefore read the vault back through the CLI. What the adapter guarantees is that the
value never enters the context at interception time, and that any later read is an explicit
tool call, visible in the transcript and refusable by a PreToolUse hook. Nothing more.
"""

from __future__ import annotations

import re
import shutil

from omp.adapters.base import StoreError, StoreResult, run_quiet

SECRET_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


class DopplerAdapter:
    name = "doppler"

    def __init__(self, project: str, config: str) -> None:
        if not project or not config:
            raise StoreError("doppler: project and config are required (python3 -m omp.setup)")
        self._project = project
        self._config = config

    def available(self) -> bool:
        return shutil.which("doppler") is not None

    def store(self, name: str, value: str) -> StoreResult:
        if not SECRET_NAME.match(name):
            raise StoreError(f"invalid secret name for Doppler: {name}")
        run_quiet(
            [
                "doppler", "secrets", "set", name,
                "--project", self._project,
                "--config", self._config,
                "--silent",
            ],
            value,
        )
        location = f"doppler {self._project}/{self._config}"
        return StoreResult(
            reference=f"{location} under the name {name}",
            retrieve_hint=f"rename it from the Doppler dashboard, or consume it with doppler run --project {self._project} --config {self._config}",
        )
