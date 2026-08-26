"""Level 3, the default: the value is stored nowhere.

It was intercepted before reaching the model, it lives in the hook's memory for the duration
of the run, then the process dies with it. Zero surface. This is the behaviour of a plugin
that knows nothing about the machine it runs on.
"""

from __future__ import annotations

from omp.adapters.base import StoreResult


class DiscardAdapter:
    name = "discard"

    def available(self) -> bool:
        return True

    def store(self, name: str, value: str) -> StoreResult:
        return StoreResult(
            reference="discarded (no vault configured)",
            retrieve_hint="the value no longer exists; set it again outside this session, or configure a vault: python3 -m omp.setup",
        )
