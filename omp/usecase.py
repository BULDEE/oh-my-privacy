"""Use case: intercept the secrets in a text, store them, return the cleaned text.

Host-agnostic. Claude Code (hook), Hermes (plugin) and the CLI call it with the same
contract: a text and an adapter go in, an Interception comes out, the value never comes
back. Presentation belongs to the host.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from omp.adapters import StoreError, StoreResult, VaultAdapter
from omp.detect import Finding, detect


@dataclass(frozen=True)
class Outcome:
    name: str
    kind: str
    stored: bool
    reference: str
    hint: str


@dataclass(frozen=True)
class Interception:
    cleaned: str
    vault: str
    outcomes: tuple[Outcome, ...] = field(default_factory=tuple)

    @property
    def names(self) -> list[str]:
        return ["$" + outcome.name for outcome in self.outcomes]


def _store(adapter: VaultAdapter, finding: Finding) -> Outcome:
    try:
        result: StoreResult = adapter.store(finding.name, finding.value)
    except StoreError as error:
        return Outcome(name=finding.name, kind=finding.kind, stored=False, reference=str(error), hint="")
    return Outcome(name=finding.name, kind=finding.kind, stored=True, reference=result.reference, hint=result.retrieve_hint)


def intercept(text: str, adapter: VaultAdapter) -> Interception | None:
    """Return None when the text is clean. Otherwise the values are already stored and forgotten."""
    cleaned, findings = detect(text)
    if not findings:
        return None
    outcomes = tuple(_store(adapter, finding) for finding in findings)
    del findings
    return Interception(cleaned=cleaned, vault=adapter.name, outcomes=outcomes)
