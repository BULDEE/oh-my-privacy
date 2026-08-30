"""Deterministic audit of the OhMyPrivacy installation on this machine.

The question it answers, with evidence: "which version of OhMyPrivacy actually protects a
session, and is there only one?" The 2026-08-30 review found an ambiguous state (marketplace
plugin disabled, managed install retired, several source trees, yet scrubs still running).
Reconciling means a single active source, identified and versioned.

Exit 0 when the installation is unambiguous (exactly one active source, up to date). Exit 1
otherwise, with a report of the sources found. This is the verify command for the
reconciliation (Option A): red while the state is ambiguous, green once one source remains.
"""

from __future__ import annotations

import json
from pathlib import Path

CLAUDE = Path.home() / ".claude"
MANAGED_ROOT = Path("/Library/Application Support/ClaudeCode")
MANAGED_INSTALL = Path("/usr/local/lib/oh-my-privacy")
TRUTH_TREE = Path.home() / "Dev" / "claude" / "oh-my-privacy"
KNOWN_TREES = [
    TRUTH_TREE,
    Path.home() / "Dev" / "oh-my-privacy",
]
FRESHNESS_MARKERS = ("omp/telemetry.py", "hooks/split_segments.py")
FRESHNESS_FILES = ("omp/hook.py", "hooks/guard.sh", "omp/detect.py")


def managed_install_gaps() -> list[str]:
    """Gaps of the active managed install (/usr/local/lib) against the source of truth (dev repo).

    An active but stale source is the worst state: it looks like it protects while deploying
    code without the latest fixes. The verify must judge freshness, not mere presence.
    """
    import filecmp

    if not (MANAGED_INSTALL / "omp").is_dir():
        return []
    gaps = []
    for marker in FRESHNESS_MARKERS:
        if (TRUTH_TREE / marker).is_file() and not (MANAGED_INSTALL / marker).is_file():
            gaps.append(f"{marker} missing (predates the recent fixes)")
    for relative in FRESHNESS_FILES:
        here, truth = MANAGED_INSTALL / relative, TRUTH_TREE / relative
        if here.is_file() and truth.is_file() and not filecmp.cmp(here, truth, shallow=False):
            gaps.append(f"{relative} differs from the source of truth")
    return gaps


def _hooks_reference_omp(settings: dict[str, object]) -> list[str]:
    wired = []
    for event, groups in (settings.get("hooks", {}) if isinstance(settings, dict) else {}).items():
        for group in groups or []:
            for hook in group.get("hooks", []):
                command = str(hook.get("command", ""))
                if ("/omp/" in command or "guard.sh" in command) and ".retired" not in command:
                    wired.append(f"{event}: {command}")
    return wired


def _version(tree: Path) -> str | None:
    manifest = tree / ".claude-plugin" / "plugin.json"
    if not manifest.is_file():
        return None
    try:
        return str(json.loads(manifest.read_text()).get("version", "?"))
    except (OSError, ValueError):
        return "unreadable"


def _read_json(path: Path) -> dict[str, object]:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def source_trees() -> list[tuple[Path, str, bool]]:
    """(path, version, has telemetry) for each source tree present on disk."""
    found = []
    for tree in KNOWN_TREES:
        version = _version(tree)
        if version is not None:
            found.append((tree, version, (tree / "omp" / "telemetry.py").is_file()))
    return found


def marketplace_enabled() -> dict[str, bool]:
    settings = _read_json(CLAUDE / "settings.json")
    enabled = settings.get("enabledPlugins", {}) if isinstance(settings, dict) else {}
    return {k: bool(v) for k, v in enabled.items() if "oh-my-privacy" in k.lower()}


def user_hooks() -> list[str]:
    """OMP hooks wired in ~/.claude/settings.json (user-settings install)."""
    return _hooks_reference_omp(_read_json(CLAUDE / "settings.json"))


def managed_hooks() -> list[str]:
    """OMP hooks wired in the root managed drop-ins (install the agent cannot remove)."""
    wired = []
    for dropin in sorted(MANAGED_ROOT.glob("managed-settings.d/*.json")) + [MANAGED_ROOT / "managed-settings.json"]:
        if dropin.is_file():
            wired.extend(f"managed:{ref}" for ref in _hooks_reference_omp(_read_json(dropin)))
    return wired


def _report(trees: list[tuple[Path, str, bool]], enabled: dict[str, bool], user: list[str], managed: list[str]) -> None:
    print("== Source trees present ==")
    for tree, version, has_telemetry in trees:
        print(f"  {tree}  v{version}  telemetry={'yes' if has_telemetry else 'no'}")
    print("== Marketplace plugin ==")
    for name, is_on in enabled.items():
        print(f"  {name} = {'enabled' if is_on else 'DISABLED'}")
    print("== OMP hooks wired ==")
    print("  user (~/.claude/settings.json): " + ("\n    ".join(user) if user else "none"))
    print("  managed (root drop-ins): " + ("\n    ".join(managed) if managed else "none"))


def _ambiguity_reasons(active_sources: int, trees: list[tuple[Path, str, bool]]) -> list[str]:
    reasons = []
    if active_sources == 0:
        reasons.append("no source declared active: a fresh session is unprotected")
    if active_sources > 1:
        reasons.append(f"{active_sources} active sources competing (double execution)")
    if len(trees) > 1:
        listed = ", ".join(f"{tree} v{version}" for tree, version, _ in trees)
        reasons.append(f"{len(trees)} source trees on disk ({listed})")
    return reasons


def main() -> int:
    trees = source_trees()
    enabled = marketplace_enabled()
    user, managed = user_hooks(), managed_hooks()
    _report(trees, enabled, user, managed)
    gaps = managed_install_gaps()
    print("== Freshness of the active managed install ==")
    print("  " + ("up to date vs source of truth" if not gaps else "STALE: " + " ; ".join(gaps)))

    active_sources = sum(1 for is_on in enabled.values() if is_on) + (1 if user else 0) + (1 if managed else 0)
    reasons = _ambiguity_reasons(active_sources, trees)
    if gaps:
        reasons.append("the active install is stale (deploys code without the latest fixes)")
    print("== Verdict ==")
    if active_sources == 1 and not gaps and len(trees) <= 1:
        print("  OK: a single active source, up to date, no ambiguity.")
        return 0
    print("  RECONCILE: " + " ; ".join(reasons))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
