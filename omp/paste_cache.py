"""Claude Code paste cache: long pastes are staged on disk before they reach the prompt.

`~/.claude/paste-cache/*.txt` holds the content behind `[Pasted text #N +M lines]`
placeholders, 0600, and it persists after the session. Two duties here: tell the prompt
hook whether a recent paste contains a secret (so a collapsed placeholder cannot smuggle
one past the block), and scrub recent cache files after a block or a leak.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp.detect import Finding, detect  # noqa: E402

CACHE_DIR = Path(os.environ.get("OMP_PASTE_CACHE", str(Path.home() / ".claude" / "paste-cache"))).expanduser()
RECENT_SECONDS = 600
MAX_BYTES = 8_000_000


def recent_files(since_seconds: float | None = None) -> list[Path]:
    if not CACHE_DIR.is_dir():
        return []
    threshold = since_seconds if since_seconds is not None else time.time() - RECENT_SECONDS
    return [path for path in CACHE_DIR.iterdir() if path.is_file() and path.stat().st_mtime >= threshold]


def _read(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    if len(raw) > MAX_BYTES:
        return ""
    return raw.decode("utf-8", errors="surrogateescape")


def recent_contents(since_seconds: float | None = None) -> list[str]:
    return [text for text in (_read(path) for path in sorted(recent_files(since_seconds))) if text]


def findings_in_recent_pastes() -> list[Finding]:
    found: dict[str, Finding] = {}
    for path in recent_files():
        _, findings = detect(_read(path))
        for finding in findings:
            found.setdefault(finding.name, finding)
    return list(found.values())


def scrub_recent(since_seconds: float | None = None) -> int:
    """Rewrite recent cache files with placeholders. Return the number of files changed."""
    changed = 0
    for path in recent_files(since_seconds):
        text = _read(path)
        cleaned, findings = detect(text)
        if not findings:
            continue
        mode = path.stat().st_mode & 0o777
        temporary = path.with_name(path.name + ".omp-tmp")
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(descriptor, "w", errors="surrogateescape") as handle:
            handle.write(cleaned)
        temporary.replace(path)
        changed += 1
    return changed
