"""Cleanup of ~/.claude/history.jsonl after a block.

Measured on 2026-08-26: a prompt refused by the hook does not enter the session transcript,
but Claude Code still writes it, in clear, to the up-arrow history. The block protects the
model, not the disk.

The scrubber receives NO value: it re-reads recent history entries and applies the same
detector as the hook. No secret travels to the background process, neither by argv, nor by
stdin, nor in memory beyond the line being processed. Since the write order between the
hook and the history file is not guaranteed, the scrub runs once immediately, then in the
background for a few seconds.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp.detect import detect  # noqa: E402

DEFAULT_HISTORY = Path(os.environ.get("OMP_HISTORY", str(Path.home() / ".claude" / "history.jsonl"))).expanduser()
RECENT_WINDOW_MS = 120_000
BACKGROUND_RETRY_SECONDS = 15.0
BACKGROUND_INTERVAL_SECONDS = 1.0


def _clean(node: object) -> tuple[object, bool]:
    if isinstance(node, str):
        cleaned, findings = detect(node)
        return cleaned, bool(findings)
    if isinstance(node, list):
        items = [_clean(item) for item in node]
        return [item for item, _ in items], any(changed for _, changed in items)
    if isinstance(node, dict):
        pairs = {key: _clean(item) for key, item in node.items()}
        return {key: item for key, (item, _) in pairs.items()}, any(changed for _, changed in pairs.values())
    return node, False


def _is_recent(entry: object, since_ms: int) -> bool:
    if not isinstance(entry, dict):
        return True
    timestamp = entry.get("timestamp")
    return not isinstance(timestamp, int | float) or timestamp >= since_ms


def _scrub_line(line: str, since_ms: int) -> tuple[str, bool]:
    try:
        entry = json.loads(line)
    except ValueError:
        cleaned, findings = detect(line)
        return cleaned, bool(findings)
    if not _is_recent(entry, since_ms):
        return line, False
    cleaned_entry, changed = _clean(entry)
    return (json.dumps(cleaned_entry, ensure_ascii=False) if changed else line), changed


def _write_atomic(history: Path, text: str) -> None:
    mode = history.stat().st_mode & 0o777
    temporary = history.with_name(history.name + ".omp-tmp")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, "w", errors="surrogateescape") as handle:
        handle.write(text)
    temporary.replace(history)


def scrub(since_ms: int = 0, history: Path = DEFAULT_HISTORY) -> int:
    """Scrub entries newer than since_ms. Return the number of modified lines."""
    if not history.exists():
        return 0
    original = history.read_text(errors="surrogateescape")
    results = [_scrub_line(line, since_ms) for line in original.splitlines()]
    touched = sum(1 for _, changed in results if changed)
    if touched == 0:
        return 0
    _write_atomic(history, "\n".join(line for line, _ in results) + ("\n" if original.endswith("\n") else ""))
    return touched


def scrub_until_clean(since_ms: int, history: Path = DEFAULT_HISTORY) -> int:
    deadline = time.monotonic() + BACKGROUND_RETRY_SECONDS
    total = 0
    while time.monotonic() < deadline:
        total += scrub(since_ms, history)
        time.sleep(BACKGROUND_INTERVAL_SECONDS)
    return total


def spawn_background(since_ms: int, history: Path = DEFAULT_HISTORY) -> bool:
    try:
        subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), str(since_ms), str(history)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return False
    return True


def recent_window_start() -> int:
    return int(time.time() * 1000) - RECENT_WINDOW_MS


def main() -> int:
    since_ms = int(sys.argv[1]) if len(sys.argv) > 1 else recent_window_start()
    history = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_HISTORY
    scrub_until_clean(since_ms, history)
    return 0


if __name__ == "__main__":
    sys.exit(main())
