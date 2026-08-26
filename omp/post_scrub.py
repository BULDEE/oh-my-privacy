"""PostToolUse hook: no secret survives on disk after a tool call.

Two kinds of tool output escape source masking: results of tools whose input cannot be
rewritten (MCP servers, WebFetch), and snapshots Claude Code takes of files touched by
Edit/Write under `~/.claude/file-history/`. This hook re-detects secrets in the tool
response; when it finds some, it scrubs the tail of the session transcript, the session's
file-history snapshots and the paste cache, and tells the model the values are burnt.

Scrubbing is re-detection (ADR-0004): no value is handed to anything.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Iterable, Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import history, paste_cache  # noqa: E402
from omp.detect import detect  # noqa: E402
from omp.pre_read import MASKED_ROOT  # noqa: E402

FILE_HISTORY_ROOT = Path(os.environ.get("OMP_FILE_HISTORY", str(Path.home() / ".claude" / "file-history"))).expanduser()
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
TRANSCRIPT_WINDOW_MS = 10 * 60 * 1000
SNAPSHOT_MAX_BYTES = 8_000_000


def scrub_plain_file(path: Path) -> int:
    try:
        raw = path.read_bytes()
    except OSError:
        return 0
    if len(raw) > SNAPSHOT_MAX_BYTES or b"\x00" in raw[:4096]:
        return 0
    cleaned, findings = detect(raw.decode("utf-8", errors="surrogateescape"))
    if not findings:
        return 0
    mode = path.stat().st_mode & 0o777
    temporary = path.with_name(path.name + ".omp-tmp")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, "w", errors="surrogateescape") as handle:
        handle.write(cleaned)
    temporary.replace(path)
    return len(findings)


def scrub_file_history(session_id: str, since_seconds: float) -> int:
    """Opt-in: snapshots feed /rewind, and a masked snapshot restored over a real file would erase its secrets.

    A snapshot mirrors a file that already sits in clear on the same disk, so scrubbing it adds
    little protection and a real data-loss risk. Enable with OMP_SCRUB_FILE_HISTORY=1.
    """
    if os.environ.get("OMP_SCRUB_FILE_HISTORY", "0") != "1":
        return 0
    directory = FILE_HISTORY_ROOT / session_id
    if not session_id or not directory.is_dir():
        return 0
    total = 0
    for snapshot in directory.iterdir():
        if snapshot.is_file() and snapshot.stat().st_mtime >= since_seconds:
            total += 1 if scrub_plain_file(snapshot) else 0
    return total


def _is_own_masked_copy_path(text: str) -> bool:
    """True when `text` is exactly the path of a masked copy pre_read.py wrote.

    That path is our own construction: MASKED_ROOT / a sha256-derived hex digest /
    the original filename. Scanned as plain text it mixes lowercase, uppercase (from a
    filename such as README.md) and hex digits, which is enough to pass the entropy
    heuristic (detect.py's `looks_like_token`), so the tool metadata that merely names
    where the masked copy lives gets misread as the secret it exists to prevent.
    """
    try:
        return Path(text).resolve().is_relative_to(MASKED_ROOT.resolve())
    except (OSError, ValueError):
        return False


def _iter_strings(value: object) -> Iterator[str]:
    """Yield every string leaf of a tool payload, each with its own real newlines intact.

    Scanning leaf by leaf, instead of one `json.dumps`-serialized blob, keeps each leaf's
    own newlines real (JSON would escape them to the two characters backslash and `n`,
    which could fuse the tail of one line with the head of the next into a run that never
    existed in the actual output).
    """
    if isinstance(value, str):
        if not _is_own_masked_copy_path(value):
            yield value
        return
    if isinstance(value, dict):
        yield from _iter_string_items(value.values())
        return
    if isinstance(value, list | tuple):
        yield from _iter_string_items(value)


def _iter_string_items(values: Iterable[object]) -> Iterator[str]:
    for item in values:
        yield from _iter_strings(item)


def response_has_secrets(tool_response: object) -> int:
    return sum(len(detect(text)[1]) for text in _iter_strings(tool_response))


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (OSError, ValueError):
        return 0
    if not isinstance(payload, dict):
        return 0
    tool_name = str(payload.get("tool_name", ""))
    leaked = response_has_secrets(payload.get("tool_response"))
    typed = response_has_secrets(payload.get("tool_input"))
    if not leaked and not typed and tool_name not in EDIT_TOOLS:
        return 0
    scrubbed = scrub_traces(payload, leaked + typed)
    if leaked:
        print(json.dumps(warning(tool_name, leaked, scrubbed)))
    return 0


def scrub_traces(payload: dict[str, object], leaked: int) -> int:
    now = time.time()
    scrubbed = scrub_file_history(str(payload.get("session_id", "")), now - 600)
    scrubbed += paste_cache.scrub_recent(now - 600)
    transcript = payload.get("transcript_path")
    if leaked and isinstance(transcript, str):
        scrubbed += history.scrub(int(now * 1000) - TRANSCRIPT_WINDOW_MS, Path(transcript))
    return scrubbed


def warning(tool_name: str, leaked: int, scrubbed: int) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"OhMyPrivacy: the output of `{tool_name}` contained {leaked} secret(s) that could not be masked at the source. "
                f"Local traces were scrubbed ({scrubbed} file(s)). Never repeat these values; tell the user to revoke them."
            ),
        },
    }


if __name__ == "__main__":
    sys.exit(main())
