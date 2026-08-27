"""PreToolUse hook for the Read tool: the model reads a masked copy, never the original.

Claude Code lets a PreToolUse hook replace the tool input (`updatedInput`, PreToolUse only).
When the requested file contains secrets, a masked copy is written under
`~/.claude/omp/masked/` (0600) and the Read call is redirected to it. The model still gets
the file, with `$OMP_*` placeholders where the values were. Files that are binary or
larger than the limit are left alone: they cannot be masked line by line.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import telemetry  # noqa: E402
from omp.detect import detect  # noqa: E402

MASKED_ROOT = Path(os.environ.get("OMP_MASKED_DIR", str(Path.home() / ".claude" / "omp" / "masked"))).expanduser()
MAX_BYTES = 8_000_000


def masked_copy_path(original: Path) -> Path:
    digest = hashlib.sha256(str(original).encode()).hexdigest()[:16]
    return MASKED_ROOT / digest / original.name


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)


def mask_file(original: Path) -> tuple[Path | None, list[str]]:
    """Return the masked copy path and the kinds found, or (None, []) when nothing to mask."""
    try:
        raw = original.read_bytes()
    except OSError:
        return None, []
    if len(raw) > MAX_BYTES or b"\x00" in raw[:4096]:
        return None, []
    cleaned, findings = detect(raw.decode("utf-8", errors="replace"))
    if not findings:
        return None, []
    target = masked_copy_path(original)
    write_private(target, cleaned)
    return target, [finding.kind for finding in findings]


def requested_file(payload: object) -> tuple[dict[str, object], Path] | None:
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    if not isinstance(tool_input, dict):
        return None
    file_path = tool_input.get("file_path")
    if not isinstance(file_path, str) or not file_path:
        return None
    original = Path(file_path).expanduser()
    return (tool_input, original) if original.is_file() else None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (OSError, ValueError):
        return 0
    request = requested_file(payload)
    if request is None:
        return 0
    tool_input, original = request
    started = time.perf_counter()
    target, kinds = mask_file(original)
    latency_ms = (time.perf_counter() - started) * 1000
    if target is None:
        return 0
    telemetry.record("claude_code", "Read", kinds, "mask", latency_ms)
    updated = dict(tool_input)
    updated["file_path"] = str(target)
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated,
            "additionalContext": (
                f"OhMyPrivacy masked {len(kinds)} secret(s) in {original}. You are reading a masked copy; "
                f"$OMP_* placeholders stand for the values. Never reconstruct them. An Edit whose old_string "
                f"spans a masked line will not match the real file."
            ),
        },
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
