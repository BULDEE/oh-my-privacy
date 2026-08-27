"""Output masking for tool results.

`mask(text)` replaces every detected secret with its placeholder. As a CLI it reads one or
two files (stdout capture, stderr capture) produced by the Bash wrapper and prints their
masked content on the matching descriptors, so the model sees `$OMP_KIND_HASH` instead of
the value. Placeholders derive from the value's hash, so the same secret keeps the same
name across a prompt, a file read and a command output.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import telemetry  # noqa: E402
from omp.detect import detect  # noqa: E402

MAX_BYTES = 8_000_000


def mask(text: str) -> tuple[str, list[str]]:
    cleaned, findings = detect(text)
    return cleaned, [finding.kind for finding in findings]


def mask_file(path: Path) -> tuple[str, list[str]]:
    try:
        raw = path.read_bytes()
    except OSError:
        return "", []
    if len(raw) > MAX_BYTES:
        return f"[OhMyPrivacy: output of {len(raw)} bytes exceeds the {MAX_BYTES} byte masking limit and was withheld]\n", []
    return mask(raw.decode("utf-8", errors="replace"))


def main() -> int:
    if len(sys.argv) == 1:
        text = sys.stdin.read()
        started = time.perf_counter()
        cleaned, kinds = mask(text)
        latency_ms = (time.perf_counter() - started) * 1000
        sys.stdout.write(cleaned)
        if kinds:
            telemetry.record("claude_code", "Bash", kinds, "mask", latency_ms)
        return 0
    started = time.perf_counter()
    out_text, out_kinds = mask_file(Path(sys.argv[1]))
    err_text: str = ""
    err_kinds: list[str] = []
    if len(sys.argv) > 2:
        err_text, err_kinds = mask_file(Path(sys.argv[2]))
    latency_ms = (time.perf_counter() - started) * 1000
    sys.stdout.write(out_text)
    if len(sys.argv) > 2:
        sys.stderr.write(err_text)
    kinds = out_kinds + err_kinds
    if kinds:
        sys.stderr.write(f"[OhMyPrivacy: {len(kinds)} secret(s) masked in this output; refer to them by their $OMP_* name]\n")
        telemetry.record("claude_code", "Bash", kinds, "mask", latency_ms)
    return 0


if __name__ == "__main__":
    sys.exit(main())
