"""Output masking for tool results.

`mask(text)` replaces every detected secret with its placeholder. As a CLI it reads one or
two files (stdout capture, stderr capture) produced by the Bash wrapper and prints their
masked content on the matching descriptors, so the model sees `$OMP_KIND_HASH` instead of
the value. Placeholders derive from the value's hash, so the same secret keeps the same
name across a prompt, a file read and a command output.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp.detect import detect  # noqa: E402

MAX_BYTES = 8_000_000


def mask(text: str) -> tuple[str, int]:
    cleaned, findings = detect(text)
    return cleaned, len(findings)


def mask_file(path: Path) -> tuple[str, int]:
    try:
        raw = path.read_bytes()
    except OSError:
        return "", 0
    if len(raw) > MAX_BYTES:
        return f"[OhMyPrivacy: output of {len(raw)} bytes exceeds the {MAX_BYTES} byte masking limit and was withheld]\n", 0
    return mask(raw.decode("utf-8", errors="replace"))


def main() -> int:
    if len(sys.argv) == 1:
        cleaned, _ = mask(sys.stdin.read())
        sys.stdout.write(cleaned)
        return 0
    out_text, out_count = mask_file(Path(sys.argv[1]))
    sys.stdout.write(out_text)
    err_count = 0
    if len(sys.argv) > 2:
        err_text, err_count = mask_file(Path(sys.argv[2]))
        sys.stderr.write(err_text)
    total = out_count + err_count
    if total:
        sys.stderr.write(f"[OhMyPrivacy: {total} secret(s) masked in this output; refer to them by their $OMP_* name]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
