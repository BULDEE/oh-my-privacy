"""PreToolUse hook for the Grep tool: content matches are masked before the model sees them.

Grep in `files_with_matches` or `count` mode returns paths only; nothing to mask. In
`content` mode the matched lines reach the model. The hook runs the same search itself
(ripgrep, shipped inside the Claude Code binary or found on PATH), and when the matches
contain secrets it denies the call and hands the masked output back in the denial reason.
Clean searches are left to the tool untouched.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp.detect import detect  # noqa: E402

SEARCH_TIMEOUT_SECONDS = 20
MAX_OUTPUT_BYTES = 4_000_000


def ripgrep_command() -> tuple[str, list[str]] | None:
    """Return (executable, argv0 prefix) for ripgrep: the Claude Code binary answers to argv0 'rg'."""
    claude = os.environ.get("CLAUDE_CODE_EXECPATH") or shutil.which("claude")
    if claude and os.access(claude, os.X_OK):
        return claude, ["rg"]
    system = shutil.which("rg")
    if system:
        return system, ["rg"]
    return None


def build_args(tool_input: dict[str, object]) -> list[str]:
    args: list[str] = ["--no-heading", "--with-filename", "--color", "never", "--hidden", "--glob", "!.git"]
    if tool_input.get("-i"):
        args.append("-i")
    if tool_input.get("-n", True):
        args.append("-n")
    for flag in ("-A", "-B", "-C"):
        value = tool_input.get(flag)
        if isinstance(value, int):
            args += [flag, str(value)]
    if tool_input.get("multiline"):
        args += ["-U", "--multiline-dotall"]
    glob = tool_input.get("glob")
    if isinstance(glob, str) and glob:
        args += ["--glob", glob]
    file_type = tool_input.get("type")
    if isinstance(file_type, str) and file_type:
        args += ["--type", file_type]
    args += ["-e", str(tool_input.get("pattern", "")), str(tool_input.get("path") or os.getcwd())]
    return args


def run_search(tool_input: dict[str, object]) -> str | None:
    located = ripgrep_command()
    if located is None:
        return None
    executable, argv0 = located
    try:
        completed = subprocess.run(
            argv0 + build_args(tool_input), executable=executable, capture_output=True, text=True,
            timeout=SEARCH_TIMEOUT_SECONDS, check=False, env={**os.environ, "ARGV0": "rg"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode not in (0, 1):
        return None
    return completed.stdout[:MAX_OUTPUT_BYTES]


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (OSError, ValueError):
        return 0
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    if not isinstance(tool_input, dict) or tool_input.get("output_mode", "files_with_matches") != "content":
        return 0
    output = run_search(tool_input)
    if not output:
        return 0
    cleaned, findings = detect(output)
    if not findings:
        return 0
    head_limit = tool_input.get("head_limit")
    if isinstance(head_limit, int) and head_limit > 0:
        cleaned = "\n".join(cleaned.splitlines()[:head_limit])
    print(json.dumps(deny_with(cleaned, len(findings))))
    return 0


def deny_with(cleaned: str, count: int) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"OhMyPrivacy ran this search itself: {count} secret(s) in the matches were masked. "
                f"Use the masked results below; do not retry the search to see the values.\n\n{cleaned}"
            ),
        },
    }


if __name__ == "__main__":
    sys.exit(main())
