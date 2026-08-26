"""PreToolUse hook for the Bash tool: every command's output is masked before the model sees it.

Claude Code has no hook that rewrites a tool result, but a PreToolUse hook can rewrite the
tool input. The command is wrapped so that stdout and stderr are captured to private temp
files, passed through the detector, then printed. The wrapper runs in the same shell
(braces, not a subshell), so `cd` still persists across calls; the exit status is
preserved.

Other PreToolUse hooks that rewrite the command (a token-saving proxy, for instance) would
be lost, since Claude Code keeps the last `updatedInput` only. `OMP_CHAIN_HOOK` names such a
hook command; it is run first on the same payload and its rewrite is the one wrapped.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

MASK = Path(__file__).resolve().parent / "mask.py"
CHAIN_TIMEOUT_SECONDS = 10


def chained_rewrite(payload: dict[str, object], raw_payload: str) -> tuple[str | None, dict[str, object] | None]:
    """Return (command from the chained hook, passthrough decision) when OMP_CHAIN_HOOK is set."""
    chain = os.environ.get("OMP_CHAIN_HOOK", "").strip()
    if not chain:
        return None, None
    try:
        completed = subprocess.run(shlex.split(chain), input=raw_payload, capture_output=True, text=True, timeout=CHAIN_TIMEOUT_SECONDS, check=False)
        result = json.loads(completed.stdout) if completed.stdout.strip() else {}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None, None
    specific = result.get("hookSpecificOutput", {}) if isinstance(result, dict) else {}
    if not isinstance(specific, dict):
        return None, None
    if specific.get("permissionDecision") in ("deny", "ask"):
        return None, result
    updated = specific.get("updatedInput")
    if isinstance(updated, dict) and isinstance(updated.get("command"), str):
        return str(updated["command"]), None
    return None, None


def wrap(command: str) -> str:
    python = shlex.quote(sys.executable)
    mask = shlex.quote(str(MASK))
    # An `exit` inside the command must not skip the masking step: the EXIT trap prints the
    # captured output before the shell goes away, and the exit status survives.
    return (
        '__omp_o=$(mktemp) && __omp_e=$(mktemp) && '
        f'__omp_finish() {{ {python} {mask} "$__omp_o" "$__omp_e"; rm -f "$__omp_o" "$__omp_e"; }}; '
        "trap __omp_finish EXIT; "
        "{\n" + command + "\n} > \"$__omp_o\" 2> \"$__omp_e\"; __omp_rc=$?; "
        "trap - EXIT; __omp_finish; unset -f __omp_finish; unset __omp_o __omp_e; ( exit \"$__omp_rc\" )"
    )


def main() -> int:
    raw_payload = sys.stdin.read()
    try:
        payload = json.loads(raw_payload)
    except ValueError:
        return 0
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        return 0
    command, passthrough = chained_rewrite(payload, raw_payload)
    if passthrough is not None:
        print(json.dumps(passthrough))
        return 0
    if command is None:
        command = str(tool_input["command"])
    if "__omp_o=" in command:
        return 0
    updated = dict(tool_input)
    updated["command"] = wrap(command)
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": updated}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
