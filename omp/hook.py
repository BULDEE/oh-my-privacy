"""Claude Code UserPromptSubmit hook entry point. I/O only.

Claude Code offers no field to rewrite the prompt on this event (schema verified in binary
2.1.246: `additionalContext`, `sessionTitle`, `suppressOriginalPrompt`, nothing else;
`updatedInput` belongs to PreToolUse). Masking and passing through is impossible. The only
path that keeps the secret away from the model is to refuse the message, then hand the user
back a cleaned version of it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import config as config_module  # noqa: E402
from omp import history, paste_cache  # noqa: E402
from omp.adapters import build  # noqa: E402
from omp.usecase import Interception, intercept  # noqa: E402

CLIPBOARD_TIMEOUT_SECONDS = 3
PASTE_PLACEHOLDER = "[Pasted text #"


def read_prompt() -> str:
    try:
        payload = json.load(sys.stdin)
    except (OSError, ValueError):
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("prompt") or payload.get("user_prompt") or "")


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)
    temporary.replace(path)


def copy_to_clipboard(text: str) -> bool:
    """Overwrite the clipboard, which most likely still holds the secret the user just pasted."""
    try:
        completed = subprocess.run(["pbcopy"], input=text.encode(), timeout=CLIPBOARD_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def hand_back(config: config_module.Config, cleaned: str, vault: str) -> list[str]:
    """With no vault the clipboard may hold the user's only copy of the value: leave it alone."""
    channels: list[str] = []
    clipboard_allowed = config.clipboard and vault != "discard" and os.environ.get("OMP_CLIPBOARD", "1") != "0"
    if clipboard_allowed and copy_to_clipboard(cleaned):
        channels.append("the clipboard")
    if config.prompt_file is not None:
        write_private(config.prompt_file, cleaned)
        channels.append(str(config.prompt_file))
    return channels


def describe(interception: Interception) -> str:
    lines: list[str] = []
    for outcome in interception.outcomes:
        status = outcome.reference if outcome.stored else f"storage refused, value discarded. {outcome.reference}"
        lines.append(f"  ${outcome.name} ({outcome.kind}): {status}. {outcome.hint}")
    return "\n".join(lines)


def block_response(interception: Interception, channels: list[str]) -> dict[str, object]:
    count = len(interception.outcomes)
    where = " and ".join(channels) if channels else "below only"
    reason = (
        f"OhMyPrivacy intercepted {count} secret(s). The message is BLOCKED: it never reached the model.\n"
        f"Vault: {interception.vault}.\n{describe(interception)}\n\n"
        f"Your cleaned message is available via {where}. Paste it as is to continue:\n\n"
        f"--- cleaned message ---\n{interception.cleaned}"
    )
    return {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
        "systemMessage": f"OhMyPrivacy: {count} secret(s) intercepted, message blocked ({', '.join(interception.names)}).",
    }


def expand_pastes(prompt: str) -> str:
    """A collapsed `[Pasted text #N]` placeholder hides its content from the prompt text; the cache does not."""
    if PASTE_PLACEHOLDER not in prompt:
        return prompt
    contents = paste_cache.recent_contents()
    if not contents:
        return prompt
    return prompt + "\n\n--- pasted attachments ---\n" + "\n".join(contents)


def main() -> int:
    prompt = read_prompt()
    if not prompt:
        return 0
    config = config_module.load()
    interception = intercept(expand_pastes(prompt), build(config))
    del prompt
    if interception is None:
        return 0
    since_ms = history.recent_window_start()
    history.scrub(since_ms)
    history.spawn_background(since_ms)
    paste_cache.scrub_recent()
    print(json.dumps(block_response(interception, hand_back(config, interception.cleaned, interception.vault))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
