"""Native Hermes plugin: same levels, same detectors, different host.

Anchor points offered by Hermes (Event Hooks reference, verified on 2026-08-26):

- `pre_tool_call` may return `{"action": "block", "message": ...}`. It is the only hook
  with veto power. It is used to refuse any command, code, file write or outbound message
  that would contain a secret in clear. The value goes to the vault; the agent receives the
  name and the way forward.
- `pre_llm_call` can only inject context: Hermes allows neither blocking nor rewriting the
  user message. When a user pastes a secret from Telegram or Discord, the value reaches the
  model for that turn. It is stored in the vault and a strict instruction is injected: never
  repeat it, reference it by name. This is a host limit, documented as such, not an
  OhMyPrivacy workaround.

Hermes already redacts its logs and tool outputs (agent/redact.py) and strips environment
variables from subprocesses. OhMyPrivacy complements that: it acts BEFORE execution, on
what the agent is about to do.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

_PLUGIN_DIR = Path(__file__).resolve().parent
for candidate in (_PLUGIN_DIR, _PLUGIN_DIR.parent):
    if (candidate / "omp" / "detect.py").is_file() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from omp import telemetry  # noqa: E402
from omp.adapters import VaultAdapter, build  # noqa: E402
from omp.config import Config  # noqa: E402
from omp.usecase import Interception, intercept  # noqa: E402

_adapter: VaultAdapter | None = None
_scan_tools: frozenset[str] = frozenset()


def _config_from(ctx: Any) -> Config:
    vault = str(ctx.get_config("vault", default="discard"))
    options: dict[str, str] = {}
    if vault == "doppler":
        options = {"project": str(ctx.get_config("doppler_project", default="")), "config": str(ctx.get_config("doppler_config", default=""))}
    if vault == "age":
        options = {"recipient": str(ctx.get_config("age_recipient", default="")), "store_dir": str(ctx.get_config("age_store_dir", default=""))}
    return Config(vault=vault, options=options, clipboard=False, prompt_file=None)


def _flatten(args: Any) -> str:
    if isinstance(args, str):
        return args
    try:
        return json.dumps(args, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(args)


def _describe(interception: Interception) -> str:
    lines = [f"  ${outcome.name} ({outcome.kind}): {outcome.reference}. {outcome.hint}" for outcome in interception.outcomes]
    return "\n".join(lines)


def on_pre_tool_call(tool_name: str, args: dict[str, Any], task_id: str, **kwargs: Any) -> dict[str, str] | None:
    """Refuse a tool call whose arguments contain a secret in clear."""
    if _adapter is None or (_scan_tools and tool_name not in _scan_tools):
        return None
    started = time.perf_counter()
    interception = intercept(_flatten(args), _adapter)
    latency_ms = (time.perf_counter() - started) * 1000
    if interception is None:
        return None
    kinds = [outcome.kind for outcome in interception.outcomes]
    event_id = telemetry.record("hermes", tool_name, kinds, "block", latency_ms)
    message = (
        f"OhMyPrivacy: call to `{tool_name}` refused, {len(interception.outcomes)} secret(s) in clear in the arguments. "
        f"Vault: {interception.vault}.\n{_describe(interception)}\n"
        "Never copy a secret value into a command, a file or a message. "
        "Reference it by name, or ask the user to consume it themselves."
    )
    if event_id:
        message += f"\n\nFalse positive? python3 -m omp.telemetry --false-positive {event_id}"
    return {"action": "block", "message": message}


def on_pre_llm_call(session_id: str, user_message: str, **kwargs: Any) -> dict[str, str] | None:
    """Store a secret pasted by the user and forbid the model from repeating it."""
    if _adapter is None or not user_message:
        return None
    started = time.perf_counter()
    interception = intercept(user_message, _adapter)
    latency_ms = (time.perf_counter() - started) * 1000
    if interception is None:
        return None
    kinds = [outcome.kind for outcome in interception.outcomes]
    telemetry.record("hermes", "prompt", kinds, "context", latency_ms)
    return {
        "context": (
            f"[OhMyPrivacy] The user's message contained {len(interception.outcomes)} secret(s), "
            f"stored in the {interception.vault} vault:\n{_describe(interception)}\n"
            "Never repeat, quote, summarize or transform these values, in whole or in part, "
            "in a reply, a tool call, a file or an outbound message. Refer to them only by their $OMP_* name. "
            "Cleaned version of the message:\n" + interception.cleaned
        )
    }


def register(ctx: Any) -> None:
    global _adapter, _scan_tools
    _adapter = build(_config_from(ctx))
    raw_tools = str(ctx.get_config("scan_tools", default=""))
    _scan_tools = frozenset(name.strip() for name in raw_tools.split(",") if name.strip())
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
