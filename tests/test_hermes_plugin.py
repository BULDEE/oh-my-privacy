from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hermes as plugin  # noqa: E402

FAKE = "sk-ant-api03-FAKEKEYFORTESTINGONLY0000000000"


class FakeContext:
    def __init__(self, settings: dict[str, str] | None = None) -> None:
        self.settings = settings or {}
        self.hooks: dict[str, Any] = {}

    def get_config(self, key: str, default: str = "") -> str:
        return self.settings.get(key, default)

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks[name] = callback


class HermesPlugin(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = FakeContext({"vault": "discard"})
        plugin.register(self.ctx)

    def test_registers_the_two_hooks_declared_in_manifest(self) -> None:
        self.assertEqual(set(self.ctx.hooks), {"pre_tool_call", "pre_llm_call"})

    def test_tool_call_with_secret_is_blocked_and_value_absent_from_message(self) -> None:
        directive = self.ctx.hooks["pre_tool_call"](tool_name="terminal", args={"command": f"curl -H 'Authorization: Bearer {FAKE}' https://x"}, task_id="t1")
        assert directive is not None
        self.assertEqual(directive["action"], "block")
        self.assertNotIn(FAKE, directive["message"])
        self.assertIn("$OMP_ANTHROPIC_", directive["message"])

    def test_clean_tool_call_passes(self) -> None:
        self.assertIsNone(self.ctx.hooks["pre_tool_call"](tool_name="terminal", args={"command": "ls -la"}, task_id="t1"))

    def test_file_write_with_secret_is_blocked(self) -> None:
        directive = self.ctx.hooks["pre_tool_call"](tool_name="write_file", args={"path": ".env", "content": f"ANTHROPIC_API_KEY={FAKE}"}, task_id="t1")
        assert directive is not None
        self.assertEqual(directive["action"], "block")

    def test_user_message_with_secret_injects_strict_context(self) -> None:
        injected = self.ctx.hooks["pre_llm_call"](
            session_id="s", user_message=f"here is my key {FAKE}", conversation_history=[], is_first_turn=True, model="m", platform="telegram",
        )
        assert injected is not None
        self.assertNotIn(FAKE, injected["context"])
        self.assertIn("Never repeat", injected["context"])
        self.assertIn("$OMP_ANTHROPIC_", injected["context"])

    def test_clean_user_message_injects_nothing(self) -> None:
        self.assertIsNone(self.ctx.hooks["pre_llm_call"](
            session_id="s", user_message="hello", conversation_history=[], is_first_turn=True, model="m", platform="cli",
        ))

    def test_scan_tools_restricts_scope(self) -> None:
        ctx = FakeContext({"vault": "discard", "scan_tools": "terminal, send_message"})
        plugin.register(ctx)
        self.assertIsNone(ctx.hooks["pre_tool_call"](tool_name="read_file", args={"path": FAKE}, task_id="t"))
        self.assertIsNotNone(ctx.hooks["pre_tool_call"](tool_name="send_message", args={"text": FAKE}, task_id="t"))

    def test_callbacks_accept_unknown_kwargs(self) -> None:
        self.assertIsNone(self.ctx.hooks["pre_tool_call"](tool_name="x", args={}, task_id="t", future_field=1))
        self.assertIsNone(self.ctx.hooks["pre_llm_call"](session_id="s", user_message="ok", future_field=1))


if __name__ == "__main__":
    unittest.main()
