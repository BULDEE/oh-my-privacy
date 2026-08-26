#!/usr/bin/env bash
# Managed installation: makes OhMyPrivacy irremovable by a process running under the user's
# UID, that is, by the agent.
#
# Two facts verified in Claude Code 2.1.246:
#   1. Hooks defined in managed settings survive a `disableAllHooks: true` set in user files
#      (hook resolution function in the binary).
#   2. `/Library/Application Support/ClaudeCode/managed-settings.d/` is writable by root only.
#      `sudo` without a terminal fails: the agent's Bash tool can neither edit nor delete what
#      is placed here.
#
# The code is copied to a root:wheel 0755 directory, readable by everyone, writable by nobody
# but root. The interpreter is pinned to an absolute path resolved now, so a `python3` planted
# earlier on a future PATH cannot stand in for it. The configuration (~/.claude/omp.json)
# stays with the user: it only decides the vault, never the block.
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="/usr/local/lib/oh-my-privacy"
MANAGED_DIR="/Library/Application Support/ClaudeCode/managed-settings.d"
DROPIN="$MANAGED_DIR/50-oh-my-privacy.json"
PYTHON="$(command -v python3)"
BASH_BIN="$(command -v bash)"

if [[ "$(uname)" != "Darwin" ]]; then
  echo "This script targets macOS. On Linux, set MANAGED_DIR to /etc/claude-code/managed-settings.d." >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run again with sudo: sudo $0" >&2
  exit 1
fi
case "$PYTHON" in
  /usr/bin/*|/opt/homebrew/*|/usr/local/*|/Library/Frameworks/*) ;;
  *) echo "Refusing to pin an interpreter outside a system location: $PYTHON" >&2; exit 1 ;;
esac

install -d -o root -g wheel -m 0755 "$TARGET_DIR" "$MANAGED_DIR"
# macOS ships openrsync, which lacks --chown/--chmod: plain cp, then explicit ownership and modes.
rm -rf "$TARGET_DIR/omp" "$TARGET_DIR/hooks"
cp -R "$SOURCE_DIR/omp" "$SOURCE_DIR/hooks" "$TARGET_DIR/"
find "$TARGET_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} +
chown -R root:wheel "$TARGET_DIR"
find "$TARGET_DIR" -type d -exec chmod 0755 {} +
find "$TARGET_DIR" -type f -exec chmod 0644 {} +
chmod 0755 "$TARGET_DIR/hooks/guard.sh"

hook() { printf '{ "type": "command", "command": "%s \\"%s\\"", "timeout": %s }' "$1" "$2" "$3"; }

install -o root -g wheel -m 0644 /dev/stdin "$DROPIN" <<JSON
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ $(hook "$PYTHON" "$TARGET_DIR/omp/hook.py" 30) ] }
    ],
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ $(hook "$BASH_BIN" "$TARGET_DIR/hooks/guard.sh" 10), $(hook "$PYTHON" "$TARGET_DIR/omp/pre_bash.py" 15) ] },
      { "matcher": "Read", "hooks": [ $(hook "$PYTHON" "$TARGET_DIR/omp/pre_read.py" 15) ] },
      { "matcher": "Grep", "hooks": [ $(hook "$PYTHON" "$TARGET_DIR/omp/pre_grep.py" 30) ] }
    ],
    "PostToolUse": [
      { "hooks": [ $(hook "$PYTHON" "$TARGET_DIR/omp/post_scrub.py" 30) ] }
    ]
  },
  "disableAllHooks": false
}
JSON

"$PYTHON" -c "import json; json.load(open('$DROPIN'))"

echo "Installed:"
echo "  code   : $TARGET_DIR (root:wheel, read-only for the user)"
echo "  policy : $DROPIN (interpreter pinned to $PYTHON)"
echo "Check inside Claude Code with /status: the 'Setting sources' line must mention Enterprise managed settings (drop-ins)."
echo "Then remove the OhMyPrivacy entries from ~/.claude/settings.json: they would run the hooks twice."
