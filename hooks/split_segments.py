"""Split a shell command into the segments the guard judges, one per line.

Kept out of guard.sh on purpose: this logic lived inline in a double-quoted bash string,
where one misplaced backslash made the splitter exit non-zero, print nothing, and leave the
guard judging an empty list. A guard that refuses nothing looks exactly like a guard that
found nothing wrong. Here it is a file, with tests.

A heredoc body is data: the shell never runs it, so the guard does not judge it. The one
exception is a body piped into an interpreter, which is executed and stays under judgement.
"""

from __future__ import annotations

import re
import sys

HEREDOC = re.compile(r"""<<-?\s*[\"'\\]?([A-Za-z_][A-Za-z0-9_]*)""")
INTERPRETER = re.compile(r"\|\s*(bash|sh|zsh|python3?|node|perl|ruby|php|eval)\b")
SEPARATORS = re.compile(r"\|\||&&|;|\|")


def segments(command: str) -> list[str]:
    lines = command.split("\n")
    found: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        found.extend(part.strip() for part in SEPARATORS.split(line) if part.strip())
        opening = HEREDOC.search(line)
        if not opening or INTERPRETER.search(line):
            continue
        # Skip the body only once its closing delimiter is in sight. A `<<` inside a quoted
        # string opens no heredoc, and skipping to a delimiter that never comes swallowed the
        # command that followed (`echo "x << y"` then a real read). When the delimiter is
        # absent, judge the lines instead of trusting them. Fail closed.
        delimiter = opening.group(1)
        closing = next((ahead for ahead in range(index, len(lines)) if lines[ahead].strip() == delimiter), None)
        if closing is None:
            continue
        index = closing + 1
    return found


def main() -> int:
    if len(sys.argv) < 2:
        return 1
    for segment in segments(sys.argv[1]):
        print(segment)
    return 0


if __name__ == "__main__":
    sys.exit(main())
