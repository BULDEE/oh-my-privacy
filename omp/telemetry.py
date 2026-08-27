"""Local, opt-out telemetry: volume and friction, never a secret value.

Every host times its own `detect()`/`intercept()` call and records the outcome here: how
many interceptions, of what kind, at what latency, and whether the user later disputed one
as a false positive. Nothing leaves the machine; the store lives next to `omp.json`. A
value never reaches this module: only `Finding.kind` (a category label) is ever recorded.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import config as config_module  # noqa: E402

DEFAULT_STATS_PATH = Path.home() / ".claude" / "omp-stats.json"
RING_BUFFER_SIZE = 50
VALID_ACTIONS: frozenset[str] = frozenset({"block", "mask", "scrub", "context"})
MAX_LABEL_LENGTH = 64
_UNSAFE_LABEL_CHARS = re.compile(r"[^A-Za-z0-9_.-]")


def _sanitize_label(value: str) -> str:
    """Strip `host`/`tool` to a safe character set before they reach the bucket key or the ring buffer.

    Both values can originate from a tool name a host passes through largely unchecked
    (`payload.get("tool_name", "")` in `post_scrub.py`); this keeps them from injecting
    control characters or shell metacharacters into the store, and therefore into --report's output.
    """
    return _UNSAFE_LABEL_CHARS.sub("_", value)[:MAX_LABEL_LENGTH]


def stats_path() -> Path:
    override = os.environ.get("OMP_STATS")
    return Path(override).expanduser() if override else DEFAULT_STATS_PATH


def load(path: Path | None = None) -> dict[str, object]:
    target = path or stats_path()
    try:
        raw = json.loads(target.read_text())
    except (OSError, ValueError):
        raw = None
    if not isinstance(raw, dict):
        raw = {}
    raw.setdefault("version", 1)
    raw.setdefault("counters", {})
    raw.setdefault("recent_events", [])
    return raw


def _save(path: Path, store: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(store, handle, indent=2)
        handle.write("\n")


def _bucket_key(host: str, tool: str, kind: str, action: str) -> str:
    return f"{host}.{tool}.{kind}.{action}"


def _bump(counters: dict[str, object], key: str, latency_ms: float) -> None:
    raw_bucket = counters.get(key)
    bucket = raw_bucket if isinstance(raw_bucket, dict) else {"count": 0, "latency_ms_total": 0.0, "false_positive_count": 0}
    bucket["count"] = int(bucket.get("count", 0)) + 1
    bucket["latency_ms_total"] = float(bucket.get("latency_ms_total", 0.0)) + latency_ms
    counters[key] = bucket


def record(host: str, tool: str, kinds: list[str], action: str, latency_ms: float, path: Path | None = None) -> str | None:
    # craftsman-ignore: PY002 (brief-specified implementation, kept as one unit for the single try/except no-raise contract)
    """Best-effort: never raises. Returns None when telemetry is off, the input is invalid, or the write fails."""
    if action not in VALID_ACTIONS or not kinds:
        return None
    host = _sanitize_label(host)
    tool = _sanitize_label(tool)
    try:
        config = config_module.load()
        if not config.telemetry:
            return None
        target = path or stats_path()
        store = load(target)
        counters = store["counters"]
        if not isinstance(counters, dict):
            counters = {}
            store["counters"] = counters
        for kind in kinds:
            _bump(counters, _bucket_key(host, tool, kind, action), latency_ms)
        events = store["recent_events"]
        if not isinstance(events, list):
            events = []
            store["recent_events"] = events
        event_id = secrets.token_hex(4)
        events.append(
            {
                "id": event_id,
                "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "host": host,
                "tool": tool,
                "kinds": list(kinds),
                "action": action,
                "latency_ms": latency_ms,
                "false_positive": False,
            }
        )
        del events[:-RING_BUFFER_SIZE]
        _save(target, store)
        return event_id
    except (OSError, ValueError, TypeError):
        return None


def mark_false_positive(event_id: str, path: Path | None = None) -> bool:
    try:
        target = path or stats_path()
        store = load(target)
        events = store.get("recent_events")
        counters = store.get("counters")
        if not isinstance(events, list) or not isinstance(counters, dict):
            return False
        matched = False
        for event in events:
            if not isinstance(event, dict) or event.get("id") != event_id:
                continue
            matched = True
            if event.get("false_positive"):
                break
            event["false_positive"] = True
            host, tool, action = str(event.get("host")), str(event.get("tool")), str(event.get("action"))
            for kind in event.get("kinds", []):
                bucket = counters.get(_bucket_key(host, tool, str(kind), action))
                if isinstance(bucket, dict):
                    bucket["false_positive_count"] = int(bucket.get("false_positive_count", 0)) + 1
            break
        if matched:
            _save(target, store)
        return matched
    except (OSError, ValueError, TypeError):
        return False


def format_report(store: dict[str, object]) -> str:
    counters = store.get("counters")
    if not isinstance(counters, dict) or not counters:
        return "No telemetry recorded yet."
    lines = [
        "Counts are per finding, not per interception (one call can touch several kinds).",
        f"{'bucket':<45} {'count':>6} {'avg_ms':>8} {'false_positive':>15}",
    ]
    for key in sorted(counters):
        bucket = counters[key]
        if not isinstance(bucket, dict):
            continue
        count = int(bucket.get("count", 0))
        total_latency = float(bucket.get("latency_ms_total", 0.0))
        false_positives = int(bucket.get("false_positive_count", 0))
        average = total_latency / count if count else 0.0
        rate = (false_positives / count * 100) if count else 0.0
        lines.append(f"{key:<45} {count:>6} {average:>7.1f}ms {rate:>14.1f}%")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OhMyPrivacy local telemetry: report usage or mark a false positive.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--false-positive", metavar="ID", help="mark a recent interception id as a false positive")
    group.add_argument("--report", action="store_true", help="print counts, latency and false-positive rate by bucket")
    arguments = parser.parse_args(argv)
    if arguments.report:
        print(format_report(load()))
        return 0
    marked = mark_false_positive(arguments.false_positive)
    print("Marked." if marked else f"No event {arguments.false_positive} found in the last {RING_BUFFER_SIZE} interceptions.")
    return 0 if marked else 1


if __name__ == "__main__":
    sys.exit(main())
