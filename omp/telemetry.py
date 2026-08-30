"""Local, opt-out telemetry: volume and friction, never a secret value.

Every host times its own `detect()`/`intercept()` call and records the outcome here: how
many interceptions, of what kind, at what latency, and whether the user later disputed one
as a false positive. Nothing leaves the machine; the store lives next to `omp.json`. A
value never reaches this module: only `Finding.kind` (a category label) is ever recorded.

This is a best-effort instrument, never a gate: `record()` and `mark_false_positive()`
catch every exception, so a corrupt, hostile or unwritable store can never propagate a
failure into the host's block decision. Hosts generate their own event id and emit their
decision before calling in here, so telemetry is off the critical path entirely.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import secrets
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import config as config_module  # noqa: E402

DEFAULT_STATS_PATH = Path.home() / ".claude" / "omp-stats.json"
RING_BUFFER_SIZE = 50
VALID_ACTIONS: frozenset[str] = frozenset({"block", "mask", "scrub", "context"})
MAX_LABEL_LENGTH = 64
MAX_STATS_BYTES = 2_000_000
MAX_BUCKETS = 500
_UNSAFE_LABEL_CHARS = re.compile(r"[^A-Za-z0-9_.-]")


def _sanitize_label(value: str) -> str:
    """Strip `host`/`tool`/`kind` to a safe character set before they reach the bucket key or the ring buffer.

    All three can originate from a name a host passes through largely unchecked
    (`payload.get("tool_name", "")` in `post_scrub.py`); this keeps them from injecting
    control characters or shell metacharacters into the store, and therefore into --report's output.
    """
    return _UNSAFE_LABEL_CHARS.sub("_", value)[:MAX_LABEL_LENGTH]


def _as_int(value: object) -> int:
    """A store file can be written by anything on this machine: never trust a field's type or range.

    Clamped, not just type-checked: Python ints have no size limit, so an integer literal just
    under `json`'s own 4300-digit str-conversion cap survives `int()` unraised, then `+ 1` here
    pushes it one digit over that cap - `json.dump` raises on the *next* save, which `_save()`
    cannot recover from once the bad value is already back in the bucket. Clamping keeps every
    stored count inside a range arithmetic on it can never overflow.
    """
    if not isinstance(value, int | float):
        return 0
    try:
        result = int(value)
    except (ValueError, OverflowError):
        return 0
    return result if -(2**63) < result < 2**63 else 0


def _as_float(value: object) -> float:
    """A store file can be written by anything on this machine: never trust a field's type or range."""
    if not isinstance(value, int | float):
        return 0.0
    try:
        result = float(value)
    except OverflowError:
        return 0.0
    return result if math.isfinite(result) else 0.0


def stats_path() -> Path:
    override = os.environ.get("OMP_STATS")
    return Path(override).expanduser() if override else DEFAULT_STATS_PATH


def _open_nonblocking(path: Path, flags: int, mode: int = 0) -> int | None:
    """Open without ever blocking on a FIFO or device, and refuse anything but a regular file.

    A store path a hostile local process pre-plants as a named pipe (`mkfifo`) would otherwise
    block `open()` indefinitely until a reader/writer connects on the other end - turning a
    best-effort instrument into a hang on the caller's decision path. `O_NONBLOCK` makes that
    fail fast with `OSError` instead; `O_NOFOLLOW` (POSIX only) additionally refuses a symlink.
    """
    try:
        combined = flags | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            combined |= os.O_NOFOLLOW
        descriptor = os.open(str(path), combined, mode) if mode else os.open(str(path), combined)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            return None
    except OSError:
        os.close(descriptor)
        return None
    return descriptor


def load(path: Path | None = None) -> dict[str, object]:
    target = path or stats_path()
    raw: object = None
    descriptor = _open_nonblocking(target, os.O_RDONLY)
    if descriptor is not None:
        try:
            with os.fdopen(descriptor, "r") as handle:
                if os.fstat(handle.fileno()).st_size <= MAX_STATS_BYTES:
                    raw = json.loads(handle.read())
        except Exception:
            raw = None
    if not isinstance(raw, dict):
        raw = {}
    raw.setdefault("version", 1)
    raw.setdefault("counters", {})
    raw.setdefault("recent_events", [])
    return raw


ORPHAN_TMP_AGE_SECONDS = 3600


def _sweep_orphan_temp_files(path: Path) -> None:
    """Best-effort: a killed writer leaves its uniquely-named temp file behind forever.

    Only sweep files older than an hour, so this never touches a concurrent writer's own
    in-flight temp file - each call's name is unique, but an old one is never still in use.
    """
    try:
        cutoff = datetime.now(UTC).timestamp() - ORPHAN_TMP_AGE_SECONDS
        for orphan in path.parent.glob(f"{path.name}.*.tmp"):
            try:
                if orphan.stat().st_mtime < cutoff:
                    orphan.unlink(missing_ok=True)
            except OSError:
                continue
    except OSError:
        pass


def _save(path: Path, store: dict[str, object]) -> None:
    """Write through a fresh temp inode, then rename: never follow a symlink, never block on a FIFO,
    never leave a half-written store, never collide with a concurrent writer's temp file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _sweep_orphan_temp_files(path)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    descriptor = _open_nonblocking(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if descriptor is None:
        return
    try:
        with os.fdopen(descriptor, "w") as handle:
            # `os.open`'s mode argument is ignored when the temp file already exists: force it shut either way.
            os.fchmod(handle.fileno(), 0o600)
            json.dump(store, handle, indent=2)
            handle.write("\n")
        temporary.replace(path)
    except Exception:
        # A half-written temp file must never outlive the failure: json.dump streams, so it can
        # already hold whatever the caller handed in before hitting a value it cannot serialize.
        temporary.unlink(missing_ok=True)
        raise


def _bucket_key(host: str, tool: str, kind: str, action: str) -> str:
    return f"{host}.{tool}.{kind}.{action}"


def _bump(counters: dict[str, object], key: str, latency_ms: float) -> None:
    if key not in counters and len(counters) >= MAX_BUCKETS:
        return
    raw_bucket = counters.get(key)
    bucket = raw_bucket if isinstance(raw_bucket, dict) else {}
    counters[key] = {
        "count": _as_int(bucket.get("count", 0)) + 1,
        "latency_ms_total": _as_float(bucket.get("latency_ms_total", 0.0)) + latency_ms,
        "false_positive_count": _as_int(bucket.get("false_positive_count", 0)),
    }


def record(
    host: str,
    tool: str,
    kinds: list[str],
    action: str,
    latency_ms: float,
    path: Path | None = None,
    event_id: str | None = None,
) -> str | None:
    # craftsman-ignore: PY002 (brief-specified implementation, kept as one unit for the single try/except no-raise contract)
    """Best-effort: never raises. Returns None when telemetry is off, the input is invalid, or the write fails.

    `kinds` must be plain category labels (`Finding.kind`), never `Finding` objects: a repr
    of a `Finding` carries the value. Anything that is not a `str` is refused outright.
    """
    if action not in VALID_ACTIONS or not isinstance(host, str) or not isinstance(tool, str):
        return None
    if not kinds or not all(isinstance(kind, str) for kind in kinds):
        return None
    try:
        # Inside the try as well: a caller that defeats the guards above must still not get an exception back.
        host = _sanitize_label(host)
        tool = _sanitize_label(tool)
        labels = [_sanitize_label(kind) for kind in kinds]
        config = config_module.load()
        if not config.telemetry:
            return None
        target = path or stats_path()
        store = load(target)
        counters = store["counters"]
        if not isinstance(counters, dict):
            counters = {}
            store["counters"] = counters
        for label in labels:
            _bump(counters, _bucket_key(host, tool, label, action), latency_ms)
        events = store["recent_events"]
        if not isinstance(events, list):
            events = []
            store["recent_events"] = events
        event_id = event_id or secrets.token_hex(4)
        events.append(
            {
                "id": event_id,
                "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "host": host,
                "tool": tool,
                "kinds": labels,
                "action": action,
                "latency_ms": latency_ms,
                "false_positive": False,
            }
        )
        del events[:-RING_BUFFER_SIZE]
        _save(target, store)
        return event_id
    except Exception:
        return None


def mark_false_positive(event_id: str, path: Path | None = None) -> bool:
    """Best-effort: never raises. Returns False when telemetry is off, the id is unknown, or the write fails."""
    try:
        if not config_module.load().telemetry:
            return False
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
                    bucket["false_positive_count"] = _as_int(bucket.get("false_positive_count", 0)) + 1
            break
        if matched:
            _save(target, store)
        return matched
    except Exception:
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
        try:
            count = int(bucket.get("count", 0))
            total_latency = float(bucket.get("latency_ms_total", 0.0))
            false_positives = int(bucket.get("false_positive_count", 0))
            if not math.isfinite(total_latency):
                continue
            average = total_latency / count if count else 0.0
            rate = (false_positives / count * 100) if count else 0.0
        except (ValueError, OverflowError, TypeError):
            continue
        # Sanitized on read too: the store is a plain file any local process can rewrite, and this line goes to a terminal.
        lines.append(f"{_sanitize_label(str(key)):<45} {count:>6} {average:>7.1f}ms {rate:>14.1f}%")
    return "\n".join(lines)


def false_positive_hint(event_id: str | None) -> str:
    """The one line an intercepting host appends so a false positive is contestable in-flow.

    Without it only prompt blocks carried an id, so the false-positive rate measured almost
    nothing: every mask and scrub counted as a clean success no one could dispute.
    """
    if not event_id:
        return ""
    return f"\nFalse positive? python3 -m omp.telemetry --false-positive {event_id}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OhMyPrivacy local telemetry: report usage or mark a false positive.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--false-positive", metavar="ID", help="mark a recent interception id as a false positive")
    group.add_argument("--report", action="store_true", help="print counts, latency and false-positive rate by bucket")
    group.add_argument("--deny", metavar="RULE", help="record a guard refusal (its rule name) as a block event")
    arguments = parser.parse_args(argv)
    if arguments.report:
        print(format_report(load()))
        return 0
    if arguments.deny:
        record("claude_code", "Bash", [arguments.deny], "block", 0.0)
        return 0
    marked = mark_false_positive(arguments.false_positive)
    print("Marked." if marked else f"No event {arguments.false_positive} found in the last {RING_BUFFER_SIZE} interceptions.")
    return 0 if marked else 1


if __name__ == "__main__":
    sys.exit(main())
