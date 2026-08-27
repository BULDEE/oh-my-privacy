"""Configuration: ~/.claude/omp.json, or the path carried by OMP_CONFIG.

No vault credential lives here. Authentication stays with the vault CLI (doppler login,
passphrase-protected age identity); OhMyPrivacy only reuses it.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path.home() / ".claude" / "omp.json"
DEFAULT_VAULT = "discard"
MAX_CONFIG_BYTES = 100_000


@dataclass(frozen=True)
class Config:
    vault: str = DEFAULT_VAULT
    options: dict[str, str] = field(default_factory=dict)
    clipboard: bool = True
    telemetry: bool = True
    prompt_file: Path | None = Path.home() / ".claude" / "omp-last-prompt.txt"


def config_path() -> Path:
    override = os.environ.get("OMP_CONFIG")
    return Path(override).expanduser() if override else DEFAULT_PATH


def load(path: Path | None = None) -> Config:
    """A missing or unreadable file yields the default configuration: discard.

    Falling back to the safest mode is deliberate: a broken configuration must never turn
    a block into a leak.
    """
    raw = _read_json(path or config_path())
    if raw is None:
        return Config()
    vault = str(raw.get("vault", DEFAULT_VAULT))
    options_raw = raw.get(vault, {})
    options = {str(key): str(value) for key, value in options_raw.items()} if isinstance(options_raw, dict) else {}
    return Config(
        vault=vault,
        options=options,
        clipboard=bool(raw.get("clipboard", True)),
        telemetry=bool(raw.get("telemetry", True)),
        prompt_file=_prompt_file(raw.get("prompt_file", True)),
    )


def _read_json(target: Path) -> dict[str, object] | None:
    # craftsman-ignore: PY002 (single unit: the fd-open/type-check/read sequence must not be split
    # without re-litigating where each OSError is caught - same shape already accepted for
    # omp/telemetry.py's record())
    """Never block: a hostile local process can replace this path with a FIFO or a device.

    `record()` (`omp/telemetry.py`) reads this file on every interception across four hosts
    that never touched `omp.json` before telemetry existed; the same `O_NONBLOCK` +
    `O_NOFOLLOW` + regular-file-only pattern that hardens the telemetry store applies here,
    duplicated rather than imported to avoid a circular import (telemetry imports config).
    """
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(str(target), flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            return None
    except OSError:
        os.close(descriptor)
        return None
    try:
        with os.fdopen(descriptor, "r") as handle:
            if os.fstat(handle.fileno()).st_size > MAX_CONFIG_BYTES:
                return None
            raw = json.loads(handle.read())
    except Exception:
        # Deeply nested JSON raises RecursionError (a RuntimeError, not ValueError) before the size
        # cap can help: matches telemetry.py's load(), same reasoning, same "never raises" contract.
        return None
    return raw if isinstance(raw, dict) else None


def _prompt_file(raw: object) -> Path | None:
    if raw is False:
        return None
    if isinstance(raw, str):
        return Path(raw).expanduser()
    return Config().prompt_file


def save(config: Config, path: Path | None = None) -> Path:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {"vault": config.vault, "clipboard": config.clipboard, "telemetry": config.telemetry}
    if config.options:
        payload[config.vault] = dict(config.options)
    if config.prompt_file is None:
        payload["prompt_file"] = False
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return target
