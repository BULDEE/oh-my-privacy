"""Interactive setup: `python3 -m omp.setup`, to be run in YOUR terminal.

This script needs a real terminal for age (passphrase on /dev/tty). It writes no credential:
Doppler authentication stays with `doppler login`, and the age identity is encrypted with the
passphrase you choose here.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp import config as config_module  # noqa: E402
from omp.adapters.age import DEFAULT_STORE_DIR, IDENTITY_FILE  # noqa: E402
from omp.config import Config, save  # noqa: E402

CHOICES = ("discard", "doppler", "age")
DOPPLER_WARNING = (
    "Warning: an authenticated Doppler CLI on this machine can also READ. Any process running under your "
    "account, the agent included, can read the vault back. On a development machine, age is strictly safer: "
    "decryption requires your passphrase on a terminal, which the agent does not have."
)


def detected_clis() -> dict[str, bool]:
    return {"doppler": shutil.which("doppler") is not None, "age": shutil.which("age") is not None and shutil.which("age-keygen") is not None}


def ask(question: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    answer = input(f"{question}{suffix}: ").strip()
    return answer or default


def doppler_json(argv: list[str]) -> list[dict[str, str]]:
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        return []
    try:
        parsed = json.loads(completed.stdout)
    except ValueError:
        return []
    return parsed if isinstance(parsed, list) else []


def configure_doppler() -> Config:
    print(DOPPLER_WARNING)
    projects = [entry["name"] for entry in doppler_json(["doppler", "projects", "--json"]) if "name" in entry]
    if projects:
        print("Doppler projects: " + ", ".join(projects))
    project = ask("Doppler project", projects[0] if projects else "")
    configs = [entry["name"] for entry in doppler_json(["doppler", "configs", "--project", project, "--json"]) if "name" in entry]
    if configs:
        print("Configs: " + ", ".join(configs))
    config_name = ask("Doppler config", next((name for name in configs if name.startswith("dev")), configs[0] if configs else ""))
    return Config(vault="doppler", options={"project": project, "config": config_name})


def configure_age() -> Config:
    DEFAULT_STORE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DEFAULT_STORE_DIR, 0o700)
    identity_path = DEFAULT_STORE_DIR / IDENTITY_FILE
    if identity_path.exists():
        recipient = ask("Existing identity found. Public key (age1...)")
        return Config(vault="age", options={"recipient": recipient})
    keygen = subprocess.run(["age-keygen"], capture_output=True, text=True, check=True)
    recipient = next(line.split(":", 1)[1].strip() for line in keygen.stdout.splitlines() if line.startswith("# public key:"))
    print("Choose the passphrase that will protect the private key. It is asked on every decryption, never on encryption.")
    subprocess.run(["age", "--passphrase", "--output", str(identity_path)], input=keygen.stdout, text=True, check=True)
    os.chmod(identity_path, 0o600)
    print(f"Encrypted identity: {identity_path}")
    return Config(vault="age", options={"recipient": recipient})


def choose(vault: str | None) -> str:
    available = detected_clis()
    print("Detected vaults: " + (", ".join(name for name, present in available.items() if present) or "none"))
    if vault:
        return vault
    print("Recommended: age (level 2, unreadable by the agent). Doppler suits team sharing and deployments.")
    return ask("Vault (discard, doppler, age)", "age" if available["age"] else "doppler" if available["doppler"] else "discard")


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure the OhMyPrivacy vault.")
    parser.add_argument("--vault", choices=CHOICES)
    arguments = parser.parse_args()
    vault = choose(arguments.vault)
    if vault not in CHOICES:
        print(f"Unknown vault: {vault}", file=sys.stderr)
        return 1
    builders = {"doppler": configure_doppler, "age": configure_age}
    config = builders[vault]() if vault in builders else Config(vault="discard")
    config = replace(config, telemetry=config_module.load().telemetry)
    path = save(config)
    print(f"Configuration written: {path} (vault: {config.vault})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
