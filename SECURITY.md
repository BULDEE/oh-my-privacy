# Security Policy

## Threat model

OhMyPrivacy targets the well-meaning user who pastes a secret without realizing it, not an
adversary trying to defeat their own guard. See [ADR-0008](docs/adr/0008-accidental-leak-threat-model.md).
The [Honest limits](README.md#honest-limits) section of the README lists every known gap in
that model; those are not vulnerabilities, they are documented boundaries.

## Reporting a vulnerability

Open a private report via [GitHub Security Advisories](https://github.com/BULDEE/oh-my-privacy/security/advisories/new)
for this repository, or email contact@buldee.com. Include:

- affected version (`plugin.json` / `hermes/plugin.yaml`)
- host (Claude Code or Hermes Agent) and vault (`discard`, `age`, `doppler`)
- minimal reproduction

Expect an acknowledgement within 5 business days. Do not open a public issue for a
suspected bypass of the guardrail itself; use the advisory channel above.

## Pre-installation verification

Only install this plugin from `github.com/BULDEE/oh-my-privacy`. Do not trust forks,
mirrors, or "improved" copies distributed elsewhere. Before trusting a build:

```bash
git clone https://github.com/BULDEE/oh-my-privacy
cd oh-my-privacy
python3 -m unittest discover -s tests -v      # 76 tests, 4 documented limits
claude plugin validate . --strict
```

## Supported versions

Only the latest tagged release on `main` receives security fixes.
