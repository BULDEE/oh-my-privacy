# Contributing

## Setup

```bash
git clone https://github.com/BULDEE/oh-my-privacy
cd oh-my-privacy
python3 -m unittest discover -s tests -v
```

## Before opening a PR

```bash
python3 -m unittest discover -s tests -v      # 76 tests, 4 documented limits
ruff check .
mypy omp hermes
shellcheck hooks/guard.sh install/install-managed.sh
claude plugin validate . --strict
hermes plugins doctor hermes --ci              # on a machine with Hermes
```

CI (`.github/workflows/ci.yml`) runs the same checks on every push and pull request.

## Ground rules

- **Write-only adapters.** No adapter may expose a read path back to a stored secret
  ([ADR-0002](docs/adr/0002-write-only-adapters.md)). `tests/test_adapters.py` enforces this
  as an invariant; a PR that breaks it will not merge regardless of what else it does.
- **Block, never mask.** No host rewrites a prompt in flight; see
  [ADR-0001](docs/adr/0001-block-never-mask.md) before proposing a masking approach.
- **New secret patterns** go through `omp/detect.py` with a test in `tests/test_detect.py`
  covering both the positive match and a documented false-positive it should not catch.
- **Design decisions** worth remembering as an ADR live in `docs/adr/`; see
  [docs/adr/README.md](docs/adr/README.md) for the format.
- **No em dash** (`-`, U+2014) in any source file; CI checks for it. Use `:`, `.`, `,`, or
  restructure the sentence.

## Reporting a bypass of the guardrail itself

Do not open a public issue. See [SECURITY.md](SECURITY.md).
