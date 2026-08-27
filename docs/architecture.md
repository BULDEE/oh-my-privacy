# Architecture

OhMyPrivacy is a host-agnostic core wrapped by thin host integrations. The core decides
*what* is a secret and *where* it goes; each host decides *how* to refuse.

## Layers

```
hosts            omp/hook.py (Claude Code)     hermes/__init__.py (Hermes)     omp/setup.py (CLI)
                 hooks/guard.sh (PreToolUse)   install/install-managed.sh
                        │                              │
application      omp/usecase.py  ──  intercept(text, adapter) -> Interception | None
                        │                              │
domain           omp/detect.py   ──  detect(text) -> (cleaned, [Finding])
                        │
infrastructure   omp/adapters/{discard,age,doppler}.py   omp/history.py   omp/config.py
```

Dependency direction is downward only. `detect.py` imports nothing from the project.
`usecase.py` imports the detector and the adapter protocol. Hosts are composition roots:
they load configuration, build the adapter, call the use case and format the answer.

## Data flow, Claude Code

```mermaid
sequenceDiagram
    participant U as User
    participant CC as Claude Code
    participant H as omp/hook.py
    participant D as detect()
    participant V as Vault adapter
    participant HS as history.py
    U->>CC: prompt with a secret
    CC->>H: UserPromptSubmit JSON on stdin
    H->>D: detect(prompt)
    D-->>H: cleaned text + findings
    H->>V: store(name, value) on stdin of the vault CLI
    V-->>H: reference, retrieve hint
    H->>HS: scrub(since) now, then detached for 15 s
    H-->>CC: decision=block, suppressOriginalPrompt, reason with cleaned text
    H-->>U: cleaned text on clipboard and in a private file
    CC-->>U: block banner; the model never sees the prompt
```

## Data flow, Hermes

```mermaid
sequenceDiagram
    participant A as Agent (model)
    participant HA as Hermes runtime
    participant P as hermes/__init__.py
    participant D as detect()
    participant V as Vault adapter
    A->>HA: tool call (terminal, write_file, send_message...)
    HA->>P: pre_tool_call(tool_name, args)
    P->>D: detect(json.dumps(args))
    alt secret found
        P->>V: store(name, value)
        P-->>HA: {"action": "block", "message": names + guidance}
        HA-->>A: call refused
    else clean
        P-->>HA: None
        HA->>HA: execute the tool
    end
```

## Detection pipeline

Stages run in order; each replaces what it finds before the next runs, so nothing is
counted twice and later stages never see earlier matches.

1. **Prefix patterns**: vendor prefixes (`sk-ant-`, `ghp_`, `AKIA`, JWT, PEM blocks).
2. **Fragment patterns**: a known prefix followed by a truncated, wrapped or polluted key;
   the next line is taken along when it looks like the rest of the key.
3. **Context patterns**: `api_key =`, `token:`, `Authorization: Bearer` with values of 16+
   characters; `password:`/`passphrase:`/`pwd=` from 6 characters.
4. **Inline credentials**: `curl -u user:pass`, `scheme://user:pass@host`.
5. **Long hex**: 48+ hexadecimal characters not preceded by `sha256:`, `sha512-`,
   `integrity`, `md5:`.
6. **Entropy**: 32+ characters, mixed case plus digits, Shannon entropy at or above 4.5
   bits per character, same digest-marker exclusion.

Placeholder names are `OMP_<KIND>_<8 hex of sha256(value)>`: stable, collision-resistant,
and safe to show anywhere.

## Storage levels

See ADR-0003. `build(config)` in `omp/adapters/__init__.py` is the only factory; every
failure path returns `DiscardAdapter`.

## Guards around the core

- `hooks/guard.sh` (Claude Code `PreToolUse`, `Bash` matcher) refuses read paths to vaults
  and environment dumps, as an allowlist for Doppler forms (ADR-0006).
- `install/install-managed.sh` moves both hooks under root-owned managed settings so the
  agent cannot remove them (ADR-0005).
- `omp/history.py` removes what Claude Code wrote to the up-arrow history (ADR-0004).

## Extension points

| To add | Touch | Prove with |
|---|---|---|
| A vault | one class in `omp/adapters/`, one line in `REGISTRY` | `NoReadPathInvariant` still green, a store round-trip test |
| A secret format | one tuple in `PREFIX_PATTERNS` or `FRAGMENT_PATTERNS` | a detection test and a precision test on prose |
| A host | one composition root calling `usecase.intercept` | a simulated-context test plus a real-host validation |
| Telemetry on a new host | time the `detect()`/`intercept()` call, one `telemetry.record(...)` line | a subprocess or in-process test asserting the bucket appears in the stats file |

## Repository layout

```
omp/               core: detect, usecase, config, history, adapters/, hook.py, setup.py
hooks/             Claude Code hooks manifest and PreToolUse guard
hermes/            Hermes native plugin (plugin.yaml, register(ctx))
skills/            portable skill (rules for any agent)
install/           managed installation script
tests/             unit tests, host simulations, documented limits
docs/              this file, ADRs, examples
.claude-plugin/    Claude Code plugin manifest
plugin.json        Agent Plugins v1 manifest (portable package)
```
