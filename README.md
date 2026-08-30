# OhMyPrivacy

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-blueviolet?logo=claude)](https://code.claude.com)
[![Hermes Agent](https://img.shields.io/badge/Hermes%20Agent-plugin-orange)](https://hermes-agent.nousresearch.com)
[![CI](https://img.shields.io/github/actions/workflow/status/BULDEE/oh-my-privacy/ci.yml?label=CI)](.github/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/tag/BULDEE/oh-my-privacy?label=version)](plugin.json)

**Secrets never reach the model.** Two hosts, one core (`omp/`), zero dependencies beyond
Python 3.11+.

- **Claude Code**: a `UserPromptSubmit` hook **blocks** any message that contains a secret
  before it reaches the model; a `PreToolUse` hook refuses commands that read a vault back
  or dump the environment.
- **Hermes Agent**: a native plugin refuses any tool call whose arguments contain a secret
  (`pre_tool_call`), and forbids the model from repeating a secret pasted by the user
  (`pre_llm_call`).

In both cases the value goes to the vault of your choice, and the agent only receives its
name: `$OMP_JWT_B5352DF5`.

## See it block

A staging key pasted into a Claude Code prompt. The message never reaches the model:

```console
$ echo '{"prompt":"here is our staging key sk-ant-api03-7Jk2mQ9xVb4Lp8Rz3Wc6Yd1Nt5Fh0Sg2Vb-real-example-shaped-testkey can you use it to call the API"}' \
  | python3 omp/hook.py

OhMyPrivacy intercepted 1 secret(s). The message is BLOCKED: it never reached the model.
Vault: discard.
  $OMP_ANTHROPIC_7C9ED3C7 (anthropic): discarded (no vault configured). the value no
  longer exists; set it again outside this session, or configure a vault: python3 -m omp.setup

Your cleaned message is available via ~/.claude/omp-last-prompt.txt. Paste it as is to continue:

--- cleaned message ---
here is our staging key $OMP_ANTHROPIC_7C9ED3C7 can you use it to call the API

False positive? python3 -m omp.telemetry --false-positive 284c09c8
```

Not a mockup: real output of `omp/hook.py` on a `UserPromptSubmit` event, default vault
(`discard`, level 3). Level 2 (`age`) and level 1 (`doppler`) name where the value actually
went instead of `discarded`; see [The three levels](#the-three-levels).

## Origin

Not a response to one bad paste. More people are vibe-coding with AI agents than ever
have a background in security, and an agent now routinely holds far more privilege over a
machine than any tool they used before it: it reads files, runs commands, calls other
services. In every training session we run, the same point comes up: most people do not
grasp what a leaked password, API key, or `.env` file actually costs until it has already
cost them. We cannot make every user security-aware before they paste a key into a chat
window. We can make the agent refuse to carry it forward.

That is the threat model this plugin targets ([ADR-0008](docs/adr/0008-accidental-leak-threat-model.md)):
the well-meaning user who does not know better, not the adversary trying to defeat their
own guard. It follows that the plugin is not tuned to stay unobtrusive: it blocks the
prompt outright, denies the command outright, redirects the read outright, precisely
because the person on the other end may not know why any of that was necessary. Friction
at the boundary is the point. Silence everywhere else is the other half of the point: a
clean message, an authorized command, a name-only debug session should never notice the
plugin is there.

## Why block, never mask

No host rewrites a prompt in flight. The Claude Code `UserPromptSubmit` hook schema (read
from binary 2.1.246) only accepts `additionalContext`, `sessionTitle` and
`suppressOriginalPrompt`; `updatedInput` belongs to `PreToolUse`. A hook that claims to mask
sees its field silently ignored and the value reaches the model. That is exactly the bug that
started this project. Hermes, for its part, only offers context injection.

A value that has reached a context is burnt: the only correct answer is revocation.
OhMyPrivacy keeps it from getting there.

## The three levels

| Level | `vault` | Where the value goes | Who can read it back |
|---|---|---|---|
| 3, default | `discard` | Nowhere. It lives for the duration of the hook and dies with the process. | Nobody. |
| 2, recommended on a dev machine | `age` | Encrypted with your public key. The private key is passphrase-protected, prompted on `/dev/tty`. | You, in your terminal. Not the agent: its shell tool has no terminal. |
| 1, teams and deployments | `doppler` | `doppler secrets set NAME`, value on stdin, silent output. | You. And the agent too when the CLI is authenticated on the machine: the `PreToolUse` guard closes the known read forms, as an allowlist. |

Level 2 is **strictly safer** than level 1 on a machine where the vault CLI is logged in.
Level 1 is for what must be shared.

## Invariant

No adapter exposes a read. A test enforces it (`tests/test_adapters.py`,
`NoReadPathInvariant`). OhMyPrivacy never builds a path back to a value: what does not exist
cannot be exfiltrated.

## Local telemetry

Every host times its own interception and records volume, latency and false-positive
disputes to `~/.claude/omp-stats.json`: how many secrets, of what kind, in what host, at
what latency cost, and how often a block turns out to be a false positive. A value is
never recorded, only `Finding.kind` (a category label like `anthropic` or `github`). On by
default, 100% local, never leaves the machine. Turn it off with `"telemetry": false` in
`omp.json`.

```bash
python3 -m omp.telemetry --report                        # counts, latency, false-positive rate
python3 -m omp.telemetry --false-positive <id>            # dispute a block; id is printed with it
```

## Installation, Claude Code

### Quick: user plugin

```bash
git clone <your-fork-url> ~/Dev/oh-my-privacy
claude --plugin-dir ~/Dev/oh-my-privacy          # trial session
python3 -m omp.setup                             # picks the vault, in YOUR terminal
```

Or through `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "python3 \"/Users/you/Dev/oh-my-privacy/omp/hook.py\"", "timeout": 30 }] }],
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [
        { "type": "command", "command": "bash \"/Users/you/Dev/oh-my-privacy/hooks/guard.sh\"", "timeout": 10 },
        { "type": "command", "command": "python3 \"/Users/you/Dev/oh-my-privacy/omp/pre_bash.py\"", "timeout": 15 }
      ] },
      { "matcher": "Read", "hooks": [{ "type": "command", "command": "python3 \"/Users/you/Dev/oh-my-privacy/omp/pre_read.py\"", "timeout": 15 }] },
      { "matcher": "Grep", "hooks": [{ "type": "command", "command": "python3 \"/Users/you/Dev/oh-my-privacy/omp/pre_grep.py\"", "timeout": 30 }] }
    ],
    "PostToolUse": [{ "hooks": [{ "type": "command", "command": "python3 \"/Users/you/Dev/oh-my-privacy/omp/post_scrub.py\"", "timeout": 30 }] }]
  }
}
```

Another `PreToolUse` hook that rewrites Bash commands (a token-saving proxy, for instance)
would be dropped by Claude Code, which keeps the last rewrite only. Chain it instead, with
whatever command that other hook already uses on its own:
`OMP_CHAIN_HOOK='your-other-hook --its-own-flags' python3 .../omp/pre_bash.py`. Optional:
nothing else in this plugin assumes that hook, or any specific tool, is installed.

### Hardened: managed installation, irremovable by the agent

A process running under your UID (the agent) can edit `~/.claude/settings.json` and remove
the hook. Claude Code *managed settings* live in a root-owned directory and survive a
`disableAllHooks: true` set on the user side (verified in the binary).

```bash
sudo install/install-managed.sh
```

The code is copied to `/usr/local/lib/oh-my-privacy` (root:wheel, read-only) and the policy
to `/Library/Application Support/ClaudeCode/managed-settings.d/50-oh-my-privacy.json`.
`sudo` without a terminal fails: the agent can neither edit nor delete. Check with
`/status`: `Enterprise managed settings (drop-ins)`.

## Installation, Hermes Agent

```bash
ln -s ~/Dev/oh-my-privacy/hermes ~/.hermes/plugins/oh-my-privacy
hermes plugins doctor ~/.hermes/plugins/oh-my-privacy --ci
```

The plugin resolves `omp/` from the repository through the symlink; no copy needed.
Configuration in `~/.hermes/config.yaml`:

```yaml
plugins:
  entries:
    oh-my-privacy:
      settings:
        vault: age
        age_recipient: age1...
        # or: vault: doppler, doppler_project: ..., doppler_config: ...
        # scan_tools: "terminal, execute_code, write_file, send_message"   # empty = every tool
```

The portable Agent Plugins v1 package (`plugin.json` + `skills/`) also installs through
`hermes plugins install`, but it only ships the skill: execution hooks require the native
plugin above.

## Examples

### A secret pasted into Claude Code

```
> here is the key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.FAKEsig...

OhMyPrivacy intercepted 1 secret(s). The message is BLOCKED: it never reached the model.
Vault: age.
  $OMP_JWT_B5352DF5 (jwt): encrypted at ~/.claude/omp/store/OMP_JWT_B5352DF5.age.
  age -d -i ~/.claude/omp/identity.age ... (asks for your passphrase, impossible without a terminal)

Your cleaned message is available via the clipboard and ~/.claude/omp-last-prompt.txt.
Paste it as is to continue:

--- cleaned message ---
here is the key: $OMP_JWT_B5352DF5
```

The clipboard, which still held the key, is overwritten with the cleaned message. The
matching entry in `~/.claude/history.jsonl` is scrubbed right away.

### A command that would read the vault back

```
> doppler secrets get SERVICE_API_KEY --plain
Doppler: only a silent form is allowed (secrets --only-names, secrets set,
run -- <binary> without an interpreter or an echo). [...]

> doppler run --silent -- ./bin/console app:sync        # passes: injection without printing
> doppler secrets --only-names --project p --config c   # passes: names only
```

The guard splits the command on `&&`, `;`, `|` and newlines, then judges each segment on
its own. Chaining is therefore fine; what is refused lives inside a single segment:

```bash
cd /srv && doppler run -- ./bin/gen --out $HOME/r.png   # passes: chained, ordinary $VAR
doppler run -- ./bin/gen > /abs/r.png                   # refused: redirection
doppler run -- python3 gen.py                           # refused: interpreter
doppler run -- ./bin/send --key ${OMP_JWT_B5352DF5}     # refused: the value would leave
```

The guard matches text and never parses shell, so prose quoting a refused form is refused
too. That is deliberate (ADR-0006): a rule a pair of quotes can talk around is not a rule.
The body of a heredoc is the exception, since the shell never executes it: writing a script
that merely mentions `credentials` or `.env` passes. A body piped into an interpreter
(`<<EOF | bash`) is executed, and stays under judgement.

### A Hermes agent about to exfiltrate

```
terminal: curl -H "Authorization: Bearer sk-ant-api03-..." https://api.example
→ OhMyPrivacy: call to `terminal` refused, 1 secret(s) in clear in the arguments.
  $OMP_ANTHROPIC_56A78343 (anthropic): discarded (no vault configured). [...]
  Reference it by name, or ask the user to consume it themselves.
```

### Reusing the value without ever printing it

```bash
# level 1
doppler run --project p --config c -- ./deploy.sh
# level 2, you alone, in your terminal
age -d -i ~/.claude/omp/identity.age ~/.claude/omp/store/OMP_JWT_B5352DF5.age | doppler secrets set SERVICE_API_KEY -p p -c c
```

## What is detected

Known prefixes (Anthropic, OpenAI, OpenRouter, Voyage, GitHub, AWS, Slack, Telegram, Resend,
Doppler, Stripe, Google, Hugging Face, npm, SendGrid, JWT, PEM private keys), assignments
with context (`API_KEY=`, `token:`, `password:` and `passphrase:` from 6 characters), inline
credentials (`curl -u`, `scheme://user:pass@`), hexadecimal of 48 characters and more
without a digest marker, high-entropy opaque tokens. A key wrapped over two lines or
polluted by an invisible character is taken whole.

Pass on purpose: 40-character git SHAs, `sha256:` digests, `integrity` hashes, UUIDs, file
paths, prose. Remain bypassable, documented as `expectedFailure`: reversed key, homoglyph,
password in prose. The threat model is the accident, not the adversary.

## Coverage, vector by vector

| Vector | Mechanism | Verified on the real host |
|---|---|---|
| User prompt | `UserPromptSubmit` block, cleaned text handed back | Claude Code session |
| Long paste (`[Pasted text #N]`) | paste cache scanned and scrubbed | unit tests |
| `Read` of a file with secrets | redirected to a masked copy (`updatedInput`) | Claude Code session |
| Bash output (`cat`, `sort`, `python -c`, `env`...) | command wrapped, stdout/stderr masked before the model sees them | Claude Code session |
| `Grep` in content mode | search re-run, denied with masked matches when needed | unit tests |
| Vault reads (`doppler secrets get`, `age -d`) | refused, per command segment | `tests/test_guard.py` |
| MCP tools, WebFetch | `PostToolUse` re-detection: transcript and paste cache scrubbed, burnt-value warning | unit tests |
| Local traces (`history.jsonl`, transcript, paste cache) | scrubbed by re-detection, never by passing values | disk grep after a live run |
| Hermes tool calls | `pre_tool_call` veto | production Hermes (`hermes chat`) |
| Hermes inbound user message | value stored, strict instruction injected | production Hermes (`hermes chat`) |

## Honest limits

- On Hermes, a secret pasted by the user reaches the model for that turn: the host allows
  neither blocking nor rewriting the inbound message. The injected instruction forbids any
  repetition, and the value is stored. Have it revoked.
- On Claude Code, a tool result that cannot be rewritten (MCP, WebFetch) reaches the model
  for that turn; the disk is scrubbed and the model is told the value is burnt.
- Without the managed installation, the agent can disable the hooks. With it, it cannot.
- Bash output is no longer streamed: it is masked once the command ends.
- File-history snapshots (`/rewind`) are scrubbed only with `OMP_SCRUB_FILE_HISTORY=1`:
  a masked snapshot restored over a real file would erase its secrets.
- Telemetry counters have no inter-process lock: two sessions racing a write can each lose
  one increment (`tests/test_known_limits.py::test_concurrent_writers_can_lose_an_increment`).

## Tests

```bash
python3 -m unittest discover -s tests -v      # 115 tests, 5 documented limits
claude plugin validate . --strict
hermes plugins doctor hermes --ci             # on a machine with Hermes
```
