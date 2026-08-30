# ADR-0006: The PreToolUse guard is an allowlist for vault CLIs

Status: accepted (2026-08-26)

## Context

The first `PreToolUse` guard was a denylist with a "masked output" bypass: any command
containing `| wc`, `| python3`, `--silent` or the word `masque` passed. A one-line probe
(`cat ~/.claude/.omp-secrets | wc -c`) went straight through it. A denylist always has a
door; the reviewer's job is to find it, and the agent will too.

## Decision

For vault CLIs, the guard enumerates what is allowed and refuses everything else:

- Doppler: `secrets --only-names`, `secrets set`, `secrets delete`, `projects`, `configs`,
  `configure`, `login`, `logout`, `me`, `activity`, `environments`, and `run -- <binary>`
  provided the command after `run` contains no interpreter (`python`, `node`, `sh -c`...),
  no environment dump (`env`, `printenv`, `export`), no echo or transfer tool
  (`echo`, `printf`, `curl`, `base64`...), no redirection, and no expansion of a
  secret-bearing variable.
- age: `-d` / `--decrypt` and `age-keygen -y` are always refused.

A rule that a pair of braces or a reordered flag can talk around is not a rule. Two such
rules shipped and were closed on 2026-08-30 (`tests/test_guard.py`):

- the variable rule matched `$[A-Z_]+`, so `${OMP_JWT_...}` passed while `$HOME` was
  refused: exactly backwards. It now names what carries a value (`OMP_*`, and any name
  ending in `SECRET`, `TOKEN`, `PASSWORD`, `API_KEY`, `CREDENTIAL`, `PRIVATE_KEY`), in both
  brace forms, and lets ordinary paths through.
- the age rule required `-d` to be the first argument, so `age -i id.txt -d store/X.age`
  decrypted freely. The flag is now matched wherever it sits.
- Environment dumps (`env`, `printenv`, `export -p`, `declare -x`, `set`) and reads of
  secret files (`.env`, `.zshenv`, `credentials`, `.netrc`, the age store) are refused;
  the only accepted masking form is `sed 's/=.*/=<masked>/'`.
- `railway variables` passes only when piped to `jq keys`.

## Consequences

- Legitimate injection forms (`doppler run --silent -- ./bin/console`, `npm test`) pass.
  So do the compound forms: `&&`, a pipe, and a heredoc written on an earlier line, since
  the guard splits on those separators and judges each segment alone.
- New safe forms must be added explicitly; the default answer is "no".
- The guard matches text; it does not parse shell. Quoting changes nothing, which is the
  point, and it produces three accepted false positives, each asserted in
  `tests/test_guard.py::AcceptedFalsePositives`:
  - prose quoting a forbidden form inside quotes is refused. Loud is what a guard should be.
  - a redirection on `run` (`run -- ./gen > out.png`) is refused even though the value
    never leaves. It is defence in depth: `> f` followed by a later read of `f` leaves the
    masked-output path. Legitimate writes go through the binary's own `--out` flag.
  - `$VAR` names are matched, not resolved, so a variable that merely *sounds* like a
    secret (`$DEPLOY_TOKEN_PATH`) is refused. Rename it, or pass it as a literal.
- These false positives are the reason a working form can look broken. They belong in the
  documentation of whatever calls the wrapper, not in the discovery log of each session.

## A false positive is not a cosmetic defect

On 2026-08-30 a heredoc writing `bot-env-sync.sh` was refused over the word `credentials`
in a comment. The caller did not notice the refusal, the file was never created, and the
empty result overwrote the target with 0 bytes. Two things were wrong, and only one of them
was the rule:

- The guard judged the body of a heredoc as if it were commands. The shell never executes
  that body, so neither does the guard now (`hooks/split_segments.py`). A body piped into
  an interpreter is executed, and stays under judgement.
- `credentials` matched as a bare word. Only a path form (`.../credentials`) does now.

The splitter moved out of the inline bash string it lived in, because the failure mode of
that string is silent: one stray backslash makes it exit non-zero, print nothing, and leave
the guard judging an empty list. A guard that refuses nothing is indistinguishable from a
guard that found nothing wrong. It now falls back to judging the raw command whenever the
split fails or comes back empty, and `tests/test_guard.py::FailsClosed` holds that shut.

The refusal message says the command did not run. A hook cannot make its caller notice, but
it can stop the message from reading like a warning.
