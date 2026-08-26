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
  (`echo`, `printf`, `curl`, `base64`...), no redirection and no `$VAR` expansion.
- age: `-d` / `--decrypt` and `age-keygen -y` are always refused.
- Environment dumps (`env`, `printenv`, `export -p`, `declare -x`, `set`) and reads of
  secret files (`.env`, `.zshenv`, `credentials`, `.netrc`, the age store) are refused;
  the only accepted masking form is `sed 's/=.*/=<masked>/'`.
- `railway variables` passes only when piped to `jq keys`.

## Consequences

- Legitimate injection forms (`doppler run --silent -- ./bin/console`, `npm test`) pass.
- New safe forms must be added explicitly; the default answer is "no".
- The guard matches the whole command text, so prose quoting a forbidden form inside a
  heredoc is refused too. That is accepted: it is loud, and loud is what a guard should be.
