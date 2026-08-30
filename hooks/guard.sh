#!/usr/bin/env bash
# PreToolUse hook (Bash): refuses commands that read a vault back. Output masking
# (omp/pre_bash.py) covers everything else; this guard closes the paths where masking would
# still hand the agent a value it has no business asking for. Every segment of a compound
# command is judged on its own, so an allowed form cannot smuggle a refused one after `;`.
set -uo pipefail

SPLITTER="$(dirname -- "${BASH_SOURCE[0]}")/split_segments.py"
TELEMETRY="$(dirname -- "${BASH_SOURCE[0]}")/../omp/telemetry.py"
readonly SPLITTER TELEMETRY

input=$(cat)
command=$(printf '%s' "$input" | python3 -c "
import sys, json
try:
    print(json.load(sys.stdin).get('tool_input', {}).get('command', ''))
except Exception:
    print('')
" 2>/dev/null)

[[ -z "$command" ]] && exit 0

deny() {
  # Record the refusal (rule name only, never a value) before answering. Best-effort: telemetry
  # must never delay or break a block, so a failure here is swallowed.
  python3 "$TELEMETRY" --deny "${2:-guard}" >/dev/null 2>&1 || true
  python3 -c "
import json, sys
print(json.dumps({'hookSpecificOutput': {
    'hookEventName': 'PreToolUse',
    'permissionDecision': 'deny',
    'permissionDecisionReason': sys.argv[1],
}}))
" "$1"
  exit 0
}

segment_matches() { printf '%s' "$1" | grep -qE -- "$2"; }

# What may never follow `doppler run`: an interpreter, an environment dump, an echo, a
# transfer tool, a redirection, or the expansion of a variable that carries a secret.
# The variable rule names secrets rather than capitals: `$HOME` and `${CLAUDE_PLUGIN_ROOT}`
# are ordinary paths, while `${OMP_JWT_...}` is a value on its way out. Both brace forms are
# covered, since `$FOO` and `${FOO}` expand identically and only the regex told them apart.
readonly RUN_FORBIDDEN='doppler run .*(env|printenv|export|declare|set$|python|node|perl|ruby|php|sh -c|bash -c|zsh -c|eval|echo|printf|cat |curl|wget|nc |base64|xxd|od |hexdump|tee|tr |awk|sed|>|\$\{?(OMP_|[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|CREDENTIAL|PRIVATE_KEY)))'
# age decrypts whatever the flag order is: `-d` last is the same command as `-d` first.
readonly AGE_DECRYPT='(^|[[:space:]])(-[a-zA-Z]*d[a-zA-Z]*|--decrypt)([[:space:]]|$)'

# Doppler: allowlist. Silent forms only; `run` may launch a binary but never an interpreter, an environment dump or an echo.
judge_doppler() {
  local segment="$1"
  segment_matches "$segment" '(^|[[:space:]])doppler([[:space:]]|$)' || return 0
  segment_matches "$segment" 'doppler secrets --only-names' && return 0
  segment_matches "$segment" 'doppler secrets (set|delete) ' && return 0
  segment_matches "$segment" 'doppler (projects|configs|configure|login|logout|me|--version|activity|environments)' && return 0
  segment_matches "$segment" 'doppler run ' && ! segment_matches "$segment" "$RUN_FORBIDDEN" && return 0
  deny "Doppler: only a silent form is allowed (secrets --only-names, secrets set, run -- <binary> without an interpreter, an echo, a redirection or a secret-bearing \$VAR). OhMyPrivacy never opens a path back to a value: consume it with doppler run -- <binary> without printing it." doppler_read
}

# age: decryption belongs to the user, on a terminal.
judge_age() {
  local segment="$1"
  if { segment_matches "$segment" '(^|[[:space:]])age([[:space:]]|$)' && segment_matches "$segment" "$AGE_DECRYPT"; } \
     || segment_matches "$segment" 'age-keygen[[:space:]]+.*-y'; then
    deny "age: decryption requires the user's passphrase on their terminal. Ask them to decrypt it themselves." age_decrypt
  fi
}

# Whole-environment dumps: masked anyway, refused because no task needs them.
judge_env_dump() {
  if segment_matches "$1" '^[[:space:]]*(env|printenv|export -p|declare -x|set)[[:space:]]*$'; then
    deny "env, printenv, export -p, declare -x and set dump the whole environment. Target the variable you need." env_dump
  fi
}

# Well-known secret files: refused outright rather than left to output masking (ADR-0001,
# ADR-0006). The only accepted form redacts inline before anything is printed.
# `credentials` is an English word before it is a file, so only a path form counts. The
# others are distinctive enough to match bare.
judge_secret_files() {
  local segment="$1"
  segment_matches "$segment" '(^|[[:space:]/'\''"])(\.env|\.zshenv|\.netrc|identity\.age)([[:space:]'\''"]|$)' \
    || segment_matches "$segment" '(^|[[:space:]'\''"])[^[:space:]'\''"]*/credentials([[:space:]'\''"]|$)' \
    || return 0
  segment_matches "$segment" "sed[[:space:]].*s/=\\.\\*/=<masked>/" && return 0
  deny "This command did not run: nothing was read, and nothing was written. Reads of .env, .zshenv, .netrc, a credentials file or the age identity are refused outright. Redact inline instead: sed 's/=.*/=<masked>/' <file>" secret_file
}

judge_segment() {
  judge_doppler "$1"
  judge_age "$1"
  judge_env_dump "$1"
  judge_secret_files "$1"
}

# Pipeline-level rule: the masking pipe is what makes the command acceptable, so it is judged on the whole command.
if segment_matches "$command" 'railway (variables|list-variables)' && ! segment_matches "$command" 'jq +(-r +)?'"'"'?keys'; then
  deny "railway variables prints every secret. For NAMES only: railway variables --json | jq keys" railway_vars
fi

# Segments come from hooks/split_segments.py: statement and pipeline separators, minus the
# heredoc bodies the shell never executes. Judging those bodies refused `cat > script.sh
# <<EOF` over a word in a comment, and the caller took the refusal for a success and
# installed an empty file (incident, 2026-08-30).
#
# Fail closed. A splitter that dies prints nothing, and a guard fed nothing refuses nothing
# while looking perfectly healthy. If the split cannot be trusted, judge the raw command:
# noisier than the truth, never quieter.
if ! segments=$(python3 "$SPLITTER" "$command" 2>/dev/null) || [[ -z "$segments" ]]; then
  segments="$command"
fi

printf '%s\n' "$segments" | while IFS= read -r segment; do
  [[ -n "$segment" ]] && judge_segment "$segment"
done

exit 0
