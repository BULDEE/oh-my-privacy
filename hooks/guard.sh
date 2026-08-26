#!/usr/bin/env bash
# PreToolUse hook (Bash): refuses commands that read a vault back. Output masking
# (omp/pre_bash.py) covers everything else; this guard closes the paths where masking would
# still hand the agent a value it has no business asking for. Every segment of a compound
# command is judged on its own, so an allowed form cannot smuggle a refused one after `;`.
set -uo pipefail

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

judge_segment() {
  local segment="$1"
  # Doppler: allowlist. Silent forms only; `run` may launch a binary but never an interpreter, an environment dump or an echo.
  if segment_matches "$segment" '(^|[[:space:]])doppler([[:space:]]|$)'; then
    if segment_matches "$segment" 'doppler secrets --only-names' \
       || segment_matches "$segment" 'doppler secrets (set|delete) ' \
       || segment_matches "$segment" 'doppler (projects|configs|configure|login|logout|me|--version|activity|environments)' \
       || { segment_matches "$segment" 'doppler run ' && ! segment_matches "$segment" 'doppler run .*(env|printenv|export|declare|set$|python|node|perl|ruby|php|sh -c|bash -c|zsh -c|eval|echo|printf|cat |curl|wget|nc |base64|xxd|od |hexdump|tee|tr |awk|sed|>|\$[A-Z_]+)'; }; then
      return 0
    fi
    deny "Doppler: only a silent form is allowed (secrets --only-names, secrets set, run -- <binary> without an interpreter or an echo). OhMyPrivacy never opens a path back to a value: consume it with doppler run -- <binary> without printing it."
  fi
  # age: decryption belongs to the user, on a terminal.
  if segment_matches "$segment" '(^|[[:space:]])age[[:space:]]+(-d|--decrypt)' || segment_matches "$segment" 'age-keygen -y'; then
    deny "age: decryption requires the user's passphrase on their terminal. Ask them to decrypt it themselves."
  fi
  # Whole-environment dumps: masked anyway, refused because no task needs them.
  if segment_matches "$segment" '^[[:space:]]*(env|printenv|export -p|declare -x|set)[[:space:]]*$'; then
    deny "env, printenv, export -p, declare -x and set dump the whole environment. Target the variable you need."
  fi
  # Well-known secret files: refused outright rather than left to output masking (ADR-0001,
  # ADR-0006). The only accepted form redacts inline before anything is printed.
  if segment_matches "$segment" '(^|[[:space:]/])(\.env|\.zshenv|\.netrc|credentials|identity\.age)([[:space:]]|$)'; then
    if ! segment_matches "$segment" "sed[[:space:]].*s/=\\.\\*/=<masked>/"; then
      deny "Reads of .env, .zshenv, .netrc, credentials or the age identity are refused outright. Redact inline instead: sed 's/=.*/=<masked>/' <file>"
    fi
  fi
  return 0
}

# Pipeline-level rule: the masking pipe is what makes the command acceptable, so it is judged on the whole command.
if segment_matches "$command" 'railway (variables|list-variables)' && ! segment_matches "$command" 'jq +(-r +)?'"'"'?keys'; then
  deny "railway variables prints every secret. For NAMES only: railway variables --json | jq keys"
fi

# Split on statement and pipeline separators; newlines separate statements too.
python3 -c "
import re, sys
for segment in re.split(r'\|\||&&|;|\||\n', sys.argv[1]):
    segment = segment.strip()
    if segment:
        print(segment)
" "$command" | while IFS= read -r segment; do
  judge_segment "$segment"
done

exit 0
