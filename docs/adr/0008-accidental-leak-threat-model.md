# ADR-0008: The threat model is the accidental leak, not the adversarial user

Status: accepted (2026-08-26)

## Context

A red-team pass against the detector found bypasses of two kinds. Some are shapes a user
produces without meaning to: a key wrapped over two lines by a terminal that folds long
lines, a zero-width character picked up in a copy, a short password after `password:`, a
`curl -u user:pass`. Others require intent: a reversed key, a Cyrillic homoglyph in the
prefix, a key spaced every eight characters, a password buried in prose.

## Decision

OhMyPrivacy protects against the first kind and documents the second.

- Accidental shapes are covered by explicit stages: fragment patterns that take the next
  line along, context patterns with a low threshold for password-like keys, inline
  credential patterns, long-hex and entropy stages with digest-marker exclusions.
- Adversarial shapes are recorded as `unittest.expectedFailure` in
  `tests/test_known_limits.py`. A limit that starts passing must lose its marker.

The user is the party being protected, not the adversary. Someone determined to smuggle
their own secret past their own guard does not need to be stopped by it.

## Consequences

- False positives cost one paste of the cleaned message, so precision is tuned for prose,
  git SHAs, docker digests, `integrity` hashes, UUIDs and file paths to pass.
- Adversarial coverage is a non-goal; a pull request that adds it must show it does not
  degrade precision on the accidental corpus.
