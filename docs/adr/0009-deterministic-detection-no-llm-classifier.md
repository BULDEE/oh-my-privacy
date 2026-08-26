# ADR-0009: Detection stays deterministic; no LLM classifier in the blocking path

Status: accepted (2026-08-26)

## Context

Context keywords (`password`, `token`, `api_key`) are language-bound. The question came up
of replacing or complementing the pattern stages with a small language model that would
judge, whatever the language, whether a prompt contains a secret.

## Decision

No model in the blocking path, hosted or local.

1. **It would be the leak.** Classifying the prompt with a hosted model means sending the
   secret to a third party to decide whether it is a secret. The guard exists to keep the
   value on the machine until it is stored or discarded.
2. **Reproducibility.** A guard must be testable: a regex false negative is a failing test;
   a probabilistic false negative is invisible and drifts with every model update.
3. **Latency.** The hook runs on every prompt. A model call adds hundreds of milliseconds
   each time, for a benefit limited to the keyword stage.
4. **The regex does not grow.** Values are language-independent: prefixes, entropy, hex
   length. Only the keyword alternation is language-bound, and it is data, not logic: a
   short table per language, kept in one place.

A local model would remove the first objection only, at the price of a runtime dependency
and the same non-determinism.

## Consequences

- Multilingual keywords, if ever needed, are added as data to the context and password
  patterns, with a test corpus per language.
- Any future probabilistic stage must run after the deterministic block, offline, on
  already-cleaned text, and must never see a value the deterministic stages missed by
  sending it off the machine.
