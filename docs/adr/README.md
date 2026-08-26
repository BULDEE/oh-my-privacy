# Architecture Decision Records

| ADR | Decision |
|---|---|
| [0001](0001-block-never-mask.md) | Block the message, never mask it in flight |
| [0002](0002-write-only-adapters.md) | Vault adapters are write-only |
| [0003](0003-three-storage-levels.md) | Three storage levels, discard by default, age recommended on workstations |
| [0004](0004-history-scrub-by-redetection.md) | Scrub the prompt history by re-detection, never by passing values |
| [0005](0005-managed-settings-installation.md) | Tamper resistance through Claude Code managed settings |
| [0006](0006-allowlist-tool-guard.md) | The PreToolUse guard is an allowlist for vault CLIs |
| [0007](0007-hermes-native-plugin.md) | Hermes integration through a native plugin, not the portable package |
| [0008](0008-accidental-leak-threat-model.md) | The threat model is the accidental leak, not the adversarial user |
| [0009](0009-deterministic-detection-no-llm-classifier.md) | Detection stays deterministic; no LLM classifier in the blocking path |
| [0010](0010-agent-side-masking.md) | Mask what the agent reads, not only what the user types |

Format: context, decision, consequences. A superseded record keeps its file and gains a
`Status: superseded by ADR-XXXX` line.
