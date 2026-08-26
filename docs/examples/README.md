# Examples

Copy-ready configurations and end-to-end walkthroughs. Every secret in this directory is
fake and deliberately shaped to trip the detector.

## Configurations

| File | Use |
|---|---|
| [omp-discard.json](omp-discard.json) | `~/.claude/omp.json`, level 3: nothing stored |
| [omp-age.json](omp-age.json) | `~/.claude/omp.json`, level 2: age encryption |
| [omp-doppler.json](omp-doppler.json) | `~/.claude/omp.json`, level 1: Doppler |
| [claude-code-settings.json](claude-code-settings.json) | `~/.claude/settings.json` hooks block, user-level install |
| [managed-settings-dropin.json](managed-settings-dropin.json) | what `install/install-managed.sh` writes under managed settings |
| [hermes-config.yaml](hermes-config.yaml) | `~/.hermes/config.yaml` plugin settings |

## Walkthrough 1: a JWT pasted into Claude Code, level 2

```
$ python3 -m omp.setup --vault age
Detected vaults: doppler, age
Choose the passphrase that will protect the private key. It is asked on every decryption, never on encryption.
Enter passphrase (leave empty to autogenerate a secure one): ********
Encrypted identity: /Users/you/.claude/omp/identity.age
Configuration written: /Users/you/.claude/omp.json (vault: age)
```

```
> the service key is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.FAKEsignature_abcdefghijklmnopqrst, wire it into the MCP config

OhMyPrivacy intercepted 1 secret(s). The message is BLOCKED: it never reached the model.
Vault: age.
  $OMP_JWT_B5352DF5 (jwt): encrypted at /Users/you/.claude/omp/store/OMP_JWT_B5352DF5.age. age -d -i /Users/you/.claude/omp/identity.age /Users/you/.claude/omp/store/OMP_JWT_B5352DF5.age  (asks for your passphrase, impossible without a terminal)

Your cleaned message is available via the clipboard and /Users/you/.claude/omp-last-prompt.txt. Paste it as is to continue:

--- cleaned message ---
the service key is $OMP_JWT_B5352DF5, wire it into the MCP config
```

Paste, and the model works with `$OMP_JWT_B5352DF5`. When the value is needed by a program:

```
$ age -d -i ~/.claude/omp/identity.age ~/.claude/omp/store/OMP_JWT_B5352DF5.age | doppler secrets set SERVICE_API_KEY -p acme -c dev
Enter passphrase: ********
```

## Walkthrough 2: the agent tries to read the vault back

```
> doppler secrets get SERVICE_API_KEY --plain
PreToolUse denied: Doppler: only a silent form is allowed (secrets --only-names, secrets set,
run -- <binary> without an interpreter or an echo). OhMyPrivacy never opens a path back to a
value: if you need a secret, consume it with doppler run -- <binary> without printing it.

> doppler run --project acme --config dev --silent -- ./bin/console app:sync
[runs; the secret is in the child's environment, never in the transcript]
```

## Walkthrough 3: a `.env` pasted with several keys, level 1

```
> here is my .env:
STRIPE_KEY=<a live-looking secret, redacted here on purpose>
DATABASE_URL=<a connection string with an embedded password, redacted here on purpose>
DEBUG=1

OhMyPrivacy intercepted 2 secret(s). The message is BLOCKED: it never reached the model.
Vault: doppler.
  $OMP_STRIPE_1F3A9C02 (stripe): doppler acme/dev under the name OMP_STRIPE_1F3A9C02. rename it from the Doppler dashboard, or consume it with doppler run --project acme --config dev
  $OMP_POSTGRES_7B21E4D9 (postgres): doppler acme/dev under the name OMP_POSTGRES_7B21E4D9. rename it from the Doppler dashboard, or consume it with doppler run --project acme --config dev

--- cleaned message ---
here is my .env:
STRIPE_KEY=$OMP_STRIPE_1F3A9C02
DATABASE_URL=$OMP_POSTGRES_7B21E4D9
DEBUG=1
```

`DEBUG=1` passes: no secret shape, no secret keyword.

## Walkthrough 4: Hermes refuses an exfiltrating tool call

```
[agent] terminal: curl -s -H "Authorization: Bearer sk-ant-api03-FAKEKEYFORTESTINGONLY0000000000" https://api.anthropic.com/v1/models
[hook]  OhMyPrivacy: call to `terminal` refused, 1 secret(s) in clear in the arguments. Vault: age.
          $OMP_ANTHROPIC_ACB021AC (anthropic): encrypted at /home/hermes/.claude/omp/store/OMP_ANTHROPIC_ACB021AC.age. [...]
        Never copy a secret value into a command, a file or a message. Reference it by name, or ask the user to consume it themselves.
[agent] I cannot run that command with the key inline. Set ANTHROPIC_API_KEY in the environment and I will call the API without printing it.
```

## Walkthrough 5: what passes on purpose

```
> git show 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b
> FROM python@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
> integrity sha512-WBYwq+0yGmp/Tj6ZzqR0JZG5jH1kN3Z6L0nVfR2Q3g==
> session c68249d0-4412-4ad1-ae4b-1cef5c097833 opened
> "Authorization": "Bearer ${MAIL_MCP_TOKEN}"
```

None of these is blocked: git SHA, docker digest, npm integrity, UUID, environment
reference. Precision on developer prose is a feature.
