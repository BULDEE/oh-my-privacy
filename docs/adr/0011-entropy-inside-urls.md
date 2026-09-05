# ADR-0011: Inside a URL, entropy is read where a credential can live

Status: accepted (2026-09-05)

Supersedes the A1 revision of 2026-08-30, which removed the URL carve-out from the entropy
stage entirely.

## Context

A1 removed the old carve-out so that a secret carried by a URL, a Slack or Discord webhook,
a presigned S3 link, would still be inspected. The carve-out was too wide and A1 was right
to close it.

It was also too wide in the other direction. A document id from Google Docs, Notion or
Dropbox has exactly the shape of an opaque token: 32 to 60 characters, mixed case and
digits, Shannon entropy above the 4.5 threshold. `is_structured_identifier` cannot spare it
either, since the id is a single segment far longer than `STRUCTURED_MAX_SEGMENT`. Sharing a
document link with the agent, one of the most frequent things a user does, therefore blocked
the message. Reported 2026-09-05 on a `docs.google.com` link.

Entropy alone cannot separate the two: a link-shared document id and a capability token are
the same object measured that way. What separates them is position.

## Decision

The entropy stage reads a URL only where a credential can live.

- The query string and the fragment are always read: `?X-Amz-Signature=`, `#access_token=`.
- A path is read when it names what it carries: `/hooks/`, `/webhooks/`, `/services/`,
  `/oauth/`, `/callback/`, `/token/`, `/secret/`, `/key/`, `/credentials/`, `/signed/`,
  `/presigned/`, `/invite/` (`URL_CREDENTIAL_MARKER`).
- Any other path segment is a resource identifier and passes.

Prefix, fragment, context and inline-credential stages are unchanged: they run before this
one and keep reading the whole string, so a vendor-prefixed key or a `token=` assignment
inside a URL is still caught wherever it sits.

Within a URL, a match is also cut on `/ ? # & =` before being masked, so the placeholder
replaces the secret and not the host tail around it. The cut is confined to URLs: `/` and
`=` are legitimate base64 content, and cutting there in free text would drop each half of an
encoded 32-byte key under the 32-character floor.

## Consequences

- A presigned or capability link whose path carries no marker, `https://storage.test/download/<opaque>`,
  passes. This is the accepted cost, stated plainly: precision on shared document links is
  worth more than coverage of an unmarked capability URL, per the ADR-0008 threat model where
  the user is the party being protected and a false positive blocks the whole message.
- `URL_CREDENTIAL_MARKER` is the lever to widen coverage. A new marker costs one regex term
  and must come with a case in `EntropyPatterns`.
- A base64 blob containing `/` inside a query string, with no keyword naming it, is cut and
  can fall under the floor. `CONTEXT_PATTERN` covers the named forms, which is every query
  parameter a real service emits.
