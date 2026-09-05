"""Secret detection in free text.

Three stages, from most precise to broadest. A secret matched by one stage is replaced by
its placeholder before the next stage runs, so nothing is counted twice.

1. Known prefixes (sk-ant-, ghp_, AKIA, JWT...): maximum precision.
2. Assignment context (`api_key = ...`, `password: ...`): the name betrays the value.
3. Entropy: a long, mixed, dense string is a token, never prose. Pure hexadecimal (git SHA,
   docker digest, UUID) cannot reach the threshold, so it passes: a commit SHA in a prompt
   is a legitimate and frequent use. Inside a URL this stage reads the query string and the
   fragment, plus any path whose shape announces a credential; an ordinary path segment is a
   resource identifier and passes.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass

PREFIX_PATTERNS: tuple[tuple[str, str], ...] = (
    ("anthropic", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai", r"sk-proj-[A-Za-z0-9_\-]{20,}"),
    ("openrouter", r"sk-or-v1-[A-Za-z0-9]{32,}"),
    ("voyage", r"\bpa-[A-Za-z0-9_\-]{30,}"),
    ("github", r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    ("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{60,}"),
    ("aws", r"\bAKIA[0-9A-Z]{16}\b"),
    ("slack", r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    ("telegram", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{30,}"),
    ("postgres", r"postgres(?:ql)?://[^:\s]+:[^@\s]{6,}@[^\s]+"),
    ("resend", r"\bre_[A-Za-z0-9_]{20,}"),
    ("doppler", r"\bdp\.(?:ct|st|pt|sa)\.[A-Za-z0-9]{20,}"),
    ("stripe", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}"),
    ("google", r"\bAIza[A-Za-z0-9_\-]{35}\b"),
    ("huggingface", r"\bhf_[A-Za-z0-9]{30,}"),
    ("npm", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("sendgrid", r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    ("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
)

# A known prefix followed by a truncated key, a key wrapped by a line break (copied from a
# terminal that folds long lines), or a key polluted by an invisible character: block on
# the prefix alone and take the next line along when it looks like the rest of the key.
FRAGMENT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("anthropic", r"sk-ant-\S*(?:\n[A-Za-z0-9_\-]{8,})?"),
    ("openai", r"sk-proj-\S*(?:\n[A-Za-z0-9_\-]{8,})?"),
    ("openrouter", r"sk-or-v1-\S*(?:\n[A-Za-z0-9_\-]{8,})?"),
    ("github", r"\bgh[pousr]_\S*(?:\n[A-Za-z0-9_\-]{8,})?"),
    ("slack", r"\bxox[baprs]-\S*(?:\n[A-Za-z0-9_\-]{8,})?"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.\S*(?:\n[A-Za-z0-9_\-]{8,})?"),
)

# The separator and the value stay on the keyword's line: a `Password:` prompt followed by
# the next line of a terminal capture is not an assignment.
CONTEXT_PATTERN = re.compile(
    r"(?i)[A-Za-z0-9_\-]*(?:api[_-]?key|secret(?:[_-]?key)?|token|"
    r"auth(?:orization)?|bearer|credentials?)[\"']?[ \t]*[:=][ \t]*[\"']?"
    r"(?P<value>[^\s\"']{16,})"
)

# A password is short and readable: only the context gives it away, so the threshold drops.
PASSWORD_PATTERN = re.compile(
    r"(?i)[A-Za-z0-9_\-]*(?:password|passwd|passphrase|pwd)[\"']?[ \t]*[:=][ \t]*[\"']?"
    r"(?P<value>[^\s\"']{6,})"
)

# `curl -u user:pass`, `scheme://user:pass@host`: the identifier comes first, the secret follows.
INLINE_CREDENTIAL_PATTERNS: tuple[str, ...] = (
    r"(?:-u|--user)\s+[^\s:]+:(?P<value>[^\s]{4,})",
    r"[a-z][a-z0-9+.\-]*://[^:/\s@]+:(?P<value>[^@\s]{4,})@",
)

# What a URL carries belongs to whoever handed the URL out, never to the user who pastes it. The
# entropy stage therefore never reads inside a URL: only a positively identified secret does,
# through the prefix and userinfo stages, which run earlier.
URL_PATTERN = re.compile(
    r"""(?ix)
    \b[a-z][a-z0-9+.\-]*://[^\s"'<>`]+
    | \bwww\.[^\s"'<>`]+
    | \b[a-z0-9\-]+(?:\.[a-z0-9\-]+)+/[^\s"'<>`]+
    """
)
# A URL path that names what it carries: a webhook endpoint, an OAuth or callback route, a
# signed-link route. Everywhere else in a path, a long opaque block is a resource identifier.
URL_CREDENTIAL_MARKER = re.compile(
    r"(?i)/(?:hooks?|webhooks?|services|callbacks?|oauth|auth|tokens?|secrets?|keys?|"
    r"credentials?|signed|presigned|invites?)(?:/|$)"
)
GENERIC_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{32,}")
# Inside a URL, `/ ? # & =` are structure, never token content: a match that straddles them is
# cut back to the block that actually carries the entropy, so the placeholder replaces the
# secret and not the host tail or the path around it.
URL_SEPARATORS = re.compile(r"[/?#&=]")
LONG_HEX = re.compile(r"\b[0-9a-fA-F]{48,}\b")
DIGEST_PREFIX = re.compile(r"(?i)(?:sha\d*[:\-]|integrity\s+|md5[:\-])$")
# A path, a slug, a composite id: several short segments glued by separators. An opaque token
# keeps its randomness inside one block; splitting a URL path never yields a long random segment.
STRUCTURED_SEPARATORS = re.compile(r"[-_./]")
STRUCTURED_MIN_SEGMENTS = 3
STRUCTURED_MAX_SEGMENT = 20
ENTROPY_THRESHOLD = 4.5
PLACEHOLDER_PREFIX = "$OMP_"


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    name: str


def placeholder_name(kind: str, value: str) -> str:
    """Stable name: the same secret always yields the same name, so never a duplicate."""
    digest = hashlib.sha256(value.encode()).hexdigest()[:8].upper()
    return f"OMP_{kind.upper()}_{digest}"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_structured_identifier(candidate: str) -> bool:
    """`org/repo/actions/runs/1895`, `run-2026-08-27-build`: structure, not entropy.

    The mix of case and digits comes from the assembled segments, never from one of them. A real
    token concentrates its randomness in a single block, so at least one segment stays long.
    """
    segments = [segment for segment in STRUCTURED_SEPARATORS.split(candidate) if segment]
    if len(segments) < STRUCTURED_MIN_SEGMENTS:
        return False
    return all(len(segment) < STRUCTURED_MAX_SEGMENT for segment in segments)


def looks_like_token(candidate: str) -> bool:
    # Placeholders, paths and command-line option clusters (`-abcdefgh...`) are never tokens.
    if candidate.startswith(("OMP_", "/", "-")):
        return False
    if is_structured_identifier(candidate):
        return False
    has_lower = any(char.islower() for char in candidate)
    has_upper = any(char.isupper() for char in candidate)
    has_digit = any(char.isdigit() for char in candidate)
    if not (has_lower and has_upper and has_digit):
        return False
    return shannon_entropy(candidate) >= ENTROPY_THRESHOLD


def _record(findings: dict[str, Finding], kind: str, value: str) -> str:
    name = placeholder_name(kind, value)
    findings.setdefault(name, Finding(kind=kind, value=value, name=name))
    return PLACEHOLDER_PREFIX + name[len("OMP_"):]


def _preceded_by_digest_marker(text: str, start: int) -> bool:
    return DIGEST_PREFIX.search(text[max(0, start - 12):start]) is not None


def _apply_patterns(cleaned: str, findings: dict[str, Finding], patterns: tuple[tuple[str, str], ...]) -> str:
    for kind, pattern in patterns:
        for match in sorted(set(re.findall(pattern, cleaned)), key=len, reverse=True):
            if match.startswith("$OMP_") or PLACEHOLDER_PREFIX in match:
                continue
            cleaned = cleaned.replace(match, _record(findings, kind, match))
    return cleaned


def _apply_context(cleaned: str, findings: dict[str, Finding], pattern: re.Pattern[str], kind: str) -> str:
    for match in list(pattern.finditer(cleaned)):
        value = match.group("value")
        if value.startswith("OMP_") or value.startswith("$"):
            continue
        cleaned = cleaned.replace(value, _record(findings, kind, value))
    return cleaned


def _url_spans(text: str) -> list[tuple[int, int, str]]:
    return [(match.start(), match.end(), match.group(0)) for match in URL_PATTERN.finditer(text)]


def _is_shielded_url_path(spans: list[tuple[int, int, str]], position: int) -> bool:
    """A1 revised: an entropic block in a URL is read only where a credential can live.

    A webhook, a presigned link and an OAuth redirect all announce themselves: the value sits in
    the query string or the fragment, or the path names what it carries (`/services/`, `/hooks/`,
    `/oauth/`). An ordinary path segment is a resource identifier, and a document id from Google
    Docs, Notion or Dropbox has exactly the shape of an opaque token, so reading it there costs a
    blocked message on every shared link. The trade-off is stated in ADR-0011.
    """
    for start, end, url in spans:
        if not start <= position < end:
            continue
        boundaries = [index for index in (url.find("?"), url.find("#")) if index != -1]
        path_end = min(boundaries) if boundaries else len(url)
        if position - start >= path_end:
            return False
        return URL_CREDENTIAL_MARKER.search(url[:path_end]) is None
    return False


def _split_in_url(spans: list[tuple[int, int, str]], match: re.Match[str]) -> list[tuple[int, str]]:
    """Outside a URL the match stands whole; inside one it is cut on the URL's own separators.

    Cutting is confined to URLs because `/` and `=` are legitimate base64 content: a key whose
    encoding carries a slash must keep matching as one block anywhere else, or half of it drops
    under the 32-character floor and escapes.
    """
    candidate = match.group(0)
    if not any(start <= match.start() < end for start, end, _ in spans):
        return [(match.start(), candidate)]
    parts: list[tuple[int, str]] = []
    offset = 0
    for piece in URL_SEPARATORS.split(candidate):
        if len(piece) >= 32:
            parts.append((match.start() + offset, piece))
        offset += len(piece) + 1
    return parts


def _apply_entropy(cleaned: str, findings: dict[str, Finding]) -> str:
    # Decisions are read on the stage input, never on the text already being rewritten: a
    # replacement shifts every following offset, and both the digest marker and the URL span are
    # positional.
    source = cleaned
    spans = _url_spans(source)
    stages: tuple[tuple[re.Pattern[str], str], ...] = ((LONG_HEX, "hex"), (GENERIC_TOKEN, "token"))
    for pattern, kind in stages:
        matches = sorted(pattern.finditer(source), key=lambda found: -len(found.group(0)))
        for start, candidate in [part for match in matches for part in _split_in_url(spans, match)]:
            if kind == "token" and not looks_like_token(candidate):
                continue
            if _preceded_by_digest_marker(source, start):
                continue
            if _is_shielded_url_path(spans, start):
                continue
            cleaned = cleaned.replace(candidate, _record(findings, kind, candidate))
    return cleaned


def detect(text: str) -> tuple[str, list[Finding]]:
    """Return the cleaned text and the secrets found, in discovery order."""
    findings: dict[str, Finding] = {}
    cleaned = _apply_patterns(text, findings, PREFIX_PATTERNS)
    cleaned = _apply_patterns(cleaned, findings, FRAGMENT_PATTERNS)
    cleaned = _apply_context(cleaned, findings, CONTEXT_PATTERN, "credential")
    cleaned = _apply_context(cleaned, findings, PASSWORD_PATTERN, "password")
    for pattern in INLINE_CREDENTIAL_PATTERNS:
        cleaned = _apply_context(cleaned, findings, re.compile(pattern), "password")
    cleaned = _apply_entropy(cleaned, findings)
    return cleaned, list(findings.values())
