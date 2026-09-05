from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from omp.detect import detect, is_structured_identifier, looks_like_token, placeholder_name  # noqa: E402

FAKE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaXNzIjoibjhuIn0.FAKEsignature_abcdefghijklmnopqrst"
FAKE_ANTHROPIC = "sk-ant-api03-FAKEKEYFORTESTINGONLY0000000000"
FAKE_HEX64 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
FAKE_OPAQUE = "Qm7xR2vLk9PzT4wN8yH3sB6cF1dJ5gA0eU2iO7pM4nK9lW3zX6vC8bH1tY5rE2qD"


class PrefixPatterns(unittest.TestCase):
    def test_jwt_is_detected(self) -> None:
        cleaned, findings = detect(f"here is the key: {FAKE_JWT}")
        self.assertEqual([finding.kind for finding in findings], ["jwt"])
        self.assertNotIn(FAKE_JWT, cleaned)
        self.assertIn("$OMP_JWT_", cleaned)

    def test_anthropic_is_detected(self) -> None:
        cleaned, findings = detect(f"my key {FAKE_ANTHROPIC} there")
        self.assertEqual(findings[0].kind, "anthropic")
        self.assertEqual(cleaned, f"my key ${findings[0].name} there")

    def test_private_key_block_is_detected_whole(self) -> None:
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----"
        cleaned, findings = detect(f"ssh key:\n{pem}\nend")
        self.assertEqual(findings[0].kind, "private_key")
        self.assertNotIn("AAAA", cleaned)

    def test_same_secret_twice_yields_one_finding(self) -> None:
        cleaned, findings = detect(f"{FAKE_ANTHROPIC} and again {FAKE_ANTHROPIC}")
        self.assertEqual(len(findings), 1)
        self.assertEqual(cleaned.count("$OMP_ANTHROPIC_"), 2)

    def test_placeholder_is_stable(self) -> None:
        self.assertEqual(placeholder_name("jwt", FAKE_JWT), placeholder_name("jwt", FAKE_JWT))
        self.assertNotEqual(placeholder_name("jwt", FAKE_JWT), placeholder_name("jwt", FAKE_JWT + "x"))


class ContextPatterns(unittest.TestCase):
    def test_assignment_context_is_detected(self) -> None:
        cleaned, findings = detect("MAIL_MCP_TOKEN=abcdefghij1234567890ABCDEF")
        self.assertEqual(findings[0].kind, "credential")
        self.assertNotIn("abcdefghij1234567890ABCDEF", cleaned)

    def test_yaml_password_is_detected(self) -> None:
        _, findings = detect("password: SuperSecretPassw0rdValue")
        self.assertEqual(len(findings), 1)

    def test_env_reference_is_not_a_secret(self) -> None:
        _, findings = detect('"Authorization": "Bearer ${MAIL_MCP_TOKEN}"')
        self.assertEqual(findings, [])

    def test_placeholder_is_not_re_detected(self) -> None:
        _, findings = detect("token = $OMP_JWT_B5352DF5 then doppler")
        self.assertEqual(findings, [])


class EntropyPatterns(unittest.TestCase):
    def test_opaque_token_is_detected(self) -> None:
        cleaned, findings = detect(f"the token is {FAKE_OPAQUE} thanks")
        self.assertEqual(findings[0].kind, "token")
        self.assertNotIn(FAKE_OPAQUE, cleaned)

    def test_git_sha_passes(self) -> None:
        _, findings = detect(f"look at commit {FAKE_HEX64[:40]}")
        self.assertEqual(findings, [])

    def test_sha256_git_object_is_flagged_by_design(self) -> None:
        """A 64-char hex without a digest marker looks more like a token than a still-rare SHA-256 git object."""
        _, findings = detect(f"look at commit {FAKE_HEX64}")
        self.assertEqual([finding.kind for finding in findings], ["hex"])

    def test_uuid_passes(self) -> None:
        _, findings = detect("session c68249d0-4412-4ad1-ae4b-1cef5c097833 opened")
        self.assertEqual(findings, [])

    def test_project_slug_passes(self) -> None:
        _, findings = detect("file /Users/dev/.claude/projects/-Users-dev-Dev-acme-stack-infra-scripts/cad86bcf.jsonl")
        self.assertEqual(findings, [])

    def test_github_actions_url_passes(self) -> None:
        _, findings = detect("regarde https://github.com/BULDEE/ai-craftsman-superpowers/actions/runs/18952661234/job/54123456789?pr=29")
        self.assertEqual(findings, [])

    def test_deep_url_path_passes(self) -> None:
        for text in (
            "https://console.cloud.google.com/logs/query/projectXY/runs/2026-08-27T10/entries/AbCd12",
            "https://app.example.io/orgs/Acme42/workspaces/Prod9/pipelines/Build77/runs/1234567",
        ):
            _, findings = detect(text)
            self.assertEqual(findings, [], text)

    def test_composite_identifier_passes(self) -> None:
        for text in (
            "job run-2026-08-27-BULDEE-build-4210 failed",
            "bucket s3://acme-prod-eu-west-1/exports/Report2026/final-V2.csv",
        ):
            _, findings = detect(text)
            self.assertEqual(findings, [], text)

    def test_credential_shaped_url_is_still_inspected(self) -> None:
        """A1 revised (ADR-0011): a URL is read where a credential can live, which is the query
        string, the fragment, and a path that names what it carries."""
        for text in (
            f"https://hooks.slack.test/services/T00/B00/{FAKE_OPAQUE}",
            f"https://discord.test/api/webhooks/1234567890/{FAKE_OPAQUE}",
            f"https://bucket.s3.test/report.pdf?X-Amz-Signature={FAKE_OPAQUE}",
            f"https://app.test/callback#access_token={FAKE_OPAQUE}",
        ):
            _, findings = detect(text)
            self.assertTrue(findings, text)

    def test_document_id_in_a_url_path_passes(self) -> None:
        """ADR-0011: a shared document link is the highest-frequency false positive of the entropy
        stage, and an ordinary path segment carries a resource id, not a credential."""
        for text in (
            "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit",
            "https://www.notion.so/team/Page-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2",
            f"https://example.test/download/{FAKE_OPAQUE}",
        ):
            _, findings = detect(text)
            self.assertEqual(findings, [], text)

    def test_url_structure_survives_the_mask(self) -> None:
        """The placeholder replaces the secret alone: `/` and `=` are URL structure, so a match that
        straddles them is cut back before it swallows the host tail or the path."""
        cleaned, findings = detect(f"https://hooks.slack.test/services/T00/B00/{FAKE_OPAQUE}")
        self.assertEqual([finding.value for finding in findings], [FAKE_OPAQUE])
        self.assertTrue(cleaned.startswith("https://hooks.slack.test/services/T00/B00/"), cleaned)

    def test_base64_secret_with_a_slash_stays_one_block(self) -> None:
        """Outside a URL, `/` is base64 content: cutting there would drop each half under the
        32-character floor and let half of all encoded 32-byte keys through."""
        secret = "aB3/dE5+fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7b="
        cleaned, findings = detect(f"key {secret}")
        self.assertEqual([finding.value for finding in findings], [secret])
        self.assertNotIn(secret, cleaned)

    def test_entropy_outside_the_url_is_still_detected(self) -> None:
        _, findings = detect(f"https://example.test/docs then paste {FAKE_OPAQUE}")
        self.assertEqual([finding.kind for finding in findings], ["token"])

    def test_known_prefix_inside_a_url_is_still_detected(self) -> None:
        cleaned, findings = detect(f"curl 'https://api.test/x?key={FAKE_ANTHROPIC}'")
        self.assertEqual([finding.kind for finding in findings], ["anthropic"])
        self.assertNotIn(FAKE_ANTHROPIC, cleaned)

    def test_prose_passes(self) -> None:
        _, findings = detect("explain the repository pattern and show a PHP example with sk-ant short")
        self.assertEqual(findings, [])

    def test_structured_identifier_is_not_a_token(self) -> None:
        self.assertTrue(is_structured_identifier("com/BULDEE/ai-craftsman-superpowers/actions/runs/18952661234"))
        self.assertFalse(is_structured_identifier(FAKE_OPAQUE))

    def test_looks_like_token_requires_mixed_classes(self) -> None:
        self.assertFalse(looks_like_token("a" * 40))
        self.assertFalse(looks_like_token("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"))
        self.assertTrue(looks_like_token(FAKE_OPAQUE))


class AccidentalShapes(unittest.TestCase):
    """Shapes a user produces without meaning to: wrapped copy, invisible character, short password."""

    def test_key_wrapped_on_two_lines_is_taken_whole(self) -> None:
        cleaned, findings = detect(f"key {FAKE_ANTHROPIC[:20]}\n{FAKE_ANTHROPIC[20:]}")
        self.assertEqual(findings[0].kind, "anthropic")
        self.assertNotIn(FAKE_ANTHROPIC[20:], cleaned)

    def test_zero_width_space_does_not_hide_the_key(self) -> None:
        cleaned, findings = detect(f"key {FAKE_ANTHROPIC[:20]}​{FAKE_ANTHROPIC[20:]}")
        self.assertEqual(len(findings), 1)
        self.assertNotIn(FAKE_ANTHROPIC[20:], cleaned)

    def test_short_password_with_context(self) -> None:
        for text in ("password: hunter2", "passphrase = Sunflower26", "PWD=abc123"):
            _, findings = detect(text)
            self.assertEqual([finding.kind for finding in findings], ["password"], text)

    def test_curl_basic_auth(self) -> None:
        cleaned, findings = detect("curl -u alexandre:MyPassw0rd2026! https://x.test")
        self.assertEqual(findings[0].kind, "password")
        self.assertNotIn("MyPassw0rd2026!", cleaned)
        self.assertIn("alexandre:", cleaned)

    def test_url_embedded_credentials_any_scheme(self) -> None:
        cleaned, findings = detect("redis://default:s3cretPassw0rd@redis.internal:6379")
        self.assertEqual(len(findings), 1)
        self.assertNotIn("s3cretPassw0rd", cleaned)

    def test_long_hex_without_context_is_a_secret(self) -> None:
        _, findings = detect(f"paste this in the provider console {FAKE_HEX64}")
        self.assertEqual(findings[0].kind, "hex")

    def test_hex_with_digest_marker_passes(self) -> None:
        for text in (f"FROM python@sha256:{FAKE_HEX64}", f"sha256-{FAKE_HEX64}"):
            _, findings = detect(text)
            self.assertEqual(findings, [], text)

    def test_npm_integrity_hash_passes(self) -> None:
        _, findings = detect("integrity sha512-WBYwq+0yGmp/Tj6ZzqR0JZG5jH1kN3Z6L0nVfR2Q3g==")
        self.assertEqual(findings, [])

    def test_git_sha_still_passes(self) -> None:
        _, findings = detect("git show 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b")
        self.assertEqual(findings, [])


class TerminalCaptures(unittest.TestCase):
    """A pasted terminal session is prose with prompts in it, not a list of assignments."""

    def test_sudo_password_prompt_followed_by_next_line_passes(self) -> None:
        _, findings = detect("Password:\nrsync: unrecognized option `--chown=root:wheel'")
        self.assertEqual(findings, [])

    def test_password_prompt_with_value_on_the_same_line_is_detected(self) -> None:
        _, findings = detect("Password: hunter22")
        self.assertEqual([finding.kind for finding in findings], ["password"])

    def test_option_cluster_in_a_usage_line_passes(self) -> None:
        _, findings = detect("usage: rsync [-abcdeghlnopqrtuvxzCDEHILNOPSWX0123456789] [-e program]")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
