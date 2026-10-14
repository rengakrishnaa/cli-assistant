import unittest

from local_ai.classifier import classify, scan
from local_ai.models import Sensitivity as S
from local_ai.redactor import redact

FAKE_KEY = "sk_test_" + "localaidemokey01"


class ClassifierTests(unittest.TestCase):
    def test_credential_value_is_secret(self):
        result = classify(f"rotate {FAKE_KEY} today")
        self.assertEqual(result.tier, S.SECRET)
        self.assertIn("stripe_key", [f.rule for f in result.findings])

    def test_explanation_never_contains_matched_text(self):
        self.assertNotIn(FAKE_KEY, str(classify(f"key is {FAKE_KEY}").explain()))

    def test_health_context_is_personal_and_source_adds_confidential(self):
        result = classify("Patient diagnostics show elevated glucose", source="Internal Portal")
        self.assertEqual(result.tier, S.PERSONAL)
        self.assertIn(S.CONFIDENTIAL, result.tiers_detected)

    def test_roadmap_is_confidential(self):
        self.assertEqual(classify("Reviewed the Q2 marketing roadmap").tier, S.CONFIDENTIAL)

    def test_public_reference(self):
        self.assertEqual(classify("Read the MDN documentation on CORS").tier, S.PUBLIC)

    def test_unmatched_content_fails_closed(self):
        result = classify("lunch at noon")
        self.assertEqual(result.tier, S.PERSONAL)
        self.assertEqual(result.explain()["reasons"][0]["rule"], "fail_closed_default")


class RedactorTests(unittest.TestCase):
    def test_values_removed_and_output_rescans_clean(self):
        text = f"export AWS_SECRET_ACCESS_KEY=abcdef123456 and {FAKE_KEY}, mail a@b.com"
        out, count = redact(text)
        self.assertEqual(count, 3)
        for secret in ("abcdef123456", FAKE_KEY, "a@b.com"):
            self.assertNotIn(secret, out)
        self.assertEqual([f for f in scan(out) if f.kind == "value"], [])


if __name__ == "__main__":
    unittest.main()
