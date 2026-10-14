import unittest

from local_ai.config import Settings
from local_ai.egress import EgressDenied, build_cloud_request
from local_ai.models import Sensitivity as S
from local_ai.router import decide

FAKE_KEY = "sk_test_" + "localaidemokey01"
CLOUD_ON = Settings(cloud_ai_enabled=True)


class RouterTests(unittest.TestCase):
    def test_public_goes_to_cloud_when_enabled(self):
        self.assertEqual(decide("MDN docs on CORS", CLOUD_ON, inherited=[S.PUBLIC]).route, "cloud_ai")

    def test_personal_stays_local(self):
        self.assertEqual(decide("glucose reading", CLOUD_ON, inherited=[S.PERSONAL]).route, "local_ai")

    def test_cloud_disabled_means_local(self):
        self.assertEqual(decide("docs", Settings(), inherited=[S.PUBLIC]).route, "local_ai")

    def test_cloud_only_request_is_blocked_not_downgraded(self):
        decision = decide("x", CLOUD_ON, inherited=[S.PERSONAL], prefer="cloud")
        self.assertEqual(decision.route, "blocked")

    def test_leaked_credential_is_blocked_everywhere(self):
        decision = decide(f"key {FAKE_KEY}", CLOUD_ON, inherited=[S.PUBLIC])
        self.assertEqual(decision.route, "blocked")

    def test_injection_is_quarantined(self):
        decision = decide("docs", CLOUD_ON, inherited=[S.PUBLIC], flags=["prompt_injection_suspected"])
        self.assertEqual(decision.route, "local_ai")

    def test_consent_flag_allows_confidential(self):
        settings = Settings(cloud_ai_enabled=True, send_confidential_data_to_cloud=True)
        self.assertEqual(decide("roadmap", settings, inherited=[S.CONFIDENTIAL]).route, "cloud_ai")

    def test_decision_output_never_contains_payload(self):
        decision = decide("glucose reading 182", CLOUD_ON, inherited=[S.PERSONAL])
        self.assertNotIn("glucose", str(decision.to_dict()))


class EgressTests(unittest.TestCase):
    def test_only_cloud_verdicts_with_unchanged_payload_are_serialized(self):
        payload = "MDN docs on CORS"
        allowed = decide(payload, CLOUD_ON, inherited=[S.PUBLIC])
        self.assertIn(b"CORS", build_cloud_request(payload, allowed))
        with self.assertRaises(EgressDenied):
            build_cloud_request(payload, decide(payload, Settings(), inherited=[S.PUBLIC]))
        with self.assertRaises(EgressDenied):
            build_cloud_request(payload + " plus edits", allowed)


if __name__ == "__main__":
    unittest.main()
