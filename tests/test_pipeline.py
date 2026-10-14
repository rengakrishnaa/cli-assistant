import base64
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from local_ai.config import Paths, Settings
from local_ai.crypto import Cipher, KeyManager
from local_ai.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
PLAINTEXT_THAT_MUST_NOT_BE_ON_DISK = (
    b"localaidemokey01", b"wJalrXUtnFEMI", b"908-112-AC", b"Xk9#mQ2",
)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["LOCAL_AI_MASTER_KEY"] = base64.b64encode(os.urandom(32)).decode()
        self.paths = Paths(Path(self.tmp.name))
        self.pipe = Pipeline(self.paths, Settings(cloud_ai_enabled=True), Cipher(KeyManager().load()))
        self.report = self.pipe.ingest_file(ROOT / "mock_events.json")

    def tearDown(self):
        self.pipe.close()
        self.tmp.cleanup()

    def test_counts(self):
        r = self.report
        self.assertEqual((r.received, r.stored, r.dropped, r.invalid), (7, 6, 1, 0))

    def test_reingest_is_idempotent(self):
        again = self.pipe.ingest_file(ROOT / "mock_events.json")
        self.assertEqual((again.stored, again.duplicates), (0, 6))

    def test_no_plaintext_secret_on_disk(self):
        for name in ("vault.db", "memory.db"):
            for suffix in ("", "-wal"):
                path = self.paths.root / (name + suffix)
                if path.exists():
                    data = path.read_bytes()
                    for needle in PLAINTEXT_THAT_MUST_NOT_BE_ON_DISK:
                        self.assertNotIn(needle, data, f"{needle!r} found in {path.name}")

    def test_vault_round_trip(self):
        event_id = self.report.events[0]["event_id"]
        self.assertIn("Stripe", self.pipe.vault.get(event_id).content)

    def test_routes(self):
        routes = [e["route"] for e in self.report.events]
        self.assertEqual(routes.count("cloud_ai"), 1)
        flagged = [e for e in self.report.events if "prompt_injection_suspected" in e["flags"]]
        self.assertEqual([e["route"] for e in flagged], ["local_ai"])

    def test_search_ranks_stripe_first_and_routes_locally(self):
        hits, decision = self.pipe.search("Stripe pricing")
        self.assertIn("Stripe", hits[0][0].topics)
        self.assertEqual(decision.route, "local_ai")

    def test_forget_range_removes_both_layers(self):
        start = int(datetime(2026, 5, 19, 10, 0, tzinfo=timezone.utc).timestamp())
        end = int(datetime(2026, 5, 19, 11, 0, tzinfo=timezone.utc).timestamp())
        self.assertEqual(self.pipe.forget_range(start, end), (1, 1))
        self.assertEqual(self.pipe.search("Stripe")[0], [])


if __name__ == "__main__":
    unittest.main()
