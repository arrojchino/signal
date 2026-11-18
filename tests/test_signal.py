import json
import tempfile
import unittest
from pathlib import Path

import signal as sig


class SignalTests(unittest.TestCase):
    def setUp(self):
        self.rules = sig.load_rules(Path("rules.json"))

    def test_fingerprint_is_stable_and_order_independent(self):
        a = {"Application Name": "app", "Severity": "High", "CWE ID": "CWE-89", "Flaw Name": "SQLi", "Filename/Class": "a.py", "Finding Status": "open"}
        b = dict(reversed(list(a.items())))
        self.assertEqual(sig.fingerprint(a), sig.fingerprint(b))
        self.assertEqual(len(sig.fingerprint(a)), 16)

    def test_ingest_normalizes_and_counts(self):
        with tempfile.TemporaryDirectory() as d:
            csv = Path(d) / "f.csv"
            csv.write_text("Application,Severity,CWE,Flaw Name,Filename,Status\napp,High,CWE-89,SQLi,a.py,open\napp,Low,CWE-200,Info,b.py,open\n", encoding="utf-8")
            store = sig.ingest(csv, self.rules)
            self.assertEqual(store["counts"], {"High": 1, "Low": 1})
            self.assertEqual(store["verification"], {"unverified": 2})
            self.assertEqual(store["findings"][0]["Fingerprint"], sig.fingerprint(store["findings"][0]))

    def test_verify_adds_hashed_evidence_and_state(self):
        row = {"Application": "app", "Severity": "High", "CWE": "CWE-89", "Flaw Name": "SQLi", "Filename": "a.py", "Status": "open"}
        store = sig.envelope([sig.normalize(row, self.rules)], self.rules)
        with tempfile.TemporaryDirectory() as d:
            ev = Path(d) / "proof.txt"
            ev.write_text("proof", encoding="utf-8")
            out = sig.verify(store, store["findings"][0]["Fingerprint"], "confirmed", ev)
            self.assertEqual(out["verification"], {"confirmed": 1})
            self.assertEqual(len(out["findings"][0]["Evidence"]), 1)
            self.assertEqual(out["findings"][0]["Evidence"][0]["sha256"], sig.hashlib.sha256(b"proof").hexdigest())

    def test_report_is_self_contained(self):
        row = {"Application": "app", "Severity": "High", "CWE": "CWE-89", "Flaw Name": "SQLi", "Filename": "a.py", "Status": "open"}
        html = sig.render_html(sig.envelope([sig.normalize(row, self.rules)], self.rules))
        self.assertIn("<style>", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertIn("SQLi", html)
        self.assertIn("open_proof_gap", html)

    def test_sarif_contract(self):
        row = {"Application": "app", "Severity": "High", "CWE": "CWE-89", "Flaw Name": "SQLi", "Filename": "a.py", "Status": "open"}
        doc = json.loads(sig.render_sarif(sig.envelope([sig.normalize(row, self.rules)], self.rules)))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"]), 1)
        result = doc["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "CWE-89")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["partialFingerprints"]["signal/v1"], sig.fingerprint(sig.normalize(row, self.rules)))


if __name__ == "__main__":
    unittest.main()
