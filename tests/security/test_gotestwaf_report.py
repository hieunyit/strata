import csv
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import gotestwaf_report as g  # noqa: E402


def report(tp=91.25, tn=100.0):
    return {
        "score": 87.17,
        "summary": {
            "true_positive_tests": {"score": tp, "summary": {"blocked_tests": 615, "resolved_tests": 674}},
            "true_negative_tests": {"score": tn, "summary": {"blocked_tests": 0, "resolved_tests": 141}},
        },
        "rows": [
            {"payload": "PGltZyBzcmM9eD4", "test_set": "owasp", "test_case": "xss-scripting",
             "encoder": "Base64Flat", "placeholder": "URLPath"},
            {"payload": "%28alert%29%281%29", "test_set": "owasp", "test_case": "xss-scripting",
             "encoder": "URL", "placeholder": "URLParam"},
            {"payload": "%28alert%29%281%29", "test_set": "owasp", "test_case": "xss-scripting",
             "encoder": "URL", "placeholder": "URLParam"},
            {"payload": "x", "test_set": "owasp", "test_case": "rce",
             "encoder": "Plain", "placeholder": "Header"},
            {"payload": "!!!", "test_set": "owasp", "test_case": "rce",
             "encoder": "Base64Flat", "placeholder": "HTMLForm"},
        ],
    }


class Test(unittest.TestCase):
    def run_main(self, rep, *args):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            rows = rep.pop("rows")
            with open(p, "w") as f:
                json.dump(rep, f)
            cp = os.path.join(d, "r.csv")
            with open(cp, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Payload", "Check Status", "Response Code", "Placeholder", "Encoder", "Set", "Case", "Test Result"])
                for r in rows:
                    w.writerow([r["payload"], "passed", 200, r["placeholder"], r["encoder"], r["test_set"], r["test_case"], "failed"])
                # a blocked one and a true-negative one are not candidates
                w.writerow(["<script>", "blocked", 403, "URLParam", "Plain", "owasp", "xss-scripting", "passed"])
                w.writerow(["hello", "passed", 200, "URLParam", "Plain", "false-pos", "texts", "passed"])
            c = os.path.join(d, "c.jsonl")
            rc = g.main([p, "--csv", cp, "--candidates", c, *args])
            with open(c) as f:
                rows = [json.loads(l) for l in f]
        return rc, rows

    def test_candidates_decoded_deduplicated_known_carriers_only(self):
        rc, rows = self.run_main(report())
        self.assertEqual(rc, 0)
        self.assertEqual(
            [(r["payload"], r["carrier"], r["encoding"]) for r in rows],
            [("<img src=x>", "path", "base64url"), ("(alert)(1)", "query", "")],
        )

    def test_thresholds(self):
        self.assertEqual(self.run_main(report(), "--min-tp", "91", "--min-tn", "100")[0], 0)
        self.assertEqual(self.run_main(report(tp=90.0), "--min-tp", "91")[0], 1)
        self.assertEqual(self.run_main(report(tn=99.29), "--min-tn", "100")[0], 1)


if __name__ == "__main__":
    unittest.main()
