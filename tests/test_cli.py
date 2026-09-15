import argparse
import csv
from pathlib import Path
import tempfile
import unittest

from as_engine.cli import run
from as_engine.validation import validate_scores


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_bundled_eve_end_to_end_and_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            args = argparse.Namespace(
                eve=str(ROOT / "logs/suricata/eve.json"),
                rules=str(ROOT / "rules/rule_metadata.yaml"),
                scoring=str(ROOT / "config/scoring-v2.yaml"),
                profile=None,
                out_jsonl=str(output / "scores.jsonl"),
                out_csv=str(output / "scores.csv"),
                out_summary=str(output / "summary.json"),
                fail_on_malformed=True,
            )
            summary = run(args)
            errors = validate_scores(
                args.out_csv, str(ROOT / "config/ground_truth.yaml")
            )
            with open(args.out_csv, encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(summary["alert_count"], 10)
        self.assertEqual(summary["rule_matches"], {"exact": 10})
        self.assertEqual(errors, [])
        union_alert = next(row for row in rows if row["sid"] == "2006448")
        self.assertEqual(union_alert["packet_src_ip"], "10.0.0.20")
        self.assertEqual(union_alert["attacker_candidate"], "203.0.113.10")
        self.assertEqual(union_alert["alert_direction"], "to_client")


if __name__ == "__main__":
    unittest.main()
