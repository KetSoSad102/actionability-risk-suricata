import argparse
import csv
import json
from pathlib import Path
import tempfile
import unittest

from as_engine.experiment import _validate_figure_file, run_experiment


ROOT = Path(__file__).resolve().parents[1]


class ControlledExperimentTests(unittest.TestCase):
    def test_generated_figure_validation_rejects_empty_and_invalid_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "figure.pdf"
            path.write_bytes(b"")
            with self.assertRaises(OSError):
                _validate_figure_file(path, "pdf")
            path.write_bytes(b"not-a-pdf")
            with self.assertRaises(OSError):
                _validate_figure_file(path, "pdf")
            path.write_bytes(b"%PDF-1.4\nminimal-test-fixture")
            _validate_figure_file(path, "pdf")

    def test_two_factor_design_and_expected_score_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                eve=str(ROOT / "logs/suricata/eve.json"),
                rules=str(ROOT / "rules/rule_metadata.yaml"),
                scoring=str(ROOT / "config/scoring-v2.yaml"),
                variants=str(ROOT / "config/controlled_variants.yaml"),
                contexts=str(ROOT / "config/context_variants.yaml"),
                profile=None,
                output_dir=directory,
                annotation_target=300,
                annotation_seed=2026,
                ratings_per_item=3,
                no_figures=True,
            )
            summary = run_experiment(args)
            with (Path(directory) / "controlled_cases.jsonl").open(encoding="utf-8") as handle:
                records = [json.loads(line) for line in handle]
            with (Path(directory) / "sensitivity.csv").open(encoding="utf-8") as handle:
                sensitivity_rows = list(csv.DictReader(handle))
            with (Path(directory) / "annotation/annotation_items.jsonl").open(encoding="utf-8") as handle:
                annotation_items = [json.loads(line) for line in handle]
            with (Path(directory) / "annotation/annotation_responses_template.csv").open(encoding="utf-8") as handle:
                response_rows = list(csv.DictReader(handle))

        self.assertEqual(summary["profiles"]["primary"], "proposed_default")
        self.assertEqual(summary["design"]["observed_seed_count"], 10)
        self.assertEqual(summary["design"]["base_archetype_count"], 10)
        self.assertEqual(summary["design"]["outcome_context_count"], 5)
        self.assertEqual(summary["design"]["base_context_vignette_count"], 50)
        self.assertEqual(summary["design"]["evidence_profile_count"], 10)
        self.assertEqual(summary["design"]["presentation_count"], 500)
        self.assertEqual(len(records), 500)
        self.assertEqual(len(annotation_items), 300)
        self.assertEqual(len(response_rows), 900)
        self.assertNotIn("actionability_score", annotation_items[0])
        self.assertNotIn("evidence_profile", annotation_items[0])

        dlink = {
            (record["experiment"]["context"], record["experiment"]["evidence_profile"]): record
            for record in records
            if record["experiment"]["base_sid"] == 2025756
        }
        self.assertGreater(
            dlink[("observed", "complete")]["actionability_score"],
            dlink[("observed", "observed")]["actionability_score"],
        )
        self.assertGreater(
            dlink[("observed", "complete")]["actionability_score"],
            dlink[("observed", "no_http_context")]["actionability_score"],
        )
        self.assertEqual(
            dlink[("rejected_403", "complete")]["outcome_class"],
            "failure_evidenced",
        )
        self.assertEqual(
            dlink[("success_marker_200", "complete")]["outcome_class"],
            "success_evidenced",
        )
        self.assertEqual(
            dlink[("failure_marker_200", "complete")]["outcome_class"],
            "failure_evidenced",
        )
        self.assertLess(
            dlink[("rejected_403", "complete")]["risk_score"],
            dlink[("success_marker_200", "complete")]["risk_score"],
        )
        unknown = dlink[("observed", "unknown_metadata")]
        self.assertEqual(unknown["rule_match_quality"], "withheld_metadata")
        self.assertGreater(
            dlink[("observed", "complete")]["experiment"]["field_presence_baseline"],
            unknown["experiment"]["field_presence_baseline"],
        )
        self.assertEqual(len(summary["ablation"]), 7)
        self.assertTrue(all(row["mean_score_drop"] > 0 for row in summary["ablation"]))
        self.assertEqual(set(summary["comparator_results"]), {"equal_weight", "field_presence"})
        self.assertEqual(len(sensitivity_rows), 30)


if __name__ == "__main__":
    unittest.main()
