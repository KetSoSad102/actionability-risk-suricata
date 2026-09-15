import unittest

from as_engine.annotation_analysis import analyze_annotations


class AnnotationAnalysisTests(unittest.TestCase):
    def test_completed_ratings_produce_agreement_and_grouped_metrics(self) -> None:
        key_rows = []
        response_rows = []
        for index, (score, rating, label) in enumerate(
            [
                (0.10, 1, "non_actionable"),
                (0.30, 2, "non_actionable"),
                (0.80, 4, "actionable"),
                (0.95, 5, "actionable"),
            ]
        ):
            item_id = f"item-{index}"
            key_rows.append(
                {
                    "item_id": item_id,
                    "seed_id": f"seed-{index % 2}",
                    "automated_actionability_score": str(score),
                    "equal_weight_actionability": str(score),
                    "field_presence_baseline": str(score),
                }
            )
            for slot in range(3):
                response_rows.append(
                    {
                        "item_id": item_id,
                        "actionability_likert_1_5": str(rating),
                        "actionability_class": label,
                        "understands_event_1_5": str(rating),
                        "understands_outcome_1_5": str(rating),
                        "knows_next_action_1_5": str(rating),
                        "additional_pivot_required": "no" if label == "actionable" else "yes",
                        "confidence_1_5": str(rating),
                        "decision_seconds": str(60 - rating * 5),
                    }
                )

        result = analyze_annotations(
            key_rows,
            response_rows,
            minimum_ratings=3,
            bootstrap_repetitions=20,
            seed=7,
        )
        self.assertEqual(result["item_count"], 4)
        self.assertEqual(result["rating_count"], 12)
        self.assertEqual(result["agreement"]["krippendorff_alpha_ordinal"], 1.0)
        self.assertEqual(result["agreement"]["fleiss_kappa_actionability_class"], 1.0)
        self.assertEqual(
            result["binary_actionability"]["auprc"]["proposed_default"]["estimate"],
            1.0,
        )
        self.assertEqual(
            result["criterion_associations"]["actionability_likert"]["cluster"],
            "seed_id",
        )


if __name__ == "__main__":
    unittest.main()
