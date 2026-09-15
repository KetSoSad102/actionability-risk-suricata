import json
from pathlib import Path
import unittest

from as_engine.annotation import balanced_sample


ROOT = Path(__file__).resolve().parents[1]


class AnnotationSamplingTests(unittest.TestCase):
    def test_balanced_sample_is_deterministic_and_score_blind(self) -> None:
        records = []
        for context_index in range(5):
            for profile_index in range(10):
                for sid_index in range(10):
                    records.append(
                        {
                            "actionability_score": sid_index / 10,
                            "experiment": {
                                "case_id": f"c{context_index}-p{profile_index}-s{sid_index}",
                                "context": f"c{context_index}",
                                "evidence_profile": f"p{profile_index}",
                                "base_index": sid_index + 1,
                            },
                        }
                    )
        first = balanced_sample(records, 300, 2026)
        second = balanced_sample(list(reversed(records)), 300, 2026)
        self.assertEqual(
            [row["experiment"]["case_id"] for row in first],
            [row["experiment"]["case_id"] for row in second],
        )
        cells: dict[tuple[str, str], int] = {}
        for row in first:
            key = (
                row["experiment"]["context"],
                row["experiment"]["evidence_profile"],
            )
            cells[key] = cells.get(key, 0) + 1
        self.assertEqual(set(cells.values()), {6})


if __name__ == "__main__":
    unittest.main()
