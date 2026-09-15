import unittest

from as_engine.archetypes import aggregate_archetypes, balanced_sample


class ArchetypeTests(unittest.TestCase):
    def test_repeated_alerts_collapse_and_sampling_is_deterministic(self) -> None:
        base = {
            "dataset_name": "AIT-ADS",
            "dataset_scenario": "fox",
            "dataset_label": "false_positive",
            "sid": 1,
            "signature": "Example",
            "proto": "TCP",
            "app_proto": "http",
            "alert_direction": "to_server",
            "outcome_class": "unknown",
            "actionability_level": "medium",
            "risk_level": "low",
            "actionability_score": 0.6,
            "risk_score": 0.3,
            "timestamp": "2022-01-01T00:00:00Z",
            "missing_evidence": [{"code": "investigation.payload"}],
        }
        second = dict(base)
        second["timestamp"] = "2022-01-01T00:01:00Z"
        different = dict(base)
        different["sid"] = 2
        different["signature"] = "Other"
        archetypes, raw_count = aggregate_archetypes([base, second, different])

        self.assertEqual(raw_count, 3)
        self.assertEqual(len(archetypes), 2)
        repeated = next(row for row in archetypes if row["sid"] == 1)
        self.assertEqual(repeated["raw_alert_count"], 2)
        self.assertEqual(
            [row["archetype_id"] for row in balanced_sample(archetypes, 1, 2026)],
            [row["archetype_id"] for row in balanced_sample(archetypes, 1, 2026)],
        )


if __name__ == "__main__":
    unittest.main()
