import unittest

from as_engine.explain import render_markdown


class ExplainTests(unittest.TestCase):
    def test_markdown_contains_weights_contributions_and_missing_codes(self) -> None:
        record = {
            "sid": 1,
            "signature": "Example",
            "alert_direction": "to_server",
            "attacker_candidate": "192.0.2.1",
            "victim_candidate": "192.0.2.2",
            "attribution_confidence": "high",
            "outcome_class": "unknown",
            "outcome_confidence": 0.4,
            "actionability_score": 0.5,
            "actionability_level": "medium",
            "risk_score": 0.3,
            "risk_level": "low",
            "score_breakdown": {
                "actionability": {
                    "components": {
                        "investigation_evidence": {
                            "label": "Investigation evidence",
                            "score": 0.5,
                            "weight": 0.25,
                            "contribution": 0.125,
                        }
                    }
                },
                "risk": {"components": {}},
            },
            "missing_evidence_by_dimension": {
                "investigation_evidence": [
                    {"code": "investigation.payload", "label": "Missing payload"}
                ]
            },
            "explanation": ["Example explanation."],
            "not_applicable": [],
        }
        rendered = render_markdown(record)
        self.assertIn("Investigation evidence", rendered)
        self.assertIn("0.125", rendered)
        self.assertIn("investigation.payload", rendered)


if __name__ == "__main__":
    unittest.main()
