from pathlib import Path
import unittest

from as_engine.evidence import extract_evidence
from as_engine.parser import FlowContext, normalize_event
from as_engine.rule_catalog import RuleCatalog
from as_engine.rule_catalog import RuleMatch
from as_engine.scoring import build_score_record, calculate_scores, load_scoring_profile


ROOT = Path(__file__).resolve().parents[1]


def make_alert(status: int, payload: str | None = None):
    event = {
        "timestamp": "2026-01-01T00:00:00Z",
        "event_type": "alert",
        "flow_id": 10,
        "tx_id": 0,
        "src_ip": "203.0.113.10",
        "src_port": 41003,
        "dest_ip": "10.0.0.20",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "alert": {
            "signature_id": 2025756,
            "rev": 3,
            "signature": "D-Link command injection",
            "category": "Attempted User Privilege Gain",
            "severity": 2,
        },
        "http": {
            "hostname": "victim.local",
            "url": "/login.cgi?cli=abc;id",
            "http_method": "GET",
            "status": status,
            "http_user_agent": "curl/8.0",
        },
    }
    context = FlowContext(
        client_ip="203.0.113.10",
        client_port=41003,
        server_ip="10.0.0.20",
        server_port=80,
        app_proto="http",
        source="flow",
    )
    alert = normalize_event(event, context)
    assert alert is not None
    if payload is not None:
        from dataclasses import replace

        alert = replace(alert, payload_printable=payload)
    return alert


class ScoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = RuleCatalog.from_yaml(str(ROOT / "rules/rule_metadata.yaml"))
        cls.profile = load_scoring_profile(str(ROOT / "config/scoring-v2.yaml"))

    def test_not_applicable_cve_does_not_reduce_context(self) -> None:
        alert = make_alert(200)
        rule = self.catalog.lookup(2025756, 3)
        evidence = extract_evidence(alert, rule)
        self.assertEqual(evidence.subscores.attack_context, 1.0)
        self.assertIn("context.cve", evidence.not_applicable)
        self.assertEqual(evidence.outcome_class, "possibly_successful")
        self.assertEqual(evidence.risk_signals.outcome_likelihood, 0.60)
        actionability, risk = calculate_scores(evidence, self.profile)
        self.assertAlmostEqual(actionability, 0.86)
        self.assertAlmostEqual(risk, 0.69)
        record = build_score_record(
            alert.to_dict(),
            evidence,
            actionability,
            risk,
            self.profile,
            RuleMatch(rule, "exact"),
        )
        contributions = record["score_breakdown"]["actionability"]["components"]
        self.assertAlmostEqual(
            sum(component["contribution"] for component in contributions.values()),
            record["actionability_score"],
        )
        self.assertIn("investigation_evidence", record["missing_evidence_by_dimension"])

    def test_failure_is_high_evidence_but_low_likelihood(self) -> None:
        alert = make_alert(403)
        evidence = extract_evidence(alert, self.catalog.lookup(2025756, 3))
        self.assertEqual(evidence.outcome_class, "failure_evidenced")
        self.assertEqual(evidence.subscores.outcome_evidence, 1.0)
        self.assertEqual(evidence.risk_signals.outcome_likelihood, 0.10)

    def test_payload_marker_overrides_status_only_inference(self) -> None:
        rule = self.catalog.lookup(2025756, 3)
        failed = extract_evidence(
            make_alert(200, "HTTP/1.1 200 OK\\r\\n\\r\\nCONTROLLED_FAILURE_MARKER"),
            rule,
        )
        succeeded = extract_evidence(
            make_alert(200, "HTTP/1.1 200 OK\\r\\n\\r\\nCONTROLLED_SUCCESS_MARKER"),
            rule,
        )
        self.assertEqual(failed.outcome_class, "failure_evidenced")
        self.assertEqual(failed.risk_signals.outcome_likelihood, 0.10)
        self.assertEqual(succeeded.outcome_class, "success_evidenced")
        self.assertEqual(succeeded.subscores.outcome_evidence, 1.0)
        self.assertEqual(succeeded.risk_signals.outcome_likelihood, 0.90)


if __name__ == "__main__":
    unittest.main()
