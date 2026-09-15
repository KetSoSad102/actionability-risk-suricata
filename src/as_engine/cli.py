from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
import os
from pathlib import Path
from typing import Any

from as_engine.evidence import extract_evidence
from as_engine.parser import ParseDiagnostics, iter_eve_alerts
from as_engine.rule_catalog import RuleCatalog
from as_engine.scoring import build_score_record, calculate_scores, load_scoring_profile


CSV_COLUMNS = [
    "alert_id",
    "timestamp",
    "dataset_name",
    "dataset_scenario",
    "dataset_label",
    "dataset_source_record_index",
    "flow_id",
    "tx_id",
    "community_id",
    "packet_src_ip",
    "packet_src_port",
    "packet_dest_ip",
    "packet_dest_port",
    "client_ip",
    "client_port",
    "server_ip",
    "server_port",
    "attacker_candidate",
    "victim_candidate",
    "alert_direction",
    "attribution_confidence",
    "proto",
    "app_proto",
    "sid",
    "rev",
    "signature",
    "category",
    "attack_type",
    "cve",
    "mitre",
    "suricata_severity",
    "http_hostname",
    "http_url",
    "http_method",
    "http_status",
    "http_user_agent",
    "payload_printable",
    "recommended_action_count",
    "rule_match_quality",
    "rule_match_warning",
    "score_profile",
    "actionability_score",
    "actionability_level",
    "risk_score",
    "risk_level",
    "outcome_class",
    "outcome_confidence",
    "entity_completeness",
    "attack_context",
    "outcome_evidence",
    "investigation_evidence",
    "recommended_response",
    "severity_impact",
    "outcome_likelihood",
    "missing_evidence_count",
    "missing_evidence_codes",
    "not_applicable_count",
]


def flatten_for_csv(record: dict[str, Any]) -> dict[str, Any]:
    subscores = record.get("subscores", {})
    risk_signals = record.get("risk_signals", {})
    flat = {name: record.get(name) for name in CSV_COLUMNS}
    flat.update(
        entity_completeness=subscores.get("entity_completeness"),
        attack_context=subscores.get("attack_context"),
        outcome_evidence=subscores.get("outcome_evidence"),
        investigation_evidence=subscores.get("investigation_evidence"),
        recommended_response=subscores.get("recommended_response"),
        severity_impact=risk_signals.get("severity_impact"),
        outcome_likelihood=risk_signals.get("outcome_likelihood"),
        missing_evidence_count=len(record.get("missing_evidence", [])),
        missing_evidence_codes=";".join(
            item.get("code", "") for item in record.get("missing_evidence", [])
        ),
        not_applicable_count=len(record.get("not_applicable", [])),
        cve=";".join(record.get("cve") or []),
        mitre=";".join(record.get("mitre") or []),
        recommended_action_count=len(record.get("recommended_actions") or []),
    )
    return flat


class RunSummary:
    def __init__(self) -> None:
        self.alert_count = 0
        self.actionability_total = 0.0
        self.risk_total = 0.0
        self.actionability_min: float | None = None
        self.actionability_max: float | None = None
        self.risk_min: float | None = None
        self.risk_max: float | None = None
        self.outcomes: Counter[str] = Counter()
        self.rule_matches: Counter[str] = Counter()
        self.actionability_levels: Counter[str] = Counter()
        self.risk_levels: Counter[str] = Counter()
        self.missing_evidence: Counter[str] = Counter()

    def add(self, record: dict[str, Any]) -> None:
        actionability = float(record["actionability_score"])
        risk = float(record["risk_score"])
        self.alert_count += 1
        self.actionability_total += actionability
        self.risk_total += risk
        self.actionability_min = actionability if self.actionability_min is None else min(self.actionability_min, actionability)
        self.actionability_max = actionability if self.actionability_max is None else max(self.actionability_max, actionability)
        self.risk_min = risk if self.risk_min is None else min(self.risk_min, risk)
        self.risk_max = risk if self.risk_max is None else max(self.risk_max, risk)
        self.outcomes[record["outcome_class"]] += 1
        self.rule_matches[record["rule_match_quality"]] += 1
        self.actionability_levels[record["actionability_level"]] += 1
        self.risk_levels[record["risk_level"]] += 1
        self.missing_evidence.update(
            item["code"] for item in record.get("missing_evidence", [])
        )

    def to_dict(
        self,
        diagnostics: ParseDiagnostics,
        profile_name: str,
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        count = self.alert_count
        return {
            "schema_version": 2,
            "score_profile": profile_name,
            "alert_count": count,
            "actionability": {
                "average": round(self.actionability_total / count, 6) if count else 0.0,
                "minimum": self.actionability_min,
                "maximum": self.actionability_max,
                "levels": dict(self.actionability_levels),
            },
            "risk": {
                "average": round(self.risk_total / count, 6) if count else 0.0,
                "minimum": self.risk_min,
                "maximum": self.risk_max,
                "levels": dict(self.risk_levels),
            },
            "outcomes": dict(self.outcomes),
            "rule_matches": dict(self.rule_matches),
            "most_common_missing_evidence": self.missing_evidence.most_common(10),
            "parser": diagnostics.to_dict(),
            "ruleset_provenance": provenance,
        }


def _temporary_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.tmp")


def run(args: argparse.Namespace) -> dict[str, Any]:
    eve_path = Path(args.eve)
    if not eve_path.exists():
        raise FileNotFoundError(f"EVE file not found: {eve_path}")

    catalog = RuleCatalog.from_yaml(args.rules)
    profile = load_scoring_profile(args.scoring, args.profile)
    out_jsonl = Path(args.out_jsonl)
    out_csv = Path(args.out_csv)
    out_summary = Path(args.out_summary)
    for path in (out_jsonl, out_csv, out_summary):
        path.parent.mkdir(parents=True, exist_ok=True)

    jsonl_tmp = _temporary_path(out_jsonl)
    csv_tmp = _temporary_path(out_csv)
    summary_tmp = _temporary_path(out_summary)
    diagnostics = ParseDiagnostics()
    summary = RunSummary()

    try:
        with open(jsonl_tmp, "w", encoding="utf-8") as jsonl_handle, open(
            csv_tmp, "w", encoding="utf-8", newline=""
        ) as csv_handle:
            writer = csv.DictWriter(csv_handle, fieldnames=CSV_COLUMNS, lineterminator="\n")
            writer.writeheader()
            for alert in iter_eve_alerts(str(eve_path), diagnostics):
                match = catalog.lookup_with_quality(alert.sid, alert.rev)
                evidence = extract_evidence(alert, match.rule)
                actionability, risk = calculate_scores(evidence, profile)
                record = build_score_record(
                    alert.to_dict(), evidence, actionability, risk, profile, match
                )
                jsonl_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                writer.writerow(flatten_for_csv(record))
                summary.add(record)

        if args.fail_on_malformed and diagnostics.malformed_json:
            raise ValueError(f"Malformed EVE JSON lines: {diagnostics.malformed_json}")

        summary_record = summary.to_dict(diagnostics, profile.name, catalog.provenance)
        with open(summary_tmp, "w", encoding="utf-8") as handle:
            json.dump(summary_record, handle, ensure_ascii=False, indent=2)
            handle.write("\n")

        os.replace(jsonl_tmp, out_jsonl)
        os.replace(csv_tmp, out_csv)
        os.replace(summary_tmp, out_summary)
        return summary_record
    finally:
        for path in (jsonl_tmp, csv_tmp, summary_tmp):
            if path.exists():
                path.unlink()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Correlate Suricata EVE events and compute Actionability and Risk scores."
    )
    parser.add_argument("--eve", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--scoring", required=True)
    parser.add_argument("--profile", help="Scoring profile name; defaults to default_profile in YAML")
    parser.add_argument("--out-jsonl", required=True)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--out-summary", required=True)
    parser.add_argument(
        "--fail-on-malformed",
        action="store_true",
        help="Fail atomically instead of skipping malformed EVE JSON lines",
    )
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    summary = run(args)
    print(f"[+] Parsed alerts: {summary['alert_count']}")
    print(f"[+] Malformed EVE lines: {summary['parser']['malformed_json']}")
    print(f"[+] Rule matches: {summary['rule_matches']}")
    print(f"[+] JSONL output: {args.out_jsonl}")
    print(f"[+] CSV output: {args.out_csv}")
    print(f"[+] Summary output: {args.out_summary}")


if __name__ == "__main__":
    main()
