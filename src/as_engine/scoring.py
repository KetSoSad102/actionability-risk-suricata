from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml

from as_engine.evidence import EvidenceResult, RiskSignals, SubScores
from as_engine.rule_catalog import RuleMatch


ACTIONABILITY_LABELS = {
    "entity_completeness": "Entity completeness",
    "attack_context": "Attack context",
    "outcome_evidence": "Outcome evidence strength",
    "investigation_evidence": "Investigation evidence",
    "recommended_response": "Recommended response quality",
}

RISK_LABELS = {
    "severity_impact": "Severity and impact",
    "outcome_likelihood": "Outcome likelihood",
}


@dataclass
class ScoringProfile:
    name: str
    actionability_weights: dict[str, float]
    risk_weights: dict[str, float]
    actionability_thresholds: dict[str, float]
    risk_thresholds: dict[str, float]


def _normalized_weights(raw: Any, required: set[str], label: str) -> dict[str, float]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} weights must be a mapping")
    missing = required - set(raw)
    unknown = set(raw) - required
    if missing:
        raise ValueError(f"Missing {label} weights: {sorted(missing)}")
    if unknown:
        raise ValueError(f"Unknown {label} weights: {sorted(unknown)}")
    weights = {name: float(value) for name, value in raw.items()}
    if any(value < 0 for value in weights.values()):
        raise ValueError(f"{label} weights cannot be negative")
    total = sum(weights.values())
    if total <= 0:
        raise ValueError(f"Total {label} weight must be positive")
    return {name: value / total for name, value in weights.items()}


def _thresholds(raw: Any, label: str) -> dict[str, float]:
    defaults = {"medium": 0.50, "high": 0.75}
    if raw is None:
        return defaults
    if not isinstance(raw, dict):
        raise ValueError(f"{label} thresholds must be a mapping")
    values = {key: float(value) for key, value in raw.items()}
    if set(values) != {"medium", "high"}:
        raise ValueError(f"{label} thresholds require exactly medium and high")
    if not 0 <= values["medium"] <= values["high"] <= 1:
        raise ValueError(f"{label} thresholds must satisfy 0 <= medium <= high <= 1")
    return values


def load_scoring_profile(path: str, profile_name: str | None = None) -> ScoringProfile:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("Scoring configuration root must be a mapping")
    if data.get("schema_version") != 2:
        raise ValueError("Scoring configuration schema_version must be 2")
    selected = profile_name or data.get("default_profile", "proposed_default")
    profiles = data.get("profiles", {})
    if selected not in profiles:
        raise ValueError(f"Missing scoring profile: {selected}")
    profile = profiles[selected]
    if not isinstance(profile, dict):
        raise ValueError(f"Scoring profile {selected} must be a mapping")

    actionability_required = set(SubScores.__dataclass_fields__)
    risk_required = set(RiskSignals.__dataclass_fields__)
    return ScoringProfile(
        name=selected,
        actionability_weights=_normalized_weights(
            profile.get("actionability"), actionability_required, "actionability"
        ),
        risk_weights=_normalized_weights(profile.get("risk"), risk_required, "risk"),
        actionability_thresholds=_thresholds(
            profile.get("actionability_thresholds"), "actionability"
        ),
        risk_thresholds=_thresholds(profile.get("risk_thresholds"), "risk"),
    )


def validate_score(name: str, value: float) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in [0, 1], got {value}")


def _weighted_score(values: dict[str, float], weights: dict[str, float]) -> float:
    total = 0.0
    for name, value in values.items():
        validate_score(name, value)
        total += weights[name] * value
    return total


def calculate_actionability_score(subscores: SubScores, profile: ScoringProfile) -> float:
    return _weighted_score(subscores.to_dict(), profile.actionability_weights)


def calculate_risk_score(signals: RiskSignals, profile: ScoringProfile) -> float:
    return _weighted_score(signals.to_dict(), profile.risk_weights)


def score_level(score: float, thresholds: dict[str, float]) -> str:
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    return "low"


def calculate_scores(evidence: EvidenceResult, profile: ScoringProfile) -> tuple[float, float]:
    return (
        calculate_actionability_score(evidence.subscores, profile),
        calculate_risk_score(evidence.risk_signals, profile),
    )


def _attribution(alert: dict[str, Any], match: RuleMatch) -> tuple[str | None, str | None, str]:
    client = alert.get("client_ip")
    server = alert.get("server_ip")
    role = match.rule.attacker_role if match.rule is not None else "client"
    if role == "client":
        return client, server, alert.get("role_confidence", "unknown")
    if role == "server":
        return server, client, alert.get("role_confidence", "unknown")
    return None, None, "unknown"


def _component_breakdown(
    values: dict[str, float],
    weights: dict[str, float],
    labels: dict[str, str],
) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "label": labels[name],
            "score": round(float(value), 6),
            "weight": round(float(weights[name]), 6),
            "contribution": round(float(value) * float(weights[name]), 6),
        }
        for name, value in values.items()
    }


def build_score_record(
    alert: dict[str, Any],
    evidence: EvidenceResult,
    actionability_score: float,
    risk_score: float,
    profile: ScoringProfile,
    match: RuleMatch,
) -> dict[str, Any]:
    attacker, victim, attribution_confidence = _attribution(alert, match)
    actionability_values = evidence.subscores.to_dict()
    risk_values = evidence.risk_signals.to_dict()
    actionability_breakdown = _component_breakdown(
        actionability_values, profile.actionability_weights, ACTIONABILITY_LABELS
    )
    risk_breakdown = _component_breakdown(
        risk_values, profile.risk_weights, RISK_LABELS
    )
    missing_by_dimension: dict[str, list[dict[str, str]]] = {}
    for item in evidence.missing_evidence:
        missing_by_dimension.setdefault(item.dimension, []).append(item.to_dict())
    return {
        "alert_id": alert["alert_id"],
        "timestamp": alert["timestamp"],
        "dataset_name": alert.get("dataset_name"),
        "dataset_scenario": alert.get("dataset_scenario"),
        "dataset_label": alert.get("dataset_label"),
        "dataset_source_record_index": alert.get("dataset_source_record_index"),
        "flow_id": alert["flow_id"],
        "tx_id": alert["tx_id"],
        "community_id": alert["community_id"],
        "packet_src_ip": alert["packet_src_ip"],
        "packet_src_port": alert["packet_src_port"],
        "packet_dest_ip": alert["packet_dest_ip"],
        "packet_dest_port": alert["packet_dest_port"],
        "client_ip": alert["client_ip"],
        "client_port": alert["client_port"],
        "server_ip": alert["server_ip"],
        "server_port": alert["server_port"],
        "attacker_candidate": attacker,
        "victim_candidate": victim,
        "alert_direction": alert["alert_direction"],
        "attribution_confidence": attribution_confidence,
        "proto": alert["proto"],
        "app_proto": alert["app_proto"],
        "sid": alert["sid"],
        "rev": alert["rev"],
        "signature": alert["signature"],
        "category": alert["category"],
        "suricata_severity": alert.get("suricata_severity"),
        "http_hostname": alert["http_hostname"],
        "http_url": alert["http_url"],
        "http_method": alert["http_method"],
        "http_status": alert["http_status"],
        "http_user_agent": alert.get("http_user_agent"),
        "payload_printable": alert.get("payload_printable"),
        "attack_type": match.rule.attack_type if match.rule is not None else None,
        "cve": list(match.rule.cve) if match.rule is not None else [],
        "mitre": list(match.rule.mitre) if match.rule is not None else [],
        "recommended_actions": (
            [
                {
                    "phase": action.phase,
                    "action": action.action,
                    "evidence": list(action.evidence),
                    "condition": action.condition,
                }
                for action in match.rule.recommended_actions
            ]
            if match.rule is not None
            else []
        ),
        "rule_match_quality": match.quality,
        "rule_match_warning": match.warning,
        "score_profile": profile.name,
        "actionability_score": round(actionability_score, 6),
        "actionability_level": score_level(actionability_score, profile.actionability_thresholds),
        "risk_score": round(risk_score, 6),
        "risk_level": score_level(risk_score, profile.risk_thresholds),
        "outcome_class": evidence.outcome_class,
        "outcome_confidence": evidence.outcome_confidence,
        "subscores": actionability_values,
        "risk_signals": risk_values,
        "risk_signal_sources": {
            "severity_impact": (
                "rule_metadata"
                if match.rule is not None and match.rule.severity is not None
                else "suricata_eve"
                if alert.get("suricata_severity") is not None
                else "missing"
            ),
            "outcome_likelihood": (
                "configured_payload_marker"
                if any("configured" in text and "marker" in text for text in evidence.explanation)
                else "protocol_outcome_mapping"
                if alert.get("http_status") is not None
                else "missing"
            ),
            "severity_conflict": (
                match.rule is not None
                and match.rule.severity is not None
                and alert.get("suricata_severity") is not None
                and int(match.rule.severity) != int(alert["suricata_severity"])
            ),
        },
        "score_breakdown": {
            "actionability": {
                "total": round(actionability_score, 6),
                "components": actionability_breakdown,
                "calculation": "sum(component score * component weight)",
            },
            "risk": {
                "total": round(risk_score, 6),
                "components": risk_breakdown,
                "calculation": "sum(risk signal * signal weight)",
            },
        },
        "missing_evidence": [item.to_dict() for item in evidence.missing_evidence],
        "missing_evidence_by_dimension": missing_by_dimension,
        "not_applicable": evidence.not_applicable,
        "explanation": evidence.explanation,
    }
