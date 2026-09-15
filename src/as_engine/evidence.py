from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from as_engine.parser import NormalizedAlert
from as_engine.rule_catalog import RuleMetadata


@dataclass
class SubScores:
    entity_completeness: float
    attack_context: float
    outcome_evidence: float
    investigation_evidence: float
    recommended_response: float

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


@dataclass
class RiskSignals:
    severity_impact: float
    outcome_likelihood: float

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


@dataclass(frozen=True)
class MissingEvidence:
    code: str
    dimension: str
    label: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class EvidenceResult:
    subscores: SubScores
    risk_signals: RiskSignals
    missing_evidence: list[MissingEvidence]
    not_applicable: list[str]
    explanation: list[str]
    outcome_class: str
    outcome_confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "subscores": self.subscores.to_dict(),
            "risk_signals": self.risk_signals.to_dict(),
            "missing_evidence": [item.to_dict() for item in self.missing_evidence],
            "not_applicable": self.not_applicable,
            "explanation": self.explanation,
            "outcome_class": self.outcome_class,
            "outcome_confidence": self.outcome_confidence,
        }


@dataclass(frozen=True)
class EvidenceItem:
    code: str
    label: str
    state: bool | None
    weight: float


def present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str) and value.strip() == "":
        return False
    return True


def score_items(items: list[EvidenceItem], dimension: str) -> tuple[float, list[MissingEvidence], list[str]]:
    applicable = [item for item in items if item.state is not None]
    denominator = sum(item.weight for item in applicable)
    score = sum(item.weight for item in applicable if item.state) / denominator if denominator else 0.0
    missing = [
        MissingEvidence(item.code, dimension, item.label)
        for item in applicable
        if item.state is False
    ]
    not_applicable = [item.code for item in items if item.state is None]
    return score, missing, not_applicable


def _is_http(alert: NormalizedAlert) -> bool:
    return alert.app_proto in {"http", "http1", "http2"} or any(
        present(value)
        for value in (alert.http_hostname, alert.http_url, alert.http_method, alert.http_status)
    )


def score_entity(alert: NormalizedAlert) -> tuple[float, list[MissingEvidence], list[str], list[str]]:
    ports_apply = (alert.proto or "").upper() in {"TCP", "UDP"}
    http = _is_http(alert)
    items = [
        EvidenceItem("entity.client_ip", "Missing client IP", present(alert.client_ip), 0.20),
        EvidenceItem("entity.server_ip", "Missing server IP", present(alert.server_ip), 0.20),
        EvidenceItem("entity.client_port", "Missing client port", present(alert.client_port) if ports_apply else None, 0.10),
        EvidenceItem("entity.server_port", "Missing server port", present(alert.server_port) if ports_apply else None, 0.10),
        EvidenceItem("entity.protocol", "Missing protocol", present(alert.proto) or present(alert.app_proto), 0.10),
        EvidenceItem("entity.hostname", "Missing HTTP hostname", present(alert.http_hostname) if http else None, 0.15),
        EvidenceItem("entity.flow_id", "Missing flow ID", present(alert.flow_id), 0.15),
    ]
    score, missing, not_applicable = score_items(items, "entity_completeness")
    explanation = [
        f"Client/server roles were resolved with {alert.role_confidence} confidence; packet direction is {alert.alert_direction}."
    ]
    return score, missing, not_applicable, explanation


def score_attack_context(
    alert: NormalizedAlert,
    rule: RuleMetadata | None,
) -> tuple[float, list[MissingEvidence], list[str], list[str]]:
    cve_state: bool | None
    mitre_state: bool | None
    if rule is None:
        cve_state = False
        mitre_state = False
    else:
        cve_state = len(rule.cve) > 0 if rule.cve_applicable else None
        mitre_state = len(rule.mitre) > 0 if rule.mitre_applicable else None

    items = [
        EvidenceItem("context.signature", "Missing signature/message", present(alert.signature), 0.20),
        EvidenceItem("context.category", "Missing attack category", present(alert.category) or (rule is not None and present(rule.category)), 0.20),
        EvidenceItem("context.attack_type", "Missing attack type", rule is not None and present(rule.attack_type), 0.25),
        EvidenceItem("context.cve", "Missing applicable CVE reference", cve_state, 0.15),
        EvidenceItem("context.mitre", "Missing applicable MITRE ATT&CK mapping", mitre_state, 0.20),
    ]
    score, missing, not_applicable = score_items(items, "attack_context")
    explanation = [
        "Attack context was enriched from exact or fallback SID metadata."
        if rule
        else "No SID metadata was found; context uses EVE fields only."
    ]
    if rule is None:
        missing.append(MissingEvidence("context.sid_metadata", "attack_context", "No SID metadata found"))
    return score, missing, not_applicable, explanation


def score_outcome(
    alert: NormalizedAlert,
    rule: RuleMetadata | None,
) -> tuple[str, float, float, list[MissingEvidence], list[str]]:
    status = alert.http_status
    payload = alert.payload_printable or ""
    indicators = rule.success_indicators if rule is not None else {}
    success_markers = [
        str(value).casefold()
        for value in indicators.get("payload_contains_success", [])
    ]
    failure_markers = [
        str(value).casefold()
        for value in indicators.get("payload_contains_failure", [])
    ]
    folded_payload = payload.casefold()

    # A configured body marker is more specific than the HTTP status.  In
    # particular, a custom error page may legitimately return HTTP 200.
    matched_failure = next(
        (marker for marker in failure_markers if marker in folded_payload), None
    )
    if matched_failure is not None:
        return (
            "failure_evidenced",
            1.0,
            0.10,
            [],
            [
                "A configured failure marker was present in the payload; "
                "this overrides status-only inference."
            ],
        )
    matched_success = next(
        (marker for marker in success_markers if marker in folded_payload), None
    )
    if matched_success is not None:
        return (
            "success_evidenced",
            1.0,
            0.90,
            [],
            [
                "A configured success marker was present in the payload; "
                "the result is stronger than status-only evidence."
            ],
        )

    if status is None:
        return (
            "unknown",
            0.0,
            0.30,
            [MissingEvidence("outcome.protocol_result", "outcome_evidence", "Missing HTTP status or protocol outcome")],
            ["No direct success/failure evidence was found."],
        )

    success_statuses = {200, 201, 202}
    failure_statuses = {400, 401, 403, 404, 500}
    if rule is not None:
        success_statuses = set(indicators.get("http_status_success") or success_statuses)
        failure_statuses = set(indicators.get("http_status_failure") or failure_statuses)

    if status in failure_statuses:
        return (
            "failure_evidenced",
            1.0,
            0.10,
            [],
            [f"HTTP status {status} is strong evidence that the request failed or was rejected."],
        )
    if status in success_statuses:
        return (
            "possibly_successful",
            0.60,
            0.60,
            [],
            [f"HTTP status {status} is partial evidence only; it does not prove application impact."],
        )
    return (
        "unknown",
        0.40,
        0.40,
        [],
        [f"HTTP status {status} is available but not decisive."],
    )


def score_severity_impact(alert: NormalizedAlert, rule: RuleMetadata | None) -> tuple[float, list[MissingEvidence], list[str]]:
    metadata_severity = rule.severity if rule is not None else None
    severity = metadata_severity if metadata_severity is not None else alert.suricata_severity
    if severity is None:
        return (
            0.0,
            [MissingEvidence("risk.severity", "risk", "Missing severity")],
            ["Severity/impact could not be determined."],
        )
    score = {1: 1.00, 2: 0.75, 3: 0.50, 4: 0.25}.get(int(severity), 0.25)
    source = "rule metadata" if metadata_severity is not None else "Suricata EVE"
    explanation = f"Severity signal was derived from {source} priority value {severity}."
    if (
        metadata_severity is not None
        and alert.suricata_severity is not None
        and int(metadata_severity) != int(alert.suricata_severity)
    ):
        explanation += (
            f" Suricata EVE reported {alert.suricata_severity}; both values are retained "
            "as provenance rather than silently treated as identical."
        )
    return score, [], [explanation]


def score_investigation(alert: NormalizedAlert) -> tuple[float, list[MissingEvidence], list[str], list[str]]:
    http = _is_http(alert)
    items = [
        EvidenceItem("investigation.http_url", "Missing HTTP URL", present(alert.http_url) if http else None, 0.16),
        EvidenceItem("investigation.http_method", "Missing HTTP method", present(alert.http_method) if http else None, 0.08),
        EvidenceItem("investigation.http_status", "Missing HTTP status", present(alert.http_status) if http else None, 0.12),
        EvidenceItem("investigation.hostname", "Missing HTTP hostname", present(alert.http_hostname) if http else None, 0.12),
        EvidenceItem("investigation.user_agent", "Missing HTTP user-agent", present(alert.http_user_agent) if http else None, 0.08),
        EvidenceItem("investigation.flow_id", "Missing flow ID", present(alert.flow_id), 0.12),
        EvidenceItem("investigation.community_id", "Missing Community ID", present(alert.community_id), 0.12),
        EvidenceItem("investigation.payload", "Missing payload excerpt", present(alert.payload_printable), 0.20),
    ]
    score, missing, not_applicable = score_items(items, "investigation_evidence")
    return score, missing, not_applicable, ["Investigation evidence was checked from flow, HTTP, Community ID, and payload fields."]


def score_recommended_response(
    rule: RuleMetadata | None,
) -> tuple[float, list[MissingEvidence], list[str], list[str]]:
    if rule is None:
        return (
            0.0,
            [MissingEvidence("response.metadata", "recommended_response", "No rule metadata, therefore no response guidance")],
            [],
            ["Recommended response is unavailable."],
        )
    actions = rule.recommended_actions
    if not actions:
        return (
            0.0,
            [MissingEvidence("response.actions", "recommended_response", "Missing recommended response")],
            [],
            ["No response guidance was mapped to this SID."],
        )

    phases = {action.phase for action in actions}
    score = 0.20  # Some concrete guidance exists.
    score += 0.25 if "validate" in phases else 0.0
    score += 0.20 if "scope" in phases else 0.0
    score += 0.20 if "contain" in phases else 0.0
    score += 0.15 if any(action.evidence for action in actions) else 0.0

    missing: list[MissingEvidence] = []
    for phase in ("validate", "scope", "contain"):
        if phase not in phases:
            missing.append(
                MissingEvidence(
                    f"response.phase.{phase}",
                    "recommended_response",
                    f"Missing {phase} response step",
                )
            )
    if not any(action.evidence for action in actions):
        missing.append(
            MissingEvidence(
                "response.evidence_link",
                "recommended_response",
                "Response guidance does not identify evidence to inspect",
            )
        )
    return min(score, 1.0), missing, [], ["Response quality was scored by phase coverage and evidence linkage, not action count."]


def extract_evidence(alert: NormalizedAlert, rule: RuleMetadata | None) -> EvidenceResult:
    missing: list[MissingEvidence] = []
    not_applicable: list[str] = []
    explanation: list[str] = []

    entity, current_missing, current_na, current_explanation = score_entity(alert)
    missing += current_missing
    not_applicable += current_na
    explanation += current_explanation

    context, current_missing, current_na, current_explanation = score_attack_context(alert, rule)
    missing += current_missing
    not_applicable += current_na
    explanation += current_explanation

    outcome, outcome_evidence, outcome_likelihood, current_missing, current_explanation = score_outcome(alert, rule)
    missing += current_missing
    explanation += current_explanation

    severity, current_missing, current_explanation = score_severity_impact(alert, rule)
    missing += current_missing
    explanation += current_explanation

    investigation, current_missing, current_na, current_explanation = score_investigation(alert)
    missing += current_missing
    not_applicable += current_na
    explanation += current_explanation

    response, current_missing, current_na, current_explanation = score_recommended_response(rule)
    missing += current_missing
    not_applicable += current_na
    explanation += current_explanation

    # Defensive de-duplication by stable evidence code.
    missing_by_code = {item.code: item for item in missing}
    return EvidenceResult(
        subscores=SubScores(entity, context, outcome_evidence, investigation, response),
        risk_signals=RiskSignals(severity, outcome_likelihood),
        missing_evidence=list(missing_by_code.values()),
        not_applicable=sorted(set(not_applicable)),
        explanation=explanation,
        outcome_class=outcome,
        outcome_confidence=outcome_evidence,
    )
