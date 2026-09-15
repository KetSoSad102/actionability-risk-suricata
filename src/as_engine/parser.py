from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


@dataclass
class ParseDiagnostics:
    total_lines: int = 0
    malformed_json: int = 0
    alert_events: int = 0
    non_alert_events: int = 0
    correlated_alerts: int = 0
    inferred_role_alerts: int = 0
    unresolved_role_alerts: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass
class FlowContext:
    client_ip: str | None = None
    client_port: int | None = None
    server_ip: str | None = None
    server_port: int | None = None
    app_proto: str | None = None
    community_id: str | None = None
    source: str = "unknown"
    http_transactions: dict[int | None, dict[str, Any]] = field(default_factory=dict)


@dataclass
class NormalizedAlert:
    alert_id: str
    timestamp: str | None
    flow_id: int | None
    tx_id: int | None
    community_id: str | None
    event_type: str
    packet_src_ip: str | None
    packet_src_port: int | None
    packet_dest_ip: str | None
    packet_dest_port: int | None
    client_ip: str | None
    client_port: int | None
    server_ip: str | None
    server_port: int | None
    attacker_candidate: str | None
    victim_candidate: str | None
    alert_direction: str
    role_confidence: str
    proto: str | None
    app_proto: str | None
    sid: int | None
    rev: int | None
    signature: str | None
    category: str | None
    suricata_severity: int | None
    http_hostname: str | None
    http_url: str | None
    http_method: str | None
    http_status: int | None
    http_user_agent: str | None
    payload_printable: str | None
    dataset_name: str | None
    dataset_scenario: str | None
    dataset_label: str | None
    dataset_source_record_index: int | None
    raw: dict[str, Any]

    # Compatibility aliases. They remain packet-oriented, exactly like EVE.
    @property
    def src_ip(self) -> str | None:
        return self.packet_src_ip

    @property
    def src_port(self) -> int | None:
        return self.packet_src_port

    @property
    def dest_ip(self) -> str | None:
        return self.packet_dest_ip

    @property
    def dest_port(self) -> int | None:
        return self.packet_dest_port

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.update(
            src_ip=self.packet_src_ip,
            src_port=self.packet_src_port,
            dest_ip=self.packet_dest_ip,
            dest_port=self.packet_dest_port,
        )
        return result


def _read_json_lines(path: str, diagnostics: ParseDiagnostics | None = None) -> Iterable[dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            if diagnostics is not None:
                diagnostics.total_lines += 1
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                if diagnostics is not None:
                    diagnostics.malformed_json += 1


def _flow_id(event: dict[str, Any]) -> int | None:
    value = event.get("flow_id")
    return value if isinstance(value, int) else None


def _tx_id(event: dict[str, Any]) -> int | None:
    value = event.get("tx_id")
    return value if isinstance(value, int) else None


def _context_from_event(event: dict[str, Any], source: str) -> FlowContext:
    return FlowContext(
        client_ip=event.get("src_ip"),
        client_port=event.get("src_port"),
        server_ip=event.get("dest_ip"),
        server_port=event.get("dest_port"),
        app_proto=event.get("app_proto"),
        community_id=event.get("community_id"),
        source=source,
    )


def index_eve_context(path: str, diagnostics: ParseDiagnostics | None = None) -> dict[int, FlowContext]:
    """Index flow roles and HTTP transactions before normalizing alerts.

    Response-side alerts reverse packet src/dst. Suricata's ``flow`` and
    transaction ``http`` events retain the flow initiator as src, so this pass
    uses them as the authoritative client/server mapping.
    """

    contexts: dict[int, FlowContext] = {}
    for event in _read_json_lines(path, diagnostics):
        event_type = event.get("event_type")
        if diagnostics is not None:
            if event_type == "alert":
                diagnostics.alert_events += 1
            else:
                diagnostics.non_alert_events += 1

        flow_id = _flow_id(event)
        if flow_id is None or event_type not in {"flow", "http"}:
            continue

        existing = contexts.get(flow_id)
        # A flow event is preferred because it represents the initiating side.
        if existing is None or event_type == "flow":
            replacement = _context_from_event(event, event_type)
            if existing is not None:
                replacement.http_transactions = existing.http_transactions
                replacement.app_proto = replacement.app_proto or existing.app_proto
                replacement.community_id = replacement.community_id or existing.community_id
            contexts[flow_id] = replacement
            existing = replacement

        if event_type == "http":
            http = event.get("http") or {}
            existing.http_transactions[_tx_id(event)] = http
            existing.app_proto = existing.app_proto or event.get("app_proto") or "http"
            existing.community_id = existing.community_id or event.get("community_id")

    return contexts


def _infer_http_roles(event: dict[str, Any]) -> FlowContext:
    src_port = event.get("src_port")
    dest_port = event.get("dest_port")
    common_server_ports = {80, 443, 8000, 8080, 8443}

    if dest_port in common_server_ports and src_port not in common_server_ports:
        return _context_from_event(event, "port_heuristic")
    if src_port in common_server_ports and dest_port not in common_server_ports:
        return FlowContext(
            client_ip=event.get("dest_ip"),
            client_port=dest_port,
            server_ip=event.get("src_ip"),
            server_port=src_port,
            app_proto=event.get("app_proto") or "http",
            community_id=event.get("community_id"),
            source="port_heuristic",
        )
    return FlowContext(app_proto=event.get("app_proto"), source="unknown")


def _alert_direction(event: dict[str, Any], context: FlowContext) -> str:
    src_ip = event.get("src_ip")
    src_port = event.get("src_port")
    if src_ip == context.client_ip and src_port == context.client_port:
        return "to_server"
    if src_ip == context.server_ip and src_port == context.server_port:
        return "to_client"
    if src_ip == context.client_ip:
        return "to_server"
    if src_ip == context.server_ip:
        return "to_client"
    return "unknown"


def stable_alert_id(event: dict[str, Any], context: FlowContext | None = None) -> str:
    alert = event.get("alert") or {}
    http = event.get("http") or {}
    key = "|".join(
        [
            str(event.get("timestamp", "")),
            str(event.get("flow_id", "")),
            str(event.get("tx_id", "")),
            str((context.client_ip if context else None) or event.get("src_ip", "")),
            str((context.server_ip if context else None) or event.get("dest_ip", "")),
            str(alert.get("signature_id", "")),
            str(alert.get("rev", "")),
            str(http.get("url", "")),
            str(http.get("status", "")),
        ]
    )
    return hashlib.sha256(key.encode()).hexdigest()


def normalize_event(event: dict[str, Any], context: FlowContext | None = None) -> NormalizedAlert | None:
    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert") or {}
    dataset = event.get("dataset") if isinstance(event.get("dataset"), dict) else {}
    flow_id = _flow_id(event)
    tx_id = _tx_id(event)
    context = context or _infer_http_roles(event)

    correlated_http = context.http_transactions.get(tx_id) or context.http_transactions.get(None) or {}
    http = dict(correlated_http)
    http.update({key: value for key, value in (event.get("http") or {}).items() if value is not None})

    direction = _alert_direction(event, context)
    confidence = (
        "high"
        if context.source in {"flow", "http"}
        else "medium"
        if context.source == "port_heuristic"
        else "unknown"
    )

    # These are intentionally candidates, not definitive attribution. The
    # bundled rules describe client-to-server HTTP activity.
    attacker_candidate = context.client_ip if confidence != "unknown" else None
    victim_candidate = context.server_ip if confidence != "unknown" else None

    return NormalizedAlert(
        alert_id=stable_alert_id(event, context),
        timestamp=event.get("timestamp"),
        flow_id=flow_id,
        tx_id=tx_id,
        community_id=context.community_id or event.get("community_id"),
        event_type=event.get("event_type", "alert"),
        packet_src_ip=event.get("src_ip"),
        packet_src_port=event.get("src_port"),
        packet_dest_ip=event.get("dest_ip"),
        packet_dest_port=event.get("dest_port"),
        client_ip=context.client_ip,
        client_port=context.client_port,
        server_ip=context.server_ip,
        server_port=context.server_port,
        attacker_candidate=attacker_candidate,
        victim_candidate=victim_candidate,
        alert_direction=direction,
        role_confidence=confidence,
        proto=event.get("proto"),
        app_proto=event.get("app_proto") or context.app_proto,
        sid=alert.get("signature_id"),
        rev=alert.get("rev"),
        signature=alert.get("signature"),
        category=alert.get("category"),
        suricata_severity=alert.get("severity"),
        http_hostname=http.get("hostname"),
        http_url=http.get("url"),
        http_method=http.get("http_method"),
        http_status=http.get("status"),
        http_user_agent=http.get("http_user_agent"),
        payload_printable=event.get("payload_printable"),
        dataset_name=dataset.get("name"),
        dataset_scenario=dataset.get("scenario"),
        dataset_label=dataset.get("label"),
        dataset_source_record_index=(
            dataset.get("source_record_index")
            if isinstance(dataset.get("source_record_index"), int)
            else None
        ),
        raw=event,
    )


def iter_eve_alerts(path: str, diagnostics: ParseDiagnostics | None = None) -> Iterable[NormalizedAlert]:
    diagnostics = diagnostics or ParseDiagnostics()
    contexts = index_eve_context(path, diagnostics)

    # Do not count lines again on the normalization pass.
    for event in _read_json_lines(path):
        if event.get("event_type") != "alert":
            continue
        context = contexts.get(_flow_id(event)) or _infer_http_roles(event)
        normalized = normalize_event(event, context)
        if normalized is None:
            continue
        if normalized.role_confidence == "high":
            diagnostics.correlated_alerts += 1
        elif normalized.role_confidence == "medium":
            diagnostics.inferred_role_alerts += 1
        else:
            diagnostics.unresolved_role_alerts += 1
        yield normalized
