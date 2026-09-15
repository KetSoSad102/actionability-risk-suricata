from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re
from typing import Any, Iterable


@dataclass
class AitAdsDiagnostics:
    total_records: int = 0
    malformed_json: int = 0
    suricata_records: int = 0
    non_suricata_records: int = 0
    missing_sid: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


def _value(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def _integer(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        parsed = Decimal(str(value))
        if not parsed.is_finite() or parsed != parsed.to_integral_value():
            return None
        return int(parsed)
    except (InvalidOperation, TypeError, ValueError):
        return None


def _strip_suricata_prefix(description: str) -> str:
    return re.sub(r"^Suricata:\s*(?:Alert\s*-\s*)?", "", description).strip()


def _epoch_second(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        pass
    try:
        normalized = str(value).replace("Z", "+00:00")
        return int(datetime.fromisoformat(normalized).timestamp())
    except ValueError:
        return None


def load_label_csv(path: str | Path) -> dict[tuple[int, str], dict[str, str]]:
    """Load ``alerts_csv/<scenario>_alerts.txt`` from the official analysis.

    Labels are joined by whole-second timestamp and normalized signature. The
    official CSV can contain repeated instances of the same alert; identical
    keys are accepted only when their labels agree.
    """

    labels: dict[tuple[int, str], dict[str, str]] = {}
    with Path(path).open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            second = _epoch_second(row.get("time"))
            signature = _strip_suricata_prefix(row.get("name") or "")
            if second is None or not signature:
                continue
            value = {
                "time_label": row.get("time_label") or "-",
                "event_label": row.get("event_label") or "-",
                "short": row.get("short") or "-",
            }
            key = (second, signature)
            existing = labels.get(key)
            if existing is None or existing == value:
                labels[key] = value
    return labels


def convert_wazuh_record(
    record: dict[str, Any],
    scenario: str,
    record_index: int,
    label_lookup: dict[tuple[int, str], dict[str, str]] | None = None,
) -> dict[str, Any] | None:
    """Convert one Wazuh-embedded AIT-ADS Suricata record to EVE-like JSON.

    AIT-ADS stores Suricata detections inside Wazuh export records. Field
    availability differs by Wazuh decoder and data-set release, so the adapter
    accepts both nested EVE fragments and the flattened fields used by the
    official AIT-ADS analysis scripts. Missing values remain missing; the
    adapter never fabricates flow, transaction, payload, or outcome evidence.
    """

    rule = record.get("rule") if isinstance(record.get("rule"), dict) else {}
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    description = str(rule.get("description") or "")
    if not description.startswith("Suricata:"):
        return None

    embedded_alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    signature = _value(embedded_alert, "signature") or _strip_suricata_prefix(description)
    sid = _integer(
        _value(embedded_alert, "signature_id", "sid")
        or _value(data, "signature_id", "sid", "alert.signature_id")
    )
    rev = _integer(_value(embedded_alert, "rev") or _value(data, "rev", "alert.rev"))
    severity = _integer(
        _value(embedded_alert, "severity")
        or _value(data, "severity", "alert.severity")
    )
    category = (
        _value(embedded_alert, "category")
        or _value(data, "category", "alert.category")
    )

    http = data.get("http") if isinstance(data.get("http"), dict) else {}
    http_out = {
        "hostname": _value(http, "hostname") or _value(data, "http.hostname", "http_hostname"),
        "url": _value(http, "url") or _value(data, "http.url", "http_url"),
        "http_method": _value(http, "http_method", "method")
        or _value(data, "http.http_method", "http_method"),
        "status": _integer(
            _value(http, "status", "http_status")
            or _value(data, "http.status", "http_status")
        ),
        "http_user_agent": _value(http, "http_user_agent", "user_agent")
        or _value(data, "http.http_user_agent", "http_user_agent"),
    }
    http_out = {key: value for key, value in http_out.items() if value is not None}

    timestamp = _value(data, "timestamp") or record.get("timestamp")
    dataset = {
        "name": "AIT-ADS",
        "scenario": scenario,
        "source_record_index": record_index,
        "source": "Wazuh-embedded Suricata alert",
    }
    second = _epoch_second(timestamp)
    if label_lookup is not None and second is not None:
        matched_label = label_lookup.get((second, signature))
        if matched_label is not None:
            dataset.update(matched_label)
            event_label = matched_label.get("event_label")
            time_label = matched_label.get("time_label")
            dataset["label"] = (
                event_label if event_label not in (None, "", "-") else time_label
            )

    event: dict[str, Any] = {
        "timestamp": timestamp,
        "event_type": "alert",
        "src_ip": _value(data, "src_ip", "srcip"),
        "src_port": _integer(_value(data, "src_port", "srcport")),
        "dest_ip": _value(data, "dest_ip", "dst_ip", "dstip"),
        "dest_port": _integer(_value(data, "dest_port", "dst_port", "dstport")),
        "proto": _value(data, "proto"),
        "app_proto": _value(data, "app_proto"),
        "flow_id": _integer(_value(data, "flow_id")),
        "tx_id": _integer(_value(data, "tx_id")),
        "community_id": _value(data, "community_id"),
        "payload_printable": _value(data, "payload_printable"),
        "alert": {
            "signature_id": sid,
            "rev": rev,
            "signature": signature,
            "category": category,
            "severity": severity,
        },
        "dataset": dataset,
    }
    if http_out:
        event["http"] = http_out

    # Omit absent keys instead of serializing misleading explicit null values.
    for key in list(event):
        if key not in {"alert", "dataset"} and event[key] is None:
            del event[key]
    event["alert"] = {
        key: value for key, value in event["alert"].items() if value is not None
    }
    return event


def iter_ait_ads_events(
    path: str | Path,
    scenario: str,
    diagnostics: AitAdsDiagnostics | None = None,
    label_lookup: dict[tuple[int, str], dict[str, str]] | None = None,
) -> Iterable[dict[str, Any]]:
    diagnostics = diagnostics or AitAdsDiagnostics()
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            diagnostics.total_records += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                diagnostics.malformed_json += 1
                continue
            if not isinstance(record, dict):
                diagnostics.non_suricata_records += 1
                continue
            converted = convert_wazuh_record(record, scenario, index, label_lookup)
            if converted is None:
                diagnostics.non_suricata_records += 1
                continue
            diagnostics.suricata_records += 1
            if "signature_id" not in converted["alert"]:
                diagnostics.missing_sid += 1
            yield converted


def run(args: argparse.Namespace) -> dict[str, Any]:
    diagnostics = AitAdsDiagnostics()
    label_lookup = load_label_csv(args.labels_csv) if args.labels_csv else None
    output = Path(args.out_eve)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            for event in iter_ait_ads_events(
                args.input, args.scenario, diagnostics, label_lookup
            ):
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        if args.fail_on_malformed and diagnostics.malformed_json:
            raise ValueError(
                f"Malformed AIT-ADS JSON lines: {diagnostics.malformed_json}"
            )
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()

    summary = {
        "schema_version": 1,
        "adapter": "ait_ads_wazuh_to_eve",
        "scenario": args.scenario,
        "input": str(args.input),
        "output": str(output),
        "labels_csv": str(args.labels_csv) if args.labels_csv else None,
        "diagnostics": diagnostics.to_dict(),
        "limitations": [
            "AIT-ADS Wazuh exports may omit raw EVE flow_id, tx_id, HTTP outcome, and payload fields.",
            "The adapter preserves missing evidence and does not infer attack ground truth.",
            (
                "Time-phase labels were joined by whole-second timestamp and normalized signature."
                if args.labels_csv
                else "No official AIT-ADS time-phase label CSV was supplied."
            ),
        ],
    }
    summary_path = Path(args.out_summary) if args.out_summary else output.with_suffix(".summary.json")
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return summary


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert Wazuh-embedded Suricata alerts from AIT-ADS to EVE-like JSONL."
    )
    parser.add_argument("--input", required=True, help="AIT-ADS <scenario>_wazuh.json")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--out-eve", required=True)
    parser.add_argument("--out-summary")
    parser.add_argument(
        "--labels-csv",
        help="Optional official alerts_csv/<scenario>_alerts.txt for time/event labels",
    )
    parser.add_argument("--fail-on-malformed", action="store_true")
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    summary = run(args)
    diagnostics = summary["diagnostics"]
    print(f"[+] Input records: {diagnostics['total_records']}")
    print(f"[+] Suricata records: {diagnostics['suricata_records']}")
    print(f"[+] Records without SID: {diagnostics['missing_sid']}")
    print(f"[+] EVE-like output: {summary['output']}")


if __name__ == "__main__":
    main()
