from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


def iter_score_records(path: str | Path) -> Iterable[dict[str, Any]]:
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed score JSONL at line {line_number}") from exc
            if isinstance(record, dict):
                yield record


def select_record(
    records: Iterable[dict[str, Any]], sid: int | None, alert_id: str | None
) -> dict[str, Any]:
    for record in records:
        if alert_id is not None and record.get("alert_id") == alert_id:
            return record
        if alert_id is None and sid is not None and record.get("sid") == sid:
            return record
    target = f"alert_id={alert_id}" if alert_id else f"sid={sid}"
    raise LookupError(f"No score record found for {target}")


def _missing_summary(record: dict[str, Any], dimension: str) -> str:
    entries = record.get("missing_evidence_by_dimension", {}).get(dimension, [])
    if not entries:
        return "none"
    return ", ".join(item.get("code", "unknown") for item in entries)


def render_markdown(record: dict[str, Any]) -> str:
    actionability = record.get("score_breakdown", {}).get("actionability", {})
    risk = record.get("score_breakdown", {}).get("risk", {})
    lines = [
        f"# Alert explanation: SID {record.get('sid')}",
        "",
        f"Signature: {record.get('signature') or 'unknown'}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Direction | {record.get('alert_direction') or 'unknown'} |",
        f"| Attacker candidate | {record.get('attacker_candidate') or 'unknown'} |",
        f"| Victim candidate | {record.get('victim_candidate') or 'unknown'} |",
        f"| Attribution confidence | {record.get('attribution_confidence') or 'unknown'} |",
        f"| Outcome | {record.get('outcome_class') or 'unknown'} ({float(record.get('outcome_confidence') or 0):.2f}) |",
        "",
        f"## Actionability: {float(record.get('actionability_score') or 0):.3f} ({record.get('actionability_level')})",
        "",
        "| Criterion | Score | Weight | Contribution | Missing evidence |",
        "|---|---:|---:|---:|---|",
    ]
    for name, item in actionability.get("components", {}).items():
        lines.append(
            "| {label} | {score:.3f} | {weight:.2f} | {contribution:.3f} | {missing} |".format(
                label=item.get("label", name),
                score=float(item.get("score", 0)),
                weight=float(item.get("weight", 0)),
                contribution=float(item.get("contribution", 0)),
                missing=_missing_summary(record, name),
            )
        )
    lines.extend(
        [
            "",
            f"## Risk: {float(record.get('risk_score') or 0):.3f} ({record.get('risk_level')})",
            "",
            "| Signal | Score | Weight | Contribution |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, item in risk.get("components", {}).items():
        lines.append(
            "| {label} | {score:.3f} | {weight:.2f} | {contribution:.3f} |".format(
                label=item.get("label", name),
                score=float(item.get("score", 0)),
                weight=float(item.get("weight", 0)),
                contribution=float(item.get("contribution", 0)),
            )
        )
    lines.extend(["", "## Explanation", ""])
    for explanation in record.get("explanation", []):
        lines.append(f"- {explanation}")
    not_applicable = record.get("not_applicable", [])
    if not_applicable:
        lines.extend(["", "Not applicable: " + ", ".join(not_applicable)])
    return "\n".join(lines) + "\n"


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render a criterion-by-criterion explanation for one scored alert."
    )
    parser.add_argument("--scores", default="runs/improved/scores.jsonl")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sid", type=int)
    group.add_argument("--alert-id")
    parser.add_argument("--output", help="Write Markdown to a file instead of stdout")
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    record = select_record(iter_score_records(args.scores), args.sid, args.alert_id)
    rendered = render_markdown(record)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"[+] Explanation written to {path}")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
