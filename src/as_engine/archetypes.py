from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable


@dataclass
class ArchetypeAccumulator:
    key: tuple[str, ...]
    first: dict[str, Any]
    raw_alert_count: int = 0
    actionability_sum: float = 0.0
    risk_sum: float = 0.0
    first_timestamp: str | None = None
    last_timestamp: str | None = None

    def add(self, record: dict[str, Any]) -> None:
        self.raw_alert_count += 1
        self.actionability_sum += float(record.get("actionability_score") or 0.0)
        self.risk_sum += float(record.get("risk_score") or 0.0)
        timestamp = record.get("timestamp")
        if isinstance(timestamp, str):
            self.first_timestamp = (
                timestamp
                if self.first_timestamp is None
                else min(self.first_timestamp, timestamp)
            )
            self.last_timestamp = (
                timestamp
                if self.last_timestamp is None
                else max(self.last_timestamp, timestamp)
            )

    def finalize(self) -> dict[str, Any]:
        record = self.first
        key_text = "|".join(self.key)
        return {
            "archetype_id": hashlib.sha256(key_text.encode()).hexdigest()[:20],
            "dataset_name": record.get("dataset_name") or "unspecified",
            "dataset_scenario": record.get("dataset_scenario") or "unspecified",
            "dataset_label": record.get("dataset_label") or "unlabeled",
            "sid": record.get("sid"),
            "signature": record.get("signature"),
            "proto": record.get("proto"),
            "app_proto": record.get("app_proto"),
            "alert_direction": record.get("alert_direction"),
            "outcome_class": record.get("outcome_class"),
            "actionability_level": record.get("actionability_level"),
            "risk_level": record.get("risk_level"),
            "missing_evidence_profile": self.key[-1],
            "raw_alert_count": self.raw_alert_count,
            "mean_actionability": round(
                self.actionability_sum / self.raw_alert_count, 6
            ),
            "mean_risk": round(self.risk_sum / self.raw_alert_count, 6),
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
        }


ARCHETYPE_COLUMNS = [
    "archetype_id",
    "dataset_name",
    "dataset_scenario",
    "dataset_label",
    "sid",
    "signature",
    "proto",
    "app_proto",
    "alert_direction",
    "outcome_class",
    "actionability_level",
    "risk_level",
    "missing_evidence_profile",
    "raw_alert_count",
    "mean_actionability",
    "mean_risk",
    "first_timestamp",
    "last_timestamp",
]


def _iter_jsonl(path: str | Path) -> Iterable[dict[str, Any]]:
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


def _archetype_key(record: dict[str, Any]) -> tuple[str, ...]:
    missing = sorted(
        item.get("code", "unknown")
        for item in record.get("missing_evidence", [])
        if isinstance(item, dict)
    )
    identity = record.get("sid")
    if identity is None:
        identity = record.get("signature") or "unknown_signature"
    return (
        str(record.get("dataset_name") or "unspecified"),
        str(record.get("dataset_scenario") or "unspecified"),
        str(record.get("dataset_label") or "unlabeled"),
        str(identity),
        str(record.get("proto") or "unknown"),
        str(record.get("app_proto") or "unknown"),
        str(record.get("alert_direction") or "unknown"),
        str(record.get("outcome_class") or "unknown"),
        ";".join(missing) if missing else "complete",
    )


def aggregate_archetypes(records: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    groups: dict[tuple[str, ...], ArchetypeAccumulator] = {}
    raw_count = 0
    for record in records:
        raw_count += 1
        key = _archetype_key(record)
        accumulator = groups.get(key)
        if accumulator is None:
            accumulator = ArchetypeAccumulator(key=key, first=record)
            groups[key] = accumulator
        accumulator.add(record)
    finalized = [group.finalize() for group in groups.values()]
    finalized.sort(
        key=lambda row: (
            row["dataset_scenario"],
            row["dataset_label"],
            str(row["sid"]),
            row["archetype_id"],
        )
    )
    return finalized, raw_count


def _stable_order(row: dict[str, Any], seed: int) -> str:
    return hashlib.sha256(f"{seed}|{row['archetype_id']}".encode()).hexdigest()


def balanced_sample(
    archetypes: list[dict[str, Any]], target: int, seed: int
) -> list[dict[str, Any]]:
    """Deterministically round-robin over scenario/label/outcome strata."""

    if target >= len(archetypes):
        return list(archetypes)
    strata: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in archetypes:
        key = (
            str(row["dataset_scenario"]),
            str(row["dataset_label"]),
            str(row["outcome_class"]),
        )
        strata.setdefault(key, []).append(row)
    for rows in strata.values():
        rows.sort(key=lambda row: _stable_order(row, seed))

    selected: list[dict[str, Any]] = []
    ordered_strata = sorted(strata)
    while len(selected) < target:
        progressed = False
        for key in ordered_strata:
            rows = strata[key]
            if rows and len(selected) < target:
                selected.append(rows.pop(0))
                progressed = True
        if not progressed:
            break
    selected.sort(key=lambda row: row["archetype_id"])
    return selected


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ARCHETYPE_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def run(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    archetypes, raw_count = aggregate_archetypes(_iter_jsonl(args.scores))
    if args.max_archetypes is not None:
        target = min(len(archetypes), max(1, args.max_archetypes))
        sampling_mode = f"maximum_{args.max_archetypes}"
    else:
        fraction = float(args.sample_fraction)
        if not 0 < fraction <= 1:
            raise ValueError("sample_fraction must be in (0, 1]")
        target = max(1, math.ceil(len(archetypes) * fraction)) if archetypes else 0
        sampling_mode = f"fraction_{fraction}"
    sample = balanced_sample(archetypes, target, args.seed)

    _write_csv(output_dir / "archetypes_all.csv", archetypes)
    _write_csv(output_dir / "archetypes_sample.csv", sample)
    represented_alerts = sum(int(row["raw_alert_count"]) for row in sample)
    summary = {
        "schema_version": 1,
        "input_scores": str(args.scores),
        "statistical_unit": (
            "dataset + scenario + label + SID/signature + protocol + direction + "
            "outcome class + missing-evidence profile"
        ),
        "raw_alert_count": raw_count,
        "archetype_count": len(archetypes),
        "sample": {
            "mode": sampling_mode,
            "seed": args.seed,
            "archetype_count": len(sample),
            "archetype_fraction": round(len(sample) / len(archetypes), 6) if archetypes else 0.0,
            "represented_raw_alerts": represented_alerts,
        },
        "coverage": {
            "datasets": dict(Counter(row["dataset_name"] for row in archetypes)),
            "scenarios": dict(Counter(row["dataset_scenario"] for row in archetypes)),
            "labels": dict(Counter(row["dataset_label"] for row in archetypes)),
            "outcomes": dict(Counter(row["outcome_class"] for row in archetypes)),
            "unique_sids": len({row["sid"] for row in archetypes if row["sid"] is not None}),
            "unique_signatures": len({row["signature"] for row in archetypes if row["signature"]}),
        },
        "claim_boundary": (
            "Raw alert frequency is descriptive. Statistical comparisons should use archetypes "
            "or independent flows/incidents to avoid pseudo-replication."
        ),
    }
    with (output_dir / "archetype_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return summary


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate scored alerts into independent-style archetypes and draw a balanced sample."
    )
    parser.add_argument("--scores", required=True)
    parser.add_argument("--output-dir", required=True)
    sample = parser.add_mutually_exclusive_group()
    sample.add_argument("--sample-fraction", type=float, default=1.0)
    sample.add_argument("--max-archetypes", type=int)
    parser.add_argument("--seed", type=int, default=2026)
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    summary = run(args)
    print(f"[+] Raw alerts: {summary['raw_alert_count']}")
    print(f"[+] Alert archetypes: {summary['archetype_count']}")
    print(f"[+] Sampled archetypes: {summary['sample']['archetype_count']}")
    print(f"[+] Output: {args.output_dir}")


if __name__ == "__main__":
    main()
