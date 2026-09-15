from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


ITEM_FIELDS = [
    "item_id",
    "timestamp",
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
    "alert_direction",
    "proto",
    "app_proto",
    "sid",
    "signature",
    "category",
    "attack_type",
    "http_hostname",
    "http_url",
    "http_method",
    "http_status",
    "http_user_agent",
    "payload_printable",
    "cve",
    "mitre",
    "recommended_actions",
]


RESPONSE_FIELDS = [
    "item_id",
    "rater_slot",
    "rater_id",
    "actionability_likert_1_5",
    "actionability_class",
    "understands_event_1_5",
    "understands_outcome_1_5",
    "knows_next_action_1_5",
    "additional_pivot_required",
    "proposed_next_action",
    "confidence_1_5",
    "decision_seconds",
    "comments",
]


def _write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _annotation_id(case_id: str, seed: int) -> str:
    token = hashlib.sha256(f"{seed}|{case_id}".encode()).hexdigest()[:16]
    return f"PA-{token}"


def balanced_sample(
    records: list[dict[str, Any]], target: int, seed: int
) -> list[dict[str, Any]]:
    """Select cases evenly across outcome-context/evidence-profile strata.

    For the bundled 500-case design this selects six of ten SIDs from each of
    the 50 cells.  The cyclic starting position rotates by cell, producing 300
    items with exact context/profile balance and near-exact SID balance without
    using the score as a sampling variable.
    """

    if target <= 0:
        raise ValueError("Annotation target must be positive")
    if target > len(records):
        raise ValueError("Annotation target cannot exceed the available presentations")

    strata: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        experiment = record.get("experiment") or {}
        key = (str(experiment.get("context")), str(experiment.get("evidence_profile")))
        strata[key].append(record)
    if not strata:
        raise ValueError("No experiment strata were found")

    ordered_keys = sorted(strata)
    base_quota, remainder = divmod(target, len(ordered_keys))
    if any(len(strata[key]) < base_quota for key in ordered_keys):
        raise ValueError("A stratum is too small for balanced sampling")

    selected: list[dict[str, Any]] = []
    for stratum_index, key in enumerate(ordered_keys):
        group = sorted(
            strata[key],
            key=lambda record: (
                int(record["experiment"].get("base_index") or 0),
                str(record["experiment"]["case_id"]),
            ),
        )
        quota = base_quota + (1 if stratum_index < remainder else 0)
        if quota > len(group):
            raise ValueError("A stratum is too small for the requested remainder")
        start = (seed + stratum_index) % len(group)
        selected.extend(group[(start + offset) % len(group)] for offset in range(quota))

    # Hide systematic presentation order from raters while remaining reproducible.
    return sorted(
        selected,
        key=lambda record: hashlib.sha256(
            f"order|{seed}|{record['experiment']['case_id']}".encode()
        ).hexdigest(),
    )


def _analyst_item(record: dict[str, Any], item_id: str) -> dict[str, Any]:
    item = {field: record.get(field) for field in ITEM_FIELDS if field != "item_id"}
    item["item_id"] = item_id
    item["cve"] = json.dumps(item.get("cve") or [], ensure_ascii=False)
    item["mitre"] = json.dumps(item.get("mitre") or [], ensure_ascii=False)
    item["recommended_actions"] = json.dumps(
        item.get("recommended_actions") or [], ensure_ascii=False
    )
    return {field: item.get(field) for field in ITEM_FIELDS}


def write_annotation_pack(
    records: list[dict[str, Any]],
    output_dir: str | Path,
    target: int = 300,
    seed: int = 2026,
    ratings_per_item: int = 3,
) -> dict[str, Any]:
    if ratings_per_item < 1:
        raise ValueError("ratings_per_item must be at least one")
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    selected = balanced_sample(records, target, seed)

    item_rows: list[dict[str, Any]] = []
    key_rows: list[dict[str, Any]] = []
    response_rows: list[dict[str, Any]] = []
    item_json: list[dict[str, Any]] = []
    for record in selected:
        experiment = record["experiment"]
        item_id = _annotation_id(str(experiment["case_id"]), seed)
        item = _analyst_item(record, item_id)
        item_rows.append(item)
        item_json.append(item)
        key_rows.append(
            {
                "item_id": item_id,
                "case_id": experiment["case_id"],
                "seed_id": experiment["seed_id"],
                "base_context_id": experiment["base_context_id"],
                "base_sid": experiment["base_sid"],
                "context": experiment["context"],
                "evidence_profile": experiment["evidence_profile"],
                "controlled_transformation": experiment["controlled_transformation"],
                "automated_actionability_score": record["actionability_score"],
                "equal_weight_actionability": experiment["equal_weight_actionability"],
                "field_presence_baseline": experiment["field_presence_baseline"],
                "automated_risk_score": record["risk_score"],
                "automated_outcome_class": record["outcome_class"],
            }
        )
        for slot in range(1, ratings_per_item + 1):
            response_rows.append(
                {
                    "item_id": item_id,
                    "rater_slot": slot,
                    **{field: "" for field in RESPONSE_FIELDS[2:]},
                }
            )

    _write_csv(directory / "annotation_items.csv", item_rows, ITEM_FIELDS)
    _write_csv(directory / "annotation_key.csv", key_rows, list(key_rows[0]))
    _write_csv(directory / "annotation_responses_template.csv", response_rows, RESPONSE_FIELDS)
    with (directory / "annotation_items.jsonl").open("w", encoding="utf-8") as handle:
        for item in item_json:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    context_counts = Counter(row["context"] for row in key_rows)
    profile_counts = Counter(row["evidence_profile"] for row in key_rows)
    cell_counts = Counter(
        f"{row['context']}|{row['evidence_profile']}" for row in key_rows
    )
    sid_counts = Counter(str(row["base_sid"]) for row in key_rows)
    summary = {
        "schema_version": 1,
        "sampling_seed": seed,
        "available_presentations": len(records),
        "selected_items": len(item_rows),
        "ratings_per_item": ratings_per_item,
        "expected_rating_rows": len(response_rows),
        "blinding": (
            "annotation_items excludes automated scores, evidence-profile names, "
            "outcome labels, and controlled-context identifiers; annotation_key must "
            "remain hidden from raters"
        ),
        "balance": {
            "by_context": dict(sorted(context_counts.items())),
            "by_evidence_profile": dict(sorted(profile_counts.items())),
            "by_context_profile_cell": dict(sorted(cell_counts.items())),
            "by_sid": dict(sorted(sid_counts.items())),
        },
        "claim_boundary": (
            "This pack is an annotation protocol and empty response template. It is "
            "not evidence that analyst validation has been completed."
        ),
    }
    with (directory / "annotation_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return summary


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a blinded, balanced analyst-annotation pack from controlled presentations."
    )
    parser.add_argument("--cases", default="runs/experiments/controlled/controlled_cases.jsonl")
    parser.add_argument("--output-dir", default="runs/experiments/controlled/annotation")
    parser.add_argument("--target", type=int, default=300)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--ratings-per-item", type=int, default=3)
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    records = _read_jsonl(Path(args.cases))
    summary = write_annotation_pack(
        records,
        args.output_dir,
        target=args.target,
        seed=args.seed,
        ratings_per_item=args.ratings_per_item,
    )
    print(f"[+] Blinded annotation items: {summary['selected_items']}")
    print(f"[+] Empty rating rows: {summary['expected_rating_rows']}")
    print(f"[+] Annotation output: {args.output_dir}")


if __name__ == "__main__":
    main()
