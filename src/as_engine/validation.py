from __future__ import annotations

import argparse
from collections import Counter
import csv
from pathlib import Path
from typing import Any

import yaml


class ValidationFailure(ValueError):
    pass


def validate_scores(scores_path: str, truth_path: str) -> list[str]:
    with open(scores_path, "r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    with open(truth_path, "r", encoding="utf-8") as handle:
        truth = yaml.safe_load(handle) or {}

    if not isinstance(truth, dict) or truth.get("schema_version") != 1:
        raise ValidationFailure("Ground-truth schema_version must be 1")

    expected = truth.get("expected_alerts", [])
    if not isinstance(expected, list):
        raise ValidationFailure("expected_alerts must be a list")

    errors: list[str] = []
    expected_sids: set[int] = set()
    actual_counts = Counter(int(row["sid"]) for row in rows if row.get("sid"))

    for item in expected:
        sid = int(item["sid"])
        expected_sids.add(sid)
        expected_count = int(item.get("count", 1))
        actual_count = actual_counts.get(sid, 0)
        if actual_count != expected_count:
            errors.append(f"SID {sid}: expected {expected_count} alert(s), found {actual_count}")
            continue

        matching = [row for row in rows if int(row["sid"]) == sid]
        for field in (
            "attacker_candidate",
            "victim_candidate",
            "alert_direction",
            "outcome_class",
            "rule_match_quality",
        ):
            expected_value = item.get(field)
            if expected_value is None:
                continue
            unexpected = sorted({row.get(field, "") for row in matching if row.get(field) != str(expected_value)})
            if unexpected:
                errors.append(
                    f"SID {sid}: expected {field}={expected_value!r}, found {unexpected!r}"
                )

    if not truth.get("allow_unexpected_sids", False):
        unexpected_sids = sorted(set(actual_counts) - expected_sids)
        if unexpected_sids:
            errors.append(f"Unexpected SIDs: {unexpected_sids}")
    return errors


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate scored alerts against ground truth.")
    parser.add_argument("--scores", required=True)
    parser.add_argument("--truth", required=True)
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    if not Path(args.scores).exists():
        raise FileNotFoundError(args.scores)
    errors = validate_scores(args.scores, args.truth)
    if errors:
        print("[-] Ground-truth validation failed:")
        for error in errors:
            print(f"    - {error}")
        raise SystemExit(1)
    print("[+] Ground-truth validation passed")


if __name__ == "__main__":
    main()
