from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
import math
from pathlib import Path
import random
from statistics import mean, median
from typing import Any, Callable


LIKERT_FIELDS = [
    "actionability_likert_1_5",
    "understands_event_1_5",
    "understands_outcome_1_5",
    "knows_next_action_1_5",
    "confidence_1_5",
]
CLASSES = ("actionable", "non_actionable", "unsure")


def _read_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _rank(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(order):
        end = position + 1
        while end < len(order) and values[order[end]] == values[order[position]]:
            end += 1
        average_rank = (position + 1 + end) / 2.0
        for index in order[position:end]:
            ranks[index] = average_rank
        position = end
    return ranks


def _pearson(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        return float("nan")
    left_mean = mean(left)
    right_mean = mean(right)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))
    denominator = math.sqrt(
        sum((value - left_mean) ** 2 for value in left)
        * sum((value - right_mean) ** 2 for value in right)
    )
    return numerator / denominator if denominator else float("nan")


def spearman(left: list[float], right: list[float]) -> float:
    return _pearson(_rank(left), _rank(right))


def average_precision(scores: list[float], labels: list[int]) -> float:
    positives = sum(labels)
    if positives == 0:
        return float("nan")
    pairs = sorted(zip(scores, labels), key=lambda pair: -pair[0])
    found = processed = 0
    total = 0.0
    position = 0
    while position < len(pairs):
        end = position + 1
        while end < len(pairs) and pairs[end][0] == pairs[position][0]:
            end += 1
        group_positives = sum(label for _, label in pairs[position:end])
        processed += end - position
        found += group_positives
        total += (group_positives / positives) * (found / processed)
        position = end
    return total


def krippendorff_alpha_ordinal(units: list[list[int]]) -> float:
    # Ordinal distance uses the empirical category frequencies, not interval distance.
    units = [ratings for ratings in units if len(ratings) >= 2]
    counts = Counter(value for ratings in units for value in ratings)
    total = sum(counts.values())
    if total < 2:
        return float("nan")
    def distance(a: int, b: int) -> float:
        lo, hi = sorted((a, b))
        return (sum(counts[v] for v in counts if lo <= v <= hi)
                - (counts[lo] + counts[hi]) / 2) ** 2 if lo != hi else 0.0
    observed = sum(
        sum(distance(a, b) for a in ratings for b in ratings) / (len(ratings) - 1)
        for ratings in units
    ) / total
    expected = sum(counts[a] * counts[b] * distance(a, b)
                   for a in counts for b in counts) / (total * (total - 1))
    return 1.0 - observed / expected if expected else float("nan")


def fleiss_kappa(units: list[list[str]]) -> float:
    if not units:
        return float("nan")
    rating_count = len(units[0])
    if rating_count < 2 or any(len(unit) != rating_count for unit in units):
        raise ValueError("Fleiss kappa requires the same number of ratings per item")
    total_ratings = len(units) * rating_count
    category_totals = Counter(value for unit in units for value in unit)
    expected = sum((category_totals[name] / total_ratings) ** 2 for name in CLASSES)
    observed = mean(
        (
            sum(Counter(unit)[name] ** 2 for name in CLASSES) - rating_count
        )
        / (rating_count * (rating_count - 1))
        for unit in units
    )
    return (observed - expected) / (1.0 - expected) if expected < 1.0 else float("nan")


def _percentile(values: list[float], probability: float) -> float:
    finite = sorted(value for value in values if math.isfinite(value))
    if not finite:
        return float("nan")
    position = probability * (len(finite) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return finite[lower]
    fraction = position - lower
    return finite[lower] * (1 - fraction) + finite[upper] * fraction


def _cluster_bootstrap(
    items: list[dict[str, Any]],
    metric: Callable[[list[dict[str, Any]]], float],
    repetitions: int,
    seed: int,
) -> dict[str, float]:
    clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        clusters[str(item["seed_id"])].append(item)
    names = sorted(clusters)
    generator = random.Random(seed)
    estimates: list[float] = []
    for _ in range(repetitions):
        sample: list[dict[str, Any]] = []
        for _ in names:
            sample.extend(clusters[generator.choice(names)])
        estimates.append(metric(sample))
    estimate = metric(items)
    return {
        "estimate": round(estimate, 6),
        "ci95_low": round(_percentile(estimates, 0.025), 6),
        "ci95_high": round(_percentile(estimates, 0.975), 6),
        "bootstrap_repetitions": repetitions,
        "finite_bootstrap_estimates": sum(math.isfinite(v) for v in estimates),
        "cluster_count": len(names),
        "cluster": "seed_id",
    }


def analyze_annotations(
    key_rows: list[dict[str, str]],
    response_rows: list[dict[str, str]],
    minimum_ratings: int = 3,
    bootstrap_repetitions: int = 1000,
    seed: int = 2026,
) -> dict[str, Any]:
    key = {row["item_id"]: row for row in key_rows}
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in response_rows:
        item_id = row.get("item_id", "")
        if item_id not in key:
            raise ValueError(f"Response references unknown item_id {item_id!r}")
        for field in LIKERT_FIELDS:
            try:
                value = int(row.get(field, ""))
            except ValueError as error:
                raise ValueError(f"{item_id}: {field} must be an integer 1--5") from error
            if value not in range(1, 6):
                raise ValueError(f"{item_id}: {field} must be in 1--5")
        if row.get("actionability_class") not in CLASSES:
            raise ValueError(f"{item_id}: invalid actionability_class")
        if row.get("additional_pivot_required") not in {"yes", "no", "unsure"}:
            raise ValueError(f"{item_id}: invalid additional_pivot_required")
        try:
            if not math.isfinite(float(row.get("decision_seconds", ""))) or float(row.get("decision_seconds", "")) <= 0:
                raise ValueError
        except ValueError as error:
            raise ValueError(f"{item_id}: decision_seconds must be positive") from error
        grouped[item_id].append(row)

    missing = sorted(item_id for item_id in key if len(grouped[item_id]) < minimum_ratings)
    if missing:
        raise ValueError(
            f"{len(missing)} items have fewer than {minimum_ratings} complete ratings"
        )

    items: list[dict[str, Any]] = []
    for item_id in sorted(key):
        rows = grouped[item_id]
        classes = Counter(row["actionability_class"] for row in rows)
        majority = classes.most_common(1)[0][0]
        if len(classes) > 1 and classes.most_common(2)[0][1] == classes.most_common(2)[1][1]:
            majority = "unsure"
        item = {
            "item_id": item_id,
            "seed_id": key[item_id]["seed_id"],
            "score": float(key[item_id]["automated_actionability_score"]),
            "equal_weight": float(key[item_id]["equal_weight_actionability"]),
            "field_presence": float(key[item_id]["field_presence_baseline"]),
            "likert": median(int(row["actionability_likert_1_5"]) for row in rows),
            "event": median(int(row["understands_event_1_5"]) for row in rows),
            "outcome": median(int(row["understands_outcome_1_5"]) for row in rows),
            "next_action": median(int(row["knows_next_action_1_5"]) for row in rows),
            "confidence": median(int(row["confidence_1_5"]) for row in rows),
            "no_pivot_fraction": mean(
                1.0 if row["additional_pivot_required"] == "no" else 0.0
                for row in rows
            ),
            "decision_seconds": median(float(row["decision_seconds"]) for row in rows),
            "majority_class": majority,
        }
        items.append(item)

    def correlation(field: str) -> dict[str, float]:
        return _cluster_bootstrap(
            items,
            lambda sample: spearman(
                [entry["score"] for entry in sample],
                [entry[field] for entry in sample],
            ),
            bootstrap_repetitions,
            seed,
        )

    binary_items = [item for item in items if item["majority_class"] != "unsure"]

    def ap_result(score_field: str) -> dict[str, float]:
        return _cluster_bootstrap(
            binary_items,
            lambda sample: average_precision(
                [entry[score_field] for entry in sample],
                [1 if entry["majority_class"] == "actionable" else 0 for entry in sample],
            ),
            bootstrap_repetitions,
            seed,
        )

    ordinal_units = [
        [int(row["actionability_likert_1_5"]) for row in grouped[item_id]]
        for item_id in sorted(key)
    ]
    class_units = [
        [row["actionability_class"] for row in grouped[item_id]]
        for item_id in sorted(key)
    ]
    return {
        "schema_version": 1,
        "item_count": len(items),
        "rating_count": sum(len(rows) for rows in grouped.values()),
        "minimum_ratings_per_item": minimum_ratings,
        "agreement": {
            "krippendorff_alpha_ordinal": round(
                krippendorff_alpha_ordinal(ordinal_units), 6
            ),
            "fleiss_kappa_actionability_class": round(fleiss_kappa(class_units), 6),
        },
        "criterion_associations": {
            "actionability_likert": correlation("likert"),
            "understands_event": correlation("event"),
            "understands_outcome": correlation("outcome"),
            "knows_next_action": correlation("next_action"),
            "no_pivot_fraction": correlation("no_pivot_fraction"),
            "confidence": correlation("confidence"),
            "decision_seconds": correlation("decision_seconds"),
        },
        "binary_actionability": {
            "included_items": len(binary_items),
            "positive_prevalence": round(
                mean(
                    1.0 if item["majority_class"] == "actionable" else 0.0
                    for item in binary_items
                ),
                6,
            )
            if binary_items
            else None,
            "auprc": {
                "proposed_default": ap_result("score") if binary_items else None,
                "equal_weight": ap_result("equal_weight") if binary_items else None,
                "field_presence": ap_result("field_presence") if binary_items else None,
            },
        },
        "resampling": {
            "method": "non-parametric cluster bootstrap",
            "cluster": "seed_id",
            "repetitions": bootstrap_repetitions,
            "sampling_seed": seed,
        },
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze completed blinded analyst ratings without presentation-level leakage."
    )
    parser.add_argument("--key", required=True)
    parser.add_argument("--responses", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--minimum-ratings", type=int, default=3)
    parser.add_argument("--bootstrap-repetitions", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=2026)
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    result = analyze_annotations(
        _read_csv(args.key),
        _read_csv(args.responses),
        minimum_ratings=args.minimum_ratings,
        bootstrap_repetitions=args.bootstrap_repetitions,
        seed=args.seed,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(f"[+] Analyzed {result['item_count']} items and {result['rating_count']} ratings")
    print(f"[+] Analysis output: {output}")


if __name__ == "__main__":
    main()
