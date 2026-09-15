from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import dataclass, fields, replace
import hashlib
import json
import math
from pathlib import Path
from statistics import mean, median, pstdev
import tempfile
from typing import Any, Iterable

import yaml

from as_engine.annotation import write_annotation_pack
from as_engine.cli import CSV_COLUMNS, flatten_for_csv
from as_engine.evidence import extract_evidence, present
from as_engine.parser import NormalizedAlert, iter_eve_alerts
from as_engine.rule_catalog import RuleCatalog, RuleMatch, RuleMetadata
from as_engine.scoring import (
    ScoringProfile,
    build_score_record,
    calculate_scores,
    load_scoring_profile,
)


EXPERIMENT_SCHEMA_VERSION = 1
COMPONENTS = [
    "entity_completeness",
    "attack_context",
    "outcome_evidence",
    "investigation_evidence",
    "recommended_response",
]


@dataclass(frozen=True)
class Variant:
    name: str
    label: str
    description: str
    enrich: bool
    remove: tuple[str, ...]
    set_values: dict[str, Any]
    withhold_metadata: bool


@dataclass(frozen=True)
class ContextVariant:
    name: str
    label: str
    description: str
    remove: tuple[str, ...]
    set_values: dict[str, Any]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_variants(path: str | Path) -> tuple[str, list[Variant]]:
    with Path(path).open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if data.get("schema_version") != EXPERIMENT_SCHEMA_VERSION:
        raise ValueError("Controlled variant configuration schema_version must be 1")
    experiment_id = str(data.get("experiment_id") or "controlled_evidence")
    raw_scenarios = data.get("scenarios")
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise ValueError("Controlled variant configuration needs a non-empty scenarios list")

    allowed_fields = {field.name for field in fields(NormalizedAlert)} - {"raw"}
    variants: list[Variant] = []
    seen: set[str] = set()
    for raw in raw_scenarios:
        if not isinstance(raw, dict):
            raise ValueError("Every controlled scenario must be a mapping")
        name = str(raw.get("name") or "").strip()
        if not name or name in seen:
            raise ValueError(f"Invalid or duplicate controlled scenario name: {name!r}")
        seen.add(name)
        remove = tuple(str(value) for value in (raw.get("remove") or []))
        set_values = raw.get("set") or {}
        if not isinstance(set_values, dict):
            raise ValueError(f"Scenario {name}: set must be a mapping")
        unknown = (set(remove) | set(set_values)) - allowed_fields
        if unknown:
            raise ValueError(f"Scenario {name}: unknown NormalizedAlert fields {sorted(unknown)}")
        variants.append(
            Variant(
                name=name,
                label=str(raw.get("label") or name.replace("_", " ").title()),
                description=str(raw.get("description") or ""),
                enrich=bool(raw.get("enrich", False)),
                remove=remove,
                set_values=dict(set_values),
                withhold_metadata=bool(raw.get("withhold_metadata", False)),
            )
        )
    required = {"observed", "complete"}
    if not required.issubset(seen):
        raise ValueError(f"Controlled scenarios must include {sorted(required)}")
    return experiment_id, variants


def load_contexts(path: str | Path) -> tuple[str, list[ContextVariant]]:
    with Path(path).open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if data.get("schema_version") != EXPERIMENT_SCHEMA_VERSION:
        raise ValueError("Context variant configuration schema_version must be 1")
    context_set_id = str(data.get("context_set_id") or "post_alert_outcomes")
    raw_contexts = data.get("contexts")
    if not isinstance(raw_contexts, list) or not raw_contexts:
        raise ValueError("Context variant configuration needs a non-empty contexts list")

    allowed_fields = {field.name for field in fields(NormalizedAlert)} - {"raw"}
    contexts: list[ContextVariant] = []
    seen: set[str] = set()
    for raw in raw_contexts:
        if not isinstance(raw, dict):
            raise ValueError("Every controlled context must be a mapping")
        name = str(raw.get("name") or "").strip()
        if not name or name in seen:
            raise ValueError(f"Invalid or duplicate controlled context name: {name!r}")
        seen.add(name)
        remove = tuple(str(value) for value in (raw.get("remove") or []))
        set_values = raw.get("set") or {}
        if not isinstance(set_values, dict):
            raise ValueError(f"Context {name}: set must be a mapping")
        unknown = (set(remove) | set(set_values)) - allowed_fields
        if unknown:
            raise ValueError(f"Context {name}: unknown NormalizedAlert fields {sorted(unknown)}")
        contexts.append(
            ContextVariant(
                name=name,
                label=str(raw.get("label") or name.replace("_", " ").title()),
                description=str(raw.get("description") or ""),
                remove=remove,
                set_values=dict(set_values),
            )
        )
    if "observed" not in seen:
        raise ValueError("Controlled contexts must include observed")
    return context_set_id, contexts


def _complete_alert(alert: NormalizedAlert) -> NormalizedAlert:
    payload = alert.payload_printable
    if not present(payload):
        method = alert.http_method or "GET"
        url = alert.http_url or "/"
        hostname = alert.http_hostname or "unknown.local"
        payload = f"{method} {url} HTTP/1.1\\r\\nHost: {hostname}\\r\\n\\r\\n"
    community_id = alert.community_id
    if not present(community_id):
        token = hashlib.sha256(alert.alert_id.encode()).hexdigest()[:20]
        community_id = f"1:controlled-{token}"
    return replace(
        alert,
        community_id=community_id,
        payload_printable=payload,
        http_user_agent=alert.http_user_agent or "controlled-client/1.0",
    )


def apply_variant(alert: NormalizedAlert, variant: Variant) -> NormalizedAlert:
    result = _complete_alert(alert) if variant.enrich else alert
    changes: dict[str, Any] = {name: None for name in variant.remove}
    changes.update(variant.set_values)
    case_token = f"{alert.alert_id}|{variant.name}"
    changes["alert_id"] = hashlib.sha256(case_token.encode()).hexdigest()
    return replace(result, **changes)


def apply_context(alert: NormalizedAlert, context: ContextVariant) -> NormalizedAlert:
    changes: dict[str, Any] = {name: None for name in context.remove}
    changes.update(context.set_values)
    token = f"{alert.alert_id}|context|{context.name}"
    changes["alert_id"] = hashlib.sha256(token.encode()).hexdigest()
    return replace(alert, **changes)


def field_presence_baseline(alert: NormalizedAlert, rule: RuleMetadata | None) -> float:
    """Unweighted coverage baseline over unique analyst-facing fields.

    This deliberately ignores the dimension structure and weights. It is a
    transparent comparator for testing whether the configured score behaves
    differently from simply counting populated fields.
    """

    is_http = alert.app_proto in {"http", "http1", "http2"} or any(
        present(value)
        for value in (
            alert.http_hostname,
            alert.http_url,
            alert.http_method,
            alert.http_status,
        )
    )
    ports_apply = (alert.proto or "").upper() in {"TCP", "UDP"}
    checks: list[bool] = [
        present(alert.client_ip),
        present(alert.server_ip),
        present(alert.proto) or present(alert.app_proto),
        present(alert.flow_id),
        present(alert.signature),
        present(alert.category),
        rule is not None and present(rule.attack_type),
        present(alert.community_id),
        present(alert.payload_printable),
    ]
    if ports_apply:
        checks.extend([present(alert.client_port), present(alert.server_port)])
    if is_http:
        checks.extend(
            [
                present(alert.http_hostname),
                present(alert.http_url),
                present(alert.http_method),
                present(alert.http_status),
                present(alert.http_user_agent),
            ]
        )
    if rule is not None:
        if rule.cve_applicable:
            checks.append(bool(rule.cve))
        if rule.mitre_applicable:
            checks.append(bool(rule.mitre))
        phases = {action.phase for action in rule.recommended_actions}
        checks.extend(phase in phases for phase in ("validate", "scope", "contain"))
        checks.append(any(action.evidence for action in rule.recommended_actions))
    else:
        # Metadata-backed context, playbook coverage, and evidence linkage.
        checks.extend([False, False, False, False, False])
    return sum(checks) / len(checks) if checks else 0.0


def _stats(values: Iterable[float]) -> dict[str, float]:
    numbers = list(values)
    return {
        "mean": round(mean(numbers), 6),
        "median": round(median(numbers), 6),
        "std": round(pstdev(numbers), 6),
        "minimum": round(min(numbers), 6),
        "maximum": round(max(numbers), 6),
    }


def _kendall_tau_b(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise ValueError("Kendall tau inputs must have equal length")
    concordant = discordant = tie_left = tie_right = 0
    for first in range(len(left) - 1):
        for second in range(first + 1, len(left)):
            dx = (left[first] > left[second]) - (left[first] < left[second])
            dy = (right[first] > right[second]) - (right[first] < right[second])
            if dx == 0 and dy == 0:
                continue
            if dx == 0:
                tie_left += 1
            elif dy == 0:
                tie_right += 1
            elif dx == dy:
                concordant += 1
            else:
                discordant += 1
    denominator = math.sqrt(
        (concordant + discordant + tie_left)
        * (concordant + discordant + tie_right)
    )
    return (concordant - discordant) / denominator if denominator else 1.0


def _top_fraction_overlap(
    case_ids: list[str], reference: list[float], candidate: list[float], fraction: float = 0.20
) -> float:
    count = max(1, math.ceil(len(case_ids) * fraction))
    ref_order = sorted(range(len(case_ids)), key=lambda i: (-reference[i], case_ids[i]))
    new_order = sorted(range(len(case_ids)), key=lambda i: (-candidate[i], case_ids[i]))
    return len(set(ref_order[:count]) & set(new_order[:count])) / count


def _sensitivity_rows(
    records: list[dict[str, Any]], profile: ScoringProfile
) -> list[dict[str, Any]]:
    case_ids = [record["experiment"]["case_id"] for record in records]
    reference = [float(record["actionability_score"]) for record in records]
    rows: list[dict[str, Any]] = []
    for magnitude in (0.10, 0.20, 0.30):
        for component in COMPONENTS:
            for direction in (-1, 1):
                weights = dict(profile.actionability_weights)
                weights[component] *= 1.0 + direction * magnitude
                total = sum(weights.values())
                weights = {name: value / total for name, value in weights.items()}
                candidate = [
                    sum(
                        weights[name] * float(record["subscores"][name])
                        for name in COMPONENTS
                    )
                    for record in records
                ]
                deltas = [abs(a - b) for a, b in zip(reference, candidate)]
                rows.append(
                    {
                        "magnitude": magnitude,
                        "component": component,
                        "direction": "increase" if direction > 0 else "decrease",
                        "kendall_tau_b": round(_kendall_tau_b(reference, candidate), 6),
                        "top_20_overlap": round(
                            _top_fraction_overlap(case_ids, reference, candidate), 6
                        ),
                        "mean_absolute_delta": round(mean(deltas), 6),
                        "maximum_absolute_delta": round(max(deltas), 6),
                    }
                )
    return rows


def _comparator_summary(records: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    case_ids = [record["experiment"]["case_id"] for record in records]
    primary = [float(record["actionability_score"]) for record in records]
    comparators = {
        "equal_weight": [
            float(record["experiment"]["equal_weight_actionability"])
            for record in records
        ],
        "field_presence": [
            float(record["experiment"]["field_presence_baseline"])
            for record in records
        ],
    }
    return {
        name: {
            "kendall_tau_b": round(_kendall_tau_b(primary, values), 6),
            "top_20_overlap": round(
                _top_fraction_overlap(case_ids, primary, values), 6
            ),
            "mean_absolute_delta": round(
                mean(abs(left - right) for left, right in zip(primary, values)), 6
            ),
        }
        for name, values in comparators.items()
    }


def _ablation_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_case = {
        (
            record["experiment"]["base_context_id"],
            record["experiment"]["evidence_profile"],
        ): record
        for record in records
    }
    ablations = [
        "no_payload",
        "no_community_id",
        "no_outcome",
        "no_flow_identity",
        "no_http_context",
        "no_role_resolution",
        "unknown_metadata",
    ]
    rows: list[dict[str, Any]] = []
    base_ids = sorted({record["experiment"]["base_context_id"] for record in records})
    for scenario in ablations:
        deltas: list[float] = []
        for base_id in base_ids:
            complete = by_case[(base_id, "complete")]
            candidate = by_case[(base_id, scenario)]
            deltas.append(
                float(complete["actionability_score"])
                - float(candidate["actionability_score"])
            )
        rows.append(
            {
                "scenario": scenario,
                "case_count": len(deltas),
                "mean_score_drop": round(mean(deltas), 6),
                "minimum_score_drop": round(min(deltas), 6),
                "maximum_score_drop": round(max(deltas), 6),
            }
        )
    return rows


def _evidence_profile_summary(
    records: list[dict[str, Any]], variants: list[Variant]
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for variant in variants:
        selected = [
            record
            for record in records
            if record["experiment"]["evidence_profile"] == variant.name
        ]
        summaries.append(
            {
                "scenario": variant.name,
                "label": variant.label,
                "description": variant.description,
                "case_count": len(selected),
                "actionability": _stats(
                    float(record["actionability_score"]) for record in selected
                ),
                "risk": _stats(float(record["risk_score"]) for record in selected),
                "equal_weight_actionability": _stats(
                    float(record["experiment"]["equal_weight_actionability"])
                    for record in selected
                ),
                "field_presence_baseline": _stats(
                    float(record["experiment"]["field_presence_baseline"])
                    for record in selected
                ),
                "actionability_levels": dict(
                    Counter(record["actionability_level"] for record in selected)
                ),
                "risk_levels": dict(Counter(record["risk_level"] for record in selected)),
                "outcomes": dict(Counter(record["outcome_class"] for record in selected)),
                "component_means": {
                    name: round(mean(float(record["subscores"][name]) for record in selected), 6)
                    for name in COMPONENTS
                },
            }
        )
    return summaries


def _context_summary(
    records: list[dict[str, Any]], contexts: list[ContextVariant]
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for context in contexts:
        selected = [
            record
            for record in records
            if record["experiment"]["context"] == context.name
        ]
        summaries.append(
            {
                "context": context.name,
                "label": context.label,
                "description": context.description,
                "case_count": len(selected),
                "actionability": _stats(
                    float(record["actionability_score"]) for record in selected
                ),
                "risk": _stats(float(record["risk_score"]) for record in selected),
                "outcomes": dict(Counter(record["outcome_class"] for record in selected)),
                "component_means": {
                    name: round(
                        mean(float(record["subscores"][name]) for record in selected),
                        6,
                    )
                    for name in COMPONENTS
                },
            }
        )
    return summaries


def _context_profile_rows(
    records: list[dict[str, Any]],
    contexts: list[ContextVariant],
    variants: list[Variant],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for context in contexts:
        for variant in variants:
            selected = [
                record
                for record in records
                if record["experiment"]["context"] == context.name
                and record["experiment"]["evidence_profile"] == variant.name
            ]
            rows.append(
                {
                    "context": context.name,
                    "context_label": context.label,
                    "evidence_profile": variant.name,
                    "evidence_profile_label": variant.label,
                    "case_count": len(selected),
                    "actionability_mean": _stats(
                        float(record["actionability_score"]) for record in selected
                    )["mean"],
                    "risk_mean": _stats(
                        float(record["risk_score"]) for record in selected
                    )["mean"],
                    "outcomes": json.dumps(
                        dict(Counter(record["outcome_class"] for record in selected)),
                        sort_keys=True,
                    ),
                }
            )
    return rows


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _validate_figure_file(path: Path, extension: str) -> None:
    signatures = {
        "pdf": b"%PDF-",
        "png": b"\x89PNG\r\n\x1a\n",
    }
    expected = signatures[extension]
    if not path.exists() or path.stat().st_size < len(expected):
        raise OSError(f"Generated figure is empty or missing: {path}")
    with path.open("rb") as handle:
        header = handle.read(len(expected))
    if header != expected:
        raise OSError(f"Generated figure has an invalid {extension.upper()} signature: {path}")


def _write_figures(
    output_dir: Path,
    records: list[dict[str, Any]],
    scenario_summaries: list[dict[str, Any]],
    context_summaries: list[dict[str, Any]],
    context_profile_rows: list[dict[str, Any]],
    ablations: list[dict[str, Any]],
    sensitivity: list[dict[str, Any]],
    profile: ScoringProfile,
) -> list[str]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    figure_dir = output_dir / "figures"
    figure_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update(
        {
            "font.size": 9,
            "axes.titlesize": 11,
            "axes.labelsize": 9,
            "legend.fontsize": 7,
            "figure.dpi": 140,
            "savefig.dpi": 300,
        }
    )
    palette = plt.get_cmap("tab20")
    generated: list[str] = []

    def save(name: str) -> None:
        figure = plt.gcf()
        try:
            for extension in ("png", "pdf"):
                path = figure_dir / f"{name}.{extension}"
                saved = False
                last_error: Exception | None = None
                for _attempt in range(2):
                    with tempfile.NamedTemporaryFile(
                        prefix=f".{name}.",
                        suffix=f".{extension}.tmp",
                        dir=figure_dir,
                        delete=False,
                    ) as handle:
                        temporary_path = Path(handle.name)
                    try:
                        figure.savefig(temporary_path, format=extension, bbox_inches="tight")
                        _validate_figure_file(temporary_path, extension)
                        temporary_path.replace(path)
                        saved = True
                        break
                    except Exception as error:  # pragma: no cover - backend/filesystem dependent
                        last_error = error
                    finally:
                        temporary_path.unlink(missing_ok=True)
                if not saved:
                    raise OSError(f"Could not write a valid figure: {path}") from last_error
                generated.append(str(path.relative_to(output_dir)))
        finally:
            plt.close(figure)

    labels = [item["label"] for item in scenario_summaries]
    means = [item["actionability"]["mean"] for item in scenario_summaries]
    lows = [m - item["actionability"]["minimum"] for m, item in zip(means, scenario_summaries)]
    highs = [item["actionability"]["maximum"] - m for m, item in zip(means, scenario_summaries)]
    positions = np.arange(len(labels))
    plt.figure(figsize=(7.2, 5.2))
    plt.barh(positions, means, xerr=np.array([lows, highs]), color="#4472C4", alpha=0.88, capsize=3)
    plt.yticks(positions, labels)
    plt.gca().invert_yaxis()
    plt.xlim(0, 1.08)
    plt.xlabel("Actionability score (mean; range across 50 base-context vignettes)")
    plt.title("Controlled evidence profiles")
    plt.grid(axis="x", alpha=0.22)
    for position, value in zip(positions, means):
        plt.text(min(value + 0.012, 1.0), position, f"{value:.3f}", va="center", fontsize=8)
    save("actionability_by_scenario")

    matrix = np.array(
        [[item["component_means"][name] for name in COMPONENTS] for item in scenario_summaries]
    )
    plt.figure(figsize=(7.4, 5.4))
    image = plt.imshow(matrix, vmin=0, vmax=1, cmap="YlGnBu", aspect="auto")
    plt.colorbar(image, label="Mean component score")
    plt.xticks(
        np.arange(len(COMPONENTS)),
        ["Entity", "Context", "Outcome", "Investigation", "Response"],
        rotation=25,
        ha="right",
    )
    plt.yticks(np.arange(len(labels)), labels)
    for row in range(matrix.shape[0]):
        for column in range(matrix.shape[1]):
            color = "white" if matrix[row, column] > 0.58 else "black"
            plt.text(column, row, f"{matrix[row, column]:.2f}", ha="center", va="center", color=color, fontsize=7)
    plt.title("Evidence-component response to controlled degradation")
    save("component_heatmap")

    plt.figure(figsize=(7.4, 5.3))
    for index, summary in enumerate(context_summaries):
        selected = [
            record for record in records
            if record["experiment"]["context"] == summary["context"]
        ]
        plt.scatter(
            [record["actionability_score"] for record in selected],
            [record["risk_score"] for record in selected],
            label=summary["label"],
            color=palette(index),
            s=32,
            alpha=0.75,
            edgecolors="white",
            linewidths=0.35,
        )
    plt.axvline(profile.actionability_thresholds["high"], color="black", linestyle="--", linewidth=0.8)
    plt.axhline(profile.risk_thresholds["high"], color="black", linestyle="--", linewidth=0.8)
    plt.xlim(0, 1.02)
    plt.ylim(0, 1.02)
    plt.xlabel("Actionability score")
    plt.ylabel("Risk score")
    plt.title("Actionability and risk remain separate signals")
    plt.grid(alpha=0.18)
    plt.legend(ncol=2, loc="lower left", frameon=True)
    save("actionability_risk_matrix")

    profile_names = [item["scenario"] for item in scenario_summaries]
    context_names = [item["context"] for item in context_summaries]
    lookup = {
        (row["context"], row["evidence_profile"]): row["actionability_mean"]
        for row in context_profile_rows
    }
    context_matrix = np.array(
        [[lookup[(context, profile_name)] for profile_name in profile_names] for context in context_names]
    )
    plt.figure(figsize=(7.5, 3.8))
    image = plt.imshow(context_matrix, vmin=0, vmax=1, cmap="YlGnBu", aspect="auto")
    plt.colorbar(image, label="Mean Actionability score")
    plt.xticks(
        np.arange(len(profile_names)),
        [item["label"] for item in scenario_summaries],
        rotation=32,
        ha="right",
    )
    plt.yticks(
        np.arange(len(context_names)),
        [item["label"] for item in context_summaries],
    )
    for row in range(context_matrix.shape[0]):
        for column in range(context_matrix.shape[1]):
            color = "white" if context_matrix[row, column] > 0.58 else "black"
            plt.text(
                column,
                row,
                f"{context_matrix[row, column]:.2f}",
                ha="center",
                va="center",
                color=color,
                fontsize=6.5,
            )
    plt.title("Outcome context crossed with evidence availability")
    save("context_profile_heatmap")

    ablation_labels = [row["scenario"].replace("_", " ") for row in ablations]
    ablation_values = [row["mean_score_drop"] for row in ablations]
    plt.figure(figsize=(7.2, 4.2))
    bars = plt.barh(np.arange(len(ablations)), ablation_values, color="#ED7D31")
    plt.yticks(np.arange(len(ablations)), ablation_labels)
    plt.gca().invert_yaxis()
    plt.xlabel("Mean Actionability decrease from complete evidence")
    plt.title("Evidence ablation")
    plt.grid(axis="x", alpha=0.22)
    for bar, value in zip(bars, ablation_values):
        plt.text(value + 0.004, bar.get_y() + bar.get_height() / 2, f"{value:.3f}", va="center", fontsize=8)
    save("ablation")

    fig, axes = plt.subplots(1, 2, figsize=(7.4, 3.4), sharex=True)
    magnitudes = (0.10, 0.20, 0.30)
    tau_groups = [[row["kendall_tau_b"] for row in sensitivity if row["magnitude"] == value] for value in magnitudes]
    overlap_groups = [[row["top_20_overlap"] for row in sensitivity if row["magnitude"] == value] for value in magnitudes]
    axes[0].boxplot(tau_groups, tick_labels=["10%", "20%", "30%"], widths=0.55)
    axes[1].boxplot(overlap_groups, tick_labels=["10%", "20%", "30%"], widths=0.55)
    axes[0].set_ylabel("Kendall tau-b")
    axes[1].set_ylabel("Top-20% overlap")
    for axis in axes:
        axis.set_xlabel("Single-weight perturbation")
        axis.set_ylim(0.94, 1.005)
        axis.grid(axis="y", alpha=0.22)
    fig.suptitle("Ranking sensitivity to weight perturbation")
    save("weight_sensitivity")

    chosen_sid = 2025756
    chosen_scenarios = ["complete", "observed", "no_outcome", "no_http_context", "unknown_metadata"]
    selected = [
        record for scenario in chosen_scenarios for record in records
        if record["experiment"]["base_sid"] == chosen_sid
        and record["experiment"]["context"] == "observed"
        and record["experiment"]["evidence_profile"] == scenario
    ]
    if selected:
        plt.figure(figsize=(7.3, 3.7))
        left = np.zeros(len(selected))
        component_colors = ["#4E79A7", "#59A14F", "#F28E2B", "#E15759", "#B07AA1"]
        for component, color in zip(COMPONENTS, component_colors):
            values = np.array(
                [record["subscores"][component] * profile.actionability_weights[component] for record in selected]
            )
            plt.barh(np.arange(len(selected)), values, left=left, label=component.replace("_", " "), color=color)
            left += values
        plt.yticks(
            np.arange(len(selected)),
            [record["experiment"]["evidence_profile"].replace("_", " ") for record in selected],
        )
        plt.gca().invert_yaxis()
        plt.xlim(0, 1.03)
        plt.xlabel("Weighted Actionability contribution")
        plt.title(f"Score decomposition for SID {chosen_sid}")
        for position, value in enumerate(left):
            plt.text(value + 0.008, position, f"{value:.3f}", va="center", fontsize=8)
        plt.legend(ncol=2, loc="lower center", bbox_to_anchor=(0.5, -0.43))
        save("score_decomposition_sid_2025756")

    return generated


def run_experiment(args: argparse.Namespace) -> dict[str, Any]:
    eve_path = Path(args.eve)
    rules_path = Path(args.rules)
    scoring_path = Path(args.scoring)
    variants_path = Path(args.variants)
    contexts_path = Path(args.contexts)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    experiment_id, variants = load_variants(variants_path)
    context_set_id, contexts = load_contexts(contexts_path)
    alerts = list(iter_eve_alerts(str(eve_path)))
    if not alerts:
        raise ValueError("The controlled experiment requires at least one EVE alert")
    catalog = RuleCatalog.from_yaml(str(rules_path))
    profile = load_scoring_profile(str(scoring_path), args.profile)
    equal_profile = load_scoring_profile(str(scoring_path), "equal_weight")

    records: list[dict[str, Any]] = []
    flat_rows: list[dict[str, Any]] = []
    for base_index, base_alert in enumerate(alerts, start=1):
        # Include a stable alert token so repeated occurrences of one SID never
        # collide in case IDs or ablation lookups.
        sid_token = base_alert.sid if base_alert.sid is not None else "missing"
        seed_id = f"sid-{sid_token}-{base_alert.alert_id[:12]}"
        for context_index, context in enumerate(contexts, start=1):
            contextual_alert = apply_context(base_alert, context)
            base_context_id = f"{seed_id}--{context.name}"
            for profile_index, variant in enumerate(variants, start=1):
                alert = apply_variant(contextual_alert, variant)
                match = (
                    RuleMatch(
                        None,
                        "withheld_metadata",
                        "SID metadata withheld by controlled evidence profile",
                    )
                    if variant.withhold_metadata
                    else catalog.lookup_with_quality(alert.sid, alert.rev)
                )
                evidence = extract_evidence(alert, match.rule)
                actionability, risk = calculate_scores(evidence, profile)
                equal_actionability, equal_risk = calculate_scores(evidence, equal_profile)
                coverage = field_presence_baseline(alert, match.rule)
                record = build_score_record(
                    alert.to_dict(), evidence, actionability, risk, profile, match
                )
                case_id = f"{base_context_id}--{variant.name}"
                record["experiment"] = {
                    "experiment_id": experiment_id,
                    "context_set_id": context_set_id,
                    "case_id": case_id,
                    "presentation_id": case_id,
                    "archetype_id": seed_id,
                    "seed_id": seed_id,
                    "base_context_id": base_context_id,
                    "base_alert_id": base_alert.alert_id,
                    "base_sid": base_alert.sid,
                    "base_index": base_index,
                    "context": context.name,
                    "context_index": context_index,
                    "context_label": context.label,
                    "context_description": context.description,
                    # scenario remains as a compatibility alias for evidence profile.
                    "scenario": variant.name,
                    "scenario_index": profile_index,
                    "scenario_label": variant.label,
                    "scenario_description": variant.description,
                    "evidence_profile": variant.name,
                    "evidence_profile_index": profile_index,
                    "evidence_profile_label": variant.label,
                    "evidence_profile_description": variant.description,
                    "controlled_transformation": not (
                        context.name == "observed" and variant.name == "observed"
                    ),
                    "equal_weight_actionability": round(equal_actionability, 6),
                    "equal_weight_risk": round(equal_risk, 6),
                    "field_presence_baseline": round(coverage, 6),
                }
                records.append(record)
                flat = {
                    "experiment_id": experiment_id,
                    "context_set_id": context_set_id,
                    "case_id": case_id,
                    "presentation_id": case_id,
                    "archetype_id": seed_id,
                    "seed_id": seed_id,
                    "base_context_id": base_context_id,
                    "base_alert_id": base_alert.alert_id,
                    "base_sid": base_alert.sid,
                    "context": context.name,
                    "context_label": context.label,
                    "scenario": variant.name,
                    "scenario_label": variant.label,
                    "evidence_profile": variant.name,
                    "evidence_profile_label": variant.label,
                    "controlled_transformation": record["experiment"]["controlled_transformation"],
                    "equal_weight_actionability": round(equal_actionability, 6),
                    "equal_weight_risk": round(equal_risk, 6),
                    "field_presence_baseline": round(coverage, 6),
                }
                flat.update(flatten_for_csv(record))
                flat_rows.append(flat)

    scenario_summaries = _evidence_profile_summary(records, variants)
    context_summaries = _context_summary(records, contexts)
    context_profile_rows = _context_profile_rows(records, contexts, variants)
    ablations = _ablation_rows(records)
    sensitivity = _sensitivity_rows(records, profile)
    comparator_results = _comparator_summary(records)
    figure_files: list[str] = []
    if not args.no_figures:
        figure_files = _write_figures(
            output_dir,
            records,
            scenario_summaries,
            context_summaries,
            context_profile_rows,
            ablations,
            sensitivity,
            profile,
        )

    with (output_dir / "controlled_cases.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    annotation_summary = None
    if args.annotation_target > 0:
        annotation_summary = write_annotation_pack(
            records,
            output_dir / "annotation",
            target=args.annotation_target,
            seed=args.annotation_seed,
            ratings_per_item=args.ratings_per_item,
        )
    experiment_columns = [
        "experiment_id",
        "context_set_id",
        "case_id",
        "presentation_id",
        "archetype_id",
        "seed_id",
        "base_context_id",
        "base_alert_id",
        "base_sid",
        "context",
        "context_label",
        "scenario",
        "scenario_label",
        "evidence_profile",
        "evidence_profile_label",
        "controlled_transformation",
        "equal_weight_actionability",
        "equal_weight_risk",
        "field_presence_baseline",
    ]
    _write_csv(output_dir / "controlled_cases.csv", flat_rows, experiment_columns + CSV_COLUMNS)
    _write_csv(
        output_dir / "ablation.csv",
        ablations,
        ["scenario", "case_count", "mean_score_drop", "minimum_score_drop", "maximum_score_drop"],
    )
    _write_csv(
        output_dir / "sensitivity.csv",
        sensitivity,
        [
            "magnitude",
            "component",
            "direction",
            "kendall_tau_b",
            "top_20_overlap",
            "mean_absolute_delta",
            "maximum_absolute_delta",
        ],
    )
    comparator_rows = [
        {"comparator": name, **values}
        for name, values in comparator_results.items()
    ]
    _write_csv(
        output_dir / "comparators.csv",
        comparator_rows,
        list(comparator_rows[0]),
    )
    summary_rows: list[dict[str, Any]] = []
    for item in scenario_summaries:
        summary_rows.append(
            {
                "scenario": item["scenario"],
                "label": item["label"],
                "case_count": item["case_count"],
                "actionability_mean": item["actionability"]["mean"],
                "actionability_std": item["actionability"]["std"],
                "actionability_min": item["actionability"]["minimum"],
                "actionability_max": item["actionability"]["maximum"],
                "risk_mean": item["risk"]["mean"],
                "field_presence_mean": item["field_presence_baseline"]["mean"],
                **{f"mean_{name}": item["component_means"][name] for name in COMPONENTS},
            }
        )
    _write_csv(
        output_dir / "variant_summary.csv",
        summary_rows,
        list(summary_rows[0]),
    )
    context_rows = [
        {
            "context": item["context"],
            "label": item["label"],
            "case_count": item["case_count"],
            "actionability_mean": item["actionability"]["mean"],
            "actionability_std": item["actionability"]["std"],
            "actionability_min": item["actionability"]["minimum"],
            "actionability_max": item["actionability"]["maximum"],
            "risk_mean": item["risk"]["mean"],
            "outcomes": json.dumps(item["outcomes"], sort_keys=True),
        }
        for item in context_summaries
    ]
    _write_csv(output_dir / "context_summary.csv", context_rows, list(context_rows[0]))
    _write_csv(
        output_dir / "context_profile_summary.csv",
        context_profile_rows,
        list(context_profile_rows[0]),
    )

    sensitivity_by_magnitude = {}
    for magnitude in (0.10, 0.20, 0.30):
        selected = [row for row in sensitivity if row["magnitude"] == magnitude]
        sensitivity_by_magnitude[str(magnitude)] = {
            "kendall_tau_b": _stats(row["kendall_tau_b"] for row in selected),
            "top_20_overlap": _stats(row["top_20_overlap"] for row in selected),
            "mean_absolute_delta": _stats(row["mean_absolute_delta"] for row in selected),
        }

    summary = {
        "schema_version": EXPERIMENT_SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "design": {
            "observed_seed_count": len(alerts),
            "base_alert_count": len(alerts),
            "base_archetype_count": len(
                {record["experiment"]["archetype_id"] for record in records}
            ),
            "outcome_context_count": len(contexts),
            "base_context_vignette_count": len(
                {record["experiment"]["base_context_id"] for record in records}
            ),
            "evidence_profile_count": len(variants),
            "scenario_count": len(variants),
            "presentation_count": len(records),
            "controlled_case_count": len(records),
            "statistical_unit": (
                "alert presentation nested within a controlled base-context vignette "
                "derived from an observed Suricata seed"
            ),
            "claim_boundary": (
                "Controlled post-alert sensitivity and functional behavior only; the 500 "
                "presentations are not 500 independent attacks, production alerts, or analyst "
                "judgements."
            ),
        },
        "profiles": {
            "primary": profile.name,
            "equal_weight_comparator": equal_profile.name,
            "field_presence_comparator": "unweighted_unique_field_coverage",
        },
        "comparator_results": comparator_results,
        "overall": {
            "actionability": _stats(float(record["actionability_score"]) for record in records),
            "risk": _stats(float(record["risk_score"]) for record in records),
            "outcomes": dict(Counter(record["outcome_class"] for record in records)),
        },
        "evidence_profiles": scenario_summaries,
        "scenarios": scenario_summaries,
        "contexts": context_summaries,
        "ablation": ablations,
        "sensitivity": sensitivity_by_magnitude,
        "annotation_protocol": annotation_summary,
        "provenance": {
            "eve_path": str(eve_path),
            "eve_sha256": _sha256_file(eve_path),
            "rules_path": str(rules_path),
            "rules_sha256": _sha256_file(rules_path),
            "scoring_path": str(scoring_path),
            "scoring_sha256": _sha256_file(scoring_path),
            "variants_path": str(variants_path),
            "variants_sha256": _sha256_file(variants_path),
            "contexts_path": str(contexts_path),
            "contexts_sha256": _sha256_file(contexts_path),
        },
        "figures": figure_files,
    }
    with (output_dir / "experiment_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return summary


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run controlled evidence-degradation, ablation, and weight-sensitivity experiments."
    )
    parser.add_argument("--eve", default="logs/suricata/eve.json")
    parser.add_argument("--rules", default="rules/rule_metadata.yaml")
    parser.add_argument("--scoring", default="config/scoring-v2.yaml")
    parser.add_argument("--variants", default="config/controlled_variants.yaml")
    parser.add_argument("--contexts", default="config/context_variants.yaml")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--output-dir", default="runs/experiments/controlled")
    parser.add_argument("--annotation-target", type=int, default=300)
    parser.add_argument("--annotation-seed", type=int, default=2026)
    parser.add_argument("--ratings-per-item", type=int, default=3)
    parser.add_argument("--no-figures", action="store_true")
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    summary = run_experiment(args)
    print(f"[+] Observed Suricata seeds: {summary['design']['observed_seed_count']}")
    print(f"[+] Base-context vignettes: {summary['design']['base_context_vignette_count']}")
    print(f"[+] Evidence profiles: {summary['design']['evidence_profile_count']}")
    print(f"[+] Controlled presentations: {summary['design']['presentation_count']}")
    if summary["annotation_protocol"] is not None:
        print(f"[+] Blinded annotation items: {summary['annotation_protocol']['selected_items']}")
    print(f"[+] Actionability range: {summary['overall']['actionability']['minimum']:.3f}--{summary['overall']['actionability']['maximum']:.3f}")
    print(f"[+] Experiment output: {args.output_dir}")


if __name__ == "__main__":
    main()
