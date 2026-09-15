from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

import yaml


class RuleCatalogError(ValueError):
    pass


@dataclass
class RecommendedAction:
    phase: str
    action: str
    evidence: list[str]
    condition: str | None = None


@dataclass
class RuleMetadata:
    sid: int
    rev: int | None
    name: str | None
    attack_type: str | None
    category: str | None
    severity: int | None
    cve: list[str]
    cve_applicable: bool
    mitre: list[str]
    mitre_applicable: bool
    success_indicators: dict[str, Any]
    recommended_actions: list[RecommendedAction]
    attacker_role: str


@dataclass
class RuleMatch:
    rule: RuleMetadata | None
    quality: str
    warning: str | None = None


def _list_of_strings(value: Any, field_name: str, sid: int) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise RuleCatalogError(f"SID {sid}: {field_name} must be a list of non-empty strings")
    return value


def _parse_actions(value: Any, sid: int) -> list[RecommendedAction]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuleCatalogError(f"SID {sid}: recommended_actions must be a list")

    actions: list[RecommendedAction] = []
    for index, item in enumerate(value):
        if isinstance(item, str):
            if not item.strip():
                raise RuleCatalogError(f"SID {sid}: recommended action {index} is empty")
            actions.append(RecommendedAction("unspecified", item, []))
            continue
        if not isinstance(item, dict):
            raise RuleCatalogError(f"SID {sid}: recommended action {index} must be a string or mapping")
        phase = str(item.get("phase") or "unspecified")
        if phase not in {"validate", "scope", "contain", "recover", "unspecified"}:
            raise RuleCatalogError(
                f"SID {sid}: recommended action {index} has invalid phase {phase!r}"
            )
        action = str(item.get("action") or "").strip()
        if not action:
            raise RuleCatalogError(f"SID {sid}: recommended action {index} has no action text")
        evidence = _list_of_strings(item.get("evidence"), f"recommended_actions[{index}].evidence", sid)
        condition = item.get("condition")
        actions.append(RecommendedAction(phase, action, evidence, str(condition) if condition else None))
    return actions


class RuleCatalog:
    def __init__(self, rules: list[RuleMetadata], provenance: dict[str, Any] | None = None):
        self.by_sid_rev: dict[tuple[int, int | None], RuleMetadata] = {}
        self.by_sid: dict[int, RuleMetadata] = {}
        self.provenance = provenance or {}
        for rule in rules:
            key = (rule.sid, rule.rev)
            if key in self.by_sid_rev:
                raise RuleCatalogError(f"Duplicate SID/revision metadata: {rule.sid}/{rule.rev}")
            self.by_sid_rev[key] = rule
            if rule.sid in self.by_sid:
                raise RuleCatalogError(
                    f"SID {rule.sid} appears more than once; SID-only fallback would be ambiguous"
                )
            self.by_sid[rule.sid] = rule

    @classmethod
    def from_yaml(cls, path: str) -> "RuleCatalog":
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise RuleCatalogError("Rule metadata root must be a mapping")
        if data.get("schema_version") != 2:
            raise RuleCatalogError("Rule metadata schema_version must be 2")
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise RuleCatalogError("rules must be a list")

        rules: list[RuleMetadata] = []
        for item in raw_rules:
            if not isinstance(item, dict) or "sid" not in item:
                raise RuleCatalogError("Every rule metadata entry must be a mapping with a SID")
            sid = int(item["sid"])
            if sid <= 0:
                raise RuleCatalogError(f"Invalid SID: {sid}")
            rev = item.get("rev")
            if rev is not None:
                rev = int(rev)
                if rev < 0:
                    raise RuleCatalogError(f"SID {sid}: revision cannot be negative")
            severity = item.get("severity")
            if severity is not None:
                severity = int(severity)
                if severity not in {1, 2, 3, 4}:
                    raise RuleCatalogError(f"SID {sid}: severity must be 1, 2, 3, or 4")

            cve = _list_of_strings(item.get("cve"), "cve", sid)
            mitre = _list_of_strings(item.get("mitre"), "mitre", sid)
            invalid_cve = [value for value in cve if re.fullmatch(r"CVE-\d{4}-\d{4,}", value) is None]
            if invalid_cve:
                raise RuleCatalogError(f"SID {sid}: invalid CVE IDs: {invalid_cve}")
            invalid_mitre = [value for value in mitre if re.fullmatch(r"T\d{4}(?:\.\d{3})?", value) is None]
            if invalid_mitre:
                raise RuleCatalogError(f"SID {sid}: invalid MITRE technique IDs: {invalid_mitre}")

            indicators = item.get("success_indicators") or {}
            if not isinstance(indicators, dict):
                raise RuleCatalogError(f"SID {sid}: success_indicators must be a mapping")
            for name in ("http_status_success", "http_status_failure"):
                statuses = indicators.get(name, [])
                if not isinstance(statuses, list) or any(not isinstance(status, int) or not 100 <= status <= 599 for status in statuses):
                    raise RuleCatalogError(f"SID {sid}: {name} must contain valid HTTP status codes")
            for name in ("payload_contains_success", "payload_contains_failure"):
                _list_of_strings(indicators.get(name), f"success_indicators.{name}", sid)

            attacker_role = str(item.get("attacker_role") or "client")
            if attacker_role not in {"client", "server", "unknown"}:
                raise RuleCatalogError(f"SID {sid}: attacker_role must be client, server, or unknown")
            for applicability_field in ("cve_applicable", "mitre_applicable"):
                if applicability_field in item and not isinstance(item[applicability_field], bool):
                    raise RuleCatalogError(f"SID {sid}: {applicability_field} must be boolean")

            rules.append(
                RuleMetadata(
                    sid=sid,
                    rev=rev,
                    name=item.get("name"),
                    attack_type=item.get("attack_type"),
                    category=item.get("category"),
                    severity=severity,
                    cve=cve,
                    cve_applicable=bool(item.get("cve_applicable", True)),
                    mitre=mitre,
                    mitre_applicable=bool(item.get("mitre_applicable", True)),
                    success_indicators=indicators,
                    recommended_actions=_parse_actions(item.get("recommended_actions"), sid),
                    attacker_role=attacker_role,
                )
            )
        return cls(rules, provenance=data.get("provenance") or {})

    def lookup_with_quality(self, sid: int | None, rev: int | None = None) -> RuleMatch:
        if sid is None:
            return RuleMatch(None, "missing_sid", "Alert has no SID")
        exact = self.by_sid_rev.get((sid, rev))
        if exact is not None:
            return RuleMatch(exact, "exact")
        fallback = self.by_sid.get(sid)
        if fallback is None:
            return RuleMatch(None, "unknown_sid", f"No metadata found for SID {sid}")
        return RuleMatch(
            fallback,
            "sid_fallback",
            f"Metadata revision mismatch for SID {sid}: alert rev={rev}, catalog rev={fallback.rev}",
        )

    def lookup(self, sid: int | None, rev: int | None = None) -> RuleMetadata | None:
        return self.lookup_with_quality(sid, rev).rule
