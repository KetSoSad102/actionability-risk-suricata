# Changelog

## 2.2.2

- Keep this repository focused on executable software, configurations, tests, and reproducible outputs.
- Remove non-product distribution assets and stale documentation links.
- Remove the obsolete compatibility-only scoring profile.
- Remove the hard-coded repository URL so a newly created GitHub repository can define its own remote.

## 2.2.1

- Run writable Python services with the invoking host UID/GID.
- Pass the supported `PUID` and `PGID` variables to the Suricata image.
- Prevent Docker-generated PCAP, log, score, annotation, and figure artifacts from becoming unreadable root-owned files on Linux/WSL bind mounts.
- Document the one-time ownership repair for artifacts created by older releases.

## 2.2.0

- Reframed the evaluation as a post-alert study with a fixed Suricata ruleset.
- Crossed 10 observed Suricata seeds, 5 outcome contexts, and 10 evidence profiles to produce 500 controlled alert presentations.
- Added explicit seed, base-context vignette, and presentation identifiers to prevent pseudo-replication claims.
- Added payload success/failure indicators that override ambiguous HTTP-status-only inference.
- Added complete analyst-facing context and response playbooks to JSONL output.
- Added a deterministic, score-blinded 300-item annotation sample with three empty rating slots per item.
- Added a post-annotation analyzer for agreement, criterion associations, AUPRC baselines, and seed-cluster bootstrap intervals.
- Added context/profile tables, a two-factor heatmap, and regenerated sensitivity and ablation figures.
- Expanded the regression suite to 15 tests.
- Made figure export atomic and fail-fast when a generated PNG/PDF is empty or has an invalid signature.

## 2.1.0

- Added criterion-level score breakdowns with weights and contributions.
- Added a 110-case controlled evidence benchmark over 10 base alert archetypes.
- Added ablation, weight-sensitivity, profile and field-presence comparators.
- Added reproducible PNG/PDF experiment figures.
- Added an AIT-ADS Wazuh-to-EVE adapter with optional official label joining.
- Added deterministic alert-archetype aggregation and balanced sampling.
- Renamed the primary profile to `proposed_default`.
- Expanded the regression suite to 11 tests.

## 2.0.0

- Correlate EVE flow and HTTP transactions before normalizing alerts.
- Add explicit packet, client/server, direction, and candidate attribution fields.
- Split Actionability Score, Risk Score, and outcome confidence.
- Add `not_applicable` evidence semantics.
- Validate metadata and expose SID revision mismatch warnings.
- Score response guidance by phase coverage and evidence linkage.
- Stream CSV/JSONL output and add aggregate `summary.json`.
- Add ground-truth validation, unit tests, regression tests, and CI.
- Correct ColdFusion SID 2016185 metadata revision to match the bundled rule.

## 1.0.0

- Original offline Suricata and Actionability Score demonstration.
