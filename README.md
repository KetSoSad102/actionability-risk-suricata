# SurEvi — Evidence-Based Actionability and Risk-Aware Triage of Suricata Alerts

SurEvi (**Suricata Evidence**) is an open-source, offline post-detection pipeline for correlating Suricata EVE records, enriching alerts with investigation context, and computing separate **Actionability** and **Risk** scores.

The project was originally developed under the name **Actionability Suricata v2.2.2**. The current paper and artifact use the name **SurEvi**.

> SurEvi is a research and reproducibility artifact. It is not a production IDS, does not replace Suricata detection, and does not treat its scores as probabilities of compromise.

## Main Capabilities

SurEvi currently provides:

1. Two-pass correlation of `alert`, `http`, and `flow` EVE records using `flow_id` and `tx_id`.
2. Preservation of packet-level source/destination fields together with semantic `client/server` roles.
3. Explicit `to_server`, `to_client`, attacker-candidate, victim-candidate, and attribution-confidence fields.
4. Separate **Actionability** and **Risk** scoring.
5. A three-state evidence model: `present`, `missing`, and `not_applicable`.
6. SID/revision-aware rule metadata validation.
7. Response guidance scored by response phase and evidence links rather than text length.
8. Streaming CSV/JSONL output and run-level summaries.
9. Per-record score decomposition with component values, weights, and weighted contributions.
10. A controlled two-factor experiment with 10 Suricata alert seeds, 5 outcome contexts, and 10 evidence profiles.
11. Stable `seed_id`, `base_context_id`, and `presentation_id` identifiers to prevent pseudo-replication.
12. Paired ablation, comparator, and local weight-sensitivity analysis.
13. Blinded analyst-rating materials for future criterion validation.
14. An AIT-ADS adapter and archetype aggregation for repeated external alerts.
15. Repeated offline runtime and peak-memory measurement utilities.

## Paper Artifact Status

The current artifact matches the evaluation reported in the paper **“SurEvi: Evidence-Based Actionability and Risk-Aware Triage of Suricata Alerts.”**

The reported evaluation includes:

- 41 EVE records containing 10 Suricata alerts.
- 10/10 exact SID and revision metadata matches.
- Correct role recovery for all 10 controlled alerts, including 6 response-side alerts.
- 500 controlled alert presentations.
- 4 AIT-ADS scenarios:
  - `russellmitchell`
  - `shaw`
  - `wardbeck`
  - `santos`
- 94,500 retained AIT-ADS Suricata alerts.
- 150 scenario-specific archetypes.
- Repeated offline runtime and peak-RSS measurements.
- 21 unit and regression tests.

The repository also prepares a blinded 30-item, three-rater pilot for analyst validation. **No real analyst ratings are included in the repository, and no human-agreement or score–analyst correlation result is claimed.**

## Repository Structure

```text
config/
  scoring-v2.yaml
  ground_truth.yaml
  context_variants.yaml
  controlled_variants.yaml

docs/
  ait_ads_pilot.md
  annotation_protocol.md
  human30_protocol_vi.md
  paper_extension_reproduction.md
  paper_extension_results_vi.md
  paper_revision_summary_vi.md

logs/
  suricata/
    eve.json
    fast.log
    stats.log
    suricata.log

payloads/
  generate_official_payloads_pcap.py

pcaps/
  generated_official_payloads.pcap

rules/
  improved.rules
  rule_metadata.yaml

runs/
  improved/
  experiments/
  paper_extension/

scripts/
  run_all.sh
  run_experiments.sh
  show_results.sh
  explain_alert.sh
  import_ait_ads.sh
  benchmark_controlled.py
  fetch_full_upstream_rules.sh

src/as_engine/
  parser.py
  rule_catalog.py
  evidence.py
  scoring.py
  cli.py
  validation.py
  explain.py
  experiment.py
  annotation.py
  annotation_analysis.py
  human_study.py
  ait_ads.py
  archetypes.py
  external_validation.py
  benchmark.py

tests/
```

## Pipeline

```text
Synthetic HTTP scenarios
        |
        v
     Scapy PCAP
        |
        v
  Suricata 7 offline
        |
        v
     EVE JSON
        |
        v
Flow / HTTP / transaction correlation
        |
        v
SID metadata enrichment
        |
        v
Evidence extraction
        |
        +-----------------------+
        |                       |
        v                       v
Actionability Score        Risk Score
        |                       |
        +-----------+-----------+
                    |
                    v
       CSV / JSONL / summary
                    |
                    v
      Ground-truth validation
                    |
                    v
Controlled post-alert experiment
                    |
                    v
Blinded annotation materials
```

AIT-ADS records are adapted into EVE-like records and then processed through the same downstream scoring and evidence-analysis pipeline.

## Quick Start with Docker

Requirements:

- Docker
- Docker Compose
- `jq`

Run the complete controlled pipeline:

```bash
./scripts/run_all.sh
```

The scripts pass the current UID/GID into writable containers so generated PCAPs, logs, tables, and figures are owned by the invoking user.

If files under `runs/`, `logs/suricata/`, or `pcaps/` were previously created as root, fix permissions once:

```bash
sudo chown -R "$(id -u):$(id -g)" runs logs/suricata pcaps
sudo chmod -R u+rwX runs logs/suricata pcaps
```

The full workflow performs:

1. Image build.
2. Synthetic PCAP generation.
3. Offline Suricata execution.
4. SurEvi scoring.
5. Ground-truth validation.
6. Controlled 500-presentation experiment generation.
7. Figure and table generation.
8. Blinded annotation-pack generation.

Important outputs include:

```text
logs/suricata/eve.json

runs/improved/
  scores.jsonl
  scores.csv
  summary.json

runs/experiments/controlled/
  controlled_cases.csv
  controlled_cases.jsonl
  experiment_summary.json
  variant_summary.csv
  context_summary.csv
  context_profile_summary.csv
  comparators.csv
  ablation.csv
  sensitivity.csv
  figures/
  annotation/
```

To inspect a compact summary:

```bash
./scripts/show_results.sh
```

To explain one alert by SID:

```bash
./scripts/show_results.sh 2025756
```

or:

```bash
./scripts/explain_alert.sh 2025756
```

The explanation includes the raw component score, configured weight, weighted contribution, and missing-evidence codes.

## Running the Scoring Engine Without Docker

The repository includes a committed `eve.json` fixture for local regression testing.

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Then run:

```bash
PYTHONPATH=src python -m as_engine.cli \
  --eve logs/suricata/eve.json \
  --rules rules/rule_metadata.yaml \
  --scoring config/scoring-v2.yaml \
  --out-jsonl runs/improved/scores.jsonl \
  --out-csv runs/improved/scores.csv \
  --out-summary runs/improved/summary.json \
  --fail-on-malformed
```

To use the equal-weight profile:

```bash
PYTHONPATH=src python -m as_engine.cli \
  --eve logs/suricata/eve.json \
  --rules rules/rule_metadata.yaml \
  --scoring config/scoring-v2.yaml \
  --profile equal_weight \
  --out-jsonl /tmp/scores.jsonl \
  --out-csv /tmp/scores.csv \
  --out-summary /tmp/summary.json
```

## Default Scoring Model

The default profile is named `proposed_default` to emphasize that the weights are transparent research design choices rather than empirically learned or universally optimal parameters.

### Actionability

```text
A =
0.25 * entity_completeness
+ 0.20 * attack_context
+ 0.15 * outcome_evidence
+ 0.25 * investigation_evidence
+ 0.15 * recommended_response
```

Severity is intentionally excluded from the Actionability score.

Configured Actionability thresholds:

```text
low     < 0.50
medium  >= 0.50 and < 0.75
high    >= 0.75
```

### Risk

```text
R =
0.60 * severity_impact
+ 0.40 * outcome_likelihood
```

Configured Risk thresholds:

```text
low     < 0.45
medium  >= 0.45 and < 0.75
high    >= 0.75
```

The configuration is stored in:

```text
config/scoring-v2.yaml
```

## Evidence Model

Each evidence item is represented as one of:

```text
present
missing
not_applicable
```

Non-applicable evidence is excluded from both the numerator and denominator of the corresponding evidence dimension.

For example, a scanner rule that has no applicable CVE is not penalized merely because no CVE exists.

The five main Actionability dimensions are:

```text
entity_completeness
attack_context
outcome_evidence
investigation_evidence
recommended_response
```

## Outcome Interpretation

Outcome evidence and outcome likelihood are intentionally separate.

| Observed condition | Outcome evidence | Outcome likelihood |
|---|---:|---:|
| Configured success marker | 1.00 | 0.90 |
| Configured failure marker | 1.00 | 0.10 |
| HTTP 400/401/403/404/500 | 1.00 | 0.10 |
| HTTP 200/201/202 | 0.60 | 0.60 |
| Other observed status | 0.40 | 0.40 |
| No protocol outcome | 0.00 | 0.30 |

Configured payload markers take precedence over HTTP status.

An HTTP 200 response is therefore only treated as **possibly successful**. It is not proof of application or host compromise.

## Packet Direction and Semantic Roles

Response-side Suricata rules may generate alerts on packets traveling from server to client even when the suspicious request was initiated by the client.

SurEvi therefore preserves packet endpoints separately from semantic roles:

```text
packet_src_ip
packet_src_port
packet_dest_ip
packet_dest_port

client_ip
client_port
server_ip
server_port

alert_direction
attacker_candidate
victim_candidate
attribution_confidence
```

`attacker_candidate` and `victim_candidate` are role-based hypotheses derived from protocol context and rule metadata. They are not forensic proof of ownership or malicious intent.

## Rule Metadata

`rules/rule_metadata.yaml` supports fields such as:

```yaml
cve_applicable: false
mitre_applicable: true
attacker_role: client

recommended_actions:
  - phase: validate
    action: "Inspect the request."
    evidence:
      - "http.url"
      - "payload_printable"
```

SID lookup quality is recorded as:

```text
exact
sid_fallback
unknown_sid
```

A revision mismatch is therefore visible rather than silently treated as an exact metadata match.

## Controlled Post-Alert Experiment

Install experiment dependencies:

```bash
pip install -r requirements-experiments.txt
```

Then run:

```bash
./scripts/run_experiments.sh
```

The design crosses:

```text
10 observed Suricata alert seeds
x 5 controlled outcome contexts
= 50 base-context vignettes

50 base-context vignettes
x 10 evidence profiles
= 500 alert presentations
```

### Outcome Contexts

Defined in:

```text
config/context_variants.yaml
```

The five contexts are:

1. Observed HTTP 200.
2. HTTP 200 with a configured success marker.
3. HTTP 200 with a configured failure marker.
4. Rejected HTTP 403.
5. Ambiguous HTTP 302.

### Evidence Profiles

Defined in:

```text
config/controlled_variants.yaml
```

The ten profiles are:

1. Native evidence.
2. Complete evidence.
3. No payload.
4. No Community ID.
5. No outcome evidence.
6. No flow identity.
7. No HTTP context.
8. No role resolution.
9. Unknown SID metadata.
10. Minimal alert.

The three identifiers used to preserve experimental nesting are:

```text
seed_id
base_context_id
presentation_id
```

The 500 presentations are **not** 500 independent attacks, 500 independent production alerts, or 500 analyst judgments.

## Controlled Experiment Results

Results by evidence profile:

| Evidence profile | Presentations | Mean Actionability | Mean Risk |
|---|---:|---:|---:|
| Complete evidence | 50 | 0.9700 | 0.573 |
| Native evidence | 50 | 0.9300 | 0.573 |
| No Community ID | 50 | 0.9400 | 0.573 |
| No payload | 50 | 0.8960 | 0.589 |
| No flow identity | 50 | 0.8725 | 0.573 |
| No role resolution | 50 | 0.8200 | 0.573 |
| No outcome evidence | 50 | 0.7700 | 0.525 |
| Unknown SID metadata | 50 | 0.6760 | 0.739 |
| No HTTP context | 50 | 0.6225 | 0.525 |
| Minimal alert | 50 | 0.1050 | 0.675 |

Across all 500 controlled presentations:

```text
Mean Actionability: 0.7602
Median Actionability: 0.8500
Actionability range: 0.105–1.000

Mean Risk: 0.5918
```

Outcome classes are distributed as:

```text
110 possibly_successful
50  success_evidenced
120 failure_evidenced
220 unknown
```

### Paired Ablation

Using the complete-evidence condition as the reference, the largest mean paired Actionability decreases are:

```text
No HTTP context:  0.3475
Unknown metadata: 0.2940
No outcome:       0.2000
```

These values describe the behavior of the declared scoring model under controlled evidence removal. They do not establish agreement with analyst utility.

## Comparator and Weight-Sensitivity Results

Relative to the proposed Actionability ranking:

```text
Equal-weight comparator:
  Kendall tau-b: 0.910370
  Top-20% overlap: 1.00

Field-presence comparator:
  Kendall tau-b: 0.808418
  Top-20% overlap: 0.53
```

For local 10–30% single-weight perturbations:

```text
Minimum Kendall tau-b: 0.940671
```

The paper reports this as `0.9407` after rounding.

These results measure internal ranking stability under the controlled design. They do not prove that the proposed ranking is preferred by analysts.

## AIT-ADS External Evidence-Coverage Evaluation

SurEvi was evaluated on four AIT-ADS scenarios using the same adapter, rule metadata, scoring configuration, and `proposed_default` profile.

No per-scenario score tuning or metadata enrichment was introduced.

| Scenario | Alerts | Archetypes | Mean A | Role resolved | HTTP context | Decisive outcome | SID metadata |
|---|---:|---:|---:|---:|---:|---:|---:|
| russellmitchell | 9,186 | 31 | 0.3709 | 99.37% | 3.88% | 0.39% | 0.29% |
| shaw | 16,692 | 19 | 0.3749 | 99.14% | 3.12% | 0.00% | 0.00% |
| wardbeck | 24,510 | 42 | 0.3593 | 99.39% | 1.91% | 0.03% | 0.04% |
| santos | 44,112 | 58 | 0.3677 | 41.38% | 0.88% | 0.03% | 0.03% |

Total:

```text
94,500 alerts
150 scenario-specific archetypes
```

Scenario-level mean Actionability ranges from:

```text
0.3593 to 0.3749
```

The macro mean is:

```text
0.3682
```

Leave-one-scenario-out macro means range from:

```text
0.3660 to 0.3712
```

These narrow means should not be interpreted as proof of cross-scenario invariance.

For example, role resolution is above 99% in three scenarios but only 41.38% in `santos`. The external experiment therefore characterizes **evidence availability and portability of the fixed pipeline**, not detection accuracy or production generalization.

## AIT-ADS Import

The repository does not bundle the full AIT-ADS dataset.

Use the public dataset and official per-alert labels, then run:

```bash
./scripts/import_ait_ads.sh \
  russellmitchell \
  /path/to/russellmitchell_wazuh.json \
  /path/to/russellmitchell_alerts.txt
```

The third argument must be the per-alert label file, for example:

```text
alerts_csv/russellmitchell_alerts.txt
```

Do not use the top-level `labels.csv` as a replacement for this file.

If labels are unavailable, the adapter can still run without the third argument.

The adapter:

- Retains only Wazuh records with the `Suricata:` prefix.
- Preserves absent fields as absent.
- Does not invent `flow_id`.
- Does not invent `tx_id`.
- Does not invent payload.
- Does not invent outcome evidence.
- Records unavailable SID metadata as `unknown_sid`.

Archetypes are grouped using scenario, label, SID/signature, protocol, direction, outcome class, and missing-evidence profile.

## Offline Runtime and Memory Evaluation

Each adapter, scoring, and aggregation stage is executed sequentially in a fresh process.

The measurement protocol uses:

```text
1 warmup run
5 measured runs
```

Wall time, CPU time, and OS peak resident memory are recorded.

Two measurement batches are preserved because timing varied on the uncontrolled host.

### Batch 1

| Scenario | Adapter (s) | Scoring median (s) | Aggregation (s) | Scoring peak RSS (MiB) |
|---|---:|---:|---:|---:|
| russellmitchell | 0.93 | 3.05 | 0.46 | 25.7 |
| shaw | 1.27 | 5.25 | 0.66 | 25.9 |
| wardbeck | 1.66 | 7.86 | 0.92 | 25.9 |
| santos | 2.51 | 57.64 | 8.42 | 26.0 |

### Batch 2

| Scenario | Adapter (s) | Scoring median (s) | Aggregation (s) | Scoring peak RSS (MiB) |
|---|---:|---:|---:|---:|
| russellmitchell | 3.56 | 10.05 | 1.51 | 24.8 |
| shaw | 4.88 | 17.62 | 2.27 | 24.8 |
| wardbeck | 6.87 | 28.49 | 4.31 | 25.0 |
| santos | 10.88 | 55.97 | 6.64 | 25.0 |

Peak scoring memory remains near 25 MiB across the evaluated input sizes.

Runtime is substantially less stable. The host was not controlled for background load, disk cache, power policy, or temperature, so these measurements should not be interpreted as production capacity estimates.

The benchmark excludes:

- Suricata traffic detection cost.
- Live ingestion.
- Long-term retention.
- Analyst labor.
- Production infrastructure cost.

## Analyst Validation Materials

The repository contains two analyst-study workflows.

### 300-Item Blinded Annotation Pack

The controlled experiment generates a deterministic 300/500 sample that is balanced across outcome contexts, evidence profiles, context–profile cells, and SIDs.

The analyst-facing file does not expose:

- automated score,
- evidence-profile label,
- outcome-condition label.

Three empty rating slots are generated per item, giving:

```text
300 items
900 empty rating rows
```

These are protocol materials, not analyst results.

### 30-Item, Three-Rater Pilot

The paper extension additionally prepares a smaller pilot in which:

```text
3 raters
x the same 30 items
= 90 expected ratings
```

Each rater receives the same 30 items in a different order.

The intended analysis includes:

- Spearman correlation between SurEvi Actionability and median Likert rating.
- 95% bootstrap confidence intervals clustered by `seed_id`.
- Ordinal Krippendorff's alpha.
- Fleiss' kappa.
- AUPRC against majority-class labels.

No completed human-rating dataset is included in this repository. Therefore, score–analyst alignment remains unassessed.

See:

```text
docs/human30_protocol_vi.md
docs/annotation_protocol.md
docs/paper_extension_reproduction.md
```

## Automated Verification

Run:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The current regression suite contains **21 tests**.

The committed test run reports:

```text
Ran 21 tests
OK
```

The test suite covers:

- AIT-ADS conversion without fabricated evidence.
- Deterministic blinded annotation sampling.
- Annotation agreement and grouped-metric analysis.
- Archetype collapsing and deterministic sampling.
- Benchmark child-process failure handling.
- Invalid benchmark repeat-count rejection.
- Bundled EVE end-to-end validation.
- Controlled figure validation.
- Two-factor controlled experiment generation.
- Per-alert explanation output.
- Ordinal-distance handling for the human-study analyzer.
- Three-rater pilot pack blinding and ordering.
- Partial-factorial balance for the 30-item pilot.
- Enforcement of the same three raters across all 30 pilot items.
- Port-based role inference fallback.
- Response-side role correlation.
- Exact and SID-fallback metadata matching.
- Metadata-schema validation.
- Failure evidence with low outcome likelihood.
- `not_applicable` CVE handling.
- Payload-marker precedence over HTTP-status-only inference.

Ground-truth validation can also be run directly:

```bash
PYTHONPATH=src python -m as_engine.validation \
  --scores runs/improved/scores.csv \
  --truth config/ground_truth.yaml
```

The committed controlled fixture currently reports:

```text
41 EVE records
10 alerts
10 correlated alerts
10 exact SID/revision metadata matches
0 malformed JSON lines
0 unresolved-role alerts
```

## Reproducibility Notes

The bundled rule subset comes from:

```text
https://github.com/Koen1999/ruling-the-unruly
```

The pinned upstream commit is:

```text
73d86b249635215f0dee05dc38a32d49c8b1810c
```

All 16 bundled rule lines were verified as an exact subset of `improved.rules` from that upstream commit.

The bundled rules remain subject to the Emerging Threats BSD license terms documented in:

```text
THIRD_PARTY_NOTICES.md
licenses/EMERGING-THREATS-BSD.txt
```

The helper script:

```bash
./scripts/fetch_full_upstream_rules.sh
```

can fetch the pinned upstream rule set.

The full upstream set is not loaded by default because it includes dependencies, including Lua-based rules, that are outside the minimal reproducible experiment.

## Limitations

Important limitations of the current artifact include:

- The controlled PCAP is synthetic.
- The controlled experiment starts from only 10 observed Suricata alert seeds.
- The 500 controlled presentations are deterministic transformations, not 500 independent attacks.
- The AIT-ADS evaluation covers four of eight scenarios.
- The four AIT-ADS scenarios are a convenience sample rather than a production SOC distribution.
- External Wazuh exports contain sparse HTTP, outcome, and SID metadata.
- Archetypes reduce repeated-alert dominance but are not proven independent incidents.
- AIT-ADS labels describe attack phases and are not analyst-rated Actionability ground truth.
- The current parser is primarily optimized for HTTP.
- Attribution is role-based and remains a candidate hypothesis.
- HTTP status alone cannot establish compromise.
- The Risk score is a transparent ranking heuristic, not a calibrated probability.
- Runtime measurements were collected on an uncontrolled personal machine.
- No completed independent analyst-rating study is currently included.
- Production effectiveness, calibrated risk, and analyst utility are therefore not established.

## Research Scope

SurEvi is designed to study the question:

> When Suricata has already generated an alert, does the alert contain enough contextual and outcome evidence for an analyst to investigate and act on it?

The project does **not** claim to improve Suricata detection accuracy.

Its main focus is post-detection evidence quality, correlation, explainable scoring, evidence gaps, and triage readiness.

## License and Third-Party Material

See:

```text
THIRD_PARTY_NOTICES.md
licenses/
```

before redistributing bundled third-party rules or derived artifacts.

## Citation

If you use this repository in academic work, cite the accompanying paper:

```text
SurEvi: Evidence-Based Actionability and Risk-Aware Triage of Suricata Alerts
```

The repository is intended to accompany the experimental artifact and reproducibility materials described in that paper.
