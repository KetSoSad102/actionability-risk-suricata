# Analyst annotation protocol

## Purpose

This protocol tests criterion validity for the post-alert Actionability Score. It does not ask analysts to decide whether a Suricata signature is technically correct. The question is whether the presented alert contains enough evidence and sufficiently specific guidance to begin a defensible investigation or response.

## Unit and blinding

The rating unit is one alert presentation. A presentation is derived from an observed Suricata seed, one controlled outcome context, and one evidence-availability profile. The rater sees only `annotation_items.csv` or `annotation_items.jsonl`. The files `annotation_key.csv`, `controlled_cases.csv`, and `controlled_cases.jsonl` contain automated scores or experimental conditions and must remain hidden until all ratings are frozen.

The default main sample contains 300 presentations. Each item requires three independent ratings, producing 900 expected rating rows. Assign 8--12 practitioners using an incomplete crossed design. Do not allow raters to discuss items before submission.

## Rating fields

For every assigned item, complete these fields in `annotation_responses_template.csv`:

| Field | Allowed value | Meaning |
|---|---|---|
| `actionability_likert_1_5` | Integer 1--5 | 1 means not actionable; 5 means immediately actionable |
| `actionability_class` | `actionable`, `non_actionable`, or `unsure` | Coarse operational decision |
| `understands_event_1_5` | Integer 1--5 | Confidence in understanding what happened |
| `understands_outcome_1_5` | Integer 1--5 | Confidence in understanding success, failure, or uncertainty |
| `knows_next_action_1_5` | Integer 1--5 | Confidence that the next investigation or response step is clear |
| `additional_pivot_required` | `yes`, `no`, or `unsure` | Whether another data source must be opened before starting |
| `proposed_next_action` | Free text | First concrete next step and evidence source |
| `confidence_1_5` | Integer 1--5 | Confidence in the rating |
| `decision_seconds` | Positive number | Time from opening the item to freezing the decision |

An item is actionable when the analyst can identify the relevant entities, understand the likely event and outcome uncertainty, and name a concrete next step without an unexplained external pivot. High severity alone does not make an item actionable. Likewise, a clearly failed request can still be highly actionable because its outcome and response path are explicit.

## Quality control

Before unblinding, reject only ratings that are incomplete, use invalid categories, or have a documented administration failure. Never reject a rating because it disagrees with the automated score. Report inter-rater agreement, the number of excluded rows with reasons, and score associations with Likert rating, binary actionability, pivot need, next-action quality, confidence, and decision time.

All train/test splits and bootstrap resampling must be grouped by `seed_id` or SID family. Presentation-level random splitting is prohibited because several presentations share the same underlying alert seed.

After the completed response file is frozen, run:

```bash
PYTHONPATH=src python -m as_engine.annotation_analysis \
  --key runs/experiments/controlled/annotation/annotation_key.csv \
  --responses /path/to/frozen_annotation_responses.csv \
  --output runs/experiments/controlled/annotation/annotation_analysis.json
```

The analyzer refuses incomplete or invalid rating rows, calculates ordinal Krippendorff alpha and categorical Fleiss kappa, compares the proposed score with equal-weight and field-presence baselines, and obtains 95% confidence intervals by bootstrapping `seed_id` clusters rather than individual presentations.

## Claim boundary

The presence of this protocol and its empty response template does not constitute analyst validation. Any publication or evaluation report may claim analyst agreement or criterion validity only after independent practitioners have completed the ratings and the frozen responses have been analyzed.
