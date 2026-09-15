#!/usr/bin/env bash
set -euo pipefail
if [ ! -f runs/improved/scores.csv ]; then
  echo "runs/improved/scores.csv not found. Run ./scripts/run_as.sh first."
  exit 1
fi

if [ "$#" -gt 0 ]; then
  ./scripts/explain_alert.sh "$1"
  exit 0
fi

python3 - <<'PY'
import csv
from pathlib import Path
p = Path('runs/improved/scores.csv')
rows = list(csv.DictReader(p.open()))
if not rows:
    print('No scored alerts found.')
    raise SystemExit
print('A = Actionability; R = Risk; Ent/Ctx/Out/Inv/Resp = Actionability components; Sev/Lik = Risk signals')
print(
    f"{'A':>5} {'R':>5} {'Ent':>5} {'Ctx':>5} {'Out':>5} {'Inv':>5} "
    f"{'Resp':>5} {'Sev':>5} {'Lik':>5} {'SID':>8} {'Dir':>9}  Signature"
)
print('-' * 150)
for r in sorted(
    rows,
    key=lambda x: (
        float(x['actionability_score'] or 0),
        float(x['risk_score'] or 0),
    ),
    reverse=True,
):
    values = [
        r.get('actionability_score'), r.get('risk_score'),
        r.get('entity_completeness'), r.get('attack_context'),
        r.get('outcome_evidence'), r.get('investigation_evidence'),
        r.get('recommended_response'), r.get('severity_impact'),
        r.get('outcome_likelihood'),
    ]
    numeric = ' '.join(f"{float(value or 0):5.2f}" for value in values)
    print(
        f"{numeric} {str(r.get('sid') or ''):>8} "
        f"{str(r.get('alert_direction') or ''):>9}  "
        f"{str(r.get('signature') or '')[:72]}"
    )
PY
