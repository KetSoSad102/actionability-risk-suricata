import csv
import hashlib
import json
from pathlib import Path
import subprocess
from as_engine.benchmark import sha256

root=Path('runs/paper_extension')
a=json.loads((root/'external/manifest.json').read_text())
b=json.loads((root/'external_recheck/manifest.json').read_text())
checks={}
for file,expected in a['configuration_sha256'].items():
    baseline=subprocess.check_output(['git','show',f'HEAD:{file}'])
    assert Path(file).read_bytes().replace(b'\r\n',b'\n') == baseline.replace(b'\r\n',b'\n')
    assert sha256(file)==expected==b['configuration_sha256'][file]
checks['configuration_unchanged_from_upstream']=True
checks['scenario_outputs']={}
for scenario in a['scenarios']:
    left=root/'external'/scenario;right=root/'external_recheck'/scenario
    lh,rh=sha256(left/'scores.jsonl'),sha256(right/'scores.jsonl')
    assert lh==rh,scenario
    n=json.loads((left/'score_summary.json').read_text())['alert_count']
    adapter=json.loads((left/'adapter_summary.json').read_text())['diagnostics']
    assert adapter['malformed_json']==0 and adapter['suricata_records']==n
    for parent in (left,right):
        for stage in ('adapter','scoring','archetypes'):
            bench=json.loads((parent/f'bench_{stage}'/'benchmark.json').read_text())
            measured=[r for r in bench['runs'] if not r['warmup']]
            assert len(measured)==5
            assert all(r['process_wall_seconds']>0 and r['peak_rss_mib']>0 for r in measured)
    checks['scenario_outputs'][scenario]={'identical_score_sha256':lh,'alerts':n,'malformed':0}
checks['delivered_source_sha256']={str(f):sha256(f) for f in sorted(Path('src/as_engine').glob('*.py'))}
checks['measurement_source_note']='Original manifest retains source snapshot from each benchmark launch. Subsequent edits concern the human-study tools, reporting, and scenario-selection wording and allowing a benchmark worker with zero module arguments. Scoring, adaptation, archetype algorithms and the measurement implementation for these nonempty-argument runs are unchanged.'
(root/'verification.json').write_text(json.dumps(checks,indent=2),encoding='utf-8')
print(json.dumps(checks['scenario_outputs'],indent=2))
