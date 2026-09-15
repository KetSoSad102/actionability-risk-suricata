"""Frozen-configuration AIT-ADS replication and measured offline processing cost."""
import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import statistics
import subprocess
from datetime import datetime, timezone
from .benchmark import measure, sha256, environment


def score_args(eve, output):
    return ['--eve', str(eve), '--rules', 'rules/rule_metadata.yaml', '--scoring', 'config/scoring-v2.yaml',
        '--profile', 'proposed_default', '--out-jsonl', str(output/'scores.jsonl'), '--out-csv', str(output/'scores.csv'),
        '--out-summary', str(output/'score_summary.json'), '--fail-on-malformed']


def describe(output, scenario):
    counts = Counter()
    n = 0
    with (output/'scores.jsonl').open(encoding='utf-8') as f:
        for line in f:
            r = json.loads(line)
            n += 1
            counts['role_resolved'] += r.get('alert_direction') in ('to_server','to_client')
            counts['http_context'] += bool(r.get('http_url') or r.get('http_method') or r.get('http_status'))
            counts['decisive_outcome'] += r['outcome_class'] in ('success_evidenced','failure_evidenced')
            counts['sid_metadata'] += r['rule_match_quality'] != 'unknown_sid'
            counts['unlabeled'] += r.get('dataset_label') in (None, '', 'unlabeled')
            counts['attack_phase'] += r.get('dataset_label') not in (None, '', 'unlabeled','false_positive')
    with (output/'archetypes'/'archetypes_all.csv').open(encoding='utf-8') as f:
        archetypes = list(csv.DictReader(f))
    values = [float(r['mean_actionability']) for r in archetypes]
    return {'scenario': scenario, 'raw_alerts': n, 'archetypes': len(values),
        'archetype_mean_actionability': statistics.mean(values) if values else None,
        'archetype_median_actionability': statistics.median(values) if values else None,
        'archetype_min': min(values) if values else None, 'archetype_max': max(values) if values else None,
        **{k: int(v) for k,v in counts.items()},
        **{k+'_fraction': v/n if n else None for k,v in counts.items()}}


def main():
    p = argparse.ArgumentParser(__doc__)
    p.add_argument('--data-dir', required=True)
    p.add_argument('--labels-dir', required=True)
    p.add_argument('--scenarios', nargs='+', required=True)
    p.add_argument('--output', default='runs/paper_extension/external')
    p.add_argument('--repeats', type=int, default=5)
    a = p.parse_args()
    if len(set(a.scenarios)) != len(a.scenarios) or any(Path(s).name != s for s in a.scenarios):
        raise ValueError('Scenarios must be distinct plain names')
    root = Path(a.output)
    root.mkdir(parents=True, exist_ok=True)
    frozen = {f: sha256(f) for f in ('config/scoring-v2.yaml','rules/rule_metadata.yaml')}
    manifest = {'created_utc': datetime.now(timezone.utc).isoformat(), 'environment': environment(),
        'base_commit': subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip(),
        'configuration_sha256': frozen, 'source_sha256': {str(f):sha256(f) for f in sorted(Path('src/as_engine').glob('*.py'))},
        'scenarios': a.scenarios, 'inputs': {}, 'results': [],
        'selection': 'Scenarios specified explicitly on the command line; the paper protocol documents selection before scoring.',
        'interpretation': 'Descriptive cross-scenario evidence coverage; archetypes are aggregation units, not proven independent incidents. No maliciousness classifier or human validity claim.'}
    for scenario in a.scenarios:
        source = Path(a.data_dir)/f'{scenario}_wazuh.json'
        labels = Path(a.labels_dir)/f'{scenario}_alerts.txt'
        manifest['inputs'][scenario] = {'data_sha256': sha256(source), 'data_bytes': source.stat().st_size, 'labels_sha256': sha256(labels)}
        out = root/scenario
        out.mkdir(exist_ok=True)
        adapter = measure('as_engine.ait_ads', ['--input', source, '--scenario', scenario, '--labels-csv', labels,
            '--out-eve', out/'eve.json', '--out-summary', out/'adapter_summary.json', '--fail-on-malformed'], out/'bench_adapter', a.repeats)
        scoring = measure('as_engine.cli', score_args(out/'eve.json', out), out/'bench_scoring', a.repeats)
        aggregation = measure('as_engine.archetypes', ['--scores', out/'scores.jsonl', '--output-dir', out/'archetypes', '--sample-fraction','0.25','--seed','2026'], out/'bench_archetypes', a.repeats)
        assert all(sha256(f) == h for f,h in frozen.items()), 'Configuration changed during run'
        row = describe(out, scenario)
        for stage, result in [('adapter', adapter),('scoring',scoring),('archetypes',aggregation)]:
            row[stage+'_wall_seconds'] = result['process_wall_seconds']['median']
            row[stage+'_peak_rss_mib'] = result['peak_rss_mib']['median']
        row['scoring_alerts_per_second'] = row['raw_alerts']/row['scoring_wall_seconds']
        manifest['results'].append(row)
        (root/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        print(json.dumps(row), flush=True)
    demo = root/'synthetic10'
    demo.mkdir(exist_ok=True)
    manifest['synthetic10'] = measure('as_engine.cli', score_args(Path('logs/suricata/eve.json'), demo), demo/'bench_scoring', a.repeats)
    manifest['synthetic10_input_sha256'] = sha256('logs/suricata/eve.json')
    rows = manifest['results']
    manifest['leave_one_scenario_out_macro_means'] = {row['scenario']: statistics.mean(r['archetype_mean_actionability'] for r in rows if r is not row) for row in rows} if len(rows)>1 else {}
    with (root/'comparison.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    (root/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
