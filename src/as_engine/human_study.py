"""Fixed 30-item / same-three-rater pilot; no simulated research ratings."""
import argparse
import csv
import hashlib
import html
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from .annotation import write_annotation_pack, _read_jsonl, _write_csv, RESPONSE_FIELDS
from .annotation_analysis import analyze_annotations, _read_csv


def select_thirty(records, seed=2026):
    seeds = sorted({r['experiment']['seed_id'] for r in records})
    contexts = sorted({r['experiment']['context'] for r in records})
    profiles = sorted({r['experiment']['evidence_profile'] for r in records})
    if (len(seeds), len(contexts), len(profiles)) != (10, 5, 10):
        raise ValueError('This preregistered design requires 10 seeds, 5 contexts, 10 profiles')
    lookup = {(r['experiment']['seed_id'], r['experiment']['context'], r['experiment']['evidence_profile']): r for r in records}
    chosen = []
    for block in range(3):
        for i in range(10):
            chosen.append(lookup[(seeds[i], contexts[(i + block + seed) % 5], profiles[(i + 3 * block + seed) % 10])])
    return chosen


def prepare(cases, output, seed=2026):
    root = Path(output)
    selected = select_thirty(_read_jsonl(Path(cases)), seed)
    summary = write_annotation_pack(selected, root / 'coordinator', 30, seed, 3)
    summary['source_presentations'] = len(_read_jsonl(Path(cases)))
    summary['sampling_design'] = '3 per seed, 3 per profile, 6 per context; 30 distinct base contexts; partial factorial'
    (root / 'coordinator' / 'annotation_summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    items = _read_csv(root / 'coordinator' / 'annotation_items.csv')
    for slot in range(1, 4):
        folder = root / f'rater_{slot}'
        folder.mkdir(parents=True, exist_ok=True)
        ordered = sorted(items, key=lambda r: hashlib.sha256(f'{seed}|{slot}|{r["item_id"]}'.encode()).hexdigest())
        rows = [{**dict.fromkeys(RESPONSE_FIELDS, ''), 'item_id': r['item_id'], 'rater_slot': slot} for r in ordered]
        _write_csv(folder / 'responses.csv', rows, RESPONSE_FIELDS)
        cards = []
        for n, item in enumerate(ordered, 1):
            fields = ''.join(f'<tr><th>{html.escape(k)}</th><td><pre>{html.escape(v or "[not provided]")}</pre></td></tr>' for k,v in item.items() if k != 'item_id')
            cards.append(f'<article><h2>{n}. {item["item_id"]}</h2><table>{fields}</table></article>')
        (folder / 'items.html').write_text('<!doctype html><meta charset="utf-8"><title>Blinded alert review</title><style>body{max-width:1000px;margin:30px auto;font:16px Arial}article{border-top:2px solid #555;margin:30px 0}th{text-align:left;vertical-align:top;width:220px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px monospace}td{padding:5px}table{width:100%}</style><h1>30 alert presentations</h1><p>Review independently. Record your answers in responses.csv using item_id. Read protocol_vi.md first.</p>' + ''.join(cards), encoding='utf-8')
    protocol = Path(__file__).resolve().parents[2] / 'docs' / 'human30_protocol_vi.md'
    if protocol.exists():
        for slot in range(1, 4):
            (root / f'rater_{slot}' / 'protocol_vi.md').write_text(protocol.read_text(encoding='utf-8-sig'), encoding='utf-8')
    return summary


def validate_panel(key, responses):
    ids = {r['item_id'] for r in key}
    if len(key) != 30 or len(ids) != 30 or len(responses) != 90:
        raise ValueError('Require exactly 30 unique items and 90 ratings')
    grouped = defaultdict(list)
    slots = defaultdict(set)
    for row in responses:
        if row.get('item_id') not in ids or not row.get('rater_id', '').strip():
            raise ValueError('Unknown item or empty rater_id')
        grouped[row['item_id']].append(row['rater_id'].strip())
        if row.get('rater_slot') not in {'1','2','3'}:
            raise ValueError('rater_slot must be 1, 2, or 3')
        slots[row['rater_slot']].add(row['rater_id'].strip())
    raters = {r for values in grouped.values() for r in values}
    if len(raters) != 3 or any(len(v) != 3 or set(v) != raters for v in grouped.values()):
        raise ValueError('The same three distinct raters must each rate every item once')
    if len(slots) != 3 or any(len(v) != 1 for v in slots.values()):
        raise ValueError('Each rater slot must map to one consistent rater')


def clean_json(value):
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {k: clean_json(v) for k,v in value.items()}
    if isinstance(value, list):
        return [clean_json(v) for v in value]
    return value


def main():
    p = argparse.ArgumentParser(__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--cases', default='runs/experiments/controlled/controlled_cases.jsonl')
    prep.add_argument('--output', default='runs/paper_extension/human30')
    analysis = sub.add_parser('analyze')
    analysis.add_argument('--key', required=True)
    analysis.add_argument('--responses', nargs=3, required=True)
    analysis.add_argument('--output', required=True)
    a = p.parse_args()
    if a.command == 'prepare':
        print(json.dumps(prepare(a.cases, a.output), indent=2))
    else:
        key = _read_csv(a.key)
        responses = [r for file in a.responses for r in _read_csv(file)]
        validate_panel(key, responses)
        result = analyze_annotations(key, responses, bootstrap_repetitions=2000)
        result['provenance'] = {
            'key_sha256': hashlib.sha256(Path(a.key).read_bytes()).hexdigest(),
            'response_sha256': {str(Path(f)): hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in a.responses},
        }
        result['study_status'] = 'completed ratings analyzed; expertise must be documented separately'
        result['undefined_metrics'] = 'null denotes undefined statistics; no variation or no eligible cases'
        Path(a.output).parent.mkdir(parents=True, exist_ok=True)
        Path(a.output).write_text(json.dumps(clean_json(result), indent=2, allow_nan=False), encoding='utf-8')

if __name__ == '__main__':
    main()
