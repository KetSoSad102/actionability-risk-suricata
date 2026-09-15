import csv
import math
from pathlib import Path
import tempfile
import unittest
from collections import Counter
from as_engine.human_study import select_thirty, prepare, validate_panel, clean_json
from as_engine.annotation import _read_jsonl
from as_engine.annotation_analysis import krippendorff_alpha_ordinal, spearman

ROOT = Path(__file__).resolve().parents[1]

class HumanPilotTests(unittest.TestCase):
    def test_partial_factorial_balance_and_distinct_base_contexts(self):
        records = _read_jsonl(ROOT/'runs/experiments/controlled/controlled_cases.jsonl')
        selected = select_thirty(records)
        self.assertEqual(selected, select_thirty(list(reversed(records))))
        for key, count in [('seed_id',3),('context',6),('evidence_profile',3)]:
            self.assertEqual(set(Counter(r['experiment'][key] for r in selected).values()), {count})
        self.assertEqual(len({r['experiment']['base_context_id'] for r in selected}),30)

    def test_pack_blinding_same_items_different_order_and_empty_ratings(self):
        with tempfile.TemporaryDirectory() as d:
            prepare(ROOT/'runs/experiments/controlled/controlled_cases.jsonl',d)
            ids=[]
            for slot in range(1,4):
                folder=Path(d)/f'rater_{slot}'
                with (folder/'responses.csv').open(encoding='utf-8') as f: rows=list(csv.DictReader(f))
                ids.append([r['item_id'] for r in rows])
                self.assertTrue(all(not r['actionability_likert_1_5'] for r in rows))
                page=(folder/'items.html').read_text(encoding='utf-8')
                self.assertNotIn('automated_actionability_score',page)
                self.assertNotIn('evidence_profile',page)
                self.assertFalse((folder/'annotation_key.csv').exists())
            self.assertEqual(set(ids[0]),set(ids[1]))
            self.assertEqual(set(ids[0]),set(ids[2]))
            self.assertNotEqual(ids[0],ids[1])

    def test_same_three_raters_required(self):
        key=[{'item_id':str(i)} for i in range(30)]
        rows=[{'item_id':str(i),'rater_slot':str(r),'rater_id':f'R{r}'} for i in range(30) for r in range(1,4)]
        validate_panel(key,rows)
        for changed in ('R1','R4',''):
            bad=[dict(r) for r in rows];bad[1]['rater_id']=changed
            with self.assertRaises(ValueError):validate_panel(key,bad)
        with self.assertRaises(ValueError):validate_panel(key,rows[:-1])

    def test_ordinal_distance_uses_category_marginals(self):
        # 1,2,5 frequencies 3,2,1; ordinal distances: 6.25, 2.25, 16.
        # Three two-rater units: observed=(0+2.25+6.25)/3;
        # expected=2*(3*2*6.25+2*1*2.25+3*1*16)/(6*5)=6.
        self.assertAlmostEqual(krippendorff_alpha_ordinal([[1,1],[2,5],[1,2]]), 1-(8.5/3)/6)
        self.assertTrue(math.isnan(spearman([1,1],[2,3])))
        self.assertIsNone(clean_json(float('nan')))

if __name__=='__main__':unittest.main()
