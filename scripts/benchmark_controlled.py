import json
from pathlib import Path
from as_engine.benchmark import measure, environment, sha256
root=Path('runs/paper_extension/controlled_cost')
result=measure('as_engine.experiment',['--eve','logs/suricata/eve.json','--rules','rules/rule_metadata.yaml','--scoring','config/scoring-v2.yaml','--profile','proposed_default','--output-dir',str(root/'generated'),'--no-figures'],root/'benchmark',5)
result['environment']=environment()
result['scope']='Generate 500 controlled presentations, tables, sensitivity calculations and 300-item annotation pack; figures disabled. This is experiment-generation cost, not raw-alert scoring throughput.'
result['input_sha256']={f:sha256(f) for f in ['logs/suricata/eve.json','config/scoring-v2.yaml','config/controlled_variants.yaml','config/context_variants.yaml','rules/rule_metadata.yaml']}
(root/'summary.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result['process_wall_seconds']))
