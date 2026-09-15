"""Paper figure; time whiskers are min-max repeated runs, not confidence intervals."""
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

root=Path('runs/paper_extension')
first=json.loads((root/'external/manifest.json').read_text())
second=json.loads((root/'external_recheck/manifest.json').read_text())
rows=first['results'];names=[r['scenario'] for r in rows];x=list(range(len(names)))
plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False})
fig,axes=plt.subplots(1,3,figsize=(15,4.8),layout='constrained')
values=[r['archetype_mean_actionability'] for r in rows]
axes[0].bar(x,values,color='#287f8e',width=.6)
for i,v in enumerate(values):axes[0].text(i,v+.018,f'{v:.4f}',ha='center',fontsize=9)
axes[0].set_ylim(0,1);axes[0].set_ylabel('Unweighted archetype mean (0-1)');axes[0].set_title('Evidence readiness across scenarios')
for folder,label,offset,color in [('external','Initial run',-.10,'#287f8e'),('external_recheck','Recheck',.10,'#ce7541')]:
    benchmarks=[json.loads((root/folder/s/'bench_scoring/benchmark.json').read_text()) for s in names]
    vals=[b['process_wall_seconds']['median'] for b in benchmarks]
    low=[v-b['process_wall_seconds']['minimum'] for v,b in zip(vals,benchmarks)]
    high=[b['process_wall_seconds']['maximum']-v for v,b in zip(vals,benchmarks)]
    axes[1].errorbar([i+offset for i in x],vals,yerr=[low,high],fmt='o',capsize=4,label=label,color=color)
    axes[2].plot([i+offset for i in x],[b['peak_rss_mib']['median'] for b in benchmarks],'o',label=label,color=color)
axes[1].set_ylabel('Scoring process wall time (seconds)');axes[1].set_title('Median and min-max of five runs');axes[1].set_ylim(bottom=0);axes[1].legend(frameon=False)
axes[2].set_ylabel('Median OS peak RSS (MiB)');axes[2].set_title('Scoring memory includes Python');axes[2].set_ylim(0,40)
for ax in axes:
 ax.set_xticks(x,names,rotation=25,ha='right');ax.grid(axis='y',alpha=.18);ax.set_axisbelow(True)
fig.suptitle('AIT-ADS offline validation: fixed scoring configuration',fontsize=15)
out=root/'figures';out.mkdir(exist_ok=True)
fig.savefig(out/'paper_extension.png',dpi=220)
fig.savefig(out/'paper_extension.pdf')
plt.close(fig)
