"""Offline module benchmark: process wall time, CPU time, OS peak resident memory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import statistics
import subprocess
import sys
import time
import psutil


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def worker(module, arguments, metrics):
    sys.argv = [module, *arguments]
    start = time.perf_counter()
    cpu = time.process_time()
    runpy.run_module(module, run_name='__main__')
    elapsed, cpu_elapsed = time.perf_counter() - start, time.process_time() - cpu
    if os.name == 'nt':
        peak = psutil.Process().memory_info().peak_wset
    else:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform != 'darwin':
            peak *= 1024
    Path(metrics).write_text(json.dumps({'module_wall_seconds': elapsed, 'cpu_seconds': cpu_elapsed,
        'peak_rss_mib': peak / 1024**2}), encoding='utf-8')


def measure(module, arguments, directory, repeats=5, warmups=1):
    if repeats < 1 or warmups < 0:
        raise ValueError('Invalid repeat count')
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for index in range(warmups + repeats):
        metrics = directory / f'metrics_{index}.json'
        cmd = [sys.executable, '-m', 'as_engine.benchmark', '--worker', module, str(metrics), *map(str, arguments)]
        start = time.perf_counter()
        with (directory / f'run_{index}.log').open('w', encoding='utf-8') as log:
            subprocess.run(cmd, check=True, stdout=log, stderr=subprocess.STDOUT)
        row = json.loads(metrics.read_text())
        row.update(process_wall_seconds=time.perf_counter()-start, repetition=index, warmup=index < warmups)
        rows.append(row)
    included = [r for r in rows if not r['warmup']]
    result = {'module': module, 'arguments': list(map(str, arguments)), 'runs': rows,
              'repeats': repeats, 'warmups': warmups}
    for field in ('process_wall_seconds', 'module_wall_seconds', 'cpu_seconds', 'peak_rss_mib'):
        values = [r[field] for r in included]
        result[field] = {'median': statistics.median(values), 'minimum': min(values), 'maximum': max(values)}
    (directory / 'benchmark.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def environment():
    return {'platform': platform.platform(), 'python': sys.version, 'processor': platform.processor(),
        'logical_cpus': psutil.cpu_count(), 'physical_cpus': psutil.cpu_count(logical=False),
        'ram_gib': psutil.virtual_memory().total / 1024**3, 'psutil': psutil.__version__,
        'measurement': 'Fresh subprocess per repetition; one warmup; OS cache not flushed. Wall includes process startup and output I/O; CPU excludes worker bootstrap. Peak RSS is OS high-water mark for the child, including Python runtime. No network download, Suricata detection or parent memory included.'}

if __name__ == '__main__':
    if len(sys.argv) >= 4 and sys.argv[1] == '--worker':
        worker(sys.argv[2], sys.argv[4:], sys.argv[3])
    else:
        raise SystemExit('Use as_engine.external_validation to run the benchmark suite')
