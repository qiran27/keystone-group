#!/usr/bin/env python3
"""Plan and summarize the single-worker cipher experiment using real samples."""
import argparse
import csv
import math
from pathlib import Path
import statistics

ALGORITHMS = ('aes-ecb-128', 'aes-gcm-128', 'chacha20-poly1305')
SIZES = (60, 100, 200, 300, 400, 500)
METRICS = ('wall_seconds', 'cpu_seconds', 'descheduled_seconds', 'wall_mb_per_sec', 'cpu_mb_per_sec')


def make_plan(repeats, size, destination, algorithm='all'):
    sizes = SIZES if size == 'sweep' else (int(size[:-2]),)
    if not 1 <= repeats <= 20 or any(mb not in SIZES for mb in sizes):
        raise ValueError('repetitions must be 1..20; size must be sweep or a supported MB size')
    if algorithm != 'all' and algorithm not in ALGORITHMS:
        raise ValueError('cipher must be all or a supported algorithm')
    algorithms = ALGORITHMS if algorithm == 'all' else (algorithm,)
    with destination.open('x', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(('cipher', 'operation', 'total_bytes', 'sample'))
        for cipher in algorithms:
            for mb in sizes:
                for sample in range(1, repeats + 1):
                    operations = ('encrypt', 'decrypt') if sample % 2 else ('decrypt', 'encrypt')
                    for operation in operations:
                        writer.writerow((cipher, operation, mb * 1000000, sample))


def summarize(directory):
    with (directory/'plan.csv').open(newline='', encoding='utf-8') as f:
        planned = list(csv.DictReader(f))
    with (directory/'samples.csv').open(newline='', encoding='utf-8') as f:
        samples = list(csv.DictReader(f))
    def key(r):
        return r['cipher'], r['operation'], int(r['total_bytes']), int(r['sample'])
    expected = {key(r) for r in planned}
    assert len(expected) == len(planned), 'duplicate plan keys'
    assert len(samples) == len(expected) and {key(r) for r in samples} == expected, 'missing or duplicate samples'
    groups = {}
    for r in samples:
        assert r['execution_environment'] == 'riscv-worker-enclave'
        assert r['timing_scope'] == 'sum-of-transform-intervals'
        assert r['validated'] == '1' and r['error_code'] == '0', 'failed sample remains in raw CSV'
        assert r['worker_count'] == '1' and r['data_io_operations'] == '0' and r['timed_ocalls'] == '0'
        total, processed, hz = (int(r[k]) for k in ('total_bytes', 'processed_bytes', 'timebase_hz'))
        wall, cpu = (float(r[k]) for k in ('wall_seconds', 'cpu_seconds'))
        assert total == processed and hz > 0 and 0 < cpu <= wall
        for k in METRICS:
            assert math.isfinite(float(r[k])), ('nonfinite metric', k)
        assert math.isclose(wall, int(r['wall_ticks'])/hz, rel_tol=1e-10)
        assert math.isclose(cpu, int(r['cpu_ticks'])/hz, rel_tol=1e-10)
        assert math.isclose(float(r['wall_mb_per_sec']), total/wall/1e6, rel_tol=1e-10)
        assert math.isclose(float(r['cpu_mb_per_sec']), total/cpu/1e6, rel_tol=1e-10)
        assert math.isclose(float(r['descheduled_seconds']), wall-cpu, abs_tol=1e-9)
        block = int(r['block_bytes'])
        assert block > 0 and int(r['blocks']) == (total+block-1)//block
        groups.setdefault(key(r)[:3], []).append(r)
    rows = []
    for (algorithm, operation, total), rs in sorted(groups.items(), key=lambda item:(item[0][2], item[0][1], ALGORITHMS.index(item[0][0]))):
        row = {'total_mb':total//1000000, 'cipher':algorithm, 'operation':operation,
               'worker_count':1, 'samples':len(rs), 'total_bytes':total,
               'authenticated':int(algorithm != 'aes-ecb-128')}
        for metric in METRICS:
            values = [float(r[metric]) for r in rs]
            row.update({metric+'_min':min(values), metric+'_median':statistics.median(values), metric+'_max':max(values)})
        rows.append(row)
    with (directory/'summary.csv').open('x', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        writer.writeheader(); writer.writerows(rows)
    comparison = []
    for total in sorted({k[2] for k in groups}):
        for operation in ('encrypt', 'decrypt'):
            row = {'total_mb':total//1000000, 'operation':operation, 'worker_count':1}
            for algorithm in ALGORITHMS:
                if (algorithm, operation, total) not in groups:
                    continue
                rs = groups[algorithm, operation, total]
                row[algorithm+'_samples'] = len(rs)
                for metric in ('wall_mb_per_sec', 'cpu_mb_per_sec'):
                    values = [float(r[metric]) for r in rs]
                    row.update({algorithm+'_'+metric+'_'+s:v for s,v in zip(('min','median','max'), (min(values),statistics.median(values),max(values)))})
            comparison.append(row)
    with (directory/'comparison.csv').open('x', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(comparison[0]), lineterminator='\n')
        writer.writeheader(); writer.writerows(comparison)
    print(f'[crypto-compute] verified {len(samples)} real samples, {len(rows)} summary rows; {directory}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    plan = sub.add_parser('plan')
    plan.add_argument('repetitions', type=int); plan.add_argument('size'); plan.add_argument('destination', type=Path)
    plan.add_argument('--cipher', choices=('all',) + ALGORITHMS, default='all')
    summary = sub.add_parser('summarize'); summary.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.command == 'plan': make_plan(args.repetitions, args.size, args.destination, args.cipher)
    else: summarize(args.directory)
