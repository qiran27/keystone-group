#!/usr/bin/env python3
"""Extent-I/O real-system three-configuration summary; stdlib-only SVG figures."""
import argparse
import csv
import hashlib
import html
import math
import pathlib
import statistics as stats

CASES = ('sync-1', 'async-1', 'async-3')
LABELS = ('Sync, 1 enclave', 'Async, 1 enclave', 'Async, 3 enclaves')


def read(path):
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def one(path):
    rows = read(path)
    if len(rows) != 1:
        raise ValueError('expected exactly one production case: ' + str(path))
    return rows[0]


def write(path, rows):
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)


def integer(row, name):
    n = float(row[name])
    if not math.isfinite(n) or n < 0 or n != int(n):
        raise ValueError('invalid integer: ' + name)
    return int(n)


def union(items):
    result = []
    for lo, hi in sorted(items):
        if hi < lo:
            raise ValueError('reversed interval')
        if result and lo <= result[-1][1]:
            result[-1] = (result[-1][0], max(hi, result[-1][1]))
        else:
            result.append((lo, hi))
    return result


def intersection(left, right):
    left, right = union(left), union(right)
    i = j = total = 0
    while i < len(left) and j < len(right):
        total += max(0, min(left[i][1], right[j][1]) - max(left[i][0], right[j][0]))
        if left[i][1] <= right[j][1]: i += 1
        else: j += 1
    return total


def timeline(root, entry, total_bytes):
    events = read(root / entry['gantt_csv'])
    crypto = read(root / entry['crypto_csv'])
    workers = int(entry['workers'])
    starts = [int(r['timestamp_ns']) for r in events if r['event'] == 'perf_begin']
    ends = [int(r['timestamp_ns']) for r in events if r['event'] == 'perf_end']
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0] or not crypto:
        raise ValueError('missing complete diagnostic window')
    if any(r['event'] == 'case_abort' or int(r['request_events_omitted']) or
           int(r['request_sample_stride']) != 1 for r in events):
        raise ValueError('aborted or sampled diagnostic')
    origin, limit = starts[0], ends[0]
    pending = {}; spans = []; seen = set(); read_bytes = 0
    for r in sorted(events, key=lambda x: int(x['event_seq'])):
        if r['operation'] != 'read' or r['event'] not in ('storage_io_begin', 'storage_io_end'):
            continue
        key = (r['worker_index'], r['run_id'], r['request_id'])
        t = int(r['timestamp_ns'])
        if r['event'] == 'storage_io_begin':
            if key in pending or key in seen: raise ValueError('duplicate storage begin')
            pending[key] = r
        else:
            if key not in pending or int(r['result']): raise ValueError('unmatched/failed storage end')
            first = pending.pop(key); lo = int(first['timestamp_ns'])
            worker = int(r['worker_index'])
            if not 0 <= worker < workers or not origin <= lo <= t <= limit:
                raise ValueError('invalid storage interval')
            spans.append(dict(configuration=entry['mode']+'-'+entry['workers'], worker=worker,
                              stage='Host storage service', begin_ns=lo-origin, end_ns=t-origin,
                              bytes=int(r['length']), uncertainty_ns=0))
            read_bytes += int(r['length']); seen.add(key)
    if pending or read_bytes != total_bytes: raise ValueError('incomplete Host read coverage')
    amounts = [0]*workers; counts = [0]*workers; last = [origin]*workers
    coverage = [[] for _ in range(workers)]
    for r in crypto:
        w = int(r['worker']); lo = int(r['begin_ns']); hi = int(r['end_ns'])
        error = int(r['clock_uncertainty_ns']); hz = int(r['timebase_hz'])
        if not 0 <= w < workers or int(r['sequence']) != counts[w] or hz <= 0:
            raise ValueError('invalid Worker identity/sequence')
        if not origin-error <= lo <= hi <= limit+error or lo < last[w] or not 0<int(r['bytes'])<=2000000:
            raise ValueError('invalid crypto coverage or alignment')
        if int(r['runtime_ticks']) > int(r['end_ticks'])-int(r['begin_ticks']):
            raise ValueError('crypto on-CPU duration exceeds wall interval')
        spans.append(dict(configuration=entry['mode']+'-'+entry['workers'], worker=w,
                          stage='Enclave crypto (wall interval)', begin_ns=lo-origin,
                          end_ns=hi-origin, bytes=int(r['bytes']), uncertainty_ns=error))
        amounts[w] += int(r['bytes']); counts[w] += 1; last[w] = hi
        coverage[w].append((int(r['logical_offset']),int(r['logical_offset'])+int(r['bytes'])))
    if sum(amounts) != total_bytes or not all(counts): raise ValueError('incomplete Worker crypto coverage')
    for w in range(workers):
        next_offset = 0
        for lo,hi in sorted(coverage[w]):
            if lo!=next_offset: raise ValueError('overlap/gap in Worker coverage')
            next_offset=hi
        expected=(total_bytes//240//workers+(w<total_bytes//240%workers))*240
        if next_offset!=expected: raise ValueError('wrong Worker partition size')
    host = [(s['begin_ns'],s['end_ns']) for s in spans if s['stage'].startswith('Host')]
    cpu = [(s['begin_ns'],s['end_ns']) for s in spans if s['stage'].startswith('Enclave')]
    report = dict(configuration=entry['mode']+'-'+entry['workers'], complete=1,
                  host_intervals=len(host), crypto_intervals=len(cpu), total_bytes=total_bytes,
                  read_service_crypto_overlap_ms=intersection(host,cpu)/1e6,
                  clock_uncertainty_max_ns=max(s['uncertainty_ns'] for s in spans),
                  scope='Host-service/crypto-wall intersection; not physical disk busy or pure CPU time')
    return spans, report


def svg_start(width, height, title):
    return [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
            '<rect width="100%" height="100%" fill="white"/>',
            '<style>text{font-family:Arial,sans-serif;fill:#20242b;font-size:13px}</style>',
            f'<text x="24" y="30" style="font-size:19px">{html.escape(title)}</text>']


def perf_svg(rows):
    parts = svg_start(900, 300, 'Extent-I/O: End-to-End Motivation')
    high = max(r['seconds_max'] for r in rows)*1.12
    for i, r in enumerate(rows):
        y = 67+i*65; x = 220; scale = 600/high
        parts.append(f'<text x="24" y="{y+17}">{LABELS[i]}</text>')
        parts.append(f'<rect x="{x}" y="{y}" width="{r["seconds_median"]*scale:.2f}" height="27" fill="{("#617482","#287f9a","#45835a")[i]}"/>')
        lo = x+r['seconds_min']*scale; hi = x+r['seconds_max']*scale
        parts.append(f'<path d="M {lo:.2f} {y+13} H {hi:.2f} M {lo:.2f} {y+7} V {y+20} M {hi:.2f} {y+7} V {y+20}" stroke="#151b22"/>')
        parts.append(f'<text x="{x+5}" y="{y+45}">{r["seconds_median"]:.4f} s; n={r["samples"]}</text>')
    parts.append('<text x="24" y="285">Median total time; whiskers: measured min/max. Diagnostic runs excluded.</text></svg>')
    return '\n'.join(parts)


def timeline_svg(spans):
    parts = svg_start(1120, 620, 'Extent-I/O: Execution Timeline (Separate Diagnostic Runs)')
    # Fixed rule, not a best-case crop: common startup window ending at the
    # sixth single-Worker Sync crypto completion, or its last block if fewer.
    sync = sorted(s['end_ns'] for s in spans if s['configuration']=='sync-1' and s['stage'].startswith('Enclave'))
    end = max(1,sync[min(5,len(sync)-1)])
    left = 235; scale = 850/end; y = 67
    for index, case in enumerate(CASES):
        parts.append(f'<text x="24" y="{y}" style="font-weight:bold">{LABELS[index]}</text>'); y += 23
        workers = 3 if case=='async-3' else 1
        for stage, w in [('Host',None)]+[('Enclave',w) for w in range(workers)]:
            label = 'Host storage service' if w is None else f'Worker {w+1} / lane {w}: crypto'
            parts.append(f'<text x="24" y="{y+13}">{label}</text>')
            parts.append(f'<path d="M {left} {y+20} H 1090" stroke="#d4d8dd"/>')
            for s in spans:
                if s['configuration']!=case or not s['stage'].startswith(stage) or (w is not None and s['worker']!=w): continue
                lo = max(0,s['begin_ns']); hi = min(end,s['end_ns'])
                if hi>lo:
                    parts.append(f'<rect x="{left+lo*scale:.3f}" y="{y}" width="{max(.25,(hi-lo)*scale):.3f}" height="18" fill="{("#287f9a" if w is None else "#d08738")}"><title>{html.escape(str(s))}</title></rect>')
            y += 32
        y += 23
    for i in range(6):
        x = left+850*i/5
        parts.append(f'<text x="{x:.1f}" y="{y}">{end*i/5e6:.1f}</text>')
    parts.append(f'<text x="235" y="{y+25}">Time from diagnostic window start (ms); identical startup crop across panels</text>')
    parts.append(f'<text x="24" y="{y+57}">Host service is not physical disk busy time. Crypto wall intervals may include descheduling.</text>')
    parts.append(f'<text x="24" y="{y+78}">Complete intervals and clock uncertainty are retained in timeline-intervals.csv.</text></svg>')
    return '\n'.join(parts)


def summarize(root):
    manifest = read(root/'manifest.csv')
    if not manifest or len({r['run_id'] for r in manifest})!=len(manifest): raise ValueError('empty/duplicate manifest')
    samples = []; evidence = []; hashes = []
    identities = set(); kinds = set(); digests = {}
    for e in manifest:
        if e['status']!='complete': raise ValueError('failed run retained: '+e['run_id'])
        case = e['mode']+'-'+e['workers']
        if case not in CASES: raise ValueError('unexpected configuration')
        interface = e.get('interface', 'sqlite')
        if interface not in ('sqlite', 'fio'): raise ValueError('unknown production interface')
        workload = 'readseq' if interface == 'sqlite' else 'fio-seq-read-2m'
        p = one(root/e['performance_csv']); io = one(root/e['io_csv'])
        for path in (e['performance_csv'],e['io_csv'],e['gantt_csv'],e['crypto_csv']):
            if path: hashes.append(hashlib.sha256((root/path).read_bytes()).hexdigest()+'  '+path)
        expected = e['mode']+'-no-extent'
        if p['io_mode']!=expected or integer(p,'worker_count')!=int(e['workers']) or integer(p,'samples')!=1 or p['workload']!=workload:
            raise ValueError('production case selection mismatch')
        for field in ('io_mode','worker_count','samples','workload','cache_mode','cipher'):
            if p[field]!=io[field]: raise ValueError('performance/I/O mismatch: '+field)
        total = integer(p,'total_bytes'); seconds = float(p['seconds_median']); throughput = float(p['mb_per_sec_median'])
        if not math.isfinite(seconds) or seconds<=0 or not math.isclose(throughput,total/1e6/seconds,rel_tol=2e-8):
            raise ValueError('inconsistent total time/throughput')
        if integer(p,'vfs_read_bytes')!=total or integer(p,'vfs_write_bytes') or integer(io,'useful_bytes_median')!=total or integer(io,'failed_request_count_median'):
            raise ValueError('invalid workload byte/I/O coverage')
        diag = e['kind']=='timeline'
        if p['timing_scope'].startswith('diagnostic-')!=diag or bool(e['crypto_csv'])!=diag or bool(e['gantt_csv'])!=diag:
            raise ValueError('diagnostic/performance separation violated')
        if e['kind'] not in ('formal','diagnostic','timeline'): raise ValueError('unknown run kind')
        identities.add((interface,total,p['cipher'],p['cache_mode'],p['workload'],p['address_mode']))
        key = e['workers']
        if key in digests and digests[key]!=p['digest']: raise ValueError('same-N result digest mismatch')
        digests[key] = p['digest']
        row = dict(run_id=e['run_id'],kind=e['kind'],configuration=case,repetition=int(e['repetition']),
                   order=int(e['order']),total_bytes=total,seconds=seconds,mb_per_sec=throughput,
                   logical_data_requests=integer(io,'member_request_count_median'),
                   host_data_operations=integer(io,'io_request_count_median'),
                   io_uring_submissions=integer(p,'io_uring_submissions'),
                   doorbells=integer(p,'vfs_ring_doorbells'),completion_waits=integer(p,'completion_wait_ocalls'),
                   result_digest=p['digest'],cipher=p['cipher'],cache=p['cache_mode'],interface=interface)
        if diag: evidence.append((e,total))
        else: samples.append(row); kinds.add(e['kind'])
    if len(identities)!=1 or len(kinds)!=1: raise ValueError('mixed workloads/ciphers/cache/sample kinds')
    if {e['mode']+'-'+e['workers'] for e,_ in evidence}!=set(CASES) or len(evidence)!=3:
        raise ValueError('missing or repeated diagnostic configuration')
    groups = {}
    for r in samples: groups.setdefault(r['repetition'],[]).append(r)
    if any(len(g)!=3 or {r['configuration'] for r in g}!=set(CASES) or {r['order'] for r in g}!={1,2,3} for g in groups.values()):
        raise ValueError('incomplete performance triplet')
    rows = []
    for case in CASES:
        selected = [r for r in samples if r['configuration']==case]
        if not selected: raise ValueError('missing performance configuration')
        row = dict(configuration=case,samples=len(selected),total_bytes=selected[0]['total_bytes'],
                   cipher=selected[0]['cipher'],cache=selected[0]['cache'],interface=selected[0]['interface'],
                   formal_eligible=int(kinds=={'formal'} and len(groups)>=3))
        for name in ('seconds','mb_per_sec','logical_data_requests','host_data_operations','io_uring_submissions','doorbells','completion_waits'):
            for suffix,fn in (('median',stats.median),('min',min),('max',max)):
                row[name+'_'+suffix]=fn(r[name] for r in selected)
        rows.append(row)
    for r in rows:
        r['speedup_vs_sync1']=rows[0]['seconds_median']/r['seconds_median']
        r['time_reduction_vs_sync1_pct']=(1-r['seconds_median']/rows[0]['seconds_median'])*100
        r['speedup_vs_async1']=rows[1]['seconds_median']/r['seconds_median']
        r['host_io_reduction_vs_sync1_pct']=(1-r['host_data_operations_median']/rows[0]['host_data_operations_median'])*100
    spans = []; reports = []
    for entry,total in evidence:
        s,r = timeline(root,entry,total); spans.extend(s); reports.append(r)
    write(root/'samples.csv',samples); write(root/'summary.csv',rows)
    write(root/'timeline-intervals.csv',spans); write(root/'timeline-evidence.csv',reports)
    (root/'performance.svg').write_text(perf_svg(rows),encoding='utf-8')
    (root/'timeline.svg').write_text(timeline_svg(spans),encoding='utf-8')
    (root/'input-sha256.txt').write_text('\n'.join(hashes)+'\n',encoding='utf-8')
    (root/'results.txt').write_text('Extent-I/O primary architecture motivation: production Master/protected TSR/Worker/Host path\n'+
        'Production interface: '+rows[0]['interface']+'; existing sequential-read workload, not minimal 64KB framing.\n'+
        '\n'.join(str(r) for r in rows)+'\n'+
        'Whole-architecture comparison, not isolated overlap or clustering gain.\n'+
        'Formal eligibility requires >=3 complete untraced triplets; actual per-configuration samples are reported.\n'+
        'Sync uses the production Host BLOB path; Async uses metadata plus external ciphertext I/O.\n'+
        'Same-N digests checked; cross-N partitioning follows the real workload and need not have identical digests.\n'+
        'io_uring_submissions counts that backend only; zero for Sync does not mean zero SQLite/kernel calls.\n'+
        'Timeline uses three separate diagnostic runs, not median timing samples. No gain is guaranteed.\n',encoding='utf-8')
    return rows


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('directory',type=pathlib.Path)
    args = p.parse_args()
    result = summarize(args.directory)
    print('[motivation-system] configurations=3 formal_eligible='+str(all(r['formal_eligible'] for r in result)))
