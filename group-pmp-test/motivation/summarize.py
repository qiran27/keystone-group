#!/usr/bin/env python3
"""Summarize 1-Sync, 1-Async and 3-Async with fixed total input."""
import argparse
import csv
import pathlib
import statistics as stats
from collections import defaultdict
from xml.sax.saxutils import escape


def write_csv(path, rows):
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    if len({(r.get('csv_schema','1'),r.get('timing_scope','worker-start-to-release-v1'),
             r.get('execution_environment','riscv-enclave'),r['crypto_algorithm']) for r in rows})>1:
        raise ValueError('different cipher/timing/schema revisions must be summarized separately')
    groups = defaultdict(list)
    seen = set()
    for r in rows:
        if r["run_id"] in seen:
            raise ValueError("duplicate run_id: " + r["run_id"])
        seen.add(r["run_id"])
        groups[(int(r["input_bytes"]), r["cache_policy"], r["diagnostic"],
                r.get('csv_schema','1'), r.get('timing_scope','worker-start-to-release-v1'),
                int(r['block_bytes']))].append(r)
    result = []
    for (size, cache, diag, schema, timing, block_bytes), group in sorted(groups.items()):
        if schema not in ('1','2','3','4','5','6','7','8'):
            raise ValueError('unknown motivation schema: '+schema)
        cases=('sync','async','async3') if schema in ('2','3','4','5','6','7','8') else ('sync','async')
        def case(r):
            key=(r['mode'],r['worker_enclaves'])
            names={('sync','1'):'sync',('async','1'):'async',('async','3'):'async3'}
            if key not in names or names[key] not in cases:
                raise ValueError('unsupported configuration: '+r['run_id'])
            return names[key]
        valid = {m: [r for r in group if case(r)==m and r["result_ok"] == "1"] for m in cases}
        for m in valid:
            for r in valid[m]:
                if (int(r["processed_bytes"]) != size or int(r["elapsed_ns"]) <= 0
                        or int(r["host_data_operations"]) != int(r["block_count"])
                        or r["slots"] != "2" or int(r.get('max_outstanding','2'))>2*int(r['worker_enclaves'])):
                    raise ValueError("invalid successful sample: " + r["run_id"])
                if schema in ('2','3','4','5','6','7','8') and (int(r['total_data_slots'])!=2*int(r['worker_enclaves'])
                                   or int(r['host_io_threads'])!=(2 if schema=='2' else 1)*int(r['worker_enclaves'])):
                    raise ValueError('slot/thread configuration mismatch: '+r['run_id'])
                if schema in ('3','4','5','6','7','8') and (r['io_backend']!='shared-io-uring-fixed'
                                    or int(r['completion_cqes'])!=int(r['block_count'])
                                    or int(r['submit_syscalls'])<1
                                    or int(r['max_outstanding'])>(1 if m=='sync' else 2*int(r['worker_enclaves']))):
                    raise ValueError('shared transport mismatch: '+r['run_id'])
                if schema in ('4','5','6','7','8') and (r['read_ocall_semantics']!=('blocking-until-read-complete' if m=='sync' else 'admission-only')
                                    or (m=='sync' and (int(r['wait_calls']) or int(r['submit_return_before_io_done'])))):
                    raise ValueError('blocking OCALL contract mismatch: '+r['run_id'])
                if schema in ('5','6','7','8') and (r['active_master']!='1' or
                        any(int(r[k])!=int(r['worker_enclaves']) for k in ('tsr_dispatches','tsr_aggregates','tsr_releases')) or
                        r['master_aggregate_digest']!=r['result_digest'] or
                        r['timing_scope']!='master-first-dispatch-to-final-protected-aggregate'):
                    raise ValueError('protected task/aggregate contract mismatch: '+r['run_id'])
                if schema in ('6','7','8') and r['crypto_algorithm'] not in ('aes-128-ecb','aes-128-gcm'):
                    raise ValueError('unsupported motivation cipher: '+r['run_id'])
                if schema in ('7','8'):
                    count=(size+block_bytes-1)//block_bytes if block_bytes>0 else 0
                    payload=size if r['crypto_algorithm']=='aes-128-gcm' else (size+15)//16*16
                    if (block_bytes not in (4096,16384,65536) or int(r['block_count'])!=count or
                            int(r['ciphertext_bytes'])!=payload+64*count):
                        raise ValueError('invalid block geometry: '+r['run_id'])
                if schema=='8':
                    workers=int(r['worker_enclaves']);count=int(r['block_count'])
                    initial=sum(min(count*(w+1)//workers-count*w//workers,1 if m=='sync' else 2) for w in range(workers))
                    if (int(r['read_ocalls'])!=count or int(r['release_only_ocalls'])!=initial or
                            int(r['release_submit_ocalls'])!=count-initial or int(r['data_path_ocalls'])!=count+initial):
                        raise ValueError('recycle-submit OCALL accounting mismatch: '+r['run_id'])
                if schema in ('2','3','4','5','6','7','8'):
                    begin,end,hz=(int(r[k]) for k in ('cohort_start_ticks','cohort_end_ticks','timebase_hz'))
                    if not 0<begin<end or hz<=0 or abs(int(r['elapsed_ns'])-(end-begin)*1e9/hz)>1:
                        raise ValueError('cohort elapsed clock mismatch: '+r['run_id'])
        row = dict(input_mb=size / 1000000, block_bytes=block_bytes, crypto_algorithm=group[0]['crypto_algorithm'],cache_policy=cache, diagnostic=int(diag),csv_schema=int(schema),timing_scope=timing)
        if schema in ('4','5','6','7','8'): row['execution_environment']=group[0]['execution_environment']
        for m in valid:
            times = [int(r["elapsed_ns"]) / 1e6 for r in valid[m]]
            row[m + "_valid_runs"] = len(times)
            for suffix, fn in (("median", stats.median), ("min", min), ("max", max)):
                row[m + "_ms_" + suffix] = fn(times) if times else ""
            counters=('host_data_operations','submit_syscalls','completion_cqes','wait_calls')
            if schema in ('5','6','7','8'): counters+=('tsr_dispatches','tsr_aggregates','tsr_releases')
            if schema=='8': counters+=('read_ocalls','release_only_ocalls','release_submit_ocalls','data_path_ocalls')
            for counter in counters:
                values=[int(r[counter]) for r in valid[m] if counter in r]
                for suffix,fn in (("median",stats.median),("min",min),("max",max)):
                    row[m+'_'+counter+'_'+suffix]=fn(values) if values else ''
        digests = {r["result_digest"] for v in valid.values() for r in v}
        # Compare all fixed workload properties, not only aggregate digest.
        identity = {tuple(r[k] for k in ("ciphertext_bytes", "block_bytes", "block_count",
                    "crypto_algorithm", "compute_task", "timebase_hz"))
                    for v in valid.values() for r in v}
        consistent = len(digests) == 1 and len(identity) == 1 and all(valid.values())
        row["results_consistent"] = int(bool(consistent))
        row["failed_runs"] = sum(r["result_ok"] != "1" for r in group)
        pairs = defaultdict(list)
        for r in group:
            pairs[r["experiment_block"]].append(r)
        order_ok = all(len(p)==len(cases) and {case(r) for r in p}==set(cases)
                       and {r['order'] for r in p}=={str(i+1) for i in range(len(cases))} for p in pairs.values())
        row["paired_order_complete"] = int(order_ok) if schema=='1' else ''
        row['configuration_order_complete']=int(order_ok)
        row["formal_eligible"] = int(diag == "0" and consistent and order_ok
                                    and group[0].get('execution_environment','riscv-enclave')=='riscv-enclave'
                                    and not row["failed_runs"]
                                    and min(len(v) for v in valid.values()) >= (3 if schema in ('4','5','6','7','8') else 10))
        ts, ta = row["sync_ms_median"], row["async_ms_median"]
        comparable = consistent and ts != "" and ta != ""
        row["speedup_sync_over_async"] = ts / ta if comparable else ""
        row["XX_sync_extra_time_pct"] = (ts / ta - 1) * 100 if comparable else ""
        row["YY_async_time_reduction_pct"] = (1 - ta / ts) * 100 if comparable else ""
        base=row['sync_host_data_operations_median']
        for m in cases:
            value=row[m+'_host_data_operations_median']
            row[m+'_host_io_reduction_vs_sync_pct']=(1-value/base)*100 if comparable and base and value!='' else ''
        t3=row.get('async3_ms_median','')
        row['async3_vs_sync1_speedup']=ts/t3 if comparable and t3!='' else ''
        row['async3_vs_async1_speedup']=ta/t3 if comparable and t3!='' else ''
        row['async3_vs_sync1_time_reduction_pct']=(1-t3/ts)*100 if comparable and t3!='' else ''
        row['async3_vs_async1_time_reduction_pct']=(1-t3/ta)*100 if comparable and t3!='' else ''
        result.append(row)
    return result


def interval_union_ticks(intervals):
    total=0;end=None
    for lo,hi in sorted(intervals):
        if hi<lo: raise ValueError('reversed interval')
        total+=hi-lo if end is None else max(0,hi-max(lo,end))
        end=hi if end is None else max(end,hi)
    return total


def trace_summary(path, sample):
    with path.open(newline="") as f:
        trace = [{k: int(v) for k, v in r.items()} for r in csv.DictReader(f)]
    hz = int(sample["timebase_hz"])
    io = sorted((r["io_begin_ticks"], r["io_end_ticks"], r["block"]) for r in trace)
    cpu = sorted((r["compute_begin_ticks"], r["compute_end_ticks"], r["block"]) for r in trace)
    overlap = 0
    wall_pieces=[]
    first = 0
    for cb, ce, block in cpu:
        while first < len(io) and io[first][1] <= cb:
            first += 1
        pieces = []
        for index in range(first, len(io)):
            ib, ie, other = io[index]
            if ib >= ce:
                break
            if other != block and ie > cb:
                pieces.append((max(cb, ib), min(ce, ie)))
        # Union: overlapping Host reads must not count compute time twice.
        end = cb
        for lo, hi in pieces:
            overlap += max(0, hi - max(lo, end))
            end = max(end, hi)
            wall_pieces.append((lo,hi))
    complete = (len(trace) == int(sample["block_count"])
                and {r["block"] for r in trace} == set(range(len(trace))))
    if sample.get('csv_schema') in ('2','3','4','5','6','7','8'):
        begin,end=int(sample['cohort_start_ticks']),int(sample['cohort_end_ticks'])
        complete=complete and all(begin<=r['admit_ticks']<=r['io_begin_ticks']<=r['io_end_ticks']
                   <=r['compute_begin_ticks']<=r['compute_end_ticks']<=r['release_ticks']<=end for r in trace)
    if sample.get('csv_schema') in ('4','5','6','7','8'):
        complete=complete and all(r['io_end_ticks']<=r['publish_ticks']<=r['compute_begin_ticks'] for r in trace)
        if sample['mode']=='sync':
            complete=complete and all(r['publish_ticks']<=r['submit_return_ticks']<=r['compute_begin_ticks'] for r in trace)
    if sample.get('csv_schema') in ('7','8'):
        complete=complete and all(r['compute_begin_ticks']<=r['capture_end_ticks']<=r['decrypt_end_ticks']<=r['compute_end_ticks'] for r in trace)
    if sample.get('csv_schema')=='8':
        previous={}
        for r in sorted(trace,key=lambda r:r['admit_ticks']):
            key=(r.get('worker',1),r['slot']);old=previous.get(key)
            complete=complete and r['slot'] in (0,1) and (sample['mode']!='sync' or r['slot']==0)
            complete=complete and r['generation']==(old['generation']+1 if old else 1)
            complete=complete and (old is None or old['release_ticks']<=r['admit_ticks'])
            previous[key]=r
    workers=int(sample.get('worker_enclaves','1'))
    if workers>1:
        total=int(sample['block_count'])
        complete=complete and all(1<=r['worker']<=workers and
                    total*(r['worker']-1)//workers<=r['block']<total*r['worker']//workers for r in trace)
    wall=0;end=0
    for lo,hi in sorted(wall_pieces):
        wall+=max(0,hi-max(lo,end));end=max(end,hi)
    io_pairs=[(lo,hi) for lo,hi,_ in io];cpu_pairs=[(lo,hi) for lo,hi,_ in cpu]
    elapsed_ms=int(sample['elapsed_ns'])/1e6 if 'elapsed_ns' in sample else None
    occupied_ms=interval_union_ticks(io_pairs+cpu_pairs)*1000/hz
    report=dict(run_id=sample["run_id"], mode=sample["mode"], worker_enclaves=workers,blocks=len(trace),
                io_interval_scope='submit-preparation-to-CQE-observation' if sample.get('csv_schema') in ('3','4','5','6','7','8') else 'pread-service',
                complete=int(complete), io_compute_overlap_ms=wall * 1000 / hz,
                worker_overlap_ms_sum=overlap*1000/hz,
                early_submit_returns=sum(r["submit_return_ticks"] < r["io_end_ticks"] for r in trace),
                max_outstanding=int(sample["max_outstanding"]),
                out_of_order_consumed=int(sample["out_of_order_consumed"]),
                read_service_ms_sum=sum(hi-lo for lo,hi in io_pairs)*1000/hz,
                read_service_ms_union=interval_union_ticks(io_pairs)*1000/hz,
                processing_ms_sum=sum(hi-lo for lo,hi in cpu_pairs)*1000/hz,
                processing_ms_union=interval_union_ticks(cpu_pairs)*1000/hz,
                cohort_elapsed_ms=elapsed_ms if elapsed_ms is not None else '',
                not_in_read_or_processing_ms=max(0,elapsed_ms-occupied_ms) if elapsed_ms is not None else '')
    if sample.get('csv_schema') in ('7','8'):
        spans={
            'cipher_capture':[(r['compute_begin_ticks'],r['capture_end_ticks']) for r in trace],
            'identity_and_decrypt':[(r['capture_end_ticks'],r['decrypt_end_ticks']) for r in trace],
            'full_byte_verify':[(r['decrypt_end_ticks'],r['compute_end_ticks']) for r in trace],
            'ready_to_consume':[(r['publish_ticks'],r['compute_begin_ticks']) for r in trace],
            'read_admission':[(r['admit_ticks'],r['submit_return_ticks']) for r in trace],
            'release_to_next_submit':[],
        }
        for worker in range(1,workers+1):
            records=sorted((r for r in trace if r.get('worker',1)==worker),key=lambda r:r['admit_ticks'])
            last_release={}
            for r in records:
                if r['slot'] in last_release:
                    spans['release_to_next_submit'].append((last_release[r['slot']],r['admit_ticks']))
                last_release[r['slot']]=r['release_ticks']
        for name,pieces in spans.items():
            report[name+'_ms_sum']=sum(hi-lo for lo,hi in pieces)*1000/hz
            report[name+'_ms_union']=interval_union_ticks(pieces)*1000/hz
        processing=sum(hi-lo for lo,hi in cpu_pairs)
        verification=sum(hi-lo for lo,hi in spans['full_byte_verify'])
        report['verify_share_of_processing_pct']=100*verification/processing if processing else ''
        report['block_bytes']=int(sample['block_bytes'])
    return report, trace


def plot(root, summary, traces, samples):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    # Separate cache and diagnostic conditions, never merge their medians.
    conditions = {(r["cache_policy"], r["diagnostic"],r['csv_schema']) for r in summary}
    for cache, diag, schema in sorted(conditions):
        rows = [r for r in summary if (r["cache_policy"], r["diagnostic"],r['csv_schema']) == (cache, diag,schema)
                and r["results_consistent"]]
        if not rows:
            continue
        fig, ax = plt.subplots(figsize=(7, 4))
        configs=(("sync",-.26,'#3978a8','1 Worker Sync'),('async',0,'#db8734','1 Worker Async'),
                 ('async3',.26,'#368466','3 Workers Async')) if schema in (2,3,4,5,6,7,8) else (
                 ('sync',-.19,'#3978a8','1 Worker Sync'),('async',.19,'#db8734','1 Worker Async'))
        for m, shift, color,label in configs:
            med = [r[m + "_ms_median"] / 1000 for r in rows]
            err = [[(r[m + "_ms_median"] - r[m + "_ms_min"]) / 1000 for r in rows],
                   [(r[m + "_ms_max"] - r[m + "_ms_median"]) / 1000 for r in rows]]
            ax.bar([i + shift for i in range(len(rows))], med, width=.25 if schema in (2,3,4,5,6,7,8) else .38,
                   yerr=err, capsize=3, label=label, color=color)
        ax.set_xticks(range(len(rows)), [str(int(r["input_mb"])) for r in rows])
        ax.set(xlabel="Input (decimal MB)", ylabel="Elapsed time (s)",
               title=f"Fixed total input; {cache}; median with measured min/max" + ("; diagnostic" if diag else ""))
        ax.legend(); fig.tight_layout()
        for ext in ("png", "pdf"):
            fig.savefig(root / f"figure-1c-{cache}-diagnostic{diag}.{ext}", dpi=180)
        plt.close(fig)
    for run_id, trace in traces.items():
        if not trace:
            continue
        hz = int(samples[run_id]["timebase_hz"])
        head = sorted(trace, key=lambda r: r["admit_ticks"])[:24]
        origin = min(r["admit_ticks"] for r in head)
        workers=int(samples[run_id].get('worker_enclaves','1'))
        fig, ax = plt.subplots(figsize=(10, 3+workers))
        for r in head:
            base=3*(r.get('worker',1)-1)
            for begin, end, y, color in (("io_begin_ticks", "io_end_ticks", base+r["slot"], "#3978a8"),
                                         ("compute_begin_ticks", "compute_end_ticks", base+2, "#db8734")):
                x = (r[begin] - origin) * 1000 / hz
                width = (r[end] - r[begin]) * 1000 / hz
                ax.broken_barh([(x, width)], (y - .25, .5), facecolors=color)
                ax.text(x, y + .28, str(r["block"]), fontsize=7)
        labels=[label for w in range(1,workers+1) for label in (f'W{w} Host slot 0',f'W{w} Host slot 1',f'W{w} capture/decrypt/hash')]
        ax.set_yticks(range(3*workers),labels)
        ax.set(xlabel="Time from first admission (ms)", title=run_id + " (first 24 admissions; diagnostic)")
        fig.tight_layout(); fig.savefig(root / (run_id + "-timeline.png"), dpi=180); plt.close(fig)


def task_witness(root,sample,trace):
    path=root/(sample['run_id']+'-tasks.csv')
    with path.open(newline='') as f: rows=[{k:int(v) for k,v in r.items()} for r in csv.DictReader(f)]
    workers=int(sample['worker_enclaves']);begin=int(sample['cohort_start_ticks']);end=int(sample['cohort_end_ticks'])
    if len(rows)!=workers or {r['worker'] for r in rows}!=set(range(1,workers+1)):
        raise ValueError('incomplete protected task witnesses')
    for r in rows:
        if (r['lane']!=r['worker']-1 or r['sequence']!=r['worker'] or r['epoch']<1 or
            not begin<=r['dispatch_begin']<=r['acquire_ticks']<=r['done_ticks']<=r['aggregate_begin']<=r['aggregate_end']<=end or
            not r['dispatch_begin']<=r['dispatch_end']<=r['aggregate_begin']):
            raise ValueError('invalid protected task chronology/identity')
        records=[t for t in trace if t['worker']==r['worker']]
        if not records or any(t['admit_ticks']<r['acquire_ticks'] or t['release_ticks']>r['done_ticks'] for t in records):
            raise ValueError('data I/O occurred outside protected task ownership')
    return rows


def timeline_svg(root, traces, samples):
    """One matched triplet per diagnostic block; fixed, shared startup crop."""
    groups=defaultdict(dict)
    for run_id,trace in traces.items():
        sample=samples[run_id]
        if sample.get('csv_schema') not in ('4','5','6','7','8'): continue
        groups[(sample['experiment_block'],sample['cache_policy'],sample.get('block_bytes','65536'))][(sample['mode'],int(sample['worker_enclaves']))]=(sample,trace)
    for (block,cache,block_bytes),group in groups.items():
        cases=[('sync',1),('async',1),('async',3)]
        if set(group)!=set(cases): continue
        sync,events=group[('sync',1)]
        ordered=sorted(events,key=lambda r:r['compute_end_ticks'])
        if not ordered: continue
        # Same window for all configurations, defined before looking at Async.
        width_ticks=ordered[min(5,len(ordered)-1)]['compute_end_ticks']-int(sync['cohort_start_ticks'])
        if width_ticks<=0: continue
        hz=int(sync['timebase_hz']); left=180;plot_width=880;height=740
        parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="{height}" viewBox="0 0 1120 {height}">',
               '<rect width="1120" height="740" fill="white"/>',
               '<g font-family="Arial, sans-serif" font-size="13" fill="#222">',
               '<text x="28" y="30" font-size="20">Extent-I/O: Blocking OCALL and Asynchronous Execution</text>',
               '<text x="28" y="54">Blue: Host read service (not device busy); orange: capture, decrypt and compute</text>',
               f'<text x="28" y="76">{escape(sync.get("execution_environment","riscv-enclave"))}; {escape(sync.get("crypto_algorithm","unspecified cipher"))}; {escape(cache)}; {escape(block_bytes)} B; diagnostic; first-six-block Sync window</text>']
        top=110
        for case in cases:
            sample,trace=group[case];workers=case[1];origin=int(sample['cohort_start_ticks'])
            parts.append(f'<text x="28" y="{top}" font-size="16">{workers} Worker {case[0].title()}</text>')
            y0=top+24
            if sample.get('csv_schema') in ('5','6','7','8'):
                tasks=task_witness(root,sample,trace)
                parts.append(f'<text x="28" y="{y0+12}">Master TSR protocol</text>')
                for t in tasks:
                    for start,stop in [('dispatch_begin','dispatch_end'),('aggregate_begin','aggregate_end')]:
                        lo=max(0,t[start]-origin);hi=min(width_ticks,t[stop]-origin)
                        if hi>lo:
                            parts.append(f'<rect x="{left+plot_width*lo/width_ticks:.3f}" y="{y0}" width="{max(.3,plot_width*(hi-lo)/width_ticks):.3f}" height="15" fill="#45835a"><title>{start} task {t["worker"]}</title></rect>')
                y0+=24
            for w in range(1,workers+1):
                for kind,label,color in ((0,'Host read','#3978a8'),(1,'Enclave task' if sample['execution_environment']=='riscv-enclave' else 'Native task','#db8734')):
                    y=y0+48*(w-1)+22*kind
                    parts.append(f'<text x="28" y="{y+12}">W{w} {label}</text>')
                    parts.append(f'<line x1="{left}" y1="{y+17}" x2="{left+plot_width}" y2="{y+17}" stroke="#ddd"/>')
                    for r in trace:
                        if r.get('worker',1)!=w: continue
                        begin=r['io_begin_ticks' if kind==0 else 'compute_begin_ticks']-origin
                        end=r['io_end_ticks' if kind==0 else 'compute_end_ticks']-origin
                        begin=max(0,begin);end=min(width_ticks,end)
                        if end<=begin: continue
                        x=left+plot_width*begin/width_ticks;wid=plot_width*(end-begin)/width_ticks
                        parts.append(f'<rect x="{x:.3f}" y="{y}" width="{max(.3,wid):.3f}" height="15" fill="{color}"><title>block {r["block"]}</title></rect>')
            axis=y0+48*workers
            for i in range(6):
                x=left+plot_width*i/5
                parts.append(f'<text x="{x:.1f}" y="{axis+15}" text-anchor="middle">{width_ticks*1000/hz*i/5:.2f}</text>')
            top=axis+62
        origin_label='Master first task dispatch' if sync.get('csv_schema') in ('5','6','7','8') else 'common START release'
        parts.append(f'<text x="620" y="{top-8}" text-anchor="middle">Milliseconds from {origin_label} (each run aligned independently)</text>')
        parts.append('</g></svg>')
        safe=''.join(c if c.isalnum() or c in '-_' else '_' for c in block)
        (root/('timeline-'+safe+'-'+block_bytes+'B.svg')).write_text('\n'.join(parts),encoding='utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=pathlib.Path)
    p.add_argument("--plot", action="store_true", help="requires matplotlib on analysis PC")
    args = p.parse_args()
    root = args.directory
    with (root / "samples.csv").open(newline="") as f:
        samples = list(csv.DictReader(f))
    summary = summarize(samples)
    write_csv(root / "summary.csv", summary)
    write_csv(root / "figure-1c-data.csv", summary)
    reports, traces = [], {}
    for r in samples:
        path = root / (r["run_id"] + "-trace.csv")
        if r.get('csv_schema') in ('5','6','7','8') and r['diagnostic']=='1' and not path.exists():
            raise ValueError('missing protected-task diagnostic trace: '+r['run_id'])
        if r["diagnostic"] == "1" and path.exists():
            report, trace = trace_summary(path, r)
            if not report['complete']: raise ValueError('incomplete data trace: '+r['run_id'])
            if r.get('csv_schema') in ('5','6','7','8'):
                task_witness(root,r,trace)
                report['protected_tasks_complete']=1
            reports.append(report); traces[r["run_id"]] = trace
    write_csv(root / "overlap-evidence.csv", reports)
    timeline_svg(root,traces,{r['run_id']:r for r in samples})
    lines = ["Motivation: 1 Worker Sync, 1 Worker Async, 3 Workers Async; fixed total input; measured data only.",
             "XX=(Ts/Ta-1)*100; YY=(1-Ta/Ts)*100; Ts/Ta are medians, not peaks.",
             "No failed or slow successful samples are replaced. v4/v5/v6/v7/v8 formal eligibility requires >=3 complete board groups (older schemas: >=10), never native simulation; valid_runs records actual repetitions.",
             "ECB is a performance configuration, not authenticated encryption. Compare service modes within one cipher only; never pool or relabel the old GCM results.",
             "Processing intervals are wall time (capture/decrypt/hash), not isolated on-CPU crypto cycles. Sum and union differ for multiple Workers; untracked wall gaps are not automatically protocol overhead."]
    lines.append('Schema7/8 split diagnostic processing into ciphertext capture, identity/decrypt and full-byte verification. Timer boundaries add diagnostic overhead; formal runs omit these extra timestamps. Read admission includes blocking I/O in Sync and must not be added to read-service time. Ready-to-consume and slot-reuse gaps overlap other work; they are not additive CPU costs. Block sizes are separate workload configurations, not an algorithm-only speedup.')
    lines.append('Schema8 uses the same release+next-read OCALL in Sync and Async; Sync still blocks for the new read. data_path_ocalls=read_ocalls+release_only_ocalls excludes WAIT, setup and final DONE. release_submit_ocalls is a subset of read_ocalls, not additional calls. Host data operations and cryptographic validation are unchanged.')
    for r in summary:
        lines.append(str(r))
    if reports:
        lines.append("Overlap is intersection of Host read-service intervals with OTHER-block Worker processing, not proof of device-only activity or attribution of all total-time savings.")
        lines.extend(str(r) for r in reports)
    else:
        lines.append("No diagnostic trace in this directory: actual I/O/compute overlap is not established by this summary alone.")
    lines.append("No gain is guaranteed. Do not infer a bottleneck from total times alone; inspect the separate diagnostic trace.")
    (root / "results.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if args.plot:
        plot(root, summary, traces, {r["run_id"]: r for r in samples})
    print(f"[motivation-summary] groups={len(summary)} formal_eligible={sum(r['formal_eligible'] for r in summary)} directory={root}")


if __name__ == "__main__":
    main()
