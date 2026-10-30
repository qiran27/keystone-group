#!/usr/bin/env python3
"""Run on an independent trusted analysis machine AFTER evidence transfer.
No business keys; only the public test nonce is used to reconstruct the marker.
"""
import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path


def marker(nonce):
    mask = (1 << 64) - 1
    state = nonce ^ 0x67d184aec759f302
    out = bytearray()
    for _ in range(64):
        state = (state + 0x9e3779b97f4a7c15) & mask
        z = ((state ^ (state >> 30)) * 0xbf58476d1ce4e5b9) & mask
        z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & mask
        out.append((z ^ (z >> 31)) & 255)
    return bytes(out)


def rows(path):
    if not path.exists():
        return []
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def union_size(intervals):
    total, end = 0, -1
    for a, b in sorted(intervals):
        total += max(0, b - max(a, end))
        end = max(end, b)
    return total


def verify(directory):
    d = Path(directory)
    config = json.loads((d / 'configuration.json').read_text())
    token = marker(int(config['nonce']))
    capture = rows(d / 'capture.csv')
    reads = rows(d / 'reads.csv')
    inventory = rows(d / 'inventory.csv')
    phases = rows(d / 'phases.csv')
    gaps = rows(d / 'gaps.csv')
    missing = []
    if not capture or (d / 'capture-failure.txt').exists():
        missing.append('capture-not-completed')
    positive = bool(config.get('positive', False))
    matched = []
    failed_reads = []
    counts = defaultdict(int)
    unique = defaultdict(lambda: defaultdict(list))
    streams = {}
    with (d / 'contents.bin').open('rb') as content:
        for r in reads:
            region, status = r['region'], r['status']
            counts[region + ':objects'] += 1
            if status == 'not-applicable':
                continue
            length = int(r['bytes_read'])
            if status != 'covered' or length != int(r['length']):
                # Alternative sources remain explicit and require a successful
                # record for that same range/checkpoint, never a silent skip.
                failed_reads.append(r)
                counts[region + ':read_errors'] += 1
                if not length:
                    streams.pop((r['snapshot'],r['phase'],r['region'],r['object']),None)
                    continue
            if length < 0 or length > int(r['length']):
                raise ValueError('invalid successful-read length')
            address = int(r['address'])
            content.seek(int(r['blob_offset']))
            data = content.read(length)
            if len(data) != length:
                missing.append('truncated-content-blob')
                continue
            counts[region + ':repeated_bytes'] += length
            pfn = int(r['pfn'])
            identity = ('physical', pfn) if pfn else ('object', r['object'], address // 4096)
            unique[region][identity].append((address % 4096, address % 4096 + length))
            if region == 'host-process' and not pfn:
                counts['host-physical-id-unavailable'] += 1
            # File/cache/BIO records are interleaved. Retain the boundary carry
            # per stream rather than accidentally losing cross-page markers.
            key = r['snapshot'], r['phase'], r['region'], '' if region=='host-process' else r['object']
            carry, next_address, prior_pfn = streams.get(key,(b'',None,0))
            if address != next_address:carry=b''
            joined = carry + data
            offset, start = 0, address - len(carry)
            while True:
                at = joined.find(token, offset)
                if at < 0:
                    break
                matched.append(dict(region=region, object=r['object'], address=start + at,
                                    time_ns=r['time_ns'], phase=r['phase'], snapshot=r['snapshot'],
                                    marker_id=config['run_id'],pfn=prior_pfn if at<len(carry) else pfn))
                offset = at + 1
            streams[key] = joined[-63:], address + length, pfn
    # Host self-read is an explicit alternative for live PFN UTM. It is not a
    # replacement for arbitrary unreadable process mappings or kernel buffers.
    self_rows = []
    self_times = {}
    self_file = d / 'self.csv'
    if self_file.exists():
        with self_file.open(newline='') as f:
            for record in csv.reader(f):
                if len(record)==8:
                    self_times[(record[0],record[2],record[3])] = record[7]
                elif len(record)!=7:
                    raise ValueError('invalid Host self-read record')
                self_rows.append(record[:7])
    physical_by_snapshot={(r['snapshot'],r['phase'],int(r['address'])//4096):int(r['pfn']) for r in reads
                          if r['region']=='host-process' and int(r['pfn'])}
    checkpoint_snapshots = {}
    for r in phases:
        if r['kind'] == 'checkpoint' and r.get('checkpoint_id'):
            key = r['checkpoint_id'], r['phase']
            if key in checkpoint_snapshots:
                missing.append('duplicate-checkpoint-identity')
            checkpoint_snapshots[key] = r['snapshot']
    self_unknown=0
    self_snapshot_ids = {}
    for checkpoint, phase, region, address, length, offset, filename in self_rows:
        address, length, offset = int(address), int(length), int(offset)
        snapshot = checkpoint_snapshots.get((checkpoint, phase))
        if snapshot is None:
            # Older evidence is usable only when its phase identifies one
            # checkpoint unambiguously. Never borrow a later snapshot's PFN.
            candidates = [r['snapshot'] for r in phases
                          if r['kind'] == 'checkpoint' and r['phase'] == phase]
            if len(candidates) == 1:
                snapshot = candidates[0]
            else:
                missing.append('self-checkpoint-identity-unavailable:' + checkpoint + ':' + phase)
        self_snapshot_ids[(checkpoint, phase, region, address)] = snapshot
        with (d / filename).open('rb') as f:
            f.seek(offset)
            data = f.read(length)
        if len(data) != length:
            missing.append('truncated-self-range')
            continue
        counts[region + ':repeated_bytes'] += length
        for i in range(0,length,4096):
            pfn=physical_by_snapshot.get((snapshot,phase,(address+i)//4096),0)
            identity=('physical',pfn) if pfn else ('virtual-owner',address+i)
            unique[region][identity].append((0,min(4096,length-i)))
            if not pfn:self_unknown+=1
        pos = 0
        while True:
            pos = data.find(token, pos)
            if pos < 0:
                break
            matched.append(dict(region=region, object=filename, address=address+pos,
                                time_ns=self_times.get((checkpoint,region,str(address)),''),
                                phase=phase, snapshot=snapshot or 'unresolved-checkpoint-'+checkpoint,
                                marker_id=config['run_id'],pfn=0))
            pos += 1
    kernel_alternatives={(r['snapshot'],r['address'],int(r['length'])) for r in reads
                         if r['region'] in ('kernel-io-uring','kernel-vma') and r['status']=='covered'
                         and int(r['bytes_read']) == int(r['length'])}
    self_by_snapshot=defaultdict(list)
    for checkpoint,phase,kind,start,size,_,_ in self_rows:
        if kind in ('control-utm','data-utm','host-ciphertext-buffer'):
            snapshot = self_snapshot_ids.get((checkpoint,phase,kind,int(start)))
            if snapshot is not None:
                self_by_snapshot[(snapshot,phase)].append((int(start),int(start)+int(size)))
    def alternative_read(r):
        address, length = int(r['address']), int(r['length'])
        if r['region'] != 'host-process':
            return False
        if r['status'] == 'alternative':
            return (r['snapshot'],r['address'],length) in kernel_alternatives
        return any(start<=address and address+length<=end
                   for start,end in self_by_snapshot[(r['snapshot'],r['phase'])])
    fallback_keys=set()
    for r in failed_reads:
        if alternative_read(r):
            fallback_keys.add((r['snapshot'],r['region'],r['object'],r['address'],int(r['length'])))
        else:
            missing.append(f"{r['region']}:{r['snapshot']}:{r['address']}:{r['reason']}")
    coverage = {k: dict(repeated_bytes=counts[k + ':repeated_bytes'],
                        unique_bytes=sum(union_size(v) for v in objects.values()))
                for k, objects in unique.items()}
    # Also compare the required-object inventory with the successful-read ledger.
    successful = {(r['snapshot'], r['region'], r['object'], r['address'], int(r['length']))
                  for r in reads if r['status'] == 'covered' and int(r['bytes_read']) == int(r['length'])}
    for obj in inventory:
        if obj['status'] in ('protected','not-applicable'):
            continue
        key = obj['snapshot'], obj['region'], obj['object'], obj['address']
        if key + (int(obj['length']),) not in successful and key + (int(obj['length']),) not in fallback_keys:
            missing.append('inventory-without-successful-read:' + ':'.join(key))
    observed = {r['phase'] for r in phases if r['kind'] == 'checkpoint'}
    worker_phases = defaultdict(set)
    missing_phases = []
    if not positive:
        required_phases = {'completed-before-destroy', 'quiesced-before-destroy', 'after-cleanup', 'worker-milestone-1',
                           'worker-milestone-2', 'worker-milestone-4'}
        if config['workload'] == 'readrandom':
            required_phases.add('worker-milestone-3')
        missing_phases = sorted(required_phases - observed)
        missing += ['missed-phase:' + x for x in missing_phases]
        if not any(r['kind'] == 'periodic' or
                   (r['kind'] == 'running-sample' and config.get('security_batch_requests') == 8)
                   for r in phases):
            missing.append('no-running-sample')
        for region in ('host-process', 'control-utm', 'data-utm', 'kernel-page-cache', 'ciphertext-file'):
            if coverage.get(region, {}).get('unique_bytes', 0) == 0:
                missing.append('required-region-not-read:' + region)
        if not rows(d / 'protected.csv'):
            missing.append('no-protected-range-evidence')
        if config.get('swap_enabled') or config.get('dump_enabled'):
            missing.append('enabled-swap-or-dump-path-not-captured')
        fs = rows(d / 'filesystem.csv')
        tmpfs = bool(fs and int(fs[0]['magic']) == 0x01021994)
        if not tmpfs and not coverage.get('kernel-bio', {}).get('unique_bytes', 0):
            missing.append('block-storage-bio-path-not-covered')
        history = d / 'phase-history.csv'
        if history.exists():
            with history.open(newline='') as f:
                for owner,phase,seen,missed in csv.reader(f):
                    worker_phases[owner].add(int(phase))
                    if int(missed):
                        missing.append(f'missed-worker-phase:owner={owner}:mask={missed}')
            required_worker_phases = {1, 2, 4}
            if config['workload'] == 'readrandom':
                required_worker_phases.add(3)
            if len(worker_phases) != int(config['workers']):
                missing.append('worker-phase-owner-count-mismatch')
            for owner, seen in worker_phases.items():
                for phase in sorted(required_worker_phases - seen):
                    missing.append(f'missed-worker-checkpoint:owner={owner}:phase={phase}')
        else:
            missing.append('worker-phase-history-unavailable')
        if counts['host-physical-id-unavailable'] or self_unknown:
            missing.append('physical-alias-identity-incomplete')
    positive_checked = []
    if positive:
        for item in rows(d / 'positive-injected.csv'):
            address, offset = int(item['address']), int(item['marker_offset'])
            if item['region'] == 'kernel-control':
                candidates = [r for r in reads if r['region'] == 'kernel-control' and int(r['pfn']) == address]
                detected = bool(candidates and any(h['region']=='kernel-control' and h['pfn']==address
                                                  and h['address']%4096==offset for h in matched))
            else:
                detected = any(h['region'] in ('host-process','control-utm','data-utm') and
                               h['address']==address+offset for h in matched)
            positive_checked.append(dict(**item, detected=detected))
            if not detected:
                missing.append('positive-control-not-detected:' + item['region'])
        categories = {x['region'] for x in positive_checked}
        if not {'host-temp','host-stack','host-unregistered','host-shared','kernel-control','control-utm','data-utm'} <= categories:
            missing.append('positive-control-injection-incomplete')
        # A control validates only its specifically planted ranges, not every
        # incidental process mapping. Preserve incidental unreadable evidence
        # separately instead of claiming whole-process positive coverage.
        missing = [x for x in missing if x.startswith(('positive-control','truncated','capture-'))]
    else:
        control = d.parent / config['positive_run'] / 'verification.json'
        if not control.exists() or json.loads(control.read_text()).get('status') != 'POSITIVE_PASS':
            missing.append('regional-positive-controls-not-verified')
    missing += [r['region'] + ':' + r['reason'] for r in gaps]
    if config.get('host_snapshot_protocol') == 1:
        stops = defaultdict(list)
        for row in rows(d / 'process-stops.csv'):
            stops[row['snapshot']].append(row)
        for snapshot in {r['snapshot'] for r in phases
                         if r['kind'] in ('checkpoint', 'periodic', 'running-sample')}:
            entries = stops[snapshot]
            if len(entries) != 1:
                missing.append('host-stop-evidence-missing-or-duplicate:' + snapshot)
                continue
            entry = entries[0]
            start, end = int(entry['stopped_ns']), int(entry['resume_ns'])
            if (entry['status'] != 'resumed' or entry['method'] != 'SIGSTOP-waitpid-SIGCONT'
                    or not 0 < int(entry['requested_ns']) <= start <= end):
                missing.append('host-stop-evidence-invalid:' + snapshot)
                continue
            if any(r['snapshot'] == snapshot and
                   r['region'] in ('host-process', 'kernel-io-uring', 'kernel-vma') and
                   (r['phase'] != entry['phase'] or not start <= int(r['time_ns']) <= end)
                   for r in reads):
                missing.append('host-read-outside-stopped-interval:' + snapshot)
    missing = sorted(set(missing))
    workload_ok = bool(capture and capture[0]['workload_ok'] == '1')
    if not workload_ok:
        missing.append('workload-invalid')
    status = ('POSITIVE_PASS' if positive else 'PASS_OBSERVED_EXTENDED_SCOPE') if not missing else 'COVERAGE_INCOMPLETE'
    if matched and not positive:
        status = 'PLAINTEXT_HIT'
    result = dict(run_id=config['run_id'], status=status, workload_ok=workload_ok,
                  snapshots=int(capture[0]['snapshots']) if capture else None,
                  checkpoints=sum(r['kind'] == 'checkpoint' for r in phases),
                  periodic_snapshots=sum(r['kind'] == 'periodic' for r in phases),
                  running_samples=sum(r['kind'] in ('periodic','running-sample') for r in phases),
                  missing_phases=missing_phases,
                  worker_phase_coverage=[dict(owner=owner, phases=sorted(seen))
                                         for owner, seen in sorted(worker_phases.items())],
                  scan_errors=len(failed_reads) + len(gaps),
                  explained_alternative_reads=len(fallback_keys),
                  skipped_ranges=sum(r['status'] == 'not-applicable' for r in reads),
                  negative_hits=len(matched) if not positive and sum(
                      value for key, value in counts.items() if key.endswith(':repeated_bytes')) else None,
                  positive_injected=len(positive_checked) if positive else None,
                  positive_detected=sum(x['detected'] for x in positive_checked) if positive else None,
                  coverage=coverage, coverage_basis='physical-page+offset when PFN available; otherwise explicitly virtual/object based',
                  missing=missing, controls=positive_checked)
    result['region_read_errors'] = {key[:-12]: value for key, value in counts.items()
                                    if key.endswith(':read_errors')}
    for family,kinds in (('host',('host-process','control-utm','data-utm','host-ciphertext-buffer')),
                         ('kernel',('kernel-page-cache','kernel-io-uring','kernel-vma','kernel-bio'))):
        combined=defaultdict(list)
        for kind in kinds:
            for identity,intervals in unique[kind].items():combined[identity].extend(intervals)
        result[family+'_coverage']=dict(repeated_bytes=sum(counts[k+':repeated_bytes'] for k in kinds),
                                      unique_bytes=sum(union_size(v) for v in combined.values()),
                                      known_physical_unique_bytes=sum(union_size(v) for k,v in combined.items() if k[0]=='physical'),
                                      virtual_object_unique_bytes=sum(union_size(v) for k,v in combined.items() if k[0]!='physical'),
                                      physical_identity_missing=counts['host-physical-id-unavailable']+self_unknown if family=='host' else 0)
    with (d / 'hits.csv').open('w', newline='') as f:
        fields = ['region','object','address','time_ns','phase','snapshot','marker_id','pfn']
        writer = csv.DictWriter(f, fieldnames=fields);writer.writeheader();writer.writerows(matched)
    (d / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence_root', type=Path)
    args = parser.parse_args()
    root = args.evidence_root
    configs = sorted(root.glob('*/configuration.json'))
    # Separate controls are verified before negative experiments.
    configs.sort(key=lambda p: not json.loads(p.read_text()).get('positive', False))
    results = []
    for p in configs:
        print('[security-verify] checking',p.parent.name,flush=True)
        try:
            result=verify(p.parent)
            results.append(result)
            print('[security-verify]',result['run_id'],result['status'],
                  'negative_hits='+str(result['negative_hits']),
                  'positive='+str(result['positive_detected'])+'/'+str(result['positive_injected']),
                  'missing='+str(len(result['missing'])),flush=True)
        except (OSError,ValueError,KeyError) as error:
            results.append(dict(run_id=p.parent.name,status='EVIDENCE_INVALID',workload_ok=False,
                                snapshots=None,negative_hits=None,positive_injected=None,positive_detected=None,
                                missing=[str(error)]))
    actual_ids={r['run_id'] for r in results}
    for r in rows(root/'execution-matrix.csv'):
        if r['run_id'] not in actual_ids:
            results.append(dict(run_id=r['run_id'],status=r['status'],workload_ok=None,snapshots=None,
                                negative_hits=None,positive_injected=None,positive_detected=None,missing=[]))
    actual_ids={r['run_id'] for r in results}
    for r in rows(root/'planned-combinations.csv'):
        if r['run_id'] not in actual_ids:
            results.append(dict(run_id=r['run_id'],status='not-executed',workload_ok=None,snapshots=None,
                                negative_hits=None,positive_injected=None,positive_detected=None,missing=['run-not-executed']))
    (root / 'verified-results.json').write_text(json.dumps(results, indent=2) + '\n')
    with (root / 'verified-summary.txt').open('w') as summary:
        summary.write('Observed security evidence; limits are in verified-results.json\n')
        summary.write('run_id | result | negative_hits | positive_detected/injected | missing\n')
        for r in results:
            if r['status']=='unsupported':continue
            summary.write('{} | {} | {} | {}/{} | {}\n'.format(r['run_id'],r['status'],
                r.get('negative_hits'),r.get('positive_detected'),r.get('positive_injected'),len(r['missing'])))
    with (root / 'verified-results.csv').open('w', newline='') as f:
        fields=['run_id','status','workload_ok','snapshots','negative_hits','positive_injected','positive_detected','missing_count',
                'checkpoints','periodic_snapshots','scan_errors','explained_alternative_reads','skipped_ranges',
                'host_repeated_bytes','host_unique_bytes','kernel_repeated_bytes','kernel_unique_bytes']
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
        for r in results:
            record = {k:r.get(k) for k in fields}
            record['missing_count'] = len(r['missing'])
            for family in ('host','kernel'):
                for kind in ('repeated_bytes','unique_bytes'):
                    record[family+'_'+kind] = r.get(family+'_coverage',{}).get(kind)
            writer.writerow(record)
    # Evidence transport fingerprints, not protection from a forged test kernel.
    with (root / 'evidence.sha256').open('w') as f:
        for path in sorted(root.rglob('*')):
            if path.is_file() and path.name != 'evidence.sha256':
                h=hashlib.sha256()
                with path.open('rb') as data:
                    for block in iter(lambda:data.read(1024*1024),b''):h.update(block)
                f.write(h.hexdigest()+'  '+str(path.relative_to(root))+'\n')
    print('Verified runs:',len(results),'passes:',sum(r['status'] in ('POSITIVE_PASS','PASS_OBSERVED_EXTENDED_SCOPE') for r in results))
    return 0 if results and all(r['status'] in ('POSITIVE_PASS','PASS_OBSERVED_EXTENDED_SCOPE','unsupported') for r in results) else 2


if __name__=='__main__':
    raise SystemExit(main())
