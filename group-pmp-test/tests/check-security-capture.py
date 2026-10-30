#!/usr/bin/env python3
"""Synthetic verifier fixtures, NOT measured board security/performance results."""
import csv
import importlib.util
import json
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('capture_verifier',root/'security/verify-capture.py')
v = importlib.util.module_from_spec(spec); spec.loader.exec_module(v)


def csvfile(path,fields,data):
    with path.open('w',newline='') as f:
        out=csv.DictWriter(f,fieldnames=fields);out.writeheader();out.writerows(data)


def fixture(base,name,positive=False,leak=False):
    d=base/name;d.mkdir()
    nonce=77331 if positive else 99882
    config=dict(run_id=name,positive=positive,nonce=str(nonce),workload='readrandom',workers=1,total_bytes=500000000,
                positive_run='positive',swap_enabled=False,dump_enabled=False)
    (d/'configuration.json').write_text(json.dumps(config))
    csvfile(d/'capture.csv',['workload_ok','snapshots','capture_errors','repeated_read_bytes','negative_hits'],
            [dict(workload_ok=1,snapshots=1,capture_errors=0,repeated_read_bytes=1,negative_hits='')])
    records=[];expected=[];contents=bytearray()
    if positive:
        items=[('host-process','host-temp',65536,11),('host-process','host-stack',69632,12),
               ('host-process','host-unregistered',73728,13),('host-process','host-shared',77824,14),
               ('kernel-control','kernel-control',0,77)]
    else:
        items=[('host-process','host',65536,11),('kernel-page-cache','cache',0,12),
               ('ciphertext-file','file',0,0)]
    items += [('host-process','control-alias',81920,15),('host-process','data-alias',86016,16)]
    for region,label,address,pfn in items:
        page=bytearray(4096)
        if positive or (leak and region=='host-process'): page[128:192]=v.marker(nonce)
        offset=len(contents);contents.extend(page)
        records.append(dict(snapshot=1,phase='quiesced-before-destroy',time_ns=100,region=region,object=label,
                            address=address,length=4096,pfn=pfn,bytes_read=4096,blob_offset=offset,status='covered',reason=''))
        if positive and label not in ('control-alias','data-alias'):
            expected.append(dict(region=label,address=pfn if region=='kernel-control' else address,length=4096,marker_offset=128))
    (d/'contents.bin').write_bytes(contents)
    csvfile(d/'reads.csv',list(records[0]),records)
    inventory=[dict(snapshot=x['snapshot'],phase=x['phase'],time_ns=x['time_ns'],region=x['region'],object=x['object'],
                    address=x['address'],length=x['length'],pfn=x['pfn'],status='required',basis='synthetic-held-page') for x in records]
    csvfile(d/'inventory.csv',list(inventory[0]),inventory)
    page=bytearray(4096)
    if positive:page[128:192]=v.marker(nonce)
    (d/'self-1.bin').write_bytes(page*2)
    with (d/'self.csv').open('w',newline='') as f:
        writer=csv.writer(f)
        for i,region in enumerate(('control-utm','data-utm')):
            writer.writerow([1,'quiesced-before-destroy',region,81920+i*4096,4096,i*4096,'self-1.bin'])
            if positive:expected.append(dict(region=region,address=81920+i*4096,length=4096,marker_offset=128))
    csvfile(d/'positive-injected.csv',['region','address','length','marker_offset'],expected)
    phases=[dict(snapshot=1,phase=phase,time_ns=100,kind='checkpoint',checkpoint_id=1 if phase=='quiesced-before-destroy' else i+10)
            for i,phase in enumerate(('completed-before-destroy','quiesced-before-destroy','after-cleanup','worker-milestone-1',
                                     'worker-milestone-2','worker-milestone-3','worker-milestone-4'))]
    phases.append(dict(snapshot=1,phase='during',time_ns=100,kind='periodic',checkpoint_id=0))
    csvfile(d/'phases.csv',list(phases[0]),phases)
    csvfile(d/'protected.csv',['snapshot','start','length','group','epoch','type','permissions','basis'],
            [dict(snapshot=1,start=0x100000,length=4096,group=1,epoch=1,type=1,permissions=7,basis='synthetic')])
    csvfile(d/'filesystem.csv',['magic','source'],[dict(magic=0x01021994,source='/synthetic-tmpfs')])
    (d/'phase-history.csv').write_text('65536,1,2,0\n65536,2,6,0\n65536,3,14,0\n65536,4,30,0\n')
    return d


with tempfile.TemporaryDirectory(prefix='security-capture-verifier-') as path:
    base=Path(path)
    p=fixture(base,'positive',True)
    assert v.verify(p)['status']=='POSITIVE_PASS'
    healthy=fixture(base,'healthy')
    result=v.verify(healthy)
    assert result['status']=='PASS_OBSERVED_EXTENDED_SCOPE' and result['negative_hits']==0
    assert result['checkpoints']==7 and result['periodic_snapshots']==1 and result['scan_errors']==0
    compact=fixture(base,'compact-1MB')
    config=json.loads((compact/'configuration.json').read_text())
    config.update(total_bytes=1000000,effective_total_bytes=999840,security_batch_requests=8)
    (compact/'configuration.json').write_text(json.dumps(config))
    phases=v.rows(compact/'phases.csv')
    for phase in phases:
        if phase['kind']=='periodic':phase['kind']='running-sample'
    csvfile(compact/'phases.csv',list(phases[0]),phases)
    result=v.verify(compact)
    assert result['status']=='PASS_OBSERVED_EXTENDED_SCOPE'
    assert result['running_samples']==1 and result['periodic_snapshots']==0
    for positive in (False, True):
        stopped=fixture(base,'stopped-'+str(positive),positive)
        config=json.loads((stopped/'configuration.json').read_text())
        config['host_snapshot_protocol']=1
        (stopped/'configuration.json').write_text(json.dumps(config))
        assert 'host-stop-evidence-missing-or-duplicate:1' in v.verify(stopped)['missing']
        record=dict(snapshot=1,phase='quiesced-before-destroy',pid=100,requested_ns=80,
                    stopped_ns=90,resume_ns=110,status='resumed',method='SIGSTOP-waitpid-SIGCONT')
        csvfile(stopped/'process-stops.csv',list(record),[record])
        assert not v.verify(stopped)['missing']
        record['resume_ns']=99
        csvfile(stopped/'process-stops.csv',list(record),[record])
        assert 'host-read-outside-stopped-interval:1' in v.verify(stopped)['missing']
        record['resume_ns']=110;record['status']='failed'
        csvfile(stopped/'process-stops.csv',list(record),[record])
        assert 'host-stop-evidence-invalid:1' in v.verify(stopped)['missing']
        csvfile(stopped/'process-stops.csv',list(record),[record,record])
        assert 'host-stop-evidence-missing-or-duplicate:1' in v.verify(stopped)['missing']
    no_sample=fixture(base,'missing-running-sample')
    phases=v.rows(no_sample/'phases.csv')
    phases=[phase for phase in phases if phase['kind']!='periodic']
    csvfile(no_sample/'phases.csv',list(phases[0]),phases)
    assert 'no-running-sample' in v.verify(no_sample)['missing']
    leaking=fixture(base,'leaking',leak=True)
    assert v.verify(leaking)['status']=='PLAINTEXT_HIT'
    incomplete=fixture(base,'incomplete')
    data=v.rows(incomplete/'reads.csv');data[0]['status']='unreadable';data[0]['bytes_read']=0
    csvfile(incomplete/'reads.csv',list(data[0]),data)
    assert v.verify(incomplete)['status']=='COVERAGE_INCOMPLETE'
    missed=fixture(base,'missed')
    (missed/'phase-history.csv').write_text('65536,4,30,6\n')
    assert any('missed-worker-phase' in x for x in v.verify(missed)['missing'])
    alias=fixture(base,'alias')
    data=v.rows(alias/'reads.csv');duplicate=dict(data[1]);duplicate['region']='kernel-bio';data.append(duplicate)
    csvfile(alias/'reads.csv',list(data[0]),data)
    result=v.verify(alias)
    assert result['kernel_coverage']['repeated_bytes']==8192 and result['kernel_coverage']['unique_bytes']==4096
    boundary=fixture(base,'boundary')
    token=v.marker(99882);payload=bytearray((boundary/'contents.bin').read_bytes())
    file_offset=8192
    payload[file_offset+4064:file_offset+4096]=token[:32]
    next_offset=len(payload);payload.extend(token[32:]+bytes(4096-32))
    (boundary/'contents.bin').write_bytes(payload)
    data=v.rows(boundary/'reads.csv')
    # Insert an unrelated cache read between the two adjacent file pieces.
    next_piece=dict(data[2]);next_piece['address']=4096;next_piece['blob_offset']=next_offset
    data.append(dict(data[1]));data.append(next_piece)
    csvfile(boundary/'reads.csv',list(data[0]),data)
    result=v.verify(boundary)
    assert result['status']=='PLAINTEXT_HIT'
    assert any(r['region']=='ciphertext-file' for r in v.rows(boundary/'hits.csv'))
    bad_control=fixture(base,'bad-control',True)
    data=v.rows(bad_control/'positive-injected.csv');data[4]['address']=999
    csvfile(bad_control/'positive-injected.csv',list(data[0]),data)
    assert v.verify(bad_control)['status']=='COVERAGE_INCOMPLETE'
    missing_worker=fixture(base,'missing-worker')
    config=json.loads((missing_worker/'configuration.json').read_text());config['workers']=4
    (missing_worker/'configuration.json').write_text(json.dumps(config))
    result=v.verify(missing_worker)
    assert result['status']=='COVERAGE_INCOMPLETE' and 'worker-phase-owner-count-mismatch' in result['missing']
    missing_checkpoint=fixture(base,'missing-owner-checkpoint')
    (missing_checkpoint/'phase-history.csv').write_text('65536,1,2,0\n65536,3,14,0\n65536,4,30,0\n')
    assert 'missed-worker-checkpoint:owner=65536:phase=2' in v.verify(missing_checkpoint)['missing']
    reused=fixture(base,'checkpoint-page-reuse')
    data=v.rows(reused/'reads.csv')
    duplicate=dict(data[-2]);duplicate.update(snapshot=2,pfn=25);data.append(duplicate)
    csvfile(reused/'reads.csv',list(data[0]),data)
    phases=v.rows(reused/'phases.csv')
    phases.append(dict(snapshot=2,phase='quiesced-before-destroy',time_ns=200,kind='checkpoint',checkpoint_id=2))
    csvfile(reused/'phases.csv',list(phases[0]),phases)
    (reused/'self-2.bin').write_bytes(bytes(4096))
    with (reused/'self.csv').open('a',newline='') as f:
        csv.writer(f).writerow([2,'quiesced-before-destroy','control-utm',81920,4096,0,'self-2.bin'])
    result=v.verify(reused)
    assert result['status']=='PASS_OBSERVED_EXTENDED_SCOPE'
    assert result['coverage']['control-utm']['unique_bytes']==8192
    for phase in phases:phase.pop('checkpoint_id')
    csvfile(reused/'phases.csv',list(phases[0]),phases)
    assert any(x.startswith('self-checkpoint-identity-unavailable:') for x in v.verify(reused)['missing'])
    partial=fixture(base,'partial-success-record')
    data=v.rows(partial/'reads.csv');data[0]['bytes_read']=256
    csvfile(partial/'reads.csv',list(data[0]),data)
    result=v.verify(partial)
    assert result['status']=='COVERAGE_INCOMPLETE' and result['scan_errors']==1
    assert any(x.startswith('inventory-without-successful-read:') for x in result['missing'])
    partial_blob=bytearray((partial/'contents.bin').read_bytes());partial_blob[128:192]=v.marker(99882)
    (partial/'contents.bin').write_bytes(partial_blob)
    assert v.verify(partial)['status']=='PLAINTEXT_HIT'
    csvfile(base/'execution-matrix.csv',['run_id','status'],[dict(run_id='unsupported-cipher',status='unsupported')])
    csvfile(base/'planned-combinations.csv',['run_id'],[dict(run_id='never-executed')])
    import sys
    sys.argv=['verify-capture.py',str(base)]
    assert v.main()==2
    report={r['run_id']:r for r in v.rows(base/'verified-results.csv')}
    assert report['healthy']['checkpoints']=='7' and report['healthy']['scan_errors']=='0'
    assert int(report['healthy']['host_unique_bytes'])>0 and int(report['healthy']['kernel_unique_bytes'])>0
    assert report['unsupported-cipher']['negative_hits']=='' and report['unsupported-cipher']['checkpoints']==''
    assert report['never-executed']['status']=='not-executed' and report['never-executed']['host_unique_bytes']==''
    assert 'compact-1MB | PASS_OBSERVED_EXTENDED_SCOPE | 0' in (base/'verified-summary.txt').read_text()
print('Extended verifier: real offsets, controls, alias dedup, leak/error/missed-phase rejection PASS (synthetic fixtures only)')
