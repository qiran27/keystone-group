"""Synthetic fixtures ONLY: never stored in real benchmark output directories."""
import csv
import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('system_summary', ROOT/'motivation/system-summary.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


def write(path, rows):
    module.write(path, rows)


def emit(folder, mode, workers, size=60000000, diag=False, cipher='aes-ecb-128', cache='cold', interface='sqlite'):
    total = size//240*240
    seconds = 3 if mode=='sync' else 2 if workers==1 else 1
    chunks = []
    for w in range(workers):
        amount=(total//240//workers+(w<total//240%workers))*240
        parts=[(off,min(2000000,amount-off)) for off in range(0,amount,2000000)]
        if mode=='async' and len(parts)>1: parts[0],parts[1]=parts[1],parts[0]
        for n,(off,length) in enumerate(parts): chunks.append((w,n,off,length))
    perf=dict(io_mode=mode+'-no-extent',worker_count=workers,samples=1,
              workload='readseq' if interface=='sqlite' else 'fio-seq-read-2m',
              cache_mode=cache,cipher=cipher,address_mode='locality-random-v1',
              total_bytes=total,seconds_median=seconds,mb_per_sec_median=total/1e6/seconds,
              vfs_read_bytes=total,vfs_write_bytes=0,digest=100+workers,
              timing_scope=('diagnostic-motivation-system-' if diag else '')+'master-first-dispatch-to-final-aggregate',
              io_uring_submissions=len(chunks) if mode=='async' else 0,
              vfs_ring_doorbells=len(chunks),completion_wait_ocalls=len(chunks))
    io={k:perf[k] for k in ('io_mode','worker_count','samples','workload','cache_mode','cipher')}
    io.update(useful_bytes_median=total,failed_request_count_median=0,
              io_request_count_median=len(chunks),member_request_count_median=len(chunks))
    write(folder/'performance.csv',[perf]); write(folder/'io.csv',[io])
    if not diag: return
    origin=1000000000
    events=[]; crypto=[]
    def event(kind,t,w=-1,request=0,length=0,operation='none'):
        events.append(dict(event=kind,timestamp_ns=t,event_seq=len(events),request_sample_stride=1,
                           request_events_omitted=0,worker_index=w,request_id=request,run_id=1,
                           operation=operation,result=0,length=length))
    event('perf_begin',origin)
    for w,n,off,length in chunks:
        lo=origin+1000000+w*100000+n*(10000000 if mode=='sync' else 6000000)
        event('storage_io_begin',lo,w,n+1,length,'read')
        event('storage_io_end',lo+5000000,w,n+1,length,'read')
        crypto.append(dict(worker=w,sequence=n,logical_offset=off,bytes=length,
                           begin_ticks=lo+5000000,end_ticks=lo+8000000,runtime_ticks=3000000,
                           timebase_hz=1000000000,begin_ns=lo+5000000,end_ns=lo+8000000,clock_uncertainty_ns=100))
    event('perf_end',origin+seconds*1000000000)
    write(folder/'host-events.csv',events); write(folder/'crypto.csv',crypto)


def fixture(root, repetitions=10, interface='sqlite'):
    rows=[]
    for kind,count in (('formal',repetitions),('timeline',1)):
        for rep in range(1,count+1):
            for order,(mode,workers) in enumerate((('sync',1),('async',1),('async',3)),1):
                id=f'{kind}-r{rep}-{mode}-{workers}'; folder=root/id; folder.mkdir()
                emit(folder,mode,workers,diag=kind=='timeline',interface=interface)
                rows.append(dict(kind=kind,run_id=id,repetition=rep,order=order,mode=mode,workers=workers,
                                 performance_csv=id+'/performance.csv',io_csv=id+'/io.csv',
                                 gantt_csv=id+'/host-events.csv' if kind=='timeline' else '',
                                 crypto_csv=id+'/crypto.csv' if kind=='timeline' else '',status='complete',interface=interface))
    write(root/'manifest.csv',rows)


def mock():
    e=os.environ
    assert e['GROUP_PMP_MOTIVATION_SYSTEM']=='1'
    assert e['GROUP_PMP_SQLITE_RANDOM_SEED']=='1397519439'
    interface=e['GROUP_PMP_MOTIVATION_INTERFACE']
    assert interface in ('sqlite','fio') and 'GROUP_PMP_SECURITY_NONCE' not in e
    if interface=='fio': assert e['GROUP_PMP_FIO_PROFILE']=='seq-read-2m'
    else: assert 'GROUP_PMP_FIO_PROFILE' not in e
    args=sys.argv[2:]
    assert args[:3]==['--cipher',e['GROUP_PMP_BENCH_CIPHER'],'sqlite-bench']
    mode=args[3].split('-')[0]; workers=int(args[4]); size=int(args[6][:-2])*1000000
    assert args[5]=='1' and workers==int(e['GROUP_PMP_MOTIVATION_WORKERS'])
    folder=pathlib.Path(e['GROUP_PMP_SQLITE_CSV']).parent
    emit(folder,mode,workers,size,diag='GROUP_PMP_SQLITE_GANTT_CSV' in e,
         cipher=e['GROUP_PMP_BENCH_CIPHER'],cache=args[7],interface=interface)
    (pathlib.Path(e['GROUP_PMP_SQLITE_STORAGE_DIR'])/'private-test-fixture.db').write_text('fixture only')
    if e.get('MOCK_SYSTEM_FAIL')=='1': sys.exit(5)
    print('fixture-only production selection PASS')


class Tests(unittest.TestCase):
    def test_fio_summary_and_interface_separation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); fixture(root,3,'fio')
            rows=module.summarize(root)
            self.assertEqual({r['interface'] for r in rows},{'fio'})
            self.assertTrue(all(r['formal_eligible'] for r in rows))
            path=root/'manifest.csv'; manifest=module.read(path)
            manifest[0]['interface']='sqlite'; write(path,manifest)
            with self.assertRaises(ValueError): module.summarize(root)

    def test_legacy_manifest_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); fixture(root,3)
            path=root/'manifest.csv'; rows=module.read(path)
            for row in rows: del row['interface']
            write(path,rows)
            self.assertEqual({r['interface'] for r in module.summarize(root)},{'sqlite'})

    def test_three_round_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);fixture(root,3)
            rows=module.summarize(root)
            self.assertEqual([r['samples'] for r in rows],[3,3,3])
            self.assertTrue(all(r['formal_eligible'] for r in rows))
            self.assertEqual(len(module.read(root/'samples.csv')),9)
            self.assertEqual(len(module.read(root/'timeline-evidence.csv')),3)
            manifest=module.read(root/'manifest.csv')
            for r in manifest:
                if r['kind']=='formal': r['kind']='diagnostic'
            write(root/'manifest.csv',manifest)
            self.assertFalse(any(r['formal_eligible'] for r in module.summarize(root)))

    def test_summary_and_svg(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); fixture(root)
            rows=module.summarize(root)
            self.assertEqual([r['samples'] for r in rows],[10,10,10])
            self.assertEqual([r['speedup_vs_sync1'] for r in rows],[1,1.5,3])
            self.assertTrue(all(r['formal_eligible'] for r in rows))
            self.assertEqual(len(module.read(root/'samples.csv')),30)
            for name in ('timeline.svg','performance.svg'):
                ET.parse(root/name)
                self.assertNotIn('fio',(root/name).read_text().lower())
            self.assertEqual(len(module.read(root/'timeline-evidence.csv')),3)
            # Out-of-order logical offsets still represent complete legal reads.
            self.assertGreater(float(module.read(root/'timeline-evidence.csv')[1]['read_service_crypto_overlap_ms']),0)

    def test_diagnostic_poison_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); fixture(root,1)
            path=root/'formal-r1-sync-1/performance.csv'; rows=module.read(path)
            rows[0]['timing_scope']='diagnostic-contamination';write(path,rows)
            with self.assertRaises(ValueError): module.summarize(root)

    def test_missing_case_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); fixture(root,1)
            rows=module.read(root/'manifest.csv');write(root/'manifest.csv',rows[1:])
            with self.assertRaises(ValueError): module.summarize(root)

    def test_trace_gap_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); fixture(root,1)
            path=root/'timeline-r1-async-1/crypto.csv'; rows=module.read(path)
            rows[0]['logical_offset']='1';write(path,rows)
            with self.assertRaises(ValueError): module.summarize(root)

    def test_failed_run_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); fixture(root,1)
            rows=module.read(root/'manifest.csv');rows[0]['status']='failed';write(root/'manifest.csv',rows)
            with self.assertRaises(ValueError): module.summarize(root)

    def test_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); (root/'data').mkdir();(root/'motivation').mkdir()
            for f in ('run-motivation-system.sh','run-motivation-architecture.sh','run-benchmark-cipher.sh'): shutil.copy(ROOT/f,root)
            shutil.copy(ROOT/'motivation/system-summary.py',root/'motivation')
            shutil.copy(__file__,root/'mock.py')
            # mock.py imports ROOT/motivation/system-summary.py from this copy.
            script=root/'run-p10-mixed-scaling.sh'
            script.write_text('#!/bin/sh\nexec python3 "'+str(pathlib.Path(__file__).resolve())+'" --mock "$@"\n')
            marker='keystone-motivation-real-system-v1 keystone-benchmark-cipher-v1 keystone-motivation-production-interface-v1 keystone-fio-enclave-profile-v1\n'
            for f in ('group-pmp-test-runner','group-pmp-sqlite-worker.eapp_riscv'):
                (root/f).write_text('#!/bin/sh\n# '+marker+'echo artifact-fixture\n');(root/f).chmod(0o755)
            (root/'group-pmp-sqlite-master.eapp_riscv').write_text('keystone-sqlite-host-engine-v1 fixture')
            for name in ('eyrie-rt','loader.bin'): (root/name).write_text('fixture')
            env=dict(os.environ,GROUP_PMP_SECURITY_NONCE='stale',GROUP_PMP_SQLITE_IO_BATCH_MAX='1')
            def run(reps,kind,output,fail=False):
                return subprocess.run(['sh',str(root/'run-motivation-system.sh'),'--cipher','aes-gcm-128',str(reps),
                                       '500MB','cold',str(root/'data'),str(root/output),kind],
                                      env=dict(env,MOCK_SYSTEM_FAIL=str(int(fail))),capture_output=True,text=True)
            result=run(10,'formal','out')
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            folder=next((root/'out').iterdir())
            self.assertEqual(len(module.read(folder/'manifest.csv')),33)
            self.assertEqual(len(module.read(folder/'samples.csv')),30)
            self.assertFalse(list((root/'data').iterdir()))
            for interface in ('sqlite','fio'):
                command=['sh',str(root/'run-motivation-architecture.sh'),'--cipher','aes-ecb-128',
                         '--interface',interface,'1','60MB','cold',str(root/'data'),str(root/interface),'diagnostic']
                production=subprocess.run(command,env=env,capture_output=True,text=True)
                self.assertEqual(production.returncode,0,production.stdout+production.stderr)
                directory=next((root/interface).iterdir())
                self.assertTrue(directory.name.startswith('production-'+interface+'-'))
                self.assertEqual({r['interface'] for r in module.read(directory/'summary.csv')},{interface})
                self.assertEqual(len(module.read(directory/'manifest.csv')),6)
                self.assertIn('execution_path=production-worker-vfs-and-host-service', (directory/'environment.txt').read_text())
                bad=subprocess.run(command[:2]+['--block-size','64KB']+command[2:],env=env,capture_output=True,text=True)
                self.assertEqual(bad.returncode,2)
            runner=root/'group-pmp-test-runner'; original=runner.read_text()
            runner.write_text(original.replace('keystone-motivation-production-interface-v1','stale'))
            result=run(1,'diagnostic','stale-interface')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('production interface selection',result.stderr)
            self.assertFalse((root/'stale-interface').exists())
            runner.write_text(original)
            fio_formal=subprocess.run(['sh',str(root/'run-motivation-architecture.sh'),
                                      '--interface','fio','--cipher','chacha20-poly1305',
                                      '3','100MB','hot',str(root/'data'),str(root/'fio-formal'),'formal'],
                                     env=env,capture_output=True,text=True)
            self.assertEqual(fio_formal.returncode,0,fio_formal.stdout+fio_formal.stderr)
            directory=next((root/'fio-formal').iterdir())
            self.assertEqual(len(module.read(directory/'manifest.csv')),12)
            self.assertEqual(len(module.read(directory/'samples.csv')),9)
            self.assertTrue(all(r['formal_eligible']=='1' and r['interface']=='fio'
                                for r in module.read(directory/'summary.csv')))
            for options in (['--interface','bad'], ['--interface'], ['--interface','fio','--block-size','sweep']):
                invalid=subprocess.run(['sh',str(root/'run-motivation-architecture.sh')]+options,
                                       env=env,capture_output=True,text=True)
                self.assertEqual(invalid.returncode,2)
            self.assertEqual(run(1,'formal','invalid').returncode,2)
            self.assertEqual(run(2,'formal','invalid-two').returncode,2)
            result=run(3,'formal','three')
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            three=next((root/'three').iterdir())
            self.assertEqual(len(module.read(three/'manifest.csv')),12)
            self.assertEqual(len(module.read(three/'samples.csv')),9)
            self.assertEqual([r['samples'] for r in module.read(three/'summary.csv')],['3','3','3'])
            self.assertTrue(all(r['formal_eligible']=='1' for r in module.read(three/'summary.csv')))
            environment=(three/'environment.txt').read_text()
            self.assertIn('group-pmp-sqlite-master.eapp_riscv',environment)
            self.assertNotIn('group-pmp-mixed-master.eapp_riscv',environment)
            self.assertIn('primary-architecture-motivation',environment)
            self.assertFalse(list((root/'data').iterdir()))
            result=run(1,'diagnostic','preview')
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(len(module.read(next((root/'preview').iterdir())/'manifest.csv')),6)
            result=run(10,'formal','failed',True)
            self.assertNotEqual(result.returncode,0)
            failed=next((root/'failed').iterdir())
            self.assertEqual(module.read(failed/'manifest.csv')[0]['status'],'failed')
            self.assertFalse((failed/'summary.csv').exists())
            self.assertFalse(list((root/'data').iterdir()))
            master=root/'group-pmp-sqlite-master.eapp_riscv'
            master.unlink()
            result=run(3,'formal','missing-master')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('missing production artifact',result.stderr)
            self.assertFalse((root/'missing-master').exists())
            master.write_text('wrong-master-fixture')
            result=run(3,'formal','wrong-master')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('production task Master',result.stderr)
            self.assertFalse((root/'wrong-master').exists())


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--mock': mock()
    else: unittest.main()
