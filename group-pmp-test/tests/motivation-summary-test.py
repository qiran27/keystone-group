import importlib.util
import pathlib
import unittest
import csv
import tempfile
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mot_summary", ROOT / "motivation/summarize.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixtures():
    # Synthetic unit fixtures only; never placed in benchmark result directories.
    return [dict(run_id=f"{m}-{r}", experiment_block=str(r), order=str(i+1), mode=m,
                 input_bytes="60000000", ciphertext_bytes="60058624", block_bytes="65536",
                 block_count="916", worker_enclaves="1", slots="2", crypto_algorithm="aes-128-gcm",
                 compute_task="hash", cache_policy="cold", diagnostic="0", elapsed_ns=str(t),
                 processed_bytes="60000000", result_ok="1", host_data_operations="916",
                 result_digest="123", timebase_hz="4000000")
            for r in range(10) for i, (m, t) in enumerate((("sync", 2000000), ("async", 1000000)))]

def triples():
    rows=[]
    for r in range(10):
        for order,(mode,workers,time) in enumerate((('sync',1,6000000),('async',1,3000000),('async',3,1000000)),1):
            row=dict(fixtures()[0],run_id=f'{r}-{mode}-{workers}',experiment_block=str(r),order=str(order),
                     mode=mode,worker_enclaves=str(workers),elapsed_ns=str(time),csv_schema='2',
                     total_data_slots=str(2*workers),host_io_threads=str(2*workers),max_outstanding=str(2*workers),
                     timing_scope='shared-start-to-final-validated-DONE',cohort_start_ticks='1000',
                     cohort_end_ticks=str(1000+time//250))
            rows.append(row)
    return rows


class TestSummary(unittest.TestCase):
    def test_schema8_recycle_accounting(self):
        rows=triples()[:9]
        for r in rows:
            workers=int(r['worker_enclaves']);initial=1 if r['mode']=='sync' else 2*workers
            r.update(csv_schema='8',crypto_algorithm='aes-128-ecb',host_io_threads=r['worker_enclaves'],
                io_backend='shared-io-uring-fixed',submit_syscalls='916',completion_cqes='916',
                execution_environment='riscv-enclave',wait_calls='0',submit_return_before_io_done='0',
                read_ocall_semantics='blocking-until-read-complete' if r['mode']=='sync' else 'admission-only',
                active_master='1',tsr_dispatches=r['worker_enclaves'],tsr_aggregates=r['worker_enclaves'],
                tsr_releases=r['worker_enclaves'],master_aggregate_digest=r['result_digest'],
                timing_scope='master-first-dispatch-to-final-protected-aggregate',read_ocalls='916',
                release_only_ocalls=str(initial),release_submit_ocalls=str(916-initial),data_path_ocalls=str(916+initial))
            if r['mode']=='sync':r['max_outstanding']='1'
        summary=mod.summarize(rows)[0]
        self.assertEqual(summary['formal_eligible'],1)
        self.assertEqual(summary['sync_data_path_ocalls_median'],917)
        self.assertEqual(summary['async_data_path_ocalls_median'],918)
        self.assertEqual(summary['async3_data_path_ocalls_median'],922)
        for field in ('read_ocalls','release_only_ocalls','release_submit_ocalls','data_path_ocalls'):
            invalid=[dict(r) for r in rows];invalid[0][field]='0'
            with self.assertRaises(ValueError):mod.summarize(invalid)
        rows[0]['csv_schema']='7'
        with self.assertRaises(ValueError):mod.summarize(rows)

    def test_schema7_geometry_groups(self):
        rows=[]
        for block_bytes in (4096,16384,65536):
            for r in triples()[:9]:
                r=dict(r);count=(60000000+block_bytes-1)//block_bytes
                r.update(run_id=str(block_bytes)+'-'+r['run_id'],experiment_block=str(block_bytes)+'-'+r['experiment_block'],
                    csv_schema='7',block_bytes=str(block_bytes),block_count=str(count),ciphertext_bytes=str(60000000+64*count),
                    crypto_algorithm='aes-128-ecb',host_io_threads=r['worker_enclaves'],host_data_operations=str(count),
                    io_backend='shared-io-uring-fixed',submit_syscalls=str(count),completion_cqes=str(count),
                    execution_environment='riscv-enclave',wait_calls='0',submit_return_before_io_done='0',
                    read_ocall_semantics='blocking-until-read-complete' if r['mode']=='sync' else 'admission-only',
                    active_master='1',tsr_dispatches=r['worker_enclaves'],tsr_aggregates=r['worker_enclaves'],
                    tsr_releases=r['worker_enclaves'],master_aggregate_digest=r['result_digest'],
                    timing_scope='master-first-dispatch-to-final-protected-aggregate')
                if r['mode']=='sync':r['max_outstanding']='1'
                rows.append(r)
        result=mod.summarize(rows)
        self.assertEqual({r['block_bytes'] for r in result},{4096,16384,65536})
        self.assertTrue(all(r['formal_eligible']==1 for r in result))
        rows[0]['ciphertext_bytes']='1'
        with self.assertRaises(ValueError):mod.summarize(rows)

    def test_schema7_stage_timing(self):
        sample=dict(run_id='stages',mode='sync',worker_enclaves='1',block_count='2',timebase_hz='1000',
            elapsed_ns='100000000',max_outstanding='1',out_of_order_consumed='0',csv_schema='7',
            cohort_start_ticks='1',cohort_end_ticks='101',block_bytes='4096')
        rows=[dict(worker=1,block=i,slot=0,generation=i+1,admit_ticks=2+40*i,
            io_begin_ticks=3+40*i,io_end_ticks=5+40*i,publish_ticks=6+40*i,submit_return_ticks=7+40*i,
            compute_begin_ticks=8+40*i,capture_end_ticks=10+40*i,decrypt_end_ticks=20+40*i,
            compute_end_ticks=25+40*i,release_ticks=26+40*i) for i in range(2)]
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'trace.csv'
            def save():
                with path.open('w',newline='') as f:
                    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
            save();report,_=mod.trace_summary(path,sample)
            self.assertEqual(report['complete'],1)
            self.assertEqual(report['cipher_capture_ms_sum'],4)
            self.assertEqual(report['identity_and_decrypt_ms_sum'],20)
            self.assertEqual(report['full_byte_verify_ms_sum'],10)
            self.assertEqual(report['release_to_next_submit_ms_sum'],16)
            self.assertAlmostEqual(report['verify_share_of_processing_pct'],100*10/34)
            sample['csv_schema']='8'
            self.assertEqual(mod.trace_summary(path,sample)[0]['complete'],1)
            rows[1]['generation']=1;save()
            self.assertEqual(mod.trace_summary(path,sample)[0]['complete'],0)
            rows[1]['generation']=2;rows[1]['admit_ticks']=25;save()
            with self.assertRaises(ValueError):mod.trace_summary(path,sample)
            rows[1]['admit_ticks']=42;save()
            self.assertEqual(mod.trace_summary(path,sample)[0]['complete'],1)
            rows[0]['capture_end_ticks']=21;save()
            with self.assertRaises(ValueError):mod.trace_summary(path,sample)

    def test_cipher_separation_and_schema6(self):
        rows=triples()[:9]
        for r in rows:
            r.update(csv_schema='6',crypto_algorithm='aes-128-ecb',host_io_threads=r['worker_enclaves'],
                     io_backend='shared-io-uring-fixed',submit_syscalls='916',completion_cqes='916',
                     execution_environment='riscv-enclave',wait_calls='0',submit_return_before_io_done='0',
                     read_ocall_semantics='blocking-until-read-complete' if r['mode']=='sync' else 'admission-only',
                     active_master='1',tsr_dispatches=r['worker_enclaves'],tsr_aggregates=r['worker_enclaves'],
                     tsr_releases=r['worker_enclaves'],master_aggregate_digest=r['result_digest'],
                     timing_scope='master-first-dispatch-to-final-protected-aggregate')
            if r['mode']=='sync':r['max_outstanding']='1'
        result=mod.summarize(rows)[0]
        self.assertEqual((result['formal_eligible'],result['crypto_algorithm']),(1,'aes-128-ecb'))
        bad=[dict(r) for r in rows];bad[0]['crypto_algorithm']='aes-128-gcm'
        with self.assertRaises(ValueError):mod.summarize(bad)
        for r in rows:r['crypto_algorithm']='invalid'
        with self.assertRaises(ValueError):mod.summarize(rows)

    def test_protected_task_contract(self):
        rows=triples()[:9]
        for r in rows:
            r.update(csv_schema='5',host_io_threads=r['worker_enclaves'],io_backend='shared-io-uring-fixed',
                     submit_syscalls='916',completion_cqes='916',execution_environment='riscv-enclave',
                     read_ocall_semantics='blocking-until-read-complete' if r['mode']=='sync' else 'admission-only',
                     wait_calls='0',submit_return_before_io_done='0',active_master='1',
                     tsr_dispatches=r['worker_enclaves'],tsr_aggregates=r['worker_enclaves'],
                     tsr_releases=r['worker_enclaves'],master_aggregate_digest=r['result_digest'],
                     timing_scope='master-first-dispatch-to-final-protected-aggregate')
            if r['mode']=='sync':r['max_outstanding']='1'
        self.assertEqual(mod.summarize(rows)[0]['formal_eligible'],1)
        for field,value in [('active_master','0'),('tsr_dispatches','0'),('tsr_aggregates','0'),
                            ('tsr_releases','0'),('master_aggregate_digest','999')]:
            bad=[dict(r) for r in rows];bad[0][field]=value
            with self.assertRaises(ValueError):mod.summarize(bad)
        for r in rows:r['execution_environment']='native-linux-no-enclave'
        self.assertEqual(mod.summarize(rows)[0]['formal_eligible'],0)

    def test_protected_task_witness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            sample=dict(run_id='task',worker_enclaves='1',cohort_start_ticks='100',cohort_end_ticks='300')
            trace=[dict(worker=1,admit_ticks=150,release_ticks=240)]
            row=dict(worker=1,lane=0,epoch=1,sequence=1,dispatch_begin=101,dispatch_end=110,
                     acquire_ticks=120,done_ticks=250,aggregate_begin=260,aggregate_end=270)
            def save(value):
                with (root/'task-tasks.csv').open('w',newline='') as f:
                    w=csv.DictWriter(f,fieldnames=value);w.writeheader();w.writerow(value)
            save(row)
            self.assertEqual(len(mod.task_witness(root,sample,trace)),1)
            for field,value in [('lane',1),('epoch',0),('sequence',2),('done_ticks',200),('aggregate_end',301)]:
                save(dict(row,**{field:value}))
                with self.assertRaises(ValueError):mod.task_witness(root,sample,trace)

    def test_blocking_contract(self):
        rows=triples()
        for r in rows:
            r.update(csv_schema='4',host_io_threads=r['worker_enclaves'],io_backend='shared-io-uring-fixed',
                     submit_syscalls='916',completion_cqes='916',execution_environment='riscv-enclave',
                     read_ocall_semantics='blocking-until-read-complete' if r['mode']=='sync' else 'admission-only',
                     wait_calls='0',submit_return_before_io_done='0')
            if r['mode']=='sync': r['max_outstanding']='1'
        self.assertEqual(mod.summarize(rows)[0]['formal_eligible'],1)
        three=rows[:9]
        result=mod.summarize(three)[0]
        self.assertEqual((result['formal_eligible'],result['sync_valid_runs'],
                          result['async_valid_runs'],result['async3_valid_runs']),(1,3,3,3))
        self.assertEqual(mod.summarize(rows[:6])[0]['formal_eligible'],0)
        self.assertEqual(mod.summarize(rows[:3])[0]['formal_eligible'],0)
        diagnostic=[dict(r,diagnostic='1') for r in three]
        self.assertEqual(mod.summarize(diagnostic)[0]['formal_eligible'],0)
        failed=[dict(r) for r in three];failed[0]['result_ok']='0'
        self.assertEqual(mod.summarize(failed)[0]['formal_eligible'],0)
        for field,value in [('wait_calls','1'),('submit_return_before_io_done','1'),('read_ocall_semantics','admission-only')]:
            bad=[dict(r) for r in rows];bad[0][field]=value
            with self.assertRaises(ValueError):mod.summarize(bad)
        for r in rows:r['execution_environment']='native-linux-no-enclave'
        self.assertEqual(mod.summarize(rows)[0]['formal_eligible'],0)
        self.assertEqual(mod.summarize(rows[:9])[0]['formal_eligible'],0)

    def test_triplet_svg(self):
        with tempfile.TemporaryDirectory() as tmp:
            samples={};traces={}
            for mode,workers in [('sync',1),('async',1),('async',3)]:
                name=f'{mode}-{workers}'
                samples[name]=dict(run_id=name,experiment_block='fixture',cache_policy='cold',csv_schema='4',
                    mode=mode,worker_enclaves=str(workers),timebase_hz='1000',cohort_start_ticks='100',
                    execution_environment='native-linux-no-enclave')
                traces[name]=[dict(worker=w,block=w,io_begin_ticks=100,io_end_ticks=105,
                    compute_begin_ticks=106,compute_end_ticks=110) for w in range(1,workers+1)]
            mod.timeline_svg(pathlib.Path(tmp),traces,samples)
            tree=ET.parse(pathlib.Path(tmp)/'timeline-fixture-65536B.svg')
            self.assertGreater(len(tree.findall('.//{http://www.w3.org/2000/svg}rect')),5)

    def test_shared_transport(self):
        rows=triples()
        for r in rows:
            r.update(csv_schema='3',host_io_threads=r['worker_enclaves'],io_backend='shared-io-uring-fixed',
                     submit_syscalls='916',completion_cqes='916')
            if r['mode']=='sync': r['max_outstanding']='1'
        result=mod.summarize(rows)[0]
        self.assertEqual(result['formal_eligible'],1)
        self.assertEqual(result['async_host_io_reduction_vs_sync_pct'],0)
        self.assertEqual(result['async_submit_syscalls_median'],916)
        bad=[dict(r) for r in rows];bad[0]['io_backend']='pread'
        with self.assertRaises(ValueError):mod.summarize(bad)
        bad=[dict(r) for r in rows];bad[0]['completion_cqes']='915'
        with self.assertRaises(ValueError):mod.summarize(bad)
        bad=[dict(r) for r in rows];bad[0]['max_outstanding']='2'
        with self.assertRaises(ValueError):mod.summarize(bad)

    def test_mixed_backend_revisions(self):
        rows=triples(); rows[0]['csv_schema']='3'
        with self.assertRaises(ValueError):mod.summarize(rows)

    def test_three_configurations(self):
        r=mod.summarize(triples())[0]
        self.assertEqual((r['formal_eligible'],r['async3_valid_runs'],r['async3_vs_sync1_speedup'],r['async3_vs_async1_speedup']),(1,10,6,3))
        self.assertEqual(r['configuration_order_complete'],1)

    def test_missing_three_worker(self):
        rows=[r for r in triples() if r['worker_enclaves']=='1']
        r=mod.summarize(rows)[0]
        self.assertEqual((r['formal_eligible'],r['configuration_order_complete']),(0,0))

    def test_mixed_timing_rejected(self):
        with self.assertRaises(ValueError): mod.summarize(fixtures()+triples())

    def test_cohort_clock_mismatch(self):
        rows=triples();rows[0]['cohort_end_ticks']='1001'
        with self.assertRaises(ValueError):mod.summarize(rows)
    def test_formulas(self):
        r = mod.summarize(fixtures())[0]
        self.assertEqual((r["formal_eligible"], r["XX_sync_extra_time_pct"], r["YY_async_time_reduction_pct"]), (1, 100, 50))

    def test_failure_preserved(self):
        rows = fixtures(); rows[0]["result_ok"] = "0"
        r = mod.summarize(rows)[0]
        self.assertEqual((r["formal_eligible"], r["failed_runs"], r["sync_valid_runs"]), (0, 1, 9))

    def test_diagnostic_not_formal(self):
        rows = fixtures()
        for r in rows: r["diagnostic"] = "1"
        self.assertEqual(mod.summarize(rows)[0]["formal_eligible"], 0)

    def test_digest_mismatch(self):
        rows = fixtures(); rows[0]["result_digest"] = "bad"
        self.assertEqual(mod.summarize(rows)[0]["speedup_sync_over_async"], "")

    def test_duplicate(self):
        rows = fixtures()
        with self.assertRaises(ValueError): mod.summarize(rows + [rows[0]])

    def test_unpaired(self):
        self.assertEqual(mod.summarize(fixtures()[1:])[0]["paired_order_complete"], 0)

    def test_overlap_union(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "trace.csv"
            trace = [dict(block=0, slot=0, generation=1, admit_ticks=0, io_begin_ticks=0,
                          io_end_ticks=10, publish_ticks=10, submit_return_ticks=2,
                          compute_begin_ticks=10, compute_end_ticks=30, release_ticks=31),
                     dict(block=1, slot=1, generation=1, admit_ticks=1, io_begin_ticks=5,
                          io_end_ticks=20, publish_ticks=20, submit_return_ticks=3,
                          compute_begin_ticks=31, compute_end_ticks=41, release_ticks=42)]
            with path.open("w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=trace[0]); w.writeheader(); w.writerows(trace)
            sample = dict(run_id="fixture", mode="async", timebase_hz="1000", block_count="2",
                          max_outstanding="2", out_of_order_consumed="0")
            r, _ = mod.trace_summary(path, sample)
            self.assertEqual((r["complete"], r["io_compute_overlap_ms"], r["early_submit_returns"]), (1, 10, 2))
            self.assertEqual((r['read_service_ms_sum'],r['read_service_ms_union'],r['processing_ms_sum'],r['processing_ms_union']),
                             (25,20,30,30))
            if importlib.util.find_spec("matplotlib"):
                mod.plot(path.parent, mod.summarize(fixtures()), {"fixture": trace}, {"fixture": sample})
                self.assertGreater((path.parent / "figure-1c-cold-diagnostic0.png").stat().st_size, 1000)
                self.assertGreater((path.parent / "fixture-timeline.png").stat().st_size, 1000)


if __name__ == "__main__": unittest.main()
