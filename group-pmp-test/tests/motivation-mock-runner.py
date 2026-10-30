#!/usr/bin/env python3
# keystone-worker-overlap-v7
# keystone-motivation-blocking-ocall-v4
# keystone-motivation-shared-uring-v3
# keystone-motivation-epm-reservation-v2
# keystone-motivation-three-config-v2
# keystone-motivation-protected-task-v4
# SCRIPT TEST FIXTURE ONLY. Does not execute or measure enclave workloads.
import csv
import os
import pathlib
import sys

if "--artifact-info" in sys.argv:
    print("mock-artifact: no measured data")
    sys.exit(0)
e = os.environ
assert e["GROUP_PMP_TEST_MODE"] == "motivation"
mode = e["MOT_MODE"]
workers=int(e['MOT_WORKERS'])
if mode == "prepare":
    pathlib.Path(e["MOT_FILE"]).write_bytes(b"script-test-ciphertext-fixture")
else:
    size = int(e["MOT_BYTES"])
    block_bytes = int(e.get('MOT_BLOCK_BYTES',65536)); blocks = (size + block_bytes - 1) // block_bytes
    failed = e.get("MOCK_FAIL") == "1"
    row = dict(run_id=e["MOT_RUN_ID"], experiment_block=e["MOT_EXPERIMENT_BLOCK"],
               order=e["MOT_ORDER"], mode=mode, input_bytes=size,
               ciphertext_bytes=size+blocks*64, block_bytes=block_bytes, block_count=blocks,
               worker_enclaves=workers, slots=2, crypto_algorithm="aes-128-ecb" if e.get('MOT_CIPHER')=='aes-ecb-128' else "aes-128-gcm", compute_task="fixture-only",
               cache_policy=e["MOT_CACHE"], elapsed_ns=10000000, processed_bytes=size,
               result_ok=int(not failed), error_code=1 if failed else 0, timebase_hz=1000000000,
               result_digest=42, host_data_operations=blocks, wait_calls=0, max_outstanding=1,
               max_active_reads=1, submit_return_before_io_done=0, out_of_order_consumed=0,
               diagnostic=e["MOT_DIAGNOSTIC"],csv_schema=4,total_data_slots=2*workers,host_io_threads=workers,
               timing_scope='shared-start-to-final-validated-DONE',cohort_start_ticks=1000,cohort_end_ticks=10001000,
               io_backend='shared-io-uring-fixed',submit_syscalls=blocks,completion_cqes=blocks,
               read_ocall_semantics='blocking-until-read-complete' if mode=='sync' else 'admission-only',
               execution_environment='riscv-enclave')
    path = pathlib.Path(e["MOT_CSV"])
    if e.get('MOT_ARCHITECTURE')=='1':
        row.update(csv_schema=8,timing_scope='master-first-dispatch-to-final-protected-aggregate',
                   active_master=1,tsr_dispatches=workers,tsr_aggregates=workers,tsr_releases=workers,
                   master_aggregate_digest=42)
        initial=sum(min(blocks*(w+1)//workers-blocks*w//workers,1 if mode=='sync' else 2) for w in range(workers))
        row.update(read_ocalls=blocks,release_only_ocalls=initial,release_submit_ocalls=blocks-initial,data_path_ocalls=blocks+initial)
        if e['MOT_DIAGNOSTIC']=='1' and not failed:
            trace=[];tasks=[]
            for w in range(workers):
                first=blocks*w//workers;limit=blocks*(w+1)//workers
                for b in range(first,limit):
                    t=1010+20*(b-first)
                    trace.append(dict(worker=w+1,block=b,slot=0 if mode=='sync' else (b-first)%2,
                        generation=b-first+1 if mode=='sync' else (b-first)//2+1,
                        admit_ticks=t,io_begin_ticks=t+1,io_end_ticks=t+3,publish_ticks=t+3,
                        submit_return_ticks=t+3 if mode=='sync' else t+2,
                        compute_begin_ticks=t+4,compute_end_ticks=t+8,release_ticks=t+9,capture_end_ticks=t+5,decrypt_end_ticks=t+7))
                tasks.append(dict(worker=w+1,lane=w,epoch=1,sequence=w+1,dispatch_begin=1000,
                    dispatch_end=1001,acquire_ticks=1002,done_ticks=1010+20*(limit-first),
                    aggregate_begin=10000500+20*w,aggregate_end=10000505+20*w))
            for filename,records in [(e['MOT_TRACE'],trace),(str(path.parent/(e['MOT_RUN_ID']+'-tasks.csv')),tasks)]:
                with open(filename,'w',newline='') as f:
                    writer=csv.DictWriter(f,fieldnames=records[0]);writer.writeheader();writer.writerows(records)
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=row)
        if new: w.writeheader()
        w.writerow(row)
    if failed: sys.exit(5)
print("mock PASS: script flow only")
