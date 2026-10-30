# Enclave KV Pipeline Benchmark v1

This is a self-contained **fixed-key-space KV prototype**, not a port of
ShieldStore, RocksDB, or a standardized Secure KV benchmark. Its purpose is
comparison of Sync/Async/Adaptive encrypted I/O pipelines and clustering cost.
AES-128-ECB is unchanged. It does **not** authenticate records, hide access
patterns, or protect against rollback. Full-record checks are benchmark
correctness checks against deterministic expected data, not cryptographic MACs.

## Actual application and storage

- The worker constructs PUT values, computes key-to-record addresses, decrypts
  GET records, and checks **all bytes** inside private EPM.
- Keys are 64-bit record-slot IDs within a worker-owned shard. There is no
  general-purpose hash table, range scan, variable-key engine, or cross-worker
  update to the same key. The shard and fixed slot give a direct-address index.
- A normal encrypted record is 4096 bytes: key (8), owner/shard (4), generation
  (4), and deterministic value payload (4080). The final short record is
  retained, AES-block aligned, with the same 16-byte header. Total size counts
  serialized record bytes, not only value bytes. This is not SQLite's 240-byte
  record benchmark despite reuse of its transport task accounting.
- PUT creates the shard with generation 0. GET preloads generation-0 records
  before timing, then reads each key once. UPDATE preloads generation 0 before
  timing and replaces every key with generation 1. No mixed read/write workload
  is claimed in v1. Writes check status/sequence/length; board PUT/UPDATE do not
  read back every write in the measured window. Native tests independently read
  back persisted ciphertext and verify updated versions.
- All modes use the current deterministic `locality-random-v1` address workload.
  This has controlled locality and is not uniform random or a YCSB generator.
  There is no future-address planning: clustering sees only submitted requests.
- Master task distribution, SM lane isolation, registered ciphertext UTM,
  request/completion rings and result aggregation reuse the existing group path.
- Sync reuses the SQLite encrypted-BLOB baseline. Async and Adaptive share the
  metadata-only SQLite + external ciphertext implementation, depth, two buffers,
  metadata queries, and completion publication. Only Adaptive performs clustering
  (including its measured planning costs and calibrated representation gates).
  Sync versus Async is therefore a complete pipeline/storage comparison, not an
  isolated test of asynchronous submission. Async versus Adaptive isolates the
  existing merge strategy within their common execution path.

## Build and run

In the build VM, run `./rebuild-and-test.sh`, then redeploy the **entire** deploy
directory. It builds `group-pmp-kv-worker.eapp_riscv`, updates the Host entry,
syncs `secure-kv/*.c,*.h`, and deploys both KV scripts. A marker check rejects
an old runner or worker.

```sh
# Quick preview, all three workloads and modes, 1..15 workers, one repetition.
sh ./run-secure-kv-enclave-scaling.sh all all 15 1 60MB cold
# Six sizes, five repetitions per scale, all three workloads/modes.
sh ./run-secure-kv-enclave-scaling.sh all all 15 5 sweep cold
# GET only, Async and Adaptive.
sh ./run-secure-kv-enclave-scaling.sh get both 15 5 500MB cold
# Optional directories.
KV_ENCLAVE_STORAGE_DIR=/tmp KV_ENCLAVE_OUTPUT_DIR=/secure-kv-bench \
sh ./run-secure-kv-enclave-scaling.sh all all 15 5 sweep cold
```

Defaults: data under a unique `/tmp/.keystone-kv-*` directory, results under
`/secure-kv-bench/`. Data is removed after each mode/workload/size; results
are retained. On the current board `/tmp` is tmpfs: this tests RAM-backed
encrypted storage, **not SD or USB disk bandwidth**. `cold` reuses the current
post-prefill cache reset, not a guarantee of physical cold-device traffic.
The available cache modes are hot and buffered cold (no Direct mode in v1).
At least 3x configured input size in free data capacity is required. All scale
samples use the same fixed shuffled order. One run is a preview; no performance
gain is promised without board measurements.

Before Adaptive runs, the wrapper generates the same repeated, paired mixed
batch calibration as SQLite (default 93 rounds). Its `.profile` and `.log` are
retained in the results directory. `GROUP_PMP_SQLITE_MERGE_PROFILE=/absolute/path`
can supply an existing compatible profile. Calibration may reject a merge
representation, including random reads; the wrapper does not lower thresholds
or force a desired merge ratio. The calibration excludes KV/AES application
work, so end-to-end comparison is still necessary.

## Outputs and interpretation

For each workload/size/mode:

- `*.csv`: scale summaries with seconds/MB/s/ops/s median, real min/max, and
  seconds P95 across the configured repetitions.
- `*-samples.csv`: every successfully measured repetition, including performance,
  logical KV operation count, Host data operations, submit calls, doorbells,
  wakes, useful/transferred bytes, planning/vector/API/publication timing, and
  validation. Samples are flushed before the next run. Failed samples are not
  converted to estimated values.
- `*-io.csv`: same-scale medians of I/O counts and timing measurements.
- `*.log`: runtime evidence including validated completion.

`*-comparison.csv` is produced only after all selected modes succeed and their
workload/cache/address/bytes/sample/logical-count fields match. All gains and
I/O reductions use **same-N medians**. `both` has no Sync reference (NA). No
outlier substitution is performed. ops/s counts completed serialized KV records
(including the short tail), not SQLite metadata rows or submit calls.

Host operation counts are not device-level block requests. Sum timing buckets
are not wall-clock breakdowns because operations overlap. For publication,
`last_cqe_to_buffer_publish_p95_ns` and `buffer_enqueue_to_publish_p95_ns` are
per-run internal buffer P95 measurements; their summary is the **median of
per-run P95**, not a pooled P95. Counts and API measurements describe the shared
I/O implementation and retain its existing scope/Sync availability limits.

## Local verification

`sh tests/run-kv-tests.sh` exercises production store compilation, real AES
roundtrip with persisted ciphertext, PUT/GET/UPDATE and tails, full-record
negative checks, independent/out-of-order completions, Host syntax, six-size
wrapper selection, comparison formulas, failures and cleanup. Run
`sh tests/run-rv8-tests.sh` too to check the shared store regression surface.
These native tests do not emulate PMP or prove board performance.
