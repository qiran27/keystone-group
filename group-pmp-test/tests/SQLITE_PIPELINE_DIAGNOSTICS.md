# SQLite pipeline diagnostics (policy 28, CSV schema 24)

This change does not increase logical batch limits, the four-live-plan limit,
the initial 64-SQE depth, or the 8 MB extent limit. AES, worker buffer ownership,
SM/CFS, and the request/completion ABI are unchanged.

## Changes and boundaries

1. The Host reactor again admits one compatible plan before refilling the
   kernel queue. It no longer plans several queued batches ahead of that first
   submission. Later plans may enter while earlier I/O remains in flight;
   the four-live-plan limit is unchanged. Already prepared sequential neighbors
   can still join into an extent, but no first submission waits for a future
   plan. Random credit guards, controls and overlapping-write barriers remain.
2. Depth feedback again observes successful whole-buffer publications, not
   physical CQEs. A ring split across plans produces one sample only after all
   its children, metadata and completion publication finish. The gate remains
   16 samples and 20 ms. Descriptor submission costs and depth epochs follow
   each buffer through publication. Old/mixed epochs and overlapping transition
   samples do not train a new depth. CQE counts and SQE diagnostics are retained
   independently; the reactor keeps serving I/O throughout settling.
3. A growth trial must actually exceed the old depth; a shrink trial must
   encounter pending work at its new SQE limit. A supply-limited trial returns
   to the stable depth and is reported as unexposed, not as a measured failure.
   Byte pressure alone does not trigger an SQE-depth probe. Throughput, tail,
   submission cost, cooldown, and the existing 16--128 depth bounds still apply.
4. Sequential neighbors are classified at submission time. With two buffers,
   both are initially free. In steady state one may still contain unread
   ciphertext or be in Host I/O while the other is refilled. Such a neighbor
   is not yet a safely reusable target. Do not delay the free buffer, add an
   ownership violation, or change the workload solely to increase merging.

Async and Adaptive share the one-plan-before-refill admission and diagnostics.
Async retains fixed physical depth and discrete I/O. Adaptive alone performs
extent joining and changes depth. Sync remains outside this persistent reactor;
its pipeline counters are zero.

## Controllable Host critical path

Two serial dependencies are corrected without increasing SQE depth or batch
sizes. The global edge-call dispatcher calls `submitBatch()` before publishing
the submission ACK. Adaptive random writes previously waited there for the
service queue to drop below its depth limit. That wait held the edge dispatcher,
delaying other producers and completion-WAIT handling. Admission now reserves
only descriptors for the existing two UTM buffers per worker, using the maximum
ring descriptor count even for a short tail. At 15 workers this is 7,680 queued
descriptors, capped at the existing 32,768 overall limit. Payloads stay in UTM;
the four-plan limit and physical SQE/byte credits still bound service. Overflow
outside this finite reservation and shutdown retain their existing handling.
This admission change is Adaptive-only; Sync and Async submission policy are
not changed.

The persistent reactor previously reconstructed buffer groups and rescanned all
live descriptors after every CQE batch, even when no buffer could complete.
Each plan now indexes its completion groups once and updates unfinished-child
counts when CQEs arrive. Publication inspects the small buffer-group index and
visits descriptors only for buffers ready to publish. Async and Adaptive share
this structural improvement. A ring split across plans is still unpublished
until all its children are present and done. Overwrite dependencies, failed
replacement propagation, metadata-before-success, buffer ownership and
exactly-once wakeups are retained. No kernel/SM/CFS or AES changes are involved.

The new `io_pipeline_` counters isolate the remaining Host work:

| Fields | Scope |
| --- | --- |
| `admission_wait_count`, `admission_wait_ns`, `admission_wait_max_ns` | Actual queue-capacity waits inside submission, excluding acquisition of the queue mutex. Normally zero for valid two-buffer producers within their reservation. |
| `enqueue_lock_ns` | Cumulative time acquiring the queue mutex during submission. |
| `completion_indexed_tasks`, `completion_buffer_checks`, `completion_check_ns` | Descriptors indexed once, buffer groups checked, and Host time in publication eligibility checks (including index construction when needed). |
| `metadata_lookup_ns`, `metadata_commit_ns` | Host lookup and commit sections, including their locking/preparation. Commit is also represented within existing commit/publication buckets; do not add overlapping buckets. |
| `wake_callback_ns` | Completion callback dispatch, including any synchronous batched resume ioctl. It ends at Host return, not actual enclave execution. |

These are accumulated Host elapsed intervals, not exclusive CPU time or additive
end-to-end stages. Join with worker submission/WAIT-return timestamps to separate
Host admission from normal runnable queueing. The change does not claim to
remove all worker resume delay. The new benchmark output must establish which
remaining section dominates; no fixed-delay or speedup target is manufactured.

## Failed trials and low-gain merges

Depth trials that fail the throughput, tail or submission-cost checks return
to the stable depth and use the document policy's fixed four-window cooldown.
Accepted and unexposed trials also use four windows; an unexposed trial is not
a measured failure. Each window requires 16 successful buffer samples and
20 ms. Failure-streak, cooldown and skipped-window counters remain. Requests
keep being served; no worker delay or collection sleep is added.

The two readrand100k copy-cost classes evaluate both discrete references and
merge trials after four completed plans. Merging stops if it fails the existing
service-per-byte gain, service-tail or Host planning/copy/publication-cost
checks. A failed trial uses a fixed eight-window cooldown rather than increasing
it after consecutive failures. Successful merging still periodically refreshes
a discrete reference through normal work.
Already submitted I/O completes normally; stale feedback epochs cannot reverse
the decision. Random 4 KB fast paths and Async policy are unchanged.

Sync now counts READ/WRITE attempts in `logical_request_count`,
`physical_request_count` and `sparse_io_count`, including failed data requests.
RESET/SYNC and other controls remain in `sqlite_task_count` and control timing
but not in the data-I/O counters. These are one-per-request SQLite BLOB
operations, not SQLite's internal filesystem or block-device request counts.
This fixes the old per-row excess of N control tasks without changing timing
or the workload.

## Reading the CSV

All names below have the `io_pipeline_` prefix. `io_pipeline_version` is 6.
The CSV still has 329 fields and schema 24; version 6 identifies the restored
buffer-level learning semantics. Do not pool its feedback samples with version 5.

| Fields | Meaning |
| --- | --- |
| `sqes_accepted`, `submits` | Accepted SQEs and nonempty submit groups. Their ratio is the average actual SQEs per group, not descriptors per doorbell. |
| `submit_one`, `submit_2_4`, `submit_5_16`, `submit_17_64`, `submit_over64`, `submit_max` | Accepted group-size distribution and maximum. |
| `enter_calls`, `enter_partial` | Actual enter syscall attempts and positive short accepts. A submit group may need multiple enters; accepted writes are never replayed. |
| `credit_limited`, `byte_limited`, `ready_exhausted` | Refill stop reasons: SQE credits, in-flight byte budget, or all prepared operations submitted. Counts are decisions, not elapsed time. |
| `admit_rounds`, `admitted_plans`, `plan_limited`, `barrier_blocked`, `write_conflict` | One-plan admission attempts, admitted plans, capacity and correctness barriers. |
| `seq_peer_inflight`, `seq_peer_queued`, `seq_peer_absent`, `seq_peer_ready_unjoined` | Where the next adjacent region was found for a below-limit Adaptive sequential operation. Absent includes file/task end; ready-unjoined includes span/byte/vector/direct-I/O constraints. |
| `seq_ready_ns` | Sum of each logical sequential request's Host dequeue-to-submit duration. Overlapping requests are counted separately; this is not wall time. |
| `depth_samples`, `depth_windows`, `depth_pending_samples` | Successful buffer learning samples, closed observation windows and samples left in the current window. Cache-only/error buffers do not train. |
| `depth_stale_samples`, `depth_transition_samples` | Old/mixed-depth buffers and current-depth buffer samples overlapping the settling boundary. |
| `depth_probes`, `depth_accepts`, `depth_rejects`, `depth_unexposed`, `depth_probe_active` | Trial outcomes. An unfinished or unexposed trial is not evidence of gain or regression. |
| `depth_failure_streak`, `depth_backoff_windows`, `depth_backoff_skips` | Capped consecutive failures, cooldown windows remaining and observation windows served without starting a new trial. |

`service_ewma_ns` is earliest buffer submission to Host completion publication,
including metadata/cache/publication work. `tail_ewma_ns` also includes the Host
queue before submission. Neither is a pure disk hardware latency or percentile.
Observation throughput spans the sampled interval and may include producer idle
time. It does not measure actual enclave resume; use the separate worker-side
return timestamps. Completion publication and buffer reuse remain separately
measured. Use the existing worker-side `readseq_initial_requests`
and `readseq_refill_peer_{io,ready,idle}_requests` with the new Host-side neighbor
counts to distinguish producer availability from missed Host opportunities.

These are application I/O/SQE counts, not device block-request counts. A small
SQE group can be correct if one SQE is an 8 MB vector, little work is ready, or
only a few credits became free. Do not treat small groups alone as a regression.
In multi-repetition summary CSVs, counters are independently aggregated by
median. For exact count identities and ratios, inspect a single repetition.

## Verification and board check

On Linux, run `sh tests/run-sqlite-io-regression.sh`. The regression covers real
io_uring early completion/refill, ready-only cross-plan 8 MB vector I/O, write
barriers, distinct byte/credit limits, clean depth epochs, unexposed trials,
short-run buffer sample accounting, no CQE-level training, fixed four-window
depth cooldown, four-plan merge evaluation with eight-window cooldown, stale
merge epochs, one-plan submission before further planning, two-buffer ACK admission without storage
progress, bounded overflow/cancellation, incremental completion of split rings,
Sync data/control counts, drain
finalization and the expanded CSV schema.
It does not emulate board PMP, HSM or device performance.

Rebuild and deploy the example runner and matching script, then preview with:

```sh
./run-p10-mixed-scaling.sh sqlite-bench all 15 1 60MB cold
```

Use the same command with `5 512MB cold` for longer observations. A preview can
legitimately end with too few samples or an unfinished probe. No throughput
improvement is established until board measurements confirm it.

## Completion-order-independent read validation

The read sample checksum now sums per-request fingerprints bound to the logical
offset, length and the same first/last 16 plaintext bytes checked previously.
It must not chain the preceding request's hash: WAIT_ANY and local completion
consumption can legitimately change the order between repetitions. This remains
a benchmark sample check, not cryptographic authentication. No extra payload
scan, in-order completion wait, AES or I/O policy change is introduced.

The regression first reproduced different READSEQ digests solely by changing
buffer completion order. It now checks five completion schedules for READSEQ,
READRANDOM and READRAND100K, including partial tails and corrupted edge samples.
Five-sample aggregation retains strict digest and dispatch/aggregate checks;
variable OCALL/wait counts remain performance observations. SQLite checks these
invariants after each timed case and logs the sample, field and both values on
failure, rather than discovering the mismatch only after the whole suite.
Checksum values from before this fix are not numerically comparable to the new
ones; throughput units, timing intervals, CSV schema and policy 28 are unchanged.
