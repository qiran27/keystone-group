# Motivation: 1 Worker Sync, 1 Worker Async, 3 Workers Async

## Direct Production Interface Modes

The same entry now accepts `--interface sqlite` or `--interface fio`, in addition
to the unchanged default `--interface minimal`. Production choices run the actual
production Master/Worker, encrypted VFS and Host Sync/Async services, not the
private motivation backend. The fio choice uses the existing `seq-read-2m` enclave
profile and shares the current implementation with SQLite; it is not upstream fio.
Both choices use existing 2MB buffers/production validation, not the minimal
64KB full-byte-check task. Production Sync BLOB and Async external-extent service
differences remain and must be disclosed; do not call this an overlap-only gain.
See `minimal-architecture.md` for commands, data separation and limits. No change
to the main SQLite/fio benchmarks or Adaptive is intended by this selection mode.

## Latest Scope: A Minimal Experiment Using Real Architecture Mechanisms

The implemented entry is `run-motivation-architecture.sh` (protected-task v4,
CSV schema 8). An active Master publishes actual protected TSR tasks and
aggregates their protected results. The common task is read/decrypt/validate;
Sync1, Async1 and Async3 share one ciphertext file and registered io_uring
backend. Default cipher is AES-128-ECB, matching the main ECB performance
configuration; `--cipher aes-gcm-128` retains the GCM comparison. This is an
explicit workload configuration change, not a claim that old GCM results
became faster. Never mix the ciphers. There is no SQLite business or Adaptive clustering. See
`minimal-architecture.md` for the exact protocol, measurement and limitations.
V3 adds optional `--block-size 4KB|16KB|64KB|sweep` (64KB default) and diagnostic
capture/decrypt/full-byte-check timing. Formal runs omit the extra stage clocks;
no validation is removed and no gain is guaranteed. Each geometry is reported
separately; use all three sizes to assess sensitivity rather than select a ratio.
V4 performs old-buffer release and same-slot next-read admission in one shared
OCALL, only after full validation. Sync blocks for the NEW read's completion;
Async remains admission-only. Initial reads and final tail releases stay simple.
There is no new algorithm, batching wait, extra buffer or application workload.
The new data-path OCALL counters distinguish reduced interactions from unchanged
Host read counts. Default remains 64KB and full-byte verification is unchanged.

```sh
# VM: rebuild, then copy the complete deployment to the board.
./rebuild-and-test.sh
# Board: 3 samples/configuration plus a separate three-panel diagnostic timeline.
sh ./run-motivation-architecture.sh --cipher aes-ecb-128 3 500MB cold /myusb/wj/deploy /motivation-architecture formal
# Optional matched granularity diagnostics, 3 cases at each of 3 block sizes:
sh ./run-motivation-architecture.sh --block-size sweep 1 500MB cold /myusb/wj/deploy /motivation-architecture diagnostic
```

This is nine untraced timing runs plus three separate traced runs, not twelve
samples per configuration. Local native verification uses the same C protocol
with a strict test-only permission model; it is not hardware PMP evidence.
The historical whole-system and inactive-owner experiments below remain
available but are not interchangeable with schema 8 or pooled with its data.

## Existing Architecture Comparison

The existing architecture comparison is `run-motivation-system.sh`. It uses the real
production task Master, protected TSR dispatch/acquire/completion/revocation,
Worker enclave store, Control/Data UTM separation, two 2MB transport buffers,
Host asynchronous service, independent buffer publication and Master result
aggregation. The Master is active, not the inactive owner in the controlled
experiment. Existing lane placement, SM/PMP protection and scheduler are reused.
Do not present the separate 64KiB overlap experiment as evidence of this whole
execution chain. No Adaptive clustering is enabled in these three groups.

```sh
# VM: build and copy the COMPLETE deployment when production binaries are stale.
./rebuild-and-test.sh
# Board: keep GCM as in the preceding diagnostic, now on the actual architecture.
sh ./run-motivation-system.sh --cipher aes-gcm-128 3 500MB cold /myusb/wj/deploy /motivation-system formal
# Optional one-round preview: three task runs plus three independent trace runs.
sh ./run-motivation-system.sh --cipher aes-gcm-128 1 500MB cold /myusb/wj/deploy /motivation-system diagnostic
```

Three formal rounds mean nine untraced task runs (Sync1/Async1/Async3 each three
times), followed by three separate timeline runs: twelve measured task runs in
total. Initialization/prefill/cache preparation are separate and each production
case may take additional time. Default repetitions remain ten; formal accepts
3..20, diagnostic accepts 1..20. The script supports one of the six explicit
sizes, not `sweep`. Cipher defaults to the production AES-128-ECB setting unless
explicitly selected. All three groups within a run share that cipher and cache.

Outputs include actual min/median/max, performance and Host operation/submission/
completion counters, `performance.svg` and one three-panel `timeline.svg`.
For 500MB the unchanged production workload rounds to 499999920 effective bytes,
not the custom experiment's exact 500000000 bytes. Existing standalone GCM
results are auxiliary evidence and must not be reclassified or pooled with this
new experiment. Do not promise a larger gain before board measurements.

Sync is our production synchronous implementation; Async is our complete
production asynchronous path. Their storage layouts also differ: ciphertext
BLOB service versus metadata plus external ciphertext. Consequently this is an
overall architecture comparison, not a claim of a pristine upstream Keystone
binary baseline or an isolated numerical attribution to overlap alone.

## Auxiliary: Blocking OCALL Versus Overlapped Execution (v4)

`run-motivation-overlap.sh` is retained ONLY as a controlled mechanism ablation,
not the primary architecture motivation. Revision `keystone-worker-overlap-v4`
uses the SAME ciphertext file, 64KiB record stream, AES-128-GCM, plaintext
digest computation and registered read backend in all configurations:

1. One Worker Sync: SDK `ocall()` enters a normal blocking read handler. The
   handler stays blocked until that read's CQE is observed and its UTM data and
   completion are published. Only then can the enclave resume, decrypt, compute
   and release the slot. There is no second completion-WAIT OCALL for that read.
2. One Worker Async: read OCALL returns on admission. Two UTM slots allow the
   next arrived read to run during current-block decrypt/compute. WAIT_ANY is
   used only when no owned slot is ready. No plaintext leaves the Worker.
3. Three Workers Async: disjoint ranges of the same total input, one private
   two-slot UTM per Worker, three compute lanes, one shared Host CPU.

This restores Keystone's conventional BLOCKING OCALL semantics for Sync while
keeping the storage backend matched. Group creation, exclusive lane launch and
SDK edge dispatch still use this repository. It is NOT a binary comparison
against an unmodified upstream Keystone image. An io_uring read inside the
blocking Host handler does not make the enclave's Sync API asynchronous.
Neither production SQLite layouts nor clustering/metadata differences enter
this experiment. No injected sleep, extra compute loop or reduced Sync backend
is used to force a speedup. A small/negative measured gain is retained.

```sh
# VM, then copy the complete deploy directory to the board:
./rebuild-and-test.sh
# One triplet with timing traces (preview, not formal statistics):
sh ./run-motivation-overlap.sh 1 500MB cold /myusb/wj/deploy /motivation-overlap diagnostic
# Ten triplets without trace overhead:
sh ./run-motivation-overlap.sh 10 500MB cold /myusb/wj/deploy /motivation-overlap formal
# Shorter statistics run: three repetitions/configuration, nine tasks total:
sh ./run-motivation-overlap.sh 3 500MB cold /myusb/wj/deploy /motivation-overlap formal
```

Description of the auxiliary ablation only (not the primary architecture):

为验证异步服务方向的有效性，我们对同一“读取密文、enclave 内解密及校验计算”
任务设置单 Worker 同步、单 Worker 异步与三 Worker 异步三组对照。同步组采用
Keystone 常规阻塞 OCALL 语义，读取完成后才返回 enclave；异步组在请求准入后
返回，利用双 UTM buffer 重叠 Host 读取与 enclave 计算。三组使用相同存储后端、
密码配置、总输入和缓存准备，三 Worker 按块分摊总任务。比较端到端总时间、
吞吐量和实际执行时间线，以区分单流重叠收益和多 Worker 并行收益，不使用聚类。
该对照保留本文系统的组启动机制，并非未经修改的上游 Keystone 整机基线。

Local reproducible verification (Linux/WSL, no enclave):

```sh
sh tests/run-motivation-tests.sh
sh tests/run-motivation-local-performance.sh 500000000 10 cold /var/tmp/motivation-local-new
```

The native performance harness compiles the actual C task and production read
backend. Separate processes preserve private task state; the reactor threads
share one Host CPU and compute flows use three other logical CPUs. An explicit
START barrier prepares cache once after all warmups. Ten rotated triplets
exclude tracing; one extra triplet supplies traces. It checks all bytes,
digests, read operations, CQEs and Sync return-after-publication ordering.
CSV marks `execution_environment=native-linux-no-enclave` and can NEVER become
formal board evidence. It does not emulate PMP, RISC-V crypto speed, OCALL or
scheduler costs; local speedup cannot be promised on the board. Store the raw
samples and measured improvements/regressions together.

## Historical Whole-System Comparison: Detailed Protocol

`run-motivation-system.sh` is a separate whole-system comparison. It uses
the full production path instead of the auxiliary standalone read protocol;
the two result families must not be pooled. No new board result is asserted.

```sh
# Rebuild in Ubuntu, then copy the COMPLETE deploy directory to the board.
./rebuild-and-test.sh
# Board: ten real runs/configuration plus three independent timeline runs.
sh ./run-motivation-system.sh 10 500MB cold /myusb/wj/deploy /motivation-system formal
# Three real runs/configuration plus three independent timeline runs (12 total).
sh ./run-motivation-system.sh 3 500MB cold /myusb/wj/deploy /motivation-system formal
# Quick correctness/trace preview: three timing runs plus three trace runs.
sh ./run-motivation-system.sh 1 500MB cold /myusb/wj/deploy /motivation-system diagnostic
# Match another cipher used in the main evaluation; never mix cipher results.
sh ./run-motivation-system.sh --cipher aes-gcm-128 10 500MB cold /myusb/wj/deploy /motivation-system formal
```

That whole-system experiment directly uses the real master, storage Worker, UTM rings,
Host storage implementations, scheduling and production timing. Its workload is
sequential encrypted-data reading with the existing enclave transform and
plaintext validation. It does NOT use a separate 64KiB test protocol, inject
delays, add hash loops, change queue depth, enable clustering, or replace slow
measurements. Default cipher is AES-128-ECB, matching that main evaluation;
select GCM/ChaCha explicitly when needed. This is a performance experiment,
not an ECB integrity claim.

Configurations are Sync with one Worker, Async with one Worker, and Async with
three Workers on lanes 0/1/2. The real Master runs in its normal role. All three
process the same configured total work, not a copy per Worker. The real workload
rounds to complete 240-byte records, so requested 500MB means 499999920 effective
bytes, equally in all configurations. Work and ciphertext are generated through
the unchanged production prefill, separately for each configuration; it is NOT
one identical ciphertext file reused across different storage layouts. Same-N
result digests are checked; cross-N partitioning can change the digest.

Formal runs keep tracing OFF and rotate the triplet's order each repetition.
They report the existing master-first-dispatch-to-final-aggregate elapsed time,
including actual storage, OCALL, blocking, resume and aggregation; creation,
prefill, cache preparation and cleanup remain outside the benchmark boundary.
Data location and mounts are recorded, not inferred from a directory name.
Private per-case databases/ciphertext are deleted after that case, preserving
all result files/logs and limiting storage growth.

After the timing runs, exactly THREE extra diagnostic cases collect Host events
and bounded enclave crypto wall/on-CPU intervals. They use the same real path,
but are not included in performance statistics. Enclave events remain in EPM
during the task; only timing/offset/length metadata is copied to an already free
UTM buffer after I/O drain. No new timed OCALLs, plaintext export or request
barriers are introduced. Overflow or coverage mismatch fails the diagnostic.
Common-clock alignment is measured and its uncertainty retained. Crypto wall
intervals may include descheduling; Host service is not physical disk busy time.

The stdlib-only analyzer automatically writes `samples.csv`, `summary.csv`,
`performance.svg`, `timeline.svg`, `timeline-intervals.csv`, `timeline-evidence.csv`,
input hashes and `results.txt`. The timeline is ONE figure with three panels;
the common startup crop ends at Sync1's sixth crypto completion, not a selected
best-case interval. Full-task intervals remain available. Real min/max/median
and I/O counts are preserved, whether the result improves or regresses.

### Suggested Paper Description

为考察同步存储服务对 RISC-V enclave 执行的限制，我们在相同总输入规模、
密码配置和缓存条件下，对比单 Worker 同步执行、单 Worker 异步执行，以及
三个 Worker 分别位于三条 lane 的并行异步执行。实验沿用 Extent-I/O 的实际
Master 任务分配、受保护 TSR 槽位授权与回收、双 UTM 缓冲、Host 存储路径及
独立完成通知机制，执行加密数据顺序读取与 enclave 内解密和校验，不额外引入
独立的数据传输协议或计算负载。每种配置按指定轮数重复，三轮运行各取得三个
实测样本，报告端到端总时间的中位数及实测最小、最大值。另以独立诊断运行
采集 Host 存储服务与 enclave 加解密区间，展示请求服务、计算和并行 lane 的
时间关系。三 Worker 共同处理固定总输入，而非重复处理三份数据。

该对照评估整体架构收益，不将同步与异步存储路径、提交组织及流水线的综合
差异全部归因于重叠；三 Worker 的扩展收益也不等同于单 Worker 异步收益。
时间线用于说明受测执行关系，实际性能结论须待测量后填写，不预设提升幅度。

## Simple Motivation: Protocol and Measurement Details

Revision: `keystone-worker-overlap-v4`, 2026-10-15. Raw CSV is v4; the matching
Worker and blocking-contract markers reject stale deployments. Prior v3 board
results remain archived as v3, not relabeled as v4.

## Build and run only 500 MB

Rebuild in the Ubuntu cross-build environment:

```sh
cd /home/wuju/keystone_yx/examples/group-pmp-test
./rebuild-and-test.sh
```

Copy the complete fresh deploy directory to the board, including runner,
`group-pmp-motivation-worker.eapp_riscv`, runtime/loader, script and `motivation/`.
Old runner/Worker binaries are rejected by protocol and configuration markers.

One diagnostic group, only 500 MB (three measured tasks):

```sh
cd /deploy
sh ./run-motivation-overlap.sh 1 500MB cold /myusb/wj/deploy /motivation-overlap diagnostic
```

Formal 500 MB experiment, ten repetitions of EACH configuration (30 tasks):

```sh
sh ./run-motivation-overlap.sh 10 500MB cold /myusb/wj/deploy /motivation-overlap formal
```

Six sizes, ten repetitions each configuration (180 tasks):

```sh
sh ./run-motivation-overlap.sh 10 sweep cold /myusb/wj/deploy /motivation-overlap formal
```

Arguments remain repetitions, size, cache, data directory, result directory,
formal/diagnostic. Size supports 60/100/200/300/400/500MB or sweep. MB is decimal.
Formal accepts 3..100 repetitions (default 10); diagnostic permits one. Three
repetitions produce nine tasks per size, or 54 tasks for the six-size sweep:
`sh ./run-motivation-overlap.sh 3 sweep cold /myusb/wj/deploy /motivation-overlap formal`.
Summary min/median/max and valid counts use exactly the samples actually run;
three repetitions must not be reported as ten. The script
always tests exactly `sync-1`, `async-1`, `async-3`. It rotates their order:
first group Sync1/Async1/Async3, next Async1/Async3/Sync1, next Async3/Sync1/Async1.
`order.csv` records the actual order. Every invocation uses a fresh subdirectory.

## What is compared

* Sync1 versus Async1 measures asynchronous execution with a single compute flow.
* Async1 versus Async3 measures scaling to three Worker compute flows, with the
  SAME TOTAL INPUT. For 500 MB, the three Workers together process 500 MB.
* Sync1 versus Async3 combines both effects. It must not be labeled solely an
  asynchronous overlap benefit or a clustering benefit.

No Adaptive aggregation is enabled. Each Worker retains two safe UTM slots and
one Host io_uring reactor, all Host threads on CPU0. Worker CPUs are
1 for single-Worker configurations and 1/2/3 for three Workers. Async3 therefore
has six total slots and three Host reactors; this resource growth is recorded
in CSV. It is not a constant-total-queue-depth CPU-only scaling experiment.

The required group owner is allocated but NEVER enqueued or run. It performs no
data computation. The owner and active members use the same Worker ELF and
Params, including 4 MiB free memory each, preserving the matched EPM reservation
fix. Group capacity is 2 or 4. Exact aligned EPM sizes come from the driver logs.
SM, CFS and the driver are unchanged by this experiment.

## Identical input, partition and correctness

Preparation is a separate enclave invocation. It generates plaintext inside EPM,
encrypts it, and sends only ciphertext records to Host PUT. One file per size is
shared by all three configurations, SHA-256 checked before/after all runs, then
deleted. At most one input of about 500.5 MB is retained at a time.

Plaintext blocks are 65,536 bytes. A record has a 64-byte header plus the exact
block length, including a partial final block. Header fields are magic, object,
global block ID, length, nonce, tag and four reserved zero bytes. Ciphertext size
is `input_bytes + ceil(input_bytes/65536)*64`.

For B blocks and N Workers, zero-based Worker w receives the half-open interval
`[floor(B*w/N), floor(B*(w+1)/N))`. Each global block is read and processed once.
No block is split at a Worker boundary; only the final file block may be short.
File offsets, record identity and the deterministic plaintext generator use
GLOBAL block IDs in every configuration. There is no future-address aggregation.

AES-128-GCM uses a 128-bit fixture key, 12-byte nonce, 16-byte tag and 32-byte AAD.
Nonce is the random per-file 64-bit object ID followed by the 32-bit block ID,
in the platform's little-endian representation. The fixture key is public test
material embedded in the enclave, never transferred through UTM. This is not
production key provisioning, a global nonce uniqueness guarantee or rollback
protection. Header identity and nonce are checked against assigned task state.

Plaintext generation uses xorshift64 starting from `0x6d6f746976617431 XOR
(block+1)`. Each Worker generates expected per-block digest values only for its
assigned range BEFORE timing. During the task it captures ciphertext once into
EPM, authenticates/decrypts there, then computes and checks its FNV-style 64-bit
digest. Unauthenticated output is not processed. Key, snapshot and plaintext
remain in private memory. Workspace is cleared on exit/error.

Each Worker XORs `digest[global_block] + global_block * 0x9e3779b97f4a7c15`
modulo 2^64. Host XORs Worker results and sums bytes/blocks, checking complete
ownership release. This preserves the SAME final digest, bytes and block count
for Sync1, Async1 and Async3. The digest is a correctness check in addition to
GCM authentication. Per-Worker ranges and results are logged.

## Execution and API mapping

`motivation/core.c` is the C Worker implementation. The wrapper uses SDK OCALL 8
and copies to/from its OWN UTM (no shared-UTM reassignment). UTM protocol size is
147,456 bytes, rounded by the allocator: edge control in the first page,
completion metadata at 4096, data at 8192, two 69,632-byte strides.

| Operation | Actual implementation |
|---|---|
| Task assignment | `mot_partition` in protocol.h; assigned range returned in CONFIG |
| SUBMIT | Backend::handle validates identity/ownership, submits the same read in both modes; Sync blocks until publication, Async returns on admission |
| Host read | UringReadEngine uses the SAME GroupIo::RawIoUring class as SQLite/FIO, registered files/buffers, READ_FIXED, submitAsync and per-CQE reapAsync |
| Ready query | Worker captures completion, checks ready and identity, fences and captures it again |
| Process any ready | core.c chooses any ready valid slot, captures once, GCM authenticates/decrypts and validates digest |
| WAIT_ANY | Backend::wait_async registers a completion callback; the existing group deferred-OCALL resume path wakes only that Worker |
| RELEASE | Verifies ID/generation, then permits refill; a slot cannot be overwritten before processing ends |
| START barrier | All Workers finish local initialization/warmup and block at START; Host prepares cache ONCE, enables every backend and releases the group |
| DONE | Per-Worker exact assigned byte/block checks and drained slots, followed by Host whole-task result aggregation |

Sync1 returns from its blocking read OCALL only after completion, then processes
and releases before requesting the next block. Each Async Worker fills its two
free slots, consumes any ready completion and refills after release. Async does
not hold the dispatcher while a Worker waits for data. The Sync configuration
has exactly one Worker; its intentionally blocking handler cannot serialize
other active Workers. No SQLite database backend is involved.

Both Sync and Async now use registered io_uring, with identical registration,
reactor and completion publication. Sync uses a blocking handler; Async may use
deferred wakeup. Sync has one outstanding request, Async at most two per Worker. The
reactor submits whatever is ready without waiting for another request. Each CQE
publishes its own slot immediately; unrelated requests do not delay publication.
Accepted operations, including partial submissions, retain storage until CQE;
short/error completions invalidate the run, never expose a partial authenticated
record. Registration/setup failure stops the run, with NO pread fallback.

The common transport was extracted without changing SQLite/FIO policy or SQE
semantics. Their existing default ring capacity remains 1024; motivation uses
capacity 64, while the application admits only 1/2/6 reads across the three
configurations. io_uring capacity is not application queue depth. There is no
artificial wait to fill a batch. Setup/registration occurs before timing.

This is a controlled overlap experiment, NOT the full FIO Sync/Async comparison:
FIO still includes its metadata paths, workload-specific sizes and descriptor
batches. A FIO 40% end-to-end gain cannot be assigned to overlap alone, nor is it
promised here. GCM, 64KiB blocks, digest computation and identical total input
are intentionally unchanged. Actual overlap and speedup must be measured.

Failure stops the run. All I/O threads and callbacks are joined before the lease,
device or UTM mappings are released. Pending deferred OCALL records are cleared.
No failed sample is replaced or silently retried.

## Cache, timing and statistics

After ALL Workers warm their assigned first block, the start barrier prepares
the complete shared file exactly once. Cold uses fdatasync, fadvise(DONTNEED),
and mincore requiring zero resident pages. Hot pre-reads the complete file.
Mounts and data location are recorded; a directory name alone does not identify
the medium. Device-internal caches are not controlled by this protocol.

All three configurations retain the v2 whole-task elapsed-time boundary:

* Start: Host rdtime immediately before releasing the common START barrier,
  after every Worker is ready and cache preparation is complete.
* End: Host rdtime after the final validated DONE and whole-task digest/byte/
  block aggregation, with all data slots drained.

This is whole-task elapsed time. It is neither the sum of Worker durations nor
the maximum of independently started durations. It includes start release,
measured OCALLs, admission, I/O, capture, authentication, computation, completion
waits and final DONE/aggregation. Creation, input preparation, key/expected-data
initialization, warmup, cache preparation, final EXIT and cleanup are excluded.
Device-tree timebase (or explicit GROUP_PMP_TIMEBASE_HZ) converts rdtime to ns.

The previous v1 used a Worker-local boundary. Its saved results can still be
summarized separately, but v1/v2/v3/v4 revisions cannot be pooled. v2 used pread;
v3 replaced that transport but still returned on admission in Sync. v4 fixes
that Sync OCALL contract. New CSV has `csv_schema=4`, `worker_enclaves`, slots
PER WORKER, total_data_slots, host_io_threads, timing_scope, common start/end
ticks, io_backend=shared-io-uring-fixed, submit_syscalls and completion_cqes,
read_ocall_semantics and execution_environment. Sync must have zero WAIT_ANY
calls and zero submit-return-before-completion; violations invalidate results.

Host data operation count is the completed data-record read count, excluding
warmup/cache preparation. It should equal the global block count in every
configuration, e.g. 7,630 operations for 500,000,000 bytes. No merging is used.
Submit/wait and observed cohort-wide peaks are separately recorded; maxima are
tracked across the actual live set, not summed from unrelated per-Worker peaks.
Submission syscalls count the actual submitAsync enter calls, not completion
waits or eventfd writes; completed CQEs should equal the data block count. Peak
active reads here means admitted reads not yet observed complete, including the
bounded reactor queue; it is NOT measured physical device queue depth.

`summary.csv` and `figure-1c-data.csv` contain median/min/max, valid counts,
same-result checks, complete group/order checks and speedups. `async` fields
mean Async1; `async3` fields mean Async3. Ts/Ta is Sync1/Async1; XX=(Ts/Ta-1)*100,
YY=(1-Ta/Ts)*100. Async3/Sync1 and Async3/Async1 speedups/time reductions are
reported separately. v4 formal eligibility requires at least three complete
three-configuration groups; older schemas retain their ten-group rule.
Native runs and diagnostics remain ineligible. Actual valid counts distinguish
three from ten repetitions. Negative differences are preserved.

## Diagnostic traces and plotting

Diagnostic runs are separate from formal samples. Their combined trace includes
Worker ID, global block ID, slot/generation, admission/read/publish timestamps,
Worker submit return and processing interval, and release. The analyzer checks
whole-file block coverage and Worker partition ownership. It reports wall-time
I/O/compute intersection and the separately labeled sum of Worker overlap time;
simultaneous compute must not be mistaken for extra elapsed wall time.

v3/v4 I/O intervals run from SQE preparation to Host CQE observation, including
submission and scheduling; they are NOT physical disk busy intervals. Thus a
trace intersection proves Host read-service/compute overlap, not necessarily
device/compute overlap. Multiple in-flight reads or early return alone do not prove
useful I/O/compute overlap or a speedup. Inspect the trace and formal total times.

Summaries run automatically if Python3 exists on the board. For figures on an
analysis machine with matplotlib installed:

```sh
python3 motivation/summarize.py /path/to/result-directory --plot
```

This produces three-series Fig.1(c) PNG/PDF (median bars, measured min/max error
bars) and per-Worker diagnostic timelines. CSV/text summaries use only Python's
standard library. Environment, artifact/source hashes, frequency/isolation logs,
input hashes, order and complete run logs are retained beside raw samples.

## Verification and timeout

```sh
sh tests/run-motivation-tests.sh
```

Native tests use the actual C core and GCM with real temporary ciphertext files.
An explicitly injected reference engine exists ONLY in tests; production cannot
select it. The same tests also run through actual shared registered io_uring when
the local kernel permits it; inability is reported as SKIP, not a passed test.
Three child processes provide separate private C workspaces and process disjoint
ranges; their combined digest, bytes, blocks and operations must equal one
Worker. Additional tests cover EPM capacity2/4 with the actual driver reservation
routine under native allocation/lock stubs, shared-start admission, asynchronous
wait callbacks, tails, tampering, stale generations and error cleanup. Wrapper
fixtures cover 180 formal calls and the requested 500MB-only diagnostic triplet.
Fixture output is not measurement evidence.

The default no-event timeout is 600 seconds (MOT_EVENT_TIMEOUT_SEC), total budget
3600 seconds. RV8's separate 600-second event timeout is unchanged. Board lease,
PMP behavior, cross-linking and actual performance still require the user's
cross-build/deployment and board execution. No speedup is promised in advance.
