# Group PMP Master-Worker Test

For the standalone repository build, SDK/Runtime path selection and board
deployment, see [the repository guide](../README.MD). The default rebuild now
compiles from sources without an existing Buildroot examples build directory.

Standalone security experiments (plaintext marker scanning, access/revocation
probes and test-only GCM/ChaCha20-Poly1305 integrity) are described in
[security/README.md](security/README.md). They do not change the performance
workers' AES-128-ECB cipher or enable AEAD in performance benchmarks.

Current SQLite I/O changes and comparison semantics are documented in
[SQLite I/O policy 24](SQLITE_IO_POLICY_24.md): independent logical batching,
stable depth trials, ready-only vector joining and per-buffer tail completion.

All data-size and throughput units in this example are decimal: `1 MB =
1,000,000 bytes`, and `MB/s = bytes / 1,000,000 / seconds`. Page-table and
PMP ranges are reported separately as exact aligned byte counts where needed.

This example validates the current VisionFive2 group-PMP prototype. The default
production configuration is `GROUP_MODE_3W_1HM`: Linux CPU0/SM hart1 is the
housekeeping lane shared by HOST and the master enclave, while Linux CPU1-3/SM
hart2-4 are leased worker lanes. Each worker lane can queue multiple enclave
members, but only one member per lane is active at a time. The former
four-userspace-thread topology is retained only as
`GROUP_MODE_SATURATION_TEST`.

YXSTM uses one 67.108864 MB hardware-aligned backing allocation. Physical
slice 0 and the unused tails of slices 1-3 are reserves; each worker lane has
12 MB of logical payload inside a 16 MiB page-aligned physical backing. Before
group activation, each lane is split into one page-aligned slot per registered
worker enclave. The master maps all three complete lane backings as NX, while
each worker maps only its owned slot as NX. Protocol metadata remains in SM and
does not reduce slot payload capacity.
The SM page-table audit requires these exact views and rejects aliases,
out-of-range leaves, executable YXSTM mappings, and another member's slot.

Each slot follows `FREE -> DISPATCHING -> READY -> COMPUTING -> DONE ->
AGGREGATING -> FREE`. The master may name any free lane/slot through the task
request; publishing data changes only that owner's slot to `READY`. Blocked
workers are woken from slot metadata. READY/COMPUTING state controls CFS
eligibility, then vruntime and weight choose among eligible members; numeric
slot order is never a scheduling priority. YXSTM hardware access is an exact two-entry TOR
aperture: master dispatch is RW, worker compute is RW, and master aggregate is
R. Both R and RW CSR images are precomputed for every frozen slot.

The SM group scheduler owns MTIP. A worker lane with multiple runnable members
uses CFS-lite: actual `mtime` execution is converted to weighted `vruntime`, and
the runnable member with the smallest `vruntime` is selected. The enclave-aware
defaults are a 60 ms target latency, 12 ms minimum granularity, and 3 ms wakeup
granularity. A lane with only one runnable member leaves MTIP disabled.
The asynchronous switch path saves
all trap-frame GPRs, `mepc/mstatus`, S-mode CSRs and RV64 F/D state. Vector
state is not implemented, so group activation and binding explicitly reject a
Vector-capable configuration. Supervisor interrupts are not scheduler triggers;
worker CPUs are isolated from Linux IRQ and workqueue service for the lease.
Each dynamic CFS slice is converted to hardware ticks from the OpenSBI
timer-device frequency instead of assuming a fixed JH7110 timebase. `priority`
maps to Linux-style CFS weights; the legacy `quantum_ticks` ABI field is accepted
but no longer determines scheduling. The production lease has no
periodic Linux heartbeat. A worker holding a YXSTM grant is converted into
SM-owned suspended metadata at a timer boundary; the hardware YXSTM PMP is
revoked before a peer is installed. The grant stays bound to the original
eid/generation and is restored only after all authority epochs are revalidated.
When HOST completes an OCALL or otherwise wakes a blocked peer, SM marks a
CFS reschedule request and sends the target worker hart a scheduler IPI. This
reprograms the wakeup deadline even when the lane previously had only one
runnable member and therefore no active timer.
CPU0 enters the master through `group_run_master` and
blocks for worker barriers through the driver `group_wait_event` waitqueue.

Linux TTY output and SM `sbi_printf` output use independent console paths.
CPU0 remains the housekeeping CPU for Linux output, IRQ handling, unbound
workqueues and RCU callbacks. Worker harts are explicitly leased only after the
boot isolation configuration has been verified.
The production driver hot-unplugs Linux CPU1-3, waits for SBI HSM `STOPPED`,
then CPU0 remotely starts each hart through a lease-only secondary boot mode
that bypasses Linux `smp_callin()`. Lease release stops each hart again and
uses `add_cpu()` for the standard Linux warm-entry path. The old 100 ms
heartbeat and Linux-online kthread runner remain only in explicit test
fallback mode.

Scheduler results are retained in a bounded per-hart event queue and carry a
monotonic event sequence plus scheduler epoch. If the queue fills, the oldest
event is replaced and the cumulative `queue_overflows` counter is returned to
the host, so loss is detectable. The driver event queue maintains an additional
cumulative overflow count; the CPU0 production loop treats either counter as a
failed event stream. Host pause/cancel requests use
`groupControlEnclave`: a running member reports PENDING and applies the request
at the next cooperative or timer boundary. OCALL records have unique IDs and
deadlines; resume, cancel, timeout, member destroy and host abandonment all
resolve the record without leaving the member permanently BLOCKED.
CPU0 dispatches both master and worker OCALLs, including worker OCALLs received
after master exit, and resumes the exact eid with the event's `ocall_id`.
Dispatch failure abandons the record; timeout events are reported as
`GroupOcallTimeout` and are never redispatched.

Group and YXSTM ABI structures start with `struct keystone_abi_header`. The
current ABI requires `version == KEYSTONE_ABI_VERSION`, exact `struct_size`,
required feature bits, and `reserved == 0`. Stale structures are rejected rather
than accepted with compatibility shims. All fields are word-sized `uintptr_t`
and aligned to `sizeof(uintptr_t)`; the VisionFive2 deployment is 64-bit, and
32-bit builds must compile SM, driver, SDK, runtime and tests from the same
headers. `group_run_hart` events are stored in SM using internal eids and
generations, then translated by the driver to host-visible eids for `EXIT`,
`OCALL`, `FAULT`, `PAUSED`, `CANCELLED`, `OCALL_ABANDONED`, `HEARTBEAT`, and
`WATCHDOG`. HOST-facing calls return only standard SBI errors; Keystone detail
codes travel through `a1` and ABI `status/detail`, then map to Linux errno and
explicit SDK group errors.

YXSTM is a directly mapped, group-protected master-worker channel divided into
four slices:

- hart1/cpu0 is the master and can map slices 0-3;
- hart2/cpu1 is worker1 and can map slice1;
- hart3/cpu2 is worker2 and can map slice2;
- hart4/cpu3 is worker3 and can map slice3.

The master role is unique, but worker slices belong to lanes rather than to the
first worker eid. Additional worker members on a lane retain
`GROUP_ROLE_WORKER`, map only that lane's slice, and share the lane runqueue.
Only `lane.active_eid` can acquire the slice. A lane can switch to another eid
only at an IDLE task boundary after all grants have been revoked and the slice
has been scrubbed.

The default functional-test layout uses one bank of four 1.048576 MB slices. P10 and
the task-scheduler regression use two bank-major banks, each containing four
8.388608 MB slices, for a 67.108864 MB YXSTM region. The slice-aware access policy is:

- dispatch: master RW on worker slices, worker R on its own slice;
- aggregation: worker RW on its own slice, master R on worker slices;
- YXSTM is never executable;
- ordinary schedule-out, exit and fault revoke acquired YXSTM permissions;
- periodic host service saves the current grant as suspended metadata, revokes
  its hardware PMP access, and restores it only after eid, group generation,
  phase epoch and permission epoch validation succeeds.

The SM owns one protocol state per group and enforces
`IDLE -> DISPATCH -> COMPUTE -> AGGREGATE -> IDLE`. Only the master advances
the phase. Every acquire/release carries the current `phase_epoch`; channel
headers carry the group id, group generation, policy version, phase epoch,
session epoch, sequence, version and bounded payload length. Membership joins,
revokes, faults and phase transitions advance the SM-owned session epoch and
recompute the group session hash, so stale channel headers from an old member or
old phase are rejected before PMP permissions are opened.

Attestation reports include the group id, group generation, role, configured
hart mask, bound hart, allowed YXSTM slice mask, membership epoch, phase epoch,
session epoch, runtime measurement, security policy version and group session
hash. The enclave-report signature covers these fields together with the
original enclave measurement and user data. Group membership attestation is
therefore a snapshot: a verifier can bind a member to the current generation,
role/slice policy and session epoch, while later member removal or fault causes
a rekey and invalidates older shared-data headers.

Every phase/permission epoch change uses a synchronous per-hart coherence
transaction. The SM sends a generation-tagged IPI to the group's active-hart
snapshot, revokes YXSTM PMP access, executes memory and instruction fences plus
`sfence.vma`, and waits for sequence/epoch ACKs before committing the new
phase. Offline, timed-out, stale, duplicate, and concurrently scheduled-out
harts fail closed without advancing the phase. Successful logs report equal
`target` and `acked` masks before the subsequent phase log.

On JH7110, `PMP_MAX_N_REGION=24` is the software descriptor limit; each hart
still has eight hardware entries. The fixed layout is SM=0, group EPM=1-2,
YXSTM TOR=3-4, SEC TOR=5-6, and OS/UTM=7. Finalization performs a PMP
budget preflight, and the first schedule-in on each hart dumps the installed
PMP CSRs.

The runner covers the 3W_1HM HOST/master state machine, a two-workers-per-lane
production queue, the separate four-hart saturation mode, stale and repeated
acquire rejection, wrong-mask release rejection, phase permission denial,
access without acquire, private EPM isolation, two-group resource isolation,
capacity mismatch/overflow, four-hart and eight-member scheduling, scheduler
priority/weight parameters, and a two-pending-OCALL lifecycle that resumes one
member, abandons the other, and proves the same-lane peer can continue.
Dedicated fault fixtures remain built for later protocol-controlled fault
orchestration.

Group setup uses the explicit lifecycle `set_count -> create -> configure ->
member create/finalize -> activate -> destroy`. The runner verifies that an
ACTIVE group rejects duplicate create and hart-layout changes, and that a
recreated group id receives a new generation. Explicit destroy is terminal:
after confirming that no group hart or coherence transaction is active, the SM
revokes suspended grants, clears control/OCALL state, removes residual runqueue
members and makes every member destroyable before the driver releases memory.

The page-table policy uses the measured-runtime trust model. The SM walks the
complete tree at root registration and every scheduler/exit boundary; Eyrie
also requests a full SM audit after each dynamic map, permission change, or
unmap and rolls back a rejected leaf update. The walker rejects mappings
outside the member slice/allowed regions, cross-group and ambiguous regions,
executable non-private memory, invalid superpages, cycles, overflow, VA
overlap, sensitive shared-region aliases, and any U-mode alias of a page-table
page. This model protects members from
an untrusted U-mode eapp but intentionally keeps the measured S-mode runtime in
the TCB; SM-mediated page-table-page ownership is a separate stronger model.

Security boundary notes: PMP protects CPU memory accesses made by harts running
host or enclave code. It does not mitigate cache side channels, timing channels,
or a malicious measured runtime that intentionally abuses its TCB privileges.
Same-group members are isolated by page-table view and YXSTM phase permissions,
but protocol-level confidentiality between authorized master/worker roles is not
claimed. VisionFive2/JH7110 has no IOPMP in this prototype, so PMP must not be
described as blocking device DMA; DMA-capable devices require separate platform
isolation or must be kept out of the trusted data path. Fault, destroy and final
YXSTM release paths scrub the affected slice set, and master fault/group release
scrub all slices.

The old region-wide `yxstm_acquire/release/query_slice` ABI and writer/reader
block semantics are intentionally not built or deployed.

Run from the deployed directory:

```sh
./run-group-pmp-test.sh
```

`rebuild-and-test.sh` writes `SHA256SUMS` into the deploy directory so a tested
deployment can be tied to exact runner, eapp, runtime and loader binaries.

# Native crypto matrix

`run-aes-native-baseline.sh` now drives the unified
`crypto-native-baseline` executable. The standard matrix runs on Linux CPU1
and measures 10, 50, 100, 200 and 500 MB, with one untimed warm-up and five
recorded rounds for every operation:

- project `aes_core.c`: AES-128-ECB encrypt and decrypt;
- `RSA/rsa2048_bench.c`: streaming SHA-256 plus RSA-2048 PSS sign or verify;
- project SM3 plus the SM2 adapter: streaming SM3 plus SM2 sign or verify;
- project `SM/SM3/sm3.c`: SM3 hashing;
- project `SM/SM4/sm4.c`: SM4-ECB encrypt and decrypt.

RSA and SM2 cannot directly sign hundreds of MB. Their `hash-sign` and
`hash-verify` rows therefore time a full streaming digest of the requested
logical data followed by one public-key operation. `primitive_cycles`
separately records only the sign or verify portion. Key generation, input
generation, warm-up and verification are outside the measured interval.

The benchmark uses a fixed 1 MB aligned streaming buffer, so a 500 MB row
does not allocate several 500 MB working copies. All raw rounds are written
to one CSV after each measured operation has completed:

```sh
./run-aes-native-baseline.sh
NATIVE_CRYPTO_CSV=/tmp/crypto.csv ./run-aes-native-baseline.sh
```

The default output is `native-crypto-results.csv`. Useful overrides are
`NATIVE_CRYPTO_CPU`, `NATIVE_CRYPTO_SIZES_MB`,
`NATIVE_CRYPTO_ALGORITHMS`, `NATIVE_CRYPTO_SAMPLES` and
`NATIVE_CRYPTO_WARMUP`. The script requires a writable CPU governor unless
`NATIVE_CRYPTO_ALLOW_UNFIXED_GOVERNOR=1` is explicitly selected.

The original `aes-native-baseline` executable remains available for the
software/AF_ALG/OpenSSL AES implementation diagnostic used by
`run-aes-enclave-vs-native.sh`.

# Retired P10 pure-AES performance mode

This historical pure-AES mode is disabled by default, is not deployed, and is
excluded from regression and acceptance runs. It may be rebuilt only for
diagnosis:

```sh
GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS=ON ./rebuild-and-test.sh
cd deploy
GROUP_PMP_ALLOW_LEGACY_PURE_AES=1 ./run-p10-performance.sh
```

The remaining text in this section documents the retired implementation.

```sh
GROUP_PMP_ALLOW_LEGACY_PURE_AES=1 ./run-p10-performance.sh
```

This mode measures host `memcpy`, enclave `copy_from_shared()` over regular
shared UTM, and master-worker YXSTM zero-copy AES-128-ECB encrypt/decrypt with
1, 2 and 3 workers.

The AES benchmark keeps the current SM phase policy intact. In `DISPATCH`, the
master acquires worker slices `RW` and writes input directly into mapped YXSTM
VA. In `COMPUTE`, each worker acquires its own slice `RW`, performs AES in
place on the mapped YXSTM payload VA, releases the grant, and only then
publishes `COMPUTE_DONE`. In `AGGREGATE`, the master acquires all active worker
slices `R` once and reads their completed metadata and digest.

P10 allocates a 67.108864 MB YXSTM region as two bank-major sets of four equal 8.388608 MB
slices. The host API configures this explicitly with
`Params::setYXSTMBankedLayout(total_size, bank_count, bank_slice_size)`;
invalid layouts are rejected before enclave creation. The loader uses aligned
2,097,152-byte leaves for the large UTM and YXSTM views so the 67.108864 MB configuration
remains within the SM page-table audit
limits. The 24 MB input or decrypt ciphertext is generated in the master UTM
before the measured enclave pipeline starts. Host-side AES also generates a
small per-segment digest oracle at UTM offset 28 MB; P10 therefore keeps the
master UTM at 32 MB instead of requiring another 24 MB contiguous buffer.

Protocol polling uses one SM-owned, read-only mailbox page per member. The SM
publishes protocol snapshots with a sequence lock, so the hot polling path no
longer issues `YXSTM_QUERY_PROTOCOL` SBI calls. P10 also enables quiet protocol
mode: successful per-phase SM messages and worker serial output are suppressed,
while errors remain visible. Each phase has a 30-second VisionFive2 timebase
watchdog, so a protocol deadlock returns a stage-specific eapp status instead
of leaving the board in an effectively unbounded poll.
The deadline applies only to workers selected in that round's
`active_worker_mask`. Resident workers excluded from a 1- or 2-worker P10 round
remain idle until a later dispatch instead of consuming another worker's
deadline.

One protocol round uses a single stable `sequence` from `DISPATCH` through
`COMPUTE`, `AGGREGATE`, and the return to `IDLE`. Only the next
`IDLE -> DISPATCH` transition allocates a newer sequence. The SM rejects a
non-dispatch transition whose requested sequence does not match the active
round, preventing stale phase requests from advancing the state machine.

Successful SM scheduler startup traces are disabled by default. Direct
OpenSBI console writes and the Linux serial tty otherwise compete for the same
UART while the four harts start, which can fragment already-flushed host lines
around `bound/enqueued` and add synchronous console overhead. Error and final
performance output remain enabled. Firmware debugging can restore the startup
trace with `KEYSTONE_GROUP_STARTUP_TRACE=1`; this switch changes logging only,
not timer cadence, scheduling, PMP state, or host-service behavior.

In the default performance build, the active worker keeps one YXSTM grant and
processes its complete 12 MB payload continuously. Workers sharing a lane use
task-boundary streaming: non-owner tickets enter `BLOCKED` without a grant and
the owner wakes exactly the next ticket only after AES, OCALL and commit are
complete. Same-lane timer preemption exact-saves the enclave context and
atomically replaces the two-entry YXSTM TOR aperture before installing a
runnable peer. A real
OCALL returns the saved runner to Linux; resume
validates group/member epochs before re-entering that worker. The
runtime arms scheduler preemption only after Eyrie page-table validation and
boot initialization are complete. The
former 256 KiB release/yield/reacquire path is debug-only and can be enabled
explicitly while rebuilding:

```sh
GROUP_PMP_AES_COOPERATIVE_SERVICE=ON ./rebuild-and-test.sh
```

Formal P10 runs report `cooperative_service=0`.

Each final P10 line reports these non-additive measurements separately:

- `master_dispatch_cycles`: only master input copies into mapped YXSTM.
- `worker_compute_wall_cycles`: elapsed master-hart time from compute phase
  launch until all active workers publish their results.
- `master_aggregate_cycles`: only the small worker digest/counter aggregation.
- `protocol_cycles`: phase, acquire/release, acknowledgement and mailbox wait
  protocol overhead measured by the master.
- `pipeline_e2e_cycles`: pipeline execution excluding full AES verification.
- `[P10][sm] host_service`: completed scheduler-to-Linux service boundaries;
  total cycles include the Linux/userspace interval until the same eid resumes.
- `[P10][sm] grant_suspend_restore`: completed YXSTM PMP suspend/restore pairs;
  cycles cover only the SM revoke and reinstall work.
- `[P10][sm] ocall_e2e`: completed worker OCALL round trips, measured on the
  same worker hart from OCALL registration until that eid is scheduled again.
- `[P10][sm] ocall_handler`: only SM registration and terminal completion work.
- `[P10][sm] ocall_wait`: BLOCKED wall time in shared `mtime` ticks.
- `[P10][sm] context_components`: GPR, S-mode CSR, FPU, PMP,
  platform-switch and scheduler-lock/bookkeeping costs.
- `[P10][sm] lane_wait`: SM ticket blocks, wakes and total wait `mtime` ticks.
- `[P10][sm] cfs_lite`: picks, successful preemptions, actual runtime,
  weighted `vruntime`, scheduled slices, and minimum-granularity hits.
- `[P10][sm] heartbeat`: compatibility heartbeat ACK round trips; production
  exclusive-lease runs must report zero.
- `[P10][sm] timer_trap`: complete scheduler-owned M-mode timer handlers.
- `[P10][sm] context_switch`: actual enclave-to-enclave state/PMP switches.

Mixed scaling runs execute every worker count at least five times in a
randomized order. CSV and summary output report median and P95 for total
throughput, enclave AES MB/s, effective YXSTM payload bandwidth, scheduler
efficiency, lane utilization, and the wall-time categories below:

- `master_*_wall_seconds`: direct `rdtime` measurements for the complete
  master interval, dispatch, compute wait, and aggregate.
- `aes_oncpu_wall_seconds`: SM-accounted worker AES on-CPU time.
- `ocall_wall_seconds`: worker-observed OCALL round-trip wall time.
- `ready_wait_wall_seconds`: worker time blocked waiting for a READY slot.
- `switch_wall_seconds`: exact SM context-switch `mtime` duration.
- `protocol_wall_seconds`: summed master and worker command wall time.
- `pmp_wall_seconds_estimated` and
  `scheduler_wall_seconds_estimated`: cycle counters converted with the
  run's measured AES cycle/mtime ratio. These are estimates; the original
  cycle buckets remain in the CSV.

`yxstm_effective_payload_mb_per_sec` counts logical master writes, worker
in-place reads and writes, and the bytes actually sampled by aggregate.
`yxstm_aggregate_sample_mb_per_sec` is deliberately labeled as a sampled
metric because aggregate validates four 16-byte payload blocks per batch
instead of copying the full ciphertext.

All AES output bytes contribute to a host-precomputed per-segment digest that
the master validates, together with segment metadata, after the timed pipeline
interval. This removes the former serial AES recomputation from the master.
`direct_va=1` means every worker-reported payload VA matches its expected
direct YXSTM mapping.

# Retired P10 pure-AES enclave scaling mode

This mode is also excluded from the default build and deployment. Its results
must not be mixed with the new mixed-workload scaling series.

An explicit diagnostic build and run requires:

```sh
GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS=ON ./rebuild-and-test.sh
cd deploy
GROUP_PMP_ALLOW_LEGACY_PURE_AES=1 ./run-p10-enclave-scaling.sh
```

This scheduler-focused AES-128-ECB test keeps one control master enclave on
CPU0 and creates 1 through 10 worker enclaves. Workers are assigned round-robin
to CPU1/CPU2/CPU3, producing lane depths `1/0/0`, `1/1/0`, `1/1/1`, `2/1/1`,
`2/2/1`, and so on. Every worker uses the same default CFS-lite weight;
there are no task weights, locality hints, DAGs, or Spark-style policy.

The default `all` run contains three profiles:

- `fixed-total`: the same total 24 MB is divided between active lanes and
  their queued enclaves. This measures strong scaling and context-switch cost.
- `fixed-per-enclave`: every enclave encrypts 8 MB, so total work is
  `8 MB * worker_count`. This measures aggregate throughput while 4 through
  10 workers time-share three physical worker harts.
- `heterogeneous`: ten workers receive the same multiset of three 16 MB and
  seven 4 MB jobs. The naive round-robin placement has lane loads
  `52/12/12 MB`; the balanced reference has `28/24/24 MB`. The reference is
  only a comparison baseline for later scheduling policy, not an enabled
  Spark-style scheduler.

Workers perform AES in private EPM and use their own UTM only for a small
configuration/result record. They do not acquire YXSTM and do not issue an
explicit yield inside the AES loop. For a lane containing multiple enclaves,
the host observer requires every peer to publish `STARTED` before the first one
publishes `COMPLETED`. Therefore `timer_preemption_proof=1` demonstrates actual
timer-driven interleaving rather than sequential run-to-completion.

Each `[P10][scale]` line reports throughput, host and compute-rate speedups,
lane depths, worker cycles, SM context switches, host service, peak running
workers, lane owner changes, scrub counts, preemption evidence and elapsed
cycles-per-byte fairness. `[P10][scale-trend]` emits the complete 1-through-10
throughput, duration and speedup series. A NIST AES-128 known-answer check is
completed by every worker outside its measured loop. Performance values are
reported rather than subjected to hard speedup thresholds because CPU
frequency, thermal state and board services affect them.

Run only one profile while diagnosing a failure:

```sh
GROUP_PMP_SCALE_PROFILE=fixed-total ./run-p10-enclave-scaling.sh
GROUP_PMP_SCALE_PROFILE=fixed-per-enclave ./run-p10-enclave-scaling.sh
GROUP_PMP_SCALE_PROFILE=heterogeneous ./run-p10-enclave-scaling.sh
```

The optional retired `task` experiment enables secure double buffering. Each bank has independent
phase, phase epoch, task epoch, sequence, worker barriers and commit epoch.
After the `COMPUTE` barrier, bank 0 enters `AGGREGATE` so its workers can
transform data in place while the master dispatches the next barrier batch to
bank 1. Bank 1 remains in `DISPATCH` until the first batch commits and its three
prefetched executor tasks are atomically activated. Each hart still owns at
most one dynamic YXSTM TOR aperture, and a bank transition fails if that bank has
an installed or suspended grant. An explicitly enabled experiment executes 100
hardware task batches per worker lane (`300` task descriptors total); change
the bounded build-time value with `GROUP_PMP_TASK_BATCHES=<1..100>` while
rebuilding.

# P11 two-level task scheduler (disabled baseline)

The Spark-style scheduler is no longer part of the default build or any default
regression path. Its source remains only as an experimental comparison. To
build and run it explicitly:

```sh
GROUP_PMP_ENABLE_SPARK_SCHEDULER=ON ./rebuild-and-test.sh
GROUP_PMP_ENABLE_SPARK_SCHEDULER=1 \
./run-p11-task-scheduler.sh
```

The master/runtime owns job and stage dependencies, central FIFO, weighted
FAIR and job round-robin policy,
barrier launch, locality, backpressure, cancellation, retries and idempotent
commit. The SM sees only lane identity, bank phase, epochs and PMP grants. Three
long-lived worker enclaves act as executor slots; lightweight task descriptors
are written to bank-major YXSTM channels without creating an enclave per task.
FIFO preserves submit order. FAIR compares normalized per-job service against
bounded job weights, and locality prefers a lane whose resident bank already
matches the task input without overriding the task's hard worker mask.

# P9 validation modes

`group-pmp-test-runner` supports explicit modes through
`GROUP_PMP_TEST_MODE`:

- `smoke`: protocol, isolation, scheduler, OCALL and capacity regression;
  Spark-style task scheduling is not included.
- `stress`: lifecycle leak checking, repeated 4-hart/8-enclave scheduling and
  two-group concurrent execution.
- `fault`: master/worker fatal-fault cleanup and optional SM IPI injection.
- `perf` and `scale`: retired pure-AES diagnostics. The runner rejects both in
  the default build; they exist only with
  `GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS=ON`.
- `mixed-scale`: the production performance baseline. It runs one master and
  1..N equal-weight worker enclaves under CFS-lite, assigns workers to the
  three lanes round-robin, and processes exactly 12 MB per worker through
  direct YXSTM AES. Each 12 MB logical lane is split into one page-aligned slot
  per resident enclave inside a 16 MiB physical backing; the complete logical
  slot capacity is payload and ordered task metadata remains in SM. Master
  dispatch, worker compute, and master aggregate are
  driven independently by slot state, so completion order need not match slot
  order. Workers without READY data and workers waiting for aggregate are
  BLOCKED and excluded from CFS vruntime competition. CPU0 sleeps on the
  driver event waitqueue when no slot made progress. Creation, finalize, first
  launch, warmup and full payload verification are outside the SM
  `BEGIN/FREEZE` measurement window. The script defaults to 12 workers and
  accepts `N=1..64`. The maximum case uses lane depths 22/21/21; slot count
  and page-aligned slot size are derived from each lane's resident members.
  Each worker count runs at least five times in randomized order. The
  report contains elapsed-time median/P95 and throughput median/P05/P95. SM
  integer counters are aggregated independently using their per-field median.
  CSV output also
  contains per-member `sum_exec_runtime`, exact AES on-CPU time, lane waits,
  CFS runtime/vruntime/slice counters, OCALL handler/wait time, and separate PMP
  buckets for grant suspend, EPM revoke/install, YXSTM restore, fences,
  validation, and lock wait.
- `aes-baseline`: a fair native-versus-enclave AES-128-ECB comparison. Both
  sides compile the same `eapp/aes_core.c` with `-O3`, the configured common
  `-march/-mabi`, identical 8 MB input, two warmups, page-aligned buffers and
  the same timed AES call. Enclave seconds come from its own `rdtime` and the
  device-tree timebase, not a native-cycle-frequency estimate.
- `aes-diagnostic`: runs `aes-baseline`, then a one-worker direct YXSTM
  diagnostic. It reports EPM and YXSTM sequential read/write, streaming AES,
  cache-hot 16-byte-block AES, digest and page-stride latency separately. The
  final EPM/YXSTM ratio line separates the instruction-path ratio from the
  streaming-memory ratio. The page-stride value is a TLB
  pressure proxy because JH7110 does not expose a configured TLB-miss event
  counter here. It also prints SM-audited PTE flags, leaf sizes, NX/alias/
  linear-map status, alignment and confirms in-place access with zero hidden
  copy. It rejects a diagnostic run unless SM observes at least one 2 MiB
  Sv39 YXSTM leaf. Run it with `run-aes-enclave-vs-native.sh`; that script
  snapshots the CPU1-3 cpufreq policies, locks them before lease, keeps them
  fixed through the measurement, and restores the original governor and
  limits on every normal, failed, or interrupted exit.
- `task`: optional retired two-level scheduler experiment, present only in a
  build made with `GROUP_PMP_ENABLE_SPARK_SCHEDULER=ON`.
- `acceptance`: a fixed 16-member regression within the 65-member limit, with
  five enclaves per worker lane,
  OCALL/fault/cancel/missing-worker and clean lane rotation; it does not run
  the Spark-style scheduler.
- `all`: all non-performance regression modes.
- `host-access`: recoverable kernel-side YXSTM read/write denial probe, kept
  separate from `all` because it validates the hardware PMP path.

Run the mixed baseline after deployment with:

```sh
./run-p10-mixed-scaling.sh
```

Pass the repetition count positionally, for example
`./run-p10-mixed-scaling.sh sqlite-bench 15 5` or
`./run-p10-mixed-scaling.sh 15 7`. The existing
`GROUP_PMP_MIXED_REPETITIONS=7` environment form remains available, and
`GROUP_PMP_MIXED_RANDOM_SEED=<decimal>` for a reproducible randomized order.
The runner enforces a minimum of five repetitions.

The normal mixed test adds no artificial host-service sleep. Its single OCALL
per 12 MB task measures the actual event, HOST handling and resume path. The
separate OCALL-stress script retains eight OCALLs per worker.

Run the SQLite/YXSTM mixed benchmark with:

```sh
./run-p10-mixed-scaling.sh sqlite-bench 15
```

Select the storage path explicitly with the second positional argument:

```sh
# Current optimized path: SQLite metadata index plus external ciphertext
# extents, central sorting/coalescing and io_uring batch submission.
GROUP_PMP_MIXED_CSV=/mixed-sqlite-extent.csv \
./run-p10-mixed-scaling.sh sqlite-bench extent 15 5 512MB

# Synchronous baseline: one request at a time, without async I/O or extents.
./run-p10-mixed-scaling.sh sqlite-bench sync-no-extent 15 5 512MB

# Async baseline: request rings, double buffering and io_uring, but no merge.
./run-p10-mixed-scaling.sh sqlite-bench async-no-extent  15 5 512MB

# Primary paper comparison: synchronous unoptimized I/O followed by the
# complete adaptive I/O stack. `both` does not run async-no-extent.
./run-p10-mixed-scaling.sh sqlite-bench both 15 5 512MB

# Run sync-no-extent, async-no-extent and adaptive-extent. The adaptive CSV
# records cross-mode speedups against both baselines.
./run-p10-mixed-scaling.sh sqlite-bench all 15 5 512MB
```

The legacy syntax without a mode remains valid and defaults to `extent`
(`adaptive-extent`). Aggregate and Gantt CSV files record the selected mode
explicitly.

SQLite runs also create an I/O-range CSV. For a single mode its default path is
`/sqlite-io-ranges-<mode>-<size>MB-1-<max-workers>.csv` and can be overridden
with `GROUP_PMP_SQLITE_IO_RANGE_CSV`. In `both` mode the four default outputs
are:

```text
/sqlite-bench-sync-no-extent-<size>MB-1-<max-workers>.csv
/sqlite-bench-adaptive-extent-<size>MB-1-<max-workers>.csv
/sqlite-io-ranges-sync-no-extent-<size>MB-1-<max-workers>.csv
/sqlite-io-ranges-adaptive-extent-<size>MB-1-<max-workers>.csv
```

`all` additionally runs the `async-no-extent` diagnostic baseline and creates
its aggregate/range files. That mode uses fixed-depth discrete I/O and is not
part of the default `both` comparison.

The optimized mode is an **adaptive I/O optimization stack**, not merely an
extent merger: it combines adaptive depth, workload-aware clustering,
registered files/buffers, batched completion, group commit, and two-buffer
overlap. Publication runs require at least 512 MB and five samples; a smaller
one-sample run is explicitly preview-only.

The I/O range collector stays in memory during each measured window. It does
not write one CSV row per physical request. After all randomized repetitions
finish, it emits one compact row per `workload x worker_count`, so a 1..15 run
has 120 rows per mode. Each row includes the performance median, speedup versus
one worker, median physical/member request counts, physical/useful/gap bytes,
the covered start/end range, and minimum/maximum request sizes. The same compact
I/O fields are also included in the main SQLite performance CSV. This keeps
4 KB random-I/O tests exact without producing multi-gigabyte trace files or
adding CSV writes to the measured interval.

Request-level Gantt tracing is opt-in so timestamp collection does not alter
normal performance runs. Set a distinct trace path when a timeline is needed:

```sh
GROUP_PMP_MIXED_CSV=/mixed-sqlite.csv \
GROUP_PMP_SQLITE_GANTT_CSV=/mixed-sqlite-gantt.csv \
./run-p10-mixed-scaling.sh sqlite-bench 15 1 512MB
```

The trace is buffered in memory only during the measured window and appended
after each case finishes. It records case/perf boundaries, OCALL handler and
BLOCKED points, request submit/queue/service, SQLite metadata lookup/commit,
storage I/O, request completion, wakeup/resume, WORKERS_READY and enclave exit.
`completion_id` joins a worker's blocked interval to its Host I/O completion;
`request_id`, `task_id`, `sequence`, file range, worker, lane, hart and EID
support exact filtering and Gantt construction. Increase the bounded buffer
with `GROUP_PMP_SQLITE_GANTT_MAX_EVENTS` if the runner reports dropped critical
events. High-frequency request events are sampled deterministically when a
case would exceed the bounded trace, while OCALL, blocked, completion-ready,
wakeup, resume, and case-boundary events remain complete.

It executes `fillseq`, `fillseqbatch`, `fillrandom`, `fillrandombatch`,
`overwrite`, `readseq`, `readrandom`, and `readrand100k` for worker counts
1 through 15. SQLite mode accepts one repetition for a quick preview or 5
through 20 randomized repetitions for statistics; raw records are never
written to CSV. `speedup_vs_one` uses the current mode's worker-1 result.
`speedup_vs_sync_no_extent_one` and `speedup_vs_async_no_extent_one` use the
matching workload's worker-1 result from dynamically generated reference CSVs.
The primary paper metric is
`throughput_ratio_vs_sync_no_extent_same_workers`, which compares the same
workload and worker count. `adaptive_gain_target_met` records whether that row
reaches the default 1.10 target. In `both`, adaptive results use the complete
sync-no-extent scale matrix; `all` additionally records the async diagnostic
comparison. Every generated CSV records minimum and maximum elapsed time and
throughput in addition to median and percentile fields.

SQLite on HOST stores only the authenticated extent index: object/task id,
label/tag, logical offset, ciphertext-file offset, length and sequence. Bulk
ciphertext is stored in separate extent files. The master enclave owns task
splitting, slot dispatch, sequence assignment and digest aggregation. Worker
enclaves own plaintext generation, AES-128-ECB encryption/decryption, data
processing and construction of concrete I/O descriptors. The HOST owns request
collection, extent planning, `io_uring` execution and completion publication.
The SM owns lane scheduling, BLOCKED/RUNNABLE transitions, PMP grants and memory
isolation; it does not parse SQLite or extent-planning policy.

Each worker has two directly mapped 2 MB UTM data buffers. A submit-only write
can remain outstanding in buffer A while the enclave encrypts or prepares the
next extent in buffer B. A worker may have at most two outstanding requests and
waits only when both buffers are occupied or when a read dependency requires
the returned ciphertext. Waiting is an OCALL-backed event transaction: the SM
marks the worker BLOCKED, selects another READY member in the same lane, and
returns the original worker to RUNNABLE only after HOST completion. There is no
status-yield polling loop.

The HOST starts a rolling collection window when the first request arrives. It
seals that operation-specific batch when the adaptive target depth is reached,
the short collection deadline expires, or no compatible request is available;
it never waits for every worker. Requests are sorted by file, operation and
offset. Identical reads share one physical read, overlapping reads are read once
and scattered into each owning UTM, and strictly adjacent reads are coalesced.
A cost model may also bridge a small read hole when the saved fixed request
latency exceeds the estimated hole-read and UTM-copy cost, the merged span is
within 2--8 MB, and read amplification remains at or below 1.10 by default.
Unprofitable sparse reads remain separate SQEs in one `io_uring` submission. Writes
retain authenticated sequence order; overlapping writes use an ordered path so
an older completion cannot overwrite a newer ciphertext version. The HOST can
observe metadata and ciphertext but never plaintext or the AES key.

The 2 MB UTM buffer size is a transport capacity, not a forced physical-I/O
alignment. Sequential `fillseq`, `fillseqbatch`, and `readseq` requests remain
2 MB contiguous transfers. `fillrandom`, `fillrandombatch`, `overwrite`, and
`readrandom` use exact 4 KB SQLite-page ranges. `readrand100k` issues exact
100 KB random ranges. Each buffer-owned request ring carries up to 256
independent descriptors per OCALL; the two rings retain up to 512 outstanding
descriptors per worker. This keeps the complete worker UTM below the 4 MiB
buddy-allocation threshold. The HOST still creates one SQE per descriptor
before optional extent coalescing.

Each worker owns a fixed sparse offset namespace inside the workload's
ciphertext file. This prevents a randomized final partial extent from
overlapping the next worker partition while still allowing HOST to batch all
workers' non-contiguous requests in one `io_uring` submission.

`GROUP_PMP_SQLITE_IO_MERGE_MAX_BYTES` controls the merged-range limit and is
clamped to 2--8 MB (default 8 MB). The collector maintains EWMA estimates for
device bandwidth, request latency, queue wait and completion latency, then
adapts its collection window, batch target, queue depth and maximum profitable
gap. `GROUP_PMP_SQLITE_IO_READ_AMP_PERMILLE` is clamped to 1000--1200 and
defaults to 1100. Random writes are batched for `io_uring`, metadata
transactions and completion notification without reading or writing holes. SYNC
requests collected from multiple workers share one `fdatasync` before their
individual completion events are published.
`GROUP_PMP_SQLITE_IO_COLLECT_USEC` controls the short HOST collection window
used to combine requests from different workers.
`GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE` controls the reported
same-worker-count performance target and defaults to 1100. Missing the target
is reported per CSV row and as a final warning; it does not discard the
measurement.

Random-read UTM buffers have generation- and key-epoch-bound ciphertext cache
descriptors. Sequential reads bypass both cache lookup and cache population:
their streaming access has no reuse to repay the extra Host copy. A complete
random-read hit avoids disk I/O; a prefix or suffix hit copies only
cached ciphertext and reads the missing range. Writes, commit/SYNC, truncate,
delete, reset, generation changes and key-epoch changes invalidate entries.
The cache never contains plaintext. Completion status words are published as
one release-ordered batch, and members completed in the same lane defer driver
kicks until the final resume, producing one lane wakeup per completion batch.
The CSV schema v14 reports collection, sorting, clustering, submission, I/O API,
UTM copy, completion and wakeup time; logical and physical requests; merge,
deduplication, read-amplification and cache-hit ratios; and current EWMA and
adaptive values. It preserves raw completion-publish to SM wake latency and
also reports callback-eligibility to SM wake latency plus the count of
completions that became ready before the worker registered its wait.

Files changed for the rolling collector and true double-buffer protocol:

- `eapp/group-pmp-sqlite-vfs-shared.h`: versioned submit-only/wait ABI and
  artifact markers.
- `sqlite-bench-master/keystone_enclave_store.c`: active worker path with two
  outstanding UTM buffers and event-driven completion waits.
- `sqlite-bench-master/keystone_enclave_vfs.c`: ABI-compatible legacy VFS path;
  kept in sync even though the current CMake target uses the store path.
- `host/group-pmp-test-runner.cpp`: detached completion registry, lane-batched
  SM wakeup binding, separate submit/completion-wait OCALL accounting, and
  CSV schema v14 metrics.
- `host/sqlite-extent-io.cpp`: rolling operation-specific batches, read
  dedup/scatter, cost-aware clustering, adaptive EWMA control, ciphertext UTM
  cache and sequence-safe overlapping writes.
- `run-p10-mixed-scaling.sh`: deployed-artifact checks and runtime reporting.
- `rebuild-and-test.sh`: source, build and deploy marker verification.

### Read Pipeline and Timing (I/O Policy 16)

The random 4 KB descriptor path is unchanged (256 descriptors per ring, two
rings per worker). `readrand100k` packs twenty exact 100,000-byte requests into
each 2 MB buffer instead of nineteen page-padded requests. These requests were
already ineligible for strict 4 KB O_DIRECT because their lengths are unaligned.
`readseq` now uses one independent 2 MB read per ring: it posts both before
waiting and can decrypt a completed buffer in EPM while its peer is outstanding.
Locally completed rings need no additional completion-wait OCALL. Sequential
writes retain their two-buffer, one-doorbell 4 MB batches.

The adaptive sequential collector immediately takes compatible requests already
in its queue, without a timed collection wait. Worker-specific `run_id` values
do not split requests for the same workload and physical file. It preserves
arrival-order control and read/write boundaries, then the planner sorts the
actual file offsets. Two or four genuinely adjacent 2 MB requests can form a
4 or 8 MB vectored extent directly into registered UTM buffers. A single worker
has only 4 MB UTM, so an 8 MB extent requires adjacent requests from multiple
workers to be available together. Nonadjacent partition requests stay separate;
neither partition layout, sparse over-read nor artificial delay is used to
force an 8 MB counter. Random 4 KB collection and batching are unchanged.

An observed run with no coalescing (for example, 36 logical and 36 physical
2 MB reads) is retained with a `sequential coalescing target not observed`
warning. It is a missed optimization target, not a functional failure.
Discarding it would bias the performance CSV toward successful merges. Failed
I/O, impossible physical/logical request counts, and extents above 8 MB still
fail validation. The deterministic Host regression separately verifies that
four adjacent requests available together actually form an 8 MB extent.

For sequential reads the HOST does not copy any cache entry. For 100 KB reads,
it retains only the final cache entry per buffer in a completed batch, as before.
Ciphertext remains in UTM; decryption writes plaintext directly into private EPM.

CSV timing columns (202 columns total in schema 14; the original 191 remain in order):

- `vfs_crypto_sample_seconds`, `vfs_crypto_io_overlap_seconds`, and
  `vfs_crypto_io_overlap_ratio`: decryption intervals intersected with the peer
  ring's submit-to-completion-publication interval. The ratio is computed per
  run and then median-aggregated. It measures pipeline overlap, not physical
  disk activity or CPU utilization. Samples include any enclave descheduling
  during decryption; compare them with the on-CPU clock below, not alone.
- `vfs_both_buffers_wait_seconds`: event-wait intervals that started with both
  rings pending; not the exact intersection of two device I/O intervals.
- `vfs_completion_local_reaps`, `vfs_buffer_reuses`: completed-ring fast paths
  and ring reuse counts, including the final drain.
- `io_api_seconds`: complete Host data-I/O call path, including SQE preparation,
  submission (which can perform buffered I/O inline), and CQE drain/wait. POSIX
  fallback data calls are included. The existing `disk_io_seconds` column is
  retained as an alias, but its meaning changed in schema v12: old values counted
  only post-submit completion wait. Do not compare those buckets across schemas.
- `io_completion_wait_seconds`: just post-submit CQE wait/drain;
  `io_submit_seconds` is already part of `io_api_seconds`, not an additional cost.
- `storage_sync_seconds`: timed workload SYNC `fdatasync` calls, separate from
  data calls. SQLite metadata commits, cache advice and registration are not in
  `io_api_seconds`. `sqlite_storage_service_seconds` in the console covers the
  broader Host service, including metadata, planning and copies.
- `sequential_extent_count`, `sequential_8mb_extent_count`,
  `cross_worker_extent_count`: successfully completed Host data requests, not
  block-device request counts. The latter can include non-sequential extents.
- `io_timing_scope`, `cache_contract`, `crypto_io_overlap_scope`: explicit
  interpretation labels. Legacy sync-no-extent SQLite-internal I/O is marked
  unavailable rather than presenting its zero API bucket as zero device time.
- `aes_oncpu_seconds`, `aes_oncpu_mb_per_sec`: SM per-member execution-runtime
  deltas sampled immediately around the existing AES transform. The legacy
  `aes_seconds` and `enclave_aes_mb_per_sec` now use the same on-CPU denominator.
  The optional clock lives in the audited read-only EPM protocol mailbox, not
  UTM. SM publishes accumulated runtime and a resume anchor at scheduler
  boundaries; worker snapshots use a sequence check and `rdtime`, with no SBI
  for each AES call. Clock-only subscribers receive no unrelated full protocol
  or bank snapshots. Descheduled/blocked intervals are excluded. As with the
  SM scheduler runtime, short traps while the member remains active are not a
  separate user-mode-only hardware counter.
- `aes_elapsed_seconds`, `aes_descheduled_seconds`: summed start-to-end AES
  intervals and their difference from on-CPU time. They are not the whole-run
  wall time. Raw `worker_aes_cycles` remains a hart-cycle interval, not on-CPU
  cycles; do not divide it by on-CPU ticks to infer CPU frequency.
- `aes_timing_scope=sm-member-runtime-crypto-boundaries` identifies the new
  measurement. Clock-version, generation or monotonicity failures fail the
  test instead of silently substituting elapsed time.
- `request_queue_wait_mean_us`, `ready_to_resume_mean_us`: average Host
  request-queue wait and eligible-completion to SM wake plus enclave resume
  latency. Along with AES descheduling, context/PMP buckets and full-flow wall
  time, use these to diagnose the 7--15 worker range. Summary rows retain the
  existing median aggregation; derived means use those aggregate counters.

All these duration buckets are sums; they overlap and must not be added to
reconstruct wall time. The full-flow `seconds_median` remains the comparison
denominator. `cold` is buffered I/O after successful `fdatasync` and
`POSIX_FADV_DONTNEED` at measurement reset, after prefill; readahead and device
caches still exist. `direct_io_operations=0` is therefore expected for `cold`.
`direct` is a separate mode and unaligned requests have explicit fallback
counters. Neither mode measures actual media latency without device tracing.

When first installing the execution-clock update, rebuild/deploy SM firmware,
SDK, runner, master/worker eapps and scripts together. That update introduced
mixed result ABI 20 and SQLite VFS ABI 12; current CSV/policy versions are 14/17.
The execution clock is an optional mailbox extension; the group ABI and driver
layout are unchanged, but old SM firmware cannot register the new clock flag.
For that initial clock deployment, rebuilding only examples is insufficient.
Policy 17 itself only needs updated examples, as described below. Local Linux regression (mocked
enclave boundary plus real AES and Host I/O planner):

```sh
sh tests/run-sqlite-io-regression.sh
./run-p10-mixed-scaling.sh sqlite-bench both 15 5 512MB cold
```

Files changed for this sequential-path/on-CPU update (relative to the project):

- `sdk/include/shared/sm_call.h`: optional clock contract and snapshot helper.
- `sm/src/enclave.c`: clock publication and active-runtime boundary accounting.
- `examples/group-pmp-test/host/sqlite-extent-io.cpp` and `.hpp`: cache bypass,
  ready-only cross-worker collector and policy version.
- `examples/group-pmp-test/host/group-pmp-test-runner.cpp`: on-CPU metrics and CSV.
- `examples/group-pmp-test/sqlite-bench-master/keystone_enclave_store.c` and `.h`:
  AES-only clock snapshots, without changing encryption or random request size.
- `examples/group-pmp-test/eapp/group-pmp-sqlite-worker.c`,
  `eapp/group-pmp-sqlite-vfs-shared.h`, `eapp/group-pmp-mixed-shared.h`: clock
  registration, result fields and size assertions (last two relative to example).
- `examples/group-pmp-test/rebuild-and-test.sh`, `run-p10-mixed-scaling.sh` and
  `README.md`: source/artifact versions and measurement contract.
- `examples/group-pmp-test/tests/sqlite-store-pipeline-test.c`,
  `tests/sqlite-extent-service-test.cpp`, `tests/sqlite-csv-test.cpp` and
  `tests/check-sqlite-oncpu-riscv.sh`: regression tests and RISC-V object builds.
- `examples/group-pmp-test/tests/run-sqlite-io-regression.sh`: test orchestration
  and numeric script/runner version consistency checks.

`both` still compares sync-no-extent with adaptive-extent. One repetition is
allowed for preview; performance and overlap gains require board measurements.

Stress defaults are 2000 create/run/destroy cycles, 100 scheduler rounds and
100 two-group rounds. Override them with `GROUP_PMP_LIFECYCLE_ITERS`,
`GROUP_PMP_SCHED_STRESS_ROUNDS` and `GROUP_PMP_TWO_GROUP_ROUNDS`.
Stress also runs an active worker-lease release case. Its worker eapps do not
exit voluntarily: the test waits until all three worker harts are active, then
requires the scheduler IPI/release path to return every runner to HOST and
leave no active hart or YXSTM grant. The activity observation deadline is
controlled by `GROUP_PMP_ACTIVE_RELEASE_OBSERVE_MS` (default 5000 ms). Driver
release completion is independently bounded by the
`worker_release_timeout_ms` module parameter (default 5000 ms).

The SM resource snapshot verifies enclave, group, member, PMP metadata,
runqueue, event queue, active-hart and acquired-YXSTM counts after cleanup.
IPI counters are monotonic and are reported separately from reclaimable
resources.

Fault injection is disabled in normal firmware. Build the SM with
`KEYSTONE_GROUP_TESTING=1` and set
`GROUP_PMP_REQUIRE_FAULT_INJECTION=1` to require the test ABI. Without both,
the injection case is reported as skipped. Injection state can drop the next
coherence IPI acknowledgement or force a coherence timeout and is always
cleared by the test control path.

Use `run-p9-qemu-regression.sh` inside the QEMU guest for bounded automated
regression. Use `run-p9-board-regression.sh` on VisionFive2 for full stress and
hardware PMP/concurrency coverage. Both wrap every mode in `timeout`.

Direct host CPU access to YXSTM is tested on VisionFive2 with RISC-V
exception-table-backed nofault loads and stores. Both accesses must raise a
hardware access fault and return `-EFAULT`; an Oops, a successful access, or a
different result fails the test. QEMU validates policy and ABI behavior, while
only VisionFive2 validates JH7110 hardware PMP programming. The historical
entry-point name `run-p9-destructive-host-access.sh` is retained, but the test
is now recoverable. The runner still requires a quiescent resource snapshot
before starting so an earlier group cannot affect the result. Before returning
to host context, every schedule-out, active-hart clear, failed schedule-in and
destroy path replaces dynamic grants with full-region `PMP_NO_PERM` entries
for EPM, YXSTM and protected device regions; UTM remains host-accessible.

## Policy 20: immediate HSM event delivery and submission ACK timing

Deploy **CSV schema 17 (244 columns), adaptive policy 20, VFS ABI 13,
mixed result ABI 22 (816 bytes), effective batching v8** together. The ring
header grows from 64 to 128 bytes inside the existing 64 KiB ring allocation;
UTM data capacity, request descriptors and two-buffer ownership are unchanged.
AES, the extent planner, low-gain fast paths and SM/CFS/PMP are not changed.

The leased-hart event mailbox previously relied on a CPU0 delayed-work scan
with `msecs_to_jiffies(1)`. With HZ=100 this is tick-quantized to 10 ms, before
workqueue/Host scheduling. It can delay every submission ACK even when storage
completes quickly. The updated kernel exposes a dedicated HSM event IPI:
the offline worker publishes its mailbox and signals CPU0; the online CPU's
IPI handler queues high-priority bound work, which translates the event and
wakes the Host waitqueue immediately, without periodic scanning. The IPI
handler does not sleep, and the offline sender does not use Linux call-single,
irq_work or workqueues. Disabling events is serialized with work cancellation;
unregister waits for online IPI readers. Lease acquisition checks notification
availability before offlining workers. CPU0 must remain online during the lease.

Submission ACK means accepted, not I/O complete. Async and adaptive return the
ACK after admission so the worker can process/submit another free buffer; only
the existing WAIT/completion protocol releases ownership or blocks for I/O.
The sync baseline intentionally retains its synchronous ACK. Packed UTM
descriptor ranges use linear overlap validation; unordered ranges are sorted
and checked in O(N log N), not compared pairwise. This is validation, not new
extent planning. No collector timeout or wait-to-merge was added. Existing
sequential write batches can own both buffers; paired readseq starts keep two
independent completions and immediate single-buffer refills.

### New CSV submission stages

All four stages use the common RISC-V `rdtime` domain:

| Field prefix | Interval |
| --- | --- |
| `pipeline_submit_to_host` | worker doorbell call to Host VFS handler entry, including event delivery/dispatch lock |
| `pipeline_host_to_ack` | handler entry through admission and ACK construction; sync includes the storage wait |
| `pipeline_ack_to_resume_request` | ACK ready to the Host resume ioctl request |
| `pipeline_resume_request_to_return` | resume request through driver/SM scheduling to worker OCALL return |

Each prefix has `_seconds` (sum over the measured worker calls) and `_max_us`
(largest individual interval). `pipeline_submission_timing_count` counts valid
doorbells, not descriptors; a paired doorbell counts once. Invalid, missing or
non-monotonic Host timestamps increment `pipeline_submission_timestamp_invalid`
and are excluded, never used as authorization. Host publishes all timestamps
before resume, so no writes can race with reuse of the old ring generation.
Legacy non-ring OCALLs do not supply these timestamps. These worker intervals
overlap across harts; do not sum them with disk/AES buckets as wall time. For a
single observation, each stage's sum/count gives its mean per valid doorbell;
independently aggregated multi-sample medians are not a reconstructed timeline.

### Build and verify

This update **requires the VisionFive2 kernel and driver**, not only examples:

- In `VisionFive2_devl/linux`: `arch/riscv/include/asm/hsm_cpu_lease.h`,
  `arch/riscv/kernel/smp.c`, `arch/riscv/kernel/cpu_ops_sbi.c`.
- In `keystone_yx/linux-keystone-driver`: `keystone-group.c`.
- In this example: `host/group-pmp-test-runner.cpp`,
  `host/sqlite-submission-timing.hpp` (new), `host/sqlite-extent-io.hpp`,
  `sqlite-bench-master/keystone_enclave_store.c`,
  `eapp/group-pmp-sqlite-pipeline-timing.h`, `eapp/group-pmp-sqlite-vfs-shared.h`,
  `eapp/group-pmp-mixed-shared.h`, `run-p10-mixed-scaling.sh`, `rebuild-and-test.sh`.
- Tests/docs: `tests/sqlite-csv-test.cpp`, `tests/sqlite-store-pipeline-test.c`,
  `tests/check-hsm-event-build.py` (new), this README, project status document.

Keep CONFIG_RISCV_HSM_CPU_LEASE enabled in the target kernel. Rebuild/reboot with
the kernel and matching module, then deploy all example eapps/runner/scripts.
`rebuild-and-test.sh` builds examples; it does not install this kernel change.
An old HSM header is rejected by the new driver. No new SM/runtime/SDK ABI is
required, but retain the previously deployed execution-clock support.

Local regression: `sh tests/run-sqlite-io-regression.sh`. It covers actual
io_uring/registered buffers, held-backend ACK/second-buffer admission in both
async modes, ownership on failures, unordered completions, timing and 244 CSV
columns. `tests/check-hsm-event-build.py` replays a prepared kernel's compiler
flags into temporary objects, testing the kernel bridge/driver with HSM on/off
without changing its configuration. It is not a complete kernel link or a
hardware concurrency test. RISC-V SM/store/worker and Host runner object
compilation also passed (the runner check excludes its pre-existing unused
legacy test functions from -Werror).

Board preview for the critical path, followed by a mode comparison:

```sh
GROUP_PMP_MIXED_CSV=/sqlite-ack-preview.csv \
  ./run-p10-mixed-scaling.sh sqlite-bench adaptive-extent 1 1 60MB cold
./run-p10-mixed-scaling.sh sqlite-bench all 15 5 512MB cold
```

Check valid submission timestamps, stage averages/maxima and full-flow seconds;
`/proc/interrupts` should show CPU0 HSM lease event interrupts increasing.
Board latency/throughput and hotplug stress still require hardware validation;
neither sub-millisecond recovery nor a percentage gain is claimed by local tests.
The following sections describe previous revisions, not current deployment.

## Previous policy 19: local candidates, cache admission and pipeline timing

Previous deployment: **CSV schema 16 (234 columns), adaptive policy 19, extent
client v16, effective batching v7, cost cluster v3, ciphertext cache v2**.
The mixed application result ABI is **21**, with a 736-byte worker result.
Rebuild/deploy all example eapps, the runner and scripts together, including
the new `eapp/group-pmp-sqlite-pipeline-timing.h`. The VFS request/ring wire
layout (v12), AES, SM/CFS, PMP, driver and runtime are unchanged.

Only adaptive acquires the new local planner and cache admission policy.
Sync/async retain their scheduling, queue and I/O policies (1/2). Pipeline
instrumentation is shared by every mode using the request rings; legacy
non-ring paths leave these counters zero, not a measured zero latency.

### Candidate-only random planning

The bounded 4 KiB hash precheck now scans the complete batch and separates
duplicate/adjacent candidates from isolated pages. Only the candidate subset
is sorted, checked for write coverage and clustered. Isolated requests keep
their arrival order and become individual registered-buffer SQEs in the same
submission. For N requests and K candidates this avoids sorting/scanning all
N just because one neighbouring pair arrived. The precheck is bounded linear
work and candidate sorting is O(K log K); conflicting writes retain their
existing sequence rules. Equal-sequence overlapping writes are still errors.

When sequence-ordered writes are needed, only the local conflicting candidate
subset takes that path, not the independent remainder. Mixed files, non-page
tails, partial cache hits and exhausted hash probe budgets still require the
complete interval validation. This never means skipping ownership checks.
The cheap partition deliberately leaves isolated pages discrete rather than
searching for weak gap-bridging opportunities around them. Sequential and
100 KB clustering, maximum extent size and amplification bounds are unchanged.

- `random_local_plan_batches`: candidate and isolated subsets both nonempty.
- `random_local_candidate_requests`: requests entering candidate planning.
- `random_sparse_fast_requests`: now includes isolated requests in a mixed
  batch, not only completely sparse batches. `random_sparse_fast_batches`
  still counts entirely sparse batches.
- `random_planned_batches`: either a local or complete random plan;
  `random_precheck_fallbacks` identifies inconclusive full-plan batches.

### Low-hit ciphertext cache

Adaptive `readrandom` retains at most the last successful descriptor per UTM
buffer in a completed batch; intermediate cache copies were immediately
overwritten. Over each 128 logical reads, metadata-only reuse below 1% of
requested bytes disables further cache filling. Last-range shadow metadata
continues to observe locality without copying ciphertext. At least 1% reuse
in a later observation window re-enables filling for subsequent completions.
There is no synthetic read or timer delay to probe the cache. Full/partial
hits still require matching file, run generation, key epoch and sequence;
an empty shadow entry cannot satisfy a read. Writes/control invalidation and
measurement reset clear cache/admission state. Sequential reads still do not
fill this cache; 100 KB cache policy is unchanged.

`cache_fill_bytes`, `cache_fill_ns`, `cache_fill_skipped_bytes`,
`cache_admission_disables` and `cache_admission_reenables` distinguish cache
filling from necessary read fan-out. `cache_fill_ns` is a **subset** of
`utm_copy_seconds` (after ns conversion), not an additional cost. Skipped
bytes count admission-suppressed final entries, not discarded intermediate
entries. A middle-only cache overlap which cannot reduce the physical read
no longer performs a copy or receives hit-byte credit in either async mode.

### Completion consumption critical path

New `pipeline_*` CSV fields use rdtime/timebase, not cycles or CPU frequency.
Totals are summed across workers; `*_max_us` is the maximum single interval
across workers, then the per-experiment maximum is aggregated across samples.
Multi-sample columns use independent nearest-rank medians, as other counters.

| Prefix | Interval |
| --- | --- |
| `pipeline_doorbell_ack` | Ring publication to OCALL return with acceptance ACK; includes enclave/Host transitions and descheduling, not just Host handler CPU time. One paired doorbell is counted once. |
| `pipeline_completion_to_consume` | Host completion publication to worker beginning to consume the ring, including ready-but-not-consumed residency. |
| `pipeline_ack_to_consume` | Own ring ACK return to consumption start; can overlap peer crypto and I/O waiting. |
| `pipeline_buffer_consume` | Completion/status processing, decryption and existing edge-sample validation through releasing ring-owned payload. |
| `pipeline_buffer_refill` | Ring-owned payload consumption end to its next publication; includes request construction, write encryption and any intervening task/control work. Initial submissions and final drained buffers have no refill sample. |
| `pipeline_request_prepare` | Descriptor/status/ring construction inside `prepare_request_batch`, excluding AES. |

Time totals end in `_seconds`; single-interval maxima end in `_max_us`.
Counts accompany doorbell, completion-consumption, consumption and refill.
`pipeline_completion_timestamp_invalid` counts unavailable/out-of-bounds
Host timestamps, excluded from the completion-lag mean (use the valid count).
Host timestamps must fall between this ring's publication and consumption;
they are diagnostic only and never authorize reuse. Begin-measurement clears
previous prefill consumption stamps. Terminal draining counts consumption
but not a nonexistent next submission. These intervals overlap and must not
be added together or subtracted from multi-hart wall time to infer utilization.

Interpretation: a high doorbell/ACK bucket points to acceptance/return;
a high completion-to-consume bucket with short wake latency points to worker
consumption scheduling; a high consume bucket relative to AES elapsed time
points to status/validation work; a high refill bucket points to producer or
task/control work before the next request. Correlate with existing queue,
I/O API, wakeup and Gantt traces before attributing a fixed delay.

Local regression: `sh tests/run-sqlite-io-regression.sh` tests partitioning,
actual file contents, sequence conflicts, zero-hit suppression/re-enable,
out-of-order buffer completion, timestamp bounds, medians and CSV columns.
It does not substitute for RISC-V cross compilation or board performance.

Preview on the board (three modes, all scales 1..15):

```sh
./run-p10-mixed-scaling.sh sqlite-bench all 15 1 60MB cold
```

For publication statistics use `all 15 5 512MB cold`. Single adaptive preview:

```sh
GROUP_PMP_MIXED_CSV=/mixed-adaptive-policy19.csv \
  ./run-p10-mixed-scaling.sh sqlite-bench adaptive-extent 15 1 60MB cold
```

## Previous policy 18: sparse planning and readseq refill diagnostics

Previous deployment: **CSV schema 15 (211 columns), adaptive policy 18, extent
client v15, effective batching v6, cost cluster v2**. Sync/async policy numbers
remain 1/2. Rebuild/deploy the runner, SQLite worker eapp and scripts together.
The VFS request layout, AES, SM/CFS, PMP, driver and runtime are unchanged.

For adaptive random 4 KiB batches, a bounded linear page-range precheck proves
whether there are no duplicate, overlapping or adjacent ranges. It uses a
reusable Host-side hash table, no per-request allocation and a capped probe
count. With the 1.10 amplification cap, an isolated one-page hole between two
4 KiB reads would already require 1.50 amplification. A certified sparse
batch therefore bypasses sorting/clustering and submits the same independent
registered-buffer SQEs. Certified disjoint writes also need no second sorted
coverage scan. This is a range proof, not skipping write-order validation.

Candidates, mixed files, cache-partial reads, small tails, overflow and hash
probe exhaustion use the full existing interval/sequence planner. The check
is repeated for every batch, so new locality is detected immediately rather
than suppressed by a cooldown. Sequential and 100 KB planning are unchanged.
Full-plan duplicate counting now uses sorted adjacent equal ranges instead
of building a tree for every group, including singleton groups.

### Why readseq pairs appear at startup

At the start of a range both 2 MB UTM buffers are free, so adaptive can publish
two contiguous requests atomically. Later, `wait_batch(A)` consumes/decrypts A
and immediately refills A while B still owns its ciphertext. Even if B's I/O
has completed, B is not free until its result has been consumed. Thus the old
`pending` flag did not distinguish storage waiting from ready-but-unconsumed
data. With one read stream and two buffers this generally gives one initial
pair followed by singleton refills, not a Host batching timeout.

The refill remains immediate: there is no wait/reap of B to manufacture a
merge and no new EPM staging copy or extra buffer. Already-arrived requests
from different workers can still merge when their actual file offsets are
adjacent, up to 8 MB. Different workers normally read different partition
positions, so simultaneous arrival alone does not imply adjacency. Do not
use an 8 MB merge rate as a substitute for full-flow throughput or overlap.

New appended CSV fields (Host counters, independently aggregated medians):

- `random_sparse_fast_batches`, `random_sparse_fast_requests`: certified
  random batches/requests using the no-sort/no-cluster path.
  `request_cluster_seconds` can still include constructing the discrete I/O
  groups/vectors; it is not expected to become zero. The fast path skips merge
  decisions, not the descriptors needed to submit the requests.
- `random_planned_batches`: random batches sent to the existing full planner.
- `random_precheck_fallbacks`: inconclusive prechecks, a subset of planned
  batches; nonzero does not mean an I/O failure or a sync-I/O fallback.
- `random_precheck_ns`: precheck cost in **nanoseconds**, charged once. Full
  write interval checks remain in `write_overlap_check_seconds`; the fast
  disjoint proof is only in this precheck bucket. Both are inside Host service.
- `readseq_initial_requests`: requests from the first submission of each
  transfer range (normally two for an adaptive paired start, one otherwise).
- `readseq_refill_peer_io_requests`: refills observing peer I/O incomplete.
- `readseq_refill_peer_ready_requests`: refills observing peer complete but
  still holding unconsumed ciphertext.
- `readseq_refill_peer_idle_requests`: refills observing the peer already free.

These readseq flags are diagnostic snapshots, not control/permission inputs.
For the extent service the four counts sum to the readseq data request count.
The independent sync service does not produce these Host diagnostics (zeros).
Readseq data is decrypted only into private EPM; UTM remains ciphertext-only.
Small-range/multiple-range calls can have more than one startup per worker.

The existing `sequential_ready_*` counters describe Host batch contents, while
the new refill counters describe the producer's buffer state. Compare those
with wall time, queue time and AES on-CPU time; do not add overlapping time
buckets or interpret ready-but-unconsumed ciphertext as disk latency.

Run `sh tests/run-sqlite-io-regression.sh` on a Linux build host. It tests the
sparse certificate against range oracles, immediate locality changes, write
contents/ordering, duplicate read fan-out, bounds, all completion orderings,
no-peer-wait refills, registered I/O, CSV fields and script version agreement.
For a board preview covering all three modes, use:

```sh
./run-p10-mixed-scaling.sh sqlite-bench all 15 1 60MB cold
```

One sample diagnoses paths, not statistical gains. Follow with `all 15 5
512MB cold` for repeat measurements. `cold` remains buffered I/O with prefill
followed by cache advice; it is not O_DIRECT. CSV writes remain outside timing.

## Previous policy 17: measured write feedback and ready read pairs

This update changes the example Host/store pipeline only. It does not change
AES, the SM scheduler, PMP, the driver or runtime. Keep the previously deployed
on-CPU execution-clock support. Rebuild the examples and deploy the runner,
SQLite worker eapp and scripts together: CSV schema 14, adaptive policy 17,
extent client marker v14. Sync/async baseline policies remain 1/2.

The paired-read config flag and 128-byte doorbell/ack types are defined in
`eapp/group-pmp-sqlite-shared.h` and `eapp/group-pmp-sqlite-vfs-shared.h`.
Sync both headers together with the Host and store sources, including when
building the full Buildroot tree instead of using `rebuild-and-test.sh`.
Host/store includes resolve these contracts relative to this example, not an
installed SDK. The rebuild preflight checks the paired declarations as well
as the unchanged base VFS marker. Regression builds put poisoned same-name
headers first on the include path to detect accidental header shadowing.

- Write coverage validation sorts by file/offset, skips disjoint components,
  and uses a sequence-ordered prefix-maximum index only within overlapping
  components. Equal sequences cannot suppress each other. Remaining partial
  overlaps still use the existing ordered-write path. Complexity is O(B log B),
  not an unconditional O(B squared) comparison.
- Adaptive random writes start at 256 descriptors, bounded to 128..512 by
  default. Eight serviced batches form a feedback window. Growth is a bounded
  trial: keep it only for at least 5% higher useful-byte service throughput,
  at most 25% higher window tail latency, and no more than 80 ms tail latency.
  Rejected trials shrink to the stable target and back off for eight windows;
  high tail latency shrinks the target. No artificial wait is added. These are
  initial policy parameters, not claimed board-optimal constants.
- Pending random writes use event-based admission with capacity
  `max(2 * submitted_descriptor_count, 2 * current_target)`, bounded by the hard
  queue limit. This no longer scales the pending capacity with worker count.
  Host drains the queue independently; full completion groups remain intact,
  so actual service batch sizes can exceed the soft target at a group boundary.
  Admission waiting is included in existing submit-to-dequeue accounting.
- Adaptive readseq can publish two already-prepared single-descriptor rings
  with one doorbell when both buffers are free. Host atomically enqueues them
  with independent completion objects. Refilling one buffer never waits for
  the other just to form an extent. Only already-arrived contiguous file ranges
  merge (maximum 8 MB); cross-worker adjacency is not guaranteed by a partitioned
  workload. Sync, async-no-extent, random 4 KB and 100 KB submission paths stay
  unchanged. Plaintext remains in EPM; both UTM buffers contain ciphertext only.

New appended CSV fields:

- `write_overlap_check_seconds`: sorting, overlap detection and write coverage
  checks; separate from `request_cluster_seconds`, included in Host write service.
- `write_overlap_checks`, `write_disjoint_batches`, `write_overlap_batches`:
  interval/index steps (excluding sorting comparisons), and component-path use.
- `adaptive_write_grow_count`, `adaptive_write_shrink_count`,
  `adaptive_write_hold_count`: per-service-batch policy actions. Hold includes
  batches that have not yet completed a feedback window.
- `sequential_ready_single_batches`, `sequential_ready_multi_batches`,
  `sequential_ready_adjacent_pairs`, `sequential_ready_nonadjacent_pairs`:
  sequential planner input after metadata resolution, sorted by actual file
  offset. These distinguish missing concurrent arrivals from nonadjacent ranges.
  They are opportunity counters, not successful physical merges.

With paired readseq, `vfs_ring_doorbells` counts OCALLs and
`vfs_completion_batches` counts independently consumed rings. The latter can
be up to twice the former. Other workloads retain the one-ring/one-doorbell
invariant. Use full-flow wall time for comparison; summed buckets overlap.
The final wall/SM window is frozen before waiting for Host completion
bookkeeping to drain. The terminal snapshot includes the last request's
counters without resetting them or charging the bookkeeping wait to wall time.

Quick adaptive preview, then three-mode comparison:

```sh
./run-p10-mixed-scaling.sh sqlite-bench adaptive-extent 15 1 60MB cold
./run-p10-mixed-scaling.sh sqlite-bench all 15 5 512MB cold
```

`all` includes sync, async and adaptive; `both` still includes only sync and
adaptive. To attribute the adaptive algorithm's additional benefit, compare it
against async at the same worker count. No throughput gain is fabricated or
guaranteed for sparse workloads without aggregation opportunities.

# P15 one-hour acceptance

Run on VisionFive2 after deployment:

```sh
./run-p15-acceptance.sh
```

The default duration is 3600 seconds. During every worker-lane run the
script pins disk I/O, network ping, TTY heartbeat and process/RCU churn to CPU0.
It repeatedly executes a 16-member group with five worker enclaves queued per
lane, worker lease release, OCALL and fault injection. The retired pure-AES P10
tail run is disabled by default. The run fails if a CPU0 workload exits or if new kernel
output contains `Invalid error 100108`, an RCU stall, workqueue lockup, or SDIO
unexpected-interrupt-latency warning. For a short diagnostic run only:

```sh
GROUP_PMP_ACCEPTANCE_DURATION_SEC=60 \
./run-p15-acceptance.sh
```

`GROUP_PMP_P10_AFTER_ACCEPTANCE=1` is retained only for a legacy diagnostic
build and additionally requires `GROUP_PMP_ALLOW_LEGACY_PURE_AES=1`.
