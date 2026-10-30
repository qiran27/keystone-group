# Minimal Protected-Task Motivation (v4)

## Interface Selection (2026-10-16)

`--interface minimal` is the unchanged default described below. Two additional
test modes are available: `--interface sqlite` and `--interface fio`. These do
NOT adapt the private motivation backend to look like production: they invoke
`run-motivation-system.sh` and `run-p10-mixed-scaling.sh`, the actual production
task Master and SQLite Worker, encrypted store/VFS OCALLs, production Sync/Async
Host services and buffer completion/event handling. The fio choice selects the
existing `seq-read-2m` enclave profile; it does not execute the upstream fio binary.
Both choices keep Sync1, Async1 and Async3 with the same fixed total input.
The private motivation Worker and `Motivation::Backend` are not run in these modes.

Production uses its existing two 2,000,000-byte buffers and record-edge validation,
not the minimal experiment's 64KB framing/full-byte FNV task. Therefore an explicit
`--block-size` is rejected for production interfaces, rather than silently ignored.
The same crypto algorithm and storage directory are used across the three cases;
production Sync retains ciphertext SQLite BLOB I/O and Async retains metadata plus
external ciphertext extents. They are whole-production-path comparisons, NOT an
isolated overlap-only effect or a matched-backend replacement for minimal mode.
Production SQLite/fio do not become different storage engines merely because the
test mode label changes: the current enclave profiles share that implementation.
No AES, SM/PMP, scheduler, clustering or ordinary benchmark policy is changed.

```sh
# Board: one preview triplet plus three separate timeline runs per interface.
sh ./run-motivation-architecture.sh --interface sqlite --cipher aes-ecb-128 1 500MB cold /myusb/wj/deploy /motivation-architecture diagnostic
sh ./run-motivation-architecture.sh --interface fio --cipher aes-ecb-128 1 500MB cold /myusb/wj/deploy /motivation-architecture diagnostic
# Three formal rounds per case (nine untraced runs), plus three timeline runs.
sh ./run-motivation-architecture.sh --interface fio --cipher aes-ecb-128 3 500MB cold /myusb/wj/deploy /motivation-architecture formal
```

Results use separate `production-sqlite-*` / `production-fio-*` directories with
interface-labeled manifest, samples and summary, raw per-case performance/I/O CSVs
and logs, build fingerprints, and diagnostic-only timelines. Summarization rejects
mixed interfaces or a workload inconsistent with the selected interface. The
production runner requires `keystone-motivation-production-interface-v1` so old
deployments cannot quietly run a different mode. Existing minimal schema8 and
prior production records are neither relabeled nor pooled with these results.
Only one explicit input size (60/100/200/300/400/500MB) is accepted in production
mode; input-size sweep and block-size sweep remain minimal-mode options.

Entry: `run-motivation-architecture.sh`. Three configurations only: one Worker
Sync, one Worker Async, three Workers Async. No SQLite application, metadata
database, aggregation, future-request prediction, artificial I/O delays or added
compute loops are used. The experiment evaluates asynchronous service and
parallel execution, not the clustering algorithm.

## Shared Release and Next Read (v4)

This remains the paper's minimal three-case motivation, not a full SQLite/fio
business benchmark. Master/TSR handoff, same file/backend/cipher, two slots,
complete expected-data validation, fixed total work and 64KB default remain.

After a block has been captured, decrypted and fully checked, the Worker sends
one `MOT_RELEASE_SUBMIT` containing the old slot/block/generation and processing
witness plus the next block/generation/length. The Host validates BOTH identities
before changing ownership, retires the old record under the same mutex, then
admits a read into that same registered slot. No extra copy, queue depth or
lookahead is introduced. Invalid next requests cannot silently free old data.
An actual read-submission failure after retirement fails the whole run; it is
not acknowledged as success or retried with stale ownership.

Both modes use exactly this common path. Sync waits inside this combined OCALL
until the NEW read has completed and been published, preserving blocking
read semantics and one outstanding request. Async returns on admission and
retains independently completed slots/WAIT_ANY. It never waits for the other
slot to finish just to recycle this one. First admissions use `MOT_SUBMIT`;
with no next record, a tail uses only `MOT_RELEASE` immediately. Final DONE/TSR
completion is not reached until both slots are drained. The opcode is 13;
Master control opcodes 9..12 are not reused.

CSV8 adds `read_ocalls`, `release_submit_ocalls`, `release_only_ocalls` and
`data_path_ocalls`. A combined call is INCLUDED in `read_ocalls`, not added
twice. `data_path_ocalls=read_ocalls+release_only_ocalls` excludes WAIT, setup
and final DONE calls; it is not an all-OCALL or device-I/O metric.
At 500MB/64KB every case still performs 7,630 Host reads and CQEs. The old
separate read/release protocol used 15,260 data-path OCALLs; now Sync1 has
7,631, Async1 has 7,632, Async3 has 7,636 (the latter has six terminal slots).
Count validation and per-slot generation/reuse chronology are checked by the
backend, native tests and analyzer. Actual submission syscalls may differ from
both data-path OCALLs and data reads. Fewer control calls do not establish a
larger Async/Sync percentage: the common optimization benefits Sync as well.

```sh
# VM: rebuild and copy the COMPLETE fresh deploy directory.
./rebuild-and-test.sh
# Board: default 64KB, exactly Sync1/Async1/Async3 once, with diagnostics.
sh ./run-motivation-architecture.sh --cipher aes-ecb-128 1 500MB cold /myusb/wj/deploy /motivation-architecture diagnostic
```

## Block Geometry and Cost Diagnosis

V3 adds `--block-size 4KB|16KB|64KB|sweep`, meaning 4,096, 16,384 or 65,536
plaintext bytes per record. The default remains 64KB; `sweep` runs all three
configurations at each size in separate result directories. Input-size `sweep`
is independent (60/100/200/300/400/500 decimal MB). All three service cases
within a comparison use the same prepared file, full-byte FNV check, cipher,
cache preparation, backend and buffer capacities. No delay, added compute or
special-case weakened Sync is introduced. Different block sizes change request
granularity and fixture framing; they are separate workloads, not evidence of
an algorithm-only improvement. Report every size, not only the highest ratio.

Schema7 diagnostic traces add `capture_end_ticks` and `decrypt_end_ticks`.
`overlap-evidence.csv` reports ciphertext capture, identity/decrypt and full-byte
FNV verification wall times, each as sum and interval union, plus the verification
share of processing. Identity/nonce/padding checks are included with decryption;
this is not isolated AES on-CPU time. Stage boundary timer cost is present only
in diagnostic runs; formal runs do not take these two additional timestamps.
The existing full-byte check has NOT been removed or replaced with sampling.
Only measurements can establish whether FNV or AES dominates on the board.

Also report read admission, completion-publication-to-consumption and
same-slot release-to-next-submit gaps. Sync read admission includes blocking
I/O; these overlapping intervals must not be added together as CPU time.
Residual wall time outside reads/processing is not automatically control cost.
V4 refills the validated slot in the same release/submission interaction without
waiting for the unrelated slot; the policy is shared by all block cases.

The 64-byte record header means Host read lengths are payload+64, not raw
4KB device requests. For 500MB: 4KB has 122,071 Host reads, 16KB has 30,518,
and 64KB has 7,630. Each service mode has the SAME count at the same geometry;
this experiment does not reduce I/O operations by clustering. The fixed private
expected-hash array now covers the bounded 500MB/4KB maximum (976,568 bytes),
identically allocated for Master/Workers and every geometry. The matched-image
EPM reservation derives the required size; do not mix old/new binaries.

```sh
# Board diagnostic: 9 traced tasks total, three cases at each block size.
sh ./run-motivation-architecture.sh --cipher aes-ecb-128 --block-size sweep 1 500MB cold /myusb/wj/deploy /motivation-architecture diagnostic
# Formal: per block size, 9 timed tasks plus 3 independent diagnostic tasks.
sh ./run-motivation-architecture.sh --cipher aes-ecb-128 --block-size sweep 3 500MB cold /myusb/wj/deploy /motivation-architecture formal
```

## Real Architecture Path

1. Create one active Master and N Workers, using the same image and memory
   reservation. Master/Host use CPU0; Workers use CPU1/2/3 (lanes 0/1/2).
   Group capacity is N+1. The existing exclusive Worker lease is unchanged.
2. After every Worker warms up and parks at START, establish the selected cache
   state once. The Master then acquires each lane's protected TSR slot, writes
   one bounded whole-range task and publishes it with the actual SM slot API.
   Epoch, batch, task, sequence and permissions are checked. It does not create
   a TSR handoff for every data record.
3. Each Worker waits for READY, acquires its own TSR slot, copies and validates
   the task into EPM, then processes exactly that task's disjoint block range.
   Bootstrap UTM configuration is only checked as bounds/fixture consistency;
   processing does not start without the protected task. The Master is active,
   not an unused allocation owner.
4. Read ciphertext into the Worker's two independent UTM slots; capture into
   EPM; decrypt with the selected cipher; compute the existing FNV64 digest over
   all plaintext bytes and compare with the expected block digest. Host sees ciphertext and bounded
   completion/control metadata, not plaintext. This is a public benchmark-key fixture,
   not a key-management or anti-rollback protocol. ECB does not authenticate
   ciphertext; the expected-data check is workload validation, not an AEAD tag.
5. After all owned buffers drain, the Worker stores its processed bytes, blocks
   and digest in TSR and calls COMPUTE_DONE, revoking its slot grant. Master
   AGGREGATE_ACQUIRE reads and validates each result, combines the digest, then
   AGGREGATE_COMPLETE frees the slot and advances its epoch. Host cross-checks
   the protected aggregate against all Worker service results.

The board uses the real SDK `group_pmp_yxstm_slot_command`, protected slot
payload mapping, `groupRunMaster`, group event wait and deferred OCALL completion.
SM, PMP, CFS, the driver and main benchmark policies are not changed.
An explicit Master wait marker reports how many task results it has already
aggregated. The Host waits only for an unconsumed Worker-ready notification;
timer preemption is not treated as a result dependency. This prevents a final
timer interruption or an already-arrived result from stranding the Master.

## Matched Storage and Synchronization

All three groups read the very same prepared ciphertext file, with unchanged
selected-size plaintext records plus 64-byte identity headers, input bytes,
object identity, key, expected digest, cache policy and storage backend.
File SHA256 is checked before and after the three groups. Preparation/creation,
warmup, cache setup, trace serialization and cleanup are outside task timing.

Sync uses SDK blocking read OCALL semantics: the Host handler does not return
until its registered-buffer read completes and publishes; only then can the
Worker decrypt and validate. One data read is outstanding, without an extra
completion WAIT OCALL. The shared io_uring backend does not make this API Async.
This is the native blocking interaction pattern, not a pristine unmodified
upstream Keystone binary baseline.

Async returns on admission and permits a second owned slot to read while the
first is processed. WAIT_ANY is used when neither is ready. Completion publishes
each buffer independently. Async3 divides the SAME total input among three
Workers; it does not process three input copies. It has six total data slots and
three Host reactors, all pinned to CPU0; this resource increase is recorded.

The minimal fixture retains two bounded 69,632-byte record strides per Worker,
not the application's full 2MB capacity. It demonstrates the same ownership and
completion mechanisms without importing the complete application protocol.

## Measurement and Evidence

Schema 8 timing starts in Master immediately before its first task dispatch and
ends after its last protected result aggregation and slot release. `rdtime`
provides the common board clock. One task per Worker amortizes actual handoff
cost but does not exclude it. No Host DONE serialization extends this interval.

Defaults: AES-128-ECB, 3 repetitions per configuration, 500 decimal MB, cold. Rotation:
Sync1/Async1/Async3, Async1/Async3/Sync1, Async3/Sync1/Async1. Then three independent
diagnostic runs produce per-record I/O/processing and per-task dispatch/acquire/
completion/aggregation witnesses. Instrumented samples are never mixed into the
three uninstrumented min/median/max values. Negative/slow samples are preserved;
failures abort rather than being replaced.

Outputs: `samples.csv`, `summary.csv`, `figure-1c-data.csv`, `results.txt`, full
run logs, input/build hashes, `overlap-evidence.csv`, `*-trace.csv`, `*-tasks.csv`
and one three-panel `timeline-*.svg`. Timeline uses a common startup window ending
at Sync's sixth processed block, not a best-case Async interval. Blue means
Host read-service time, not device-only busy time. The protected-task row shows
the Master handoff. Full task witnesses remain available even when aggregation
is beyond the startup crop. Trace or witness mismatch fails validation.

Report total time, throughput, real min/max/median, Host data operations, submit
calls, CQEs, and TSR dispatch/aggregate/release counts. Host operations should
NOT fall in this experiment: at the default 64KB, 500MB = 7,630 records in every group. Async1 versus
Sync1 isolates the changed service interaction within this matched path;
Async3 additionally includes parallel resources. Never label either as clustering.

## Commands and Verification Scope

```sh
# Ubuntu VM, cross-build and deploy COMPLETE fresh output:
./rebuild-and-test.sh
# Board, 9 timed + 3 independently instrumented tasks, explicitly ECB:
sh ./run-motivation-architecture.sh --cipher aes-ecb-128 3 500MB cold /myusb/wj/deploy /motivation-architecture formal
# Optional one-triplet correctness/timeline preview (not 3-round statistics):
sh ./run-motivation-architecture.sh 1 500MB cold /myusb/wj/deploy /motivation-architecture diagnostic
# GCM comparison, reported separately, never substituted for the old result:
sh ./run-motivation-architecture.sh --cipher aes-gcm-128 3 500MB cold /myusb/wj/deploy /motivation-architecture formal
# Linux/WSL, actual C protocol/core and registered I/O backend:
sh tests/run-motivation-tests.sh
sh tests/run-motivation-architecture-local.sh 500000000 3 cold /var/tmp/motivation-architecture-native-new
```

Local tests exercise the actual Master/Worker C protocol with a strict shared-slot
permission model, including stale epochs, foreign access and revoked grants.
Separate processes run the actual crypto/check core and real file I/O. This does
NOT execute RISC-V enclaves, PMP, SM scheduling, or hardware OCALL. Local speedups
are local evidence only, not a board prediction. Board artifact markers and actual
slot operations are required before claiming hardware-path correctness.

Suggested paper description: a minimal encrypted-data read/validate task is
assigned by a Master through protected TSR slots to one or three Worker enclaves.
With matched storage, input, cryptography and validation, compare blocking OCALL
execution with dual-buffer asynchronous service, then parallel asynchronous
Workers. Measure Master first dispatch through final validated aggregation and
show a separately instrumented timeline. Fill numerical gains only after board
measurements; describe observed overlap, not guaranteed acceleration.

## Cipher Profile and Attribution

The preceding board GCM preview measured 65.933s Sync1, 64.931s Async1 and
22.165s Async3; actual Async1 read/processing overlap was only 0.788s. The
protected handoff succeeded, but its existence cannot create more I/O waiting
to overlap. Total times and overlap alone do not prove an on-CPU GCM breakdown.

V2 defaults to the existing production `eapp/aes_core.c` ECB implementation,
with an untimed AES known-answer test and unchanged all-byte FNV validation.
This aligns the motivation with the main ECB performance profile instead of
requiring the security fixture's GCM cost in every task. `--cipher aes-gcm-128`
preserves the heavier profile. All three configurations within a comparison
always use the SAME cipher, input, checks and backend. No injected storage
delay, weakened Sync engine, hidden threshold or predicted gain is used.

Cipher is explicit in samples/summary/timeline/environment and in each result
subdirectory name. Mixed-cipher analysis fails. V4 uses wire marker v7,
task protocol v4 and measured architecture CSV 8; stale binaries are rejected.
Old schema-5/6/7 files remain readable but are never relabeled or pooled.

GCM retains tag authentication and identity checking. ECB has no tag security;
its unused tag bytes are zero and checked as fixture metadata. Only the last
partial ECB record is padded to 16 bytes; plaintext length and validated bytes
stay unchanged. All six allowed data sizes are already multiples of 16, so
at the default 64KB, 500MB has 7630 reads and 500488320 ciphertext bytes. This change
does not improve I/O counts, add clustering, or change main benchmark ciphers.

The analyzer now reports read-service sum/union, capture/decrypt/check processing
sum/union, and wall time outside these intervals. Processing is measured wall
time, not isolated crypto CPU cycles. Multi-Worker sums can exceed wall time.
The residual includes task dispatch/aggregation, scheduling and control gaps;
it is NOT automatically a protocol bug. Existing v1 trace directories can be
reanalyzed without rerunning their workload:

```sh
python3 ./motivation/summarize.py /motivation-architecture/diagnostic-cold-20010103-231549-17736
```

Report the actual measured gains or regressions for each cipher. In particular,
an ECB gain would not establish a comparable GCM gain, and local native speedup
does not establish board speedup. Keep the valid small-gain GCM observation.
