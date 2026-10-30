# Security Experiments

The current `scan` entry uses a fixed 1 MB, three-mode, N=1/4, one-repeat
extended capture protocol. Read [EXTENDED_CAPTURE.md](EXTENDED_CAPTURE.md) for
the exact board-kernel observer build, separate regional controls and independent
offline verification. A captured run is not automatically a scan PASS. Current
SQLite workload cipher support is ECB; standalone AEAD fixtures do not make the
GCM/ChaCha workload combinations supported. No fio conclusion is added.

The isolation and integrity fixtures below remain unchanged. The old scoped
scanner binary is retained for reproducing initial evidence, not executed by
the new scan entry or counted as expanded Host/kernel coverage.

## Build and Run

Build in the Linux VM with `./rebuild-and-test.sh` and the exact board kernel
setting in EXTENDED_CAPTURE.md; deploy the collector, observer/driver, runner,
SQLite worker, security eapps, runtime and script together, not the script alone.
Host EPM testing requires the existing nofault driver capability. Absence is
SKIP, not PASS; never use the historical destructive EPM memcpy/memset ioctl.

On the board, from the deployment directory:

```sh
./group-pmp-test-runner --security-crypto-info
sh ./run-security-experiments.sh all 4 1 /myusb/security-1MB-all-01
```

Arguments: `all|scan|isolation|integrity|verify`, fixed selector `4`, attempts (`1` or `3` for
scan/all, 1..1000 for isolation/integrity),
and a NEW result directory. Scanning strictly tests N=1 and N=4, not a 1..4 sweep.
The scan fixes configured input at 1 MB for readrandom/fillrandom and all three
modes; complete 240-byte records account for 999,840 effective bytes. Security
batches are eight descriptors, ensuring both UTM slots and reuse at N=4.
Isolation/AEAD have their own fixed topology/repetitions, not an N sweep.
There is no 60--500 MB sweep in security testing. After copying evidence to an
independent machine, the same entry's `verify` mode performs offline matching.
Capture success returns 3 (pending verification), not an overall PASS.
The verifier also produces `verified-summary.txt` for compact screenshots.
Existing 500 MB evidence remains historical and is not relabeled as this run.

Host mapping snapshots now briefly stop the target Host thread group, enumerate
and read its mappings, then resume it. `process-stops.csv` records the interval
and the verifier checks read timestamps. This avoids heap shrink races without
ignoring missing pages. It does not freeze kernel I/O or establish continuous
coverage. Updated scripts require collector `security_capture_process_stop=1`
and runner `security_capture_ring_accounting=2`; deploy both together.

The capability line must report `security_fixture_version=7`,
`security_gcm_memory=inline-block-cipher`,
`security_aead_ocall=9`, `security_scan_scope=registered-ciphertext`,
and `security_aead_execution=exclusive-worker-lease`. OCALL 9 is inside the
SDK's 10-slot table. Historical invalid slot 17 is not used.
The scanner retains `security_scanner_fixture_version=4`; these are separate
capability versions. Rebuild the SQLite worker too: runner-only deployment does
not install the explicit pre-WARMED diagnostic stdout flush.
The run lock, lease cleanup, evidence overwrite refusal and nonzero failure exit
remain. Preserve serial captures: some SM/PMP messages are absent from dmesg.

## Initial Plaintext Scan: Historical Explicit Scope

Workers construct a run-specific 64-byte sentinel inside EPM and process it through
the real ECB pipeline. The parent scanner reconstructs it from the public nonce
and execs the runner as its child, avoiding inherited scanner-marker contamination.
An intentional positive-control page is separately counted.

Only these targets are scanned:

- Control UTM and both Data UTM buffers, registered after Host mapping exists.
- Explicitly registered temporary Host ciphertext read/scatter storage, when allocated.
- Regular files in this experiment's dedicated ciphertext/SQLite directory.
- The isolated positive-control mapping.

There is no entire heap/stack/library scan, no io_uring kernel-ring copy or scan.
EPM, protected TSR, unregistered process memory and kernel mappings are excluded.
Removed v3 snapshots are not silently counted as covered.
`host_buffer_bytes=0` may mean no staging buffer was sampled on the direct-UTM path,
not whole-Host coverage. Registration ends before the buffer storage is freed.

Registered ranges are read through `/proc/<runner>/mem` every 100 ms and at a
pre-destroy checkpoint. Host waits for ACK before UTM destruction. Reads carry
63 bytes across chunks to catch boundary-spanning markers. Short-lived buffers
can exist between samples and be missed; observations are not atomic/continuous.

PASS_OBSERVED_SCOPE requires successful workload execution, during-run UTM
coverage, completed checkpoint, both UTM classes/files scanned, positive control
detected, zero unintended hits and no checkpoint read errors. Unintended hits
are FAIL; missing coverage/errors are INCOMPLETE. Live mapping races stay logged.
Sentinel/foreign-slot diagnostic output is explicitly flushed before WARMED,
including with redirected stdout. A flush failure aborts the workload; strict
VFS counts are not relaxed. This prevents buffered diagnostic output from being
mistaken for measured VFS traffic at worker exit.

Report only: "No plaintext marker was observed in the recorded regions and
sampling periods; the positive control was detected." Do not claim absence of
transient leaks, unscanned-memory leaks or side channels. ECB is not authentication.

## Access Isolation and Revocation

The existing eleven cases remain: authorized Master/Worker control; Host EPM/TSR;
Worker EPM read/write; unacquired TSR read/write; cross-lane TSR read/write;
revoked Master TSR read/write. Immediate raw-fault fixtures retain their tested
saturation entrance. The authorized control uses the production 3W1HM lease,
real per-task dispatch and verified aggregation.

Host probes use recoverable exception-table nofault accesses. Host EPM requires
`security_nofault_epm`; absence is SKIP. Raw enclave probes record attempted
address, operation and permission state in UTM before access. The runner checks
matching EID and FAULT or runtime page-fault EXIT(-1) before destruction.
Setup returns/access-completed returns fail. EXIT(-1) alone is not proof of a
PMP trap: correlate serial fault address/cause. Page tables may also enforce faults.

N=4 scan workers additionally test foreign task-slot grant/metadata denial.
Own metadata queries succeed; foreign metadata must return SM NOT_ACCESSIBLE.
Warm FREE-slot acquisition also has state/epoch prerequisites: denial alone does
not prove rejection of every valid foreign READY task. Ordinary context switching
is not revocation evidence.

## Independent AEAD Integrity Fixture

AES-128-GCM and ChaCha20-Poly1305 execute in a separate worker with Mbed TLS 3.6.7
KATs. They do not replace AES-128-ECB in SQLite, fio or MediaBench performance.
Public test keys, run-local nonce counters and trusted expected AAD are fixtures,
not production key establishment or persistent freshness management.

AEAD uses the existing exclusive 3W1HM worker lease. Only the selected worker is
enqueued; dummy peers establish group membership/EPM capacity but do not run.
Host CPU0 handles OCALL/EXIT via `groupWaitEvent`, with a 120-second overall
fixture deadline and a lease-release attempt on every post-acquisition exit.
Long crypto no longer occupies online Linux CPU1 through `groupRunHart`.
Logs show lease activation, worker entry before KATs, scenarios and terminal/release.
The event's `value` is an opaque SM resume token, not an SDK OCALL number.
Validate OCALL 9 from the UTM edge header, then resume with the original event
token. Tokens such as 107/108 must not be rejected merely for differing from 9.
Each worker executes the selected algorithm's upstream self-test. The GCM and
ChaCha fixtures together still exercise both KAT suites; the ChaCha fixture
does not first depend on the unrelated GCM allocator/self-test path.

Fixture v6 writes a small diagnostic progress record at UTM offset 2048,
separate from the edge arguments and ciphertext packets at offset 4096. It
contains only magic, algorithm, iteration, scenario and stage, never secrets.
There is no extra progress OCALL or new event/SM protocol. A progress-copy
failure fails the fixture. Host logs successful resume requests and a bounded
best-effort progress snapshot before lease release, including after timeout.
Neither a stage record nor a successful resume ioctl counts as an AEAD PASS.

Stages distinguish config-sent/config-returned, kat-started/kat-finished,
scenario-started, snapshot-ready, mutation-returned, open-finished,
report-returned and worker-finished. A last observed stage localizes the
continuation; it does not alone prove the cause is crypto rather than scheduling.
The 120-second deadline and all authentication/output-ownership checks remain.
The v5 board run passed the scoped scan and eleven isolation cases. The v6
board evidence passes all nine ChaCha20-Poly1305 scenarios and a clean worker
exit, but GCM times out at kat-started with zero reports. This localizes the
remaining failure to the GCM self-test continuation, not the initial OCALL.

Fixture v7 uses Mbed TLS's upstream block-cipher adapter, embedding the AES
context in private enclave memory instead of allocating it through the generic
cipher API. No upstream self-test vectors or authentication checks are removed.
Native regression with the real SDK allocator/string functions also passed
under the old generic configuration, so allocator failure is not an established
hardware root cause. The inline configuration removes that dependency; hardware
success remains pending. Performance workers, SDK, SM and CFS are not changed.

To rerun only the outstanding integrity fixtures after rebuilding/deploying:

```sh
sh ./run-security-experiments.sh integrity 4 1 /myusb/security-aead-04
cat /myusb/security-aead-04/aead-gcm.log
cat /myusb/security-aead-04/aead-chacha.log
```
All four members reserve 4 MiB free EPM so the dummy master cannot undersize the pool.

Each algorithm executes nine scenarios per repetition:

1. Unmodified input accepts, matching EPM plaintext (positive control).
2. Ciphertext bit flip rejects.
3. Tag flip rejects.
4. Nonce flip rejects.
5. AAD flip rejects.
6. Valid block from another range rejects.
7. Valid block from another object rejects.
8. Host mutation before EPM snapshot rejects, application output untouched.
9. Mutation after snapshot cannot alter it: consume only the authenticated EPM
   snapshot, not a second read of modified UTM.

AAD binds object/file/offset/length/generation to trusted expected identity.
Decrypt to EPM scratch; copy application output only after verification.
Failure leaves poisoned application output unchanged, reports no valid result
and wipes scratch. Logs include expected_accept, accepted, output_changed,
consumed_verified_snapshot and valid_result. No plaintext is exported via OCALL/TSR.
This standalone fixture does not certify an AEAD production storage/TSR path.
Two mutation timings are not exhaustive race fuzzing. No anti-rollback claim;
ECB production paths cannot inherit fixture authentication results.

## Results and Verification

`security-results.csv` records prerequisites, actor, target, expected/actual,
attempts and evidence. Logs, scan CSVs/manifests, artifact hashes and kernel logs
remain available. Sentinel performance/I/O CSVs only show exercised paths:
scanning changes timing/cache state, so these are not benchmark comparisons.

```sh
sh tests/run-security-tests.sh
sh tests/run-sqlite-io-regression.sh
```

Native tests cover real SDK dispatch, KATs, transport mutation/output gating,
eight access eapps under mock permissions, strict terminal evidence, scoped
scan leak/missing-coverage controls and syntax/contracts. An intentional
unregistered-memory leak demonstrates the scope limitation, not a security success.
Actual lease/RCU behavior, PMP faults, driver fixups and board scan/AEAD outcomes
require hardware execution. Native PASS/compilation do not certify board results.
