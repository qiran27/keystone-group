# Compact Plaintext Evidence Protocol v2

This protocol collects NEW evidence. It does not reinterpret the initial 53
registered-region snapshots, four checkpoints, zero negative hits and 53
positive-control hits as Host-process or kernel coverage. Those observations
remain a separate initial experiment. No new board result is available yet.

## Required Configuration

- SQLite readrandom and fillrandom; exactly N=1 and N=4; fixed 1 decimal MB
  configured input (1,000,000 bytes). The existing 240-byte record contract
  yields 999,840 effective bytes; both quantities are recorded explicitly.
  This replaces the earlier proposed 500 MB security input at the user's
  request. It is a small security fixture, not a performance measurement.
- Sync/Async/Adaptive, each supported workload/cipher combination repeated one
  time by default (or three times with the public entry's third argument `3`),
  using the existing address generator and post-prefill buffered cold-cache
  preparation. The private data root defaults to `/tmp`. Record actual mount
  information; `SECURITY_SCAN_STORAGE_DIR` selects another medium.
- Sentinel-enabled workers use at most eight descriptors per batch, without
  changing ring or UTM capacity. Even the smallest N=4 shard exceeds four such
  batches, exercising both slots and reuse. Normal performance batches and
  minimum-input rules are unchanged. The capture-specific minimum is 100 KB.
- Current workload cipher is AES-128-ECB only. The GCM and ChaCha20-Poly1305
  implementations are independent integrity fixtures, NOT these SQLite data
  paths under this capture protocol. At three repetitions, 108 is the full
  proposed matrix, not a completed result; 36 ECB negative runs are supported
  and 72 AEAD workload combinations are recorded as unsupported. Regional
  controls run once in a separate process for each of the 12 configurations.
  The default one-repetition run plans 36 negative combinations: 12 ECB runs
  and 24 unsupported AEAD workload combinations, plus 12 separate controls.
  Planned counts are not successful measurement counts.
- No fio, MediaBench, extra cipher workload port or new access/AEAD scenario is
  added. SQLite capture findings cannot be claimed as fio coverage.

## Build and Deployment

Use the exact **fully built, configured board kernel** with `Module.symvers`,
not a different kernel's headers or `modules_prepare` alone. In the build VM:

```sh
SECURITY_EVIDENCE_KERNEL_BUILD=/absolute/path/to/the/board/kernel/build \
  ./rebuild-and-test.sh
```

That optional setting builds the observer AND updated Keystone driver with the
Buildroot compiler, and copies `keystone_evidence.ko` and `keystone-driver.ko`
to deploy. Without the setting, source/build helper is deployed but no working
kernel observation is claimed. Existing examples still compile normally.
`SECURITY_EVIDENCE_CROSS_COMPILE` overrides the prefix when required.

Redeploy the full directory. Reboot with the updated Keystone driver, or reload
it using the board's established module-loading procedure while no enclave is
active; do not load a second Keystone driver instance. The observer obtains
only live EPM/TSR **range metadata** through the driver's exported interface.
It does not read these protected regions. The existing independent access tests
provide grant/revocation evidence; driver metadata is not itself a PMP proof.

On the board:

```sh
# New plaintext protocol only.
sh ./run-security-experiments.sh scan 4 1 /myusb/security-1MB-scan-01
# Alternatively, new plaintext protocol plus the existing isolation/AEAD cases.
sh ./run-security-experiments.sh all 4 1 /myusb/security-1MB-all-01
# Optional three repetitions of the same configurations and existing cases.
sh ./run-security-experiments.sh all 4 3 /myusb/security-1MB-all-three-01
```

The wrapper loads the supplied observer with `controls=1` if necessary and
unloads it only if it loaded that instance itself. Capture requires root,
CAP_SYS_ADMIN, and CAP_SYS_PTRACE for remote io_uring VMA inspection. Never use
this observation module in production. Before launching any workload, the
collector's `--preflight` checks the observer device, the driver's protected-range
metadata provider and read access to the dedicated control page with controls
enabled. Missing prerequisites stop `scan`/`all` with exit 2; details are saved
in `preflight.log` or `observer-load.log`. Preflight does not certify later page
coverage. Runtime read errors still remain coverage gaps. Raw content is
exactly deduplicated after hash-index lookup and byte comparison, but mapping,
allocation and read ledgers are retained for every snapshot. A configurable
`SECURITY_CAPTURE_MAX_BYTES` budget defaults to 2 GiB of unique content per run;
exhaustion is recorded as incomplete, never silently truncated into a pass.

The security wrapper uses the runner's normal 1,800,000 ms warmup budget.
Explicit checkpoint waits are excluded from the workload stall watchdog;
the 120-second checkpoint ACK limit and 3,600-second wall bound remain. These are
instrumented security timings, not throughput measurements for the paper.

All safety tests are entered through `run-security-experiments.sh`; capture,
observer and verifier helpers are internal, not additional benchmark suites.
Transfer the entire evidence directory to the independent trusted analysis
machine. Python is required on that machine, not on the board. From a copy of
the deployment/source scripts on the independent machine:

```sh
SECURITY_VERIFY_INDEPENDENT=1 sh ./run-security-experiments.sh verify 4 1 /path/to/copied/security-1MB-scan-01
# For `all`, the script finds its plaintext-evidence subdirectory automatically.
```

There is deliberately NO board-side plaintext search or automatic PASS after
capture. Successful capture means `captured-unverified`. An unexecuted or
unsupported combination has no hit count. The main `scan`/`all` entry returns 3
when independent verification is pending, not 0/PASS; actual workload/capture
failures remain nonzero failure states. The offline verifier reconstructs
the diagnostic marker from the run nonce; the negative Host never constructs
that marker. Markers are generated in EPM for the negative workload. The test
nonce and deterministic generator are diagnostic, not a secret/key scheme.
The target environment is restricted to the fixture's required settings to
avoid dumping unrelated inherited credentials. Use only the dedicated public
benchmark keys and inputs; do not run these memory dumps on a business process.

## Objects, Lifetime and Phases

1. `inventory.csv` is the mapping/allocation/reference inventory; `reads.csv`
   independently records actual successful reads and errors. Raw `/proc/maps`
   snapshots retain heap, stack, file-backed, anonymous, shared and io_uring
   mappings, including unregistered memory. No registration-only whitelist is
   used for process capture. Non-readable ranges are not silently excluded.
   An unbacked PROT_NONE reservation is recorded as not applicable only when
   pagemap successfully confirms neither a present nor a swapped page.
   Adjacent absent pages are recorded as one interval. Present PROT_NONE pages
   are still inspected; unknown, swapped or unreadable pages remain required.
2. Registered Control/Data UTM and temporary ciphertext allocations retain
   their add/remove lifetime log. PFN device mappings may fail `/proc/pid/mem`;
   at a synchronized Host checkpoint, their owner dumps live ranges while the
   allocation mutex prevents free/reuse of the mapping. `self.csv` explicitly
   links this alternative, phase, address, length and content file. It does not
   excuse unrelated unreadable Host mappings or missed periodic observations.
3. The module reads **referenced pages only**: `find_get_page` plus page reference
   and trylock for existing file cache pages; live io_uring VMA with mm/mmap
   lifetime retained, and a page reference; matching file-backed BIO pages while
   the BIO owns them at `block_bio_queue`. The module registers each discovered
   file mapping and holds a file reference. It records pre-queue copies, not an
   atomic image of a device or arbitrary kernel RAM. Kernel PFN mappings use the
   board's Linux 5.15 `follow_pfn` path; unsupported versions/VMAs are gaps.
4. BIO recording is bounded. Queue overflow, unavailable tracepoints, busy pages
   or unassociated bounce events remain errors/gaps. `block_bio_bounce` events
   are observed conservatively; a bounce event does NOT establish coverage of
   its private bounce page. In tmpfs there is no block-device BIO path, explicitly
   not applicable; file cache and process/UTM checks still apply. This does not
   claim coverage of unrelated device/controller-internal memory.
5. EPM and protected TSR metadata is recorded with physical start/length, group,
   epoch/type and group permissions. A process page matching a known protected
   physical range is excluded with that basis, not read. Per-task SM grants and
   revoke checks remain a separate experiment/log. Missing range metadata
   invalidates the expanded coverage conclusion.
6. Worker milestones report the first encryption completion, submit return,
   decryption completion, buffer consumption/reuse and exit. A submit-return
   marker is NOT proof that a disk operation is still in flight (particularly
   Sync). Host-visible events trigger checkpoints at existing OCALL boundaries;
   phase history logs transitions already missed at that boundary. Periodic
   running samples, pre-destroy, quiesced-before-destroy and after-cleanup
   checkpoints complement them. No claim of instantaneous EPM inspection or
   continuous coverage is made. Missed mandatory phases prevent full pass.
   For the 1 MB negative fixture, one explicit `running-sample` starts after
   the first encryption checkpoint ACK. Host process mapping capture briefly
   stops the target thread group with SIGSTOP and waits for the confirmed stop
   (at most five seconds) before obtaining maps and reading process pages.
   SIGCONT resumes it after those reads, including on error paths. This prevents
   Host heap shrink/unmap races between inventory and read. `process-stops.csv`
   records request, confirmed-stop and resume times; new-run verification requires
   process reads to lie within that interval. Kernel I/O and enclave execution
   are not claimed to be atomically stopped. File/kernel sampling remains separate.
   A missing stop or unreadable page remains a failed capture/coverage gap.
   The running sample is counted separately from periodic snapshots, never
   relabeled as a timer sample. Final cleanup capture stops periodic sampling
   before ACK to avoid process-exit races.
7. Active swap/core-pipe/crash-dump configuration is recorded. This implementation
   does not inspect those backends: enabled paths are explicitly incomplete,
   not covered or disabled by the script. Use a controlled image with these
   paths disabled if they are not part of the experiment, and retain evidence
   of that condition. Do not silently relabel enabled paths not applicable.

Module implementation follows the page-lifetime/local-mapping requirements in
the [Linux highmem documentation](https://docs.kernel.org/mm/highmem.html).
It provides no arbitrary kernel-address or `/dev/mem` read interface. Scanning
`/proc/pid/mem` is not substituted for kernel collection.

## Separate Regional Controls

Only the independent positive run constructs a known marker in the Host. After
the group is quiesced and before UTM destruction it plants markers in a live
heap staging allocation, stack buffer, unregistered anonymous mapping, shared
mapping, every registered Control/Data UTM, and the module's dedicated control
page. `positive-injected.csv` records each exact address/PFN and marker offset.
The regular collection paths must find all planted regions. Control buffers
are cleared/unmapped, UTM is destroyed, and the next negative run uses a new
process, new nonce and reset observer. Positive counts are not negative runs.

Offline controls validate their specific planted regions, not every incidental
mapping of the positive process. Incidental unreadable records remain preserved.
Any undetected planted marker or failed control/workload blocks negative pass.

## Results and Limits

- `planned-combinations.csv`: 108 planned combinations with three repetitions,
  or 36 with one; not measured totals.
- `execution-matrix.csv`: actual capture/unsupported/failed statuses, hit/control
  counters blank pending verification; individual configuration JSON, build and
  mount/swap/dump records accompany every executed run.
- `contents.bin`, `self-*.bin`, mapping files, registration log, inventory/read
  ledgers, phase history, protected ranges, gaps, run log and kernel logs are
  original evidence. `capture.csv` does not claim marker matching.
- `hits.csv`, `verification.json`, `verified-results.csv/json`, and file SHA-256
  fingerprints are produced on the verifier. Repeated bytes and deduplicated
  coverage are separate. Physical-page+offset identities are used when available;
  unavailable identities are explicitly virtual/object based, not invented PFNs.
  Host and kernel totals remain separate and mapping aliases remain in ledgers.
- `verified-summary.txt` is a compact screenshot view of actual verifier
  results: run ID, status, negative hits, positive detections and missing
  evidence. Progress is printed per run. It does not replace the full ledger.
- A negative hit is `PLAINTEXT_HIT`; missing/unreadable/invalid evidence is
  `COVERAGE_INCOMPLETE` or `EVIDENCE_INVALID`. Unsupported/not-executed are distinct
  from zero hits. Only verified complete regions and successful regional controls
  support `PASS_OBSERVED_EXTENDED_SCOPE`.

This is controlled test instrumentation in an untrusted-kernel threat model,
not a trusted kernel mechanism. A malicious kernel allowed to forge its own
logs/dumps can defeat this evidence. Independent matching and hashes do not
solve that problem. A trusted test supervisor/image is an experimental premise.
Even complete discrete observations do not prove absence of all transient
leaks, all untrusted-memory leaks or side channels. No rollback claim is made.
Use `PAPER_PLAINTEXT_TABLE_III.txt` only with its explicit pending-validation
label until real logs, denominators and all coverage checks are verified.
