# RV8 Compute-Only Enclave Benchmarks

Version: compute adapter / CSV v2, 2026-10-13.

The upstream Makefile lists eight programs: aes, bigint, dhrystone, miniz,
norx, primes, qsort, sha512. Its README omits bigint. All eight kernels are
now available; the custom transfer workload is removed from the build and CLI.
These are bounded enclave adaptations of the upstream algorithms, not the
unmodified upstream standalone executables or their default problem sizes.

## Execution

Sync and Async both run the identical compute-only path. Input and algorithm
output stay in private EPM. There is no workload file, SQLite operation,
storage encryption, data OCALL, registered data buffer, or payload Data UTM.
The aes benchmark itself still performs its own encrypt/decrypt round trip.
The two labels preserve the experiment interface; there is no asynchronous
I/O speedup mechanism in this experiment. Any small difference between labels
must be assessed as repeated-run variation rather than attributed to I/O.

The existing Master/Worker task protocol uses protected TSR descriptors and
checksum metadata. A 4 KiB control UTM carries setup, state, timing, byte counts
and validation digest only. This is necessary to collect results; no computed
payload, sorted array, compressed data or ciphertext is exported. The Master
uses two control OCALLs around the measurement. Host CSV/log writes and enclave
loading are administrative operations, not measured workload data I/O.

All kernels operate in bounded private blocks of at most 64 KiB. The original
enclave arena is 1 MiB, reset after each block; bigint's C++ allocations also
use that arena. The input template is generated before the WARMED barrier,
with the same bytes and policy in both labels.

| Kernel | Measured work and validation |
| --- | --- |
| aes | Upstream software AES-128 block encryption, decryption, full comparison and checksum; AES known-answer self-test. |
| bigint | Upstream Nat exponentiation and decimal conversion; for a block of n work bytes, compute 23^ceil(n/64), verify its low limb by independent modular multiplication, retain a decimal checksum. Maximum exponent is 1024 per block. |
| dhrystone | Upstream Proc0/Proc1..8/Func1..2, n iterations per n work bytes; validate final integers, characters, record and arrays. Private static records replace heap allocation; initialize String1Loc, omitted by the supplied main. No gettimeofday or printf in the kernel. |
| miniz | Upstream compression/decompression, compare every recovered byte and retain checksum. File/archive APIs disabled. |
| norx | Upstream NORX encryption/authenticated decryption and complete comparison; retain the existing corrected tag check and corrupted-tag self-test. |
| primes | Upstream bitmap-sieve method over 8*n-1 integers per n work bytes; zero bitmap and use defined 64-bit shifts, sieve through sqrt(limit), independently validate the last prime. No file or allocator calls. |
| qsort | Upstream qsort on independent uint32 blocks; validate ascending order and sum/XOR preservation, retain checksum. This is not a global 500 MB sort. |
| sha-512 | Upstream SHA-512 init/update/final for each block; retain digest, empty-message known-answer self-test. This is not a single 500 MB message hash. |

The six size labels remain 60, 100, 200, 300, 400 and 500 decimal MB,
fixed total across workers. For bigint/dhrystone/primes these are **work-scale
units**, not actual file bytes. For the other five kernels they count input
bytes once, including round-trip kernels. Do not interpret their MB/s as
storage bandwidth or compare work-unit rates between unrelated algorithms.
The reused task descriptor divides work in 240-byte units; actual total_bytes
is rounded down by less than 240 bytes and is recorded in every CSV.

There are three physical Worker lanes; 4..15 enclaves share those lanes.
Total time is Master first dispatch to final aggregation, including kernel,
validation, scheduling and task protocol. Kernel CPU time separately sums SM
execution-clock deltas, excluding descheduling. Warmup, generation, loading and
CSV writes are excluded. No storage AES time is charged to either mode.

## Build And Run

Build and deploy using `./rebuild-and-test.sh`. It builds/copies all eight
workers and the updated runner and script. Stale v1 artifacts are rejected.

```sh
sh ./run-rv8-enclave-scaling.sh all both 15 1 60MB
sh ./run-rv8-enclave-scaling.sh all both 15 5 sweep
sh ./run-rv8-enclave-scaling.sh bigint both 15 3 100MB
```

Arguments: kernel, labels (sync/async/both), max workers (1..15), repetitions
(1..20), size/sweep, optional output directory. `sha512` aliases `sha-512`.
Default output is `/rv8-bench/`, overridable by the final argument or
GROUP_PMP_RV8_OUTPUT_DIR. Eight kernels, six sizes and two labels generate
separate summary/sample/log files and one same-N comparison per kernel/size.
Medians/minima/maxima come from real samples. Data I/O, storage AES, doorbell
and completion-wait columns remain for compatibility and must all be zero.
I/O reduction is blank in comparisons because its denominator is zero.

CSV version 2 must not be pooled with v1 encrypted-storage results. Pure
compute measurements cannot establish Sync/Async storage or overlap benefits.
Local tests cover kernels, exact processed work, task ownership, malformed
descriptors, control-only writes, wrapper combinations and source staging.
Actual RISC-V build and board timing remain to be checked after deployment.
