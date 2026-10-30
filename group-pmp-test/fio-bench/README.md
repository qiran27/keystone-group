# fio workload sources (import stage)

This directory stages upstream fio source and workload job files. The
`run-fio-enclave-scaling.sh` adapter translates the five `rw`/`bs` profiles
into the existing 1-15 worker-enclave Sync/Async/Adaptive request path. It
does not link or execute upstream fio inside an enclave. Results from running
upstream fio directly on the Host must not be presented as enclave results.

## Upstream source

- Project: https://github.com/axboe/fio
- Version: `fio-3.28`, tag commit
  `d5c485cf899c8db071d4a42cba2373e862fe0e55`
- Release archive: `dist/fio-3.28.tar.gz`, downloaded from
  `https://brick.kernel.dk/snaps/fio-3.28.tar.gz`
- SHA-256: `859dca5241e5494d86c4aa1531a984cc556789c78e56b30d6070acfbdd193a8c`
- Extracted source: `vendor/fio-3.28/`
- Licensing: upstream `vendor/fio-3.28/COPYING` (GPL-2.0) and
  `vendor/fio-3.28/MORAL-LICENSE` are preserved.

The archive and license hashes match the existing
`buildroot/package/fio/fio.hash` recipe. The source snapshot has not been
patched. The upstream download site's TLS certificate was expired when
fetched, so the archive was accepted only after the pinned Buildroot SHA-256
matched. Both the archive and extracted files are retained to make that
provenance independently checkable.

## Workload definitions

`jobs/*.fio` are standalone fio job files and enclave workload references.
They use `${FIO_FILE}` and `${FIO_SIZE}` so no target path or data size is
hard-coded. Set both variables before using upstream fio. `numjobs=1` is
intentional: worker-enclave count is selected by the Keystone harness, not
by fio processes. Each job defines one operation class and block size; the
enclave harness holds its address stream, total data volume, cache mode,
encryption and storage directory constant across all three modes.

The sequential jobs use 2,000,000-byte requests and the 100k read job uses
100,000-byte requests, matching the enclave's decimal-byte UTM limits. Their
filenames retain the short `2m`/`100k` labels. `4k` means 4,096 bytes.
The enclave adapter validates these fields before running; fio's native
random generator is **not** reproduced by the enclave adapter. The enclave
uses the existing deterministic `locality-random-v1` address stream in all
three modes. Do not claim native fio and enclave profiles replay the same
random trace, or use native fio results as evidence for enclave clustering.

The read jobs require an existing file of the requested size. Pre-create it
outside the measured interval. Running upstream fio write jobs directly
creates ordinary Host-visible data, **not encrypted enclave output**. Use a
disposable file only; do not use a production database or benchmark ciphertext
file as `${FIO_FILE}`.

## Enclave profile run

Deploy the rebuilt runner and the five job files, then on the board run:

```sh
./run-fio-enclave-scaling.sh rand-read-4k all 15 5 60MB cold
```

`all` runs Sync, Async and Adaptive with the same total byte count and
address rule. Storage now defaults to `FIO_ENCLAVE_STORAGE=local`, with
private benchmark data under `/tmp`, matching the SQLite default. On this
board `/tmp` is tmpfs: this measures a RAM-backed encrypted pipeline, NOT
SD card or USB disk bandwidth. Job definitions default to the script's
deployment directory (or `fio-bench/jobs/` in the source checkout). Override
these separately with `FIO_ENCLAVE_JOB_DIR` and `FIO_ENCLAVE_STORAGE_DIR`.
Full, unmodified performance and Host-operation CSVs are written directly
to `/fio-bench/` for both local and USB data storage. Override this single result directory with
`FIO_ENCLAVE_OUTPUT_DIR`. To restore USB testing:

```sh
FIO_ENCLAVE_STORAGE=usb \
FIO_ENCLAVE_DIR=/myusb/wj/deploy \
FIO_ENCLAVE_OUTPUT_DIR=/myusb/fio-bench \
  ./run-fio-enclave-scaling.sh rand-read-4k all 15 5 60MB cold
```

The legacy `FIO_ENCLAVE_DIR` overrides both job and data directories;
the separate job/storage variables take precedence. For actual SD testing,
use `FIO_ENCLAVE_STORAGE_DIR=/root/fio-data` and confirm its mount with `df`.
The job directory must exist, be readable, and contain the selected `.fio`
files; it need not be writable. Data and result directories are created if
necessary and must be writable. USB
mode retains the check rejecting root-filesystem data; results may be on the root filesystem. Local mode
does not require a USB mount. Each job run creates a private temporary
data directory, removed after that job finishes or fails. The script logs
the selected paths and `df -P` storage device before running. Each mode
produces one full performance CSV and one Host-operation CSV in the same
result directory. All values, including unexpectedly high or low samples,
remain as measured. There is no anomaly filtering, estimation or derived
comparison copy. The former separate raw-directory setting is no longer
used. No `-analysis.csv` is generated.
Read-data preparation is outside the measured interval.

To run all six sizes in order, use `sweep` instead of a single total size:

```sh
./run-fio-enclave-scaling.sh all all 15 5 sweep cold
```

This runs 60, 100, 200, 300, 400 and 500 MB with five repetitions per
worker count. For a one-repetition preview, change `5` to `1`. The shorter
form `./run-fio-enclave-scaling.sh all all 15 sweep cold` also defaults to
five repetitions. Each size gets distinct CSV names in the result
directory; the private data for each job is removed before the next job
starts, so the six sizes do not retain six simultaneous ciphertext datasets.
The Sync path retains its SQLite ciphertext-BLOB storage, while Async and
Adaptive use their existing external ciphertext extent file plus SQLite
metadata. Thus this is a three-mode **end-to-end enclave system** comparison,
not a pure device-service fio comparison or an isolated clustering ablation.
The `ioengine=sync`, `direct=0` options in the fio files apply to native fio;
the enclave adapter uses its own mode and cache arguments.
`cold` means buffered I/O with cache invalidation after prefill, not a
guarantee that a physical device's own cache is cold. On tmpfs there is no
physical disk-cache interpretation of `cold`. For a profile-only check,
use `FIO_ENCLAVE_DRY_RUN=1 ./run-fio-enclave-scaling.sh all all 15 1 60MB cold`.
The adapter accepts `direct` only for the page-aligned 4 KiB profiles; the
decimal 2,000,000- and 100,000-byte jobs have different alignment behavior.

## Remaining integration

1. Build fio for the board through the existing Buildroot package or the
   staged source, and establish a board-side reference result.
2. Add exact native-fio random trace replay if byte-for-byte address-stream
   equivalence with the upstream fio binary is required. The current adapter
   translates operation class and block size, not fio's random generator.
3. Validate three-mode 1-15 results on the board. A successful rebuild or
   shell check alone does not establish board correctness or performance.

No build or benchmark result is claimed by this import.

## Deployed job files

`rebuild-and-test.sh` copies the five `.fio` files directly into its generated
`deploy/` directory and verifies them byte-for-byte. On the board,
`run-fio-native-reference.sh` looks in `/myusb/deploy/` by default; set
`FIO_JOB_DIR` to override. `--check` only checks the files. This is a **Host
native reference**, not the enclave three-mode comparison. Read jobs require
an existing prefilled file; write jobs refuse to overwrite one by default.
