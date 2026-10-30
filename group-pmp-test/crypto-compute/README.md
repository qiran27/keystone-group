# Single Worker Crypto Compute Benchmark

Run from the deployment directory:

```sh
sh ./run-crypto-compute-bench.sh
sh ./run-crypto-compute-bench.sh 3 sweep
sh ./run-crypto-compute-bench.sh --cipher aes-gcm-128 3 sweep
sh ./run-crypto-compute-bench.sh --cipher chacha20-poly1305 3 sweep
sh ./run-crypto-compute-bench.sh 1 60MB
sh ./run-crypto-compute-bench.sh 3 500MB /crypto-compute-bench
```

Without `--cipher`, an invocation completes all ECB measurements, then all GCM
measurements, then all ChaCha20-Poly1305 measurements. These run sequentially,
never concurrently. Use `--cipher` to select just one algorithm, or `--cipher all`
to explicitly select the default. The default sweep encrypts and decrypts
60/100/200/300/400/500 decimal MB, three measured samples each: 36 per cipher,
108 in total. The implementation uses the same ECB bulk
functions and benchmark AEAD functions as the production workers, with the same
compiler options. GCM/ChaCha encryption includes tag generation; decryption
includes authentication and fails if verification fails. ECB is unauthenticated.

One Worker executes on a leased worker hart. An inactive group owner reserves
an identically sized EPM image; it performs no task or benchmark computation.
The Host remains on the housekeeping CPU. Each sample initializes new enclaves.
Startup revision 2 resolves the worker hart only after topology configuration.
Both members reserve three page-rounded private buffers plus 4 MiB of runtime
headroom: this SDK charges BSS against free memory, not ELF file bytes. Rebuild
and deploy the runner, worker and script together; startup markers reject old binaries.
SM member-runtime and rdtime clocks report CPU and elapsed transform time;
raw cycle differences are diagnostic and may include preemption intervals.

Input, ciphertext and output are three private, aligned 2,000,000-byte EPM
buffers. MB denotes cumulative processed bytes, not a 500 MB resident allocation.
A deterministic synthetic block is reused while authenticated identities and
encryption nonces advance for each block within a sample. Keys are public
test keys, scoped to this synthetic experiment; this is not secure key setup.
The measured intervals include only calls to the existing transform APIs,
including their nonce/AAD construction. Preparation, key/context setup, KATs,
one warmup pair, input encryption for decrypt tests, full-byte roundtrip checks,
cleanup and exporting scalar counters are outside the measured intervals.
All blocks are validated, not only a sampled edge or final block.

There are no measured OCALLs, storage operations or plaintext transfers to UTM.
Both input and ciphertext are already private; the benchmark therefore omits
the UTM ciphertext snapshot required by the production AEAD read path. Pure
crypto throughput is not full-system or storage throughput and does not include
those transfer, copy, scheduling, metadata or I/O costs.

Each run creates a unique directory under `/crypto-compute-bench/` containing:

- `samples.csv`: all real measurements and validation status.
- `summary.csv`: per size, algorithm and direction, actual min/median/max elapsed
  time, CPU time and MB/s. CPU throughput excludes descheduled ticks; wall
  throughput includes them within transform intervals.
- `comparison.csv`: side-by-side throughput min/median/max for all selected algorithms by size/direction.
- `plan.csv`, per-sample logs, build hashes and environment records.

Round order alternates encryption and decryption. Failed or missing
samples stop the run and prevent successful aggregation; no substitution occurs.
An all-cipher sweep produces 36 summary rows and 12 comparison rows only after
all 108 samples pass validation. Raw samples/logs remain available on failure.
Only summary CSV files are written by the Host; the measured data stays private.
The worker timeout defaults to 600 seconds per sample (including untimed checks),
overridable with `GROUP_PMP_CRYPTO_COMPUTE_TIMEOUT_SEC` in 10..3600 seconds.
`CRYPTO_COMPUTE_DRY_RUN=1` prints the plan without launching a workload.
