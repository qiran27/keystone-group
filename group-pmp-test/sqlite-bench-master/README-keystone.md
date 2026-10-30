# Keystone SQLite Benchmark Harness

This directory contains a C SQLite benchmark with bundled `sqlite3.c/sqlite3.h`.
It is preferable to the LevelDB C++ benchmark for Keystone experiments because it
does not require the system SQLite library.

## Native Baseline

Build for RISC-V board Linux:

```sh
cd /path/to/sqlite-bench-master
./build.sh riscv
```

Build for the current Linux host:

```sh
./build.sh native
```

Run the fixed workload set:

```sh
cd /path/to/sqlite-bench-master
./run-keystone-sqlite-native.sh
```

The default workload set is:

```text
fillseq,fillseqbatch,fillrandom,fillrandbatch,overwrite,readseq,readrandom,readrand100K
```

Useful overrides:

```sh
NUM=100000 READS=100000 DB_DIR=/myusb/sqlite-native ./run-keystone-sqlite-native.sh
```

## Result Comparison

After native, single-enclave, and dual-enclave logs have the same
`<workload> : <micros/op> micros/op` lines, compute overhead with:

```sh
./compare-keystone-sqlite.py \
  --native results/native.log \
  --single results/single.log \
  --dual results/dual.log \
  --csv results/sqlite-overhead.csv
```

The overhead formula is:

```text
((enclave_us_per_op - native_us_per_op) / native_us_per_op) * 100
```

## Enclave Integration Note

This benchmark still uses file-backed SQLite by default. Running it inside a
Keystone enclave requires a SQLite VFS/runtime decision:

- in-memory VFS: measures SQLite CPU/runtime overhead inside the enclave, but
  removes real filesystem I/O from the benchmark;
- host-backed encrypted VFS: keeps storage in the host/IPFS path and routes page
  I/O through enclave calls, matching the secure-storage design more closely;
- full file-backed SQLite inside enclave: requires a substantially larger POSIX
  filesystem/runtime port.

For dual-enclave measurements, a single SQLite database cannot safely be written
by two independent enclaves without defining a sharding or page-routing policy.

See `ENCLAVE-INTEGRATION.md` for the single/dual enclave execution plan.
