# SQLite Benchmark Enclave Integration Plan

The native RISC-V baseline is built by `build.sh` and runs as a normal Linux
process on the board. Enclave execution needs a separate target because the
current benchmark uses SQLite's POSIX file-backed VFS, while the eapp runtime
does not provide a normal Linux filesystem.

## Required Modes

- `native-riscv`: `sqlite-bench` runs outside the enclave on board Linux.
- `single-enclave`: one Main enclave runs the selected SQLite workload.
- `dual-enclave`: Main and Slave enclaves cooperate on the selected SQLite
  workload according to an explicitly defined partitioning policy.

## Recommended Enclave Model

Use an application-defined SQLite VFS instead of the default Unix VFS.

For a first valid enclave benchmark, use an in-memory page VFS:

- SQLite engine and benchmark loop execute inside the enclave.
- SQLite database pages are stored in enclave memory.
- The host only passes benchmark configuration and receives timing results.
- This measures enclave CPU/runtime overhead without host filesystem noise.

For a secure-storage benchmark, use a host-backed page VFS:

- SQLite still executes inside the enclave.
- SQLite page reads/writes are served by host OCALLs.
- Page contents are optionally encrypted/decrypted in the enclave.
- This measures end-to-end secure storage overhead, but it is no longer a pure
  SQLite CPU benchmark.

## Single-Enclave Semantics

Single enclave mode should run the full workload in Main enclave only:

```text
host -> Main enclave: workload, num, reads, value_size, db_backend
Main enclave -> SQLite benchmark loop
Main enclave -> host: per-workload micros/op
```

This gives a direct comparison with native Linux:

```text
loss = ((single_enclave_us - native_us) / native_us) * 100
```

## Dual-Enclave Semantics

A single SQLite database cannot safely be mutated by two independent enclaves
unless the database/page ownership policy is defined. Use one of these models:

- `dual-sharded`: Main and Slave run independent SQLite databases on disjoint
  key ranges, then aggregate throughput. This measures parallel enclave
  capacity, not single-database latency.
- `main-sqlite-slave-storage`: Main runs SQLite; Slave handles page crypto or
  storage processing. This keeps single-database semantics but measures a
  storage-pipeline design, not two SQLite engines.

Do not report dual-enclave results as "one SQLite database running in two
enclaves" unless a page-level concurrency protocol and ordering guarantees are
implemented.

## Output Contract

All modes should emit the same result format:

```text
fillseq      :      23.839 micros/op;    4.6 MB/s
fillseqbatch :       1.433 micros/op;   77.2 MB/s
...
```

`compare-keystone-sqlite.py` can then compute native vs single/dual overhead.
