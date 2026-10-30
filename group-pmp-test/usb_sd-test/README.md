# SD card and USB file-I/O benchmark

This is a standalone host-side RISC-V Linux benchmark. It does not enter an
enclave or exercise the SQLite Sync/Async/Adaptive implementations. It creates
one private temporary file per target directory and removes that file after
testing or on a handled interrupt. It never writes a raw block device or an
existing file.

## Build

From this directory on the development machine:

```sh
sh ./build-riscv.sh
```

`RISCV_CC=/path/to/riscv64-buildroot-linux-gnu-gcc` overrides toolchain
discovery. The default output is `usb-sd-bench.riscv64`; an optional first
argument changes the output path. The bundled VisionFive2 Buildroot toolchain
is discovered when this repository is beside `VisionFive2_devl`.

Running `../rebuild-and-test.sh` also builds this executable with its selected
Buildroot RISC-V compiler and copies it to `../deploy/usb-sd-bench.riscv64`.
The deploy manifest includes its SHA-256 hash. The rebuild script does not run
the storage benchmark automatically.

Copy the binary to the board, then verify `/var/tmp` really resides on its SD
card and `/myusb` is a mounted USB filesystem. Adjust `--sd-dir` if the board's
root filesystem is an initramfs, overlay, or another device. The program
rejects tmpfs by default and rejects identical filesystem device IDs for SD
and USB. These checks cannot prove the physical medium, so also inspect
`findmnt` or `/proc/mounts` on the board.

```sh
./usb-sd-bench.riscv64 --device both --sd-dir /var/tmp --usb-dir /myusb \
  --size 128MiB --seq-block 1MiB --rand-block 4KiB \
  --cache cold --repeat 3 --output /myusb/usb-sd-results.csv
```

If `/var/tmp` is not on SD, use a writable SD-backed directory. For a quick
smoke test, use `--size 8MiB --repeat 1`; statistical comparisons need multiple
runs and controlled filesystem/device conditions. `--device sd` and
`--device usb` run one target. `--allow-same-fs` and `--allow-tmpfs` are only
for intentional test environments, not for an SD-versus-USB comparison.

## Workloads and interpretation

Each repetition runs sequential write, sequential read, random write, and
random read. The entire file is accessed in each case. Random offsets are a
fixed-seed, no-replacement permutation, shared by both devices. The benchmark
uses synchronous `pread`/`pwrite` with queue depth one. It measures file I/O
through the mounted filesystem, not raw-media throughput or `fio` results.

The CSV contains per-request latency P50/P95/P99, IOPS, data-operation MiB/s,
and write `fdatasync` time. Write `mib_per_second_with_sync` includes the final
`fdatasync`; the read value is the same as its data-only throughput. File
prefill and read-cache preparation are outside the measured operation. A
write test leaves the complete file initialized for the subsequent reads.

`--cache hot` warms reads through the page cache. `--cache cold` calls
`fdatasync` and `POSIX_FADV_DONTNEED` before each read; this requests page-cache
eviction but cannot guarantee a physically cold device. `--cache direct`
uses `O_DIRECT` and requires 4 KiB-aligned block sizes and a filesystem that
supports it. Writes are still explicitly synchronized. Results from these
cache modes are not interchangeable.

Do not store the results CSV inside a directory with insufficient free space.
The output file is created exclusively so an existing CSV cannot be overwritten.
