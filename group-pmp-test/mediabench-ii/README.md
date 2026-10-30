# MediaBench II video/image source import

This directory pins the upstream MediaBench II video/image distribution for a
future 1-15 worker-enclave Sync/Async/Adaptive comparison. MPEG-4, JPEG-2000
and H.264 have private-memory codec adapters and six single-enclave board
workloads. This is not yet a MediaBench scaling runner.

## Provenance

- Maintainer page: https://cs.slu.edu/~fritts/mediabench/mb2/index.html
- Archive: https://cs.slu.edu/~fritts/mediabench/mb2/mb2_video.tgz
- Local archive: `dist/mb2_video.tgz` (95,625,596 bytes)
- Archive SHA-256: `681c554c25ee08bde62c0d3c19ab30ef5a07494b8f3a61c00a33212a32f7d6e8`
- Safe extraction: `python tools/extract_sources.py` into `vendor/`

The unpacked suite is `vendor/mediabench2_video/`. Its twelve workload
directories are `cjpeg`, `djpeg`, `jpg2000enc`, `jpg2000dec`, `h263enc`,
`h263dec`, `h264enc`, `h264dec`, `mpeg2enc`, `mpeg2dec`, `mpeg4enc`, and
`mpeg4dec`. Each has `input_base/` data. The codec source archives embedded in
that suite are also unpacked into `vendor/codecs/`:

| Suite archive | Unpacked root | SHA-256 |
| --- | --- | --- |
| `cjpeg/jpegsrc.v6b.tar.gz` | `jpeg-6b` | `75c3ec241e9996504fe02a9ed4d12f16b74ade713972f3db9e65ce95cd27e35d` |
| `jpg2000dec/jasper-1.701.0.zip` | `jasper-1.701.0` | `3593532a6dd812d665d7c04d8bb7851e01a9e168f6e851aa63a075f74baf703e` |
| `h263enc/tmn-1.7.tar.gz` | `tmn-1.7` | `638e9a5a7a6a234bb0735a4fc07dd8d8ed99d1b0525bd054614b4cf76548baa3` |
| `h263dec/tmndec-1.7.tar.gz` | `tmndec-1.7` | `349987594790494e70581064a7af40e3380ceefbe1d9cc75dcbd8c3363867060` |
| `h264dec/jm10.2.zip` | `JM` | `355c4450cea94c92dfe0bb48b4c1bd9ad2451d7600b0f818ba76100825faf0cc` |
| `mpeg2dec/mpeg2vidcodec_v12.tar.gz` | `mpeg2` | `e59da9988b2e964026c8370658771954a724e8319cc266f75c6aef2a85c40076` |
| `mpeg4dec/ffmpeg.2006_04_24.tgz` | `ffmpeg` | `d2636042da5614c99c2559e63eb1528ac979ecba4da898ad6a9be8d054b26003` |

The original compressed archives, README files, and license/copyright notices
remain intact. Each codec and input set must be reviewed under its own terms
before redistribution; this import does not assign a single license to the
whole suite. The outer archive includes 18 historical symbolic links, some
pointing to the original author's absolute home path. The extractor skips all
links, rejects unsafe paths and verifies the outer archive hash before writing.

## Porting boundary

The upstream scripts contain x86/OProfile assumptions and are not the
RISC-V/Keystone build. The later integration needs a small, explicit codec
selection, cross-build and deterministic input/output harness. For a fair
three-mode comparison, use identical inputs and work partitioning, prepare
decode inputs before timing, and define which encoded payloads cross the
encrypted Host-I/O boundary. Native MediaBench timing is not equivalent to
the enclave full-flow metric.

The first JPEG port has a bounded in-memory encoder/decoder in
`port/jpeg-memory.c`. It consumes RGB or JPEG bytes from caller-owned private
memory and writes to caller-owned private memory; it does not use `FILE*` or
expose pixels in UTM. `CMakeLists.txt` compiles the pinned IJG 6b source and
this adapter as `group-pmp-mediabench-jpeg`. The library is not yet linked to
a master/worker workload target, so its successful compilation alone must not
be reported as an enclave benchmark.

For MPEG-4, JPEG-2000, and H.264 encode/decode integration,
`rebuild-and-test.sh` stages the six corresponding `input_base/` directories in
`deploy/mediabench-ii/<workload>/input_base/` and compares each copy against
the source. It does not deploy the other six workload inputs, x86 profiling
output, or historical scripts.

## Private-memory codec adapters

- `port/mpeg4-memory.c` encodes/decodes a YUV420P frame with the pinned old
  FFmpeg API. Input, output, and decode padding are private buffers.
- `port/jp2-memory.c` encodes/decodes PPM/JP2 through JasPer memory streams.
  The enclave build replaces JasPer's temporary-file fallback with a growing
  private memory stream. The input/output buffers and any growth must fit EPM.
- `port/h264-memory.c` runs the pinned JM 10.2 encoder or decoder once per
  process. `port/jm-memory-vfs.c` redirects its `FILE*` and fd I/O to named,
  pre-registered private buffers; unknown names and output overflow fail.
  The two JM programs are separate targets because their globals conflict.
  JM's original global state is not reset for repeated invocations.
- `CMakeLists.txt` builds all three codecs for the RISC-V toolchain and links
  five eapp check binaries. These checks prove static link compatibility, not
  codec execution inside an enclave under the board's EPM limit.

`port/media-io.c` frames variable-length output into at most 2 MiB encrypted
chunks. Metadata carries task, codec, sequence, chunk offset, actual plaintext
length, padded ciphertext length, key epoch, and final-chunk state. The eapp
side encrypts from private memory into UTM and decrypts from UTM into private
memory. `port/media-store.c` is a Host-only file endpoint which stores public
metadata and ciphertext, never plaintext. Unit tests cover non-block-aligned
lengths, cross-slot chunking, malformed ordering, and ciphertext file roundtrip.
This follows the existing AES-128-ECB benchmark convention; it does **not**
authenticate data and must not be described as tamper-resistant encrypted
storage.

## Board functional run

`group-pmp-mediabench-board-runner` stages the original files as encrypted
frames, then launches one of four codec-family eapps. During `--run`, Host
callbacks read or write only public frame metadata and ciphertext in UTM;
codec input and output buffers are in enclave private memory. MPEG-4 performs
one-frame encode/decode; the other four workloads use the supplied MediaBench
II input files. The measured `seconds` line covers enclave initialization-
excluded codec run plus encrypted transport. It is a functional-run timing,
not a 1-15 worker performance datum.

After `rebuild-and-test.sh` copies the deploy tree to the board, the board
smoke command is:

```sh
cd /myusb/wj/deploy
./run-mediabench-board-smoke.sh all
```

To run only one workload, replace `all` with `mpeg4enc`, `mpeg4dec`,
`jpg2000enc`, `jpg2000dec`, `h264enc`, or `h264dec`. Optional positional
arguments override the input root (default `/myusb/wj/deploy/mediabench-ii`)
and output root (default `/myusb/MediaBench-II/board-smoke`). Encrypted input
and output frame files are retained under the output root. The Host staging
step reads the original plaintext inputs before the timed enclave run; do not
describe the whole staging process as Host-blind. AES-128-ECB and static test
key match the existing benchmark convention, but provide neither integrity
nor semantic confidentiality.

The codec libraries and transport components remain separate from the SQLite
worker. The 1-15 worker orchestration, three mode-equivalent I/O schedulers,
EPM validation on the actual board, and board functional run remain to be
verified before any Sync/Async/Adaptive MediaBench performance claim.
