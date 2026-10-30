#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/../sdk" ] && [ -d "$SCRIPT_DIR/../runtime" ]; then
  SCRIPT_PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
  SCRIPT_PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
fi
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_PROJECT_ROOT}"
PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"
BUILDROOT_DIR="${BUILDROOT_DIR:-$PROJECT_ROOT/build-starfive/visionfive264/buildroot.build}"
KEYSTONE_SDK_SRC_DIR="${KEYSTONE_SDK_SRC_DIR:-$PROJECT_ROOT/sdk}"
KEYSTONE_EYRIE_RUNTIME="${KEYSTONE_EYRIE_RUNTIME:-$PROJECT_ROOT/runtime}"
KEYSTONE_SM_DIR="${KEYSTONE_SM_DIR:-$PROJECT_ROOT/sm}"
KEYSTONE_DRIVER_DIR="${KEYSTONE_DRIVER_DIR:-$PROJECT_ROOT/linux-keystone-driver}"
GROUP_PMP_STANDALONE="${GROUP_PMP_STANDALONE:-1}"
GROUP_PMP_BUILD_DIR="${GROUP_PMP_BUILD_DIR:-$SCRIPT_DIR/build}"
if [ "$GROUP_PMP_STANDALONE" = 1 ]; then
  KEYSTONE_SDK_DIR="${KEYSTONE_SDK_DIR:-$GROUP_PMP_BUILD_DIR/sdk-install}"
else
  KEYSTONE_SDK_DIR="${KEYSTONE_SDK_DIR:-$BUILDROOT_DIR/host/share/keystone/sdk}"
fi
EXAMPLE_NAME="group-pmp-test"
LOADER_SOURCE="$KEYSTONE_EYRIE_RUNTIME/loader-binary/loader-binary.c"
LOADER_ABI_HEADER="$KEYSTONE_SDK_SRC_DIR/include/shared/sm_call.h"
SM_ENCLAVE_SOURCE="$KEYSTONE_SM_DIR/src/enclave.c"
DRIVER_GROUP_SOURCE="$KEYSTONE_DRIVER_DIR/keystone-group.c"
DRIVER_MAIN_SOURCE="$KEYSTONE_DRIVER_DIR/keystone.c"
DRIVER_PAGE_SOURCE="$KEYSTONE_DRIVER_DIR/keystone-page.c"
DRIVER_IOCTL_SOURCE="$KEYSTONE_DRIVER_DIR/keystone-ioctl.c"
LOADER_ABI_MARKER=""
YXSTM_RESUMABLE_GRANT_MARKER="keystone-yxstm-resumable-grant-v1"
YXSTM_HOST_FALLBACK_GRANT_MARKER="keystone-yxstm-host-fallback-grant-v1"
SQLITE_VFS_OCALL_ACCOUNTING_MARKER="keystone-sqlite-vfs-ocall-accounting-v1"
YXSTM_SLOT_WAIT_RUNTIME_MARKER="keystone-yxstm-slot-wait-v5"
MIXED_WORKER_WAIT_DIAG_MARKER="keystone-mixed-worker-wait-diag-v2"
MIXED_LANE_DYNAMIC_MARKER="keystone-mixed-lane-dynamic-v1"
MIXED_TERMINAL_READY_COMMIT_MARKER="keystone-terminal-ready-commit-v1"
MIXED_VARIABLE_SAMPLE_MARKER="keystone-variable-sample-aggregation-v2"
SQLITE_DESCRIPTOR_ACCOUNTING_MARKER="keystone-sqlite-descriptor-accounting-v1"
MIXED_READY_COALESCING_MARKER="keystone-worker-ready-coalescing-v1"
MIXED_WARMUP_MONOTONIC_STATE_MARKER="keystone-mixed-warmup-monotonic-state-v1"
SQLITE_YXSTM_MARKER="keystone-sqlite-host-engine-v1"
SQLITE_FULL_FLOW_BASELINE_MARKER="keystone-sqlite-full-flow-baseline-v1"
SQLITE_NO_EXTENT_BASELINE_MARKER="keystone-sqlite-dynamic-no-extent-baseline-v4"
SQLITE_CSV_SCHEMA_MARKER="keystone-sqlite-csv-schema-v44"
SQLITE_SCALE_MATCHED_BASELINE_MARKER="keystone-sqlite-scale-matched-baseline-v1"
SQLITE_ASYNC_VFS_MARKER="keystone-sqlite-host-extent-store-v3"
SQLITE_CENTRAL_IO_MARKER="keystone-sqlite-central-io-uring-v9"
SQLITE_VFS_ABI_MARKER="keystone-sqlite-vfs-abi-v17"
SQLITE_WORKLOAD_IO_POLICY_MARKER="keystone-sqlite-workload-aware-io-policy-v3"
SQLITE_ADAPTIVE_REGISTERED_IO_MARKER="keystone-sqlite-adaptive-registered-io-v3"
SQLITE_DOUBLE_BUFFER_MARKER="keystone-sqlite-double-buffer-outstanding-v5"
SQLITE_ROLLING_COLLECT_MARKER="keystone-sqlite-rolling-collect-v1"
SQLITE_COST_CLUSTER_MARKER="keystone-sqlite-cost-aware-cluster-v3"
SQLITE_ONLINE_CLUSTER_MARKER="keystone-sqlite-net-benefit-cluster-v1"
SQLITE_CIPHER_CACHE_MARKER="keystone-sqlite-utm-cipher-cache-v2"
SQLITE_SUBMIT_WAIT_ACCOUNTING_MARKER="keystone-sqlite-submit-wait-ocall-accounting-v1"
SQLITE_ASYNC_COMPLETION_ACCOUNTING_MARKER="keystone-sqlite-async-completion-accounting-v2"
SQLITE_WORKER_BUFFER_DEPTH_MARKER="keystone-sqlite-worker-buffer-depth-accounting-v1"
SQLITE_GANTT_TRACE_MARKER="keystone-sqlite-gantt-trace-v4"
SQLITE_IO_RANGE_TRACE_MARKER="keystone-sqlite-io-range-trace-v2"
SQLITE_NO_EXTENT_IO_MARKER="keystone-sqlite-no-extent-io-v2"
SQLITE_EXTENT_CLIENT_MARKER="keystone-enclave-extent-client-v21"
SQLITE_BLOCKING_PIPELINE_MARKER="keystone-sqlite-blocking-pipeline-v2"
SQLITE_BATCH_OCALL_MARKER="keystone-sqlite-batch-ocall-v1"
SQLITE_CONTROL_ABI_MARKER="keystone-sqlite-zero-length-control-v1"
SQLITE_INDEPENDENT_SYNC_MARKER="keystone-sqlite-independent-sync-v1"
CRYPTO_INTERFACE_MARKER="keystone-crypto-interface-v1"
CRYPTO_ONLY_MARKER="keystone-crypto-only-v1"
AES_BULK_MARKER="keystone-aes-bulk4-v1"
UTM_DIRECT_DATA_MARKER="keystone-utm-direct-data-v1"
SQLITE_HOST_ENGINE_MARKER="keystone-sqlite-wal-connection-pool-v1"
SQLITE_LANE_POOL_MARKER="keystone-sqlite-lane-pool-v1"
SQLITE_IMMEDIATE_OCALL_MARKER="keystone-sqlite-immediate-ocall-v1"
SQLITE_BATCHED_RANDOM_READ_MARKER="keystone-sqlite-batched-random-read-v5"
SQLITE_EXACT_IO_GRANULARITY_MARKER="keystone-sqlite-exact-io-granularity-v1"
SQLITE_DESCRIPTOR_BATCH_MARKER="keystone-sqlite-request-completion-ring-v5"
SQLITE_EFFECTIVE_BATCH_MARKER="keystone-sqlite-effective-request-batching-v8"
SQLITE_COMPLETION_FASTPATH_MARKER="keystone-sqlite-completion-fastpath-v1"
SQLITE_UTM_BUDDY_LAYOUT_MARKER="keystone-sqlite-configurable-ring-v2"
SQLITE_STATUS_COMMIT_MARKER="keystone-sqlite-status-release-commit-v1"
SQLITE_CRYPTO_TIMING_MARKER="keystone-sqlite-crypto-oncpu-timing-v2"
SQLITE_STATIC_FREEMEM_MARKER="keystone-sqlite-static-buffer-freemem-v1"
SQLITE_CONFIGURABLE_TOTAL_MARKER="keystone-sqlite-configurable-total-v1"
SQLITE_WARMUP_OCALL_MARKER="keystone-sqlite-warmup-ocall-v1"
GROUP_EVENT_OVERFLOW_EPOCH_MARKER="keystone-group-event-overflow-epoch-v3"
GROUP_THREAD_COUNT_CANONICAL_MARKER="keystone-group-thread-count-canonical-v1"
GROUP_INTERNAL_INTERRUPTED_MARKER="keystone-group-internal-interrupted-event-v1"
GROUP_TARGETED_COMPLETION_KICK_MARKER="keystone-group-targeted-completion-kick-v1"
GROUP_BATCHED_OCALL_RESUME_MARKER="keystone-group-batched-ocall-resume-v1"
GROUP_DEFERRED_WAKEUP_IPI_MARKER="keystone-group-deferred-wakeup-ipi-v1"
GROUP_DRIVER_VERSION_MARKER="1.0.0-group-pmp-v6"
UTM_PINNABLE_MAPPING_MARKER="keystone-utm-pinnable-vm-insert-page-v1"
UTM_COMPOUND_PINNABLE_MARKER="keystone-utm-compound-pinnable-v2"
UTM_IO_URING_MAPPING_MARKER="keystone-utm-io-uring-detached-file-vma-v1"
SQLITE_VFS_DIRECTIONAL_ACCOUNTING_MARKER="keystone-sqlite-vfs-directional-accounting-v1"
SQLITE_VFS_AUTHENTICATED_TRUNCATE_MARKER="keystone-sqlite-vfs-authenticated-truncate-v1"
SQLITE_POSIX_IO_MARKER="keystone-sqlite-wal-connection-pool-v1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
echo_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
echo_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

require_file() {
  if [ ! -f "$1" ]; then
    echo_error "missing file: $1"
    exit 1
  fi
}

require_text_marker() {
  local file="$1"
  local marker="$2"
  local label="$3"

  require_file "$file"
  if ! grep -aFq -- "$marker" "$file"; then
    echo_error "$label is stale or came from another source tree: $file"
    echo_error "required marker: $marker"
    exit 1
  fi
}

verify_sqlite_ring_contract() {
  local limit="${GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT:-256}"
  local ring_bytes utm_bytes
  case "$limit" in
    256) ring_bytes=131072; utm_bytes=4141056 ;;
    488) ring_bytes=262144; utm_bytes=4272128 ;;
    *) echo_error "GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT must be 256 or 488"; exit 1 ;;
  esac

  local -a compiler
  read -r -a compiler <<< "${HOSTCC:-cc}"
  if [ "${#compiler[@]}" -eq 0 ] || ! command -v "${compiler[0]}" >/dev/null 2>&1; then
    echo_error "host C compiler is required for SQLite ring preflight (HOSTCC=${HOSTCC:-cc})"
    exit 1
  fi
  # Evaluate the selected layout, rather than requiring one macro's spelling.
  # Syntax-only compilation never executes a host or target binary.
  if ! "${compiler[@]}" -std=c11 -x c -fsyntax-only -I"$SCRIPT_DIR/eapp" \
      -DGROUP_PMP_SQLITE_DESCRIPTOR_LIMIT="$limit" \
      -DEXPECTED_RING_BYTES="$ring_bytes" -DEXPECTED_UTM_BYTES="$utm_bytes" - <<'EOF'
#include "group-pmp-sqlite-vfs-shared.h"
_Static_assert(GROUP_PMP_SQLITE_VFS_BATCH_MAX == GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT,
               "SQLite descriptor capacity mismatch");
_Static_assert(GROUP_PMP_SQLITE_VFS_RING_BYTES == EXPECTED_RING_BYTES,
               "SQLite descriptor ring size mismatch");
_Static_assert(GROUP_PMP_SQLITE_VFS_UTM_BYTES == EXPECTED_UTM_BYTES,
               "SQLite UTM layout mismatch");
_Static_assert(GROUP_PMP_SQLITE_VFS_VERSION == 17000 + GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT,
               "SQLite wire version must bind descriptor capacity");
EOF
  then
    echo_error "SQLite ring preflight failed for descriptor capacity $limit"
    exit 1
  fi
  echo_info "SQLite ring contract: descriptors=$limit ring_bytes=$ring_bytes utm_bytes=$utm_bytes"
}

elf_needed_libraries() {
  local binary="$1"
  local readelf_tool=""

  if command -v riscv64-buildroot-linux-gnu-readelf >/dev/null 2>&1; then
    readelf_tool="riscv64-buildroot-linux-gnu-readelf"
  elif command -v readelf >/dev/null 2>&1; then
    readelf_tool="readelf"
  else
    echo_error "readelf is required to deploy native benchmark libraries"
    exit 1
  fi
  "$readelf_tool" -d "$binary" 2>/dev/null |
    sed -n 's/.*Shared library: \[\([^]]\+\)\].*/\1/p'
}

find_target_runtime_library() {
  local library="$1"
  local candidate

  for candidate in \
      "$BUILDROOT_DIR/per-package/keystone-examples/target/usr/lib/$library" \
      "$BUILDROOT_DIR/per-package/keystone-examples/target/lib/$library" \
      "$BUILDROOT_DIR/per-package/keystone-examples/host/riscv64-buildroot-linux-gnu/sysroot/usr/lib/$library" \
      "$BUILDROOT_DIR/target/usr/lib/$library" \
      "$BUILDROOT_DIR/target/lib/$library" \
      "$BUILDROOT_DIR/host/riscv64-buildroot-linux-gnu/sysroot/usr/lib/$library"; do
    if [ -e "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  # Standalone builds may only have a toolchain on PATH, without Buildroot.
  if command -v riscv64-buildroot-linux-gnu-gcc >/dev/null 2>&1; then
    candidate=$(riscv64-buildroot-linux-gnu-gcc -print-file-name="$library")
    if [ "$candidate" != "$library" ] && [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi

  candidate=$(find "$BUILDROOT_DIR" -type f -name "$library" \
    -path '*/usr/lib/*' -print -quit 2>/dev/null || true)
  if [ -n "$candidate" ]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  return 1
}

deploy_native_crypto_libraries() {
  local binary="$1"
  local deploy_dir="$2"
  local library source
  local copied=0

  while IFS= read -r library; do
    case "$library" in
      libcrypto.so*)
        source=$(find_target_runtime_library "$library" || true)
        if [ -z "$source" ]; then
          echo_error "cannot locate linked OpenSSL runtime: $library"
          echo_error "binary: $binary"
          exit 1
        fi
        mkdir -p "$deploy_dir/lib"
        cp -Lv "$source" "$deploy_dir/lib/$library"
        copied=1
        ;;
    esac
  done < <(elf_needed_libraries "$binary")

  if [ "$copied" -eq 1 ]; then
    echo_info "bundled target OpenSSL runtime in $deploy_dir/lib"
  else
    echo_info "native crypto benchmark has no shared libcrypto dependency"
  fi
}

verify_loader_source() {
  require_file "$LOADER_ABI_HEADER"
  LOADER_ABI_MARKER="$(
    sed -n 's/^#define[[:space:]]\+KEYSTONE_GROUP_ABI_MARKER[[:space:]]\+"\([^"]\+\)".*/\1/p' \
      "$LOADER_ABI_HEADER" | head -n 1
  )"
  if [ -z "$LOADER_ABI_MARKER" ]; then
    echo_error "cannot parse KEYSTONE_GROUP_ABI_MARKER from $LOADER_ABI_HEADER"
    exit 1
  fi
  require_text_marker "$LOADER_SOURCE" "KEYSTONE_GROUP_ABI_MARKER" \
    "runtime loader source"
  require_text_marker "$LOADER_SOURCE" "KEYSTONE_UTM_DIRECT_DATA_MARKER" \
    "runtime direct-UTM loader source"
  require_text_marker "$KEYSTONE_EYRIE_RUNTIME/call/syscall.c" \
    "KEYSTONE_UTM_DIRECT_DATA_MARKER" "runtime direct-UTM syscall source"
  require_text_marker "$KEYSTONE_SDK_SRC_DIR/include/shared/eyrie_call.h" \
    "$UTM_DIRECT_DATA_MARKER" "SDK direct-UTM ABI source"
  require_text_marker "$LOADER_ABI_HEADER" \
    "#define KEYSTONE_GROUP_ABI_MARKER            \"$LOADER_ABI_MARKER\"" \
    "SDK loader ABI definition"
}

verify_mixed_sources() {
  require_text_marker \
    "$DRIVER_GROUP_SOURCE" \
    "$GROUP_INTERNAL_INTERRUPTED_MARKER" \
    "driver internal scheduler-event filter source"
  require_text_marker \
    "$DRIVER_GROUP_SOURCE" \
    "$GROUP_TARGETED_COMPLETION_KICK_MARKER" \
    "driver targeted SQLite completion kick source"
  require_text_marker \
    "$DRIVER_IOCTL_SOURCE" \
    "$GROUP_BATCHED_OCALL_RESUME_MARKER" \
    "driver batched blocked-OCALL resume source"
  require_text_marker \
    "$DRIVER_MAIN_SOURCE" \
    "$GROUP_DRIVER_VERSION_MARKER" \
    "driver scheduler-event version source"
  require_text_marker \
    "$DRIVER_MAIN_SOURCE" \
    "$UTM_PINNABLE_MAPPING_MARKER" \
    "driver pinnable UTM mapping source"
  require_text_marker \
    "$DRIVER_MAIN_SOURCE" \
    "$UTM_IO_URING_MAPPING_MARKER" \
    "driver io_uring-registerable UTM mapping source"
  require_text_marker \
    "$DRIVER_PAGE_SOURCE" \
    "$UTM_COMPOUND_PINNABLE_MARKER" \
    "driver compound-page UTM allocation source"
  require_text_marker \
    "$SM_ENCLAVE_SOURCE" \
    "$YXSTM_RESUMABLE_GRANT_MARKER" \
    "SM resumable YXSTM grant source"
  require_text_marker \
    "$SM_ENCLAVE_SOURCE" \
    "$YXSTM_HOST_FALLBACK_GRANT_MARKER" \
    "SM resumable no-peer HOST fallback source"
  require_text_marker \
    "$SM_ENCLAVE_SOURCE" \
    "$GROUP_EVENT_OVERFLOW_EPOCH_MARKER" \
    "SM group event overflow epoch source"
  require_text_marker \
    "$SM_ENCLAVE_SOURCE" \
    "$GROUP_THREAD_COUNT_CANONICAL_MARKER" \
    "SM group thread-count canonicalization source"
  require_text_marker \
    "$SM_ENCLAVE_SOURCE" \
    "$GROUP_DEFERRED_WAKEUP_IPI_MARKER" \
    "SM deferred completion IPI source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$GROUP_EVENT_OVERFLOW_EPOCH_MARKER" \
    "group event overflow epoch host runner source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-mixed-shared.h" \
    "$MIXED_LANE_DYNAMIC_MARKER" \
    "mixed shared contract"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-mixed-shared.h" \
    "#define GROUP_PMP_MIXED_VERSION UINT64_C(23)" \
    "mixed shared contract version"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-mixed-master.c" \
    "mixed_lane_dynamic_artifact_marker" \
    "mixed master source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-mixed-worker.c" \
    "mixed_lane_dynamic_artifact_marker" \
    "mixed worker source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "mixed_lane_dynamic_artifact_marker" \
    "mixed host runner source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_VFS_OCALL_ACCOUNTING_MARKER" \
    "SQLite VFS OCALL accounting source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_VFS_DIRECTIONAL_ACCOUNTING_MARKER" \
    "SQLite directional VFS accounting source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_VFS_AUTHENTICATED_TRUNCATE_MARKER" \
    "SQLite authenticated truncate source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_POSIX_IO_MARKER" \
    "SQLite POSIX random-I/O host source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$MIXED_TERMINAL_READY_COMMIT_MARKER" \
    "mixed terminal WORKERS_READY commit source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$MIXED_VARIABLE_SAMPLE_MARKER" \
    "mixed variable-sample aggregation source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_DESCRIPTOR_ACCOUNTING_MARKER" \
    "SQLite descriptor accounting source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$MIXED_READY_COALESCING_MARKER" \
    "coalesced WORKERS_READY source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$MIXED_WARMUP_MONOTONIC_STATE_MARKER" \
    "mixed monotonic warmup-state source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-shared.h" \
    "$SQLITE_YXSTM_MARKER" \
    "SQLite shared contract"
  # The unchanged base VFS marker does not prove paired-read declarations exist.
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-shared.h" \
    "#define GROUP_PMP_SQLITE_PAIRED_READS" \
    "SQLite paired-read config header (sync eapp/group-pmp-sqlite-shared.h)"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-vfs-shared.h" \
    "struct group_pmp_sqlite_vfs_ring_pair_doorbell {" \
    "SQLite paired-read doorbell header (sync eapp/group-pmp-sqlite-vfs-shared.h)"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-vfs-shared.h" \
    "struct group_pmp_sqlite_vfs_ring_pair_ack {" \
    "SQLite paired-read ack header (sync eapp/group-pmp-sqlite-vfs-shared.h)"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "sqlite_full_flow_baseline_artifact_marker" \
    "SQLite full-flow baseline runner source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_NO_EXTENT_BASELINE_MARKER" \
    "SQLite dynamic no-extent baseline runner source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_CSV_SCHEMA_MARKER" \
    "SQLite CSV schema ($SQLITE_CSV_SCHEMA_MARKER) runner source"
  require_text_marker \
    "$LOADER_ABI_HEADER" \
    "keystone-member-exec-clock-v1" \
    "SDK read-only member execution clock"
  require_text_marker \
    "$SM_ENCLAVE_SOURCE" \
    "group_member_publish_exec_clock_locked" \
    "SM on-CPU clock publisher (rebuild and deploy firmware too)"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-worker.c" \
    "KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK" \
    "SQLite worker on-CPU clock registration"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_SCALE_MATCHED_BASELINE_MARKER" \
    "SQLite scale-matched baseline runner source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-master.c" \
    "sqlite_full_flow_baseline_marker" \
    "SQLite full-flow baseline master source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-vfs-shared.h" \
    "$SQLITE_ASYNC_VFS_MARKER" \
    "SQLite async VFS ABI source"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_BLOCKING_PIPELINE_MARKER" \
    "SQLite blocked async-completion client source"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_BATCH_OCALL_MARKER" \
    "SQLite batched OCALL client source"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_CONTROL_ABI_MARKER" \
    "SQLite zero-length control ABI client source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-vfs-shared.h" \
    "$SQLITE_EXACT_IO_GRANULARITY_MARKER" \
    "SQLite exact I/O granularity contract"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_EXACT_IO_GRANULARITY_MARKER" \
    "SQLite exact I/O granularity client"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_DESCRIPTOR_BATCH_MARKER" \
    "SQLite descriptor batching client"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_EFFECTIVE_BATCH_MARKER" \
    "SQLite effective request batching client"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-extent-io.cpp" \
    "GROUP_PMP_SQLITE_EFFECTIVE_BATCH_MARKER" \
    "SQLite effective Host request batching source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-vfs-shared.h" \
    "$SQLITE_COMPLETION_FASTPATH_MARKER" \
    "SQLite completion fastpath contract"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_COMPLETION_FASTPATH_MARKER" \
    "SQLite local completion reap client"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$GROUP_BATCHED_OCALL_RESUME_MARKER" \
    "SQLite batched blocked-OCALL resume runner"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "sqlite_async_vfs_artifact_marker" \
    "SQLite async I/O runner source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_NO_EXTENT_IO_MARKER" \
    "SQLite independent no-extent implementation"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-extent-io.cpp" \
    "GROUP_PMP_SQLITE_CENTRAL_IO_MARKER" \
    "SQLite centralized io_uring extent service source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-vfs-shared.h" \
    "$SQLITE_VFS_ABI_MARKER" \
    "SQLite VFS ABI ($SQLITE_VFS_ABI_MARKER) contract"
  verify_sqlite_ring_contract
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-vfs-shared.h" \
    "$SQLITE_UTM_BUDDY_LAYOUT_MARKER" \
    "SQLite worker UTM configurable-ring contract"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-extent-io.cpp" \
    "$SQLITE_WORKLOAD_IO_POLICY_MARKER" \
    "SQLite workload-aware I/O policy implementation"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-extent-io.cpp" \
    "$SQLITE_ADAPTIVE_REGISTERED_IO_MARKER" \
    "SQLite adaptive registered I/O implementation"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-vfs-shared.h" \
    "$SQLITE_DOUBLE_BUFFER_MARKER" \
    "SQLite double-buffer ABI contract"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_DOUBLE_BUFFER_MARKER" \
    "SQLite double-buffer worker implementation"
  require_text_marker \
    "$SCRIPT_DIR/CMakeLists.txt" \
    "sqlite-bench-master/keystone_enclave_store.c" \
    "SQLite active worker storage source selection"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-extent-io.cpp" \
    "GROUP_PMP_SQLITE_ROLLING_COLLECT_MARKER" \
    "SQLite rolling request collector"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-extent-io.cpp" \
    "GROUP_PMP_SQLITE_COST_CLUSTER_MARKER" \
    "SQLite cost-aware request clustering"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-extent-io.cpp" \
    "$SQLITE_ONLINE_CLUSTER_MARKER" \
    "SQLite net-benefit online clustering"
  require_text_marker \
    "$SCRIPT_DIR/host/online-cluster-feedback.hpp" \
    "static constexpr size_t kInitialSamples = 8;" \
    "SQLite passive clustering telemetry header"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-extent-io.cpp" \
    "GROUP_PMP_SQLITE_CIPHER_CACHE_MARKER" \
    "SQLite UTM ciphertext cache"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_SUBMIT_WAIT_ACCOUNTING_MARKER" \
    "SQLite submit/wait OCALL accounting"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_ASYNC_COMPLETION_ACCOUNTING_MARKER" \
    "SQLite async completion accounting"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_WORKER_BUFFER_DEPTH_MARKER" \
    "SQLite worker-side double-buffer depth accounting"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-gantt-trace.hpp" \
    "$SQLITE_GANTT_TRACE_MARKER" \
    "SQLite request Gantt trace contract"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-gantt-trace.cpp" \
    "$SQLITE_GANTT_TRACE_MARKER" \
    "SQLite request Gantt trace implementation"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-io-range-trace.hpp" \
    "$SQLITE_IO_RANGE_TRACE_MARKER" \
    "SQLite I/O range trace contract"
  require_text_marker \
    "$SCRIPT_DIR/host/sqlite-io-range-trace.cpp" \
    "$SQLITE_IO_RANGE_TRACE_MARKER" \
    "SQLite I/O range trace implementation"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "sqlite_independent_sync_artifact_marker" \
    "SQLite independent SYNC runner source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "sqlite_configurable_total_artifact_marker" \
    "SQLite configurable total-size runner source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "sqlite_warmup_ocall_artifact_marker" \
    "SQLite warmup OCALL runner source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "keystone-worker-lease-exit-cleanup-v1" \
    "worker lease exit cleanup runner source"
  require_text_marker \
    "$SCRIPT_DIR/prepare-3w1hm-isolation.sh" \
    "keystone-hsm-lease-recovery-v1" \
    "HSM lease recovery isolation script"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-master.c" \
    "sqlite_artifact_marker" \
    "SQLite master source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-sqlite-worker.c" \
    "sqlite_artifact_marker" \
    "SQLite worker source"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.h" \
    "$SQLITE_EXTENT_CLIENT_MARKER" \
    "SQLite enclave extent client"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "KEYSTONE_UTM_DIRECT_DATA_MARKER" \
    "SQLite direct-UTM extent client"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_HOST_ENGINE_MARKER" \
    "SQLite WAL connection-pool engine"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "GROUP_PMP_SQLITE_LANE_POOL_MARKER" \
    "SQLite per-lane connection pool source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "GROUP_PMP_SQLITE_IMMEDIATE_OCALL_MARKER" \
    "SQLite immediate OCALL enqueue source"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_BATCHED_RANDOM_READ_MARKER" \
    "SQLite batched random-read source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "GROUP_PMP_SQLITE_STATUS_COMMIT_MARKER" \
    "SQLite status release-commit host source"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_STATUS_COMMIT_MARKER" \
    "SQLite status stable-read worker source"
  require_text_marker \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "GROUP_PMP_SQLITE_CRYPTO_TIMING_MARKER" \
    "SQLite crypto-only timing source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-crypto.h" \
    "$CRYPTO_INTERFACE_MARKER" \
    "unified enclave crypto interface source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-crypto.h" \
    "$CRYPTO_ONLY_MARKER" \
    "crypto-only benchmark source"
  require_text_marker \
    "$SCRIPT_DIR/eapp/group-pmp-crypto.c" \
    "$AES_BULK_MARKER" \
    "bulk AES implementation source"
  require_text_marker \
    "$SCRIPT_DIR/host/group-pmp-test-runner.cpp" \
    "$SQLITE_STATIC_FREEMEM_MARKER" \
    "SQLite static-buffer freemem source"
}

verify_loader_artifact() {
  local loader="$1"
  local label="$2"

  require_text_marker "$loader" "$LOADER_ABI_MARKER" "$label"
  require_text_marker "$loader" "$UTM_DIRECT_DATA_MARKER" \
    "$label direct-UTM mapping"
  echo_info "$label sha256: $(sha256sum "$loader" | awk '{print $1}')"
}

find_examples_build_dir() {
  if [ "$GROUP_PMP_STANDALONE" = 1 ]; then
    printf '%s\n' "$GROUP_PMP_BUILD_DIR/examples"
    return
  fi
  local build_dir
  build_dir=$(ls -dt "$BUILDROOT_DIR/build/keystone-examples-"* 2>/dev/null | head -1 || true)
  if [ -z "$build_dir" ]; then
    echo_error "cannot find keystone-examples build directory under $BUILDROOT_DIR/build"
    echo_error "run make once from $PROJECT_ROOT first"
    exit 1
  fi
  echo "$build_dir"
}

sync_sources() {
  local enclave_build_dir="$1"
  local target_dir="$enclave_build_dir/$EXAMPLE_NAME"
  local sdk_dir="$KEYSTONE_SDK_DIR"

  if [ "$GROUP_PMP_STANDALONE" = 1 ]; then
    # CMake references this source tree directly; do not stage stale copies.
    mkdir -p "$enclave_build_dir"
    return
  fi

  echo_info "syncing $EXAMPLE_NAME sources into Buildroot examples tree"
  mkdir -p \
    "$target_dir/host" \
    "$target_dir/eapp" \
    "$target_dir/ECC" \
    "$target_dir/micro-ecc-master" \
    "$target_dir/RSA" \
    "$target_dir/SHA-256" \
    "$target_dir/sqlite-bench-master" \
    "$target_dir/mediabench-ii/port" \
    "$target_dir/mediabench-ii/vendor/codecs" \
    "$target_dir/SM/SM2" \
    "$target_dir/SM/SM3" \
    "$target_dir/SM/SM4"
  # add_eyrie_runtime uses an ExternalProject below this directory. Its
  # download stamp does not track edits in the local runtime source tree.
  rm -rf "$target_dir/runtime" "$target_dir/CMakeFiles"
  rm -f "$target_dir/Makefile" "$target_dir/cmake_install.cmake"
  rm -f "$target_dir/eyrie-rt" "$target_dir/loader.bin" "$target_dir/.options_log"
  cp -v "$SCRIPT_DIR/CMakeLists.txt" "$target_dir/"
  mkdir -p "$target_dir/motivation"
  for motivation_source in "$SCRIPT_DIR/motivation/"*.c "$SCRIPT_DIR/motivation/"*.h "$SCRIPT_DIR/motivation/"*.hpp; do
    cp -v "$motivation_source" "$target_dir/motivation/"
    cmp -s "$motivation_source" "$target_dir/motivation/${motivation_source##*/}" || exit 1
  done
  mkdir -p "$target_dir/secure-kv"
  for kv_source in "$SCRIPT_DIR/secure-kv/"*.c "$SCRIPT_DIR/secure-kv/"*.h; do
    cp -v "$kv_source" "$target_dir/secure-kv/"
    cmp -s "$kv_source" "$target_dir/secure-kv/${kv_source##*/}" || {
      echo_error "KV source sync mismatch: $kv_source"; exit 1;
    }
  done
  mkdir -p "$target_dir/rv8-bench-master/src" "$target_dir/rv8-bench-master/port"
  for rv8_source in "$SCRIPT_DIR/rv8-bench-master/src/"*.c \
      "$SCRIPT_DIR/rv8-bench-master/src/"*.cc \
      "$SCRIPT_DIR/rv8-bench-master/port/"*.c "$SCRIPT_DIR/rv8-bench-master/port/"*.h; do
    cp -v "$rv8_source" "$target_dir/rv8-bench-master/${rv8_source#"$SCRIPT_DIR/rv8-bench-master/"}"
    cmp -s "$rv8_source" "$target_dir/rv8-bench-master/${rv8_source#"$SCRIPT_DIR/rv8-bench-master/"}" || {
      echo_error "RV8 source sync mismatch: $rv8_source"; exit 1;
    }
  done
    # Security fixtures include headers from both Host and eapp sources.
    mkdir -p "$target_dir/security"
    cp -R "$SCRIPT_DIR/security/." "$target_dir/security/"
    while IFS= read -r -d '' security_source; do
      local relative_security="${security_source#"$SCRIPT_DIR/"}"
      if ! cmp -s "$security_source" "$target_dir/$relative_security"; then
        echo_error "Buildroot source sync mismatch: $relative_security"
        exit 1
      fi
    done < <(find "$SCRIPT_DIR/security" -type f -print0)
  cp -v "$SCRIPT_DIR/mediabench-ii/port/jpeg-memory.c" \
    "$SCRIPT_DIR/mediabench-ii/port/jpeg-memory.h" \
    "$SCRIPT_DIR/mediabench-ii/port/jconfig.h" \
    "$target_dir/mediabench-ii/port/"
  cp -R "$SCRIPT_DIR/mediabench-ii/vendor/codecs/jpeg-6b" \
    "$target_dir/mediabench-ii/vendor/codecs/"
  # Stage and verify the same set, including headers added by future Host edits.
  local host_source
  for host_source in "$SCRIPT_DIR/host/"*.c "$SCRIPT_DIR/host/"*.cpp \
      "$SCRIPT_DIR/host/"*.h "$SCRIPT_DIR/host/"*.hpp; do
    [ -f "$host_source" ] || continue
    if ! cp -v "$host_source" "$target_dir/host/" || \
        ! cmp -s "$host_source" "$target_dir/host/${host_source##*/}"; then
      echo_error "Buildroot source sync mismatch: host/${host_source##*/}"
      exit 1
    fi
  done
  cp -v "$SCRIPT_DIR/ECC/"*.c "$SCRIPT_DIR/ECC/"*.h "$target_dir/ECC/"
  cp -v "$SCRIPT_DIR/micro-ecc-master/uECC.c" \
    "$SCRIPT_DIR/micro-ecc-master/uECC.h" \
    "$SCRIPT_DIR/micro-ecc-master/uECC_vli.h" \
    "$SCRIPT_DIR/micro-ecc-master/types.h" \
    "$SCRIPT_DIR/micro-ecc-master/platform-specific.inc" \
    "$SCRIPT_DIR/micro-ecc-master/curve-specific.inc" \
    "$target_dir/micro-ecc-master/"
  cp -v "$SCRIPT_DIR/RSA/"*.c "$SCRIPT_DIR/RSA/"*.h "$target_dir/RSA/"
  cp -v "$SCRIPT_DIR/SHA-256/"*.c "$SCRIPT_DIR/SHA-256/"*.h \
    "$target_dir/SHA-256/"
  cp -v "$SCRIPT_DIR/SM/SM2/sm2_bench.c" \
    "$SCRIPT_DIR/SM/SM2/sm2_bench.h" \
    "$SCRIPT_DIR/SM/SM2/sm2.c" \
    "$SCRIPT_DIR/SM/SM2/sm2.h" \
    "$SCRIPT_DIR/SM/SM2/kdf.h" "$target_dir/SM/SM2/"
  cp -v "$SCRIPT_DIR/SM/SM3/sm3.c" \
    "$SCRIPT_DIR/SM/SM3/sm3.h" "$target_dir/SM/SM3/"
  cp -v "$SCRIPT_DIR/SM/SM4/sm4.c" \
    "$SCRIPT_DIR/SM/SM4/sm4.h" "$target_dir/SM/SM4/"
  cp -v "$SCRIPT_DIR/eapp/"*.c "$target_dir/eapp/"
  cp -v "$SCRIPT_DIR/eapp/"*.h "$target_dir/eapp/"
  cp -v "$SCRIPT_DIR/sqlite-bench-master/sqlite3.c" \
    "$SCRIPT_DIR/sqlite-bench-master/sqlite3.h" \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.c" \
    "$SCRIPT_DIR/sqlite-bench-master/keystone_enclave_store.h" \
    "$SCRIPT_DIR/sqlite-bench-master/sqlite-locality-address.h" \
    "$target_dir/sqlite-bench-master/"
  for relative in \
      ECC/ecdsa_p256_bench.c \
      micro-ecc-master/uECC.c \
      SM/SM2/sm2_bench.c \
      SM/SM2/sm2.c \
      eapp/group-pmp-mixed-master.c \
      eapp/group-pmp-mixed-worker.c \
      eapp/group-pmp-mixed-shared.h \
      eapp/group-pmp-sqlite-master.c \
      eapp/group-pmp-sqlite-worker.c \
      eapp/group-pmp-sqlite-shared.h \
      eapp/group-pmp-sqlite-vfs-shared.h \
      sqlite-bench-master/keystone_enclave_store.c \
      sqlite-bench-master/keystone_enclave_store.h \
      sqlite-bench-master/sqlite-locality-address.h \
      sqlite-bench-master/sqlite3.c \
      sqlite-bench-master/sqlite3.h; do
    if ! cmp -s "$SCRIPT_DIR/$relative" "$target_dir/$relative"; then
      echo_error "Buildroot source sync mismatch: $relative"
      exit 1
    fi
  done

  echo_info "syncing top-level examples CMakeLists.txt"
  cp -v "$PROJECT_ROOT/examples/CMakeLists.txt" "$enclave_build_dir/CMakeLists.txt"

  local macros_src="$KEYSTONE_SDK_SRC_DIR/macros.cmake"
  local macros_dst="$sdk_dir/cmake/macros.cmake"
  if [ -f "$macros_src" ] && [ -f "$macros_dst" ]; then
    cp -v "$macros_src" "$macros_dst" || {
      echo_warning "failed to sync SDK macros.cmake"
    }
  fi

  echo_info "syncing current SDK ABI headers"
  mkdir -p "$sdk_dir/include/shared" "$sdk_dir/include/host" "$sdk_dir/include/app"
  cp -v "$KEYSTONE_SDK_SRC_DIR/include/shared/"*.h "$sdk_dir/include/shared/"
  cp -v "$KEYSTONE_SDK_SRC_DIR/include/host/"*.h "$sdk_dir/include/host/"
  cp -v "$KEYSTONE_SDK_SRC_DIR/include/host/"*.hpp "$sdk_dir/include/host/"
  cp -v "$KEYSTONE_SDK_SRC_DIR/include/app/"*.h "$sdk_dir/include/app/"
}

build_example() {
  local enclave_build_dir="$1"
  local host_dir="$BUILDROOT_DIR/host"
  local sdk_dir="$KEYSTONE_SDK_DIR"
  local package_toolchain_dir="$BUILDROOT_DIR/per-package/keystone-examples/host/bin"
  local host_toolchain_dir="$host_dir/bin"

  if [ -d "$package_toolchain_dir" ]; then
    export PATH="$package_toolchain_dir:$PATH"
  fi
  if [ -d "$host_toolchain_dir" ]; then
    export PATH="$host_toolchain_dir:$PATH"
  fi

  if ! command -v riscv64-buildroot-linux-gnu-gcc >/dev/null 2>&1; then
    echo_error "riscv64-buildroot-linux-gnu-gcc not found in PATH"
    echo_error "checked: $package_toolchain_dir and $host_toolchain_dir"
    exit 1
  fi
  echo_info "RISC-V gcc: $(command -v riscv64-buildroot-linux-gnu-gcc)"

  local cmake_source="$enclave_build_dir"
  local -a standalone_args=()
  if [ "$GROUP_PMP_STANDALONE" = 1 ]; then
    echo_info "building and installing SDK from $KEYSTONE_SDK_SRC_DIR"
    cmake -S "$KEYSTONE_SDK_SRC_DIR" -B "$GROUP_PMP_BUILD_DIR/sdk" \
      -DKEYSTONE_SDK_DIR="$sdk_dir" -DKEYSTONE_BITS=64 \
      -DKEYSTONE_BUILD_TESTS=OFF \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=riscv64 \
      -DCMAKE_C_COMPILER="$(command -v riscv64-buildroot-linux-gnu-gcc)" \
      -DCMAKE_CXX_COMPILER="$(command -v riscv64-buildroot-linux-gnu-g++)" \
      -DCMAKE_ASM_COMPILER="$(command -v riscv64-buildroot-linux-gnu-gcc)"
    cmake --build "$GROUP_PMP_BUILD_DIR/sdk" --target install -- -j"$(nproc)"
    cmake_source="$SCRIPT_DIR/cmake/standalone"
    standalone_args+=("-DGROUP_PMP_SOURCE_DIR=$SCRIPT_DIR")
    local sysroot
    sysroot=$(riscv64-buildroot-linux-gnu-gcc -print-sysroot)
    if [ -n "$sysroot" ] && [ "$sysroot" != / ]; then
      standalone_args+=("-DCMAKE_FIND_ROOT_PATH=$sysroot"
        -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY
        -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY
        -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY
        -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER)
    fi
    # ExternalProject stamps do not track changes to the Runtime source.
    rm -rf "$enclave_build_dir/$EXAMPLE_NAME/runtime"
    rm -f "$enclave_build_dir/$EXAMPLE_NAME/eyrie-rt" \
      "$enclave_build_dir/$EXAMPLE_NAME/loader.bin" \
      "$enclave_build_dir/$EXAMPLE_NAME/.options_log"
  fi
  require_file "$sdk_dir/cmake/macros.cmake"

  echo_info "resetting examples CMake cache"
  rm -f "$enclave_build_dir/CMakeCache.txt"
  rm -rf "$enclave_build_dir/CMakeFiles"

  echo_info "configuring Keystone examples build"
  cd "$enclave_build_dir"
  cmake \
    -DPATH="$PATH" \
    -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=riscv64 \
    -DCMAKE_C_COMPILER="$(command -v riscv64-buildroot-linux-gnu-gcc)" \
    -DCMAKE_CXX_COMPILER="$(command -v riscv64-buildroot-linux-gnu-g++)" \
    -DCMAKE_ASM_COMPILER="$(command -v riscv64-buildroot-linux-gnu-gcc)" \
    -DKEYSTONE_SDK_DIR="$sdk_dir" \
    -DKEYSTONE_SDK_SRC_DIR="$KEYSTONE_SDK_SRC_DIR" \
    -DKEYSTONE_EYRIE_RUNTIME="$KEYSTONE_EYRIE_RUNTIME" \
    -DKEYSTONE_BITS=64 \
    -DGROUP_PMP_ENABLE_SPARK_SCHEDULER="${GROUP_PMP_ENABLE_SPARK_SCHEDULER:-OFF}" \
    -DGROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS="${GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS:-OFF}" \
    -DGROUP_PMP_ENABLE_NATIVE_AES_DIAGNOSTIC="${GROUP_PMP_ENABLE_NATIVE_AES_DIAGNOSTIC:-ON}" \
    -DGROUP_PMP_AES_COOPERATIVE_SERVICE="${GROUP_PMP_AES_COOPERATIVE_SERVICE:-OFF}" \
    -DGROUP_PMP_AES_MARCH="${GROUP_PMP_AES_MARCH:-rv64gc}" \
    -DGROUP_PMP_TASK_BATCHES="${GROUP_PMP_TASK_BATCHES:-100}" \
    -DGROUP_PMP_SQLITE_DESCRIPTOR_LIMIT="${GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT:-256}" \
    "${standalone_args[@]}" "$cmake_source"

  echo_info "clean-building $EXAMPLE_NAME"
  cmake --build . --target group-pmp-test --clean-first -- -j"$(nproc)"

  echo_info "building SD/USB file-I/O benchmark with the Buildroot RISC-V compiler"
  RISCV_CC="$(command -v riscv64-buildroot-linux-gnu-gcc)" \
    sh "$SCRIPT_DIR/usb_sd-test/build-riscv.sh" \
      "$enclave_build_dir/$EXAMPLE_NAME/usb-sd-bench.riscv64"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/usb-sd-bench.riscv64" \
    "usb-sd-file-io-v1" \
    "freshly built SD/USB file-I/O benchmark"

  verify_loader_artifact \
    "$enclave_build_dir/$EXAMPLE_NAME/loader.bin" \
    "freshly built loader.bin"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/eyrie-rt" \
    "$YXSTM_SLOT_WAIT_RUNTIME_MARKER" \
    "freshly built eyrie-rt"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/eyrie-rt" \
    "$UTM_DIRECT_DATA_MARKER" \
    "freshly built direct-UTM eyrie-rt"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mixed-worker.eapp_riscv" \
    "$MIXED_WORKER_WAIT_DIAG_MARKER" \
    "freshly built mixed worker eapp"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$MIXED_LANE_DYNAMIC_MARKER" \
    "freshly built mixed host runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$MIXED_TERMINAL_READY_COMMIT_MARKER" \
    "freshly built terminal WORKERS_READY commit runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$MIXED_VARIABLE_SAMPLE_MARKER" \
    "freshly built variable-sample aggregation runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_DESCRIPTOR_ACCOUNTING_MARKER" \
    "freshly built SQLite descriptor accounting runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_VFS_DIRECTIONAL_ACCOUNTING_MARKER" \
    "freshly built SQLite directional VFS accounting runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_VFS_AUTHENTICATED_TRUNCATE_MARKER" \
    "freshly built SQLite authenticated truncate runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_POSIX_IO_MARKER" \
    "freshly built SQLite POSIX random-I/O runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$MIXED_READY_COALESCING_MARKER" \
    "freshly built coalesced WORKERS_READY runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$MIXED_WARMUP_MONOTONIC_STATE_MARKER" \
    "freshly built monotonic warmup-state runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_FULL_FLOW_BASELINE_MARKER" \
    "freshly built SQLite full-flow baseline runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_NO_EXTENT_BASELINE_MARKER" \
    "freshly built SQLite dynamic no-extent baseline runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_CSV_SCHEMA_MARKER" \
    "freshly built SQLite CSV schema ($SQLITE_CSV_SCHEMA_MARKER) runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_SCALE_MATCHED_BASELINE_MARKER" \
    "freshly built SQLite scale-matched baseline runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_ASYNC_VFS_MARKER" \
    "freshly built SQLite async I/O runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_BLOCKING_PIPELINE_MARKER" \
    "freshly built blocked async-completion runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_BATCH_OCALL_MARKER" \
    "freshly built batched OCALL runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_CONTROL_ABI_MARKER" \
    "freshly built zero-length control ABI runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_INDEPENDENT_SYNC_MARKER" \
    "freshly built independent SQLite SYNC runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_CONFIGURABLE_TOTAL_MARKER" \
    "freshly built SQLite configurable total-size runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "keystone-fio-enclave-profile-v1" \
    "freshly built fio enclave profile runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_WARMUP_OCALL_MARKER" \
    "freshly built SQLite warmup OCALL runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$GROUP_EVENT_OVERFLOW_EPOCH_MARKER" \
    "freshly built group event overflow epoch runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "keystone-worker-lease-exit-cleanup-v1" \
    "freshly built worker lease exit cleanup runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$LOADER_ABI_MARKER" \
    "freshly built host runner ABI"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mixed-master.eapp_riscv" \
    "$MIXED_LANE_DYNAMIC_MARKER" \
    "freshly built mixed master eapp"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mixed-worker.eapp_riscv" \
    "$MIXED_LANE_DYNAMIC_MARKER" \
    "freshly built mixed worker eapp contract"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-master.eapp_riscv" \
    "$SQLITE_YXSTM_MARKER" \
    "freshly built SQLite master eapp"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-master.eapp_riscv" \
    "$SQLITE_FULL_FLOW_BASELINE_MARKER" \
    "freshly built SQLite full-flow baseline master"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_ASYNC_VFS_MARKER" \
    "freshly built SQLite host-store worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_CENTRAL_IO_MARKER" \
    "freshly built centralized I/O worker ABI"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_CENTRAL_IO_MARKER" \
    "freshly built centralized io_uring runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_VFS_ABI_MARKER" \
    "freshly built SQLite VFS ABI v12 runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_VFS_ABI_MARKER" \
    "freshly built SQLite VFS ABI v12 worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_UTM_BUDDY_LAYOUT_MARKER" \
    "freshly built buddy-sized SQLite UTM runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_UTM_BUDDY_LAYOUT_MARKER" \
    "freshly built buddy-sized SQLite UTM worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_WORKLOAD_IO_POLICY_MARKER" \
    "freshly built workload-aware I/O policy runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_ADAPTIVE_REGISTERED_IO_MARKER" \
    "freshly built adaptive registered I/O runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_DOUBLE_BUFFER_MARKER" \
    "freshly built double-buffer completion runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_DOUBLE_BUFFER_MARKER" \
    "freshly built double-buffer SQLite worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_COMPLETION_FASTPATH_MARKER" \
    "freshly built local completion-reap runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_COMPLETION_FASTPATH_MARKER" \
    "freshly built local completion-reap worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$GROUP_BATCHED_OCALL_RESUME_MARKER" \
    "freshly built batched blocked-OCALL resume runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_ROLLING_COLLECT_MARKER" \
    "freshly built rolling request collector"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_COST_CLUSTER_MARKER" \
    "freshly built cost-aware clustering runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_ONLINE_CLUSTER_MARKER" \
    "freshly built online clustering runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_CIPHER_CACHE_MARKER" \
    "freshly built UTM ciphertext cache runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_SUBMIT_WAIT_ACCOUNTING_MARKER" \
    "freshly built submit/wait OCALL accounting runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_ASYNC_COMPLETION_ACCOUNTING_MARKER" \
    "freshly built async completion accounting runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_WORKER_BUFFER_DEPTH_MARKER" \
    "freshly built worker-side buffer-depth accounting runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_GANTT_TRACE_MARKER" \
    "freshly built SQLite request Gantt runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_IO_RANGE_TRACE_MARKER" \
    "freshly built SQLite I/O range trace runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_NO_EXTENT_IO_MARKER" \
    "freshly built SQLite no-extent runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_EXTENT_CLIENT_MARKER" \
    "freshly built SQLite extent client worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_BLOCKING_PIPELINE_MARKER" \
    "freshly built blocked async-completion worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_BATCH_OCALL_MARKER" \
    "freshly built batched OCALL worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_CONTROL_ABI_MARKER" \
    "freshly built zero-length control ABI worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$UTM_DIRECT_DATA_MARKER" \
    "freshly built SQLite direct-UTM worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_HOST_ENGINE_MARKER" \
    "freshly built SQLite WAL connection-pool engine"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_LANE_POOL_MARKER" \
    "freshly built SQLite per-lane connection pool runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_IMMEDIATE_OCALL_MARKER" \
    "freshly built SQLite immediate OCALL enqueue runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_BATCHED_RANDOM_READ_MARKER" \
    "freshly built SQLite batched random-read worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_EXACT_IO_GRANULARITY_MARKER" \
    "freshly built SQLite exact-range worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_DESCRIPTOR_BATCH_MARKER" \
    "freshly built SQLite descriptor-batch worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_EFFECTIVE_BATCH_MARKER" \
    "freshly built SQLite effective-batch worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_EFFECTIVE_BATCH_MARKER" \
    "freshly built SQLite effective-batch runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$CRYPTO_INTERFACE_MARKER" \
    "freshly built unified-crypto SQLite worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$CRYPTO_ONLY_MARKER" \
    "freshly built crypto-only SQLite worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$AES_BULK_MARKER" \
    "freshly built bulk-AES SQLite worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_STATUS_COMMIT_MARKER" \
    "freshly built SQLite status release-commit runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_STATUS_COMMIT_MARKER" \
    "freshly built SQLite status stable-read worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_CRYPTO_TIMING_MARKER" \
    "freshly built SQLite crypto-only timing worker"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
    "$SQLITE_STATIC_FREEMEM_MARKER" \
    "freshly built SQLite static-buffer freemem runner"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-master.eapp_riscv" \
    "$LOADER_ABI_MARKER" \
    "freshly built SQLite master ABI"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_YXSTM_MARKER" \
    "freshly built SQLite worker eapp"
  require_text_marker \
    "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
    "$LOADER_ABI_MARKER" \
    "freshly built SQLite worker ABI"
}

deploy_example() {
  local enclave_build_dir="$1"
  local deploy_dir="$SCRIPT_DIR/deploy"
  local legacy_aes="${GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS:-OFF}"
  local native_aes="${GROUP_PMP_ENABLE_NATIVE_AES_DIAGNOSTIC:-ON}"

  case "$legacy_aes" in
    1|ON|on|TRUE|true|YES|yes) legacy_aes=ON ;;
    *) legacy_aes=OFF ;;
  esac
  case "$native_aes" in
    1|ON|on|TRUE|true|YES|yes) native_aes=ON ;;
    *) native_aes=OFF ;;
  esac

  echo_info "preparing deploy directory: $deploy_dir"
  rm -rf "$deploy_dir"
  mkdir -p "$deploy_dir"

  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-private-probe.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-timeslice-a.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-timeslice-b.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-timeslice-check.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-lease-hold.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-ocall-blocker.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-dispatch.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-worker.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-aggregate.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-miss.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-worker-dispatch-rw-denied.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-worker-cross-slice-fault.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-worker-slice0-fault.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-aggregate-rw-denied.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-no-acquire-fault.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-release-fault.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-hold-yield.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-inherit-fault.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-exec-fault.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-fault.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mixed-master.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mixed-worker.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-master.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mediabench-board-runner"
  require_file "$SCRIPT_DIR/run-mediabench-board-smoke.sh"
  for media_codec in mpeg4 jp2 h264-enc h264-dec; do
    require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mediabench-${media_codec}-board.eapp_riscv"
  done
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-enclave-baseline.eapp_riscv"
  if [ "$legacy_aes" = "ON" ]; then
    require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-utm-bench.eapp_riscv"
    require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-master-encrypt.eapp_riscv"
    require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-master-decrypt.eapp_riscv"
    require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-worker.eapp_riscv"
    require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-scale-worker.eapp_riscv"
  fi
  if [ "$native_aes" = "ON" ]; then
    require_file "$enclave_build_dir/$EXAMPLE_NAME/aes-native-baseline"
    require_file "$enclave_build_dir/$EXAMPLE_NAME/crypto-native-baseline"
    require_text_marker \
      "$enclave_build_dir/$EXAMPLE_NAME/crypto-native-baseline" \
      "keystone-native-crypto-ecc-sha256-v1" \
      "freshly built ECC/SHA-256 native benchmark"
    require_text_marker \
      "$enclave_build_dir/$EXAMPLE_NAME/crypto-native-baseline" \
      "keystone-native-crypto-portable-openssl-v1" \
      "freshly built portable OpenSSL native benchmark"
    require_text_marker \
      "$enclave_build_dir/$EXAMPLE_NAME/crypto-native-baseline" \
      "keystone-native-counter-perf-v1" \
      "freshly built portable native counter benchmark"
    require_text_marker \
      "$enclave_build_dir/$EXAMPLE_NAME/crypto-native-baseline" \
      "keystone-native-crypto-supplied-sm2-micro-ecc-v2" \
      "freshly built OpenSSL-compatible supplied SM2/micro-ecc benchmark"
  fi
  if [ "${GROUP_PMP_ENABLE_SPARK_SCHEDULER:-OFF}" = "ON" ]; then
    require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-task-master.eapp_riscv"
    require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-task-worker.eapp_riscv"
  fi
  require_file "$enclave_build_dir/$EXAMPLE_NAME/eyrie-rt"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/loader.bin"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/usb-sd-bench.riscv64"

  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/usb-sd-bench.riscv64" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-private-probe.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-timeslice-a.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-timeslice-b.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-timeslice-check.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-lease-hold.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-ocall-blocker.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-dispatch.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-worker.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-aggregate.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-miss.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-worker-dispatch-rw-denied.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-worker-cross-slice-fault.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-worker-slice0-fault.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-aggregate-rw-denied.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-no-acquire-fault.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-release-fault.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-hold-yield.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-inherit-fault.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-exec-fault.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mw-master-fault.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mixed-master.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mixed-worker.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-master.eapp_riscv" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" "$deploy_dir/"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-kv-worker.eapp_riscv"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-motivation-worker.eapp_riscv"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-motivation-worker.eapp_riscv" "$deploy_dir/"
  cmp -s "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-motivation-worker.eapp_riscv" \
    "$deploy_dir/group-pmp-motivation-worker.eapp_riscv" || exit 1
  require_text_marker "$deploy_dir/group-pmp-motivation-worker.eapp_riscv" \
    "keystone-worker-overlap-v7" "motivation Worker recycle-submit protocol v7"
  for motivation_artifact in group-pmp-test-runner group-pmp-motivation-worker.eapp_riscv; do
    require_text_marker "$deploy_dir/$motivation_artifact" \
      "keystone-motivation-protected-task-v4" "minimal active Master/protected TSR recycle-submit task protocol"
  done
  cp -v "$SCRIPT_DIR/run-motivation-architecture.sh" "$deploy_dir/"
  chmod +x "$deploy_dir/run-motivation-architecture.sh"
  require_text_marker "$deploy_dir/group-pmp-test-runner" \
    "keystone-motivation-epm-reservation-v2" "motivation matched EPM reservation"
  require_text_marker "$deploy_dir/group-pmp-test-runner" \
    "keystone-motivation-three-config-v2" "motivation 1-Sync/1-Async/3-Async experiment"
  require_text_marker "$deploy_dir/group-pmp-test-runner" \
    "keystone-motivation-shared-uring-v3" "motivation shared SQLite/FIO io_uring transport"
  require_text_marker "$deploy_dir/group-pmp-test-runner" \
    "keystone-motivation-blocking-ocall-v4" "motivation blocking read OCALL contract"
  mkdir -p "$deploy_dir/motivation"
  cp -v "$SCRIPT_DIR/motivation/summarize.py" "$SCRIPT_DIR/motivation/README.md" \
    "$SCRIPT_DIR/motivation/minimal-architecture.md" "$deploy_dir/motivation/"
  cp -v "$SCRIPT_DIR/run-motivation-system.sh" "$deploy_dir/"
  chmod +x "$deploy_dir/run-motivation-system.sh"
  cp -v "$SCRIPT_DIR/motivation/system-summary.py" "$deploy_dir/motivation/"
  require_text_marker "$deploy_dir/group-pmp-test-runner" \
    "keystone-motivation-real-system-v1" "Extent-I/O real-system motivation"
  require_text_marker "$deploy_dir/group-pmp-test-runner" \
    "keystone-motivation-production-interface-v1" "motivation direct SQLite/fio interface selection"
  require_text_marker "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "keystone-motivation-real-system-v1" "enclave crypto timeline export"
  (
    cd "$SCRIPT_DIR"
    sha256sum motivation/core.c motivation/core.h motivation/protocol.h motivation/backend.hpp \
      eapp/aes_core.c eapp/aes_core.h \
      motivation/architecture.c motivation/architecture.h host/motivation-architecture.hpp run-motivation-architecture.sh \
      motivation/read-engine.hpp motivation/uring-io.hpp host/io-uring-transport.hpp host/sqlite-extent-io.cpp \
      motivation/system-trace.h motivation/system-summary.py host/motivation-system.hpp \
      run-motivation-system.sh sqlite-bench-master/keystone_enclave_store.c eapp/group-pmp-sqlite-worker.c \
      eapp/group-pmp-motivation-worker.c host/motivation.hpp host/motivation-enclave-config.hpp host/group-pmp-test-runner.cpp \
      CMakeLists.txt rebuild-and-test.sh run-motivation-overlap.sh motivation/summarize.py \
      run-rv8-enclave-scaling.sh run-p10-mixed-scaling.sh
    printf 'source_commit='
    git rev-parse --verify HEAD 2>/dev/null || printf 'unavailable; identify this build by source hashes above\n'
  ) > "$deploy_dir/motivation/source-sha256.txt"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-kv-worker.eapp_riscv" "$deploy_dir/"
  cmp -s "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-kv-worker.eapp_riscv" \
    "$deploy_dir/group-pmp-kv-worker.eapp_riscv" || exit 1
  require_text_marker "$deploy_dir/group-pmp-kv-worker.eapp_riscv" \
    "keystone-enclave-kv-pipeline-v1" "deployed KV worker"
  require_text_marker "$deploy_dir/group-pmp-test-runner" \
    "keystone-enclave-kv-pipeline-v1" "deployed KV Host entry"
  for cipher_artifact in group-pmp-test-runner group-pmp-sqlite-worker.eapp_riscv group-pmp-kv-worker.eapp_riscv; do
    require_text_marker "$deploy_dir/$cipher_artifact" \
      "keystone-benchmark-cipher-v1" "deployed selectable-cipher artifact"
  done
  for rv8_kernel in bigint miniz norx aes qsort sha-512 dhrystone primes; do
    local rv8_artifact="group-pmp-rv8-${rv8_kernel}-worker.eapp_riscv"
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/$rv8_artifact" "$deploy_dir/"
    cmp -s "$enclave_build_dir/$EXAMPLE_NAME/$rv8_artifact" "$deploy_dir/$rv8_artifact" || exit 1
    require_text_marker "$deploy_dir/$rv8_artifact" \
      "keystone-rv8-enclave-compute-v2" "deployed RV8 CPU worker"
  done
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-security-scan" "$deploy_dir/"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-security-capture"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-security-capture" "$deploy_dir/"
  mkdir -p "$deploy_dir/security-evidence"
  cp -v "$SCRIPT_DIR/security/verify-capture.py" "$SCRIPT_DIR/security/build-evidence-module.sh" "$deploy_dir/security-evidence/"
  mkdir -p "$deploy_dir/security-evidence/kernel"
  cp -v "$SCRIPT_DIR/security/kernel/Makefile" "$SCRIPT_DIR/security/kernel/"*.c \
    "$SCRIPT_DIR/security/kernel/"*.h "$deploy_dir/security-evidence/kernel/"
  local kernel_build="${KEYSTONE_KERNEL_BUILD:-${SECURITY_EVIDENCE_KERNEL_BUILD:-}}"
  if [ -n "$kernel_build" ]; then
    local evidence_cross
    evidence_cross="$(dirname "$(command -v riscv64-buildroot-linux-gnu-gcc)")/riscv64-buildroot-linux-gnu-"
    make -C "$kernel_build" M="$KEYSTONE_DRIVER_DIR" ARCH=riscv \
      CROSS_COMPILE="${SECURITY_EVIDENCE_CROSS_COMPILE:-$evidence_cross}" \
      KEYSTONE_SDK_DIR="$KEYSTONE_SDK_SRC_DIR" modules
    cp -v "$KEYSTONE_DRIVER_DIR/keystone-driver.ko" "$deploy_dir/"
  else
    echo_warning "Set KEYSTONE_KERNEL_BUILD to build/deploy the matching keystone-driver.ko"
  fi
  if [ -n "${SECURITY_EVIDENCE_KERNEL_BUILD:-}" ]; then
    CROSS_COMPILE="${SECURITY_EVIDENCE_CROSS_COMPILE:-$evidence_cross}" \
      sh "$SCRIPT_DIR/security/build-evidence-module.sh" "$SECURITY_EVIDENCE_KERNEL_BUILD" "$deploy_dir/keystone_evidence.ko"
  else
    echo_warning "Security kernel observer source deployed; set SECURITY_EVIDENCE_KERNEL_BUILD to the exact built board kernel to compile its .ko"
  fi
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-security-aead.eapp_riscv" "$deploy_dir/"
  require_file "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-crypto-compute-worker.eapp_riscv"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-crypto-compute-worker.eapp_riscv" "$deploy_dir/"
  for crypto_compute_artifact in group-pmp-test-runner group-pmp-crypto-compute-worker.eapp_riscv; do
    require_text_marker "$deploy_dir/$crypto_compute_artifact" \
      "keystone-crypto-compute-startup-v2" "single-worker pure crypto benchmark"
  done
  cp -v "$SCRIPT_DIR/run-crypto-compute-bench.sh" "$deploy_dir/"
  chmod +x "$deploy_dir/run-crypto-compute-bench.sh"
  mkdir -p "$deploy_dir/crypto-compute"
  cp -v "$SCRIPT_DIR/crypto-compute/summarize.py" "$SCRIPT_DIR/crypto-compute/README.md" "$deploy_dir/crypto-compute/"
  (
    cd "$SCRIPT_DIR"
    sha256sum eapp/crypto-compute.c eapp/crypto-compute.h eapp/group-pmp-crypto-compute-worker.c \
      host/crypto-compute.hpp host/group-pmp-test-runner.cpp eapp/benchmark-cipher.c \
      eapp/group-pmp-crypto.c eapp/aes_core.c security/aead-config.h \
      run-crypto-compute-bench.sh crypto-compute/summarize.py CMakeLists.txt rebuild-and-test.sh
  ) > "$deploy_dir/crypto-compute/source-sha256.txt"
  for security_region in epm tsr-unacquired tsr-cross tsr-revoked; do
    for security_operation in read write; do
      cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-security-${security_region}-${security_operation}.eapp_riscv" "$deploy_dir/"
    done
  done
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mediabench-board-runner" "$deploy_dir/"
  cp -v "$SCRIPT_DIR/run-mediabench-board-smoke.sh" "$deploy_dir/"
  for media_codec in mpeg4 jp2 h264-enc h264-dec; do
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mediabench-${media_codec}-board.eapp_riscv" "$deploy_dir/"
  done
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-enclave-baseline.eapp_riscv" "$deploy_dir/"
  if [ "$legacy_aes" = "ON" ]; then
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-utm-bench.eapp_riscv" "$deploy_dir/"
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-master-encrypt.eapp_riscv" "$deploy_dir/"
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-master-decrypt.eapp_riscv" "$deploy_dir/"
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-worker.eapp_riscv" "$deploy_dir/"
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-aes-scale-worker.eapp_riscv" "$deploy_dir/"
  fi
  if [ "$native_aes" = "ON" ]; then
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/aes-native-baseline" "$deploy_dir/"
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/crypto-native-baseline" "$deploy_dir/"
    deploy_native_crypto_libraries \
      "$enclave_build_dir/$EXAMPLE_NAME/crypto-native-baseline" \
      "$deploy_dir"
    require_text_marker \
      "$deploy_dir/crypto-native-baseline" \
      "keystone-native-crypto-ecc-sha256-v1" \
      "deployed ECC/SHA-256 native benchmark"
    require_text_marker \
      "$deploy_dir/crypto-native-baseline" \
      "keystone-native-crypto-portable-openssl-v1" \
      "deployed portable OpenSSL native benchmark"
    require_text_marker \
      "$deploy_dir/crypto-native-baseline" \
      "keystone-native-counter-perf-v1" \
      "deployed portable native counter benchmark"
    require_text_marker \
      "$deploy_dir/crypto-native-baseline" \
      "keystone-native-crypto-supplied-sm2-micro-ecc-v2" \
      "deployed OpenSSL-compatible supplied SM2/micro-ecc benchmark"
  fi
  if [ "${GROUP_PMP_ENABLE_SPARK_SCHEDULER:-OFF}" = "ON" ]; then
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-task-master.eapp_riscv" "$deploy_dir/"
    cp -v "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-task-worker.eapp_riscv" "$deploy_dir/"
  fi
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/eyrie-rt" "$deploy_dir/"
  cp -v "$enclave_build_dir/$EXAMPLE_NAME/loader.bin" "$deploy_dir/"

  verify_loader_artifact "$deploy_dir/loader.bin" "deployed loader.bin"
  require_text_marker \
    "$deploy_dir/eyrie-rt" \
    "$YXSTM_SLOT_WAIT_RUNTIME_MARKER" \
    "deployed eyrie-rt"
  require_text_marker \
    "$deploy_dir/eyrie-rt" \
    "$UTM_DIRECT_DATA_MARKER" \
    "deployed direct-UTM eyrie-rt"
  require_text_marker \
    "$deploy_dir/group-pmp-mixed-worker.eapp_riscv" \
    "$MIXED_WORKER_WAIT_DIAG_MARKER" \
    "deployed mixed worker eapp"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$MIXED_LANE_DYNAMIC_MARKER" \
    "deployed mixed host runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$MIXED_TERMINAL_READY_COMMIT_MARKER" \
    "deployed terminal WORKERS_READY commit runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$MIXED_VARIABLE_SAMPLE_MARKER" \
    "deployed variable-sample aggregation runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_DESCRIPTOR_ACCOUNTING_MARKER" \
    "deployed SQLite descriptor accounting runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_VFS_DIRECTIONAL_ACCOUNTING_MARKER" \
    "deployed SQLite directional VFS accounting runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_VFS_AUTHENTICATED_TRUNCATE_MARKER" \
    "deployed SQLite authenticated truncate runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_POSIX_IO_MARKER" \
    "deployed SQLite POSIX random-I/O runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$MIXED_READY_COALESCING_MARKER" \
    "deployed coalesced WORKERS_READY runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$MIXED_WARMUP_MONOTONIC_STATE_MARKER" \
    "deployed monotonic warmup-state runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_FULL_FLOW_BASELINE_MARKER" \
    "deployed SQLite full-flow baseline runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_NO_EXTENT_BASELINE_MARKER" \
    "deployed SQLite dynamic no-extent baseline runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_CSV_SCHEMA_MARKER" \
    "deployed SQLite CSV schema ($SQLITE_CSV_SCHEMA_MARKER) runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_SCALE_MATCHED_BASELINE_MARKER" \
    "deployed SQLite scale-matched baseline runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_ASYNC_VFS_MARKER" \
    "deployed SQLite async I/O runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_GANTT_TRACE_MARKER" \
    "deployed SQLite request Gantt runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_IO_RANGE_TRACE_MARKER" \
    "deployed SQLite I/O range trace runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_NO_EXTENT_IO_MARKER" \
    "deployed SQLite no-extent runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_BLOCKING_PIPELINE_MARKER" \
    "deployed blocked async-completion runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_BATCH_OCALL_MARKER" \
    "deployed batched OCALL runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_CONTROL_ABI_MARKER" \
    "deployed zero-length control ABI runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_INDEPENDENT_SYNC_MARKER" \
    "deployed independent SQLite SYNC runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_CONFIGURABLE_TOTAL_MARKER" \
    "deployed SQLite configurable total-size runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_WARMUP_OCALL_MARKER" \
    "deployed SQLite warmup OCALL runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$GROUP_EVENT_OVERFLOW_EPOCH_MARKER" \
    "deployed group event overflow epoch runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "keystone-worker-lease-exit-cleanup-v1" \
    "deployed worker lease exit cleanup runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$LOADER_ABI_MARKER" \
    "deployed host runner ABI"
  require_text_marker \
    "$deploy_dir/group-pmp-mixed-master.eapp_riscv" \
    "$MIXED_LANE_DYNAMIC_MARKER" \
    "deployed mixed master eapp"
  require_text_marker \
    "$deploy_dir/group-pmp-mixed-worker.eapp_riscv" \
    "$MIXED_LANE_DYNAMIC_MARKER" \
    "deployed mixed worker eapp contract"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-master.eapp_riscv" \
    "$SQLITE_YXSTM_MARKER" \
    "deployed SQLite master eapp"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-master.eapp_riscv" \
    "$SQLITE_FULL_FLOW_BASELINE_MARKER" \
    "deployed SQLite full-flow baseline master"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_ASYNC_VFS_MARKER" \
    "deployed SQLite host-store worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_CENTRAL_IO_MARKER" \
    "deployed centralized I/O worker ABI"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_CENTRAL_IO_MARKER" \
    "deployed centralized io_uring runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_VFS_ABI_MARKER" \
    "deployed SQLite VFS ABI v12 runner"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_VFS_ABI_MARKER" \
    "deployed SQLite VFS ABI v12 worker"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_UTM_BUDDY_LAYOUT_MARKER" \
    "deployed buddy-sized SQLite UTM runner"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_UTM_BUDDY_LAYOUT_MARKER" \
    "deployed buddy-sized SQLite UTM worker"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_WORKLOAD_IO_POLICY_MARKER" \
    "deployed workload-aware I/O policy runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_ADAPTIVE_REGISTERED_IO_MARKER" \
    "deployed adaptive registered I/O runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_DOUBLE_BUFFER_MARKER" \
    "deployed double-buffer completion runner"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_DOUBLE_BUFFER_MARKER" \
    "deployed double-buffer SQLite worker"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_COMPLETION_FASTPATH_MARKER" \
    "deployed local completion-reap runner"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_COMPLETION_FASTPATH_MARKER" \
    "deployed local completion-reap worker"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$GROUP_BATCHED_OCALL_RESUME_MARKER" \
    "deployed batched blocked-OCALL resume runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_ROLLING_COLLECT_MARKER" \
    "deployed rolling request collector"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_COST_CLUSTER_MARKER" \
    "deployed cost-aware clustering runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_ONLINE_CLUSTER_MARKER" \
    "deployed online clustering runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_CIPHER_CACHE_MARKER" \
    "deployed UTM ciphertext cache runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_SUBMIT_WAIT_ACCOUNTING_MARKER" \
    "deployed submit/wait OCALL accounting runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_ASYNC_COMPLETION_ACCOUNTING_MARKER" \
    "deployed async completion accounting runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_WORKER_BUFFER_DEPTH_MARKER" \
    "deployed worker-side buffer-depth accounting runner"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_EXTENT_CLIENT_MARKER" \
    "deployed SQLite extent client worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_BLOCKING_PIPELINE_MARKER" \
    "deployed blocked async-completion worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_BATCH_OCALL_MARKER" \
    "deployed batched OCALL worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_CONTROL_ABI_MARKER" \
    "deployed zero-length control ABI worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$UTM_DIRECT_DATA_MARKER" \
    "deployed SQLite direct-UTM worker"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_HOST_ENGINE_MARKER" \
    "deployed SQLite WAL connection-pool engine"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_LANE_POOL_MARKER" \
    "deployed SQLite per-lane connection pool runner"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_IMMEDIATE_OCALL_MARKER" \
    "deployed SQLite immediate OCALL enqueue runner"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_BATCHED_RANDOM_READ_MARKER" \
    "deployed SQLite batched random-read worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_EXACT_IO_GRANULARITY_MARKER" \
    "deployed SQLite exact-range worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_DESCRIPTOR_BATCH_MARKER" \
    "deployed SQLite descriptor-batch worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_EFFECTIVE_BATCH_MARKER" \
    "deployed SQLite effective-batch worker"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_EFFECTIVE_BATCH_MARKER" \
    "deployed SQLite effective-batch runner"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$CRYPTO_INTERFACE_MARKER" \
    "deployed unified-crypto SQLite worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$CRYPTO_ONLY_MARKER" \
    "deployed crypto-only SQLite worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$AES_BULK_MARKER" \
    "deployed bulk-AES SQLite worker"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_STATUS_COMMIT_MARKER" \
    "deployed SQLite status release-commit runner"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_STATUS_COMMIT_MARKER" \
    "deployed SQLite status stable-read worker"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_CRYPTO_TIMING_MARKER" \
    "deployed SQLite crypto-only timing worker"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "$SQLITE_STATIC_FREEMEM_MARKER" \
    "deployed SQLite static-buffer freemem runner"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-master.eapp_riscv" \
    "$LOADER_ABI_MARKER" \
    "deployed SQLite master ABI"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$SQLITE_YXSTM_MARKER" \
    "deployed SQLite worker eapp"
  require_text_marker \
    "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv" \
    "$LOADER_ABI_MARKER" \
    "deployed SQLite worker ABI"
  if ! cmp -s \
      "$enclave_build_dir/$EXAMPLE_NAME/loader.bin" \
      "$deploy_dir/loader.bin"; then
    echo_error "deployed loader.bin differs from the freshly built artifact"
    exit 1
  fi
  if ! cmp -s \
      "$enclave_build_dir/$EXAMPLE_NAME/eyrie-rt" \
      "$deploy_dir/eyrie-rt"; then
    echo_error "deployed eyrie-rt differs from the freshly built artifact"
    exit 1
  fi
  if ! cmp -s \
      "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mixed-worker.eapp_riscv" \
      "$deploy_dir/group-pmp-mixed-worker.eapp_riscv"; then
    echo_error "deployed mixed worker eapp differs from the freshly built artifact"
    exit 1
  fi
  if ! cmp -s \
      "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mixed-master.eapp_riscv" \
      "$deploy_dir/group-pmp-mixed-master.eapp_riscv"; then
    echo_error "deployed mixed master eapp differs from the freshly built artifact"
    exit 1
  fi
  if ! cmp -s \
      "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-master.eapp_riscv" \
      "$deploy_dir/group-pmp-sqlite-master.eapp_riscv"; then
    echo_error "deployed SQLite master eapp differs from the freshly built artifact"
    exit 1
  fi
  if ! cmp -s \
      "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-sqlite-worker.eapp_riscv" \
      "$deploy_dir/group-pmp-sqlite-worker.eapp_riscv"; then
    echo_error "deployed SQLite worker eapp differs from the freshly built artifact"
    exit 1
  fi
  if ! cmp -s \
      "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mediabench-board-runner" \
      "$deploy_dir/group-pmp-mediabench-board-runner"; then
    echo_error "deployed MediaBench board runner differs from the freshly built artifact"
    exit 1
  fi
  for media_codec in mpeg4 jp2 h264-enc h264-dec; do
    if ! cmp -s \
        "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-mediabench-${media_codec}-board.eapp_riscv" \
        "$deploy_dir/group-pmp-mediabench-${media_codec}-board.eapp_riscv"; then
      echo_error "deployed MediaBench ${media_codec} eapp differs from the freshly built artifact"
      exit 1
    fi
  done
  if ! cmp -s \
      "$enclave_build_dir/$EXAMPLE_NAME/group-pmp-test-runner" \
      "$deploy_dir/group-pmp-test-runner"; then
    echo_error "deployed mixed host runner differs from the freshly built artifact"
    exit 1
  fi
  if ! cmp -s \
      "$enclave_build_dir/$EXAMPLE_NAME/usb-sd-bench.riscv64" \
      "$deploy_dir/usb-sd-bench.riscv64"; then
    echo_error "deployed SD/USB benchmark differs from the freshly built artifact"
    exit 1
  fi
  require_text_marker \
    "$deploy_dir/usb-sd-bench.riscv64" \
    "usb-sd-file-io-v1" \
    "deployed SD/USB file-I/O benchmark"
  require_text_marker \
    "$deploy_dir/group-pmp-test-runner" \
    "keystone-fio-enclave-profile-v1" \
    "deployed fio enclave profile runner"
  echo_info "copying test run scripts"
  cp -v "$SCRIPT_DIR/analyze-sqlite-neighbors.py" "$deploy_dir/"
  for job in seq-write-2m seq-read-2m rand-write-4k rand-read-4k rand-read-100k; do
    require_file "$SCRIPT_DIR/fio-bench/jobs/$job.fio"
    cp -v "$SCRIPT_DIR/fio-bench/jobs/$job.fio" "$deploy_dir/$job.fio"
    if ! cmp -s "$SCRIPT_DIR/fio-bench/jobs/$job.fio" "$deploy_dir/$job.fio"; then
      echo_error "deployed fio job differs from source: $job.fio"
      exit 1
    fi
  done
  local media_suite="$SCRIPT_DIR/mediabench-ii/vendor/mediabench2_video"
  local media_workload media_name
  for media_name in mpeg4enc mpeg4dec jpg2000enc jpg2000dec h264enc h264dec; do
    media_workload="$media_suite/$media_name/input_base"
    if [ ! -d "$media_workload" ]; then
      echo_error "MediaBench II input directory is missing: $media_workload"
      exit 1
    fi
    mkdir -p "$deploy_dir/mediabench-ii/$media_name"
    cp -R "$media_workload" "$deploy_dir/mediabench-ii/$media_name/"
    if ! diff -qr "$media_workload" \
        "$deploy_dir/mediabench-ii/$media_name/input_base" >/dev/null; then
      echo_error "MediaBench II deployed input differs from source: $media_name"
      exit 1
    fi
  done
  for script in "$SCRIPT_DIR"/run-*.sh; do
    if [ -f "$script" ]; then
      case "$(basename "$script")" in
        run-p10-performance.sh|run-p10-enclave-scaling.sh)
          [ "$legacy_aes" = "ON" ] || continue
          ;;
        run-aes-native-baseline.sh)
          [ "$native_aes" = "ON" ] || continue
          ;;
      esac
      cp -v "$script" "$deploy_dir/"
      chmod +x "$deploy_dir/$(basename "$script")"
    fi
  done
  cp -v "$SCRIPT_DIR/prepare-3w1hm-isolation.sh" "$deploy_dir/"
  chmod +x "$deploy_dir/prepare-3w1hm-isolation.sh"
  require_text_marker \
    "$deploy_dir/prepare-3w1hm-isolation.sh" \
    "keystone-hsm-lease-recovery-v1" \
    "deployed HSM lease recovery isolation script"
  cp -v "$SCRIPT_DIR/prepare-aes-benchmark-env.sh" "$deploy_dir/"
  chmod +x "$deploy_dir/prepare-aes-benchmark-env.sh"
  require_text_marker \
    "$deploy_dir/prepare-aes-benchmark-env.sh" \
    "keystone-worker-cpufreq-v2" \
    "deployed worker cpufreq helper"

  cat > "$deploy_dir/run-group-pmp-test.sh" <<'EOF'
#!/bin/sh
set -eu
cd "$(dirname "$0")"

if [ "${GROUP_PMP_LEASE_TEST_FALLBACK:-0}" != 1 ]; then
  ./prepare-3w1hm-isolation.sh apply
fi

exec ./group-pmp-test-runner \
    group-pmp-private-probe.eapp_riscv \
    group-pmp-timeslice-a.eapp_riscv \
    group-pmp-timeslice-b.eapp_riscv \
    group-pmp-timeslice-check.eapp_riscv \
    group-pmp-ocall-blocker.eapp_riscv \
    group-pmp-mw-master-dispatch.eapp_riscv \
    group-pmp-mw-worker.eapp_riscv \
    group-pmp-mw-master-aggregate.eapp_riscv \
    group-pmp-mw-master-miss.eapp_riscv \
    group-pmp-mw-worker-dispatch-rw-denied.eapp_riscv \
    group-pmp-mw-worker-cross-slice-fault.eapp_riscv \
    group-pmp-mw-worker-slice0-fault.eapp_riscv \
    group-pmp-mw-master-aggregate-rw-denied.eapp_riscv \
    group-pmp-mw-no-acquire-fault.eapp_riscv \
    group-pmp-mw-release-fault.eapp_riscv \
    group-pmp-mw-hold-yield.eapp_riscv \
    group-pmp-mw-inherit-fault.eapp_riscv \
    group-pmp-mw-exec-fault.eapp_riscv \
    eyrie-rt \
    loader.bin \
    "$@"
EOF
  chmod +x "$deploy_dir/run-group-pmp-test.sh"
  chmod +x "$deploy_dir/group-pmp-test-runner"
  chmod +x "$deploy_dir/group-pmp-mediabench-board-runner"
  chmod +x "$deploy_dir/run-mediabench-board-smoke.sh"
  chmod +x "$deploy_dir/usb-sd-bench.riscv64"
  if [ "$native_aes" = "ON" ]; then
    chmod +x "$deploy_dir/aes-native-baseline"
    chmod +x "$deploy_dir/crypto-native-baseline"
  fi
  (cd "$deploy_dir" &&
    find . -type f ! -name SHA256SUMS -print0 |
      sort -z |
      xargs -0 sha256sum > SHA256SUMS)

  echo_success "deploy ready: $deploy_dir"
}

main() {
  case "${1:-}" in
    --help|-h)
      printf '%s\n' 'Usage: bash rebuild-and-test.sh [--check-paths]' \
        'Default: source-build SDK, eapps, Runtime and Host tools; package deploy/.' \
        'Paths: PROJECT_ROOT, KEYSTONE_SDK_SRC_DIR, KEYSTONE_EYRIE_RUNTIME,' \
        '       KEYSTONE_SDK_DIR (install), GROUP_PMP_BUILD_DIR, BUILDROOT_DIR.' \
        'Modules: KEYSTONE_KERNEL_BUILD; optional SECURITY_EVIDENCE_KERNEL_BUILD.' \
        'Legacy Buildroot staging: GROUP_PMP_STANDALONE=0.'
      return ;;
    ''|--check-paths) ;;
    *) echo_error "unknown argument: $1"; return 2 ;;
  esac
  # Resolve before any build function changes the working directory.
  local path_var path_value
  for path_var in KEYSTONE_SDK_SRC_DIR KEYSTONE_EYRIE_RUNTIME KEYSTONE_SM_DIR \
      KEYSTONE_DRIVER_DIR GROUP_PMP_BUILD_DIR KEYSTONE_SDK_DIR BUILDROOT_DIR; do
    path_value="${!path_var}"
    printf -v "$path_var" '%s' "$(realpath -m -- "$path_value")"
  done
  LOADER_SOURCE="$KEYSTONE_EYRIE_RUNTIME/loader-binary/loader-binary.c"
  LOADER_ABI_HEADER="$KEYSTONE_SDK_SRC_DIR/include/shared/sm_call.h"
  SM_ENCLAVE_SOURCE="$KEYSTONE_SM_DIR/src/enclave.c"
  DRIVER_GROUP_SOURCE="$KEYSTONE_DRIVER_DIR/keystone-group.c"
  DRIVER_MAIN_SOURCE="$KEYSTONE_DRIVER_DIR/keystone.c"
  DRIVER_PAGE_SOURCE="$KEYSTONE_DRIVER_DIR/keystone-page.c"
  DRIVER_IOCTL_SOURCE="$KEYSTONE_DRIVER_DIR/keystone-ioctl.c"
  require_file "$KEYSTONE_SDK_SRC_DIR/CMakeLists.txt"
  require_file "$KEYSTONE_EYRIE_RUNTIME/CMakeLists.txt"
  require_file "$SM_ENCLAVE_SOURCE"
  require_file "$DRIVER_MAIN_SOURCE"
  if [ "$KEYSTONE_SDK_DIR" = "$KEYSTONE_SDK_SRC_DIR" ]; then
    echo_error "KEYSTONE_SDK_DIR is an install directory, not the SDK source directory"
    return 2
  fi
  case "$GROUP_PMP_BUILD_DIR/" in
    "$SCRIPT_DIR/"|"$PROJECT_ROOT/"|/)
      echo_error "GROUP_PMP_BUILD_DIR must be a dedicated build subdirectory"; return 2 ;;
  esac
  for path_var in PROJECT_ROOT KEYSTONE_SDK_SRC_DIR KEYSTONE_EYRIE_RUNTIME \
      KEYSTONE_SM_DIR KEYSTONE_DRIVER_DIR GROUP_PMP_BUILD_DIR KEYSTONE_SDK_DIR; do
    echo_info "$path_var=${!path_var}"
  done
  if [ "${1:-}" = --check-paths ]; then
    echo_success 'source paths checked; no build or deployment performed'
    return
  fi
  verify_loader_source
  verify_mixed_sources

  echo_info "project root: $PROJECT_ROOT"
  echo_info "buildroot dir: $BUILDROOT_DIR"
  if [ "$PROJECT_ROOT" != "$SCRIPT_PROJECT_ROOT" ]; then
    echo_warning "PROJECT_ROOT overrides the script source tree"
    echo_warning "script tree: $SCRIPT_PROJECT_ROOT"
  fi

  local enclave_build_dir
  enclave_build_dir="$(find_examples_build_dir)"
  echo_info "using examples build dir: $enclave_build_dir"

  sync_sources "$enclave_build_dir"
  build_example "$enclave_build_dir"
  deploy_example "$enclave_build_dir"

  echo_success "done"
  echo_info "copy or run from: $SCRIPT_DIR/deploy"
  echo_info "test command: ./run-group-pmp-test.sh"
}

main "$@"
