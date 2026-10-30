#!/bin/sh
set -eu
cd "$(dirname "$0")"
. ./run-benchmark-cipher.sh

lock_dir=${GROUP_PMP_RUN_LOCK_DIR:-/tmp/keystone-group-pmp-p10.lock}
lock_pid_file=$lock_dir/pid
if ! mkdir "$lock_dir" 2>/dev/null; then
  lock_pid=$(cat "$lock_pid_file" 2>/dev/null || true)
  if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
    echo "[p10][ERROR] another group-PMP test owns the worker harts: pid=$lock_pid" >&2
    exit 1
  fi
  rm -f "$lock_pid_file"
  rmdir "$lock_dir" 2>/dev/null || {
    echo "[p10][ERROR] cannot clear stale run lock: $lock_dir" >&2
    exit 1
  }
  mkdir "$lock_dir" 2>/dev/null || {
    echo "[p10][ERROR] cannot acquire worker-hart run lock: $lock_dir" >&2
    exit 1
  }
fi
printf '%s\n' "$$" > "$lock_pid_file"
lock_held=1

release_run_lock()
{
  if [ "${lock_held:-0}" = 1 ]; then
    lock_held=0
    rm -f "$lock_pid_file"
    rmdir "$lock_dir" 2>/dev/null || true
  fi
}

trap 'release_run_lock' EXIT HUP INT TERM

prepare_sqlite_output_dir()
{
  if ! mkdir -p "$GROUP_PMP_SQLITE_OUTPUT_DIR" ||
     [ ! -d "$GROUP_PMP_SQLITE_OUTPUT_DIR" ] ||
     [ ! -w "$GROUP_PMP_SQLITE_OUTPUT_DIR" ]; then
    echo "[p10][sqlite-bench][ERROR] result directory is not writable: $GROUP_PMP_SQLITE_OUTPUT_DIR" >&2
    exit 1
  fi
}

usage()
{
  echo "  prefix option: --cipher aes-ecb-128|aes-gcm-128|chacha20-poly1305 (default aes-ecb-128)" >&2
  echo "usage: $0 [max-workers] [repetitions]" >&2
  echo "       $0 mixed-scale [max-workers] [repetitions]" >&2
  echo "       $0 sqlite-bench [sync-no-extent|async-no-extent|adaptive-extent|both|all|random-pair] [max-workers] [repetitions] [total-size] [hot|cold|direct]" >&2
  echo "       $0 sqlite-bench <mode> [max-workers] [repetitions] sweep [hot|cold|direct]" >&2
  echo "  address workload: locality-random-v1 (shared by all modes)" >&2
  echo "  runs worker-count experiments 1..max-workers (valid range: 1..64)" >&2
  echo "  repetitions defaults to 5; mixed-scale accepts 5..50" >&2
  echo "  sqlite-bench accepts 1..4 for previews, or 5..20 for statistics" >&2
  echo "  SQLite total-size is decimal MB (for example 512MB), default 512MB" >&2
  echo "  small multi-sample run: sqlite-bench all 15 5 60MB cold" >&2
  echo "  single-sample 512MB diagnostic: sqlite-bench adaptive-extent 15 1 512MB cold" >&2
  echo "  fillrandom/readrandom only: sqlite-bench random-pair 15 1 512MB cold (Async then Adaptive)" >&2
  echo "  six sizes (60,100,200,300,400,500 MB): sqlite-bench random-pair 15 sweep cold (5 repetitions each)" >&2
  echo "  override sweep repetitions: sqlite-bench random-pair 15 1 sweep cold (preview)" >&2
  echo "  sweep uses automatic per-size CSV names and removes per-size temporary databases/ciphertext after each run" >&2
  echo "  custom CSV/trace output paths are not supported in sweep mode" >&2
  echo "  results default to /sqlite-bench-{ecb,gcm,chacha}/; GROUP_PMP_SQLITE_OUTPUT_DIR overrides it, including sweep" >&2
  echo "  both compares sync-no-extent with adaptive-extent; all also includes async-no-extent" >&2
  echo "  standalone adaptive references: GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV and GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV" >&2
}

if [ "${1:-}" = sqlite-bench ]; then
  GROUP_PMP_SQLITE_OUTPUT_DIR=${GROUP_PMP_SQLITE_OUTPUT_DIR:-/sqlite-bench-$BENCH_CIPHER_SUFFIX}
  case "$GROUP_PMP_SQLITE_OUTPUT_DIR" in
    /*) ;;
    *) echo '[p10][sqlite-bench][ERROR] GROUP_PMP_SQLITE_OUTPUT_DIR must be absolute' >&2; exit 2 ;;
  esac
  export GROUP_PMP_SQLITE_OUTPUT_DIR
  case "${2:-}" in
    extent|adaptive-extent|no-extent|sync-no-extent|async-no-extent|both|all|random-pair)
      if [ "${4:-}" = sweep ] || [ "${5:-}" = sweep ]; then
        sweep_mode=$2
        sweep_workers=${3:-${GROUP_PMP_SQLITE_MAX_WORKERS:-15}}
        if [ "${4:-}" = sweep ]; then
          [ "$#" -le 5 ] || { usage; exit 2; }
          sweep_repetitions=${GROUP_PMP_SQLITE_REPETITIONS:-5}
          sweep_cache=${5:-${GROUP_PMP_SQLITE_CACHE_MODE:-hot}}
        else
          [ "$#" -le 6 ] || { usage; exit 2; }
          sweep_repetitions=${4:-${GROUP_PMP_SQLITE_REPETITIONS:-5}}
          sweep_cache=${6:-${GROUP_PMP_SQLITE_CACHE_MODE:-hot}}
        fi
        case "$sweep_workers:$sweep_repetitions" in
          *[!0-9:]*|:*|*:) usage; exit 2 ;;
        esac
        if [ "$sweep_workers" -lt 1 ] || [ "$sweep_workers" -gt 64 ] ||
           [ "$sweep_repetitions" -lt 1 ] || [ "$sweep_repetitions" -gt 20 ]; then
          usage; exit 2
        fi
        case "$sweep_cache" in
          hot|cold|direct) ;;
          *) echo "SQLite cache mode must be hot, cold, or direct" >&2; exit 2 ;;
        esac
        sweep_min_per_worker=${GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER:-4000000}
        case "$sweep_min_per_worker" in
          ''|*[!0-9]*) echo "invalid GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER" >&2; exit 2 ;;
        esac
        if [ $((sweep_workers * sweep_min_per_worker)) -gt 60000000 ]; then
          echo "SQLite 60MB sweep size is too small for ${sweep_workers} workers; requires $((sweep_workers * sweep_min_per_worker)) bytes" >&2
          exit 2
        fi
        if [ -n "${GROUP_PMP_MIXED_CSV:-}${GROUP_PMP_SQLITE_CSV:-}${GROUP_PMP_SQLITE_IO_RANGE_CSV:-}${GROUP_PMP_SQLITE_GANTT_CSV:-}${GROUP_PMP_SQLITE_NO_EXTENT_CSV:-}${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_CSV:-}${GROUP_PMP_SQLITE_EXTENT_CSV:-}${GROUP_PMP_SQLITE_NO_EXTENT_IO_RANGE_CSV:-}${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_IO_RANGE_CSV:-}${GROUP_PMP_SQLITE_EXTENT_IO_RANGE_CSV:-}${GROUP_PMP_SQLITE_NO_EXTENT_GANTT_CSV:-}${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_GANTT_CSV:-}${GROUP_PMP_SQLITE_EXTENT_GANTT_CSV:-}${GROUP_PMP_SQLITE_NO_EXTENT_BASELINE_CSV:-}${GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV:-}${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV:-}${GROUP_PMP_SQLITE_CALIBRATION_OUTPUT:-}" ]; then
          echo "[p10][sqlite-sweep][ERROR] unset custom CSV, trace, baseline and calibration output paths; the sweep generates distinct paths per size" >&2
          exit 2
        fi
        sweep_storage_root=${GROUP_PMP_SQLITE_STORAGE_DIR:-/tmp}
        if [ "${GROUP_PMP_SQLITE_SWEEP_DRY_RUN:-0}" != 1 ]; then
          prepare_sqlite_output_dir
          if ! mkdir -p "$sweep_storage_root" || [ ! -w "$sweep_storage_root" ]; then
            echo "[p10][sqlite-sweep][ERROR] storage directory is not writable: $sweep_storage_root" >&2
            exit 1
          fi
          sweep_storage_root=$(CDPATH= cd "$sweep_storage_root" && pwd -P) || exit 1
        fi
        cleanup_sweep_storage()
        {
          case "$sweep_data_dir" in
            "$sweep_storage_root"/.keystone-sqlite-sweep-*) ;;
            *) echo "[p10][sqlite-sweep][ERROR] refusing cleanup outside private storage: $sweep_data_dir" >&2; return 1 ;;
          esac
          rm -r "$sweep_data_dir"
        }
        release_run_lock
        trap 'exit 130' INT TERM
        trap 'exit 129' HUP
        echo "[p10][sqlite-sweep] mode=$sweep_mode workers=1..$sweep_workers repetitions=$sweep_repetitions sizes_mb=60,100,200,300,400,500 cache=$sweep_cache storage=private-per-size cleanup=after-child-exit"
        for sweep_mb in 60 100 200 300 400 500; do
          echo "[p10][sqlite-sweep] start size=${sweep_mb}MB"
          sweep_profile=$GROUP_PMP_SQLITE_OUTPUT_DIR/sqlite-merge-cost-${sweep_mode}-${sweep_cache}-${sweep_mb}MB.profile
          if [ "${GROUP_PMP_SQLITE_SWEEP_DRY_RUN:-0}" = 1 ]; then
            echo "[p10][sqlite-sweep][DRY-RUN] GROUP_PMP_SQLITE_OUTPUT_DIR=$GROUP_PMP_SQLITE_OUTPUT_DIR GROUP_PMP_SQLITE_STORAGE_DIR=<private-${sweep_mb}MB-dir> GROUP_PMP_SQLITE_CALIBRATION_OUTPUT=$sweep_profile ./run-p10-mixed-scaling.sh sqlite-bench $sweep_mode $sweep_workers $sweep_repetitions ${sweep_mb}MB $sweep_cache"
            continue
          fi
          sweep_data_dir=$(mktemp -d "$sweep_storage_root/.keystone-sqlite-sweep-${sweep_mb}MB.XXXXXXXX") || exit 1
          if [ "${GROUP_PMP_SQLITE_SWEEP_STORAGE_TEST:-0}" = 1 ]; then
            printf 'test\n' > "$sweep_data_dir/keystone-group-ciphertext.db"
            printf 'test\n' > "$sweep_data_dir/keystone-group-ciphertext.db-wal"
            printf 'test\n' > "$sweep_data_dir/keystone-cipher-0000000000000001.bin"
            printf 'test\n' > "$sweep_profile.log"
            echo "[p10][sqlite-sweep][TEST-ONLY] simulated storage size=${sweep_mb}MB"
            sweep_status=0
          elif GROUP_PMP_SQLITE_STORAGE_DIR=$sweep_data_dir GROUP_PMP_SQLITE_CALIBRATION_OUTPUT=$sweep_profile ./run-p10-mixed-scaling.sh sqlite-bench "$sweep_mode" "$sweep_workers" "$sweep_repetitions" "${sweep_mb}MB" "$sweep_cache"; then
            sweep_status=0
          else
            sweep_status=$?
          fi
          if ! cleanup_sweep_storage; then
            echo "[p10][sqlite-sweep][ERROR] temporary data cleanup failed: $sweep_data_dir" >&2
            exit 1
          fi
          if [ "$sweep_status" -ne 0 ]; then
            echo "[p10][sqlite-sweep][ERROR] stopped at ${sweep_mb}MB status=$sweep_status; previous CSV files are retained" >&2
            exit "$sweep_status"
          fi
          echo "[p10][sqlite-sweep] complete size=${sweep_mb}MB temporary_data=removed"
        done
        echo "[p10][sqlite-sweep] complete sizes_mb=60,100,200,300,400,500"
        exit 0
      fi
      ;;
  esac
fi

if [ "$#" -gt 6 ]; then
  usage
  exit 2
fi

benchmark=mixed-scale
requested_repetitions=
requested_total_size=
requested_cache_mode=${GROUP_PMP_SQLITE_CACHE_MODE:-hot}
sqlite_io_mode=${GROUP_PMP_SQLITE_IO_MODE:-extent}
if [ "${1:-}" = sqlite-bench ]; then
  benchmark=sqlite-bench
  case "${2:-}" in
    extent|adaptive-extent|no-extent|sync-no-extent|async-no-extent|both|all|random-pair)
      sqlite_io_mode=$2
      max_workers=${3:-${GROUP_PMP_SQLITE_MAX_WORKERS:-15}}
      requested_repetitions=${4:-}
      requested_total_size=${5:-512MB}
      requested_cache_mode=${6:-$requested_cache_mode}
      ;;
    *)
      if [ "$#" -gt 5 ]; then
        usage
        exit 2
      fi
      max_workers=${2:-${GROUP_PMP_SQLITE_MAX_WORKERS:-15}}
      requested_repetitions=${3:-}
      requested_total_size=${4:-512MB}
      requested_cache_mode=${5:-$requested_cache_mode}
      ;;
  esac
elif [ "${1:-}" = mixed-scale ]; then
  if [ "$#" -gt 3 ]; then
    usage
    exit 2
  fi
  max_workers=${2:-${GROUP_PMP_MIXED_MAX_WORKERS:-12}}
  requested_repetitions=${3:-}
elif [ "$#" -le 2 ]; then
  max_workers=${1:-${GROUP_PMP_MIXED_MAX_WORKERS:-12}}
  requested_repetitions=${2:-}
else
  usage
  exit 2
fi

case "$max_workers" in
  ''|*[!0-9]*)
    usage
    exit 2
    ;;
esac
if [ "$max_workers" -lt 1 ] || [ "$max_workers" -gt 64 ]; then
  usage
  exit 2
fi
case "$requested_repetitions" in
  *[!0-9]*)
    usage
    exit 2
    ;;
esac
if [ "$benchmark" = sqlite-bench ]; then
  case "$sqlite_io_mode" in
    extent|adaptive-extent|no-extent|sync-no-extent|async-no-extent|both|all|random-pair) ;;
    *)
      echo "SQLite I/O mode must be sync-no-extent, async-no-extent, adaptive-extent, both, all, or random-pair" >&2
      exit 2
      ;;
  esac
  case "$requested_cache_mode" in
    hot|cold|direct) ;;
    *)
      echo "SQLite cache mode must be hot, cold, or direct" >&2
      exit 2
      ;;
  esac
  case "$sqlite_io_mode" in
    extent) sqlite_io_mode=adaptive-extent ;;
    no-extent) sqlite_io_mode=sync-no-extent ;;
  esac
  case "$requested_total_size" in
    *[Mm][Bb])
      sqlite_total_mb=${requested_total_size%??}
      ;;
    *)
      usage
      exit 2
      ;;
  esac
  case "$sqlite_total_mb" in
    ''|*[!0-9]*)
      usage
      exit 2
      ;;
  esac
  if [ "$sqlite_total_mb" -lt 1 ] || [ "$sqlite_total_mb" -gt 16384 ]; then
    echo "SQLite total-size must be in 1MB..16384MB" >&2
    exit 2
  fi
  GROUP_PMP_SQLITE_TOTAL_BYTES=$((sqlite_total_mb * 1000000))
  : "${GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER:=4000000}"
  case "$GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER" in
    ''|*[!0-9]*)
      echo "invalid GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER=$GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER" >&2
      exit 2
      ;;
  esac
  sqlite_minimum_total_bytes=$((max_workers * GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER))
  if [ "$GROUP_PMP_SQLITE_TOTAL_BYTES" -lt "$sqlite_minimum_total_bytes" ]; then
    echo "SQLite total-size is too small for ${max_workers} workers; the async pipeline requires at least ${sqlite_minimum_total_bytes} bytes" >&2
    exit 2
  fi
fi

mixed_marker=keystone-mixed-lane-dynamic-v1
terminal_ready_commit_marker=keystone-terminal-ready-commit-v1
variable_sample_marker=keystone-variable-sample-aggregation-v2
sqlite_descriptor_accounting_marker=keystone-sqlite-descriptor-accounting-v1
mixed_ready_coalescing_marker=keystone-worker-ready-coalescing-v1
sqlite_marker=keystone-sqlite-host-engine-v1
sqlite_full_flow_baseline_marker=keystone-sqlite-full-flow-baseline-v1
sqlite_no_extent_baseline_marker=keystone-sqlite-dynamic-no-extent-baseline-v4
sqlite_scale_matched_baseline_marker=keystone-sqlite-scale-matched-baseline-v1
sqlite_async_vfs_marker=keystone-sqlite-host-extent-store-v3
sqlite_central_io_marker=keystone-sqlite-central-io-uring-v9
sqlite_vfs_abi_marker=keystone-sqlite-vfs-abi-v17
sqlite_workload_io_policy_marker=keystone-sqlite-workload-aware-io-policy-v3
sqlite_adaptive_registered_io_marker=keystone-sqlite-adaptive-registered-io-v3
sqlite_double_buffer_marker=keystone-sqlite-double-buffer-outstanding-v5
sqlite_rolling_collect_marker=keystone-sqlite-rolling-collect-v1
sqlite_cost_cluster_marker=keystone-sqlite-cost-aware-cluster-v3
sqlite_cipher_cache_marker=keystone-sqlite-utm-cipher-cache-v2
sqlite_submit_wait_accounting_marker=keystone-sqlite-submit-wait-ocall-accounting-v1
sqlite_async_completion_accounting_marker=keystone-sqlite-async-completion-accounting-v2
sqlite_worker_buffer_depth_marker=keystone-sqlite-worker-buffer-depth-accounting-v1
sqlite_extent_client_marker=keystone-enclave-extent-client-v21
sqlite_blocking_pipeline_marker=keystone-sqlite-blocking-pipeline-v2
sqlite_batch_ocall_marker=keystone-sqlite-batch-ocall-v1
sqlite_control_abi_marker=keystone-sqlite-zero-length-control-v1
sqlite_independent_sync_marker=keystone-sqlite-independent-sync-v1
crypto_interface_marker=keystone-crypto-interface-v1
crypto_only_marker=keystone-crypto-only-v1
aes_bulk_marker=keystone-aes-bulk4-v1
utm_direct_data_marker=keystone-utm-direct-data-v1
sqlite_host_engine_marker=keystone-sqlite-wal-connection-pool-v1
sqlite_lane_pool_marker=keystone-sqlite-lane-pool-v1
sqlite_immediate_ocall_marker=keystone-sqlite-immediate-ocall-v1
sqlite_batched_random_read_marker=keystone-sqlite-batched-random-read-v5
sqlite_exact_io_granularity_marker=keystone-sqlite-exact-io-granularity-v1
sqlite_descriptor_batch_marker=keystone-sqlite-request-completion-ring-v5
sqlite_effective_batch_marker=keystone-sqlite-effective-request-batching-v8
sqlite_completion_fastpath_marker=keystone-sqlite-completion-fastpath-v1
group_batched_ocall_resume_marker=keystone-group-batched-ocall-resume-v1
sqlite_utm_buddy_layout_marker=keystone-sqlite-configurable-ring-v2
sqlite_status_commit_marker=keystone-sqlite-status-release-commit-v1
sqlite_crypto_timing_marker=keystone-sqlite-crypto-oncpu-timing-v2
sqlite_static_freemem_marker=keystone-sqlite-static-buffer-freemem-v1
sqlite_configurable_total_marker=keystone-sqlite-configurable-total-v1
sqlite_warmup_ocall_marker=keystone-sqlite-warmup-ocall-v1
sqlite_gantt_trace_marker=keystone-sqlite-gantt-trace-v4
sqlite_io_range_trace_marker=keystone-sqlite-io-range-trace-v2
sqlite_no_extent_io_marker=keystone-sqlite-no-extent-io-v2
sqlite_csv_schema_version=44
require_benchmark_cipher ./group-pmp-test-runner ./group-pmp-sqlite-worker.eapp_riscv
sqlite_csv_schema_marker=keystone-sqlite-csv-schema-v${sqlite_csv_schema_version}
sqlite_extent_policy_version=51
sqlite_vfs_batch_max=256
sqlite_vfs_ring_bytes=131072
sqlite_vfs_utm_bytes=4141056
lease_exit_cleanup_marker=keystone-worker-lease-exit-cleanup-v1
lease_recovery_marker=keystone-hsm-lease-recovery-v1
for artifact in ./group-pmp-test-runner; do
  if [ ! -f "$artifact" ] || ! grep -aFq "$mixed_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] stale host runner: $artifact" >&2
    exit 1
  fi
  if ! grep -aFq "$terminal_ready_commit_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] host runner lacks terminal WORKERS_READY commit fix: $artifact" >&2
    exit 1
  fi
  if ! grep -aFq "$variable_sample_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] host runner lacks variable-sample aggregation fix: $artifact" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_descriptor_accounting_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] host runner lacks SQLite descriptor accounting fix: $artifact" >&2
    exit 1
  fi
  if ! grep -aFq "$mixed_ready_coalescing_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] host runner lacks coalesced WORKERS_READY fix: $artifact" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_full_flow_baseline_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] host runner lacks SQLite full-flow baseline fix: $artifact" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_no_extent_baseline_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] host runner lacks dynamic no-extent baseline: $artifact" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_csv_schema_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] host runner lacks SQLite CSV schema v${sqlite_csv_schema_version}: $artifact (required marker: $sqlite_csv_schema_marker); deploy matching script and runner" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_scale_matched_baseline_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] host runner lacks scale-matched SQLite baseline comparison: $artifact" >&2
    exit 1
  fi
  if ! grep -aFq "$lease_exit_cleanup_marker" "$artifact"; then
    echo "[p10][$benchmark][ERROR] host runner lacks worker lease exit cleanup: $artifact" >&2
    exit 1
  fi
done
if ! grep -Fq "$lease_recovery_marker" ./prepare-3w1hm-isolation.sh; then
  echo "[p10][$benchmark][ERROR] isolation script lacks stale HSM lease recovery" >&2
  exit 1
fi
if [ "$benchmark" = sqlite-bench ]; then
  if ! artifact_info=$(./group-pmp-test-runner --artifact-info 2>&1); then
    echo "[p10][sqlite-bench][ERROR] runner artifact contract check failed: $artifact_info" >&2
    exit 1
  fi
  case " $artifact_info " in
    *" sqlite_csv_schema=$sqlite_csv_schema_version "*) ;;
    *)
      echo "[p10][sqlite-bench][ERROR] incompatible CSV schema: expected=$sqlite_csv_schema_version info=$artifact_info" >&2
      exit 1
      ;;
  esac
  case " $artifact_info " in
    *" sqlite_vfs_batch_max=488 "*)
      sqlite_vfs_batch_max=488
      sqlite_vfs_ring_bytes=262144
      sqlite_vfs_utm_bytes=4272128
      ;;
  esac
  case " $artifact_info " in
    *" sqlite_vfs_batch_max=$sqlite_vfs_batch_max "*) ;;
    *)
      echo "[p10][sqlite-bench][ERROR] incompatible descriptor capacity: expected=$sqlite_vfs_batch_max info=$artifact_info" >&2
      exit 1
      ;;
  esac
  case " $artifact_info " in
    *" sqlite_vfs_ring_bytes=$sqlite_vfs_ring_bytes "*) ;;
    *)
      echo "[p10][sqlite-bench][ERROR] incompatible descriptor ring size: expected=$sqlite_vfs_ring_bytes info=$artifact_info" >&2
      exit 1
      ;;
  esac
  case " $artifact_info " in
    *" sqlite_vfs_utm_bytes=$sqlite_vfs_utm_bytes "*) ;;
    *)
      echo "[p10][sqlite-bench][ERROR] incompatible worker UTM size: expected=$sqlite_vfs_utm_bytes info=$artifact_info" >&2
      exit 1
      ;;
  esac
  case " $artifact_info " in
    *" sqlite_extent_policy=$sqlite_extent_policy_version "*) ;;
    *)
      echo "[p10][sqlite-bench][ERROR] incompatible extent I/O policy: expected=$sqlite_extent_policy_version info=$artifact_info" >&2
      exit 1
      ;;
  esac
  echo "[p10][sqlite-bench] $artifact_info"

  if [ ! -f ./loader.bin ] ||
     ! grep -aFq "$utm_direct_data_marker" ./loader.bin ||
     [ ! -f ./eyrie-rt ] ||
     ! grep -aFq "$utm_direct_data_marker" ./eyrie-rt; then
    echo "[p10][sqlite-bench][ERROR] stale loader/runtime without direct UTM data mapping" >&2
    exit 1
  fi
  for artifact in \
      ./group-pmp-sqlite-master.eapp_riscv \
      ./group-pmp-sqlite-worker.eapp_riscv; do
    if [ ! -f "$artifact" ] || ! grep -aFq "$sqlite_marker" "$artifact"; then
      echo "[p10][sqlite-bench][ERROR] stale SQLite artifact: $artifact" >&2
      exit 1
    fi
  done
  if ! grep -aFq "$sqlite_full_flow_baseline_marker" \
      ./group-pmp-sqlite-master.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale SQLite full-flow baseline master: ./group-pmp-sqlite-master.eapp_riscv" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_async_vfs_marker" \
      ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$sqlite_async_vfs_marker" ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale async host-store artifacts" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_central_io_marker" \
      ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$sqlite_central_io_marker" ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale artifacts without centralized io_uring extent service" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_vfs_abi_marker" \
      ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$sqlite_vfs_abi_marker" ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale artifacts with pre-v12 SQLite VFS ABI" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_utm_buddy_layout_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$sqlite_utm_buddy_layout_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale artifacts with oversized SQLite worker UTM" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_workload_io_policy_marker" \
      ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without workload-aware I/O policy" >&2
    exit 1
  fi
  if [ "$sqlite_io_mode" != sync-no-extent ] &&
     ! grep -aFq "$sqlite_adaptive_registered_io_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale extent runner without adaptive registered I/O" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_double_buffer_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$sqlite_double_buffer_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale artifacts without true two-request UTM buffering" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_rolling_collect_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without rolling deadline collection" >&2
    exit 1
  fi
  if [ "$sqlite_io_mode" != sync-no-extent ] &&
     { ! grep -aFq "$sqlite_cost_cluster_marker" ./group-pmp-test-runner ||
       ! grep -aFq "$sqlite_cipher_cache_marker" ./group-pmp-test-runner; }; then
    echo "[p10][sqlite-bench][ERROR] stale extent runner without cost clustering/cache" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_submit_wait_accounting_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without submit/wait OCALL accounting" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_async_completion_accounting_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without async completion accounting fix" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_worker_buffer_depth_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without worker-side buffer-depth accounting" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_blocking_pipeline_marker" \
       ./group-pmp-test-runner ||
     ! grep -aFq "$sqlite_blocking_pipeline_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale artifacts without blocked async completion pipeline" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_batch_ocall_marker" \
       ./group-pmp-test-runner ||
     ! grep -aFq "$sqlite_batch_ocall_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale artifacts without batched OCALL pipeline" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_control_abi_marker" \
       ./group-pmp-test-runner ||
     ! grep -aFq "$sqlite_control_abi_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale artifacts with legacy SQLite control request length" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_independent_sync_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner with collective SQLite SYNC barrier" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_extent_client_marker" \
      ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$utm_direct_data_marker" \
      ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$sqlite_host_engine_marker" ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale SQLite WAL connection-pool artifacts" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_lane_pool_marker" ./group-pmp-test-runner ||
     ! grep -aFq "$sqlite_immediate_ocall_marker" ./group-pmp-test-runner ||
     ! grep -aFq "$sqlite_batched_random_read_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale per-lane async/batched-I/O artifacts" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_exact_io_granularity_marker" \
      ./group-pmp-sqlite-worker.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale worker with forced 2 MB random I/O" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_descriptor_batch_marker" \
      ./group-pmp-sqlite-worker.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale worker without batched small-I/O descriptors" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_effective_batch_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$sqlite_effective_batch_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale artifacts without effective request-ring batching" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_completion_fastpath_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$sqlite_completion_fastpath_marker" \
       ./group-pmp-test-runner ||
     ! grep -aFq "$group_batched_ocall_resume_marker" \
       ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale artifacts without local completion reap and batched resume" >&2
    exit 1
  fi
  if ! grep -aFq "$crypto_interface_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$crypto_only_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv ||
     ! grep -aFq "$aes_bulk_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale worker without crypto-only interface" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_status_commit_marker" ./group-pmp-test-runner ||
     ! grep -aFq "$sqlite_status_commit_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale status publication protocol" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_crypto_timing_marker" ./group-pmp-test-runner ||
     ! grep -aFq "$sqlite_crypto_timing_marker" \
       ./group-pmp-sqlite-worker.eapp_riscv; then
    echo "[p10][sqlite-bench][ERROR] stale crypto-only timing artifacts" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_static_freemem_marker" \
      ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without static-buffer freemem sizing" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_configurable_total_marker" \
      ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without configurable SQLite total size" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_warmup_ocall_marker" \
      ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without SQLite warmup OCALL handling" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_gantt_trace_marker" \
      ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without request Gantt tracing" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_io_range_trace_marker" \
      ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without compact I/O range summaries" >&2
    exit 1
  fi
  if ! grep -aFq "$sqlite_no_extent_io_marker" \
      ./group-pmp-test-runner; then
    echo "[p10][sqlite-bench][ERROR] stale runner without independent no-extent path" >&2
    exit 1
  fi
else
  for artifact in \
      ./group-pmp-mixed-master.eapp_riscv \
      ./group-pmp-mixed-worker.eapp_riscv; do
    if [ ! -f "$artifact" ] || ! grep -aFq "$mixed_marker" "$artifact"; then
      echo "[p10][mixed-scale][ERROR] stale mixed artifact: $artifact" >&2
      exit 1
    fi
  done
fi

freq_state="${TMPDIR:-/tmp}/group-pmp-mixed-cpufreq.$$"
GROUP_PMP_CPU_FREQ_STATE=$freq_state
export GROUP_PMP_CPU_FREQ_STATE
freq_locked=0

if ! grep -q 'keystone-worker-cpufreq-v2' \
    ./prepare-aes-benchmark-env.sh; then
  echo "[p10][mixed-scale][ERROR] stale prepare-aes-benchmark-env.sh; rebuild and redeploy" >&2
  exit 1
fi

restore_frequency()
{
  if [ "$freq_locked" = 1 ]; then
    freq_locked=0
    if [ -r "$freq_state" ]; then
      ./prepare-aes-benchmark-env.sh restore ||
        echo "[p10][mixed-scale][ERROR] failed to restore worker CPU frequency" >&2
    fi
  fi
  rm -f "$freq_state"
  release_run_lock
}

trap 'restore_frequency' EXIT HUP INT TERM
freq_locked=1
set +e
./prepare-aes-benchmark-env.sh apply
freq_status=$?
set -e
if [ "$freq_status" -ne 0 ]; then
  echo "[p10][mixed-scale][ERROR] worker CPU frequency apply failed: status=$freq_status" >&2
  exit "$freq_status"
fi

if [ "${GROUP_PMP_LEASE_TEST_FALLBACK:-0}" != 1 ]; then
  ./prepare-3w1hm-isolation.sh apply
fi

GROUP_PMP_TEST_MODE=$benchmark
if [ "$benchmark" = sqlite-bench ]; then
  : "${GROUP_PMP_MIXED_TIMEOUT_SEC:=3600}"
  : "${GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS:=1800000}"
else
  : "${GROUP_PMP_MIXED_TIMEOUT_SEC:=300}"
  : "${GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS:=30000}"
fi
: "${GROUP_PMP_MIXED_REPETITIONS:=5}"
: "${GROUP_PMP_MIXED_RANDOM_SEED:=557103871172}"
GROUP_PMP_MIXED_MAX_WORKERS=$max_workers
GROUP_PMP_SQLITE_MAX_WORKERS=$max_workers
export GROUP_PMP_TEST_MODE
export GROUP_PMP_MIXED_MAX_WORKERS
export GROUP_PMP_MIXED_TIMEOUT_SEC
export GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS
export GROUP_PMP_MIXED_REPETITIONS
export GROUP_PMP_MIXED_RANDOM_SEED
export GROUP_PMP_SQLITE_MAX_WORKERS

if [ "$benchmark" = sqlite-bench ]; then
  prepare_sqlite_output_dir
  : "${GROUP_PMP_SQLITE_STORAGE_DIR:=/tmp}"
  if ! mkdir -p "$GROUP_PMP_SQLITE_STORAGE_DIR" ||
     [ ! -d "$GROUP_PMP_SQLITE_STORAGE_DIR" ] ||
     [ ! -w "$GROUP_PMP_SQLITE_STORAGE_DIR" ]; then
    echo "[p10][sqlite-bench][ERROR] storage directory is not writable: $GROUP_PMP_SQLITE_STORAGE_DIR" >&2
    exit 1
  fi
  if [ -n "$requested_repetitions" ]; then
    GROUP_PMP_SQLITE_REPETITIONS=$requested_repetitions
  else
    : "${GROUP_PMP_SQLITE_REPETITIONS:=$GROUP_PMP_MIXED_REPETITIONS}"
  fi
  case "$GROUP_PMP_SQLITE_REPETITIONS" in
    ''|*[!0-9]*)
      echo "invalid GROUP_PMP_SQLITE_REPETITIONS=$GROUP_PMP_SQLITE_REPETITIONS" >&2
      exit 2
      ;;
  esac
  if [ "$GROUP_PMP_SQLITE_REPETITIONS" -lt 1 ] ||
     [ "$GROUP_PMP_SQLITE_REPETITIONS" -gt 20 ]; then
    echo "GROUP_PMP_SQLITE_REPETITIONS must be in 1..20 (1..4 preview; 5..20 statistics)" >&2
    exit 2
  fi
  : "${GROUP_PMP_SQLITE_RANDOM_SEED:=$GROUP_PMP_MIXED_RANDOM_SEED}"
  : "${GROUP_PMP_SQLITE_ADDRESS_MODE:=locality-random-v1}"
  case "$GROUP_PMP_SQLITE_ADDRESS_MODE" in
    locality-random-v1) ;;
    *) echo "SQLite address mode must be locality-random-v1" >&2; exit 2 ;;
  esac
  export GROUP_PMP_SQLITE_ADDRESS_MODE
  : "${GROUP_PMP_SQLITE_CLUSTER_MODE:=merge}"
  case "$GROUP_PMP_SQLITE_CLUSTER_MODE" in
    merge) ;;
    plan-only)
      if [ "$sqlite_io_mode" != adaptive-extent ]; then
        echo "plan-only is a standalone adaptive-extent diagnostic" >&2; exit 2
      fi ;;
    *) echo "GROUP_PMP_SQLITE_CLUSTER_MODE must be merge or plan-only" >&2; exit 2 ;;
  esac
  export GROUP_PMP_SQLITE_CLUSTER_MODE
  echo "[p10][sqlite-bench] cipher=$GROUP_PMP_BENCH_CIPHER output=$GROUP_PMP_SQLITE_OUTPUT_DIR common_path=3 metadata=batch64 descriptor_limit=$sqlite_vfs_batch_max adaptive_cluster=$GROUP_PMP_SQLITE_CLUSTER_MODE async_cluster=off cache_fill=off depth=64"
  : "${GROUP_PMP_SQLITE_CFS_QUANTUM_MULTIPLIER:=4}"
  : "${GROUP_PMP_SQLITE_IO_MERGE_MAX_BYTES:=8000000}"
  : "${GROUP_PMP_SQLITE_IO_COLLECT_USEC:=50}"
  : "${GROUP_PMP_SQLITE_IO_BATCH_MIN:=128}"
  : "${GROUP_PMP_SQLITE_IO_BATCH_INITIAL:=512}"
  : "${GROUP_PMP_SQLITE_IO_BATCH_MAX:=1024}"
  : "${GROUP_PMP_SQLITE_IO_READ_AMP_PERMILLE:=1100}"
  : "${GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE:=1100}"
  case "$GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE" in
    ''|*[!0-9]*)
      echo "invalid GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE=$GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE" >&2
      exit 2
      ;;
  esac
  if [ "$GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE" -lt 1000 ] ||
     [ "$GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE" -gt 2000 ]; then
    echo "GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE must be in 1000..2000" >&2
    exit 2
  fi
  GROUP_PMP_SQLITE_CACHE_MODE=$requested_cache_mode
  if [ "$GROUP_PMP_SQLITE_REPETITIONS" -eq 1 ]; then
    if [ "$GROUP_PMP_SQLITE_CACHE_MODE" = cold ]; then
      sqlite_sample_policy=single-cold-cache-preview
    else
      sqlite_sample_policy=single-run-preview
    fi
    echo "[p10][sqlite-bench][PREVIEW] one sample only; median/P95/min/max are the same observation and are not publication statistics"
  elif [ "$GROUP_PMP_SQLITE_REPETITIONS" -lt 5 ]; then
    sqlite_sample_policy=multi-sample-preview
    echo "[p10][sqlite-bench][PREVIEW] fewer than five samples; median/P95/min/max are exploratory, not publication statistics"
  else
    sqlite_sample_policy=randomized-multi-sample-statistics
    if [ "$GROUP_PMP_SQLITE_TOTAL_BYTES" -lt 512000000 ]; then
      sqlite_sample_policy=randomized-small-data-multi-sample-statistics
      echo "[p10][sqlite-bench] small-data statistics: repeated samples do not imply steady-state storage behavior"
    fi
  fi
  if [ "$GROUP_PMP_SQLITE_CACHE_MODE" = hot ]; then
    sqlite_cache_file_suffix=
  else
    sqlite_cache_file_suffix=-$GROUP_PMP_SQLITE_CACHE_MODE
  fi
  sqlite_cache_file_suffix=${sqlite_cache_file_suffix}-locality-random-v1
  if [ "$sqlite_vfs_batch_max" = 488 ]; then
    sqlite_cache_file_suffix=${sqlite_cache_file_suffix}-d488
  fi
  if [ "$GROUP_PMP_SQLITE_CLUSTER_MODE" = plan-only ]; then
    sqlite_cache_file_suffix=${sqlite_cache_file_suffix}-plan-only
  fi
  if [ "${GROUP_PMP_MOTIVATION_SYSTEM:-0}" = 1 ]; then
    case "${GROUP_PMP_MOTIVATION_INTERFACE:-sqlite}:${GROUP_PMP_FIO_PROFILE:-}" in
      sqlite:) GROUP_PMP_SQLITE_WORKLOAD_SET=motivation-readseq ;;
      fio:seq-read-2m) GROUP_PMP_SQLITE_WORKLOAD_SET=fio-seq-read-2m ;;
      *) echo '[motivation-system] invalid production interface/profile pair' >&2; exit 2 ;;
    esac
    sqlite_cache_file_suffix=${sqlite_cache_file_suffix}-motivation-readseq
  elif [ "$sqlite_io_mode" = random-pair ]; then
    GROUP_PMP_SQLITE_WORKLOAD_SET=random-pair
    sqlite_cache_file_suffix=${sqlite_cache_file_suffix}-random-pair
  elif [ -n "${GROUP_PMP_FIO_PROFILE:-}" ]; then
    GROUP_PMP_SQLITE_WORKLOAD_SET=fio-${GROUP_PMP_FIO_PROFILE}
    sqlite_cache_file_suffix=${sqlite_cache_file_suffix}-fio-${GROUP_PMP_FIO_PROFILE}
  else
    GROUP_PMP_SQLITE_WORKLOAD_SET=all
  fi
  export GROUP_PMP_SQLITE_WORKLOAD_SET
  if [ -n "${GROUP_PMP_FIO_PROFILE:-}" ]; then
    if ! grep -aFq 'keystone-fio-enclave-profile-v1' ./group-pmp-test-runner; then
      echo '[p10][fio-profile][ERROR] host runner lacks fio workload selection; rebuild and redeploy' >&2
      exit 1
    fi
    export GROUP_PMP_FIO_PROFILE
    echo "[p10][fio-profile] job=${GROUP_PMP_FIO_PROFILE} source=fio-job rw/bs only address_stream=locality-random-v1 storage=${GROUP_PMP_SQLITE_STORAGE_DIR}"
  fi
  if [ "$sqlite_io_mode" != both ] && [ "$sqlite_io_mode" != all ] &&
     [ "$sqlite_io_mode" != random-pair ]; then
    if [ -z "${GROUP_PMP_SQLITE_CSV:-}" ]; then
      GROUP_PMP_SQLITE_CSV=${GROUP_PMP_MIXED_CSV:-${GROUP_PMP_SQLITE_OUTPUT_DIR}/sqlite-bench-${sqlite_io_mode}${sqlite_cache_file_suffix}-${sqlite_total_mb}MB-1-${max_workers}.csv}
    fi
    if [ -z "${GROUP_PMP_SQLITE_IO_RANGE_CSV:-}" ]; then
      GROUP_PMP_SQLITE_IO_RANGE_CSV=$GROUP_PMP_SQLITE_OUTPUT_DIR/sqlite-io-ranges-${sqlite_io_mode}${sqlite_cache_file_suffix}-${sqlite_total_mb}MB-1-${max_workers}.csv
    fi
    GROUP_PMP_SQLITE_IO_MODE=$sqlite_io_mode
    if [ -z "${GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV:-}" ] &&
       [ -n "${GROUP_PMP_SQLITE_NO_EXTENT_BASELINE_CSV:-}" ]; then
      GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV=$GROUP_PMP_SQLITE_NO_EXTENT_BASELINE_CSV
    fi
    if [ -n "${GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV:-}" ]; then
      if [ ! -r "$GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV" ]; then
        echo "[p10][sqlite-bench][ERROR] sync-no-extent baseline CSV is not readable: $GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV" >&2
        exit 1
      fi
      if [ "$GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV" = "$GROUP_PMP_SQLITE_CSV" ]; then
        echo "[p10][sqlite-bench][ERROR] sync baseline and output CSV paths must differ" >&2
        exit 1
      fi
      export GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV
      sqlite_sync_baseline_status="reference-csv:$GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV"
    else
      unset GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV
      sqlite_sync_baseline_status=unavailable
    fi
    if [ -n "${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV:-}" ]; then
      if [ ! -r "$GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV" ]; then
        echo "[p10][sqlite-bench][ERROR] async-no-extent baseline CSV is not readable: $GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV" >&2
        exit 1
      fi
      if [ "$GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV" = "$GROUP_PMP_SQLITE_CSV" ]; then
        echo "[p10][sqlite-bench][ERROR] async baseline and output CSV paths must differ" >&2
        exit 1
      fi
      export GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV
      sqlite_async_baseline_status="reference-csv:$GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV"
    else
      unset GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV
      sqlite_async_baseline_status=unavailable
    fi
    if [ "$sqlite_io_mode" = sync-no-extent ]; then
      sqlite_sync_baseline_status=current-run
    elif [ "$sqlite_io_mode" = async-no-extent ]; then
      sqlite_async_baseline_status=current-run
    fi
  fi
  export GROUP_PMP_SQLITE_REPETITIONS
  export GROUP_PMP_SQLITE_RANDOM_SEED
  export GROUP_PMP_SQLITE_STORAGE_DIR
  export GROUP_PMP_SQLITE_TOTAL_BYTES
  export GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER
  export GROUP_PMP_SQLITE_CFS_QUANTUM_MULTIPLIER
  export GROUP_PMP_SQLITE_IO_MERGE_MAX_BYTES
  export GROUP_PMP_SQLITE_IO_COLLECT_USEC
  export GROUP_PMP_SQLITE_IO_BATCH_MIN
  export GROUP_PMP_SQLITE_IO_BATCH_INITIAL
  export GROUP_PMP_SQLITE_IO_BATCH_MAX
  export GROUP_PMP_SQLITE_IO_READ_AMP_PERMILLE
  export GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE
  export GROUP_PMP_SQLITE_CACHE_MODE
  if [ "$sqlite_io_mode" != both ] && [ "$sqlite_io_mode" != all ] &&
     [ "$sqlite_io_mode" != random-pair ]; then
    export GROUP_PMP_SQLITE_CSV
    export GROUP_PMP_SQLITE_IO_RANGE_CSV
    export GROUP_PMP_SQLITE_IO_MODE
  fi
  if [ "${GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC:-0}" = 1 ]; then
    case "$sqlite_io_mode" in
      adaptive-extent|async-no-extent) ;;
      *) echo "Neighbor diagnostics require a single adaptive-extent or async-no-extent run" >&2; exit 1 ;;
    esac
    if [ -z "${GROUP_PMP_SQLITE_GANTT_CSV:-}" ]; then
      echo "Set GROUP_PMP_SQLITE_GANTT_CSV to a separate diagnostic CSV path" >&2
      exit 1
    fi
    GROUP_PMP_SQLITE_GANTT_MAX_EVENTS=${GROUP_PMP_SQLITE_GANTT_MAX_EVENTS:-524288}
    export GROUP_PMP_SQLITE_NEIGHBOR_DIAGNOSTIC GROUP_PMP_SQLITE_GANTT_MAX_EVENTS
    GROUP_PMP_SQLITE_NEIGHBOR_WORKLOAD=${GROUP_PMP_SQLITE_NEIGHBOR_WORKLOAD:-7}
    GROUP_PMP_SQLITE_NEIGHBOR_WORKERS=${GROUP_PMP_SQLITE_NEIGHBOR_WORKERS:-$max_workers}
    GROUP_PMP_SQLITE_NEIGHBOR_SAMPLE=${GROUP_PMP_SQLITE_NEIGHBOR_SAMPLE:-1}
    export GROUP_PMP_SQLITE_NEIGHBOR_WORKLOAD GROUP_PMP_SQLITE_NEIGHBOR_WORKERS GROUP_PMP_SQLITE_NEIGHBOR_SAMPLE
    GROUP_PMP_SQLITE_CSV="${GROUP_PMP_SQLITE_GANTT_CSV}.diagnostic-perf.csv"
    GROUP_PMP_SQLITE_IO_RANGE_CSV="${GROUP_PMP_SQLITE_GANTT_CSV}.diagnostic-ranges.csv"
    export GROUP_PMP_SQLITE_CSV GROUP_PMP_SQLITE_IO_RANGE_CSV
    echo "[p10][sqlite-bench][DIAGNOSTIC] resolved request timeline enabled; do not use this run as a throughput benchmark"
    echo "[p10][sqlite-bench][DIAGNOSTIC] trace workload=${GROUP_PMP_SQLITE_NEIGHBOR_WORKLOAD} workers=${GROUP_PMP_SQLITE_NEIGHBOR_WORKERS} sample=${GROUP_PMP_SQLITE_NEIGHBOR_SAMPLE}; zero selects all"
  fi
  if [ -n "${GROUP_PMP_SQLITE_GANTT_CSV:-}" ]; then
    export GROUP_PMP_SQLITE_GANTT_CSV
    gantt_status=$GROUP_PMP_SQLITE_GANTT_CSV
  else
    unset GROUP_PMP_SQLITE_GANTT_CSV
    gantt_status=disabled
  fi
  if [ "$sqlite_io_mode" = both ] || [ "$sqlite_io_mode" = all ] ||
     [ "$sqlite_io_mode" = random-pair ]; then
    if [ "$sqlite_io_mode" = all ]; then
      sqlite_mode_order=sync-no-extent,async-no-extent,adaptive-extent
      sqlite_comparisons=adaptive-vs-sync+adaptive-vs-async
    elif [ "$sqlite_io_mode" = random-pair ]; then
      sqlite_mode_order=async-no-extent,adaptive-extent
      sqlite_comparisons=adaptive-vs-async
    else
      sqlite_mode_order=sync-no-extent,adaptive-extent
      sqlite_comparisons=adaptive-vs-sync
    fi
    echo "[p10][sqlite-bench] io_mode=${sqlite_io_mode} order=${sqlite_mode_order} workloads=${GROUP_PMP_SQLITE_WORKLOAD_SET} workers=1..${max_workers} repetitions=${GROUP_PMP_SQLITE_REPETITIONS} sample_policy=${sqlite_sample_policy} total_data_mb=${sqlite_total_mb} cache_mode=${GROUP_PMP_SQLITE_CACHE_MODE} comparisons=${sqlite_comparisons} adaptive_gain_target_permille=${GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE} io_granularity=seq:2MB,random:4KB,readrand100k:100KB worker_outstanding=2 max_outstanding_descriptors=$((sqlite_vfs_batch_max * 2)) host_batch=arrived-only+persistent-inflight readrand100k_batch=128..256 readrand100k_per_buffer=20 readseq_prefetch=independent-rings+common-async-paired-doorbell readseq_completion=per-buffer sequential_write=independent-buffer-ring readseq_payload=ciphertext-only io_clock=submit+reactor-wait+separate-fdatasync completion=local-reap+batch-resume-ioctl+one-ipi-per-lane cfs=ready-only+lane-depth-quantum resources=registered-file+2xregistered-utm-buffer+2x$((sqlite_vfs_ring_bytes / 2048))KiB-ring worker_utm_bytes=${sqlite_vfs_utm_bytes} io_policy=adaptive-io-stack-v${sqlite_extent_policy_version}:seq-8MB+random-read-4MB-bucket-cost-cluster+read-amp-1.10+sequence-safe-random-write+write-overlap-accounting+net-benefit-cluster+common-cost-clock+fixed-depth64+sequential-ready-accounting cache_contract=fadvise-after-prefill-for-cold+aligned-O_DIRECT-for-direct io_summary=workload-by-worker-count output=automatic"
  else
    echo "[p10][sqlite-bench] io_mode=${GROUP_PMP_SQLITE_IO_MODE} cache_mode=${GROUP_PMP_SQLITE_CACHE_MODE} workloads=fillseq,fillseqbatch,fillrandom,fillrandombatch,overwrite,readseq,readrandom,readrand100k workers=1..${max_workers} repetitions=${GROUP_PMP_SQLITE_REPETITIONS} sample_policy=${sqlite_sample_policy} total_data_mb=${sqlite_total_mb} adaptive_gain_target_permille=${GROUP_PMP_SQLITE_MIN_ADAPTIVE_GAIN_PERMILLE} io_granularity=seq:2MB,random:4KB,readrand100k:100KB worker_outstanding=2 host_batch=arrived-only+persistent-inflight readrand100k_batch=128..256 readrand100k_per_buffer=20 readseq_prefetch=independent-rings+common-async-paired-doorbell readseq_completion=per-buffer sequential_write=independent-buffer-ring readseq_payload=ciphertext-only io_clock=submit+reactor-wait+separate-fdatasync completion=local-reap+batch-resume-ioctl+one-ipi-per-lane resources=registered-file+2xregistered-utm-buffer io_policy=adaptive-io-stack-v${sqlite_extent_policy_version}:seq-8MB+random-read-4MB-bucket-cost-cluster+read-amp-1.10+sequence-safe-random-write+write-overlap-accounting+net-benefit-cluster+common-cost-clock+fixed-depth64+sequential-ready-accounting min_data_per_worker_mb=$((GROUP_PMP_SQLITE_MIN_BYTES_PER_WORKER / 1000000)) crypto=${GROUP_PMP_BENCH_CIPHER} validation=one-block-selftest+extent-edge-samples utm=4KiB-control+2x2MB-data+2x$((sqlite_vfs_ring_bytes / 2048))KiB-ring max_outstanding_per_worker=2 max_outstanding_descriptors=$((sqlite_vfs_batch_max * 2)) blocked_completion=driver-event-wakeup cfs=ready-only+lane-depth+switch-cost-adaptive base_multiplier=${GROUP_PMP_SQLITE_CFS_QUANTUM_MULTIPLIER} storage=${GROUP_PMP_SQLITE_STORAGE_DIR} baseline=one-worker-full-flow sync_baseline=${sqlite_sync_baseline_status} async_baseline=${sqlite_async_baseline_status} csv=${GROUP_PMP_SQLITE_CSV} io_ranges=${GROUP_PMP_SQLITE_IO_RANGE_CSV} gantt=${gantt_status}"
  fi
  echo "[p10][sqlite-bench] address_mode=${GROUP_PMP_SQLITE_ADDRESS_MODE} address_stream=shared-by-sync-async-adaptive version=${sqlite_extent_policy_version}"
  echo "[p10][sqlite-bench] pipeline=v22 async+adaptive=persistent-inflight+incremental-buffer-completion reactor=request-eventfd+CQ-poll adaptive_write_admission=two-buffer-descriptor-reservation async_sqe_depth=64 adaptive_sqe_depth=64 adaptive_inflight_bytes=16MB adaptive_intents=disabled-online-only adaptive_extra_cipher_cache=disabled clustering=all-workloads-arrived-candidates-only objective=fewer-host-data-operations algorithm3=disabled observer=service-ns-per-MB+publication-P95:8/16/32-buffers merge_delay_budget_ns=${GROUP_PMP_SQLITE_IO_MERGE_DELAY_NS:-50000000} delay_budget=predicted-extra-not-hard-SLA adaptive_planning=cross-worker+same-file-case-phase+indexed-ready-neighbours async_planning=per-run-discrete collection=arrived-only-no-wait completion=after-own-CQEs+metadata-commit"
  echo "[p10][sqlite-bench] file_layout=v3 shared_by=sync,async,adaptive buffered=seq-and-100KB-packed+random-4KB-page-aligned-separate-tail direct=page-aligned-regions+1998848-byte-sequential-main-requests direct_tail=exact-length-buffered-accounted utm_capacity=2x2000000 first_write=submit-after-one-buffer adaptive_completion=bounded-arrived-CQE-drain old_layout_baselines=incompatible"
else

if [ -n "$requested_repetitions" ]; then
  GROUP_PMP_MIXED_REPETITIONS=$requested_repetitions
fi
case "$GROUP_PMP_MIXED_REPETITIONS" in
  ''|*[!0-9]*)
    echo "invalid GROUP_PMP_MIXED_REPETITIONS=$GROUP_PMP_MIXED_REPETITIONS" >&2
    exit 2
    ;;
esac
if [ "$GROUP_PMP_MIXED_REPETITIONS" -lt 5 ] ||
   [ "$GROUP_PMP_MIXED_REPETITIONS" -gt 50 ]; then
  echo "GROUP_PMP_MIXED_REPETITIONS must be in 5..50" >&2
  exit 2
fi
export GROUP_PMP_MIXED_REPETITIONS

if [ -n "${GROUP_PMP_MIXED_CSV:-}" ]; then
  export GROUP_PMP_MIXED_CSV
  csv_status=$GROUP_PMP_MIXED_CSV
else
  unset GROUP_PMP_MIXED_CSV
  csv_status=disabled
fi

echo "[p10][mixed-scale] experiments=1..${GROUP_PMP_MIXED_MAX_WORKERS} repetitions=${GROUP_PMP_MIXED_REPETITIONS} randomized_seed=${GROUP_PMP_MIXED_RANDOM_SEED} yxstm=3x12MB-dynamic-slots work=12MB-average-per-worker-lane-balanced prefetch=2-per-lane ocalls_per_worker=1 csv=${csv_status}"
fi

run_sqlite_runner()
{
  if ! rm -f "$GROUP_PMP_SQLITE_CSV" "$GROUP_PMP_SQLITE_IO_RANGE_CSV"; then
    echo "[p10][sqlite-bench][ERROR] cannot remove stale output files" >&2
    return 1
  fi
  if [ -e "$GROUP_PMP_SQLITE_CSV" ] ||
     [ -e "$GROUP_PMP_SQLITE_IO_RANGE_CSV" ]; then
    echo "[p10][sqlite-bench][ERROR] stale output files still exist after cleanup" >&2
    return 1
  fi
  ./group-pmp-test-runner
  run_status=$?
  if [ "$run_status" -ne 0 ]; then
    rm -f "$GROUP_PMP_SQLITE_CSV" "$GROUP_PMP_SQLITE_IO_RANGE_CSV"
  fi
  return "$run_status"
}

if [ "$benchmark" = sqlite-bench ]; then
  case "$sqlite_io_mode" in
    adaptive-extent|extent|both|all|random-pair)
      if [ -z "${GROUP_PMP_SQLITE_MERGE_PROFILE:-}" ]; then
        GROUP_PMP_SQLITE_MERGE_PROFILE=${GROUP_PMP_SQLITE_CALIBRATION_OUTPUT:-${GROUP_PMP_SQLITE_OUTPUT_DIR}/sqlite-merge-cost-${sqlite_extent_policy_version}-${GROUP_PMP_SQLITE_CACHE_MODE}.profile}
        calibration_samples=${GROUP_PMP_SQLITE_CALIBRATION_SAMPLES:-93}
        echo "[p10][sqlite-bench] calibrating mixed batches before measurement: samples=$calibration_samples profile=$GROUP_PMP_SQLITE_MERGE_PROFILE"
        ./group-pmp-test-runner --sqlite-io-calibrate "$calibration_samples" "$GROUP_PMP_SQLITE_MERGE_PROFILE" > "$GROUP_PMP_SQLITE_MERGE_PROFILE.log"
      fi
      export GROUP_PMP_SQLITE_MERGE_PROFILE
      echo "[p10][sqlite-bench] merge_profile=$GROUP_PMP_SQLITE_MERGE_PROFILE calibration_log=$GROUP_PMP_SQLITE_MERGE_PROFILE.log"
      ;;
  esac
fi

run_sqlite_named_mode()
{
  named_mode=$1
  sync_baseline_csv=${2:-}
  async_baseline_csv=${3:-}
  GROUP_PMP_SQLITE_IO_MODE=$named_mode
  case "$named_mode" in
    sync-no-extent)
      GROUP_PMP_SQLITE_CSV=${GROUP_PMP_SQLITE_NO_EXTENT_CSV:-${GROUP_PMP_SQLITE_OUTPUT_DIR}/sqlite-bench-sync-no-extent${sqlite_cache_file_suffix}-${sqlite_total_mb}MB-1-${max_workers}.csv}
      GROUP_PMP_SQLITE_IO_RANGE_CSV=${GROUP_PMP_SQLITE_NO_EXTENT_IO_RANGE_CSV:-${GROUP_PMP_SQLITE_OUTPUT_DIR}/sqlite-io-ranges-sync-no-extent${sqlite_cache_file_suffix}-${sqlite_total_mb}MB-1-${max_workers}.csv}
      gantt_csv=${GROUP_PMP_SQLITE_NO_EXTENT_GANTT_CSV:-}
      ;;
    async-no-extent)
      GROUP_PMP_SQLITE_CSV=${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_CSV:-${GROUP_PMP_SQLITE_OUTPUT_DIR}/sqlite-bench-async-no-extent${sqlite_cache_file_suffix}-${sqlite_total_mb}MB-1-${max_workers}.csv}
      GROUP_PMP_SQLITE_IO_RANGE_CSV=${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_IO_RANGE_CSV:-${GROUP_PMP_SQLITE_OUTPUT_DIR}/sqlite-io-ranges-async-no-extent${sqlite_cache_file_suffix}-${sqlite_total_mb}MB-1-${max_workers}.csv}
      gantt_csv=${GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_GANTT_CSV:-}
      ;;
    adaptive-extent)
      GROUP_PMP_SQLITE_CSV=${GROUP_PMP_SQLITE_EXTENT_CSV:-${GROUP_PMP_SQLITE_OUTPUT_DIR}/sqlite-bench-adaptive-extent${sqlite_cache_file_suffix}-${sqlite_total_mb}MB-1-${max_workers}.csv}
      GROUP_PMP_SQLITE_IO_RANGE_CSV=${GROUP_PMP_SQLITE_EXTENT_IO_RANGE_CSV:-${GROUP_PMP_SQLITE_OUTPUT_DIR}/sqlite-io-ranges-adaptive-extent${sqlite_cache_file_suffix}-${sqlite_total_mb}MB-1-${max_workers}.csv}
      gantt_csv=${GROUP_PMP_SQLITE_EXTENT_GANTT_CSV:-}
      ;;
    *) return 2 ;;
  esac
  if [ -n "$gantt_csv" ]; then
    GROUP_PMP_SQLITE_GANTT_CSV=$gantt_csv
    export GROUP_PMP_SQLITE_GANTT_CSV
  else
    unset GROUP_PMP_SQLITE_GANTT_CSV
  fi
  unset GROUP_PMP_SQLITE_NO_EXTENT_BASELINE_CSV
  if [ -n "$sync_baseline_csv" ]; then
    GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV=$sync_baseline_csv
    export GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV
  else
    unset GROUP_PMP_SQLITE_SYNC_NO_EXTENT_BASELINE_CSV
  fi
  if [ -n "$async_baseline_csv" ]; then
    GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV=$async_baseline_csv
    export GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV
  else
    unset GROUP_PMP_SQLITE_ASYNC_NO_EXTENT_BASELINE_CSV
  fi
  export GROUP_PMP_SQLITE_IO_MODE GROUP_PMP_SQLITE_CSV
  export GROUP_PMP_SQLITE_IO_RANGE_CSV
  echo "[p10][sqlite-bench] start mode=${named_mode} cache=${GROUP_PMP_SQLITE_CACHE_MODE} csv=${GROUP_PMP_SQLITE_CSV} io_ranges=${GROUP_PMP_SQLITE_IO_RANGE_CSV}${sync_baseline_csv:+ sync_baseline=${sync_baseline_csv}}${async_baseline_csv:+ async_baseline=${async_baseline_csv}}"
  run_sqlite_runner
}

set +e
if [ "$benchmark" = sqlite-bench ] &&
   { [ "$sqlite_io_mode" = both ] || [ "$sqlite_io_mode" = all ] ||
     [ "$sqlite_io_mode" = random-pair ]; }; then
  if [ "$sqlite_io_mode" = all ]; then
    run_sqlite_named_mode sync-no-extent
    status=$?
    if [ "$status" -eq 0 ]; then
      sync_no_extent_reference_csv=$GROUP_PMP_SQLITE_CSV
      run_sqlite_named_mode async-no-extent \
        "$sync_no_extent_reference_csv"
      status=$?
    fi
    if [ "$status" -eq 0 ]; then
      async_no_extent_reference_csv=$GROUP_PMP_SQLITE_CSV
      run_sqlite_named_mode adaptive-extent \
        "$sync_no_extent_reference_csv" \
        "$async_no_extent_reference_csv"
      status=$?
    fi
  elif [ "$sqlite_io_mode" = random-pair ]; then
    run_sqlite_named_mode async-no-extent
    status=$?
    if [ "$status" -eq 0 ]; then
      async_no_extent_reference_csv=$GROUP_PMP_SQLITE_CSV
      run_sqlite_named_mode adaptive-extent "" "$async_no_extent_reference_csv"
      status=$?
    fi
  else
    run_sqlite_named_mode sync-no-extent
    status=$?
    if [ "$status" -eq 0 ]; then
      sync_no_extent_reference_csv=$GROUP_PMP_SQLITE_CSV
      run_sqlite_named_mode adaptive-extent \
        "$sync_no_extent_reference_csv"
      status=$?
    fi
  fi
elif [ "$benchmark" = sqlite-bench ]; then
  run_sqlite_runner
  status=$?
else
  ./group-pmp-test-runner
  status=$?
fi
set -e
restore_frequency
trap - EXIT HUP INT TERM
exit "$status"
