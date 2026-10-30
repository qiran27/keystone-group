#ifndef GROUP_PMP_SQLITE_EXTENT_IO_HPP
#define GROUP_PMP_SQLITE_EXTENT_IO_HPP

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include "../eapp/group-pmp-sqlite-vfs-shared.h"
#include "sqlite-gantt-trace.hpp"

constexpr uint64_t kGroupPmpSqliteExtentIoPolicyVersion = UINT64_C(51);
constexpr uint64_t kGroupPmpSqlitePipelineVersion = UINT64_C(25);
constexpr uint64_t kGroupPmpSqliteCommonPathVersion = UINT64_C(3);

inline const char* sqlite_cluster_mode_name() {
  const char* mode = std::getenv("GROUP_PMP_SQLITE_IO_MODE");
  if (mode && std::strcmp(mode, "extent") &&
      std::strcmp(mode, "adaptive-extent")) return "off";
  const char* diagnostic = std::getenv("GROUP_PMP_SQLITE_CLUSTER_MODE");
  return diagnostic && !std::strcmp(diagnostic, "plan-only") ? "plan-only" : "merge";
}

enum SqlitePipelineMetric {
  SQLITE_PIPELINE_SUBMITS, SQLITE_PIPELINE_REFILLS_INFLIGHT,
  SQLITE_PIPELINE_CQE_BATCHES, SQLITE_PIPELINE_BUFFER_COMPLETIONS,
  SQLITE_PIPELINE_EARLY_BUFFERS, SQLITE_PIPELINE_INFLIGHT_PEAK,
  SQLITE_PIPELINE_BYTES_PEAK, SQLITE_PIPELINE_DEPTH_TARGET,
  SQLITE_PIPELINE_DEPTH_GROWS, SQLITE_PIPELINE_DEPTH_SHRINKS,
  SQLITE_PIPELINE_EVENT_WAIT_NS, SQLITE_PIPELINE_BUFFER_PUBLISH_NS,
  SQLITE_PIPELINE_BUFFER_PUBLISH_MAX_NS, SQLITE_PIPELINE_SERVICE_EWMA_NS,
  SQLITE_PIPELINE_TAIL_EWMA_NS, SQLITE_PIPELINE_LOGICAL_TARGET,
  SQLITE_PIPELINE_DEPTH_WINDOWS, SQLITE_PIPELINE_DEPTH_REJECTS,
  SQLITE_PIPELINE_SUBMIT_NS_PER_MB, SQLITE_PIPELINE_READY_EXTENT_JOINS,
  SQLITE_PIPELINE_SQES_ACCEPTED, SQLITE_PIPELINE_SUBMIT_ONE,
  SQLITE_PIPELINE_SUBMIT_2_4, SQLITE_PIPELINE_SUBMIT_5_16,
  SQLITE_PIPELINE_SUBMIT_17_64, SQLITE_PIPELINE_SUBMIT_OVER64,
  SQLITE_PIPELINE_SUBMIT_MAX, SQLITE_PIPELINE_ENTER_CALLS,
  SQLITE_PIPELINE_ENTER_PARTIAL, SQLITE_PIPELINE_CREDIT_LIMITED,
  SQLITE_PIPELINE_BYTE_LIMITED, SQLITE_PIPELINE_READY_EXHAUSTED,
  SQLITE_PIPELINE_ADMIT_ROUNDS, SQLITE_PIPELINE_ADMITTED_PLANS,
  SQLITE_PIPELINE_PLAN_LIMITED, SQLITE_PIPELINE_BARRIER_BLOCKED,
  SQLITE_PIPELINE_WRITE_CONFLICT,
  SQLITE_PIPELINE_SEQ_PEER_INFLIGHT, SQLITE_PIPELINE_SEQ_PEER_QUEUED,
  SQLITE_PIPELINE_SEQ_PEER_ABSENT, SQLITE_PIPELINE_SEQ_PEER_READY_UNJOINED,
  SQLITE_PIPELINE_SEQ_READY_NS,
  SQLITE_PIPELINE_DEPTH_SAMPLES, SQLITE_PIPELINE_DEPTH_STALE_SAMPLES,
  SQLITE_PIPELINE_DEPTH_TRANSITION_SAMPLES, SQLITE_PIPELINE_DEPTH_PROBES,
  SQLITE_PIPELINE_DEPTH_ACCEPTS, SQLITE_PIPELINE_DEPTH_UNEXPOSED,
  SQLITE_PIPELINE_DEPTH_PENDING_SAMPLES, SQLITE_PIPELINE_DEPTH_PROBE_ACTIVE,
  SQLITE_PIPELINE_DEPTH_FAILURE_STREAK, SQLITE_PIPELINE_DEPTH_BACKOFF_WINDOWS,
  SQLITE_PIPELINE_DEPTH_BACKOFF_SKIPS,
  SQLITE_PIPELINE_ADMISSION_WAIT_COUNT, SQLITE_PIPELINE_ADMISSION_WAIT_NS,
  SQLITE_PIPELINE_ADMISSION_WAIT_MAX_NS, SQLITE_PIPELINE_ENQUEUE_LOCK_NS,
  SQLITE_PIPELINE_COMPLETION_INDEXED_TASKS, SQLITE_PIPELINE_COMPLETION_BUFFER_CHECKS,
  SQLITE_PIPELINE_COMPLETION_CHECK_NS, SQLITE_PIPELINE_METADATA_LOOKUP_NS,
  SQLITE_PIPELINE_METADATA_COMMIT_NS, SQLITE_PIPELINE_WAKE_CALLBACK_NS,
  SQLITE_PIPELINE_CROSS_WORKER_PLAN_BATCHES,
  SQLITE_PIPELINE_CROSS_WORKER_PLAN_REQUESTS,
  SQLITE_PIPELINE_CROSS_WORKER_CANDIDATE_REQUESTS,
  SQLITE_PIPELINE_SEQ_LOOKAHEAD_PLANS, SQLITE_PIPELINE_SEQ_LOOKAHEAD_NS,
  SQLITE_PIPELINE_READ100K_BUFFER_BOUNDARIES,
  SQLITE_PIPELINE_READ100K_FEEDBACK_BUFFERS,
  SQLITE_PIPELINE_READ100K_FEEDBACK_STALE,
  SQLITE_PIPELINE_ARRIVED_PROBE_NS, SQLITE_PIPELINE_ARRIVED_PROBE_CHECKS,
  SQLITE_PIPELINE_ARRIVED_EXTEND_REQUESTS, SQLITE_PIPELINE_ARRIVED_NO_CANDIDATE,
  SQLITE_PIPELINE_ARRIVED_PROBE_LIMITED,
  SQLITE_PIPELINE_MERGE_RELEASE_REJECTS, SQLITE_PIPELINE_MERGE_RELEASE_PENALTY_NS,
  SQLITE_PIPELINE_SEQ_LOCAL_CHECKS, SQLITE_PIPELINE_SEQ_LOCAL_NS,
  SQLITE_PIPELINE_SEQ_NONHEAD_JOINS, SQLITE_PIPELINE_SEQ_TAIL_JOINS,
  SQLITE_PIPELINE_CQE_SNAPSHOT_PASSES, SQLITE_PIPELINE_CQE_EXTRA_COMPLETIONS,
  SQLITE_PIPELINE_CQE_DRAIN_NS, SQLITE_PIPELINE_COMPLETION_PUBLICATIONS,
  SQLITE_PIPELINE_COMPLETION_MAX_BUFFERS, SQLITE_PIPELINE_WAKE_FLUSH_BATCHES,
  SQLITE_PIPELINE_WAKE_LANES, SQLITE_PIPELINE_READ100K_DISCRETE_PLAN_BYPASSES,
  SQLITE_PIPELINE_READ100K_RELEASE_NS,
  SQLITE_PIPELINE_WRITE_DEPTH_GUARD_WINDOWS, SQLITE_PIPELINE_WRITE_IO_EWMA_NS,
  SQLITE_PIPELINE_WRITE_IO_RESIDENCY_NS, SQLITE_PIPELINE_WRITE_POST_ENTER_NS,
  SQLITE_PIPELINE_WRITE_POST_ENTER_MAX_NS, SQLITE_PIPELINE_METADATA_ORDER_NS,
  SQLITE_PIPELINE_METADATA_STEPS_NS, SQLITE_PIPELINE_METADATA_FLUSH_NS,
  SQLITE_PIPELINE_METADATA_UPSERT_ROWS, SQLITE_PIPELINE_METADATA_UPSERT_TRANSACTIONS,
  SQLITE_PIPELINE_INTENT_WINDOWS, SQLITE_PIPELINE_INTENT_REQUESTS,
  SQLITE_PIPELINE_INTENT_REORDERED, SQLITE_PIPELINE_INTENT_ADJACENT_PAIRS,
  SQLITE_PIPELINE_INTENT_PLAN_NS, SQLITE_PIPELINE_INTENT_REJECTS,
  SQLITE_PIPELINE_ONLINE_BUFFERS, SQLITE_PIPELINE_ONLINE_CANDIDATE_BUFFERS,
  SQLITE_PIPELINE_ONLINE_MERGED_BUFFERS, SQLITE_PIPELINE_ONLINE_WINDOWS,
  SQLITE_PIPELINE_ONLINE_PROBES, SQLITE_PIPELINE_ONLINE_ACCEPTS,
  SQLITE_PIPELINE_ONLINE_REJECTS, SQLITE_PIPELINE_ONLINE_UNEXPOSED,
  SQLITE_PIPELINE_ONLINE_STALE, SQLITE_PIPELINE_ONLINE_MIXED,
  SQLITE_PIPELINE_ONLINE_SERVICE_NS_PER_MB, SQLITE_PIPELINE_ONLINE_PUBLICATION_P95_NS,
  SQLITE_PIPELINE_ONLINE_REFERENCE_NS_PER_MB, SQLITE_PIPELINE_ONLINE_REFERENCE_P95_NS,
  SQLITE_PIPELINE_ONLINE_MERGING, SQLITE_PIPELINE_ONLINE_PENDING_SAMPLES,
  SQLITE_PIPELINE_ONLINE_COOLDOWN, SQLITE_PIPELINE_ONLINE_EPOCH,
  SQLITE_PIPELINE_ONLINE_WINDOW_TARGET, SQLITE_PIPELINE_ONLINE_LAST_WINDOW_SAMPLES,
  SQLITE_PIPELINE_ONLINE_REFERENCE_SAMPLES, SQLITE_PIPELINE_ONLINE_WINDOW_GROWS,
  SQLITE_PIPELINE_ONLINE_EVALUATED_BUFFERS,
  SQLITE_PIPELINE_CLUSTER_BUDGET_CHECKS, SQLITE_PIPELINE_CLUSTER_BUDGET_ACCEPTS,
  SQLITE_PIPELINE_CLUSTER_DELAY_REJECTS, SQLITE_PIPELINE_CLUSTER_AMP_REJECTS,
  SQLITE_PIPELINE_BOUNDARY_SNAPSHOTS, SQLITE_PIPELINE_BOUNDARY_REFS,
  SQLITE_PIPELINE_BOUNDARY_PROBES, SQLITE_PIPELINE_BOUNDARY_CROSS_PLAN_JOINS,
  SQLITE_PIPELINE_BOUNDARY_MATCH_NS, SQLITE_PIPELINE_BOUNDARY_BACKPRESSURE_PLANS,
  SQLITE_PIPELINE_SEQ_READ_READY_ADMISSIONS, SQLITE_PIPELINE_SEQ_READ_SHARED_SUBMITS,
  SQLITE_PIPELINE_READ100K_PUBLISH_IDLE_SKIPS, SQLITE_PIPELINE_READ100K_VECTOR_PREPARATIONS,
  SQLITE_PIPELINE_BUFFER_PUBLISH_SAMPLES, SQLITE_PIPELINE_BUFFER_PUBLISH_P95_NS,
  SQLITE_PIPELINE_CLUSTER_PLANNED_SAVINGS, SQLITE_PIPELINE_CLUSTER_PLAN_ONLY_BATCHES,
  SQLITE_PIPELINE_BUFFER_ENQUEUE_PUBLISH_P95_NS,
  SQLITE_PIPELINE_BOUNDARY_DRY_CANDIDATES,
  SQLITE_PIPELINE_REQUEST_BUILD_NS, SQLITE_PIPELINE_GROUP_BUILD_NS,
  SQLITE_PIPELINE_VECTOR_PREPARE_NS, SQLITE_PIPELINE_CANDIDATE_SCAN_NS,
  SQLITE_PIPELINE_NET_BENEFIT_CHECKS, SQLITE_PIPELINE_NET_BENEFIT_REJECTS,
  SQLITE_PIPELINE_ESTIMATED_SAVED_NS, SQLITE_PIPELINE_ESTIMATED_EXTRA_NS,
  SQLITE_PIPELINE_READ_SAVED_OP_NS, SQLITE_PIPELINE_WRITE_SAVED_OP_NS,
  SQLITE_PIPELINE_REQUEST_CAPTURE_NS,
  SQLITE_PIPELINE_RELEASE_ORDER_NS, SQLITE_PIPELINE_RELEASE_ORDER_MOVES,
  SQLITE_PIPELINE_METADATA_LOOKUP_BATCHES, SQLITE_PIPELINE_METADATA_LOOKUP_ROWS,
  SQLITE_PIPELINE_METADATA_LOOKUP_LOCK_NS, SQLITE_PIPELINE_METADATA_LOOKUP_CPU_NS,
  SQLITE_PIPELINE_MERGE_CALIBRATED,
  SQLITE_PIPELINE_CALIBRATED_READ_FIXED_NS, SQLITE_PIPELINE_CALIBRATED_READ_VECTOR_NS,
  SQLITE_PIPELINE_CALIBRATED_WRITE_FIXED_NS, SQLITE_PIPELINE_CALIBRATED_WRITE_VECTOR_NS,
  SQLITE_PIPELINE_CALIBRATION_SKIPPED_BATCHES,
  SQLITE_PIPELINE_CALIBRATION_SKIPPED_REQUESTS,
  SQLITE_PIPELINE_CALIBRATION_ZERO_REJECTS,
  SQLITE_PIPELINE_SUBMIT_PREP_WALL_NS, SQLITE_PIPELINE_SUBMIT_PREP_CPU_NS,
  SQLITE_PIPELINE_SUBMIT_ENTER_WALL_NS, SQLITE_PIPELINE_SUBMIT_ENTER_CPU_NS,
  SQLITE_PIPELINE_SUBMIT_ENTER_VOLUNTARY_SWITCHES,
  SQLITE_PIPELINE_SUBMIT_ENTER_INVOLUNTARY_SWITCHES,
  SQLITE_PIPELINE_SUBMIT_ENTER_OUTPUT_BLOCKS,
  SQLITE_PIPELINE_SUBMIT_ENTER_MAX_WALL_NS,
  SQLITE_PIPELINE_SUBMIT_ENTER_SAMPLES,
  SQLITE_PIPELINE_METRICS
};

// One ordered schema for all modes, including zeros in the Sync baseline.
static const char* const sqlite_pipeline_metric_names[] = {
  "submits", "refills_inflight", "cqe_batches", "buffer_completions",
  "early_buffers", "inflight_peak", "bytes_peak", "depth_target",
  "depth_grows", "depth_shrinks", "event_wait_ns", "buffer_publish_ns",
  "buffer_publish_max_ns", "service_ewma_ns", "tail_ewma_ns", "logical_target",
  "depth_windows", "depth_rejects", "submit_ns_per_mb", "ready_extent_joins",
  "sqes_accepted", "submit_one", "submit_2_4", "submit_5_16", "submit_17_64",
  "submit_over64", "submit_max", "enter_calls", "enter_partial",
  "credit_limited", "byte_limited", "ready_exhausted", "admit_rounds",
  "admitted_plans", "plan_limited", "barrier_blocked", "write_conflict",
  "seq_peer_inflight", "seq_peer_queued", "seq_peer_absent",
  "seq_peer_ready_unjoined", "seq_ready_ns", "depth_samples",
  "depth_stale_samples", "depth_transition_samples", "depth_probes",
  "depth_accepts", "depth_unexposed", "depth_pending_samples", "depth_probe_active",
  "depth_failure_streak", "depth_backoff_windows", "depth_backoff_skips",
  "admission_wait_count", "admission_wait_ns", "admission_wait_max_ns", "enqueue_lock_ns",
  "completion_indexed_tasks", "completion_buffer_checks", "completion_check_ns",
  "metadata_lookup_ns", "metadata_commit_ns", "wake_callback_ns",
  "cross_worker_plan_batches", "cross_worker_plan_requests",
  "cross_worker_candidate_requests", "seq_lookahead_plans", "seq_lookahead_ns",
  "read100k_buffer_boundaries", "read100k_feedback_buffers", "read100k_feedback_stale",
  "arrived_probe_ns", "arrived_probe_checks", "arrived_extend_requests", "arrived_no_candidate",
  "arrived_probe_limited", "merge_release_rejects", "merge_release_penalty_ns",
  "seq_local_checks", "seq_local_ns", "seq_nonhead_joins", "seq_tail_joins",
  "cqe_snapshot_passes", "cqe_extra_completions", "cqe_drain_ns", "completion_publications",
  "completion_max_buffers", "wake_flush_batches", "wake_lanes",
  "read100k_discrete_plan_bypasses", "read100k_release_ns",
  "write_depth_guard_windows", "write_io_ewma_ns", "write_io_residency_ns",
  "write_post_enter_ns", "write_post_enter_max_ns", "metadata_order_ns",
  "metadata_steps_ns", "metadata_flush_ns", "metadata_upsert_rows", "metadata_upsert_transactions",
  "intent_windows", "intent_requests", "intent_reordered", "intent_adjacent_pairs",
  "intent_plan_ns", "intent_rejects",
  "online_buffers", "online_candidate_buffers", "online_merged_buffers", "online_windows",
  "online_probes", "online_accepts", "online_rejects", "online_unexposed",
  "online_stale", "online_mixed", "online_service_ns_per_mb", "online_publication_p95_ns",
  "online_reference_ns_per_mb", "online_reference_p95_ns", "online_merging",
  "online_pending_samples", "online_cooldown", "online_epoch",
  "online_window_target", "online_last_window_samples", "online_reference_samples",
  "online_window_grows", "online_evaluated_buffers",
  "cluster_budget_checks", "cluster_budget_accepts", "cluster_delay_rejects", "cluster_amp_rejects",
  "boundary_snapshots", "boundary_refs", "boundary_probes", "boundary_cross_plan_joins",
  "boundary_match_ns", "boundary_backpressure_plans",
  "seq_read_ready_admissions", "seq_read_shared_submits",
  "read100k_publish_idle_skips", "read100k_vector_preparations",
  "buffer_publish_samples", "buffer_publish_p95_ns",
  "cluster_planned_savings", "cluster_plan_only_batches", "buffer_enqueue_publish_p95_ns",
  "boundary_dry_candidates", "request_build_ns", "group_build_ns",
  "vector_prepare_ns", "candidate_scan_ns", "net_benefit_checks", "net_benefit_rejects",
  "estimated_saved_ns", "estimated_extra_ns", "read_saved_op_ns", "write_saved_op_ns",
  "request_capture_ns", "release_order_ns", "release_order_moves",
  "metadata_lookup_batches", "metadata_lookup_rows", "metadata_lookup_lock_ns",
  "metadata_lookup_cpu_ns", "merge_calibrated", "calibrated_read_fixed_ns",
  "calibrated_read_vector_ns", "calibrated_write_fixed_ns", "calibrated_write_vector_ns",
  "calibration_skipped_batches", "calibration_skipped_requests",
  "calibration_zero_rejects",
  "submit_prep_wall_ns", "submit_prep_cpu_ns",
  "submit_enter_wall_ns", "submit_enter_cpu_ns",
  "submit_enter_voluntary_switches", "submit_enter_involuntary_switches",
  "submit_enter_output_blocks", "submit_enter_max_wall_ns", "submit_enter_samples"
};
static_assert(sizeof(sqlite_pipeline_metric_names) / sizeof(sqlite_pipeline_metric_names[0]) ==
              SQLITE_PIPELINE_METRICS, "SQLite pipeline CSV metric schema mismatch");

enum SqliteReadMergeMetric {
  SQLITE_READ100K_DISCRETE_BATCHES, SQLITE_READ100K_MERGED_BATCHES,
  SQLITE_READ100K_DISCRETE_BYTES, SQLITE_READ100K_MERGED_BYTES,
  SQLITE_READ100K_DISCRETE_SERVICE_NS, SQLITE_READ100K_MERGED_SERVICE_NS,
  SQLITE_READ100K_BACKOFFS, SQLITE_READ100K_PROBES, SQLITE_READ100K_METRICS
};

inline uint64_t sqlite_io_time_ticks() {
#if defined(__riscv)
  uint64_t ticks;
  __asm__ volatile("rdtime %0" : "=r"(ticks));
  return ticks;
#else
  return 0;
#endif
}

inline void sqlite_publish_ring_completion(
    struct group_pmp_sqlite_vfs_ring_header* ring, uint64_t count) {
  __atomic_store_n(&ring->completed_time_ticks, sqlite_io_time_ticks(),
                    __ATOMIC_RELAXED);
  (void)__atomic_add_fetch(&ring->completion_count, count, __ATOMIC_RELEASE);
}

struct SqliteAsyncCompletion {
  uint64_t trace_id;
  std::atomic<bool> done;
  std::atomic<uint64_t> remaining;
  std::atomic<uint64_t> published_ns;
  std::atomic<uint64_t> armed_ns;
  std::mutex mutex;
  std::condition_variable ready_condition;
  std::function<void(bool)> wakeup;
  bool wakeup_invoked;
  uint64_t wakeup_lane;
  std::vector<std::weak_ptr<SqliteAsyncCompletion> > any_waiters;

  explicit SqliteAsyncCompletion(uint64_t count = 1);
  void completeOne();
  void completeMany(uint64_t count);
  bool markCompleteMany(uint64_t count);
  void invoke(bool defer_batch_flush);
  void arm(const std::function<void(bool)>& callback, uint64_t lane);
  void wait();
  bool isComplete() const;
  bool hasArmedWakeup();
  void watchAny(const std::shared_ptr<SqliteAsyncCompletion>& waiter);
  void collectReadyWaiters(std::vector<std::shared_ptr<SqliteAsyncCompletion> >& ready);
  uint64_t publishedAtNs() const;
  uint64_t wakeupEligibleAtNs() const;
};

struct SqliteIoPerfSnapshot {
  std::array<uint64_t, SQLITE_PIPELINE_METRICS> pipeline{};
  std::array<uint64_t, SQLITE_READ100K_METRICS> read100k{};
  uint64_t task_count;
  uint64_t batch_count;
  uint64_t queue_wait_ns;
  uint64_t writer_wait_ns;
  uint64_t read_service_ns;
  uint64_t write_service_ns;
  uint64_t control_service_ns;
  uint64_t commit_ns;
  uint64_t commit_count;
  uint64_t queue_depth_peak;
  uint64_t io_uring_submissions;
  uint64_t registered_file_operations;
  uint64_t registered_buffer_operations;
  uint64_t fixed_buffer_operations;
  uint64_t buffer_registration_attempts;
  uint64_t buffer_registration_failures;
  uint64_t direct_io_operations;
  uint64_t direct_alignment_fallback_operations;
  uint64_t posix_fallback_operations;
  uint64_t merged_io_count;
  uint64_t sparse_io_count;
  uint64_t useful_io_bytes;
  uint64_t physical_io_bytes;
  uint64_t logical_request_count;
  uint64_t physical_request_count;
  uint64_t deduplicated_request_count;
  uint64_t completion_wait_ocall_count;
  uint64_t cache_full_hit_count;
  uint64_t cache_partial_hit_count;
  uint64_t cache_miss_count;
  uint64_t cache_hit_bytes;
  uint64_t collect_ns;
  uint64_t sort_ns;
  uint64_t cluster_ns;
  uint64_t write_overlap_check_ns;
  uint64_t write_overlap_checks;
  uint64_t write_disjoint_batches;
  uint64_t write_overlap_batches;
  uint64_t adaptive_write_grow_count;
  uint64_t adaptive_write_shrink_count;
  uint64_t adaptive_write_hold_count;
  uint64_t sequential_ready_single_batches;
  uint64_t sequential_ready_multi_batches;
  uint64_t sequential_ready_adjacent_pairs;
  uint64_t sequential_ready_nonadjacent_pairs;
  uint64_t random_sparse_fast_batches;
  uint64_t random_sparse_fast_requests;
  uint64_t random_planned_batches;
  uint64_t random_precheck_fallbacks;
  uint64_t random_precheck_ns;
  uint64_t random_local_plan_batches;
  uint64_t random_local_candidate_requests;
  uint64_t cache_fill_bytes;
  uint64_t cache_fill_ns;
  uint64_t cache_fill_skipped_bytes;
  uint64_t cache_admission_disables;
  uint64_t cache_admission_reenables;
  uint64_t readseq_initial_requests;
  uint64_t readseq_refill_peer_io_requests;
  uint64_t readseq_refill_peer_ready_requests;
  uint64_t readseq_refill_peer_idle_requests;
  uint64_t submit_ns;
  uint64_t disk_io_ns;
  /* Streaming API accounting is submit syscalls + reactor I/O wait. It
   * excludes overlapping planning/copy/metadata work, not a device timer. */
  uint64_t completion_wait_ns;
  uint64_t storage_sync_ns;
  uint64_t sequential_extent_count;
  uint64_t sequential_8mb_extent_count;
  uint64_t cross_worker_extent_count;
  uint64_t utm_copy_ns;
  uint64_t completion_publish_ns;
  uint64_t wakeup_ns;
  uint64_t submit_to_host_dequeue_ns;
  uint64_t host_dequeue_to_io_submit_ns;
  uint64_t io_submit_to_complete_ns;
  uint64_t io_complete_to_publish_ns;
  uint64_t publish_to_host_resume_request_ns;
  uint64_t wakeup_eligible_to_host_resume_request_ns;
  // Host syscall interval only, NOT the time when the enclave executes again.
  uint64_t host_resume_ioctl_ns;
  uint64_t completion_wakeup_count;
  uint64_t completion_ready_before_wait_count;
  uint64_t ewma_bandwidth_bytes_per_sec;
  uint64_t ewma_request_latency_ns;
  uint64_t ewma_queue_wait_ns;
  uint64_t ewma_completion_latency_ns;
  uint64_t adaptive_collect_usec;
  uint64_t adaptive_batch_target;
  uint64_t adaptive_queue_depth;
  uint64_t adaptive_gap_bytes;
  /* Windowed critical-path metrics. Sum counters above are useful for cost
   * accounting; these values describe elapsed bottleneck latency. */
  uint64_t critical_path_ns;
  uint64_t max_queue_wait_ns;
  uint64_t max_batch_service_ns;
  uint64_t max_completion_latency_ns;
  uint64_t window_first_enqueue_ns;
  uint64_t window_last_completion_ns;

  SqliteIoPerfSnapshot();
};

class SqliteExtentIoService {
 public:
  SqliteExtentIoService();
  ~SqliteExtentIoService();

  bool submit(const struct group_pmp_sqlite_vfs_request& request,
              uint8_t* utm, size_t utm_size,
              const std::shared_ptr<SqliteAsyncCompletion>& completion);
  bool submitBatch(const struct group_pmp_sqlite_vfs_request* requests,
                   uint64_t count, uint8_t* utm, size_t utm_size,
                   const std::shared_ptr<SqliteAsyncCompletion>& completion);
  bool submitReadPair(const struct group_pmp_sqlite_vfs_request* requests,
                      uint8_t* utm, size_t utm_size,
                      const std::shared_ptr<SqliteAsyncCompletion>* completions);
  bool planIntents(const group_pmp_sqlite_intent_plan& plan,
                   uint8_t* utm, size_t utm_size);
  SqliteIoPerfSnapshot snapshot() const;
  // Call after producers stop; wait for completion bookkeeping without reset.
  SqliteIoPerfSnapshot drainAndSnapshot();
  bool resetPerf();
  void cleanup_case(uint64_t worker_count, uint64_t workload);
  bool prepareCase(uint64_t file_id, uint8_t* const* utms,
                   const size_t* utm_sizes, size_t count);
  void clearRegisteredUtmBuffers();
  void recordWakeupTimeline(uint64_t publish_ns, uint64_t eligible_ns,
                            uint64_t wake_ns, uint64_t resume_ns);

 private:
  friend int sqlite_io_mixed_batch_probe(unsigned iterations, const char* profile);
  class Impl;
  std::unique_ptr<Impl> impl_;
};

SqliteExtentIoService& sqlite_async_io_service();
uint64_t sqlite_extent_io_policy_version();
int sqlite_io_path_probe(unsigned iterations);
int sqlite_io_mixed_batch_probe(unsigned iterations, const char* profile = nullptr);

#endif
