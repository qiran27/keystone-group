#include "sqlite-extent-io.hpp"
#include "sqlite-io-range-trace.hpp"
#include "io-uring-transport.hpp"
#include "online-cluster-feedback.hpp"
#include "../security/security-host-hooks.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <initializer_list>
#include <map>
#include <new>
#include <set>
#include <string>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <linux/io_uring.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#include "../sqlite-bench-master/sqlite3.h"
#include "../eapp/group-pmp-sqlite-shared.h"

#ifndef ESTALE
#define ESTALE EINVAL
#endif

#ifndef __linux__
struct iovec {
  void* iov_base;
  size_t iov_len;
};
#endif

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

namespace {

/* Keep this provenance marker literal in the implementation so source-tree
 * checks and final ELF string checks validate the same central I/O service. */
static const volatile char sqlite_central_io_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_CENTRAL_IO_MARKER;
static const volatile char sqlite_online_cluster_marker[]
    __attribute__((used)) = "keystone-sqlite-net-benefit-cluster-v1";
static const volatile char sqlite_vfs_abi_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_VFS_ABI_MARKER;
static const volatile char sqlite_workload_io_policy_marker[]
    __attribute__((used)) = "keystone-sqlite-workload-aware-io-policy-v3";
static const volatile char sqlite_adaptive_registered_io_marker[]
    __attribute__((used)) = "keystone-sqlite-adaptive-registered-io-v3";
static const volatile char sqlite_effective_batch_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_EFFECTIVE_BATCH_MARKER;
static const volatile char sqlite_completion_fastpath_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_COMPLETION_FASTPATH_MARKER;
static const volatile char sqlite_utm_buddy_layout_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_UTM_BUDDY_LAYOUT_MARKER;
static const volatile char sqlite_rolling_collect_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_ROLLING_COLLECT_MARKER;
static const volatile char sqlite_cost_cluster_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_COST_CLUSTER_MARKER;
static const volatile char sqlite_cipher_cache_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_CIPHER_CACHE_MARKER;

constexpr size_t kQueueDepth = 32768;
constexpr size_t kHostBatchExtents = 1024;
constexpr size_t kMinimumAdaptiveBatch = 128;
constexpr size_t kDefaultAdaptiveBatch = 512;
constexpr size_t kAsyncNoExtentBatch = 128;
constexpr uint64_t kDefaultMergeLimit = UINT64_C(8000000);
constexpr uint64_t kMinimumMergeLimit = UINT64_C(2000000);
constexpr uint64_t kMaximumMergeLimit = UINT64_C(8000000);
constexpr uint64_t kDefaultCollectUsec = UINT64_C(50);
constexpr uint64_t kDefaultReadAmplificationPermille = UINT64_C(1100);
constexpr uint64_t kMinimumReadAmplificationPermille = UINT64_C(1100);
constexpr uint64_t kMaximumReadAmplificationPermille = UINT64_C(1200);
constexpr uint64_t kDefaultDeviceBandwidth = UINT64_C(200000000);
constexpr uint64_t kDefaultCopyBandwidth = UINT64_C(1000000000);
constexpr uint64_t kDefaultRequestLatencyNs = UINT64_C(80000);
constexpr uint64_t kDefaultGapLimit = UINT64_C(262144);
constexpr uint64_t kDefaultMergeDelayBudgetNs = UINT64_C(50000000);
constexpr uint64_t kRandomReadBucketBytes = UINT64_C(4000000);
constexpr uint64_t kEwmaWeightShift = UINT64_C(3);
constexpr size_t kWriteBatchMinimum = 128;
constexpr size_t kWriteBatchInitial = 256;
constexpr size_t kWriteBatchMaximum = 512;
constexpr uint64_t kWriteTailBudgetNs = UINT64_C(80000000);

uint64_t status_offset_for_request(
    const struct group_pmp_sqlite_vfs_request& request) {
  return (request.reserved[0] & GROUP_PMP_SQLITE_STORE_RING) ?
      GROUP_PMP_SQLITE_VFS_RING_COMPLETION_OFFSET_FOR_SLOT(
          request.ring_slot) +
          request.descriptor_id *
              sizeof(struct group_pmp_sqlite_vfs_status) :
      GROUP_PMP_SQLITE_VFS_STATUS_OFFSET +
          request.buffer_id * sizeof(struct group_pmp_sqlite_vfs_status);
}

enum class IoPlanningPolicy {
  kSequentialContiguous,
  kRandomReadClustered,
  kReadRand100kAdjacent,
  kRandomWriteBatch
};

constexpr bool coalesces_without_hole(bool read, uint64_t next_start,
                                      uint64_t current_end) {
  return read ? next_start <= current_end : next_start == current_end;
}

constexpr bool strictly_overlaps(uint64_t next_start, uint64_t current_end) {
  return next_start < current_end;
}

constexpr size_t adaptive_batch_next(size_t current, size_t completed,
                                     size_t queued, size_t minimum,
                                     size_t maximum) {
  return (queued >= current || completed == current) && current < maximum ?
      (current * 2 < maximum ? current * 2 : maximum) :
      (!queued && completed * 2 < current && current > minimum ?
       (current / 2 > minimum ? current / 2 : minimum) : current);
}

constexpr uint64_t constexpr_min(uint64_t left, uint64_t right) {
  return left < right ? left : right;
}

constexpr uint64_t constexpr_max(uint64_t left, uint64_t right) {
  return left > right ? left : right;
}

constexpr uint64_t queue_admission_limit(uint64_t request_count,
                                         uint64_t worker_count,
                                         uint64_t adaptive_depth) {
  return constexpr_min(
      kQueueDepth, constexpr_max(
          request_count > kQueueDepth / 2 ||
                  (request_count &&
                   worker_count > kQueueDepth / (request_count * 2)) ?
              kQueueDepth : worker_count * request_count * 2,
          adaptive_depth));
}

static_assert(coalesces_without_hole(true, 4096, 4096),
              "adjacent reads must coalesce");
static_assert(coalesces_without_hole(true, 2048, 4096),
              "overlapping reads must coalesce");
static_assert(!strictly_overlaps(4096, 4096),
              "adjacent reads must remain direct scatter/gather");
static_assert(strictly_overlaps(2048, 4096),
              "overlapping reads require scatter from a temporary extent");
static_assert(!coalesces_without_hole(true, 8192, 4096),
              "random-read holes must remain discrete");
static_assert(!coalesces_without_hole(false, 2048, 4096),
              "overlapping writes must preserve request order");
static_assert(adaptive_batch_next(16, 16, 16, 4, 64) == 32,
              "queue pressure must grow the host batch");
static_assert(adaptive_batch_next(32, 4, 0, 4, 64) == 16,
              "an idle queue must shrink an oversized host batch");
static_assert(adaptive_batch_next(4, 1, 0, 4, 64) == 4,
              "adaptive host batching must preserve its lower bound");
static_assert(queue_admission_limit(512, 15, 1024) == 15360,
              "15 workers must enqueue both descriptor batches");
static_assert(queue_admission_limit(512, 64, 1024) == kQueueDepth,
              "admission must remain bounded for 64 workers");

uint64_t now_ns() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
}

void atomic_update_max(std::atomic<uint64_t>& target, uint64_t value) {
  uint64_t observed = target.load(std::memory_order_relaxed);
  while (observed < value &&
         !target.compare_exchange_weak(observed, value,
                                       std::memory_order_relaxed)) {}
}

void atomic_set_first(std::atomic<uint64_t>& target, uint64_t value) {
  uint64_t expected = 0;
  (void)target.compare_exchange_strong(expected, value,
                                       std::memory_order_relaxed);
}

uint64_t ewma_update(uint64_t previous, uint64_t sample) {
  if (!sample)
    return previous;
  if (!previous)
    return sample;
  return previous - (previous >> kEwmaWeightShift) +
      (sample >> kEwmaWeightShift);
}

struct CompletionDrain {
  size_t consumed = 0, passes = 0, extra = 0;
};

template <typename Reap, typename Consume>
CompletionDrain drain_arrived_completions(bool adaptive, size_t budget,
                                          Reap reap, Consume consume) {
  CompletionDrain result;
  do {
    const auto ready = reap();
    if (ready.empty()) break;
    if (result.passes++) result.extra += ready.size();
    result.consumed += ready.size();
    consume(ready);
  } while (adaptive && result.consumed < budget);
  return result;
}

bool random_write_workload(uint64_t workload) {
  return workload == GROUP_PMP_SQLITE_FILLRANDOM ||
      workload == GROUP_PMP_SQLITE_FILLRANDOMBATCH ||
      workload == GROUP_PMP_SQLITE_OVERWRITE;
}

struct WriteBatchFeedback {
  size_t target = kWriteBatchInitial;
  size_t stable_target = kWriteBatchInitial;
  unsigned samples = 0, cooldown = 0;
  uint64_t bytes = 0, service_ns = 0, tail_ns = 0;
  uint64_t ewma_rate = 0, ewma_tail = 0;
  uint64_t reference_rate = 0, reference_tail = 0;
  bool probing = false, saturated = false;

  void reset(size_t minimum, size_t maximum) {
    *this = WriteBatchFeedback();
    target = stable_target = std::max(minimum, std::min(kWriteBatchInitial, maximum));
  }

  // Evaluate four serviced batches, not queue pressure alone. A growth trial
  // must buy >=5% throughput without a >25% tail increase; failed trials back
  // off for eight windows. No sleep or delay is added to the I/O path.
  int observe(size_t completed, size_t queued, uint64_t useful_bytes,
              uint64_t duration, uint64_t completion_tail,
              size_t minimum, size_t maximum) {
    if (!completed || !duration || !useful_bytes)
      return 0;
    bytes += useful_bytes;
    service_ns += duration;
    tail_ns = std::max(tail_ns, completion_tail);
    saturated = saturated || (completed >= target && queued >= target);
    if (++samples < 4)
      return 0;
    const uint64_t rate = bytes * UINT64_C(1000000000) / service_ns;
    const uint64_t tail = tail_ns;
    const uint64_t previous_rate = ewma_rate;
    const uint64_t previous_tail = ewma_tail;
    ewma_rate = ewma_update(ewma_rate, rate);
    ewma_tail = ewma_update(ewma_tail, tail);
    const size_t before = target;
    if (probing) {
      const bool gain = rate >= reference_rate + reference_rate / 20;
      const bool tail_ok = tail <= kWriteTailBudgetNs &&
          tail <= reference_tail + reference_tail / 4;
      if (!gain || !tail_ok) {
        target = stable_target;
        cooldown = 8;
      } else {
        stable_target = target;
        cooldown = 2;
      }
      probing = false;
    } else if (target > minimum &&
               (tail > kWriteTailBudgetNs ||
                (previous_rate && previous_tail &&
                 rate < previous_rate - previous_rate / 10 &&
                 tail > previous_tail + previous_tail / 4))) {
      target = stable_target = std::max(minimum, target / 2);
      cooldown = 8;
    } else if (cooldown) {
      --cooldown;
    } else if (saturated && target < maximum &&
               tail <= kWriteTailBudgetNs / 2) {
      reference_rate = ewma_rate;
      reference_tail = std::max(tail, ewma_tail);
      stable_target = target;
      target = std::min(maximum, target + std::max<size_t>(32, target / 4));
      probing = true;
    }
    samples = 0;
    bytes = service_ns = tail_ns = 0;
    saturated = false;
    return target > before ? 1 : (target < before ? -1 : 0);
  }
};

// Compare actual service cost per useful byte, never request-count reduction.
// Four completed buffers per pipeline comparison (plans in the legacy path), a
// fixed eight-window cooldown. Observation never delays request execution.
struct ReadMergeFeedback {
  unsigned samples = 0, cooldown = 0;
  unsigned failures = 0, accepted_windows = 0;
  bool merging = false;
  uint64_t bytes = 0, service_ns = 0, tail_ns = 0;
  uint64_t reference_cost = 0, reference_tail = 0;
  uint64_t work_ns = 0, reference_work = 0, epoch = 0;
  uint64_t release_ns = 0, reference_release = 0;

  int observe(uint64_t useful_bytes, uint64_t elapsed, uint64_t host_work = 0,
              uint64_t completion_to_release = 0) {
    if (!useful_bytes || !elapsed)
      return 0;
    bytes += useful_bytes;
    service_ns += elapsed;
    work_ns += host_work;
    release_ns += completion_to_release;
    // Service tails are normalized to one MB so differently sized batches
    // can share observations without penalizing a larger useful payload.
    tail_ns = std::max(tail_ns, elapsed * UINT64_C(1000000) / useful_bytes);
    if (++samples < 4)
      return 0;
    const uint64_t cost = service_ns * UINT64_C(1000000) / bytes;
    const uint64_t work = work_ns * UINT64_C(1000000) / bytes;
    const uint64_t release = release_ns * UINT64_C(1000000) / bytes;
    const bool was_merging = merging;
    int action = 0;
    if (merging) {
      if (cost >= reference_cost - reference_cost / 20 ||
          tail_ns > reference_tail + reference_tail / 10 ||
          (reference_work && work > reference_work + reference_work / 20 + 20000) ||
          release > reference_release + reference_release / 10 + 20000) {
        merging = false;
        failures = std::min(4U, failures + 1);
        cooldown = 8;
        accepted_windows = 0;
        action = -1;
      } else {
        failures = 0;
        if (++accepted_windows >= 8) {
          // Refresh the reference through normal discrete work, not replay.
          merging = false;
          cooldown = 0;
          accepted_windows = 0;
        }
      }
    } else {
      reference_cost = ewma_update(reference_cost, cost);
      reference_work = ewma_update(reference_work, work);
      reference_release = ewma_update(reference_release, release);
      reference_tail = tail_ns;
      if (cooldown) {
        --cooldown;
      } else {
        merging = true;
        accepted_windows = 0;
        action = 1;
      }
    }
    samples = 0;
    bytes = service_ns = tail_ns = work_ns = release_ns = 0;
    if (was_merging != merging) ++epoch;
    return action;
  }
};

uint64_t read_merge_class(size_t requests, uint64_t bytes,
                           size_t candidates, bool overlap) {
  (void)requests;
  (void)bytes;
  (void)candidates;
  // Normalize cost/tail per useful byte instead of fragmenting observations
  // by batch size and locality. Fan-out copies still need a separate model.
  return overlap ? 1 : 0;
}

uint64_t collection_window(bool adaptive, IoPlanningPolicy policy,
                             uint64_t configured) {
  // Large reads already carry useful work. Submit the currently arrived batch
  // immediately, including while feedback has temporarily disabled merging.
  return adaptive && (policy == IoPlanningPolicy::kSequentialContiguous ||
      policy == IoPlanningPolicy::kReadRand100kAdjacent) ? 0 : configured;
}

uint64_t producer_admission_limit(uint64_t workers) {
  // ACK must not wait for physical SQE credits while holding the global edge
  // dispatcher. Reserve only descriptors for the existing two buffers/worker;
  // even a short tail keeps this capacity. No payload or SQE limit is enlarged.
  return queue_admission_limit(GROUP_PMP_SQLITE_VFS_BATCH_MAX,
      std::max<uint64_t>(1, workers), 0);
}

uint64_t saturating_ns_for_bytes(uint64_t bytes, uint64_t bytes_per_second) {
  if (!bytes || !bytes_per_second)
    return 0;
  if (bytes > UINT64_MAX / UINT64_C(1000000000))
    return UINT64_MAX;
  return bytes * UINT64_C(1000000000) / bytes_per_second;
}

uint64_t env_u64(const char* name, uint64_t fallback,
                 uint64_t minimum, uint64_t maximum) {
  const char* text = std::getenv(name);
  char* end = nullptr;
  unsigned long long value;
  if (!text || !text[0])
    return fallback;
  errno = 0;
  value = std::strtoull(text, &end, 0);
  if (errno || !end || *end || value < minimum || value > maximum)
    return fallback;
  return static_cast<uint64_t>(value);
}

bool adaptive_extent_mode() {
  const char* mode = std::getenv("GROUP_PMP_SQLITE_IO_MODE");
  return !mode || (std::strcmp(mode, "extent") == 0) ||
      (std::strcmp(mode, "adaptive-extent") == 0);
}

bool pipeline_mode() {
  const char* mode = std::getenv("GROUP_PMP_SQLITE_IO_MODE");
  return adaptive_extent_mode() ||
      (mode && std::strcmp(mode, "async-no-extent") == 0);
}

bool cluster_merge_enabled() {
  return adaptive_extent_mode() && !std::strcmp(sqlite_cluster_mode_name(), "merge");
}

// Bounded common-path telemetry. Percentiles report the bucket upper bound;
// resolution is at most 1/16 of the observed nonzero delay, not a mean.
class PublicationHistogram {
 public:
  PublicationHistogram() { reset(); }
  void reset() { for (auto& n : bins_) n.store(0, std::memory_order_relaxed); }
  void record(uint64_t ns) {
    size_t shift = 0;
    uint64_t value = ns;
    while (value > 31) { value >>= 1; ++shift; }
    bins_[shift * 32 + value].fetch_add(1, std::memory_order_relaxed);
  }
  std::pair<uint64_t, uint64_t> snapshot() const {
    std::array<uint64_t, 2048> counts{};
    uint64_t total = 0;
    for (size_t i = 0; i < counts.size(); ++i)
      total += counts[i] = bins_[i].load(std::memory_order_relaxed);
    if (!total) return {0, 0};
    const uint64_t rank = total - total / 20;
    uint64_t cumulative = 0;
    for (size_t i = 0; i < counts.size(); ++i) {
      cumulative += counts[i];
      if (cumulative >= rank) {
        const uint64_t value = i % 32, shift = i / 32;
        const uint64_t upper = value == 31 && shift == 59 ? UINT64_MAX :
            ((value + 1) << shift) - 1;
        return {total, upper};
      }
    }
    return {total, UINT64_MAX};
  }
 private:
  std::array<std::atomic<uint64_t>, 2048> bins_;
};

// Physical SQE credits, not producer descriptor count. Overlapping service
// intervals must not be added to compute device throughput.
struct PipelineDepthFeedback {
  size_t target = 64, stable = 64;
  uint64_t byte_limit = UINT64_C(16000000);
  uint64_t service = 0, tail = 0, rate = 0;
  uint64_t started = 0, bytes = 0, window_tail = 0;
  uint64_t reference_rate = 0, reference_tail = 0;
  uint64_t submit_ns = 0, submit_cost = 0, reference_submit_cost = 0;
  uint64_t windows = 0, rejected = 0;
  uint64_t epoch = 1, not_before = 0;
  uint64_t stale_samples = 0, transition_samples = 0, unexposed = 0;
  uint64_t completed_samples = 0, probes = 0, accepts = 0;
  size_t peak = 0;
  unsigned samples = 0, cooldown = 0;
  unsigned failure_streak = 0;
  uint64_t backoff_skips = 0;
  unsigned congested_windows = 0;
  bool probing = false, pressure = false;
  bool shrinking = false;
  unsigned write_samples = 0, write_eligible_windows = 0;
  uint64_t write_io_ewma = 0, write_io_tail = 0, write_post_enter_tail = 0;
  uint64_t reference_publication_tail = 0, write_guard_windows = 0;

  void reset_window() {
    started = bytes = window_tail = submit_ns = 0;
    samples = 0;
    peak = 0;
    pressure = false;
    write_samples = 0;
    write_io_tail = write_post_enter_tail = 0;
  }

  void submitted(size_t inflight, bool credit_pressure) {
    peak = std::max(peak, inflight);
    pressure = pressure || credit_pressure;
  }

  // Keep epoch isolation without draining live I/O. A buffer spanning depth
  // epochs or overlapping old-depth publication cannot train the new trial.
  void settle(uint64_t now) {
    ++stale_samples;
    not_before = now;
    write_eligible_windows = 0;
    reset_window();
  }

  void completed(uint64_t now, uint64_t submitted_at, uint64_t amount,
                 uint64_t latency, uint64_t sample_epoch, uint64_t cpu_cost,
                 bool random_write = false, uint64_t io_elapsed = 0,
                 uint64_t post_enter = 0) {
    if (sample_epoch != epoch) return; // settle() precedes this publication batch.
    if (submitted_at < not_before) { ++transition_samples; return; }
    if (!amount || now < submitted_at) return;
    service = ewma_update(service, now - submitted_at);
    tail = ewma_update(tail, latency);
    started = started ? std::min(started, submitted_at) : submitted_at;
    bytes += amount;
    submit_ns += cpu_cost;
    window_tail = std::max(window_tail, latency);
    ++samples;
    ++completed_samples;
    if (random_write) {
      ++write_samples;
      write_io_ewma = ewma_update(write_io_ewma, io_elapsed);
      write_io_tail = std::max(write_io_tail, io_elapsed);
      write_post_enter_tail = std::max(write_post_enter_tail, post_enter);
    }
  }

  int evaluate(uint64_t now, bool adaptive) {
    // One sample per successfully published buffer, including metadata and
    // notification cost. Hundreds of 4 KB CQEs are not independent trials.
    if (samples < 16 || now <= started || now - started < UINT64_C(20000000)) return 0;
    const uint64_t measured = bytes * UINT64_C(1000000000) / (now - started);
    const uint64_t cost = submit_ns * UINT64_C(1000000) / bytes;
    ++windows;
    if (!adaptive) {
      rate = ewma_update(rate, measured);
      submit_cost = ewma_update(submit_cost, cost);
      not_before = now;
      reset_window();
      return 0;
    }
    const size_t before = target;
    const bool write_window = write_samples == samples;
    const uint64_t control_tail = write_window ? write_io_tail : window_tail;
    // Bound enqueue-to-publication tail. A growth
    // probe needs throughput gain, not merely a long producer queue.
    const uint64_t budget = std::max<uint64_t>(UINT64_C(5000000),
        std::min<uint64_t>(UINT64_C(40000000),
            write_window ? write_io_ewma * 2 : service * 4));
    if (probing) {
      const bool exposed = shrinking ? pressure : peak > stable;
      const bool cost_ok = cost <= reference_submit_cost +
          reference_submit_cost / (write_window ? 20 : 10) + 5000;
      const bool gain = shrinking ?
          measured >= reference_rate - (write_window ? 0 : reference_rate / 50) &&
              control_tail <= reference_tail - reference_tail / 10 :
          measured >= reference_rate + reference_rate / 20 &&
              control_tail <= budget && control_tail <= reference_tail + reference_tail / 4;
      const bool publication_ok = !write_window || window_tail <=
          reference_publication_tail + reference_publication_tail / 20;
      if (!exposed) {
        target = stable;
        ++unexposed;
        cooldown = 4;
      } else if (!gain || !cost_ok || !publication_ok) {
        target = stable;
        ++rejected;
        failure_streak = std::min(4U, failure_streak + 1);
        cooldown = 4;
      } else {
        stable = target;
        ++accepts;
        failure_streak = 0;
        cooldown = 4;
      }
      probing = false;
      congested_windows = 0;
      write_eligible_windows = 0;
    } else if (cooldown) {
      // Continue observing and serving at the stable depth. Backoff suppresses
      // only new trials, not request collection, submission or completion.
      --cooldown;
      ++backoff_skips;
      congested_windows = 0;
      write_eligible_windows = 0;
    } else {
      // Buffered writes often finish inside enter(). Queue/SQLite time is not
      // evidence that fewer live SQEs will help. CQ observation is a Host-side
      // upper bound, not a device timestamp. Require a material residual and
      // two clean windows before risking a write-depth trial.
      const bool residual = write_post_enter_tail >= UINT64_C(1000000) &&
          write_post_enter_tail >= write_io_tail / 4;
      write_eligible_windows = write_window && pressure && residual ?
          std::min(2U, write_eligible_windows + 1) : 0;
      const bool eligible = !write_window || write_eligible_windows >= 2;
      if (write_window && !eligible) ++write_guard_windows;
      congested_windows = eligible && pressure && control_tail > budget ? congested_windows + 1 : 0;
      shrinking = congested_windows >= 2 && target > 16;
      if (shrinking || (eligible && pressure && target < 128 && control_tail <= budget)) {
        reference_rate = measured;
        reference_tail = control_tail;
        reference_publication_tail = window_tail;
        reference_submit_cost = cost;
        stable = target;
        target = shrinking ? std::max<size_t>(16, target * 3 / 4) :
            std::min<size_t>(128, target + 16);
        probing = true;
        ++probes;
      }
    }
    rate = ewma_update(rate, measured);
    submit_cost = ewma_update(submit_cost, cost);
    byte_limit = std::max<uint64_t>(UINT64_C(4000000),
        std::min<uint64_t>(UINT64_C(32000000), target * UINT64_C(250000)));
    if (target != before) ++epoch;
    not_before = now;
    reset_window();
    return target > before ? 1 : target < before ? -1 : 0;
  }
};

enum class CacheMode { kHot, kCold, kDirect };

CacheMode configured_cache_mode() {
  const char* mode = std::getenv("GROUP_PMP_SQLITE_CACHE_MODE");
  if (mode && std::strcmp(mode, "cold") == 0)
    return CacheMode::kCold;
  if (mode && std::strcmp(mode, "direct") == 0)
    return CacheMode::kDirect;
  return CacheMode::kHot;
}

struct PipelineBatch;

struct Task {
  size_t arrival_order = 0;
  // Host-owned registration generation; worker run_id is NOT a file generation.
  uint64_t case_epoch = 0;
  PipelineBatch* pipeline_owner = nullptr;
  size_t* pipeline_pending = nullptr;
  struct group_pmp_sqlite_vfs_request request;
  uint8_t* utm;
  size_t utm_size;
  std::shared_ptr<SqliteAsyncCompletion> completion;
  uint64_t enqueue_ns;
  uint64_t dequeue_ns;
  uint64_t io_submit_ns;
  uint64_t io_complete_ns;
  uint64_t publish_ns;
  uint64_t pipeline_depth_epoch = 0;
  uint64_t io_enter_return_ns = 0;
  uint64_t pipeline_submit_cost = 0;
  uint64_t merge_feedback_work_ns = 0;
  uint64_t storage_offset;
  uint64_t storage_length;
  uint64_t stored_sequence;
  uint64_t stored_file_id;
  uint8_t stored_tag[16];
  uint64_t io_offset;
  uint64_t io_length;
  uint64_t data_offset;
  bool cache_satisfied;
  bool cache_partial;
  bool superseded;
  bool pipeline_done = false;
  bool pipeline_published = false;
  bool merge_feedback_candidate = false;
  bool online_candidate = false, online_merged = false;
  int result;

  Task()
      : utm(nullptr), utm_size(0), enqueue_ns(0), dequeue_ns(0),
        io_submit_ns(0), io_complete_ns(0), publish_ns(0), storage_offset(0),
        storage_length(0), stored_sequence(0), stored_file_id(0),
        io_offset(0), io_length(0), data_offset(0), cache_satisfied(false),
        cache_partial(false), superseded(false), result(0) {
    std::memset(&request, 0, sizeof(request));
    std::memset(stored_tag, 0, sizeof(stored_tag));
  }

  uint8_t* data() const { return utm + request.buffer_offset; }
  uint8_t* io_data() const { return data() + data_offset; }
};

bool same_planning_scope(const Task& a, const Task& b) {
  const uint64_t phase = GROUP_PMP_SQLITE_STORE_PREFILL | GROUP_PMP_SQLITE_STORE_MEASURED;
  return a.case_epoch == b.case_epoch &&
      a.request.file_id == b.request.file_id &&
      a.request.operation == b.request.operation &&
      a.request.workload == b.request.workload &&
      a.request.worker_count == b.request.worker_count &&
      (a.request.worker_index != b.request.worker_index ||
       (a.request.run_id == b.request.run_id && a.utm == b.utm)) &&
      (a.request.reserved[0] & phase) == (b.request.reserved[0] & phase);
}

bool same_write_owner(const Task& a, const Task& b) {
  return same_planning_scope(a, b) &&
      a.request.run_id == b.request.run_id &&
      a.request.worker_index == b.request.worker_index && a.utm == b.utm;
}

bool spans_workers(const std::vector<Task*>& tasks) {
  return !tasks.empty() && std::any_of(tasks.begin() + 1, tasks.end(),
      [&](const Task* task) {
        return task->request.worker_index != tasks.front()->request.worker_index;
      });
}

struct CipherCacheEntry {
  bool valid;
  uintptr_t utm_identity;
  uint64_t buffer_id;
  uint64_t file_id;
  uint64_t offset;
  uint64_t length;
  uint64_t generation;
  uint64_t sequence;
  uint64_t key_epoch;
  std::vector<uint8_t> ciphertext;

  CipherCacheEntry()
      : valid(false), utm_identity(0), buffer_id(0), file_id(0), offset(0),
        length(0), generation(0), sequence(0), key_epoch(0) {}
};

IoPlanningPolicy planning_policy(const Task& task) {
  switch (task.request.workload) {
    case GROUP_PMP_SQLITE_FILLSEQ:
    case GROUP_PMP_SQLITE_FILLSEQBATCH:
    case GROUP_PMP_SQLITE_READSEQ:
      return IoPlanningPolicy::kSequentialContiguous;
    case GROUP_PMP_SQLITE_READRANDOM:
      return IoPlanningPolicy::kRandomReadClustered;
    case GROUP_PMP_SQLITE_READRAND100K:
      return IoPlanningPolicy::kReadRand100kAdjacent;
    case GROUP_PMP_SQLITE_FILLRANDOM:
    case GROUP_PMP_SQLITE_FILLRANDOMBATCH:
    case GROUP_PMP_SQLITE_OVERWRITE:
    default:
      return IoPlanningPolicy::kRandomWriteBatch;
  }
}

size_t workload_batch_target(uint64_t workload, size_t adaptive_target,
                             size_t maximum) {
  size_t minimum = 1;
  size_t limit = maximum;

  switch (workload) {
    case GROUP_PMP_SQLITE_FILLSEQ:
    case GROUP_PMP_SQLITE_FILLSEQBATCH:
    case GROUP_PMP_SQLITE_READSEQ:
      minimum = 4;
      /* 2 MB logical descriptors: 4..16 descriptors keep each metadata
       * group commit in the requested 8..32 MB range. Physical extents are
       * still split at merge_limit_ (at most 8 MB). */
      limit = std::min<size_t>(maximum, 16);
      break;
    case GROUP_PMP_SQLITE_READRANDOM:
      minimum = std::min<size_t>(maximum, 512);
      limit = std::min<size_t>(maximum, 1024);
      break;
    case GROUP_PMP_SQLITE_READRAND100K:
      /* A 100 KB request has enough payload to amortize a larger host batch,
       * while 128..256 descriptors stay within a 12.8..25.6 MB service
       * window. This substantially reduces completion publications at high
       * worker counts without waiting for every worker in the run. */
      minimum = std::min<size_t>(maximum, 128);
      limit = std::min<size_t>(maximum, 256);
      break;
    case GROUP_PMP_SQLITE_FILLRANDOM:
    case GROUP_PMP_SQLITE_FILLRANDOMBATCH:
    case GROUP_PMP_SQLITE_OVERWRITE:
    default:
      minimum = std::min<size_t>(maximum, kWriteBatchMinimum);
      limit = std::min<size_t>(maximum, kWriteBatchMaximum);
      break;
  }
  return std::max(minimum, std::min(adaptive_target, limit));
}

using GroupIo::InlineOneList;
#ifdef __linux__
using GroupIo::RawIoUring;
#endif

struct IoGroup {
  uint64_t file_id;
  int fd;
  uint64_t offset;
  uint64_t end;
  uint64_t useful_bytes;
  uint64_t gap_bytes = 0;
  bool read;
  bool direct_io;
  bool overlapping;
  bool spans_gap;
  IoPlanningPolicy policy;
  InlineOneList<struct iovec> vectors;
  std::unique_ptr<uint8_t[]> read_buffer;
  std::unique_ptr<SecurityCipherRegion> security_read_region;
  InlineOneList<Task*> tasks;

  // Conservative earliest-owner span for estimating cross-buffer release delay.
  uint64_t release_floor_bytes = 0;
  bool independent_completions = false;
  bool fixed_layout = true;

  IoGroup()
      : file_id(0), fd(-1), offset(0), end(0), useful_bytes(0), read(false),
        direct_io(false), overlapping(false), spans_gap(false),
        policy(IoPlanningPolicy::kRandomWriteBatch) {}
};

#ifdef __linux__
struct PipelineBatch {
  struct BufferProgress {
    std::vector<Task*> tasks;
    size_t pending = 0;
    bool published = false;
    PipelineBatch* owner = nullptr;
  };
  using CompletionPtr = std::shared_ptr<SqliteAsyncCompletion>;
  std::map<CompletionPtr, BufferProgress, std::owner_less<CompletionPtr> > buffers;
  std::vector<Task*> unowned_ready;
  bool completion_indexed = false, atomic_error_checked = false;
  std::vector<Task> owned;
  std::vector<Task*> tasks;
  std::vector<IoGroup> groups;
  std::vector<RawIoUring::Operation> operations;
  std::vector<size_t> operation_groups;
  size_t next = 0, remaining = 0;
  uint64_t started = 0, useful = 0, work_ns = 0, feedback_epoch = 0;
  ReadMergeFeedback* feedback = nullptr;
  OnlineClusterFeedback* online_feedback = nullptr;
  uint64_t online_epoch = 0, online_started = 0;
  bool online_merge = false;
  bool merged = false;
  bool atomic_write_publish = false;
  bool boundary_backpressure = false;
  bool read100k_publication = false;
  uint64_t diagnostic_id = 0;
};

// Small, refill-local view of existing plan fronts. Never index sparse 4 KiB
// requests or scan/sort whole plans to search for a possible neighbour.
struct PlannedBoundaryWindow {
  struct Ref { std::shared_ptr<PipelineBatch> plan; size_t position; };
  std::array<Ref, 16> refs;
  size_t size = 0, probes = 0;
  static bool eligible(const IoGroup& group, const PipelineBatch& plan) {
    return group.policy == IoPlanningPolicy::kSequentialContiguous ||
        (group.policy == IoPlanningPolicy::kReadRand100kAdjacent && plan.boundary_backpressure);
  }
  void add(const std::shared_ptr<PipelineBatch>& plan) {
    const size_t end = std::min(plan->operations.size(), plan->next + 4);
    for (size_t i = plan->next; i < end && size < refs.size(); ++i) {
      const auto& g = plan->groups[plan->operation_groups[i]];
      if (!eligible(g, *plan)) break;
      if (!g.overlapping && !g.spans_gap && !g.read_buffer)
        refs[size++] = Ref{plan, i};
    }
  }
  void rotated(PipelineBatch* plan, size_t first, size_t selected) {
    for (size_t r = 0; r < size; ++r) {
      auto& ref = refs[r];
      if (ref.plan.get() != plan) continue;
      if (ref.position == selected) ref.position = first;
      else if (ref.position >= first && ref.position < selected) ++ref.position;
    }
  }
};
#endif

/* A homogeneous 4 KiB batch without duplicate or neighbouring pages cannot
 * start an extent: a one-page hole already amplifies two pages by 1.5x. Prove
 * this in bounded linear work before allocating/sorting the full plan. An
 * inconclusive lookup always falls through to the existing interval planner. */
class SparsePagePrecheck {
 public:
  enum Result { kSparse, kCandidate, kInconclusive };

  // Emit adjacent components directly from the hash index. No global sort,
  // and each isolated request keeps its arrival position relative to peers.
  bool order_pages(const std::vector<Task*>& tasks, uint64_t* checks,
                   std::vector<Task*>* ordered, size_t* candidate_count) {
    *checks = 0; *candidate_count = 0; ordered->clear();
    if (tasks.empty() || tasks.size() > kHostBatchExtents) return false;
    if (++generation_ == 0) {
      for (Entry& entry : entries_) entry.generation = 0;
      generation_ = 1;
    }
    const Task& first = *tasks.front();
    for (size_t i = 0; i < tasks.size(); ++i) {
      const Task& t = *tasks[i];
      if (t.result || t.superseded || t.stored_file_id != first.stored_file_id ||
          t.request.operation != first.request.operation || t.storage_length != 4096 ||
          t.io_length != 4096 || t.io_offset != t.storage_offset || t.data_offset ||
          (t.io_offset & 4095) || t.io_offset > UINT64_MAX - 4096) return false;
      // Duplicates need the general overlap/sequence planner.
      if (lookup(t.io_offset >> 12, checks, true, i) != 0) return false;
    }
    std::array<int, kHostBatchExtents> previous{}, next{};
    for (size_t i = 0; i < tasks.size(); ++i) {
      const uint64_t page = tasks[i]->io_offset >> 12;
      previous[i] = page ? lookup(page - 1, checks, false) : 0;
      next[i] = lookup(page + 1, checks, false);
      if (previous[i] < 0 || next[i] < 0) return false;
    }
    ordered->reserve(tasks.size());
    for (size_t i = 0; i < tasks.size(); ++i) {
      if (previous[i] || !next[i]) continue;
      size_t member = i;
      for (;;) {
        ordered->push_back(tasks[member]);
        if (!next[member]) break;
        member = entries_[next[member] - 1].index;
      }
    }
    *candidate_count = ordered->size();
    for (size_t i = 0; i < tasks.size(); ++i)
      if (!previous[i] && !next[i]) ordered->push_back(tasks[i]);
    return ordered->size() == tasks.size();
  }

  // Conservatively mark intersecting 128 KB cells, including the endpoint
  // cell for exact adjacency. False positives only reach the local planner;
    // an isolated request cannot overlap, touch, or have a <=4 KB gap.
  Result inspect_intervals(const std::vector<Task*>& tasks, uint64_t* checks,
                           std::vector<Task*>* candidates,
                           std::vector<Task*>* isolated) {
    *checks = 0;
    candidates->clear();
    isolated->clear();
    if (tasks.empty() || tasks.size() > kHostBatchExtents)
      return kInconclusive;
    if (++generation_ == 0) {
      for (Entry& entry : entries_) entry.generation = 0;
      generation_ = 1;
    }
    std::array<bool, kHostBatchExtents> local{};
    size_t cells = 0;
    for (size_t i = 0; i < tasks.size(); ++i) {
      const Task& t = *tasks[i];
      if (t.result || t.superseded || !t.io_length ||
          t.request.operation != GROUP_PMP_SQLITE_VFS_OP_READ ||
          t.stored_file_id != tasks.front()->stored_file_id ||
          t.io_length > UINT64_MAX - t.io_offset)
        return kInconclusive;
      const uint64_t first = t.io_offset >> 17;
       const uint64_t end = t.io_offset + t.io_length;
       const uint64_t last = (end + std::min<uint64_t>(UINT64_C(4096),
           UINT64_MAX - end)) >> 17;
      if (last - first > 32 || (cells += last - first + 1) > 3072)
        return kInconclusive;
      for (uint64_t cell = first; cell <= last; ++cell) {
        const int found = lookup(cell, checks, true, i);
        if (found < 0) return kInconclusive;
        if (found > 0 && entries_[found - 1].index != i)
          local[i] = local[entries_[found - 1].index] = true;
      }
    }
    for (size_t i = 0; i < tasks.size(); ++i)
      (local[i] ? *candidates : *isolated).push_back(tasks[i]);
    return candidates->empty() ? kSparse : kCandidate;
  }

  Result inspect(const std::vector<Task*>& tasks, uint64_t amplification,
                 uint64_t* checks, std::vector<Task*>* candidates = nullptr,
                 std::vector<Task*>* isolated = nullptr) {
    *checks = 0;
    if (candidates) candidates->clear();
    if (isolated) isolated->clear();
    if (tasks.empty() || tasks.size() > kHostBatchExtents ||
        amplification >= 1500)
      return kInconclusive;
    if (++generation_ == 0) {
      for (Entry& entry : entries_)
        entry.generation = 0;
      generation_ = 1;
    }
    const Task& first = *tasks.front();
    const uint64_t file = first.stored_file_id;
    const uint64_t operation = first.request.operation;
    std::array<bool, kHostBatchExtents> local{};
    bool found_candidate = false;
    for (size_t index = 0; index < tasks.size(); ++index) {
      const Task* task = tasks[index];
      ++*checks;
      if (task->result || task->superseded ||
          task->stored_file_id != file || task->request.operation != operation ||
          task->storage_length != 4096 || task->io_length != 4096 ||
          task->io_offset != task->storage_offset || task->data_offset ||
          (task->io_offset & UINT64_C(4095)) ||
          task->io_offset > UINT64_MAX - UINT64_C(4096))
        return kInconclusive;
      const uint64_t page = task->io_offset >> 12;
      for (uint64_t key : {page, page ? page - 1 : UINT64_MAX, page + 1}) {
        const int found = lookup(key, checks, false);
        if (found > 0) {
          local[index] = local[entries_[found - 1].index] = true;
          found_candidate = true;
        }
        if (found < 0)
          return kInconclusive;
      }
      if (lookup(page, checks, true, index) < 0)
        return kInconclusive;
    }
    // Every member of a duplicate/adjacent component is marked, regardless of
    // arrival order. Isolated pages cannot overlap writes in the local plan.
    for (size_t index = 0; index < tasks.size(); ++index) {
      if (local[index] && candidates) candidates->push_back(tasks[index]);
      if (!local[index] && isolated) isolated->push_back(tasks[index]);
    }
    return found_candidate ? kCandidate : kSparse;
  }

 private:
  struct Entry { uint64_t page = 0, generation = 0; size_t index = 0; };
  std::array<Entry, 4096> entries_{};
  uint64_t generation_ = 0;

  int lookup(uint64_t page, uint64_t* checks, bool insert, size_t index = 0) {
    const size_t start = static_cast<size_t>(
        (page * UINT64_C(11400714819323198485)) >> 52);
    for (size_t probe = 0; probe < 32; ++probe) {
      ++*checks;
      Entry& entry = entries_[(start + probe) & (entries_.size() - 1)];
      if (entry.generation != generation_) {
        if (insert) {
          entry.page = page;
          entry.generation = generation_;
          entry.index = index;
        }
        return 0;
      }
      if (entry.page == page)
        return static_cast<int>((start + probe) & (entries_.size() - 1)) + 1;
    }
    return -1;
  }
};

}  // namespace

SqliteAsyncCompletion::SqliteAsyncCompletion(uint64_t count)
    : trace_id(sqlite_gantt_next_completion_id()), done(false),
      remaining(count), published_ns(0), armed_ns(0), wakeup_invoked(false),
      wakeup_lane(UINT64_MAX) {}

void SqliteAsyncCompletion::completeOne() {
  completeMany(1);
}

void SqliteAsyncCompletion::completeMany(uint64_t count) {
  if (markCompleteMany(count)) {
    invoke(false);
    std::vector<std::shared_ptr<SqliteAsyncCompletion> > ready;
    collectReadyWaiters(ready);
    for (const auto& waiter : ready) waiter->invoke(false);
  }
}

void SqliteAsyncCompletion::watchAny(const std::shared_ptr<SqliteAsyncCompletion>& waiter) {
  bool completed;
  {
    std::lock_guard<std::mutex> lock(mutex);
    completed = done.load(std::memory_order_acquire);
    if (!completed) {
      any_waiters.erase(std::remove_if(any_waiters.begin(), any_waiters.end(),
          [](const std::weak_ptr<SqliteAsyncCompletion>& item) { return item.expired(); }),
          any_waiters.end());
      any_waiters.push_back(waiter);
    }
  }
  if (completed) waiter->completeOne();
}

void SqliteAsyncCompletion::collectReadyWaiters(
    std::vector<std::shared_ptr<SqliteAsyncCompletion> >& ready) {
  std::vector<std::weak_ptr<SqliteAsyncCompletion> > waiters;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (!done.load(std::memory_order_acquire)) return;
    waiters.swap(any_waiters);
  }
  for (const auto& weak : waiters)
    if (auto waiter = weak.lock())
      if (waiter->markCompleteMany(1)) ready.push_back(waiter);
}

bool SqliteAsyncCompletion::markCompleteMany(uint64_t count) {
  uint64_t old = remaining.load(std::memory_order_acquire);
  uint64_t next;
  if (!count)
    return false;
  do {
    if (!old)
      return false;
    next = count >= old ? 0 : old - count;
  } while (!remaining.compare_exchange_weak(
      old, next, std::memory_order_acq_rel, std::memory_order_acquire));
  if (next)
    return false;
  published_ns.store(now_ns(), std::memory_order_release);
  sqlite_gantt_trace().recordOcall(
      SQLITE_GANTT_COMPLETION_READY, 0, 0, 0, 0, trace_id);
  {
    std::lock_guard<std::mutex> lock(mutex);
    done.store(true, std::memory_order_release);
  }
  ready_condition.notify_all();
  return true;
}

void SqliteAsyncCompletion::invoke(bool defer_batch_flush) {
  std::function<void(bool)> callback;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (wakeup && done.load(std::memory_order_acquire) && !wakeup_invoked) {
      wakeup_invoked = true;
      callback = wakeup;
    }
  }
  if (callback)
    callback(defer_batch_flush);
}

void SqliteAsyncCompletion::arm(const std::function<void(bool)>& callback,
                                uint64_t lane) {
  const uint64_t armed = now_ns();
  bool ready = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    wakeup = callback;
    wakeup_lane = lane;
    armed_ns.store(armed, std::memory_order_release);
    ready = done.load(std::memory_order_acquire) && !wakeup_invoked;
  }
  if (ready)
    invoke(false);
}

void SqliteAsyncCompletion::wait() {
  std::unique_lock<std::mutex> lock(mutex);
  ready_condition.wait(lock, [this] {
    return done.load(std::memory_order_acquire);
  });
}

bool SqliteAsyncCompletion::isComplete() const {
  return done.load(std::memory_order_acquire);
}

bool SqliteAsyncCompletion::hasArmedWakeup() {
  std::lock_guard<std::mutex> lock(mutex);
  return static_cast<bool>(wakeup) && !wakeup_invoked;
}

uint64_t SqliteAsyncCompletion::publishedAtNs() const {
  return published_ns.load(std::memory_order_acquire);
}

uint64_t SqliteAsyncCompletion::wakeupEligibleAtNs() const {
  return std::max(published_ns.load(std::memory_order_acquire),
                  armed_ns.load(std::memory_order_acquire));
}

SqliteIoPerfSnapshot::SqliteIoPerfSnapshot()
    : task_count(0), batch_count(0), queue_wait_ns(0), writer_wait_ns(0),
      read_service_ns(0), write_service_ns(0), control_service_ns(0),
      commit_ns(0), commit_count(0), queue_depth_peak(0),
      io_uring_submissions(0), registered_file_operations(0),
      registered_buffer_operations(0), fixed_buffer_operations(0),
      buffer_registration_attempts(0), buffer_registration_failures(0),
      direct_io_operations(0),
      direct_alignment_fallback_operations(0), posix_fallback_operations(0),
      merged_io_count(0), sparse_io_count(0),
      useful_io_bytes(0), physical_io_bytes(0), logical_request_count(0),
      physical_request_count(0),
      deduplicated_request_count(0), completion_wait_ocall_count(0),
      cache_full_hit_count(0),
      cache_partial_hit_count(0), cache_miss_count(0), cache_hit_bytes(0),
      collect_ns(0), sort_ns(0), cluster_ns(0),
      write_overlap_check_ns(0),
      write_overlap_checks(0),
      write_disjoint_batches(0),
      write_overlap_batches(0),
      adaptive_write_grow_count(0),
      adaptive_write_shrink_count(0),
      adaptive_write_hold_count(0),
      sequential_ready_single_batches(0),
      sequential_ready_multi_batches(0),
      sequential_ready_adjacent_pairs(0),
      sequential_ready_nonadjacent_pairs(0),
      random_sparse_fast_batches(0),
      random_sparse_fast_requests(0),
      random_planned_batches(0),
      random_precheck_fallbacks(0),
      random_precheck_ns(0),
      random_local_plan_batches(0),
      random_local_candidate_requests(0),
      cache_fill_bytes(0),
      cache_fill_ns(0),
      cache_fill_skipped_bytes(0),
      cache_admission_disables(0),
      cache_admission_reenables(0),
      readseq_initial_requests(0),
      readseq_refill_peer_io_requests(0),
      readseq_refill_peer_ready_requests(0),
      readseq_refill_peer_idle_requests(0),
      submit_ns(0), disk_io_ns(0),
      completion_wait_ns(0),
      storage_sync_ns(0),
      sequential_extent_count(0),
      sequential_8mb_extent_count(0),
      cross_worker_extent_count(0),
      utm_copy_ns(0), completion_publish_ns(0), wakeup_ns(0),
      submit_to_host_dequeue_ns(0), host_dequeue_to_io_submit_ns(0),
      io_submit_to_complete_ns(0), io_complete_to_publish_ns(0),
      publish_to_host_resume_request_ns(0), wakeup_eligible_to_host_resume_request_ns(0),
      host_resume_ioctl_ns(0), completion_wakeup_count(0),
      completion_ready_before_wait_count(0),
      ewma_bandwidth_bytes_per_sec(0), ewma_request_latency_ns(0),
      ewma_queue_wait_ns(0), ewma_completion_latency_ns(0),
      adaptive_collect_usec(0), adaptive_batch_target(0),
      adaptive_queue_depth(0), adaptive_gap_bytes(0), critical_path_ns(0),
      max_queue_wait_ns(0), max_batch_service_ns(0),
      max_completion_latency_ns(0), window_first_enqueue_ns(0),
      window_last_completion_ns(0) {}

class SqliteExtentIoService::Impl {
  friend int sqlite_io_mixed_batch_probe(unsigned iterations, const char* profile);
 public:
#ifdef __linux__
  struct Flight {
    std::shared_ptr<PipelineBatch> batch;
    size_t operation;
    uint64_t submitted;
    uint64_t depth_epoch = 0, submit_cost = 0, useful_bytes = 0, enqueue_ns = 0;
    uint64_t file_id = 0, offset = 0, length = 0;
    bool read = false;
    std::vector<Flight> followers;
    std::shared_ptr<InlineOneList<iovec> > vectors;
    Flight(std::shared_ptr<PipelineBatch> p, size_t op, uint64_t at)
        : batch(std::move(p)), operation(op), submitted(at) {}
  };
#endif
  explicit Impl(bool start_worker = true)
      : stopping_(false), db_(nullptr), reset_statement_(nullptr),
        write_statement_(nullptr), adaptive_write_statement_(nullptr), read_statement_(nullptr),
        read_begin_statement_(nullptr), begin_statement_(nullptr), commit_statement_(nullptr),
        rollback_statement_(nullptr),
        merge_limit_(env_u64("GROUP_PMP_SQLITE_IO_MERGE_MAX_BYTES",
                             kDefaultMergeLimit, kMinimumMergeLimit,
                             kMaximumMergeLimit)),
        read_amplification_permille_(env_u64(
            "GROUP_PMP_SQLITE_IO_READ_AMP_PERMILLE",
            kDefaultReadAmplificationPermille,
            kMinimumReadAmplificationPermille,
            kMaximumReadAmplificationPermille)),
        copy_bandwidth_(env_u64("GROUP_PMP_SQLITE_IO_COPY_BPS",
                                kDefaultCopyBandwidth, UINT64_C(100000000),
                                UINT64_C(10000000000))),
        maximum_gap_(env_u64("GROUP_PMP_SQLITE_IO_GAP_MAX_BYTES",
                             kDefaultGapLimit, 0, kMaximumMergeLimit)),
        merge_delay_budget_ns_(env_u64("GROUP_PMP_SQLITE_IO_MERGE_DELAY_NS",
            kDefaultMergeDelayBudgetNs, UINT64_C(1000), UINT64_C(1000000000))),
        adaptive_batch_min_(env_u64(
            "GROUP_PMP_SQLITE_IO_BATCH_MIN", kMinimumAdaptiveBatch, 1,
            kHostBatchExtents)),
        adaptive_batch_max_(env_u64(
            "GROUP_PMP_SQLITE_IO_BATCH_MAX", kHostBatchExtents,
            adaptive_batch_min_, kHostBatchExtents)),
        adaptive_batch_target_(env_u64(
            "GROUP_PMP_SQLITE_IO_BATCH_INITIAL", kDefaultAdaptiveBatch,
            adaptive_batch_min_, adaptive_batch_max_)),
        adaptive_collect_usec_(env_u64("GROUP_PMP_SQLITE_IO_COLLECT_USEC",
                                       kDefaultCollectUsec, 0, 10000)),
        adaptive_queue_depth_(1024),
        adaptive_gap_bytes_(std::min<uint64_t>(maximum_gap_,
                                               kDefaultGapLimit)),
        ewma_bandwidth_bytes_per_sec_(kDefaultDeviceBandwidth),
        ewma_request_latency_ns_(kDefaultRequestLatencyNs),
        ewma_queue_wait_ns_(0), ewma_completion_latency_ns_(0),
        task_count_(0), batch_count_(0), queue_wait_ns_(0),
        writer_wait_ns_(0), read_service_ns_(0), write_service_ns_(0),
        control_service_ns_(0), commit_ns_(0), commit_count_(0),
        queue_depth_peak_(0), io_uring_submissions_(0),
        registered_file_operations_(0), registered_buffer_operations_(0),
        fixed_buffer_operations_(0), buffer_registration_attempts_(0),
        buffer_registration_failures_(0),
        direct_io_operations_(0), direct_alignment_fallback_operations_(0),
        posix_fallback_operations_(0), merged_io_count_(0),
        sparse_io_count_(0), useful_io_bytes_(0), physical_io_bytes_(0),
        logical_request_count_(0), physical_request_count_(0),
        deduplicated_request_count_(0),
        cache_full_hit_count_(0), cache_partial_hit_count_(0),
        cache_miss_count_(0), cache_hit_bytes_(0), collect_ns_(0),
        sort_ns_(0), cluster_ns_(0),
        write_overlap_check_ns_(0),
        write_overlap_checks_(0),
        write_disjoint_batches_(0),
        write_overlap_batches_(0),
        adaptive_write_grow_count_(0),
        adaptive_write_shrink_count_(0),
        adaptive_write_hold_count_(0),
        sequential_ready_single_batches_(0),
        sequential_ready_multi_batches_(0),
        sequential_ready_adjacent_pairs_(0),
        sequential_ready_nonadjacent_pairs_(0),
        random_sparse_fast_batches_(0),
        random_sparse_fast_requests_(0),
        random_planned_batches_(0),
        random_precheck_fallbacks_(0),
        random_precheck_ns_(0),
        random_local_plan_batches_(0),
        random_local_candidate_requests_(0),
        cache_fill_bytes_(0),
        cache_fill_ns_(0),
        cache_fill_skipped_bytes_(0),
        cache_admission_disables_(0),
        cache_admission_reenables_(0),
        readseq_initial_requests_(0),
        readseq_refill_peer_io_requests_(0),
        readseq_refill_peer_ready_requests_(0),
        readseq_refill_peer_idle_requests_(0),
        submit_ns_(0), disk_io_ns_(0),
        completion_wait_ns_(0),
        storage_sync_ns_(0),
        sequential_extent_count_(0),
        sequential_8mb_extent_count_(0),
        cross_worker_extent_count_(0),
        utm_copy_ns_(0), completion_publish_ns_(0), wakeup_ns_(0),
        submit_to_host_dequeue_ns_(0), host_dequeue_to_io_submit_ns_(0),
        io_submit_to_complete_ns_(0), io_complete_to_publish_ns_(0),
        publish_to_host_resume_request_ns_(0), wakeup_eligible_to_host_resume_request_ns_(0),
        host_resume_ioctl_ns_(0), completion_wakeup_count_(0),
        completion_ready_before_wait_count_(0),
        window_first_enqueue_ns_(0), window_last_completion_ns_(0),
        max_queue_wait_ns_(0), max_batch_service_ns_(0),
        max_completion_latency_ns_(0), processing_batch_(false),
        utm_buffers_registered_(false) {
    for (auto& value : read100k_)
      value.store(0, std::memory_order_relaxed);
    for (auto& value : pipeline_perf_) value.store(0);
#ifdef __linux__
    if (wake_fd_ < 0) throw std::runtime_error("SQLite reactor eventfd failed");
#endif
    reset_write_feedback();
    load_merge_calibration();
    if (start_worker) worker_ = std::thread(&Impl::worker_loop, this);
  }

  bool planIntents(const group_pmp_sqlite_intent_plan& p,
                   uint8_t* utm, size_t utm_size) {
    // Policy 36 accepts only real submitted data requests. Keep the old ABI
    // recognizable so stale workers fail explicitly, never silently reorder.
    (void)p; (void)utm; (void)utm_size;
    pipeline_perf_[SQLITE_PIPELINE_INTENT_REJECTS].fetch_add(1);
    return false;
  }

  void reset_write_feedback() {
    write_feedback_.reset(std::min(kWriteBatchMaximum, adaptive_batch_min_),
                          std::min(kWriteBatchMaximum, adaptive_batch_max_));
    write_queue_depth_.store(write_feedback_.target * 2, std::memory_order_relaxed);
  }

  ~Impl() {
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      stopping_ = true;
    }
    condition_.notify_all();
    notify_reactor();
    if (worker_.joinable()) worker_.join();
#ifdef __linux__
    close(wake_fd_);
#endif
    std::lock_guard<std::mutex> lock(database_mutex_);
    if (reset_statement_)
      sqlite3_finalize(reset_statement_);
    if (write_statement_)
      sqlite3_finalize(write_statement_);
    if (adaptive_write_statement_)
      sqlite3_finalize(adaptive_write_statement_);
    if (read_statement_)
      sqlite3_finalize(read_statement_);
    if (read_begin_statement_)
      sqlite3_finalize(read_begin_statement_);
    if (begin_statement_)
      sqlite3_finalize(begin_statement_);
    if (commit_statement_)
      sqlite3_finalize(commit_statement_);
    if (rollback_statement_)
      sqlite3_finalize(rollback_statement_);
    if (db_)
      sqlite3_close(db_);
#ifdef __linux__
    for (std::map<uint64_t, int>::const_iterator it = files_.begin();
         it != files_.end(); ++it)
      close(it->second);
    for (std::map<uint64_t, int>::const_iterator it = direct_files_.begin();
         it != direct_files_.end(); ++it)
      close(it->second);
#endif
  }

  bool submitBatch(const struct group_pmp_sqlite_vfs_request* requests,
                   uint64_t count, uint8_t* utm, size_t utm_size,
                   const std::shared_ptr<SqliteAsyncCompletion>& completion,
                   const std::shared_ptr<SqliteAsyncCompletion>* pair_completions = nullptr) {
    const uint64_t capture_started = now_ns();
    std::array<Task, GROUP_PMP_SQLITE_VFS_BATCH_MAX> tasks;
    const uint64_t queued_at = now_ns();
    if (!requests || !count || count > GROUP_PMP_SQLITE_VFS_BATCH_MAX)
      return false;
    if (pair_completions &&
        (!pipeline_mode() || count != 2 ||
         !pair_completions[0] || !pair_completions[1] ||
         pair_completions[0] == pair_completions[1] ||
         requests[0].ring_slot == requests[1].ring_slot ||
         requests[0].run_id != requests[1].run_id ||
         requests[0].worker_index != requests[1].worker_index ||
         requests[0].file_id != requests[1].file_id))
      return false;
    for (uint64_t index = 0; index < count; ++index) {
      const struct group_pmp_sqlite_vfs_request& request = requests[index];
      if (pair_completions &&
          (request.operation != GROUP_PMP_SQLITE_VFS_OP_READ ||
           request.workload != GROUP_PMP_SQLITE_READSEQ ||
           request.ring_slot >= GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT ||
           request.buffer_id != request.ring_slot || request.descriptor_id))
        return false;
      const uint64_t status_offset = status_offset_for_request(request);
      if (!utm || status_offset > utm_size ||
          sizeof(struct group_pmp_sqlite_vfs_status) >
              utm_size - status_offset ||
          request.buffer_offset > utm_size ||
          request.length > utm_size - request.buffer_offset)
        return false;
      tasks[index].request = request;
      tasks[index].utm = utm;
      tasks[index].utm_size = utm_size;
      tasks[index].completion = pair_completions ? pair_completions[index] : completion;
      tasks[index].enqueue_ns = queued_at;
    }
    pipeline_perf_[SQLITE_PIPELINE_REQUEST_CAPTURE_NS].fetch_add(now_ns() - capture_started);
    atomic_set_first(window_first_enqueue_ns_, queued_at);
    uint64_t depth = 0;
    const uint64_t worker_count = requests[0].worker_count;
    const bool bounded_write = pipeline_mode() &&
        random_write_workload(requests[0].workload) &&
        requests[0].operation == GROUP_PMP_SQLITE_VFS_OP_WRITE;
    {
      const uint64_t lock_started = now_ns();
      std::unique_lock<std::mutex> lock(queue_mutex_);
      pipeline_perf_[SQLITE_PIPELINE_ENQUEUE_LOCK_NS].fetch_add(now_ns() - lock_started);
      const auto can_accept = [this, count, worker_count, bounded_write] {
        const uint64_t queue_limit = bounded_write ?
            producer_admission_limit(worker_count) :
            queue_admission_limit(
            count, worker_count,
            adaptive_queue_depth_.load(std::memory_order_relaxed));
        return stopping_ ||
            (count <= queue_limit && queue_.size() <= queue_limit - count);
      };
      if (!can_accept()) {
        const uint64_t wait_started = now_ns();
        pipeline_perf_[SQLITE_PIPELINE_ADMISSION_WAIT_COUNT].fetch_add(1);
        condition_.wait(lock, can_accept);
        const uint64_t waited = now_ns() - wait_started;
        pipeline_perf_[SQLITE_PIPELINE_ADMISSION_WAIT_NS].fetch_add(waited);
        atomic_update_max(pipeline_perf_[SQLITE_PIPELINE_ADMISSION_WAIT_MAX_NS], waited);
      }
      if (stopping_)
        return false;
      const uint64_t copy_started = now_ns();
      for (uint64_t index = 0; index < count; ++index) {
        tasks[index].case_epoch = case_epoch_;
        queue_.push_back(tasks[index]);
      }
      pipeline_perf_[SQLITE_PIPELINE_REQUEST_CAPTURE_NS].fetch_add(now_ns() - copy_started);
      depth = queue_.size();
      uint64_t old = queue_depth_peak_.load(std::memory_order_relaxed);
      while (old < depth && !queue_depth_peak_.compare_exchange_weak(
                 old, depth, std::memory_order_relaxed)) {}
    }
    for (uint64_t index = 0; index < count; ++index)
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_QUEUE_ENQUEUE, requests[index],
          tasks[index].completion ? tasks[index].completion->trace_id : 0,
          0, depth, queued_at);
    batch_count_.fetch_add(1, std::memory_order_relaxed);
    condition_.notify_one();
    notify_reactor();
    return true;
  }

  SqliteIoPerfSnapshot snapshot() const {
    SqliteIoPerfSnapshot value;
    for (size_t i = 0; i < value.pipeline.size(); ++i)
      value.pipeline[i] = pipeline_perf_[i].load(std::memory_order_relaxed);
    for (size_t i = 0; i < value.read100k.size(); ++i)
      value.read100k[i] = read100k_[i].load(std::memory_order_relaxed);
    value.task_count = task_count_.load(std::memory_order_relaxed);
    value.batch_count = batch_count_.load(std::memory_order_relaxed);
    value.queue_wait_ns = queue_wait_ns_.load(std::memory_order_relaxed);
    value.writer_wait_ns = writer_wait_ns_.load(std::memory_order_relaxed);
    value.read_service_ns = read_service_ns_.load(std::memory_order_relaxed);
    value.write_service_ns = write_service_ns_.load(std::memory_order_relaxed);
    value.control_service_ns = control_service_ns_.load(std::memory_order_relaxed);
    value.commit_ns = commit_ns_.load(std::memory_order_relaxed);
    value.commit_count = commit_count_.load(std::memory_order_relaxed);
    value.queue_depth_peak = queue_depth_peak_.load(std::memory_order_relaxed);
    value.io_uring_submissions =
        io_uring_submissions_.load(std::memory_order_relaxed);
    value.registered_file_operations =
        registered_file_operations_.load(std::memory_order_relaxed);
    value.registered_buffer_operations =
        registered_buffer_operations_.load(std::memory_order_relaxed);
    value.fixed_buffer_operations =
        fixed_buffer_operations_.load(std::memory_order_relaxed);
    value.buffer_registration_attempts =
        buffer_registration_attempts_.load(std::memory_order_relaxed);
    value.buffer_registration_failures =
        buffer_registration_failures_.load(std::memory_order_relaxed);
    value.direct_io_operations =
        direct_io_operations_.load(std::memory_order_relaxed);
    value.direct_alignment_fallback_operations =
        direct_alignment_fallback_operations_.load(
            std::memory_order_relaxed);
    value.posix_fallback_operations =
        posix_fallback_operations_.load(std::memory_order_relaxed);
    value.merged_io_count = merged_io_count_.load(std::memory_order_relaxed);
    value.sparse_io_count = sparse_io_count_.load(std::memory_order_relaxed);
    value.useful_io_bytes = useful_io_bytes_.load(std::memory_order_relaxed);
    value.physical_io_bytes = physical_io_bytes_.load(std::memory_order_relaxed);
    value.logical_request_count =
        logical_request_count_.load(std::memory_order_relaxed);
    value.physical_request_count =
        physical_request_count_.load(std::memory_order_relaxed);
    value.deduplicated_request_count =
        deduplicated_request_count_.load(std::memory_order_relaxed);
    value.cache_full_hit_count =
        cache_full_hit_count_.load(std::memory_order_relaxed);
    value.cache_partial_hit_count =
        cache_partial_hit_count_.load(std::memory_order_relaxed);
    value.cache_miss_count = cache_miss_count_.load(std::memory_order_relaxed);
    value.cache_hit_bytes = cache_hit_bytes_.load(std::memory_order_relaxed);
    value.collect_ns = collect_ns_.load(std::memory_order_relaxed);
    value.sort_ns = sort_ns_.load(std::memory_order_relaxed);
    value.cluster_ns = cluster_ns_.load(std::memory_order_relaxed);
    value.write_overlap_check_ns = write_overlap_check_ns_.load(std::memory_order_relaxed);
    value.write_overlap_checks = write_overlap_checks_.load(std::memory_order_relaxed);
    value.write_disjoint_batches = write_disjoint_batches_.load(std::memory_order_relaxed);
    value.write_overlap_batches = write_overlap_batches_.load(std::memory_order_relaxed);
    value.adaptive_write_grow_count = adaptive_write_grow_count_.load(std::memory_order_relaxed);
    value.adaptive_write_shrink_count = adaptive_write_shrink_count_.load(std::memory_order_relaxed);
    value.adaptive_write_hold_count = adaptive_write_hold_count_.load(std::memory_order_relaxed);
    value.sequential_ready_single_batches = sequential_ready_single_batches_.load(std::memory_order_relaxed);
    value.sequential_ready_multi_batches = sequential_ready_multi_batches_.load(std::memory_order_relaxed);
    value.sequential_ready_adjacent_pairs = sequential_ready_adjacent_pairs_.load(std::memory_order_relaxed);
    value.sequential_ready_nonadjacent_pairs = sequential_ready_nonadjacent_pairs_.load(std::memory_order_relaxed);
    value.random_sparse_fast_batches = random_sparse_fast_batches_.load(std::memory_order_relaxed);
    value.random_sparse_fast_requests = random_sparse_fast_requests_.load(std::memory_order_relaxed);
    value.random_planned_batches = random_planned_batches_.load(std::memory_order_relaxed);
    value.random_precheck_fallbacks = random_precheck_fallbacks_.load(std::memory_order_relaxed);
    value.random_precheck_ns = random_precheck_ns_.load(std::memory_order_relaxed);
    value.random_local_plan_batches = random_local_plan_batches_.load(std::memory_order_relaxed);
    value.random_local_candidate_requests = random_local_candidate_requests_.load(std::memory_order_relaxed);
    value.cache_fill_bytes = cache_fill_bytes_.load(std::memory_order_relaxed);
    value.cache_fill_ns = cache_fill_ns_.load(std::memory_order_relaxed);
    value.cache_fill_skipped_bytes = cache_fill_skipped_bytes_.load(std::memory_order_relaxed);
    value.cache_admission_disables = cache_admission_disables_.load(std::memory_order_relaxed);
    value.cache_admission_reenables = cache_admission_reenables_.load(std::memory_order_relaxed);
    value.readseq_initial_requests = readseq_initial_requests_.load(std::memory_order_relaxed);
    value.readseq_refill_peer_io_requests = readseq_refill_peer_io_requests_.load(std::memory_order_relaxed);
    value.readseq_refill_peer_ready_requests = readseq_refill_peer_ready_requests_.load(std::memory_order_relaxed);
    value.readseq_refill_peer_idle_requests = readseq_refill_peer_idle_requests_.load(std::memory_order_relaxed);
    value.submit_ns = submit_ns_.load(std::memory_order_relaxed);
    value.disk_io_ns = disk_io_ns_.load(std::memory_order_relaxed);
    value.completion_wait_ns = completion_wait_ns_.load(std::memory_order_relaxed);
    value.storage_sync_ns = storage_sync_ns_.load(std::memory_order_relaxed);
    value.sequential_extent_count = sequential_extent_count_.load(std::memory_order_relaxed);
    value.sequential_8mb_extent_count = sequential_8mb_extent_count_.load(std::memory_order_relaxed);
    value.cross_worker_extent_count = cross_worker_extent_count_.load(std::memory_order_relaxed);
    value.utm_copy_ns = utm_copy_ns_.load(std::memory_order_relaxed);
    value.completion_publish_ns =
        completion_publish_ns_.load(std::memory_order_relaxed);
    value.wakeup_ns = wakeup_ns_.load(std::memory_order_relaxed);
    value.submit_to_host_dequeue_ns =
        submit_to_host_dequeue_ns_.load(std::memory_order_relaxed);
    value.host_dequeue_to_io_submit_ns =
        host_dequeue_to_io_submit_ns_.load(std::memory_order_relaxed);
    value.io_submit_to_complete_ns =
        io_submit_to_complete_ns_.load(std::memory_order_relaxed);
    value.io_complete_to_publish_ns =
        io_complete_to_publish_ns_.load(std::memory_order_relaxed);
    value.publish_to_host_resume_request_ns =
        publish_to_host_resume_request_ns_.load(std::memory_order_relaxed);
    value.wakeup_eligible_to_host_resume_request_ns =
        wakeup_eligible_to_host_resume_request_ns_.load(std::memory_order_relaxed);
    value.host_resume_ioctl_ns =
        host_resume_ioctl_ns_.load(std::memory_order_relaxed);
    value.completion_wakeup_count =
        completion_wakeup_count_.load(std::memory_order_relaxed);
    value.completion_ready_before_wait_count =
        completion_ready_before_wait_count_.load(
            std::memory_order_relaxed);
    value.ewma_bandwidth_bytes_per_sec =
        ewma_bandwidth_bytes_per_sec_.load(std::memory_order_relaxed);
    value.ewma_request_latency_ns =
        ewma_request_latency_ns_.load(std::memory_order_relaxed);
    value.ewma_queue_wait_ns =
        ewma_queue_wait_ns_.load(std::memory_order_relaxed);
    value.ewma_completion_latency_ns =
        ewma_completion_latency_ns_.load(std::memory_order_relaxed);
    value.adaptive_collect_usec =
        adaptive_collect_usec_.load(std::memory_order_relaxed);
    value.adaptive_batch_target =
        adaptive_batch_target_.load(std::memory_order_relaxed);
    value.adaptive_queue_depth =
        adaptive_queue_depth_.load(std::memory_order_relaxed);
    value.adaptive_gap_bytes =
        adaptive_gap_bytes_.load(std::memory_order_relaxed);
    value.window_first_enqueue_ns =
        window_first_enqueue_ns_.load(std::memory_order_relaxed);
    value.window_last_completion_ns =
        window_last_completion_ns_.load(std::memory_order_relaxed);
    value.critical_path_ns = value.window_last_completion_ns >=
            value.window_first_enqueue_ns ?
        value.window_last_completion_ns - value.window_first_enqueue_ns : 0;
    value.max_queue_wait_ns =
        max_queue_wait_ns_.load(std::memory_order_relaxed);
    value.max_batch_service_ns =
        max_batch_service_ns_.load(std::memory_order_relaxed);
    value.max_completion_latency_ns =
        max_completion_latency_ns_.load(std::memory_order_relaxed);
    const auto publication = publication_histogram_.snapshot();
    value.pipeline[SQLITE_PIPELINE_BUFFER_PUBLISH_SAMPLES] = publication.first;
    value.pipeline[SQLITE_PIPELINE_BUFFER_PUBLISH_P95_NS] = publication.second;
    value.pipeline[SQLITE_PIPELINE_BUFFER_ENQUEUE_PUBLISH_P95_NS] = buffer_latency_histogram_.snapshot().second;
    return value;
  }

  SqliteIoPerfSnapshot drainAndSnapshot() {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    condition_.wait(lock, [this] {
      return queue_.empty() && !processing_batch_;
    });
    return snapshot();
  }

  bool resetPerf() {
    std::unique_lock<std::mutex> queue_lock(queue_mutex_);
    condition_.wait(queue_lock, [this] { return queue_.empty() && !processing_batch_; });
    publication_histogram_.reset();
    buffer_latency_histogram_.reset();
    reset_write_feedback();
    bool cache_ready = true;
    invalidate_all_cache();
#ifdef __linux__
    if (configured_cache_mode() != CacheMode::kHot) {
      for (std::map<uint64_t, int>::const_iterator it = files_.begin();
           it != files_.end(); ++it) {
        if (fdatasync(it->second) != 0 ||
            posix_fadvise(it->second, 0, 0, POSIX_FADV_DONTNEED) != 0)
          cache_ready = false;
      }
    }
#endif
    // resetPerf runs only after draining the service. Do not let a warmup or
    // another workload/worker count supply a stale merge cost reference.
    read_merge_feedback_.clear();
    online_feedback_.clear();
    pipeline_depth_ = PipelineDepthFeedback();
    for (auto& value : pipeline_perf_) value.store(0);
    ewma_bandwidth_bytes_per_sec_.store(kDefaultDeviceBandwidth);
    ewma_request_latency_ns_.store(kDefaultRequestLatencyNs);
    ewma_queue_wait_ns_.store(0);
    ewma_completion_latency_ns_.store(0);
    adaptive_gap_bytes_.store(std::min(maximum_gap_, kDefaultGapLimit));
    copy_bandwidth_ = env_u64("GROUP_PMP_SQLITE_IO_COPY_BPS", kDefaultCopyBandwidth,
        UINT64_C(100000000), UINT64_C(10000000000));
#ifdef __linux__
#endif
    pending_read_feedback_ = nullptr;
    merge_plan_cost_ns_ = merge_completion_cost_ns_ = 200;
    candidate_cost_ns_ = 0;
    pipeline_perf_[SQLITE_PIPELINE_READ_SAVED_OP_NS].store(read_saved_op_ns_);
    pipeline_perf_[SQLITE_PIPELINE_WRITE_SAVED_OP_NS].store(write_saved_op_ns_);
    pipeline_perf_[SQLITE_PIPELINE_MERGE_CALIBRATED].store(merge_calibrated_ ? 1 : 0);
    pipeline_perf_[SQLITE_PIPELINE_CALIBRATED_READ_FIXED_NS].store(calibrated_saved_ns_[1][0]);
    pipeline_perf_[SQLITE_PIPELINE_CALIBRATED_READ_VECTOR_NS].store(calibrated_saved_ns_[1][1]);
    pipeline_perf_[SQLITE_PIPELINE_CALIBRATED_WRITE_FIXED_NS].store(calibrated_saved_ns_[0][0]);
    pipeline_perf_[SQLITE_PIPELINE_CALIBRATED_WRITE_VECTOR_NS].store(calibrated_saved_ns_[0][1]);
    for (auto& value : read100k_)
      value.store(0, std::memory_order_relaxed);
    task_count_.store(0, std::memory_order_relaxed);
    batch_count_.store(0, std::memory_order_relaxed);
    queue_wait_ns_.store(0, std::memory_order_relaxed);
    writer_wait_ns_.store(0, std::memory_order_relaxed);
    read_service_ns_.store(0, std::memory_order_relaxed);
    write_service_ns_.store(0, std::memory_order_relaxed);
    control_service_ns_.store(0, std::memory_order_relaxed);
    commit_ns_.store(0, std::memory_order_relaxed);
    commit_count_.store(0, std::memory_order_relaxed);
    queue_depth_peak_.store(0, std::memory_order_relaxed);
    io_uring_submissions_.store(0, std::memory_order_relaxed);
    registered_file_operations_.store(0, std::memory_order_relaxed);
    registered_buffer_operations_.store(0, std::memory_order_relaxed);
    fixed_buffer_operations_.store(0, std::memory_order_relaxed);
    direct_io_operations_.store(0, std::memory_order_relaxed);
    direct_alignment_fallback_operations_.store(
        0, std::memory_order_relaxed);
    posix_fallback_operations_.store(0, std::memory_order_relaxed);
    merged_io_count_.store(0, std::memory_order_relaxed);
    sparse_io_count_.store(0, std::memory_order_relaxed);
    useful_io_bytes_.store(0, std::memory_order_relaxed);
    physical_io_bytes_.store(0, std::memory_order_relaxed);
    logical_request_count_.store(0, std::memory_order_relaxed);
    physical_request_count_.store(0, std::memory_order_relaxed);
    deduplicated_request_count_.store(0, std::memory_order_relaxed);
    cache_full_hit_count_.store(0, std::memory_order_relaxed);
    cache_partial_hit_count_.store(0, std::memory_order_relaxed);
    cache_miss_count_.store(0, std::memory_order_relaxed);
    cache_hit_bytes_.store(0, std::memory_order_relaxed);
    collect_ns_.store(0, std::memory_order_relaxed);
    sort_ns_.store(0, std::memory_order_relaxed);
    cluster_ns_.store(0, std::memory_order_relaxed);
    write_overlap_check_ns_.store(0, std::memory_order_relaxed);
    write_overlap_checks_.store(0, std::memory_order_relaxed);
    write_disjoint_batches_.store(0, std::memory_order_relaxed);
    write_overlap_batches_.store(0, std::memory_order_relaxed);
    adaptive_write_grow_count_.store(0, std::memory_order_relaxed);
    adaptive_write_shrink_count_.store(0, std::memory_order_relaxed);
    adaptive_write_hold_count_.store(0, std::memory_order_relaxed);
    sequential_ready_single_batches_.store(0, std::memory_order_relaxed);
    sequential_ready_multi_batches_.store(0, std::memory_order_relaxed);
    sequential_ready_adjacent_pairs_.store(0, std::memory_order_relaxed);
    sequential_ready_nonadjacent_pairs_.store(0, std::memory_order_relaxed);
    random_sparse_fast_batches_.store(0, std::memory_order_relaxed);
    random_sparse_fast_requests_.store(0, std::memory_order_relaxed);
    random_planned_batches_.store(0, std::memory_order_relaxed);
    random_precheck_fallbacks_.store(0, std::memory_order_relaxed);
    random_precheck_ns_.store(0, std::memory_order_relaxed);
    random_local_plan_batches_.store(0, std::memory_order_relaxed);
    random_local_candidate_requests_.store(0, std::memory_order_relaxed);
    cache_fill_bytes_.store(0, std::memory_order_relaxed);
    cache_fill_ns_.store(0, std::memory_order_relaxed);
    cache_fill_skipped_bytes_.store(0, std::memory_order_relaxed);
    cache_admission_disables_.store(0, std::memory_order_relaxed);
    cache_admission_reenables_.store(0, std::memory_order_relaxed);
    readseq_initial_requests_.store(0, std::memory_order_relaxed);
    readseq_refill_peer_io_requests_.store(0, std::memory_order_relaxed);
    readseq_refill_peer_ready_requests_.store(0, std::memory_order_relaxed);
    readseq_refill_peer_idle_requests_.store(0, std::memory_order_relaxed);
    submit_ns_.store(0, std::memory_order_relaxed);
    disk_io_ns_.store(0, std::memory_order_relaxed);
    completion_wait_ns_.store(0, std::memory_order_relaxed);
    storage_sync_ns_.store(0, std::memory_order_relaxed);
    sequential_extent_count_.store(0, std::memory_order_relaxed);
    sequential_8mb_extent_count_.store(0, std::memory_order_relaxed);
    cross_worker_extent_count_.store(0, std::memory_order_relaxed);
    utm_copy_ns_.store(0, std::memory_order_relaxed);
    completion_publish_ns_.store(0, std::memory_order_relaxed);
    wakeup_ns_.store(0, std::memory_order_relaxed);
    submit_to_host_dequeue_ns_.store(0, std::memory_order_relaxed);
    host_dequeue_to_io_submit_ns_.store(0, std::memory_order_relaxed);
    io_submit_to_complete_ns_.store(0, std::memory_order_relaxed);
    io_complete_to_publish_ns_.store(0, std::memory_order_relaxed);
    publish_to_host_resume_request_ns_.store(0, std::memory_order_relaxed);
    wakeup_eligible_to_host_resume_request_ns_.store(0, std::memory_order_relaxed);
    host_resume_ioctl_ns_.store(0, std::memory_order_relaxed);
    completion_wakeup_count_.store(0, std::memory_order_relaxed);
    completion_ready_before_wait_count_.store(0,
                                               std::memory_order_relaxed);
    window_first_enqueue_ns_.store(0, std::memory_order_relaxed);
    window_last_completion_ns_.store(0, std::memory_order_relaxed);
    max_queue_wait_ns_.store(0, std::memory_order_relaxed);
    max_batch_service_ns_.store(0, std::memory_order_relaxed);
    max_completion_latency_ns_.store(0, std::memory_order_relaxed);
    return cache_ready;
  }

  bool prepareCase(uint64_t file_id, uint8_t* const* utms,
                   const size_t* utm_sizes, size_t count) {
#ifdef __linux__
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      condition_.wait(lock, [this] { return queue_.empty() && !processing_batch_; });
    }
    if (!utms || !utm_sizes || !count)
      return false;
    const int buffered_fd = file_for(file_id, false);
    if (buffered_fd < 0)
      return false;
    if (configured_cache_mode() == CacheMode::kDirect &&
        file_for(file_id, true) < 0)
      return false;
    std::lock_guard<std::mutex> ring_lock(ring_mutex_);
    ring_.unregisterBuffers();
    registered_utm_buffers_.clear();
    utm_buffers_registered_ = false;
    buffer_registration_attempts_.store(0, std::memory_order_relaxed);
    buffer_registration_failures_.store(0, std::memory_order_relaxed);
    for (size_t index = 0; index < count; ++index) {
      if (!utms[index] ||
          GROUP_PMP_SQLITE_VFS_UTM_BYTES > utm_sizes[index])
        return false;
      struct iovec first;
      first.iov_base = utms[index] + GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
      first.iov_len = GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
      registered_utm_buffers_.push_back(first);
      struct iovec second;
      second.iov_base = utms[index] + GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET;
      second.iov_len = GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
      registered_utm_buffers_.push_back(second);
    }
    buffer_registration_attempts_.fetch_add(1, std::memory_order_relaxed);
    utm_buffers_registered_ =
        ring_.registerBuffers(registered_utm_buffers_);
    if (!utm_buffers_registered_) {
      buffer_registration_failures_.fetch_add(1,
                                               std::memory_order_relaxed);
      std::fprintf(stderr,
                   "[P10][sqlite] io_uring UTM buffer registration failed: "
                   "workers=%zu buffers=%zu errno=%d (%s)\n",
                   count, registered_utm_buffers_.size(), errno,
                   std::strerror(errno));
    }
    prepare_registered_files();
    const bool file_registered =
        fixed_file_indices_.find(buffered_fd) != fixed_file_indices_.end();
    if (!file_registered)
      std::fprintf(stderr,
                   "[P10][sqlite] io_uring data-file registration failed: "
                   "file_id=%llu fd=%d errno=%d (%s)\n",
                   static_cast<unsigned long long>(file_id), buffered_fd,
                   errno, std::strerror(errno));
    if (utm_buffers_registered_ && file_registered) {
      std::lock_guard<std::mutex> queue_lock(queue_mutex_);
      ++case_epoch_;
    }
    return utm_buffers_registered_ && file_registered;
#else
    (void)file_id;
    (void)utms;
    (void)utm_sizes;
    (void)count;
    return false;
#endif
  }

  void clearRegisteredUtmBuffers() {
#ifdef __linux__
    {
      std::unique_lock<std::mutex> queue_lock(queue_mutex_);
      condition_.wait(queue_lock, [this] {
        return queue_.empty() && !processing_batch_;
      });
    }
    std::lock_guard<std::mutex> ring_lock(ring_mutex_);
    ring_.unregisterBuffers();
    registered_utm_buffers_.clear();
    utm_buffers_registered_ = false;
#endif
  }

  void recordWakeupTimeline(uint64_t publish_ns, uint64_t eligible_ns,
                            uint64_t wake_ns, uint64_t resume_ns) {
    if (publish_ns && wake_ns >= publish_ns)
      publish_to_host_resume_request_ns_.fetch_add(wake_ns - publish_ns,
                                       std::memory_order_relaxed);
    if (eligible_ns && wake_ns >= eligible_ns)
      wakeup_eligible_to_host_resume_request_ns_.fetch_add(
          wake_ns - eligible_ns, std::memory_order_relaxed);
    if (publish_ns && eligible_ns > publish_ns)
      completion_ready_before_wait_count_.fetch_add(
          1, std::memory_order_relaxed);
    if (resume_ns >= wake_ns)
      host_resume_ioctl_ns_.fetch_add(resume_ns - wake_ns,
                                              std::memory_order_relaxed);
    completion_wakeup_count_.fetch_add(1, std::memory_order_relaxed);
  }

  void cleanup_case(uint64_t worker_count, uint64_t workload) {
    (void)drainAndSnapshot();
    invalidate_all_cache();
    std::lock_guard<std::mutex> lock(database_mutex_);
    sqlite3_stmt* statement = nullptr;
    const char* cleanup_sql = worker_count ?
        "DELETE FROM extent_index_v3 WHERE worker_count=?1 AND workload=?2" :
        "DELETE FROM extent_index_v3 WHERE workload=?1";
    if (ensure_database_locked() &&
        sqlite3_prepare_v2(db_, cleanup_sql, -1, &statement, nullptr) ==
            SQLITE_OK) {
      sqlite3_bind_int64(statement, 1, static_cast<sqlite3_int64>(
          worker_count ? worker_count : workload));
      if (worker_count)
        sqlite3_bind_int64(statement, 2,
                           static_cast<sqlite3_int64>(workload));
      (void)sqlite3_step(statement);
      sqlite3_finalize(statement);
    }
#ifdef __linux__
    /* A case owns the workload file exclusively. Reclaim its sparse extents
     * after every run; otherwise randomized worker layouts accumulate real
     * blocks in /tmp even though their apparent ranges are sparse. */
    const int fd = file_for(workload);
    if (fd >= 0 && ftruncate(fd, 0) != 0)
      std::fprintf(stderr,
                   "[P10][sqlite-io] truncate failed: workload=%llu errno=%d\n",
                   static_cast<unsigned long long>(workload), errno);
    {
      std::lock_guard<std::mutex> ring_lock(ring_mutex_);
      ring_.unregisterBuffers();
      registered_utm_buffers_.clear();
      utm_buffers_registered_ = false;
    }
#endif
  }

 private:
  typedef std::pair<uintptr_t, uint64_t> CipherCacheKey;

  struct CacheAdmission {
    uint64_t requests = 0, bytes = 0, reusable_bytes = 0;
    bool fill = true;
    // Observe metadata even while disabled. This can re-enable a newly local
    // workload without speculative ciphertext copies or extra disk requests.
    int observe(uint64_t length, uint64_t reusable) {
      ++requests;
      bytes += length;
      reusable_bytes += reusable;
      if (requests < 128 && bytes < UINT64_C(2000000))
        return 0;
      const bool next = reusable_bytes >= (bytes + 99) / 100;
      const int change = next == fill ? 0 : (next ? 1 : -1);
      fill = next;
      requests = bytes = reusable_bytes = 0;
      return change;
    }
  };

  CipherCacheKey cache_key(const Task& task) const {
    return CipherCacheKey(reinterpret_cast<uintptr_t>(task.utm),
                          task.request.buffer_id);
  }

  void invalidate_file_cache(uint64_t file_id) {
    cache_admission_.erase(file_id);
    for (std::map<CipherCacheKey, CipherCacheEntry>::iterator it =
             cipher_cache_.begin(); it != cipher_cache_.end();) {
      if (it->second.file_id == file_id)
        it = cipher_cache_.erase(it);
      else
        ++it;
    }
  }

  void invalidate_all_cache() {
    cipher_cache_.clear();
    cache_admission_.clear();
  }

  void observe_cache(const Task& task, uint64_t reusable) {
    if (!adaptive_extent_mode() ||
        (task.request.workload != GROUP_PMP_SQLITE_READRANDOM &&
         task.request.workload != GROUP_PMP_SQLITE_READRAND100K))
      return;
    const int change = cache_admission_[task.stored_file_id].observe(
        task.storage_length, reusable);
    if (change < 0)
      cache_admission_disables_.fetch_add(1, std::memory_order_relaxed);
    else if (change > 0)
      cache_admission_reenables_.fetch_add(1, std::memory_order_relaxed);
  }

  void apply_read_cache(Task& task) {
    task.io_offset = task.storage_offset;
    task.io_length = task.storage_length;
    task.data_offset = 0;
    if (online_execution_) return;
    // Streaming readseq never revisits its previous buffer. Keep direct UTM
    // reads without allocating/copying ciphertext into an unused Host cache.
    if (task.request.workload == GROUP_PMP_SQLITE_READSEQ)
      return;
    const CipherCacheKey key = cache_key(task);
    std::map<CipherCacheKey, CipherCacheEntry>::const_iterator found =
        cipher_cache_.find(key);
    if (found == cipher_cache_.end() || !found->second.valid ||
        found->second.file_id != task.stored_file_id ||
        found->second.generation != task.request.run_id ||
        found->second.key_epoch != task.request.run_id ||
        found->second.sequence != task.stored_sequence) {
      observe_cache(task, 0);
      cache_miss_count_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    const CipherCacheEntry& entry = found->second;
    const uint64_t request_end = task.storage_offset + task.storage_length;
    const uint64_t cache_end = entry.offset + entry.length;
    if (request_end < task.storage_offset || cache_end < entry.offset) {
      observe_cache(task, 0);
      cache_miss_count_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    const uint64_t overlap_begin = std::max(task.storage_offset, entry.offset);
    const uint64_t overlap_end = std::min(request_end, cache_end);
    if (overlap_end <= overlap_begin) {
      observe_cache(task, 0);
      cache_miss_count_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    // A middle-only hit would still need the full physical read; don't copy
    // bytes which are immediately overwritten, or credit them as saved I/O.
    const bool reusable = overlap_begin == task.storage_offset ||
                          overlap_end == request_end;
    observe_cache(task, reusable ? overlap_end - overlap_begin : 0);
    if (!reusable || entry.ciphertext.size() != entry.length) {
      cache_miss_count_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    const uint64_t copy_started = now_ns();
    const uint64_t target_offset = overlap_begin - task.storage_offset;
    const uint64_t source_offset = overlap_begin - entry.offset;
    const uint64_t overlap_length = overlap_end - overlap_begin;
    std::memcpy(task.data() + target_offset,
                entry.ciphertext.data() + source_offset,
                static_cast<size_t>(overlap_length));
    utm_copy_ns_.fetch_add(now_ns() - copy_started,
                           std::memory_order_relaxed);
    cache_hit_bytes_.fetch_add(overlap_length, std::memory_order_relaxed);
    if (overlap_begin == task.storage_offset && overlap_end == request_end) {
      task.cache_satisfied = true;
      task.io_length = 0;
      cache_full_hit_count_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    /* A single physical request can represent a missing prefix or suffix.
     * A middle-only hit would require two SQEs; leave it as a miss so the
     * planner remains atomic and cannot publish a half-filled UTM buffer. */
    if (overlap_begin == task.storage_offset) {
      task.io_offset = overlap_end;
      task.data_offset = overlap_length;
      task.io_length = request_end - overlap_end;
      task.cache_partial = true;
    } else if (overlap_end == request_end) {
      task.io_offset = task.storage_offset;
      task.data_offset = 0;
      task.io_length = overlap_begin - task.storage_offset;
      task.cache_partial = true;
    }
    if (task.cache_partial)
      cache_partial_hit_count_.fetch_add(1, std::memory_order_relaxed);
    else
      cache_miss_count_.fetch_add(1, std::memory_order_relaxed);
  }

  void update_read_cache(const Task& task) {
    if (online_execution_) return;
    if (task.result != 0 || !task.storage_length ||
        task.request.workload == GROUP_PMP_SQLITE_READSEQ)
      return;
    CipherCacheEntry& entry = cipher_cache_[cache_key(task)];
    entry.valid = true;
    entry.utm_identity = reinterpret_cast<uintptr_t>(task.utm);
    entry.buffer_id = task.request.buffer_id;
    entry.file_id = task.stored_file_id;
    entry.offset = task.storage_offset;
    entry.length = task.storage_length;
    entry.generation = task.request.run_id;
    entry.sequence = task.stored_sequence;
    entry.key_epoch = task.request.run_id;
    if (adaptive_extent_mode() &&
        (task.request.workload == GROUP_PMP_SQLITE_READRANDOM ||
         task.request.workload == GROUP_PMP_SQLITE_READRAND100K) &&
        !cache_admission_[task.stored_file_id].fill) {
      // Preserve the metadata as a shadow entry, never use stale ciphertext.
      entry.ciphertext.clear();
      cache_fill_skipped_bytes_.fetch_add(task.storage_length,
                                          std::memory_order_relaxed);
      return;
    }
    const uint64_t copy_started = now_ns();
    entry.ciphertext.assign(task.data(), task.data() + task.storage_length);
    const uint64_t copied_ns = now_ns() - copy_started;
    utm_copy_ns_.fetch_add(copied_ns, std::memory_order_relaxed);
    cache_fill_ns_.fetch_add(copied_ns, std::memory_order_relaxed);
    cache_fill_bytes_.fetch_add(task.storage_length, std::memory_order_relaxed);
  }

  bool merge_within_budget(const IoGroup& group, const Task& task,
                           uint64_t union_end, uint64_t* gap_out,
                           size_t joined_tasks = 1, size_t existing_members = 0) {
    const size_t existing = existing_members ? existing_members : group.tasks.size();
    pipeline_perf_[SQLITE_PIPELINE_CLUSTER_BUDGET_CHECKS].fetch_add(1);
    if (group.tasks.empty() || !task.io_length || task.io_offset < group.offset ||
        union_end < group.end || union_end < group.offset ||
        union_end - group.offset > merge_limit_ || existing >= 1024 ||
        !joined_tasks || joined_tasks > 1024 - existing ||
        task.io_length > UINT64_MAX - group.useful_bytes)
      return false;
    const uint64_t gap = task.io_offset > group.end ? task.io_offset - group.end : 0;
    const uint64_t span = union_end - group.offset;
    const uint64_t useful = group.useful_bytes + task.io_length;
    const Task& first = *group.tasks.front();
    const bool calibrated = merge_calibrated_ && first.io_length == 4096 && task.io_length == 4096 &&
        (group.policy == IoPlanningPolicy::kRandomReadClustered ||
         group.policy == IoPlanningPolicy::kRandomWriteBatch);
    bool fixed_layout = group.fixed_layout && !group.overlapping && !group.spans_gap &&
        task.io_offset == group.end && first.utm == task.utm &&
        first.request.buffer_id == task.request.buffer_id &&
        reinterpret_cast<uintptr_t>(task.io_data()) ==
            reinterpret_cast<uintptr_t>(first.io_data()) + group.end - group.offset;
    if (calibrated && fixed_layout) {
      InlineOneList<iovec> vector;
      vector.push_back({first.io_data(), static_cast<size_t>(span)});
      fixed_layout = fixed_buffer_for_vectors(vector) >= 0;
    }
    if (calibrated && !calibrated_saved_ns_[group.read][fixed_layout ? 0 : 1]) {
      pipeline_perf_[SQLITE_PIPELINE_CALIBRATION_ZERO_REJECTS].fetch_add(1);
      return false;
    }
    const uint64_t bandwidth = ewma_bandwidth_bytes_per_sec_.load(
        std::memory_order_relaxed);
    if (gap_out) *gap_out = gap;
    // Sorted intervals cannot fill an earlier hole. Count unique coverage,
    // not overlapping/duplicate payload twice, for the amplification budget.
    if (group.gap_bytes > span || gap > span - group.gap_bytes) return false;
    const uint64_t holes = group.gap_bytes + gap;
    const uint64_t covered = span - holes;
    const bool small_100k_gap = group.policy == IoPlanningPolicy::kReadRand100kAdjacent &&
        gap <= UINT64_C(4096);
    if (gap && !(group.policy == IoPlanningPolicy::kRandomReadClustered || small_100k_gap))
      return false;
    if (gap && (gap > adaptive_gap_bytes_.load(std::memory_order_relaxed) ||
                gap > maximum_gap_))
      return false;
    // span <= 8 MB and amplification <= 1200, so these products fit uint64_t.
    if (!covered || span * 1000 > covered * read_amplification_permille_) {
      pipeline_perf_[SQLITE_PIPELINE_CLUSTER_AMP_REJECTS].fetch_add(1);
      return false;
    }
    if ((!group.read && task.io_offset != group.end) ||
        (group.policy == IoPlanningPolicy::kSequentialContiguous && gap))
      return false;
    const bool independent = group.independent_completions ||
        group.tasks.front()->completion != task.completion;
    const bool fanout = group.read && (group.overlapping || group.spans_gap || gap ||
        task.io_offset < group.end);
    const uint64_t copy_cost = saturating_ns_for_bytes(fanout ? useful : 0, copy_bandwidth_);
    const uint64_t floor = group.release_floor_bytes ? group.release_floor_bytes :
        group.end - group.offset;
    const uint64_t earliest = std::min(floor, task.io_length);
    // Bound the whole prospective extent, not each incremental join. A single
    // CQE ties its owners together; charge the smallest owner's extra transfer.
    const uint64_t release_cost = independent && span > earliest ?
        saturating_ns_for_bytes(span - earliest, bandwidth) : 0;
    const uint64_t gap_cost = saturating_ns_for_bytes(holes, bandwidth);
    uint64_t remaining = merge_delay_budget_ns_;
    const auto charge = [&remaining](uint64_t cost) {
      if (cost > remaining) return false;
      remaining -= cost;
      return true;
    };
    const uint64_t members = existing + joined_tasks;
    // Subtract before multiplying: overflow-safe and no software quad-float
    // arithmetic in the RISC-V candidate admission path.
    const bool fits = charge(std::max(release_cost, gap_cost)) && charge(copy_cost) &&
        merge_plan_cost_ns_ <= remaining / members && charge(merge_plan_cost_ns_ * members) &&
        merge_completion_cost_ns_ <= remaining / members && charge(merge_completion_cost_ns_ * members);
    if (release_cost) pipeline_perf_[SQLITE_PIPELINE_MERGE_RELEASE_PENALTY_NS].fetch_add(release_cost);
    if (!fits) {
      pipeline_perf_[SQLITE_PIPELINE_CLUSTER_DELAY_REJECTS].fetch_add(1);
      if (release_cost) pipeline_perf_[SQLITE_PIPELINE_MERGE_RELEASE_REJECTS].fetch_add(1);
      return false;
    }
    // Defaults are prior board pair-probe estimates. The mixed-batch probe
    // reports a conservative replacement; zero disables unprofitable merges.
    const uint64_t saved_op = calibrated ? calibrated_saved_ns_[group.read][fixed_layout ? 0 : 1] :
        group.read ? read_saved_op_ns_ : write_saved_op_ns_;
    const uint64_t saved = saved_op * (members - 1);
    const uint64_t extra = std::max(release_cost, gap_cost) + copy_cost +
        members * (candidate_cost_ns_ + merge_plan_cost_ns_ + extra_member_ns_);
    pipeline_perf_[SQLITE_PIPELINE_NET_BENEFIT_CHECKS].fetch_add(1);
    pipeline_perf_[SQLITE_PIPELINE_ESTIMATED_SAVED_NS].fetch_add(saved);
    pipeline_perf_[SQLITE_PIPELINE_ESTIMATED_EXTRA_NS].fetch_add(extra);
    if (saved <= extra) {
      pipeline_perf_[SQLITE_PIPELINE_NET_BENEFIT_REJECTS].fetch_add(1);
      return false;
    }
    pipeline_perf_[SQLITE_PIPELINE_CLUSTER_BUDGET_ACCEPTS].fetch_add(1);
    return true;
  }

  std::string storage_directory() const {
    const char* directory = std::getenv("GROUP_PMP_SQLITE_STORAGE_DIR");
    return directory && directory[0] ? directory : "/tmp";
  }

  std::string database_path() const {
    return storage_directory() + "/keystone-group-extent-index.db";
  }

  std::string data_path(uint64_t file_id) const {
    char name[96];
    std::snprintf(name, sizeof(name), "/keystone-cipher-%016llx.bin",
                  static_cast<unsigned long long>(file_id));
    return storage_directory() + name;
  }

  bool ensure_database_locked() {
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS extent_index_v3("
        "run_id INTEGER NOT NULL,worker_index INTEGER NOT NULL,"
        "worker_count INTEGER NOT NULL,workload INTEGER NOT NULL,"
        "task_id INTEGER NOT NULL,file_id INTEGER NOT NULL,"
        "logical_offset INTEGER NOT NULL,file_offset INTEGER NOT NULL,"
        "cipher_length INTEGER NOT NULL,logical_size INTEGER NOT NULL,"
        "sequence INTEGER NOT NULL,tag BLOB NOT NULL,"
        "PRIMARY KEY(run_id,worker_index,workload,logical_offset))";
    char* error = nullptr;
    if (db_)
      return reset_statement_ && write_statement_ && read_statement_ && read_begin_statement_ &&
          begin_statement_ && commit_statement_ && rollback_statement_;
    if (sqlite3_open_v2(database_path().c_str(), &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK)
      return false;
    if (sqlite3_exec(db_,
          "PRAGMA journal_mode=WAL;PRAGMA synchronous=NORMAL;"
          "PRAGMA busy_timeout=5000;PRAGMA wal_autocheckpoint=4096;"
          "PRAGMA temp_store=MEMORY;PRAGMA cache_size=-8192;",
          nullptr, nullptr, &error) != SQLITE_OK ||
        sqlite3_exec(db_, schema, nullptr, nullptr, &error) != SQLITE_OK) {
      if (error)
        sqlite3_free(error);
      return false;
    }
    // A bounded VALUES relation keeps per-key isolation while amortizing VM
    // setup and the WAL read snapshot across 64 lookups (256 bindings).
    std::string read_sql = "WITH requested(slot,run_id,worker_index,workload,logical_offset) AS (VALUES";
    for (size_t i = 0; i < kMetadataReadBatch; ++i) {
      if (i) read_sql += ',';
      read_sql += '(' + std::to_string(i) + ",?,?,?,?)";
    }
    read_sql += ") SELECT r.slot,e.task_id,e.file_id,e.file_offset,e.cipher_length,"
        "e.logical_size,e.sequence,e.tag FROM requested r LEFT JOIN extent_index_v3 e ON "
        "e.run_id=r.run_id AND e.worker_index=r.worker_index AND e.workload=r.workload "
        "AND e.logical_offset=r.logical_offset WHERE r.run_id IS NOT NULL";
    return sqlite3_prepare_v2(db_,
               "DELETE FROM extent_index_v3 WHERE run_id=?1 AND "
               "worker_index=?2 AND workload=?3", -1,
               &reset_statement_, nullptr) == SQLITE_OK &&
        sqlite3_prepare_v2(db_,
               "INSERT OR REPLACE INTO extent_index_v3 VALUES("
               "?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)", -1,
               &write_statement_, nullptr) == SQLITE_OK &&
        sqlite3_prepare_v2(db_, read_sql.c_str(), -1, &read_statement_, nullptr) == SQLITE_OK &&
        sqlite3_prepare_v2(db_, "BEGIN", -1, &read_begin_statement_, nullptr) == SQLITE_OK &&
        sqlite3_prepare_v2(db_, "BEGIN IMMEDIATE", -1, &begin_statement_,
                           nullptr) == SQLITE_OK &&
        sqlite3_prepare_v2(db_, "COMMIT", -1, &commit_statement_, nullptr) ==
            SQLITE_OK &&
        sqlite3_prepare_v2(db_, "ROLLBACK", -1, &rollback_statement_,
                           nullptr) == SQLITE_OK;
  }

  static bool step_control_statement(sqlite3_stmt* statement) {
    if (!statement)
      return false;
    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
    const int result = sqlite3_step(statement);
    sqlite3_reset(statement);
    return result == SQLITE_DONE;
  }

  int file_for(uint64_t file_id, bool direct = false) {
#ifdef __linux__
    std::map<uint64_t, int>& selected = direct ? direct_files_ : files_;
    std::map<uint64_t, int>::iterator found = selected.find(file_id);
    if (found != selected.end())
      return found->second;
    int flags = O_RDWR | O_CREAT | O_CLOEXEC;
#ifdef O_DIRECT
    if (direct)
      flags |= O_DIRECT;
#else
    if (direct)
      return -1;
#endif
    int fd = open(data_path(file_id).c_str(), flags, 0600);
    if (fd < 0)
      return -1;
    selected[file_id] = fd;
    return fd;
#else
  (void)file_id;
  (void)direct;
  return -1;
#endif
  }

#ifdef __linux__
  void prepare_registered_files() {
    if (ring_.inflight() || !pipeline_batches_.empty()) return;
    std::vector<int> descriptors;
    fixed_file_indices_.clear();
    for (std::map<uint64_t, int>::const_iterator it = files_.begin();
         it != files_.end(); ++it)
      descriptors.push_back(it->second);
    for (std::map<uint64_t, int>::const_iterator it = direct_files_.begin();
         it != direct_files_.end(); ++it)
      descriptors.push_back(it->second);
    if (!ring_.registerFiles(descriptors))
      return;
    for (size_t index = 0; index < descriptors.size(); ++index)
      fixed_file_indices_[descriptors[index]] = static_cast<int>(index);
  }

  void prepare_registered_buffers(const std::vector<Task*>& tasks) {
    if (ring_.inflight() || !pipeline_batches_.empty()) return;
    bool changed = false;
    for (size_t task_index = 0; task_index < tasks.size(); ++task_index) {
      const Task& task = *tasks[task_index];
      if (task.request.buffer_id >= GROUP_PMP_SQLITE_VFS_BUFFER_COUNT)
        continue;
      const uint64_t payload_offset = task.request.buffer_id ?
          GROUP_PMP_SQLITE_VFS_BUFFER1_OFFSET :
          GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET;
      if (payload_offset > task.utm_size ||
          GROUP_PMP_SQLITE_VFS_BUFFER_BYTES >
              task.utm_size - payload_offset)
        continue;
      void* const payload = task.utm + payload_offset;
      bool found = false;
      for (size_t buffer_index = 0;
           buffer_index < registered_utm_buffers_.size(); ++buffer_index) {
        if (registered_utm_buffers_[buffer_index].iov_base == payload &&
            registered_utm_buffers_[buffer_index].iov_len ==
                GROUP_PMP_SQLITE_VFS_BUFFER_BYTES) {
          found = true;
          break;
        }
      }
      if (!found) {
        struct iovec buffer;
        buffer.iov_base = payload;
        buffer.iov_len = GROUP_PMP_SQLITE_VFS_BUFFER_BYTES;
        registered_utm_buffers_.push_back(buffer);
        changed = true;
      }
    }
    /* prepareCase() registers both buffers before the timing window. Never
     * replace the registration table while a previous SQE still references it. */
    if (changed || (!utm_buffers_registered_ &&
                    !registered_utm_buffers_.empty())) {
      buffer_registration_attempts_.fetch_add(1,
                                               std::memory_order_relaxed);
      utm_buffers_registered_ =
          ring_.registerBuffers(registered_utm_buffers_);
      if (!utm_buffers_registered_)
        buffer_registration_failures_.fetch_add(
            1, std::memory_order_relaxed);
    }
  }

  int fixed_buffer_for_vectors(const InlineOneList<iovec>& vectors) const {
    if (!utm_buffers_registered_ || vectors.size() != 1)
      return -1;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(
        vectors[0].iov_base);
    const uintptr_t end = begin + vectors[0].iov_len;
    if (end < begin)
      return -1;
    for (size_t index = 0; index < registered_utm_buffers_.size(); ++index) {
      const uintptr_t registered_begin = reinterpret_cast<uintptr_t>(
          registered_utm_buffers_[index].iov_base);
      const uintptr_t registered_end = registered_begin +
          registered_utm_buffers_[index].iov_len;
      if (registered_end >= registered_begin && begin >= registered_begin &&
          end <= registered_end)
        return static_cast<int>(index);
    }
    return -1;
  }

  int fixed_buffer_for(const IoGroup& group) const {
    return group.read_buffer ? -1 : fixed_buffer_for_vectors(group.vectors);
  }

  // A vectored extent can stay on READ_FIXED/WRITE_FIXED only when its file
  // bytes and UTM bytes are both contiguous inside one registered buffer.
  void fold_contiguous_vectors(InlineOneList<iovec>* vectors,
                               uint64_t file_bytes) const {
    if (!vectors || vectors->size() < 2 || !utm_buffers_registered_)
      return;
    const uintptr_t first = reinterpret_cast<uintptr_t>((*vectors)[0].iov_base);
    uintptr_t next = first;
    uint64_t bytes = 0;
    for (const iovec& part : *vectors) {
      if (reinterpret_cast<uintptr_t>(part.iov_base) != next ||
          part.iov_len > UINTPTR_MAX - next ||
          part.iov_len > UINT64_MAX - bytes)
        return;
      next += part.iov_len;
      bytes += part.iov_len;
    }
    if (bytes != file_bytes || bytes > SIZE_MAX)
      return;
    InlineOneList<iovec> single;
    single.push_back({reinterpret_cast<void*>(first), static_cast<size_t>(bytes)});
    if (fixed_buffer_for_vectors(single) >= 0)
      *vectors = std::move(single);
  }

  bool vectors_use_registered_buffers(const IoGroup& group) const {
    if (!utm_buffers_registered_ || group.read_buffer ||
        group.vectors.empty())
      return false;
    for (size_t vector_index = 0; vector_index < group.vectors.size();
         ++vector_index) {
      const uintptr_t begin = reinterpret_cast<uintptr_t>(
          group.vectors[vector_index].iov_base);
      const uintptr_t end = begin + group.vectors[vector_index].iov_len;
      bool found = false;
      if (end < begin)
        return false;
      for (size_t index = 0; index < registered_utm_buffers_.size(); ++index) {
        const uintptr_t registered_begin = reinterpret_cast<uintptr_t>(
            registered_utm_buffers_[index].iov_base);
        const uintptr_t registered_end = registered_begin +
            registered_utm_buffers_[index].iov_len;
        if (registered_end >= registered_begin && begin >= registered_begin &&
            end <= registered_end) {
          found = true;
          break;
        }
      }
      if (!found)
        return false;
    }
    return true;
  }
#endif

  void publish(Task& task, int result, bool notify = true,
               bool publish_ring = true) {
    struct group_pmp_sqlite_vfs_status status;
    const uint64_t offset = status_offset_for_request(task.request);
    if (offset > task.utm_size || sizeof(status) > task.utm_size - offset) {
      if (notify && task.completion)
        task.completion->completeOne();
      return;
    }
    std::memset(&status, 0, sizeof(status));
    status.magic = GROUP_PMP_SQLITE_VFS_MAGIC;
    status.version = GROUP_PMP_SQLITE_VFS_VERSION;
    status.request_id = task.request.request_id;
    status.state = GROUP_PMP_SQLITE_VFS_STATE_PENDING;
    status.result = result;
    status.length = result == 0 ? task.storage_length : task.request.length;
    status.sequence = result == 0 &&
            task.request.operation == GROUP_PMP_SQLITE_VFS_OP_READ ?
        task.stored_sequence : task.request.sequence;
    if (result == 0 && task.request.operation == GROUP_PMP_SQLITE_VFS_OP_READ)
      std::memcpy(status.tag, task.stored_tag, sizeof(status.tag));
    else
      std::memcpy(status.tag, task.request.tag, sizeof(status.tag));
    std::memcpy(task.utm + offset, &status, sizeof(status));
    __atomic_store_n(reinterpret_cast<uint64_t*>(
                         task.utm + offset + offsetof(
                             struct group_pmp_sqlite_vfs_status, state)),
                     result == 0 ? GROUP_PMP_SQLITE_VFS_STATE_DONE :
                                   GROUP_PMP_SQLITE_VFS_STATE_ERROR,
                      __ATOMIC_RELEASE);
    if (publish_ring &&
        (task.request.reserved[0] & GROUP_PMP_SQLITE_STORE_RING) &&
        task.request.ring_slot < GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT) {
      const uint64_t ring_offset = GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(
          task.request.ring_slot);
      struct group_pmp_sqlite_vfs_ring_header* ring =
          reinterpret_cast<struct group_pmp_sqlite_vfs_ring_header*>(
              task.utm + ring_offset);
      if (ring_offset <= task.utm_size &&
          sizeof(*ring) <=
              task.utm_size - ring_offset &&
          ring->magic == GROUP_PMP_SQLITE_VFS_RING_MAGIC &&
          ring->version == GROUP_PMP_SQLITE_VFS_VERSION)
        sqlite_publish_ring_completion(ring, UINT64_C(1));
    }
    sqlite_gantt_trace().recordRequest(
        SQLITE_GANTT_REQUEST_COMPLETE, task.request,
        task.completion ? task.completion->trace_id : 0, result);
    if (notify && task.completion)
      task.completion->completeOne();
  }

  void publishBatch(std::vector<Task*>& tasks) {
    typedef std::shared_ptr<SqliteAsyncCompletion> CompletionPtr;
    std::map<CompletionPtr, uint64_t, std::owner_less<CompletionPtr> > counts;
    typedef std::pair<uintptr_t, uint64_t> RingKey;
    std::map<RingKey, std::pair<Task*, uint64_t> > ring_batches;
    const uint64_t publish_started = now_ns();
    for (size_t index = 0; index < tasks.size(); ++index) {
      publish(*tasks[index], tasks[index]->result, false, false);
      if (tasks[index]->completion)
        ++counts[tasks[index]->completion];
      if ((tasks[index]->request.reserved[0] &
           GROUP_PMP_SQLITE_STORE_RING) &&
          tasks[index]->request.ring_slot <
              GROUP_PMP_SQLITE_VFS_RING_SLOT_COUNT) {
        const RingKey key(reinterpret_cast<uintptr_t>(tasks[index]->utm),
                          tasks[index]->request.ring_slot);
        std::pair<Task*, uint64_t>& entry = ring_batches[key];
        if (!entry.first)
          entry.first = tasks[index];
        ++entry.second;
      }
    }
    /* Publish all descriptor statuses first, then advance each producer
     * ring's completion counter once for the entire Host batch. */
    for (std::map<RingKey, std::pair<Task*, uint64_t> >::iterator it =
             ring_batches.begin(); it != ring_batches.end(); ++it) {
      Task* task = it->second.first;
      const uint64_t ring_offset = GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(
          task->request.ring_slot);
      if (ring_offset <= task->utm_size &&
          sizeof(struct group_pmp_sqlite_vfs_ring_header) <=
              task->utm_size - ring_offset) {
        struct group_pmp_sqlite_vfs_ring_header* ring =
            reinterpret_cast<struct group_pmp_sqlite_vfs_ring_header*>(
                task->utm + ring_offset);
        if (ring->magic == GROUP_PMP_SQLITE_VFS_RING_MAGIC &&
            ring->version == GROUP_PMP_SQLITE_VFS_VERSION)
          sqlite_publish_ring_completion(ring, it->second.second);
      }
    }
    std::atomic_thread_fence(std::memory_order_release);
    const uint64_t published = now_ns();
    completion_publish_ns_.fetch_add(published - publish_started,
                                     std::memory_order_relaxed);
    for (size_t index = 0; index < tasks.size(); ++index) {
      tasks[index]->publish_ns = published;
      if (tasks[index]->io_complete_ns &&
          published >= tasks[index]->io_complete_ns)
        io_complete_to_publish_ns_.fetch_add(
            published - tasks[index]->io_complete_ns,
            std::memory_order_relaxed);
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_COMPLETION_PUBLISH, tasks[index]->request,
          tasks[index]->completion ? tasks[index]->completion->trace_id : 0,
          tasks[index]->result, tasks.size(), published);
    }
    const uint64_t wakeup_started = now_ns();
    std::vector<CompletionPtr> ready;
    for (std::map<CompletionPtr, uint64_t,
                  std::owner_less<CompletionPtr> >::iterator it =
             counts.begin(); it != counts.end(); ++it)
      if (it->first->markCompleteMany(it->second))
        ready.push_back(it->first);
    /* Queue every completion before flushing the wake batch. The runner turns
     * this into one ioctl and at most one IPI per lane, so the storage thread
     * no longer serializes one userspace/kernel/SBI round trip per enclave. */
    std::vector<CompletionPtr> wake_ready;
    for (size_t index = 0; index < ready.size(); ++index) {
      const auto completion = ready[index];
      completion->collectReadyWaiters(ready);
    }
    uint64_t lanes = 0;
    for (const auto& completion : ready) {
      std::lock_guard<std::mutex> lock(completion->mutex);
      if (!completion->wakeup || completion->wakeup_invoked) continue;
      wake_ready.push_back(completion);
      if (completion->wakeup_lane < 64) lanes |= UINT64_C(1) << completion->wakeup_lane;
    }
    if (!wake_ready.empty()) {
      unsigned lane_count = 0;
      for (; lanes; lanes &= lanes - 1) ++lane_count;
      pipeline_perf_[SQLITE_PIPELINE_WAKE_FLUSH_BATCHES].fetch_add(1);
      pipeline_perf_[SQLITE_PIPELINE_WAKE_LANES].fetch_add(lane_count);
    }
    for (size_t index = 0; index < wake_ready.size(); ++index)
      wake_ready[index]->invoke(index + 1 < wake_ready.size());
    const uint64_t callback_ns = now_ns() - wakeup_started;
    wakeup_ns_.fetch_add(callback_ns, std::memory_order_relaxed);
    pipeline_perf_[SQLITE_PIPELINE_WAKE_CALLBACK_NS].fetch_add(callback_ns);
  }

  bool resolve_reads(std::vector<Task*>& tasks) {
    if (std::none_of(tasks.begin(), tasks.end(), [](const Task* t) {
          return t->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ && !t->result;
        })) return true;
    const uint64_t lock_started = now_ns();
    std::lock_guard<std::mutex> lock(database_mutex_);
    pipeline_perf_[SQLITE_PIPELINE_METADATA_LOOKUP_LOCK_NS].fetch_add(now_ns() - lock_started);
    const auto cpu_ns = []() -> uint64_t {
#ifdef __linux__
      struct timespec ts = {};
      if (!clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts))
        return static_cast<uint64_t>(ts.tv_sec) * UINT64_C(1000000000) + ts.tv_nsec;
#endif
      return 0;
    };
    const uint64_t cpu_started = cpu_ns();
    if (!ensure_database_locked() || !step_control_statement(read_begin_statement_)) return false;
    bool ok = true;
    size_t cursor = 0;
    while (ok && cursor < tasks.size()) {
      std::array<Task*, kMetadataReadBatch> batch{};
      std::array<bool, kMetadataReadBatch> seen{};
      size_t count = 0;
      while (cursor < tasks.size() && count < batch.size()) {
        Task* t = tasks[cursor++];
        if (t->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ && !t->result)
          batch[count++] = t;
      }
      if (!count) continue;
      sqlite3_reset(read_statement_);
      sqlite3_clear_bindings(read_statement_);
      for (size_t i = 0; i < count; ++i) {
        const auto& r = batch[i]->request;
        const uint64_t keys[] = {r.run_id, r.worker_index, r.workload, r.reserved[1]};
        for (size_t key = 0; key < 4; ++key)
          ok = (sqlite3_bind_int64(read_statement_, static_cast<int>(i * 4 + key + 1), keys[key]) == SQLITE_OK) && ok;
      }
      int result = SQLITE_DONE;
      size_t rows = 0;
      while (ok && (result = sqlite3_step(read_statement_)) == SQLITE_ROW) {
        const int slot = sqlite3_column_int(read_statement_, 0);
        if (slot < 0 || static_cast<size_t>(slot) >= count || seen[slot]) { ok = false; break; }
        seen[slot] = true; ++rows;
        Task& task = *batch[slot];
        if (sqlite3_column_type(read_statement_, 1) == SQLITE_NULL ||
            sqlite3_column_bytes(read_statement_, 7) != 16) {
          task.result = -ENOENT; continue;
        }
        const uint64_t task_id = static_cast<uint64_t>(sqlite3_column_int64(read_statement_, 1));
        task.stored_file_id = static_cast<uint64_t>(sqlite3_column_int64(read_statement_, 2));
        task.storage_offset = static_cast<uint64_t>(sqlite3_column_int64(read_statement_, 3));
        task.storage_length = static_cast<uint64_t>(sqlite3_column_int64(read_statement_, 4));
        const uint64_t logical_size = static_cast<uint64_t>(sqlite3_column_int64(read_statement_, 5));
        task.stored_sequence = static_cast<uint64_t>(sqlite3_column_int64(read_statement_, 6));
        const void* tag = sqlite3_column_blob(read_statement_, 7);
        if (task_id != task.request.task_id || task.storage_length != task.request.length ||
            logical_size != task.request.logical_size || !tag) {
          task.result = -ESTALE; continue;
        }
        std::memcpy(task.stored_tag, tag, sizeof(task.stored_tag));
      }
      ok = ok && result == SQLITE_DONE && rows == count;
      pipeline_perf_[SQLITE_PIPELINE_METADATA_LOOKUP_BATCHES].fetch_add(1);
      pipeline_perf_[SQLITE_PIPELINE_METADATA_LOOKUP_ROWS].fetch_add(rows);
    }
    sqlite3_reset(read_statement_);
    sqlite3_clear_bindings(read_statement_);
    if (ok) ok = step_control_statement(commit_statement_);
    if (!ok) (void)step_control_statement(rollback_statement_);
    pipeline_perf_[SQLITE_PIPELINE_METADATA_LOOKUP_CPU_NS].fetch_add(cpu_ns() - cpu_started);
    return ok;
  }

  bool commit_writes(const std::vector<Task*>& tasks) {
    const bool adaptive_random = pipeline_mode() && !tasks.empty() &&
        std::all_of(tasks.begin(), tasks.end(), [](const Task* task) {
          return task->request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE &&
              random_write_workload(task->request.workload);
        });
    const uint64_t order_started = now_ns();
    std::vector<Task*> ordered = tasks;
    std::sort(ordered.begin(), ordered.end(), [adaptive_random](const Task* left,
                                                  const Task* right) {
      if (adaptive_random) {
        // Reorder independent metadata keys only, after their data CQEs.
        // Sequence order within a key still determines the final row.
        const auto a = std::make_tuple(left->request.run_id, left->request.worker_index,
            left->request.workload, left->request.reserved[1]);
        const auto b = std::make_tuple(right->request.run_id, right->request.worker_index,
            right->request.workload, right->request.reserved[1]);
        if (a != b) return a < b;
      }
      if (!adaptive_random && left->request.file_id != right->request.file_id)
        return left->request.file_id < right->request.file_id;
      if (left->request.sequence != right->request.sequence)
        return left->request.sequence < right->request.sequence;
      return left->request.request_id < right->request.request_id;
    });
    pipeline_perf_[SQLITE_PIPELINE_METADATA_ORDER_NS].fetch_add(now_ns() - order_started);
    const uint64_t writer_lock_started = now_ns();
    std::unique_lock<std::mutex> lock(database_mutex_);
    writer_wait_ns_.fetch_add(now_ns() - writer_lock_started,
                              std::memory_order_relaxed);
    if (!ensure_database_locked())
      return false;
    if (adaptive_random && !adaptive_write_statement_ &&
        sqlite3_prepare_v2(db_,
          "INSERT INTO extent_index_v3 VALUES("
          "?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) "
          "ON CONFLICT(run_id,worker_index,workload,logical_offset) DO UPDATE SET "
          "worker_count=excluded.worker_count,task_id=excluded.task_id,"
          "file_id=excluded.file_id,file_offset=excluded.file_offset,"
          "cipher_length=excluded.cipher_length,logical_size=excluded.logical_size,"
          "sequence=excluded.sequence,tag=excluded.tag", -1,
          &adaptive_write_statement_, nullptr) != SQLITE_OK)
      return false;
    sqlite3_stmt* statement = adaptive_random ? adaptive_write_statement_ : write_statement_;
    const uint64_t sqlite_writer_started = now_ns();
    const bool transaction_started = step_control_statement(begin_statement_);
    writer_wait_ns_.fetch_add(now_ns() - sqlite_writer_started,
                              std::memory_order_relaxed);
    if (!transaction_started)
      return false;
    const uint64_t commit_started = now_ns();
    uint64_t rows = 0;
    for (size_t index = 0; index < ordered.size(); ++index) {
      Task& task = *ordered[index];
      if (task.request.operation != GROUP_PMP_SQLITE_VFS_OP_WRITE ||
          task.result != 0 || task.superseded)
        continue;
      sqlite3_reset(statement);
      sqlite3_clear_bindings(statement);
      sqlite3_bind_int64(statement, 1, task.request.run_id);
      sqlite3_bind_int64(statement, 2, task.request.worker_index);
      sqlite3_bind_int64(statement, 3, task.request.worker_count);
      sqlite3_bind_int64(statement, 4, task.request.workload);
      sqlite3_bind_int64(statement, 5, task.request.task_id);
      sqlite3_bind_int64(statement, 6, task.request.file_id);
      sqlite3_bind_int64(statement, 7, task.request.reserved[1]);
      sqlite3_bind_int64(statement, 8, task.request.file_offset);
      sqlite3_bind_int64(statement, 9, task.request.length);
      sqlite3_bind_int64(statement, 10, task.request.logical_size);
      sqlite3_bind_int64(statement, 11, task.request.sequence);
      sqlite3_bind_blob(statement, 12, task.request.tag,
                        sizeof(task.request.tag), SQLITE_TRANSIENT);
      const int result = sqlite3_step(statement);
      if (result != SQLITE_DONE) {
        sqlite3_reset(statement);
        (void)step_control_statement(rollback_statement_);
        return false;
      }
      ++rows;
    }
    const uint64_t flush_started = now_ns();
    pipeline_perf_[SQLITE_PIPELINE_METADATA_STEPS_NS].fetch_add(flush_started - commit_started);
    if (!step_control_statement(commit_statement_)) {
      (void)step_control_statement(rollback_statement_);
      return false;
    }
    commit_ns_.fetch_add(now_ns() - commit_started,
                         std::memory_order_relaxed);
    commit_count_.fetch_add(1, std::memory_order_relaxed);
    pipeline_perf_[SQLITE_PIPELINE_METADATA_FLUSH_NS].fetch_add(now_ns() - flush_started);
    if (adaptive_random) {
      pipeline_perf_[SQLITE_PIPELINE_METADATA_UPSERT_ROWS].fetch_add(rows);
      pipeline_perf_[SQLITE_PIPELINE_METADATA_UPSERT_TRANSACTIONS].fetch_add(1);
    }
    return true;
  }

#ifdef __linux__
  bool eliminate_fully_overwritten_writes(std::vector<Task*>& tasks) {
    const uint64_t started = now_ns();
    std::vector<Task*> writes;
    for (Task* task : tasks) {
      if (task->result || task->superseded ||
          task->request.operation != GROUP_PMP_SQLITE_VFS_OP_WRITE)
        continue;
      if (task->storage_offset > UINT64_MAX - task->storage_length) {
        task->result = -EOVERFLOW;
        continue;
      }
      writes.push_back(task);
    }
    if (writes.empty())
      return false;
    std::sort(writes.begin(), writes.end(), [](const Task* a, const Task* b) {
      if (a->stored_file_id != b->stored_file_id)
        return a->stored_file_id < b->stored_file_id;
      return a->storage_offset < b->storage_offset;
    });
    uint64_t checks = 0;
    bool had_overlap = false;
    for (size_t first = 0; first < writes.size();) {
      size_t last = first + 1;
      uint64_t end = writes[first]->storage_offset + writes[first]->storage_length;
      while (last < writes.size()) {
        ++checks;
        if (writes[last]->stored_file_id != writes[first]->stored_file_id ||
            writes[last]->storage_offset >= end)
          break;
        end = std::max(end, writes[last]->storage_offset + writes[last]->storage_length);
        ++last;
      }
      if (last - first > 1) {
        had_overlap = true;
        // Sequences are local to a worker. Cross-owner overlaps cannot be
        // collapsed by comparing unrelated sequence numbers.
        if (std::any_of(writes.begin() + first + 1, writes.begin() + last,
            [&](const Task* task) { return !same_write_owner(*writes[first], *task); })) {
          first = last;
          continue;
        }
        std::vector<Task*> by_sequence(writes.begin() + first, writes.begin() + last);
        std::vector<uint64_t> starts;
        for (size_t i = first; i < last; ++i)
          starts.push_back(writes[i]->storage_offset);
        std::sort(by_sequence.begin(), by_sequence.end(), [](const Task* a, const Task* b) {
          return a->request.sequence > b->request.sequence;
        });
        // Prefix maximum of interval ends, populated only by strictly newer
        // sequences. Disjoint intervals never allocate or query this tree.
        std::vector<uint64_t> max_end(starts.size() + 1, 0);
        for (size_t i = 0; i < by_sequence.size();) {
          size_t j = i + 1;
          while (j < by_sequence.size() && by_sequence[j]->request.sequence ==
                                             by_sequence[i]->request.sequence)
            ++j;
          for (size_t k = i; k < j; ++k) {
            Task& task = *by_sequence[k];
            size_t pos = std::upper_bound(starts.begin(), starts.end(),
                                         task.storage_offset) - starts.begin();
            uint64_t covering_end = 0;
            for (; pos; pos -= pos & -pos) {
              ++checks;
              covering_end = std::max(covering_end, max_end[pos]);
            }
            if (covering_end && covering_end >= task.storage_offset + task.storage_length) {
              task.superseded = true;
              task.io_length = 0;
              deduplicated_request_count_.fetch_add(1, std::memory_order_relaxed);
            }
          }
          for (size_t k = i; k < j; ++k) {
            const Task& task = *by_sequence[k];
            size_t pos = std::lower_bound(starts.begin(), starts.end(),
                                         task.storage_offset) - starts.begin() + 1;
            for (; pos < max_end.size(); pos += pos & -pos) {
              ++checks;
              max_end[pos] = std::max(max_end[pos], task.storage_offset + task.storage_length);
            }
          }
          i = j;
        }
      }
      first = last;
    }
    bool remaining_overlap = false;
    uint64_t file_id = 0, end = 0;
    bool have_range = false;
    for (const Task* task : writes) {
      if (task->superseded)
        continue;
      ++checks;
      if (have_range && task->stored_file_id == file_id && task->storage_offset < end)
        remaining_overlap = true;
      if (!have_range || task->stored_file_id != file_id)
        end = 0;
      have_range = true;
      file_id = task->stored_file_id;
      end = std::max(end, task->storage_offset + task->storage_length);
    }
    (had_overlap ? write_overlap_batches_ : write_disjoint_batches_).fetch_add(
        1, std::memory_order_relaxed);
    write_overlap_checks_.fetch_add(checks, std::memory_order_relaxed);
    write_overlap_check_ns_.fetch_add(now_ns() - started, std::memory_order_relaxed);
    return remaining_overlap;
  }

  bool has_overlapping_writes(const std::vector<Task*>& tasks) const {
    std::vector<const Task*> writes;
    for (size_t index = 0; index < tasks.size(); ++index)
      if (tasks[index]->result == 0 && !tasks[index]->superseded &&
          tasks[index]->request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE)
        writes.push_back(tasks[index]);
    std::sort(writes.begin(), writes.end(), [](const Task* left,
                                                const Task* right) {
      if (left->stored_file_id != right->stored_file_id)
        return left->stored_file_id < right->stored_file_id;
      if (left->storage_offset != right->storage_offset)
        return left->storage_offset < right->storage_offset;
      return left->request.sequence < right->request.sequence;
    });
    uint64_t file_id = 0;
    uint64_t covered_end = 0;
    bool have_range = false;
    for (size_t index = 0; index < writes.size(); ++index) {
      const uint64_t start = writes[index]->storage_offset;
      const uint64_t end = start + writes[index]->storage_length;
      if (end < start)
        return true;
      if (!have_range || writes[index]->stored_file_id != file_id) {
        file_id = writes[index]->stored_file_id;
        covered_end = end;
        have_range = true;
        continue;
      }
      if (start < covered_end)
        return true;
      covered_end = std::max(covered_end, end);
    }
    return false;
  }

  bool execute_ordered_writes(std::vector<Task*>& tasks) {
    const uint64_t sort_started = now_ns();
    std::vector<Task*> ordered = tasks;
    std::sort(ordered.begin(), ordered.end(), [](const Task* left,
                                                  const Task* right) {
      if (left->stored_file_id != right->stored_file_id)
        return left->stored_file_id < right->stored_file_id;
      if (left->request.sequence != right->request.sequence)
        return left->request.sequence < right->request.sequence;
      return left->request.request_id < right->request.request_id;
    });
    sort_ns_.fetch_add(now_ns() - sort_started, std::memory_order_relaxed);
    for (size_t left = 0; left < ordered.size(); ++left) {
      if (ordered[left]->result != 0)
        continue;
      const uint64_t left_start = ordered[left]->storage_offset;
      const uint64_t left_end = left_start + ordered[left]->storage_length;
      for (size_t right = left + 1; right < ordered.size(); ++right) {
        if (ordered[right]->stored_file_id != ordered[left]->stored_file_id)
          break;
        const uint64_t right_start = ordered[right]->storage_offset;
        const uint64_t right_end = right_start + ordered[right]->storage_length;
        if (left_start < right_end && right_start < left_end &&
            (!same_write_owner(*ordered[left], *ordered[right]) ||
             ordered[left]->request.sequence == ordered[right]->request.sequence)) {
          ordered[left]->result = -ESTALE;
          ordered[right]->result = -ESTALE;
        }
      }
    }
    uint64_t useful = 0;
    uint64_t physical = 0;
    const uint64_t io_started = now_ns();
    uint64_t requests = 0;
    for (size_t index = 0; index < ordered.size(); ++index) {
      Task& task = *ordered[index];
      if (task.result != 0 || task.superseded)
        continue;
      int fd = file_for(task.stored_file_id);
      uint64_t completed = 0;
      int result = 0;
      if (fd < 0) {
        result = -errno;
      } else {
        while (completed < task.storage_length) {
          ssize_t value;
          do {
            value = pwrite(fd, task.data() + completed,
                           static_cast<size_t>(task.storage_length - completed),
                           static_cast<off_t>(task.storage_offset + completed));
          } while (value < 0 && errno == EINTR);
          if (value <= 0) {
            result = value < 0 ? -errno : -EIO;
            break;
          }
          completed += static_cast<uint64_t>(value);
        }
      }
      task.result = result;
      requests++;
      useful += task.storage_length;
      physical += completed;
      sparse_io_count_.fetch_add(1, std::memory_order_relaxed);
      const uint64_t worker_mask = task.request.worker_index < 64 ?
          UINT64_C(1) << task.request.worker_index : 0;
      sqlite_io_range_trace().recordExtent(
          task.stored_file_id, task.storage_offset, task.storage_length,
          task.storage_length, false, 1, worker_mask,
          SQLITE_IO_RANGE_BACKEND_POSIX_VECTOR, result);
    }
    useful_io_bytes_.fetch_add(useful, std::memory_order_relaxed);
    physical_io_bytes_.fetch_add(physical, std::memory_order_relaxed);
    physical_request_count_.fetch_add(requests, std::memory_order_relaxed);
    disk_io_ns_.fetch_add(now_ns() - io_started, std::memory_order_relaxed);
    return true;
  }
#endif

  void finish_read_feedback(bool success) {
    if (!pending_read_feedback_)
      return;
    if (success && pending_read_bytes_) {
      const uint64_t elapsed = now_ns() - pending_read_started_;
      const size_t mode = pending_read_merged_ ? 1 : 0;
      read100k_[SQLITE_READ100K_DISCRETE_BATCHES + mode].fetch_add(1);
      read100k_[SQLITE_READ100K_DISCRETE_BYTES + mode].fetch_add(pending_read_bytes_);
      read100k_[SQLITE_READ100K_DISCRETE_SERVICE_NS + mode].fetch_add(elapsed);
      // Legacy non-reactor service counters are observational too.
    }
    pending_read_feedback_ = nullptr;
  }

  bool execute_io(std::vector<Task*>& tasks, bool defer_feedback = false
#ifdef __linux__
                  , PipelineBatch* pipeline = nullptr
#endif
                  ) {
#ifdef __linux__
    const bool read100k = adaptive_extent_mode() && !tasks.empty() &&
        tasks.front()->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ &&
        tasks.front()->request.workload == GROUP_PMP_SQLITE_READRAND100K;
    const uint64_t planning_service_started = read100k ? now_ns() : 0;
    const uint64_t sort_before = sort_ns_.load(std::memory_order_relaxed);
    const uint64_t cluster_before = cluster_ns_.load(std::memory_order_relaxed);
    const uint64_t release_order_before = pipeline_perf_[SQLITE_PIPELINE_RELEASE_ORDER_NS].load();
    const uint64_t scan_before = pipeline_perf_[SQLITE_PIPELINE_CANDIDATE_SCAN_NS].load();
    candidate_cost_ns_ = 0;
    const uint64_t request_build_started = now_ns();
    uint64_t logical_requests = 0;
    for (size_t index = 0; index < tasks.size(); ++index) {
      Task& task = *tasks[index];
      task.arrival_order = index;
      if (task.result == 0 &&
          (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
           task.request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE))
        logical_requests++;
      if (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE) {
        task.stored_file_id = task.request.file_id;
        task.storage_offset = task.request.file_offset;
        task.storage_length = task.request.length;
        task.io_offset = task.storage_offset;
        task.io_length = task.storage_length;
        task.data_offset = 0;
        invalidate_file_cache(task.stored_file_id);
      } else if (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_READ &&
                 task.result == 0) {
        apply_read_cache(task);
        if (task.request.workload == GROUP_PMP_SQLITE_READSEQ) {
          const uint64_t flags = task.request.reserved[0];
          if (flags & GROUP_PMP_SQLITE_READSEQ_INITIAL)
            readseq_initial_requests_.fetch_add(1, std::memory_order_relaxed);
          else if (flags & GROUP_PMP_SQLITE_READSEQ_PEER_IO)
            readseq_refill_peer_io_requests_.fetch_add(1, std::memory_order_relaxed);
          else if (flags & GROUP_PMP_SQLITE_READSEQ_PEER_READY)
            readseq_refill_peer_ready_requests_.fetch_add(1, std::memory_order_relaxed);
          else if (flags & GROUP_PMP_SQLITE_READSEQ_PEER_IDLE)
            readseq_refill_peer_idle_requests_.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }
    logical_request_count_.fetch_add(logical_requests,
                                     std::memory_order_relaxed);
    pipeline_perf_[SQLITE_PIPELINE_REQUEST_BUILD_NS].fetch_add(now_ns() - request_build_started);
    const uint64_t calibrated_operation = tasks.empty() ? 0 : tasks.front()->request.operation;
    const bool calibration_skips_cluster = adaptive_extent_mode() && merge_calibrated_ &&
        !tasks.empty() &&
        !calibrated_saved_ns_[calibrated_operation == GROUP_PMP_SQLITE_VFS_OP_READ][0] &&
        !calibrated_saved_ns_[calibrated_operation == GROUP_PMP_SQLITE_VFS_OP_READ][1] &&
        std::all_of(tasks.begin(), tasks.end(), [calibrated_operation](const Task* task) {
          const IoPlanningPolicy policy = planning_policy(*task);
          return task->request.operation == calibrated_operation &&
              (policy == IoPlanningPolicy::kRandomReadClustered ||
                  policy == IoPlanningPolicy::kRandomWriteBatch) &&
              task->request.length == 4096 && (task->result || task->io_length == 4096);
        });
    if (calibration_skips_cluster) {
      pipeline_perf_[SQLITE_PIPELINE_CALIBRATION_SKIPPED_BATCHES].fetch_add(1);
      pipeline_perf_[SQLITE_PIPELINE_CALIBRATION_SKIPPED_REQUESTS].fetch_add(logical_requests);
      random_sparse_fast_batches_.fetch_add(1, std::memory_order_relaxed);
      random_sparse_fast_requests_.fetch_add(logical_requests, std::memory_order_relaxed);
    }
    const bool random_batch = adaptive_extent_mode() && !calibration_skips_cluster && !tasks.empty() &&
        (tasks.front()->request.workload == GROUP_PMP_SQLITE_READRANDOM ||
         random_write_workload(tasks.front()->request.workload));
    const bool cross_worker_plan = adaptive_extent_mode() && !calibration_skips_cluster && spans_workers(tasks);
    if (cross_worker_plan) {
      pipeline_perf_[SQLITE_PIPELINE_CROSS_WORKER_PLAN_BATCHES].fetch_add(1);
      pipeline_perf_[SQLITE_PIPELINE_CROSS_WORKER_PLAN_REQUESTS].fetch_add(logical_requests);
    }
    bool sparse_batch = calibration_skips_cluster;
    bool local_plan = false;
    auto& candidates = candidate_scratch_;
    auto& isolated = isolated_scratch_;
    auto& ordered = ordered_scratch_;
    candidates.clear(); isolated.clear(); ordered.clear();
    bool directly_ordered = false;
    size_t planned_count = 0;
    if (adaptive_extent_mode() && !tasks.empty() &&
        planning_policy(*tasks.front()) == IoPlanningPolicy::kSequentialContiguous) {
      // Sequential admission is small (normally <=16 descriptors). Identify
      // actual touching/overlapping peers before sorting, with bounded work.
      const uint64_t started = now_ns();
      size_t checks = 0;
      bool valid = tasks.size() <= kHostBatchExtents;
      std::array<bool, kHostBatchExtents> local{};
      for (size_t i = 0; valid && i < tasks.size(); ++i) {
        const Task& a = *tasks[i];
        if (!a.io_length || a.result || a.io_length > UINT64_MAX - a.io_offset) {
          valid = false;
          break;
        }
        for (size_t j = 0; j < i; ++j) {
          if (++checks > 4096) { valid = false; break; }
          const Task& b = *tasks[j];
          if (a.stored_file_id == b.stored_file_id && a.request.operation == b.request.operation &&
              a.io_offset <= b.io_offset + b.io_length && b.io_offset <= a.io_offset + a.io_length)
            local[i] = local[j] = true;
        }
      }
      if (valid) {
        for (size_t i = 0; i < tasks.size(); ++i)
          (local[i] ? candidates : isolated).push_back(tasks[i]);
        local_plan = true;
        sparse_batch = candidates.empty();
      }
      pipeline_perf_[SQLITE_PIPELINE_CANDIDATE_SCAN_NS].fetch_add(now_ns() - started);
    }
    if (random_batch || read100k) {
      const uint64_t started = now_ns();
      uint64_t checks = 0;
      directly_ordered = random_batch && sparse_precheck_.order_pages(
          tasks, &checks, &ordered, &planned_count);
      const auto result = directly_ordered ? (planned_count ? SparsePagePrecheck::kCandidate :
          SparsePagePrecheck::kSparse) : read100k ? sparse_precheck_.inspect_intervals(
          tasks, &checks, &candidates, &isolated) : sparse_precheck_.inspect(
          tasks, read_amplification_permille_, &checks, &candidates, &isolated);
      const uint64_t elapsed = now_ns() - started;
      random_precheck_ns_.fetch_add(elapsed, std::memory_order_relaxed);
      pipeline_perf_[SQLITE_PIPELINE_CANDIDATE_SCAN_NS].fetch_add(elapsed);
      sparse_batch = result == SparsePagePrecheck::kSparse;
      local_plan = result != SparsePagePrecheck::kInconclusive;
      (sparse_batch ? random_sparse_fast_batches_ : random_planned_batches_)
          .fetch_add(1, std::memory_order_relaxed);
      if (result == SparsePagePrecheck::kInconclusive)
        random_precheck_fallbacks_.fetch_add(1, std::memory_order_relaxed);
      if (local_plan) {
        const size_t candidate_count = directly_ordered ? planned_count : candidates.size();
        const size_t isolated_count = directly_ordered ? tasks.size() - planned_count : isolated.size();
        random_sparse_fast_requests_.fetch_add(isolated_count, std::memory_order_relaxed);
        random_local_candidate_requests_.fetch_add(candidate_count, std::memory_order_relaxed);
        if (cross_worker_plan)
          pipeline_perf_[SQLITE_PIPELINE_CROSS_WORKER_CANDIDATE_REQUESTS].fetch_add(candidate_count);
        if (candidate_count && isolated_count)
          random_local_plan_batches_.fetch_add(1, std::memory_order_relaxed);
      }
    }
    // The same legality check applies to both modes, independently of clustering.
    const bool overlapping_writes = eliminate_fully_overwritten_writes(tasks);
    /* io_uring may complete independent SQEs out of order. If write ranges
     * overlap, execute the batch by authenticated sequence instead so a later
     * ciphertext version can never be overwritten by an older completion. */
    if (overlapping_writes) {
      return execute_ordered_writes(tasks);
    }
    const std::vector<Task*>& plan = local_plan ? candidates : tasks;
    if (!directly_ordered) ordered.clear();
    for (size_t index = 0; !directly_ordered && index < plan.size(); ++index) {
      Task& task = *plan[index];
      if (local_plan && overlapping_writes)
        continue;
      if (task.result != 0 || task.superseded)
        continue;
      ordered.push_back(&task);
    }
    if (adaptive_extent_mode() && !sparse_batch && !directly_ordered) {
      const uint64_t sort_started = now_ns();
      std::sort(ordered.begin(), ordered.end(), [](const Task* left,
                                                  const Task* right) {
        if (left->stored_file_id != right->stored_file_id)
          return left->stored_file_id < right->stored_file_id;
        if (left->request.operation != right->request.operation)
          return left->request.operation < right->request.operation;
        if (left->io_offset != right->io_offset)
          return left->io_offset < right->io_offset;
        return left->io_length < right->io_length;
      });
      sort_ns_.fetch_add(now_ns() - sort_started, std::memory_order_relaxed);
    }
    if (!directly_ordered) planned_count = calibration_skips_cluster ? 0 : ordered.size();
    if (local_plan && !directly_ordered)
      ordered.insert(ordered.end(), isolated.begin(), isolated.end());
    if (adaptive_extent_mode() && planned_count)
      candidate_cost_ns_ = (pipeline_perf_[SQLITE_PIPELINE_CANDIDATE_SCAN_NS].load() - scan_before +
          sort_ns_.load(std::memory_order_relaxed) - sort_before) / planned_count;

    ReadMergeFeedback* read_feedback = nullptr;
    if (read100k && !pipeline) {
      bool candidate = false, overlap = false;
      // Record candidate exposure without delaying the first legal merge.
      for (size_t i = 1; i < planned_count; ++i) {
        Task* left = ordered[i - 1];
        Task* right = ordered[i];
        if (left->io_length && right->io_length &&
            left->io_offset <= UINT64_MAX - left->io_length &&
            right->io_offset <= UINT64_MAX - right->io_length &&
            left->stored_file_id == right->stored_file_id &&
            same_planning_scope(*left, *right) &&
            right->io_offset <= left->io_offset + left->io_length &&
            std::max(left->io_offset + left->io_length,
                     right->io_offset + right->io_length) - left->io_offset <= merge_limit_) {
          candidate = true;
          overlap = overlap || right->io_offset < left->io_offset + left->io_length;
          left->merge_feedback_candidate = right->merge_feedback_candidate = true;
        }
      }
      if (candidate) {
        read_feedback = &read_merge_feedback_[read_merge_class(0, 0, 0, overlap)];
        // Legacy service observations are retained but never gate admission.
        read_feedback->merging = true;
      }
    }

    if (pipeline && pipeline->online_feedback) {
      for (size_t i = 1; i < planned_count; ++i) {
        Task& a = *ordered[i - 1];
        Task& b = *ordered[i];
        if (!a.io_length || !b.io_length || a.stored_file_id != b.stored_file_id ||
            !same_planning_scope(a, b) || a.request.operation != b.request.operation ||
            a.io_offset > UINT64_MAX - a.io_length || b.io_offset > UINT64_MAX - b.io_length ||
            b.io_offset > a.io_offset + a.io_length ||
            (a.request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE &&
             b.io_offset != a.io_offset + a.io_length) ||
            std::max(a.io_offset + a.io_length, b.io_offset + b.io_length) - a.io_offset > merge_limit_)
          continue;
        a.online_candidate = b.online_candidate = true;
      }
    }
    // Algorithm 2 produces only join bits. Common representation construction
    // below is measured in both modes, including isolated FIXED operations.
    auto& joins = join_scratch_;
    joins.assign(ordered.size(), 0);
    uint64_t savings = 0;
    if (adaptive_extent_mode() && !calibration_skips_cluster) {
      const uint64_t cluster_started = now_ns();
      IoGroup summary;
      size_t members = 0;
      for (size_t i = 0; i < planned_count; ++i) {
        Task* task = ordered[i];
        if (task->result || task->superseded || !task->io_length ||
            task->io_offset > UINT64_MAX - task->io_length) continue;
        const uint64_t start = task->io_offset, end = start + task->io_length;
        const auto policy = planning_policy(*task);
        const bool read = task->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ;
        const uint64_t union_end = std::max(summary.end, end);
        uint64_t gap = 0;
        if (members && read100k && start <= summary.end &&
            summary.tasks.front()->completion != task->completion)
          pipeline_perf_[SQLITE_PIPELINE_READ100K_BUFFER_BOUNDARIES].fetch_add(1);
        const bool bucket = policy != IoPlanningPolicy::kRandomReadClustered ||
            start <= summary.end ||
            summary.offset / kRandomReadBucketBytes == start / kRandomReadBucketBytes;
        const bool append = members && same_planning_scope(*summary.tasks.front(), *task) &&
            summary.file_id == task->stored_file_id && summary.read == read &&
            summary.policy == policy && (read || start == summary.end) && bucket &&
            union_end - summary.offset <= merge_limit_ &&
            merge_within_budget(summary, *task, union_end, &gap, 1, members);
        if (append) {
          joins[i] = 1; ++savings;
          const Task& first = *summary.tasks.front();
          summary.fixed_layout = summary.fixed_layout && start == summary.end &&
              first.utm == task->utm && first.request.buffer_id == task->request.buffer_id &&
              reinterpret_cast<uintptr_t>(task->io_data()) ==
                  reinterpret_cast<uintptr_t>(first.io_data()) + summary.end - summary.offset;
          summary.independent_completions |= summary.tasks.front()->completion != task->completion;
          summary.overlapping |= read && start < summary.end;
          summary.spans_gap |= gap != 0;
          summary.gap_bytes += gap;
          summary.end = union_end;
          summary.useful_bytes += task->io_length;
          summary.release_floor_bytes = std::min(summary.release_floor_bytes, task->io_length);
          ++members;
        } else {
          summary = IoGroup();
          summary.tasks.push_back(task);
          summary.file_id = task->stored_file_id;
          summary.offset = start; summary.end = end; summary.read = read;
          summary.policy = policy;
          summary.useful_bytes = summary.release_floor_bytes = task->io_length;
          members = 1;
        }
      }
      cluster_ns_.fetch_add(now_ns() - cluster_started, std::memory_order_relaxed);
      pipeline_perf_[SQLITE_PIPELINE_CLUSTER_PLANNED_SAVINGS].fetch_add(savings);
      if (!cluster_merge_enabled())
        pipeline_perf_[SQLITE_PIPELINE_CLUSTER_PLAN_ONLY_BATCHES].fetch_add(1);
    }
    const uint64_t group_build_started = now_ns();
    const bool do_merge = cluster_merge_enabled();
    std::vector<IoGroup> groups;
    groups.reserve(ordered.size() - (do_merge ? savings : 0));
    uint64_t useful = 0, logical_useful = 0, physical = 0;
    for (size_t i = 0; i < ordered.size(); ++i) {
      Task* task = ordered[i];
      logical_useful += task->storage_length;
      if (task->result || task->superseded || !task->io_length) continue;
      if (task->io_offset > UINT64_MAX - task->io_length) {
        task->result = -EOVERFLOW; continue;
      }
      const uint64_t start = task->io_offset, end = start + task->io_length;
      const bool read = task->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ;
      const bool append = do_merge && joins[i] && !groups.empty();
      if (!append) {
        groups.emplace_back();
        IoGroup& group = groups.back();
        group.file_id = task->stored_file_id;
        group.fd = -1; group.offset = start; group.end = end;
        group.read = read; group.policy = planning_policy(*task);
        group.release_floor_bytes = task->io_length;
      }
      IoGroup& group = groups.back();
      if (append) {
        const Task* previous = group.tasks[group.tasks.size() - 1];
        group.fixed_layout = group.fixed_layout && start == group.end &&
            previous->utm == task->utm && previous->request.buffer_id == task->request.buffer_id &&
            reinterpret_cast<uintptr_t>(previous->io_data()) + previous->io_length ==
                reinterpret_cast<uintptr_t>(task->io_data());
        if (read && start == previous->io_offset && task->io_length == previous->io_length)
          deduplicated_request_count_.fetch_add(1, std::memory_order_relaxed);
        const uint64_t gap = start > group.end ? start - group.end : 0;
        group.overlapping |= read && start < group.end;
        group.spans_gap |= gap != 0;
        group.gap_bytes += gap;
        group.independent_completions |= group.tasks.front()->completion != task->completion;
        group.release_floor_bytes = std::min(group.release_floor_bytes, task->io_length);
        task->online_merged = group.tasks.front()->online_merged = true;
      }
      group.tasks.push_back(task);
      group.useful_bytes += task->io_length;
      group.end = std::max(group.end, end);
      useful += task->io_length;
    }
    pipeline_perf_[SQLITE_PIPELINE_GROUP_BUILD_NS].fetch_add(now_ns() - group_build_started);
    if (adaptive_extent_mode() && groups.size() > 1 && planned_count) {
      // Candidate discovery is offset-ordered, but submission must not push
      // an early buffer's isolated tail behind all later candidate groups.
      // Each group has a unique earliest member; rank/scatter is linear and
      // leaves the internal file/iovec order and write legality unchanged.
      const uint64_t started = now_ns();
      auto& ranks = release_order_scratch_;
      ranks.assign(tasks.size(), groups.size());
      for (size_t g = 0; g < groups.size(); ++g) {
        size_t first = tasks.size();
        for (const Task* t : groups[g].tasks) first = std::min(first, t->arrival_order);
        ranks[first] = g;
      }
      size_t count = 0;
      uint64_t moved = 0;
      for (size_t i = 0; i < ranks.size(); ++i) if (ranks[i] != groups.size()) {
        const size_t group = ranks[i];
        moved += group != count;
        ranks[count++] = group;
      }
      // Apply the gather permutation in place; no second group allocation.
      for (size_t i = 0; i < count; ++i) if (ranks[i] != i) {
        IoGroup saved = std::move(groups[i]);
        size_t at = i;
        while (ranks[at] != i) {
          const size_t from = ranks[at];
          groups[at] = std::move(groups[from]);
          ranks[at] = at;
          at = from;
        }
        groups[at] = std::move(saved);
        ranks[at] = at;
      }
      pipeline_perf_[SQLITE_PIPELINE_RELEASE_ORDER_MOVES].fetch_add(moved);
      pipeline_perf_[SQLITE_PIPELINE_RELEASE_ORDER_NS].fetch_add(now_ns() - started);
    }
    if (adaptive_extent_mode() && !ordered.empty() &&
        planning_policy(*ordered.front()) == IoPlanningPolicy::kSequentialContiguous) {
      (ordered.size() == 1 ? sequential_ready_single_batches_ :
          sequential_ready_multi_batches_).fetch_add(1, std::memory_order_relaxed);
      for (size_t i = 1; i < ordered.size(); ++i) {
        const Task& a = *ordered[i - 1]; const Task& b = *ordered[i];
        const bool adjacent = a.stored_file_id == b.stored_file_id &&
            a.request.operation == b.request.operation && a.io_offset <= UINT64_MAX - a.io_length &&
            a.io_offset + a.io_length == b.io_offset;
        (adjacent ? sequential_ready_adjacent_pairs_ : sequential_ready_nonadjacent_pairs_).fetch_add(1);
      }
    }
    if (adaptive_extent_mode() && planned_count) {
      const uint64_t planning = cluster_ns_.load(std::memory_order_relaxed) - cluster_before +
          pipeline_perf_[SQLITE_PIPELINE_RELEASE_ORDER_NS].load() - release_order_before;
      merge_plan_cost_ns_ = ewma_update(merge_plan_cost_ns_, planning / planned_count);
    }
    const uint64_t vector_started = now_ns();
    std::unique_lock<std::mutex> ring_lock(ring_mutex_);
    prepare_registered_buffers(tasks);
    for (size_t index = 0; index < groups.size(); ++index) {
      IoGroup& group = groups[index];
      const bool direct_requested =
          configured_cache_mode() == CacheMode::kDirect;
      bool direct_eligible = direct_requested &&
          !group.overlapping && !group.spans_gap &&
          (group.offset & UINT64_C(4095)) == 0 &&
          ((group.end - group.offset) & UINT64_C(4095)) == 0;
      for (size_t task = 0; direct_eligible && task < group.tasks.size();
           ++task)
        direct_eligible =
            (reinterpret_cast<uintptr_t>(group.tasks[task]->io_data()) &
             UINT64_C(4095)) == 0 &&
            (group.tasks[task]->io_length & UINT64_C(4095)) == 0;
      group.fd = file_for(group.file_id, direct_eligible);
      /* Exact 100 KB requests and final tails are not block aligned. Keep
       * those requests buffered but cold-cache them; aligned requests in the
       * same direct-mode run still use O_DIRECT. */
      group.direct_io = direct_eligible && group.fd >= 0;
      if (group.fd < 0 && direct_eligible) {
        group.fd = file_for(group.file_id, false);
        group.direct_io = false;
      }
      if (group.fd >= 0 && group.direct_io)
        direct_io_operations_.fetch_add(1, std::memory_order_relaxed);
      else if (group.fd >= 0 && direct_requested)
        direct_alignment_fallback_operations_.fetch_add(
            1, std::memory_order_relaxed);
#ifdef POSIX_FADV_WILLNEED
      if (group.fd >= 0 && group.read && !group.direct_io &&
          group.policy == IoPlanningPolicy::kSequentialContiguous)
        (void)posix_fadvise(group.fd, static_cast<off_t>(group.offset),
                            static_cast<off_t>(group.end - group.offset),
                            POSIX_FADV_WILLNEED);
#endif
      if (group.fd < 0) {
        for (size_t task = 0; task < group.tasks.size(); ++task)
          group.tasks[task]->result = -errno;
      }
    }
    /* Open every data file before registration so the first measured batch,
     * not only later batches, can address it through IOSQE_FIXED_FILE. */
    prepare_registered_files();
    std::vector<RawIoUring::Operation> operations;
    operations.reserve(groups.size());
    for (size_t index = 0; index < groups.size(); ++index) {
      IoGroup& group = groups[index];
      if (group.fd < 0)
        continue;
      if (group.read && (group.overlapping || group.spans_gap)) {
        const uint64_t span = group.end - group.offset;
        group.read_buffer.reset(new (std::nothrow) uint8_t[span]);
        if (!group.read_buffer) {
          for (size_t task = 0; task < group.tasks.size(); ++task)
            group.tasks[task]->result = -ENOMEM;
          group.fd = -1;
          continue;
        }
        if (security_scan_nonce())
          group.security_read_region.reset(new SecurityCipherRegion(group.read_buffer.get(), span));
        struct iovec vector;
        vector.iov_base = group.read_buffer.get();
        vector.iov_len = static_cast<size_t>(span);
        group.vectors.push_back(vector);
      } else {
        // Prove a single registered span before allocating a vector list.
        // Most local pairs share one UTM; allocating then folding throws that
        // list away. Cross-buffer groups still use their own stable iovecs.
        bool contiguous = !group.overlapping && !group.spans_gap && group.tasks.size() > 1;
        uintptr_t cursor = reinterpret_cast<uintptr_t>(group.tasks.front()->io_data());
        for (size_t task = 0; contiguous && task < group.tasks.size(); ++task) {
          const Task* child = group.tasks[task];
          if (reinterpret_cast<uintptr_t>(child->io_data()) != cursor ||
              child->io_length > UINTPTR_MAX - cursor) contiguous = false;
          else cursor += child->io_length;
        }
        if (contiguous) {
          group.vectors.push_back({group.tasks.front()->io_data(),
                                    static_cast<size_t>(group.end - group.offset)});
          if (fixed_buffer_for_vectors(group.vectors) < 0) group.vectors.clear();
        }
        if (group.vectors.empty()) {
          group.vectors.reserve(group.tasks.size());
          for (size_t task = 0; task < group.tasks.size(); ++task) {
          struct iovec vector;
          vector.iov_base = group.tasks[task]->io_data();
          vector.iov_len = static_cast<size_t>(
              group.tasks[task]->io_length);
          group.vectors.push_back(vector);
          }
        }
      }
      RawIoUring::Operation operation;
      operation.fd = group.fd;
      std::map<int, int>::const_iterator fixed_file =
          fixed_file_indices_.find(group.fd);
      if (fixed_file != fixed_file_indices_.end())
        operation.fixed_file_index = fixed_file->second;
      operation.fixed_buffer_index = fixed_buffer_for(group);
      if (operation.fixed_file_index >= 0)
        registered_file_operations_.fetch_add(1,
                                              std::memory_order_relaxed);
      if (vectors_use_registered_buffers(group))
        registered_buffer_operations_.fetch_add(1,
                                                std::memory_order_relaxed);
      if (operation.fixed_buffer_index >= 0)
        fixed_buffer_operations_.fetch_add(1,
                                           std::memory_order_relaxed);
      operation.offset = group.offset;
      operation.vectors = &group.vectors;
      operation.expected = group.end - group.offset;
      operation.read = group.read;
      operations.push_back(operation);
      physical += operation.expected;
      if (group.tasks.size() > 1)
        merged_io_count_.fetch_add(1, std::memory_order_relaxed);
      else
        sparse_io_count_.fetch_add(1, std::memory_order_relaxed);
    }
    pipeline_perf_[SQLITE_PIPELINE_VECTOR_PREPARE_NS].fetch_add(now_ns() - vector_started);
    if (!tasks.empty() && tasks.front()->request.workload == GROUP_PMP_SQLITE_READRAND100K)
      pipeline_perf_[SQLITE_PIPELINE_READ100K_VECTOR_PREPARATIONS].fetch_add(operations.size());
    if (useful && physical >
            useful * read_amplification_permille_ / UINT64_C(1000)) {
      for (size_t index = 0; index < ordered.size(); ++index)
        ordered[index]->result = -EIO;
      return false;
    }
    const bool measured_merge = std::any_of(groups.begin(), groups.end(),
        [](const IoGroup& group) { return group.tasks.size() > 1; });
    if (pipeline) {
      // Everything referenced by an SQE stays in this heap-owned plan; neither
      // the producer's stack nor the UTM ring descriptors are used as iovecs.
      pipeline->groups = std::move(groups);
      pipeline->operations = std::move(operations);
      pipeline->useful = useful;
      pipeline->feedback = read_feedback;
      pipeline->merged = measured_merge;
      pipeline->feedback_epoch = read_feedback ? read_feedback->epoch : 0;
      for (Task* task : tasks) task->pipeline_done = true;
      for (size_t i = 0; i < pipeline->groups.size(); ++i) {
        auto& group = pipeline->groups[i];
        if (group.fd < 0) continue;
        pipeline->operation_groups.push_back(i);
        for (Task* task : group.tasks) task->pipeline_done = false;
      }
      pipeline->remaining = pipeline->operations.size();
      useful_io_bytes_.fetch_add(logical_useful, std::memory_order_relaxed);
      physical_io_bytes_.fetch_add(physical, std::memory_order_relaxed);
      physical_request_count_.fetch_add(pipeline->operations.size(), std::memory_order_relaxed);
      return true;
    }
    std::vector<int> results;
    uint64_t ring_submit_ns = 0;
    uint64_t ring_completion_ns = 0;
    const uint64_t io_submit_at = now_ns();
    for (size_t index = 0; index < tasks.size(); ++index) {
      tasks[index]->io_submit_ns = io_submit_at;
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_IO_SUBMIT, tasks[index]->request,
          tasks[index]->completion ? tasks[index]->completion->trace_id : 0,
          0, operations.size(), io_submit_at);
    }
    bool submitted = operations.empty() || ring_.submit(
        operations, &results, &ring_submit_ns, &ring_completion_ns);
    submit_ns_.fetch_add(ring_submit_ns, std::memory_order_relaxed);
    /* io_uring_enter may perform buffered I/O inline. Starting this bucket
     * only after enter returned omitted most work on a hot/fast filesystem. */
    disk_io_ns_.fetch_add(ring_submit_ns + ring_completion_ns,
                          std::memory_order_relaxed);
    completion_wait_ns_.fetch_add(ring_completion_ns,
                                  std::memory_order_relaxed);
    if (submitted && !operations.empty())
      io_uring_submissions_.fetch_add(1, std::memory_order_relaxed);
    if (!submitted) {
      posix_fallback_operations_.fetch_add(
          operations.size(), std::memory_order_relaxed);
      const uint64_t fallback_started = now_ns();
      results.assign(operations.size(), -EIO);
      for (size_t index = 0; index < operations.size(); ++index) {
        ssize_t value;
        do {
          value = operations[index].read ?
              preadv(operations[index].fd,
                     operations[index].vectors->data(),
                     static_cast<int>(operations[index].vectors->size()),
                     static_cast<off_t>(operations[index].offset)) :
              pwritev(operations[index].fd,
                      operations[index].vectors->data(),
                      static_cast<int>(operations[index].vectors->size()),
                      static_cast<off_t>(operations[index].offset));
        } while (value < 0 && errno == EINTR);
        results[index] = value < 0 ? -errno : static_cast<int>(value);
      }
      disk_io_ns_.fetch_add(now_ns() - fallback_started,
                            std::memory_order_relaxed);
    }
    const uint64_t io_complete_at = now_ns();
    for (size_t index = 0; index < tasks.size(); ++index) {
      tasks[index]->io_complete_ns = io_complete_at;
      if (io_complete_at >= tasks[index]->io_submit_ns)
        io_submit_to_complete_ns_.fetch_add(
            io_complete_at - tasks[index]->io_submit_ns,
            std::memory_order_relaxed);
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_IO_COMPLETE, tasks[index]->request,
          tasks[index]->completion ? tasks[index]->completion->trace_id : 0,
          submitted ? 0 : -EIO, operations.size(), io_complete_at);
    }
    ring_lock.unlock();
    size_t operation_index = 0;
    for (size_t index = 0; index < groups.size(); ++index) {
      IoGroup& group = groups[index];
      if (group.fd < 0)
        continue;
      int result = results[operation_index++];
      uint64_t worker_mask = 0;
      for (size_t task = 0; task < group.tasks.size(); ++task)
        if (group.tasks[task]->request.worker_index < 64)
          worker_mask |= UINT64_C(1) <<
              group.tasks[task]->request.worker_index;
      const int expected = static_cast<int>(group.end - group.offset);
      const int trace_result = result == expected ? 0 :
          (result < 0 ? result : -EIO);
      if (trace_result == 0 &&
          group.policy == IoPlanningPolicy::kSequentialContiguous) {
        sequential_extent_count_.fetch_add(1, std::memory_order_relaxed);
        if (group.end - group.offset == kMaximumMergeLimit)
          sequential_8mb_extent_count_.fetch_add(1,
                                                std::memory_order_relaxed);
      }
      if (trace_result == 0 && worker_mask &&
          (worker_mask & (worker_mask - UINT64_C(1))))
        cross_worker_extent_count_.fetch_add(1, std::memory_order_relaxed);
      sqlite_io_range_trace().recordExtent(
          group.file_id, group.offset, group.end - group.offset,
          group.useful_bytes, group.read, group.tasks.size(), worker_mask,
          submitted ? SQLITE_IO_RANGE_BACKEND_IO_URING :
                      SQLITE_IO_RANGE_BACKEND_POSIX_VECTOR,
          trace_result);
      if (result == expected && group.read_buffer) {
        const uint64_t copy_started = now_ns();
        for (size_t task = 0; task < group.tasks.size(); ++task) {
          const uint64_t source_offset =
              group.tasks[task]->io_offset - group.offset;
          std::memcpy(group.tasks[task]->io_data(),
                      group.read_buffer.get() + source_offset,
                      static_cast<size_t>(group.tasks[task]->io_length));
        }
        const uint64_t copy_ns = now_ns() - copy_started;
        utm_copy_ns_.fetch_add(copy_ns, std::memory_order_relaxed);
        if (copy_ns && group.useful_bytes)
          copy_bandwidth_ = ewma_update(copy_bandwidth_,
              group.useful_bytes * UINT64_C(1000000000) / copy_ns);
      } else if (result != expected) {
        const int error = result < 0 ? result : -EIO;
        for (size_t task = 0; task < group.tasks.size(); ++task)
          group.tasks[task]->result = error;
      }
    }
    if (read_feedback && !operations.empty() &&
        std::all_of(tasks.begin(), tasks.end(), [](const Task* task) {
          return task->result == 0;
        })) {
      pending_read_feedback_ = read_feedback;
      pending_read_started_ = planning_service_started;
      pending_read_bytes_ = useful;
      pending_read_merged_ = measured_merge;
    }
    useful_io_bytes_.fetch_add(logical_useful, std::memory_order_relaxed);
    physical_io_bytes_.fetch_add(physical, std::memory_order_relaxed);
    physical_request_count_.fetch_add(operations.size(),
                                      std::memory_order_relaxed);
    /* Cache ownership is one entry per UTM buffer. Earlier entries from this
     * completed batch would immediately be overwritten by the last one. Keep
     * exactly that final entry without copying every 100 KB/2 MB payload. */
    std::set<CipherCacheKey> retained_buffers;
    for (size_t remaining = tasks.size(); remaining; --remaining) {
      const Task& task = *tasks[remaining - 1];
      if (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_READ &&
          task.result == 0 &&
          (task.request.workload == GROUP_PMP_SQLITE_READRAND100K ||
           (adaptive_extent_mode() &&
            task.request.workload == GROUP_PMP_SQLITE_READRANDOM)) &&
          retained_buffers.insert(cache_key(task)).second)
        update_read_cache(task);
    }
    for (size_t index = 0; index < tasks.size(); ++index)
      if (tasks[index]->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ &&
          tasks[index]->result == 0 &&
          !(adaptive_extent_mode() &&
            tasks[index]->request.workload == GROUP_PMP_SQLITE_READRANDOM) &&
          tasks[index]->request.workload != GROUP_PMP_SQLITE_READRAND100K &&
          tasks[index]->request.workload != GROUP_PMP_SQLITE_READSEQ)
        update_read_cache(*tasks[index]);
    if (!defer_feedback)
      finish_read_feedback(true); // Direct planner tests have no notification.
    return true;
#else
    (void)tasks;
    (void)defer_feedback;
    return false;
#endif
  }

  void process_data(std::vector<Task>& batch) {
    std::vector<Task*> tasks;
    uint64_t started = now_ns();
    bool has_read = false;
    bool has_write = false;
    for (size_t index = 0; index < batch.size(); ++index) {
      tasks.push_back(&batch[index]);
      has_read |= batch[index].request.operation == GROUP_PMP_SQLITE_VFS_OP_READ;
      has_write |= batch[index].request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE;
    }
    if (has_read)
      for (size_t index = 0; index < tasks.size(); ++index)
        if (tasks[index]->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ)
          sqlite_gantt_trace().recordRequest(
              SQLITE_GANTT_METADATA_LOOKUP_BEGIN, tasks[index]->request,
              tasks[index]->completion ? tasks[index]->completion->trace_id : 0);
    const bool reads_resolved = !has_read || resolve_reads(tasks);
    if (has_read)
      for (size_t index = 0; index < tasks.size(); ++index)
        if (tasks[index]->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ)
          sqlite_gantt_trace().recordRequest(
              SQLITE_GANTT_METADATA_LOOKUP_END, tasks[index]->request,
              tasks[index]->completion ? tasks[index]->completion->trace_id : 0,
              reads_resolved ? 0 : -EIO);
    if (has_read && !reads_resolved)
      for (size_t index = 0; index < tasks.size(); ++index)
        if (tasks[index]->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ)
          tasks[index]->result = -EIO;
    for (size_t index = 0; index < tasks.size(); ++index)
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_STORAGE_IO_BEGIN, tasks[index]->request,
          tasks[index]->completion ? tasks[index]->completion->trace_id : 0);
    const bool io_complete = execute_io(tasks, true);
    for (size_t index = 0; index < tasks.size(); ++index)
      if (tasks[index]->dequeue_ns && tasks[index]->io_submit_ns >=
              tasks[index]->dequeue_ns)
        host_dequeue_to_io_submit_ns_.fetch_add(
            tasks[index]->io_submit_ns - tasks[index]->dequeue_ns,
            std::memory_order_relaxed);
    for (size_t index = 0; index < tasks.size(); ++index)
      sqlite_gantt_trace().recordRequest(
          SQLITE_GANTT_STORAGE_IO_END, tasks[index]->request,
          tasks[index]->completion ? tasks[index]->completion->trace_id : 0,
          io_complete ? tasks[index]->result : -EIO);
    if (!io_complete)
      for (size_t index = 0; index < tasks.size(); ++index)
        tasks[index]->result = -EIO;
    if (has_write)
      for (size_t index = 0; index < tasks.size(); ++index)
        if (tasks[index]->request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE)
          sqlite_gantt_trace().recordRequest(
              SQLITE_GANTT_METADATA_COMMIT_BEGIN, tasks[index]->request,
              tasks[index]->completion ? tasks[index]->completion->trace_id : 0);
    const bool writes_committed = !has_write || commit_writes(tasks);
    if (has_write)
      for (size_t index = 0; index < tasks.size(); ++index)
        if (tasks[index]->request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE)
          sqlite_gantt_trace().recordRequest(
              SQLITE_GANTT_METADATA_COMMIT_END, tasks[index]->request,
              tasks[index]->completion ? tasks[index]->completion->trace_id : 0,
              writes_committed ? 0 : -EIO);
    if (has_write && !writes_committed)
      for (size_t index = 0; index < tasks.size(); ++index)
        if (tasks[index]->request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE)
          tasks[index]->result = -EIO;
    const uint64_t elapsed = now_ns() - started;
    if (has_read)
      read_service_ns_.fetch_add(elapsed, std::memory_order_relaxed);
    if (has_write)
      write_service_ns_.fetch_add(elapsed, std::memory_order_relaxed);
    const uint64_t publish_started = now_ns();
    publishBatch(tasks);
    if (!tasks.empty())
      merge_completion_cost_ns_ = ewma_update(merge_completion_cost_ns_,
          (now_ns() - publish_started) / tasks.size());
    // Include cache admission, completion publication and its wake callback.
    // Never train on worker AES/runnable-queue time or on a failed request.
    finish_read_feedback(io_complete && std::all_of(tasks.begin(), tasks.end(),
        [](const Task* task) { return task->result == 0; }));
  }

  void process_control(Task& task) {
    uint64_t started = now_ns();
    int result = 0;
    if (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_SYNC ||
        task.request.operation == GROUP_PMP_SQLITE_VFS_OP_RESET ||
        task.request.operation == GROUP_PMP_SQLITE_VFS_OP_DELETE ||
        task.request.operation == GROUP_PMP_SQLITE_VFS_OP_TRUNCATE)
      invalidate_all_cache();
    {
      std::lock_guard<std::mutex> lock(database_mutex_);
      if (!ensure_database_locked()) {
        result = -EIO;
      } else if (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_RESET ||
                 task.request.operation == GROUP_PMP_SQLITE_VFS_OP_DELETE ||
                 task.request.operation == GROUP_PMP_SQLITE_VFS_OP_TRUNCATE) {
        sqlite3_reset(reset_statement_);
        sqlite3_clear_bindings(reset_statement_);
        sqlite3_bind_int64(reset_statement_, 1, task.request.run_id);
        sqlite3_bind_int64(reset_statement_, 2, task.request.worker_index);
        sqlite3_bind_int64(reset_statement_, 3, task.request.workload);
        if (sqlite3_step(reset_statement_) != SQLITE_DONE)
          result = -EIO;
        sqlite3_reset(reset_statement_);
      }
    }
#ifdef __linux__
    if (result == 0 && task.request.operation == GROUP_PMP_SQLITE_VFS_OP_SYNC) {
      const uint64_t sync_started = now_ns();
      for (std::map<uint64_t, int>::const_iterator it = files_.begin();
           it != files_.end(); ++it)
        if (fdatasync(it->second) != 0) {
          result = -errno;
          break;
        }
      storage_sync_ns_.fetch_add(now_ns() - sync_started,
                                 std::memory_order_relaxed);
    }
#endif
    task.storage_length = task.request.length;
    publish(task, result);
    control_service_ns_.fetch_add(now_ns() - started,
                                  std::memory_order_relaxed);
  }

  void process_controls(std::vector<Task>& batch) {
    if (batch.size() == 1 || batch[0].request.operation !=
            GROUP_PMP_SQLITE_VFS_OP_SYNC) {
      process_control(batch[0]);
      return;
    }

    const uint64_t started = now_ns();
    invalidate_all_cache();
    int result = 0;
    {
      std::lock_guard<std::mutex> lock(database_mutex_);
      if (!ensure_database_locked())
        result = -EIO;
    }
#ifdef __linux__
    if (result == 0) {
      const uint64_t sync_started = now_ns();
      for (std::map<uint64_t, int>::const_iterator it = files_.begin();
           it != files_.end(); ++it) {
        if (fdatasync(it->second) != 0) {
          result = -errno;
          break;
        }
      }
      storage_sync_ns_.fetch_add(now_ns() - sync_started,
                                 std::memory_order_relaxed);
    }
#endif
    std::vector<Task*> tasks;
    for (size_t index = 0; index < batch.size(); ++index) {
      batch[index].storage_length = batch[index].request.length;
      batch[index].result = result;
      tasks.push_back(&batch[index]);
    }
    publishBatch(tasks);
    control_service_ns_.fetch_add(now_ns() - started,
                                  std::memory_order_relaxed);
  }

  // Probe only the next complete, already-arrived buffer. The cell index avoids
  // sorting a sparse random batch just to discover there is nothing to join.
  size_t arrived_candidate_buffer(const std::vector<Task>& batch, size_t arrived) {
    if (batch.empty() || queue_.empty() || !arrived ||
        batch.size() >= kHostBatchExtents || !queue_.front().completion)
      return 0;
    const auto completion = queue_.front().completion;
    const size_t count = completion->remaining.load(std::memory_order_acquire);
    if (!count || count > GROUP_PMP_SQLITE_VFS_BATCH_MAX || count > arrived ||
        count > queue_.size() || count > kHostBatchExtents - batch.size()) return 0;
    for (size_t i = 0; i < count; ++i)
      if (queue_[i].completion != completion ||
          !same_planning_scope(batch.front(), queue_[i]) ||
          !same_write_owner(queue_.front(), queue_[i])) return 0;
    for (const Task& own : batch)
      if (own.request.worker_index == queue_.front().request.worker_index &&
          !same_write_owner(own, queue_.front())) return 0;

    const uint64_t started = now_ns();
    const uint64_t cell_bytes = batch.front().request.length <= 8192 ? 4096 : 128000;
    const size_t budget = 8 * kHostBatchExtents;
    struct Cell { uint64_t key; size_t task; int next; };
    std::array<int, 2048> heads;
    heads.fill(-1);
    std::vector<Cell> cells;
    cells.reserve(batch.size() * 2);
    size_t work = 0;
    bool limited = false, candidate = false;
    for (size_t i = 0; i < batch.size() && !limited; ++i) {
      const auto& r = batch[i].request;
      if (!r.length || r.length > UINT64_MAX - r.file_offset) continue;
      const uint64_t end = (r.file_offset + r.length) / cell_bytes;
      for (uint64_t cell = r.file_offset / cell_bytes; cell <= end; ++cell) {
        if (++work > budget) { limited = true; break; }
        const size_t bucket = cell & (heads.size() - 1);
        cells.push_back(Cell{cell, i, heads[bucket]});
        heads[bucket] = static_cast<int>(cells.size() - 1);
      }
    }
    for (size_t i = 0; i < count && !limited && !candidate; ++i) {
      const Task& peer = queue_[i];
      const auto& r = peer.request;
      if (!r.length || r.length > UINT64_MAX - r.file_offset) continue;
      const uint64_t end = r.file_offset + r.length;
      for (uint64_t cell = r.file_offset / cell_bytes; cell <= end / cell_bytes && !candidate; ++cell) {
        if (++work > budget) { limited = true; break; }
        for (int pos = heads[cell & (heads.size() - 1)]; pos >= 0; pos = cells[pos].next) {
          if (++work > budget) { limited = true; break; }
          if (cells[pos].key != cell) continue;
          const Task& own = batch[cells[pos].task];
          const uint64_t own_end = own.request.file_offset + own.request.length;
          const bool touching = own_end == r.file_offset || end == own.request.file_offset;
          const bool overlapping = own.request.file_offset < end && r.file_offset < own_end;
          const uint64_t span = std::max(end, own_end) - std::min(r.file_offset, own.request.file_offset);
          // Cross-owner overlapping writes must retain their original plan order.
          if (same_planning_scope(own, peer) && span <= merge_limit_ &&
              (touching || (overlapping && r.operation == GROUP_PMP_SQLITE_VFS_OP_READ))) {
            candidate = true;
            break;
          }
        }
      }
    }
    pipeline_perf_[SQLITE_PIPELINE_ARRIVED_PROBE_NS].fetch_add(now_ns() - started);
    pipeline_perf_[SQLITE_PIPELINE_ARRIVED_PROBE_CHECKS].fetch_add(work);
    if (limited) pipeline_perf_[SQLITE_PIPELINE_ARRIVED_PROBE_LIMITED].fetch_add(1);
    if (!candidate) pipeline_perf_[SQLITE_PIPELINE_ARRIVED_NO_CANDIDATE].fetch_add(1);
    return candidate ? count : 0;
  }

  std::vector<Task> take_adaptive_data_locked(size_t target, size_t arrived_limit) {
    std::vector<Task> batch;
    const Task first = queue_.front();
    const size_t arrived = std::min(arrived_limit, queue_.size());
    const size_t hard_limit = std::min<size_t>(kHostBatchExtents,
        target + GROUP_PMP_SQLITE_VFS_BATCH_MAX);
    std::shared_ptr<SqliteAsyncCompletion> boundary;
    struct Owner { bool seen = false; uint64_t run = 0; uint8_t* utm = nullptr; };
    std::array<Owner, 64> owners;
    while (batch.size() < arrived && batch.size() < hard_limit && !queue_.empty()) {
      const Task& task = queue_.front();
      if (!same_planning_scope(first, task) ||
          (batch.size() >= target && boundary && task.completion != boundary)) break;
      if (task.request.worker_index >= owners.size()) break;
      Owner& owner = owners[task.request.worker_index];
      if (owner.seen && (owner.run != task.request.run_id || owner.utm != task.utm)) break;
      owner.seen = true; owner.run = task.request.run_id; owner.utm = task.utm;
      batch.push_back(std::move(queue_.front()));
      queue_.pop_front();
      if (batch.size() == target) boundary = batch.back().completion;
    }
    // Identical arrived-prefix admission in Async and Adaptive. Clustering
    // may select neighbours inside this snapshot, never enlarge admission.
    return batch;
  }

  std::vector<Task> take_ready_batch_locked(size_t target, bool barrier = false,
                                           size_t arrived_limit = SIZE_MAX) {
    std::vector<Task> batch;
    if (queue_.empty())
      return batch;
    const Task first = queue_.front();
    const uint64_t operation = first.request.operation;
    const uint64_t file_id = first.request.file_id;
    const uint64_t run_id = first.request.run_id;
    const uint64_t workload = first.request.workload;
    const bool data = operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
        operation == GROUP_PMP_SQLITE_VFS_OP_WRITE;
    const bool batched_sync = operation == GROUP_PMP_SQLITE_VFS_OP_SYNC;
    const bool cross_worker = pipeline_mode() && data;
    if (cross_worker) return take_adaptive_data_locked(target, arrived_limit);
    std::shared_ptr<SqliteAsyncCompletion> boundary_completion;
    const size_t hard_limit = std::min<size_t>(
        kHostBatchExtents,
        target + static_cast<size_t>(GROUP_PMP_SQLITE_VFS_BATCH_MAX));
    std::deque<Task> retained;
    size_t examined = 0;
    while (!queue_.empty()) {
      if (examined++ >= arrived_limit) {
        while (!queue_.empty()) {
          retained.push_back(std::move(queue_.front()));
          queue_.pop_front();
        }
        break;
      }
      Task task(std::move(queue_.front()));
      queue_.pop_front();
      const bool compatible =
          task.request.operation == operation &&
          task.request.file_id == file_id &&
          (cross_worker ? same_planning_scope(first, task) : task.request.run_id == run_id) &&
          task.request.workload == workload;
      // Snapshot only already-arrived requests. Never skip over a control,
      // generation or operation boundary to find more merge candidates.
      if ((cross_worker || barrier) && !compatible) {
        retained.push_back(std::move(task));
        while (!queue_.empty()) {
          retained.push_back(std::move(queue_.front()));
          queue_.pop_front();
        }
        break;
      }
      if (compatible &&
          (batch.size() >= hard_limit ||
           (batch.size() >= target && boundary_completion &&
            task.completion != boundary_completion))) {
        retained.push_back(std::move(task));
        while (!queue_.empty()) {
          retained.push_back(std::move(queue_.front()));
          queue_.pop_front();
        }
        break;
      }
      if (compatible) {
        batch.push_back(std::move(task));
        if (batch.size() == target)
          boundary_completion = batch.back().completion;
      } else {
        retained.push_back(std::move(task));
      }
      if (!data && !batched_sync && !batch.empty()) {
        while (!queue_.empty()) {
          retained.push_back(std::move(queue_.front()));
          queue_.pop_front();
        }
        break;
      }
    }
    queue_.swap(retained);
    return batch;
  }

  void notify_reactor() {
#ifdef __linux__
    const uint64_t one = 1;
    ssize_t result;
    do { result = write(wake_fd_, &one, sizeof(one)); }
    while (result < 0 && errno == EINTR);
#endif
  }

#ifdef __linux__
  bool pipeline_compatible(const Task& first) const {
    if (pipeline_batches_.empty()) return true;
    const uint64_t op = first.request.operation;
    if (op != GROUP_PMP_SQLITE_VFS_OP_READ && op != GROUP_PMP_SQLITE_VFS_OP_WRITE)
      return false;
    for (const auto& batch : pipeline_batches_)
      if (batch->tasks.front()->request.operation != op) return false;
    return true;
  }

  bool pipeline_write_conflict(const std::vector<Task>& batch) const {
    if (batch.empty() || batch.front().request.operation != GROUP_PMP_SQLITE_VFS_OP_WRITE)
      return false;
    // Active plans reserve disjoint write intervals until their metadata is
    // committed. A later overlapping write cannot overtake an earlier plan.
    for (const Task& task : batch) {
      if (pipeline_write_keys_.count(std::make_tuple(task.request.run_id,
          task.request.worker_index, task.request.workload, task.request.reserved[1]))) return true;
      const uint64_t begin = task.request.file_offset;
      if (task.request.length > UINT64_MAX - begin) continue;
      const uint64_t end = begin + task.request.length;
      auto next = pipeline_write_ranges_.lower_bound({task.request.file_id, begin});
      if (next != pipeline_write_ranges_.end() && next->first.first == task.request.file_id &&
          next->first.second < end) return true;
      if (next != pipeline_write_ranges_.begin()) {
        --next;
        if (next->first.first == task.request.file_id && next->second > begin) return true;
      }
    }
    return false;
  }

  void pipeline_index_completions(PipelineBatch& plan) {
    if (plan.completion_indexed) return;
    plan.read100k_publication = !plan.tasks.empty() &&
        plan.tasks.front()->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ &&
        plan.tasks.front()->request.workload == GROUP_PMP_SQLITE_READRAND100K;
    pipeline_publication_dirty_ = true;
    for (Task* task : plan.tasks) {
      task->pipeline_owner = &plan;
      if (task->pipeline_published) continue;
      if (!task->completion) {
        if (task->pipeline_done) plan.unowned_ready.push_back(task);
        continue;
      }
      auto& buffer = plan.buffers[task->completion];
      buffer.owner = &plan;
      buffer.tasks.push_back(task);
      task->pipeline_pending = &buffer.pending;
      if (!task->pipeline_done) ++buffer.pending;
    }
    plan.completion_indexed = true;
    pipeline_perf_[SQLITE_PIPELINE_COMPLETION_INDEXED_TASKS].fetch_add(plan.tasks.size());
  }

  void pipeline_mark_done(Task& task) {
    if (task.pipeline_done) return;
    task.pipeline_done = true;
    PipelineBatch* plan = task.pipeline_owner;
    if (!plan || !plan->completion_indexed) return;
    pipeline_publication_dirty_ = true;
    if (task.completion) {
      if (!task.pipeline_pending || !*task.pipeline_pending)
        throw std::logic_error("SQLite buffer completion underflow");
      --*task.pipeline_pending;
    } else {
      plan->unowned_ready.push_back(&task);
    }
  }

  void pipeline_begin(std::vector<Task> batch, uint64_t selection_started = 0) {
    if (batch.empty()) return;
    online_execution_ = true;
    auto plan = std::make_shared<PipelineBatch>();
    plan->owned = std::move(batch);
    plan->started = now_ns();
    plan->online_started = selection_started ? selection_started : plan->started;
    if (adaptive_extent_mode() && std::all_of(plan->owned.begin(), plan->owned.end(),
        [](const Task& t) { return (t.request.reserved[0] & GROUP_PMP_SQLITE_STORE_MEASURED) != 0; })) {
      const Task& first = plan->owned.front();
      const uint64_t key = (first.request.operation << 32) |
          static_cast<uint64_t>(planning_policy(first));
      plan->online_feedback = &online_feedback_[key];
      plan->online_epoch = plan->online_feedback->epoch;
      plan->online_merge = plan->online_feedback->merging;
    }
    const bool read = plan->owned.front().request.operation == GROUP_PMP_SQLITE_VFS_OP_READ;
    for (auto& task : plan->owned) {
      task.pipeline_owner = plan.get();
      plan->tasks.push_back(&task);
      task.dequeue_ns = plan->started;
      const uint64_t wait = plan->started - task.enqueue_ns;
      queue_wait_ns_.fetch_add(wait);
      submit_to_host_dequeue_ns_.fetch_add(wait);
      atomic_update_max(max_queue_wait_ns_, wait);
      sqlite_gantt_trace().recordRequest(SQLITE_GANTT_QUEUE_SERVICE_BEGIN,
          task.request, task.completion ? task.completion->trace_id : 0,
          0, plan->owned.size(), plan->started);
      if (read) sqlite_gantt_trace().recordRequest(SQLITE_GANTT_METADATA_LOOKUP_BEGIN,
          task.request, task.completion ? task.completion->trace_id : 0);
    }
    const uint64_t lookup_started = now_ns();
    const bool resolved = !read || resolve_reads(plan->tasks);
    if (read) pipeline_perf_[SQLITE_PIPELINE_METADATA_LOOKUP_NS].fetch_add(now_ns() - lookup_started);
    for (Task* task : plan->tasks) {
      if (!resolved) task->result = -EIO;
      if (read) sqlite_gantt_trace().recordRequest(SQLITE_GANTT_METADATA_LOOKUP_END,
          task->request, task->completion ? task->completion->trace_id : 0,
          task->result);
      sqlite_gantt_trace().recordRequest(SQLITE_GANTT_STORAGE_IO_BEGIN,
          task->request, task->completion ? task->completion->trace_id : 0);
    }
    const bool ok = execute_io(plan->tasks, true, plan.get());
    plan->work_ns = now_ns() - plan->started;
    if (plan->feedback) {
      uint64_t remainder = plan->work_ns % plan->tasks.size();
      for (Task* task : plan->tasks) {
        task->merge_feedback_work_ns = plan->work_ns / plan->tasks.size() + (remainder ? 1 : 0);
        if (remainder) --remainder;
      }
    }
    plan->atomic_write_publish = !read && std::any_of(plan->tasks.begin(), plan->tasks.end(),
        [](const Task* task) { return task->superseded; });
    // Ordered conflicting writes are executed by the existing sequence-safe
    // path. It may have no asynchronous groups, but still needs publication.
    if (plan->groups.empty()) {
      for (Task* task : plan->tasks) {
        task->pipeline_done = true;
        if (!ok && !task->result) task->result = -EIO;
      }
    }
    for (const auto& group : plan->groups)
      if (!group.read && group.fd >= 0)
        pipeline_write_ranges_[{group.file_id, group.offset}] = group.end;
    if (!read)
      for (const Task* task : plan->tasks)
        pipeline_write_keys_.insert(std::make_tuple(task->request.run_id,
            task->request.worker_index, task->request.workload, task->request.reserved[1]));
    pipeline_index_completions(*plan);
    if (sqlite_gantt_trace().neighborDiagnostic()) {
      plan->diagnostic_id = next_diagnostic_plan_++;
      const uint64_t ready = now_ns();
      for (const Task* task : plan->tasks)
        if (!task->result) sqlite_gantt_trace().recordPlanned(SQLITE_GANTT_NEIGHBOR_PLAN_READY,
            task->request, task->completion ? task->completion->trace_id : 0,
            task->io_offset, task->io_length, plan->diagnostic_id, 0, ready);
    }
    pipeline_batches_.push_back(plan);
  }

  void pipeline_complete_group(const Flight& flight, int result, uint64_t completed,
                               bool record = true) {
    const uint64_t started = now_ns();
    auto& plan = *flight.batch;
    auto& group = plan.groups[plan.operation_groups[flight.operation]];
    const uint64_t length = group.end - group.offset;
    const int error = result == static_cast<int>(length) ? 0 : result < 0 ? result : -EIO;
    uint64_t workers = 0;
    for (Task* task : group.tasks) {
      pipeline_mark_done(*task);
      task->io_complete_ns = completed;
      if (error) task->result = error;
      if (task->request.worker_index < 64) workers |= UINT64_C(1) << task->request.worker_index;
      io_submit_to_complete_ns_.fetch_add(completed - task->io_submit_ns);
      sqlite_gantt_trace().recordRequest(SQLITE_GANTT_IO_COMPLETE, task->request,
          task->completion ? task->completion->trace_id : 0, error, 1, completed);
    }
    if (!error && group.read_buffer) {
      const uint64_t start = now_ns();
      for (Task* task : group.tasks)
        std::memcpy(task->io_data(), group.read_buffer.get() + task->io_offset - group.offset,
                    static_cast<size_t>(task->io_length));
      const uint64_t elapsed = now_ns() - start;
      utm_copy_ns_.fetch_add(elapsed);
      if (elapsed) copy_bandwidth_ = ewma_update(copy_bandwidth_,
          group.useful_bytes * UINT64_C(1000000000) / elapsed);
    }
    if (record && !error && group.policy == IoPlanningPolicy::kSequentialContiguous) {
      sequential_extent_count_.fetch_add(1);
      if (length == kMaximumMergeLimit) sequential_8mb_extent_count_.fetch_add(1);
    }
    if (record && !error && workers && (workers & (workers - 1))) cross_worker_extent_count_.fetch_add(1);
    if (record) sqlite_io_range_trace().recordExtent(group.file_id, group.offset, length,
        group.useful_bytes, group.read, group.tasks.size(), workers,
        SQLITE_IO_RANGE_BACKEND_IO_URING, error);
    --plan.remaining;
    inflight_bytes_ -= length;
    const uint64_t work = now_ns() - started;
    plan.work_ns += work;
    if (plan.feedback) {
      uint64_t remainder = work % group.tasks.size();
      for (Task* task : group.tasks) {
        task->merge_feedback_work_ns += work / group.tasks.size() + (remainder ? 1 : 0);
        if (remainder) --remainder;
      }
    }
  }

  void pipeline_complete(const Flight& flight, int result, uint64_t completed) {
    if (flight.followers.empty()) {
      pipeline_complete_group(flight, result, completed);
      return;
    }
    const auto& head = flight.batch->groups[flight.batch->operation_groups[flight.operation]];
    uint64_t length = head.end - head.offset, useful = head.useful_bytes, workers = 0;
    size_t members = head.tasks.size();
    for (const Task* task : head.tasks)
      if (task->request.worker_index < 64) workers |= UINT64_C(1) << task->request.worker_index;
    for (const auto& part : flight.followers) {
      const auto& group = part.batch->groups[part.batch->operation_groups[part.operation]];
      length += group.end - group.offset;
      useful += group.useful_bytes;
      members += group.tasks.size();
      for (const Task* task : group.tasks)
        if (task->request.worker_index < 64) workers |= UINT64_C(1) << task->request.worker_index;
    }
    const int error = result == static_cast<int>(length) ? 0 : result < 0 ? result : -EIO;
    pipeline_complete_group(flight, error ? error : static_cast<int>(head.end - head.offset), completed, false);
    for (const auto& part : flight.followers) {
      const auto& group = part.batch->groups[part.batch->operation_groups[part.operation]];
      pipeline_complete_group(part, error ? error : static_cast<int>(group.end - group.offset), completed, false);
    }
    if (!error && head.policy == IoPlanningPolicy::kSequentialContiguous) {
      sequential_extent_count_.fetch_add(1);
      if (length == kMaximumMergeLimit) sequential_8mb_extent_count_.fetch_add(1);
    }
    if (!error && workers && (workers & (workers - 1))) cross_worker_extent_count_.fetch_add(1);
    sqlite_io_range_trace().recordExtent(head.file_id, head.offset, length, useful,
        head.read, members, workers, SQLITE_IO_RANGE_BACKEND_IO_URING, error);
  }

  bool pipeline_has_pending() const {
    return std::any_of(pipeline_batches_.begin(), pipeline_batches_.end(),
        [](const std::shared_ptr<PipelineBatch>& plan) {
          return plan->next < plan->operations.size();
        });
  }

  void pipeline_note_sequential_peer(const RawIoUring::Operation& op, uint64_t file_id) {
    const uint64_t next_offset = op.offset + op.expected;
    for (const auto& plan : pipeline_batches_)
      for (size_t i = plan->next; i < plan->operations.size(); ++i) {
        const auto& group = plan->groups[plan->operation_groups[i]];
        if (group.file_id == file_id && group.read == op.read && group.offset == next_offset) {
          pipeline_perf_[SQLITE_PIPELINE_SEQ_PEER_READY_UNJOINED].fetch_add(1);
          return; // Ready, but byte/span/vector/direct-I/O eligibility prevented joining.
        }
      }
    for (const auto& item : flights_) {
      const auto& flight = item.second;
      if (flight.file_id == file_id && flight.read == op.read &&
          flight.offset <= next_offset && next_offset - flight.offset < flight.length) {
        pipeline_perf_[SQLITE_PIPELINE_SEQ_PEER_INFLIGHT].fetch_add(1);
        return;
      }
    }
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      for (const auto& task : queue_)
        if (task.request.file_id == file_id && task.request.file_offset == next_offset &&
            task.request.operation == (op.read ? GROUP_PMP_SQLITE_VFS_OP_READ : GROUP_PMP_SQLITE_VFS_OP_WRITE)) {
          pipeline_perf_[SQLITE_PIPELINE_SEQ_PEER_QUEUED].fetch_add(1);
          return;
        }
    }
    pipeline_perf_[SQLITE_PIPELINE_SEQ_PEER_ABSENT].fetch_add(1);
  }

  bool pipeline_refill() {
    // SQEs copy scalar fields at submit; vector payloads stay plan/flight-owned.
    // Reuse only the staging arrays, never memory referenced by in-flight SQEs.
    auto& operations = submission_operations_;
    auto& tokens = submission_tokens_;
    operations.clear(); tokens.clear();
    operations.reserve(pipeline_depth_.target); tokens.reserve(pipeline_depth_.target);
    PlannedBoundaryWindow boundaries;
    uint64_t boundary_started = 0;
    if (adaptive_extent_mode() && flights_.size() < pipeline_depth_.target) {
      for (const auto& plan : pipeline_batches_) {
        if (plan->next == plan->operations.size() || !PlannedBoundaryWindow::eligible(
              plan->groups[plan->operation_groups[plan->next]], *plan)) continue;
        if (!boundary_started) boundary_started = now_ns();
        boundaries.add(plan);
      }
      if (boundary_started)
        pipeline_perf_[SQLITE_PIPELINE_BOUNDARY_MATCH_NS].fetch_add(now_ns() - boundary_started);
      if (boundaries.size) {
        pipeline_perf_[SQLITE_PIPELINE_BOUNDARY_SNAPSHOTS].fetch_add(1);
        pipeline_perf_[SQLITE_PIPELINE_BOUNDARY_REFS].fetch_add(boundaries.size);
      }
    }
    const size_t old_inflight = flights_.size();
    bool byte_limited = false;
    while (flights_.size() < pipeline_depth_.target) {
        std::shared_ptr<PipelineBatch> plan;
        for (auto& candidate : pipeline_batches_) {
          if (candidate->next == candidate->operations.size()) continue;
          if (!plan) {
            plan = candidate;
            if (candidate->groups[
                candidate->operation_groups[candidate->next]].policy != IoPlanningPolicy::kSequentialContiguous)
              break; // Random and fixed Async retain the direct FIFO plan path.
            continue;
          }
          const auto& a = plan->groups[plan->operation_groups[plan->next]];
          const auto& b = candidate->groups[candidate->operation_groups[candidate->next]];
          if (a.policy == IoPlanningPolicy::kSequentialContiguous &&
              b.policy == a.policy && a.file_id == b.file_id && a.read == b.read && b.offset < a.offset)
            plan = candidate;
        }
        if (!plan) break;
        const size_t i = plan->next;
        auto op = plan->operations[i];
        if (!flights_.empty() && inflight_bytes_ + op.expected > pipeline_depth_.byte_limit) {
          byte_limited = true;
          break;
        }
        const uint64_t token = next_token_++;
        // The actual batch timestamp is assigned below, after planning.
        Flight flight{plan, i, 0};
        ++plan->next;
        const auto& head = plan->groups[plan->operation_groups[i]];
        // Inspect planned sequential boundaries and naturally stalled 100KB reads.
        // A run/plan head is not a file boundary. Move a disjoint neighbour
        // ahead of unrelated pending work, never mutate a submitted slot.
        if (boundaries.size > 1 && boundaries.probes < 64 &&
            PlannedBoundaryWindow::eligible(head, *plan) &&
            !head.overlapping && !head.spans_gap && !head.read_buffer) {
          const uint64_t lookup_start = now_ns();
          const uint64_t sequential_capacity = group_pmp_sqlite_io_chunk(
              head.tasks.front()->request.workload, configured_cache_mode() == CacheMode::kDirect);
          size_t checks = 0;
          IoGroup release_group;
          release_group.offset = head.offset; release_group.end = head.end;
          release_group.read = head.read; release_group.policy = head.policy;
          release_group.useful_bytes = head.useful_bytes;
          release_group.release_floor_bytes = head.release_floor_bytes ? head.release_floor_bytes : op.expected;
          release_group.independent_completions = head.independent_completions;
          bool joined;
          do {
            joined = false;
            for (size_t b = 0; b < boundaries.size && boundaries.probes < 64; ++b) {
              ++boundaries.probes;
              auto& other = boundaries.refs[b].plan;
              const size_t j = boundaries.refs[b].position;
              if (j < other->next || j >= other->operations.size()) continue;
              if (head.policy == IoPlanningPolicy::kReadRand100kAdjacent && other == plan) continue;
              const auto& next = other->operations[j];
              const auto& group = other->groups[other->operation_groups[j]];
              if (group.file_id != head.file_id || next.offset != op.offset + op.expected) continue;
              ++checks;
              if (group.policy != head.policy || group.file_id != head.file_id ||
                  !same_planning_scope(*head.tasks.front(), *group.tasks.front()) ||
                  group.read != head.read || next.fd != op.fd ||
                  group.direct_io != head.direct_io || next.offset != op.offset + op.expected ||
                  op.expected >= merge_limit_ || next.expected > merge_limit_ - op.expected ||
                  (!flights_.empty() && inflight_bytes_ + op.expected + next.expected > pipeline_depth_.byte_limit) ||
                  op.vectors->size() + next.vectors->size() > 1024) continue;
              bool crosses_dependency = false;
              if (!head.read) {
                for (size_t k = other->next; k < j; ++k) {
                  const auto& earlier = other->groups[other->operation_groups[k]];
                  if (earlier.file_id == group.file_id &&
                      earlier.offset < group.end && group.offset < earlier.end) {
                    crosses_dependency = true;
                    break;
                  }
                }
              }
              if (crosses_dependency) continue;
              if (release_group.tasks.empty()) release_group.tasks = head.tasks;
              // Cross-worker plans are allowed; the same worker must retain
              // its run and UTM identity even across separate plans.
              bool owner_conflict = false;
              for (const Task* a : release_group.tasks)
                for (const Task* b : group.tasks)
                  if (a->request.worker_index == b->request.worker_index &&
                      (a->request.run_id != b->request.run_id || a->utm != b->utm))
                    owner_conflict = true;
              if (owner_conflict) continue;
              for (Task* task : head.tasks) task->online_candidate = true;
              for (Task* task : group.tasks) task->online_candidate = true;
              Task release_peer = *group.tasks.front();
              release_peer.io_offset = next.offset;
              release_peer.io_length = group.release_floor_bytes ? group.release_floor_bytes : next.expected;
              const bool old_independent = release_group.independent_completions;
              release_group.independent_completions = old_independent || group.independent_completions;
              const bool within_budget = merge_within_budget(release_group, release_peer,
                  next.offset + next.expected, nullptr, group.tasks.size());
              release_group.independent_completions = old_independent;
              if (!within_budget) continue;
              if (!cluster_merge_enabled()) {
                // Dry-run the same boundary legality and release budget without
                // mutating pending operations or coupling their completion.
                pipeline_perf_[SQLITE_PIPELINE_BOUNDARY_DRY_CANDIDATES].fetch_add(1);
                continue;
              }
              for (Task* task : release_group.tasks) task->online_merged = true;
              for (Task* task : group.tasks) task->online_merged = true;
              const auto short_request = [sequential_capacity](const Task* task) {
                return task->io_length < sequential_capacity;
              };
              if (head.policy == IoPlanningPolicy::kSequentialContiguous &&
                  (std::any_of(release_group.tasks.begin(), release_group.tasks.end(), short_request) ||
                   std::any_of(group.tasks.begin(), group.tasks.end(), short_request)))
                pipeline_perf_[SQLITE_PIPELINE_SEQ_TAIL_JOINS].fetch_add(1);
              if (!flight.vectors) flight.vectors =
                  std::make_shared<InlineOneList<iovec> >(*op.vectors);
              flight.vectors->insert(flight.vectors->end(), next.vectors->begin(), next.vectors->end());
              op.vectors = flight.vectors.get();
              op.expected += next.expected;
              fold_contiguous_vectors(op.vectors, op.expected);
              op.fixed_buffer_index = fixed_buffer_for_vectors(*op.vectors);
              release_group.end = op.offset + op.expected;
              release_group.useful_bytes += group.useful_bytes;
              release_group.tasks.insert(release_group.tasks.end(),
                  group.tasks.begin(), group.tasks.end());
              release_group.independent_completions = old_independent || group.independent_completions ||
                  release_group.tasks.front()->completion != release_peer.completion;
              release_group.release_floor_bytes = std::min(
                  release_group.release_floor_bytes, release_peer.io_length);
              // A joined vector may span separately registered UTM buffers.
              // Use READV/WRITEV, not READ_FIXED with the first buffer index.
              if (op.fixed_buffer_index >= 0) fixed_buffer_operations_.fetch_sub(1);
              if (next.fixed_buffer_index >= 0) fixed_buffer_operations_.fetch_sub(1);
              op.fixed_buffer_index = -1;
              if (next.fixed_file_index >= 0) registered_file_operations_.fetch_sub(1);
              if (vectors_use_registered_buffers(group)) registered_buffer_operations_.fetch_sub(1);
              if (flight.followers.empty() && head.tasks.size() == 1) {
                sparse_io_count_.fetch_sub(1);
                merged_io_count_.fetch_add(1);
              }
              (group.tasks.size() > 1 ? merged_io_count_ : sparse_io_count_).fetch_sub(1);
              physical_request_count_.fetch_sub(1);
              if (group.direct_io) direct_io_operations_.fetch_sub(1);
              else if (configured_cache_mode() == CacheMode::kDirect) direct_alignment_fallback_operations_.fetch_sub(1);
              // Flight references are operation indices. Rotate only pending
              // entries, preserving the relative order of all skipped writes.
              // In-flight indices and the actual groups/UTM owners stay fixed.
              if (j != other->next) {
                std::rotate(other->operations.begin() + other->next,
                    other->operations.begin() + j, other->operations.begin() + j + 1);
                std::rotate(other->operation_groups.begin() + other->next,
                    other->operation_groups.begin() + j, other->operation_groups.begin() + j + 1);
                boundaries.rotated(other.get(), other->next, j);
                if (head.policy == IoPlanningPolicy::kSequentialContiguous)
                  pipeline_perf_[SQLITE_PIPELINE_SEQ_NONHEAD_JOINS].fetch_add(1);
              }
              flight.followers.emplace_back(other, other->next, 0);
              ++other->next;
              pipeline_perf_[SQLITE_PIPELINE_READY_EXTENT_JOINS].fetch_add(1);
              if (other != plan) pipeline_perf_[SQLITE_PIPELINE_BOUNDARY_CROSS_PLAN_JOINS].fetch_add(1);
              joined = true;
              break;
            }
          } while (joined && op.expected < merge_limit_);
          const uint64_t elapsed = now_ns() - lookup_start;
          pipeline_perf_[SQLITE_PIPELINE_BOUNDARY_MATCH_NS].fetch_add(elapsed);
          if (head.policy == IoPlanningPolicy::kSequentialContiguous) {
            pipeline_perf_[SQLITE_PIPELINE_SEQ_LOCAL_CHECKS].fetch_add(checks);
            pipeline_perf_[SQLITE_PIPELINE_SEQ_LOCAL_NS].fetch_add(elapsed);
          }
        }
        if (adaptive_extent_mode() && head.policy == IoPlanningPolicy::kSequentialContiguous &&
            op.expected < merge_limit_) pipeline_note_sequential_peer(op, head.file_id);
        flight.depth_epoch = pipeline_depth_.epoch;
        flight.file_id = head.file_id;
        flight.offset = op.offset;
        flight.length = op.expected;
        flight.read = op.read;
        flights_.emplace(token, std::move(flight));
        tokens.push_back(token);
        operations.push_back(op);
        inflight_bytes_ += op.expected;
    }
    const bool pending = pipeline_has_pending();
    const bool credit_limited = pending && !byte_limited && flights_.size() >= pipeline_depth_.target;
    if (boundaries.probes) pipeline_perf_[SQLITE_PIPELINE_BOUNDARY_PROBES].fetch_add(boundaries.probes);
    if (adaptive_extent_mode() && (credit_limited || byte_limited)) {
      for (const auto& plan : pipeline_batches_) {
        if (plan->next == plan->operations.size() || plan->boundary_backpressure ||
            plan->groups[plan->operation_groups[plan->next]].policy != IoPlanningPolicy::kReadRand100kAdjacent)
          continue;
        plan->boundary_backpressure = true;
        pipeline_perf_[SQLITE_PIPELINE_BOUNDARY_BACKPRESSURE_PLANS].fetch_add(1);
      }
    }
    if (pending || !operations.empty()) {
      pipeline_perf_[byte_limited ? SQLITE_PIPELINE_BYTE_LIMITED : credit_limited ?
          SQLITE_PIPELINE_CREDIT_LIMITED : SQLITE_PIPELINE_READY_EXHAUSTED].fetch_add(1);
    }
    pipeline_depth_.submitted(flights_.size(), credit_limited);
    if (operations.empty()) return false;
    const uint64_t start = now_ns();
    uint64_t dequeue_to_submit = 0, sequential_ready_ns = 0;
    for (const uint64_t token : tokens) {
      auto& flight = flights_.find(token)->second;
      flight.submitted = flight.enqueue_ns = start;
      const auto mark_submitted = [&](const Flight& part) {
        const auto& group = part.batch->groups[part.batch->operation_groups[part.operation]];
        for (Task* task : group.tasks) {
          task->io_submit_ns = start;
          task->pipeline_depth_epoch = flight.depth_epoch;
          flight.useful_bytes += task->io_length;
          flight.enqueue_ns = std::min(flight.enqueue_ns, task->enqueue_ns);
          dequeue_to_submit += start - task->dequeue_ns;
          if (group.policy == IoPlanningPolicy::kSequentialContiguous)
            sequential_ready_ns += start - task->dequeue_ns;
          sqlite_gantt_trace().recordRequest(SQLITE_GANTT_IO_SUBMIT, task->request,
              task->completion ? task->completion->trace_id : 0, 0, 1, start);
          if (sqlite_gantt_trace().neighborDiagnostic())
            sqlite_gantt_trace().recordPlanned(SQLITE_GANTT_NEIGHBOR_SUBMIT,
                task->request, task->completion ? task->completion->trace_id : 0,
                task->io_offset, task->io_length, part.batch->diagnostic_id, token, start);
        }
      };
      mark_submitted(flight);
      for (const auto& part : flight.followers) mark_submitted(part);
    }
    int error = 0;
    size_t accepted, enters = 0, partials = 0;
    uint64_t ring_submit_ns = 0;
    RawIoUring::SubmitTiming submit_timing;
    {
      std::lock_guard<std::mutex> lock(ring_mutex_);
      // Match the non-pipeline submit bucket: SQE preparation and enter(),
      // not per-request diagnostics or time waiting for the userspace lock.
      const uint64_t ring_started = now_ns();
      accepted = ring_.submitAsync(operations, tokens, &error, &enters, &partials,
                                   &submit_timing);
      ring_submit_ns = now_ns() - ring_started;
    }
    pipeline_perf_[SQLITE_PIPELINE_SUBMIT_PREP_WALL_NS].fetch_add(submit_timing.prep_wall_ns);
    pipeline_perf_[SQLITE_PIPELINE_SUBMIT_PREP_CPU_NS].fetch_add(submit_timing.prep_cpu_ns);
    pipeline_perf_[SQLITE_PIPELINE_SUBMIT_ENTER_WALL_NS].fetch_add(submit_timing.enter_wall_ns);
    pipeline_perf_[SQLITE_PIPELINE_SUBMIT_ENTER_CPU_NS].fetch_add(submit_timing.enter_cpu_ns);
    pipeline_perf_[SQLITE_PIPELINE_SUBMIT_ENTER_VOLUNTARY_SWITCHES].fetch_add(
        submit_timing.voluntary_switches);
    pipeline_perf_[SQLITE_PIPELINE_SUBMIT_ENTER_INVOLUNTARY_SWITCHES].fetch_add(
        submit_timing.involuntary_switches);
    pipeline_perf_[SQLITE_PIPELINE_SUBMIT_ENTER_OUTPUT_BLOCKS].fetch_add(
        submit_timing.output_blocks);
    atomic_update_max(pipeline_perf_[SQLITE_PIPELINE_SUBMIT_ENTER_MAX_WALL_NS],
                      submit_timing.enter_wall_ns);
    pipeline_perf_[SQLITE_PIPELINE_SUBMIT_ENTER_SAMPLES].fetch_add(1);
    const uint64_t enter_returned = now_ns();
    if (sqlite_gantt_trace().neighborDiagnostic())
      sqlite_gantt_trace().recordPoint(SQLITE_GANTT_NEIGHBOR_SUBMIT_BATCH,
          0, 0, 0, accepted, static_cast<int64_t>(enters), start);
    // Keep the inclusive cost for the existing depth/merge feedback. A bucket
    // correction must not make the controller believe the service is cheaper.
    const uint64_t elapsed = enter_returned - start;
    host_dequeue_to_io_submit_ns_.fetch_add(dequeue_to_submit, std::memory_order_relaxed);
    if (sequential_ready_ns)
      pipeline_perf_[SQLITE_PIPELINE_SEQ_READY_NS].fetch_add(sequential_ready_ns, std::memory_order_relaxed);
    pipeline_perf_[SQLITE_PIPELINE_ENTER_CALLS].fetch_add(enters);
    pipeline_perf_[SQLITE_PIPELINE_ENTER_PARTIAL].fetch_add(partials);
    pipeline_perf_[SQLITE_PIPELINE_SQES_ACCEPTED].fetch_add(accepted);
    for (const uint64_t token : tokens) {
      auto& flight = flights_.find(token)->second;
      flight.submit_cost = elapsed / tokens.size();
      size_t descriptors = flight.batch->groups[
          flight.batch->operation_groups[flight.operation]].tasks.size();
      for (const auto& part : flight.followers)
        descriptors += part.batch->groups[part.batch->operation_groups[part.operation]].tasks.size();
      uint64_t remainder = flight.submit_cost % descriptors;
      const auto account_submit = [&](const Flight& part) {
        for (Task* task : part.batch->groups[part.batch->operation_groups[part.operation]].tasks) {
          task->pipeline_submit_cost = flight.submit_cost / descriptors + (remainder ? 1 : 0);
          task->io_enter_return_ns = enter_returned;
          if (remainder) --remainder;
        }
      };
      account_submit(flight);
      for (const auto& part : flight.followers) account_submit(part);
      const uint64_t share = elapsed / tokens.size() / (1 + flight.followers.size());
      flight.batch->work_ns += share;
      for (const auto& part : flight.followers) part.batch->work_ns += share;
    }
    submit_ns_.fetch_add(ring_submit_ns);
    disk_io_ns_.fetch_add(ring_submit_ns);
    if (accepted) {
      if (flights_.at(tokens.front()).batch->tasks.front()->request.workload ==
          GROUP_PMP_SQLITE_READSEQ) {
        const auto* first = flights_.at(tokens.front()).batch.get();
        bool shared = false, readseq = true;
        for (size_t i = 0; i < accepted; ++i) {
          const auto& f = flights_.at(tokens[i]);
          shared = shared || f.batch.get() != first;
          readseq = readseq && f.batch->tasks.front()->request.workload == GROUP_PMP_SQLITE_READSEQ;
          for (const auto& part : f.followers) shared = shared || part.batch.get() != first;
        }
        if (readseq && shared) pipeline_perf_[SQLITE_PIPELINE_SEQ_READ_SHARED_SUBMITS].fetch_add(1);
      }
      const size_t bucket = accepted == 1 ? SQLITE_PIPELINE_SUBMIT_ONE : accepted <= 4 ?
          SQLITE_PIPELINE_SUBMIT_2_4 : accepted <= 16 ? SQLITE_PIPELINE_SUBMIT_5_16 :
          accepted <= 64 ? SQLITE_PIPELINE_SUBMIT_17_64 : SQLITE_PIPELINE_SUBMIT_OVER64;
      pipeline_perf_[bucket].fetch_add(1);
      atomic_update_max(pipeline_perf_[SQLITE_PIPELINE_SUBMIT_MAX], accepted);
      io_uring_submissions_.fetch_add(1);
      pipeline_perf_[SQLITE_PIPELINE_SUBMITS].fetch_add(1);
      if (old_inflight) pipeline_perf_[SQLITE_PIPELINE_REFILLS_INFLIGHT].fetch_add(1);
    }
    // Unaccepted requests fail exactly once. Accepted requests stay live and
    // cannot be resent through POSIX after a short/failed enter syscall.
    for (size_t i = accepted; i < tokens.size(); ++i) {
      const auto found = flights_.find(tokens[i]);
      pipeline_complete(found->second, error ? error : -EIO, now_ns());
      flights_.erase(found);
    }
    atomic_update_max(pipeline_perf_[SQLITE_PIPELINE_INFLIGHT_PEAK], flights_.size());
    atomic_update_max(pipeline_perf_[SQLITE_PIPELINE_BYTES_PEAK], inflight_bytes_);
    return true;
  }

  bool pipeline_reap() {
    const uint64_t started = now_ns();
    const size_t budget = flights_.size();
    // No SQEs are submitted here. Recheck only already completed work, bounded
    // by the flights present on entry; never wait to fill a publication batch.
    const auto drained = drain_arrived_completions(true, budget,
      [&]() {
        std::lock_guard<std::mutex> lock(ring_mutex_);
        return ring_.reapAsync();
      }, [&](const std::vector<RawIoUring::Completion>& ready) {
      const uint64_t completed = now_ns();
      for (const auto& cqe : ready) {
        const auto found = flights_.find(cqe.token);
        if (found == flights_.end()) throw std::runtime_error("unknown SQLite I/O completion token");
        pipeline_complete(found->second, cqe.result, completed);
        flights_.erase(found);
      }
    });
    if (!drained.consumed) return false;
    pipeline_perf_[SQLITE_PIPELINE_CQE_BATCHES].fetch_add(1);
    pipeline_perf_[SQLITE_PIPELINE_CQE_SNAPSHOT_PASSES].fetch_add(drained.passes);
    pipeline_perf_[SQLITE_PIPELINE_CQE_EXTRA_COMPLETIONS].fetch_add(drained.extra);
    pipeline_perf_[SQLITE_PIPELINE_CQE_DRAIN_NS].fetch_add(now_ns() - started);
    return true;
  }

  void pipeline_update_feedback_metrics() {
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_TARGET].store(pipeline_depth_.target);
    pipeline_perf_[SQLITE_PIPELINE_SERVICE_EWMA_NS].store(pipeline_depth_.service);
    pipeline_perf_[SQLITE_PIPELINE_TAIL_EWMA_NS].store(pipeline_depth_.tail);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_WINDOWS].store(pipeline_depth_.windows);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_REJECTS].store(pipeline_depth_.rejected);
    pipeline_perf_[SQLITE_PIPELINE_SUBMIT_NS_PER_MB].store(pipeline_depth_.submit_cost);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_SAMPLES].store(pipeline_depth_.completed_samples);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_STALE_SAMPLES].store(pipeline_depth_.stale_samples);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_TRANSITION_SAMPLES].store(pipeline_depth_.transition_samples);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_PROBES].store(pipeline_depth_.probes);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_ACCEPTS].store(pipeline_depth_.accepts);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_UNEXPOSED].store(pipeline_depth_.unexposed);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_PENDING_SAMPLES].store(pipeline_depth_.samples);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_PROBE_ACTIVE].store(pipeline_depth_.probing ? 1 : 0);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_FAILURE_STREAK].store(pipeline_depth_.failure_streak);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_BACKOFF_WINDOWS].store(pipeline_depth_.cooldown);
    pipeline_perf_[SQLITE_PIPELINE_DEPTH_BACKOFF_SKIPS].store(pipeline_depth_.backoff_skips);
    pipeline_perf_[SQLITE_PIPELINE_WRITE_DEPTH_GUARD_WINDOWS].store(pipeline_depth_.write_guard_windows);
    pipeline_perf_[SQLITE_PIPELINE_WRITE_IO_EWMA_NS].store(pipeline_depth_.write_io_ewma);
  }

  void pipeline_observe_read_buffer(const std::vector<Task*>& tasks, uint64_t published) {
    if (tasks.empty()) return;
    const auto feedback_task = std::find_if(tasks.begin(), tasks.end(), [](const Task* task) {
      return task->merge_feedback_candidate && task->pipeline_owner && task->pipeline_owner->feedback;
    });
    if (feedback_task == tasks.end()) return;
    const PipelineBatch& origin = *(*feedback_task)->pipeline_owner;
    ReadMergeFeedback* feedback = origin.feedback;
    uint64_t first = published, bytes = 0, work = 0, last_cqe = 0, released = 0;
    for (const Task* task : tasks) {
      const PipelineBatch* plan = task->pipeline_owner;
      if (task->result || !plan || plan->feedback != feedback ||
          plan->feedback_epoch != origin.feedback_epoch || plan->merged != origin.merged ||
          !task->dequeue_ns || task->dequeue_ns > published || !task->io_complete_ns)
        return; // Partial/error/mixed-policy buffers cannot train a trial.
      first = std::min(first, task->dequeue_ns);
      bytes += task->storage_length;
      work += task->merge_feedback_work_ns + task->pipeline_submit_cost;
      last_cqe = std::max(last_cqe, task->io_complete_ns);
      released = std::max(released, task->publish_ns);
    }
    if (released && released <= published) published = released;
    if (!bytes || first == published) return;
    const uint64_t release_delay = published >= last_cqe ? published - last_cqe : 0;
    pipeline_perf_[SQLITE_PIPELINE_READ100K_RELEASE_NS].fetch_add(release_delay);
    const size_t mode = origin.merged ? 1 : 0;
    read100k_[SQLITE_READ100K_DISCRETE_BATCHES + mode].fetch_add(1);
    read100k_[SQLITE_READ100K_DISCRETE_BYTES + mode].fetch_add(bytes);
    read100k_[SQLITE_READ100K_DISCRETE_SERVICE_NS + mode].fetch_add(published - first);
    pipeline_perf_[SQLITE_PIPELINE_READ100K_FEEDBACK_BUFFERS].fetch_add(1);
    // Timestamp ends at this buffer's actual publication, not plan retirement
    // or a sibling's last CQE. Old live trials never train the opposite policy.
    if (feedback->epoch != origin.feedback_epoch || feedback->merging != origin.merged) {
      pipeline_perf_[SQLITE_PIPELINE_READ100K_FEEDBACK_STALE].fetch_add(1);
      return;
    }
    const int action = feedback->observe(bytes, published - first, work, release_delay);
    if (action) read100k_[action > 0 ? SQLITE_READ100K_PROBES : SQLITE_READ100K_BACKOFFS].fetch_add(1);
  }

  void pipeline_observe_online_buffer(const std::vector<Task*>& tasks) {
    if (tasks.empty() || !tasks.front()->pipeline_owner) return;
    const PipelineBatch& origin = *tasks.front()->pipeline_owner;
    OnlineClusterFeedback* feedback = origin.online_feedback;
    if (!feedback) return;
    uint64_t first = UINT64_MAX, enqueued = UINT64_MAX, published = 0, bytes = 0;
    bool candidate = false, merged = false;
    for (const Task* task : tasks) {
      const PipelineBatch* plan = task->pipeline_owner;
      const uint64_t service_start = plan && plan->online_started ?
          plan->online_started : task->dequeue_ns;
      if (!plan || plan->online_feedback != feedback ||
          plan->online_epoch != origin.online_epoch || plan->online_merge != origin.online_merge ||
          task->result || !task->dequeue_ns || !task->enqueue_ns || !task->publish_ns ||
          task->publish_ns < task->dequeue_ns || service_start < task->enqueue_ns ||
          service_start > task->dequeue_ns) {
        ++feedback->mixed;
        return;
      }
      first = std::min(first, service_start);
      enqueued = std::min(enqueued, task->enqueue_ns);
      published = std::max(published, task->publish_ns);
      bytes += task->storage_length;
      candidate = candidate || task->online_candidate;
      merged = merged || task->online_merged;
    }
    feedback->observe(origin.online_epoch, origin.online_merge, first, bytes,
        published - first, published - enqueued, candidate, merged);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_SERVICE_NS_PER_MB].store(feedback->last_cost);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_PUBLICATION_P95_NS].store(feedback->last_p95);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_REFERENCE_NS_PER_MB].store(feedback->reference_cost);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_REFERENCE_P95_NS].store(feedback->reference_p95);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_MERGING].store(feedback->merging);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_PENDING_SAMPLES].store(feedback->samples);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_COOLDOWN].store(feedback->cooldown);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_EPOCH].store(feedback->epoch);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_WINDOW_TARGET].store(feedback->window_target);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_LAST_WINDOW_SAMPLES].store(feedback->last_window_samples);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_REFERENCE_SAMPLES].store(feedback->reference_samples);
  }

  void pipeline_online_totals() {
    std::array<uint64_t, 10> totals{};
    uint64_t grows = 0, evaluated = 0;
    for (const auto& entry : online_feedback_) {
      const auto& f = entry.second;
      const uint64_t values[] = {f.samples_total, f.candidates_total, f.exposed_total,
          f.windows, f.probes, f.accepts, f.rejects, f.unexposed, f.stale, f.mixed};
      for (size_t i = 0; i < totals.size(); ++i) totals[i] += values[i];
      grows += f.window_grows;
      evaluated += f.evaluated_buffers;
    }
    for (size_t i = 0; i < totals.size(); ++i)
      pipeline_perf_[SQLITE_PIPELINE_ONLINE_BUFFERS + i].store(totals[i]);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_WINDOW_GROWS].store(grows);
    pipeline_perf_[SQLITE_PIPELINE_ONLINE_EVALUATED_BUFFERS].store(evaluated);
  }

  bool pipeline_publish() {
    // A new plan or completed child invalidates the publication check. Idle
    // reactor iterations need not re-scan every unfinished buffer.
    const bool unindexed = std::any_of(pipeline_batches_.begin(),
        pipeline_batches_.end(), [](const std::shared_ptr<PipelineBatch>& plan) {
          return !plan->completion_indexed;
        });
    if (!pipeline_publication_dirty_ && !unindexed) {
      if (!pipeline_batches_.empty() &&
          std::all_of(pipeline_batches_.begin(), pipeline_batches_.end(),
                      [](const std::shared_ptr<PipelineBatch>& plan) {
                        return plan->read100k_publication;
                      }))
        pipeline_perf_[SQLITE_PIPELINE_READ100K_PUBLISH_IDLE_SKIPS].fetch_add(1);
      return false;
    }
    pipeline_publication_dirty_ = false;
    const uint64_t work_started = now_ns();
    using CompletionPtr = std::shared_ptr<SqliteAsyncCompletion>;
    using BufferProgress = PipelineBatch::BufferProgress;
    std::map<CompletionPtr, std::vector<BufferProgress*>, std::owner_less<CompletionPtr> > pending;
    std::map<CompletionPtr, std::vector<Task*>, std::owner_less<CompletionPtr> > buffers;
    std::vector<Task*> ready;
    for (const auto& plan : pipeline_batches_) {
      pipeline_index_completions(*plan);
      if (plan->atomic_write_publish && !plan->remaining && !plan->atomic_error_checked) {
        if (std::any_of(plan->tasks.begin(), plan->tasks.end(),
                       [](const Task* task) { return task->result != 0; })) {
          for (Task* task : plan->tasks)
            if (task->superseded) task->result = -EIO;
        }
        plan->atomic_error_checked = true;
      }
      for (auto& buffer : plan->buffers)
        if (!buffer.second.published) pending[buffer.first].push_back(&buffer.second);
      ready.insert(ready.end(), plan->unowned_ready.begin(), plan->unowned_ready.end());
      plan->unowned_ready.clear();
    }
    uint64_t completed_buffers = 0, early = 0;
    for (const auto& buffer : pending) {
      pipeline_perf_[SQLITE_PIPELINE_COMPLETION_BUFFER_CHECKS].fetch_add(1);
      bool dependency = false;
      size_t count = 0;
      for (const BufferProgress* part : buffer.second) {
        count += part->tasks.size();
        dependency = dependency || part->pending ||
            (part->owner->atomic_write_publish && part->owner->remaining);
      }
      if (dependency) continue;
      // A producer's descriptors may span plans. Publish only after all of
      // its own children have arrived and completed, never after one fragment.
      if (count != buffer.first->remaining.load(std::memory_order_acquire)) continue;
      auto& completed = buffers[buffer.first];
      for (BufferProgress* part : buffer.second) {
        completed.insert(completed.end(), part->tasks.begin(), part->tasks.end());
        part->published = true;
      }
      ready.insert(ready.end(), completed.begin(), completed.end());
      ++completed_buffers;
      if (std::any_of(pipeline_batches_.begin(), pipeline_batches_.end(),
                     [](const std::shared_ptr<PipelineBatch>& p) { return p->remaining != 0; })) ++early;
    }
    pipeline_perf_[SQLITE_PIPELINE_COMPLETION_CHECK_NS].fetch_add(now_ns() - work_started);
    if (ready.empty()) return false;
    pipeline_perf_[SQLITE_PIPELINE_COMPLETION_PUBLICATIONS].fetch_add(1);
    atomic_update_max(pipeline_perf_[SQLITE_PIPELINE_COMPLETION_MAX_BUFFERS], completed_buffers);
    std::vector<Task*> writes;
    for (auto it = ready.rbegin(); it != ready.rend(); ++it) {
      Task& task = **it;
      if (task.request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE) writes.push_back(&task);
      // Neither async mode fills a second Host ciphertext cache. The completed
      // UTM already owns its payload; only real overlap/gap merges need scatter.
    }
    if (!writes.empty()) {
      for (Task* task : writes) sqlite_gantt_trace().recordRequest(SQLITE_GANTT_METADATA_COMMIT_BEGIN,
          task->request, task->completion ? task->completion->trace_id : 0);
      const uint64_t metadata_started = now_ns();
      const bool committed = commit_writes(writes);
      pipeline_perf_[SQLITE_PIPELINE_METADATA_COMMIT_NS].fetch_add(now_ns() - metadata_started);
      for (Task* task : writes) {
        if (!committed && !task->result) task->result = -EIO;
        sqlite_gantt_trace().recordRequest(SQLITE_GANTT_METADATA_COMMIT_END,
            task->request, task->completion ? task->completion->trace_id : 0, task->result);
      }
    }
    for (Task* task : ready) {
      task->pipeline_published = true;
      sqlite_gantt_trace().recordRequest(SQLITE_GANTT_STORAGE_IO_END, task->request,
          task->completion ? task->completion->trace_id : 0, task->result);
    }
    const uint64_t start = now_ns();
    publishBatch(ready);
    const uint64_t published = now_ns();
    const bool feedback_active = std::any_of(pipeline_batches_.begin(), pipeline_batches_.end(),
        [](const std::shared_ptr<PipelineBatch>& plan) { return plan->feedback != nullptr; });
    if (feedback_active) {
      uint64_t publication_remainder = (published - work_started) % ready.size();
      for (Task* task : ready) {
        if (task->pipeline_owner && task->pipeline_owner->feedback)
          task->merge_feedback_work_ns += (published - work_started) / ready.size() +
              (publication_remainder ? 1 : 0);
        if (publication_remainder) --publication_remainder;
      }
    }
    for (auto& plan : pipeline_batches_) {
      size_t own = 0;
      for (Task* task : ready)
        if (task->pipeline_owner == plan.get()) ++own;
      plan->work_ns += (published - work_started) * own / ready.size();
    }
    merge_completion_cost_ns_ = ewma_update(merge_completion_cost_ns_, (published - start) / ready.size());
    pipeline_perf_[SQLITE_PIPELINE_BUFFER_COMPLETIONS].fetch_add(completed_buffers);
    pipeline_perf_[SQLITE_PIPELINE_EARLY_BUFFERS].fetch_add(early);
    struct BufferDepthSample {
      uint64_t submitted, bytes, latency, epoch, submit_cost;
      bool random_write;
      uint64_t io_elapsed, post_enter;
    };
    std::vector<BufferDepthSample> depth_samples;
    // Discard mismatched observer epochs without delaying publication. Normal
    // count-first execution has no trial transitions and retains epoch 1.
    for (const auto& buffer : buffers) {
      for (const Task* task : buffer.second) {
        const auto* plan = task->pipeline_owner;
        if (plan && plan->online_feedback && plan->online_epoch != plan->online_feedback->epoch) {
          plan->online_feedback->settle(published);
          break;
        }
      }
    }
    for (const auto& buffer : buffers) {
      if (!buffer.first->isComplete()) continue;
      pipeline_observe_online_buffer(buffer.second);
      if (feedback_active) pipeline_observe_read_buffer(buffer.second, published);
      uint64_t bytes = 0, submitted = published, enqueued = published, last_cqe = 0;
      uint64_t depth_epoch = 0, submit_cost = 0;
      uint64_t post_enter = 0;
      bool random_write = true;
      bool mixed_depth = false;
      bool ok = true;
      for (const Task* task : buffer.second) {
        bytes += task->storage_length;
        if (task->io_submit_ns) {
          submitted = std::min(submitted, task->io_submit_ns);
          mixed_depth = mixed_depth || !task->pipeline_depth_epoch ||
              (depth_epoch && depth_epoch != task->pipeline_depth_epoch);
          depth_epoch = task->pipeline_depth_epoch;
          submit_cost += task->pipeline_submit_cost;
        }
        enqueued = std::min(enqueued, task->enqueue_ns);
        last_cqe = std::max(last_cqe, task->io_complete_ns);
        if (task->io_enter_return_ns && task->io_complete_ns >= task->io_enter_return_ns)
          post_enter = std::max(post_enter, task->io_complete_ns - task->io_enter_return_ns);
        random_write = random_write && task->request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE &&
            random_write_workload(task->request.workload);
        ok = ok && !task->result;
      }
      if (last_cqe) {
        // Completion publication precedes wake callbacks. Do not charge a
        // later buffer's callback or the batch loop to this buffer's P95.
        const uint64_t buffer_published = buffer.first->publishedAtNs();
        const uint64_t delay = buffer_published >= last_cqe ? buffer_published - last_cqe : 0;
        publication_histogram_.record(delay);
        buffer_latency_histogram_.record(buffer_published >= enqueued ? buffer_published - enqueued : 0);
        pipeline_perf_[SQLITE_PIPELINE_BUFFER_PUBLISH_NS].fetch_add(delay);
        atomic_update_max(pipeline_perf_[SQLITE_PIPELINE_BUFFER_PUBLISH_MAX_NS], delay);
      }
      if (ok && bytes && last_cqe) {
        depth_samples.push_back({submitted, bytes, published - enqueued,
            mixed_depth ? 0 : depth_epoch, submit_cost, random_write,
            last_cqe - submitted, post_enter});
        if (random_write) {
          pipeline_perf_[SQLITE_PIPELINE_WRITE_IO_RESIDENCY_NS].fetch_add(last_cqe - submitted);
          pipeline_perf_[SQLITE_PIPELINE_WRITE_POST_ENTER_NS].fetch_add(post_enter);
          atomic_update_max(pipeline_perf_[SQLITE_PIPELINE_WRITE_POST_ENTER_MAX_NS], post_enter);
        }
        ewma_completion_latency_ns_.store(ewma_update(ewma_completion_latency_ns_.load(),
            published - enqueued));
        ewma_request_latency_ns_.store(ewma_update(ewma_request_latency_ns_.load(),
            (published - submitted) / buffer.second.size()));
        if (pipeline_depth_.rate) ewma_bandwidth_bytes_per_sec_.store(pipeline_depth_.rate);
        uint64_t queue_wait = 0;
        for (const Task* task : buffer.second) queue_wait += task->dequeue_ns - task->enqueue_ns;
        ewma_queue_wait_ns_.store(ewma_update(ewma_queue_wait_ns_.load(), queue_wait / buffer.second.size()));
      }
    }
    // Observe whole buffer lifetimes, not CQE multiplicity. Settle all old or
    // mixed epochs before admitting any clean sample from this publication.
    for (const auto& sample : depth_samples)
      if (sample.epoch != pipeline_depth_.epoch) pipeline_depth_.settle(published);
    for (const auto& sample : depth_samples)
      pipeline_depth_.completed(published, sample.submitted, sample.bytes,
          sample.latency, sample.epoch, sample.submit_cost, sample.random_write,
          sample.io_elapsed, sample.post_enter);
    const uint64_t windows_before = pipeline_depth_.windows;
    // Preserve the policy-37 fixed depth. Passive clustering telemetry never
    // changes credits; this revision does not retune Async or admission depth.
    const int action = pipeline_depth_.evaluate(published, false);
    if (action) pipeline_perf_[action > 0 ? SQLITE_PIPELINE_DEPTH_GROWS :
                                          SQLITE_PIPELINE_DEPTH_SHRINKS].fetch_add(1);
    if (!writes.empty() && random_write_workload(writes.front()->request.workload) &&
        adaptive_extent_mode() && pipeline_depth_.windows != windows_before)
      (action > 0 ? adaptive_write_grow_count_ : action < 0 ?
          adaptive_write_shrink_count_ : adaptive_write_hold_count_).fetch_add(1);
    pipeline_update_feedback_metrics();
    pipeline_online_totals();
    const bool adaptive = adaptive_extent_mode();
    const size_t logical = std::min(kDefaultAdaptiveBatch, adaptive_batch_max_);
    adaptive_batch_target_.store(logical);
    adaptive_queue_depth_.store(logical * 4);
    write_queue_depth_.store(logical * 4);
    adaptive_collect_usec_.store(0); // Ready-only admission, never wait for merging.
    if (adaptive) {
      // Hole admission uses amplification and whole-extent delay, not savings.
      adaptive_gap_bytes_.store(maximum_gap_);
    }
    return true;
  }

  void pipeline_retire() {
    for (auto it = pipeline_batches_.begin(); it != pipeline_batches_.end();) {
      auto& plan = **it;
      if (plan.remaining || !std::all_of(plan.tasks.begin(), plan.tasks.end(),
                       [](const Task* task) { return task->pipeline_published; })) { ++it; continue; }
      const uint64_t finished = now_ns(), elapsed = finished - plan.started;
      const bool read = plan.tasks.front()->request.operation == GROUP_PMP_SQLITE_VFS_OP_READ;
      (read ? read_service_ns_ : write_service_ns_).fetch_add(elapsed);
      task_count_.fetch_add(plan.tasks.size());
      uint64_t oldest = finished;
      for (Task* task : plan.tasks) oldest = std::min(oldest, task->enqueue_ns);
      atomic_update_max(max_batch_service_ns_, elapsed);
      atomic_update_max(max_completion_latency_ns_, finished - oldest);
      atomic_update_max(window_last_completion_ns_, finished);
      for (const auto& group : plan.groups)
        if (!group.read && group.fd >= 0) pipeline_write_ranges_.erase({group.file_id, group.offset});
      if (!read)
        for (const Task* task : plan.tasks)
          pipeline_write_keys_.erase(std::make_tuple(task->request.run_id,
              task->request.worker_index, task->request.workload, task->request.reserved[1]));
      it = pipeline_batches_.erase(it);
    }
  }

  size_t pipeline_logical_target(uint64_t workload) const {
    return workload_batch_target(workload, kDefaultAdaptiveBatch, adaptive_batch_max_);
  }

  // Called with queue_mutex_ held. Inspect a bounded prefix of the captured
  // arrival snapshot; never cross a control boundary or wait for a new peer.
  bool pipeline_arrived_sequential_peer(size_t arrived) const {
    if (queue_.empty() || !arrived) return false;
    const Task& first = queue_.front();
    if (planning_policy(first) != IoPlanningPolicy::kSequentialContiguous) return false;
    const size_t limit = std::min(arrived, pipeline_logical_target(first.request.workload));
    size_t examined = 0;
    for (const Task& task : queue_) {
      if (examined++ >= limit || !same_planning_scope(first, task)) break;
      if (!task.request.length || task.request.length > UINT64_MAX - task.request.file_offset) continue;
      for (const auto& plan : pipeline_batches_)
        for (size_t i = plan->next; i < plan->operations.size(); ++i) {
          const auto& group = plan->groups[plan->operation_groups[i]];
          if (group.policy != IoPlanningPolicy::kSequentialContiguous ||
              group.overlapping || group.spans_gap ||
              !same_planning_scope(*group.tasks.front(), task) ||
              group.file_id != task.request.file_id) continue;
          const uint64_t span = group.end - group.offset;
          const uint64_t peer_end = task.request.file_offset + task.request.length;
          if ((group.end == task.request.file_offset || peer_end == group.offset) &&
              span <= merge_limit_ && task.request.length <= merge_limit_ - span &&
              inflight_bytes_ <= pipeline_depth_.byte_limit &&
              span + task.request.length <= pipeline_depth_.byte_limit - inflight_bytes_)
            return true;
        }
    }
    return false;
  }

  // Co-submit a second already-arrived readseq plan even when request hints
  // are not adjacent. Metadata resolves offsets before the existing matcher.
  // Count only captured arrivals and preserve the two-plan/credit/byte bounds.
  bool pipeline_arrived_readseq_share(size_t arrived,
      SqliteNeighborAdmissionReason* reason = nullptr) const {
    const auto reject = [reason](SqliteNeighborAdmissionReason value) {
      if (reason) *reason = value;
      return false;
    };
    if (!arrived || queue_.empty()) return reject(SQLITE_NEIGHBOR_NO_ARRIVALS);
    const Task& first = queue_.front();
    if (first.request.operation != GROUP_PMP_SQLITE_VFS_OP_READ ||
        first.request.workload != GROUP_PMP_SQLITE_READSEQ)
      return reject(SQLITE_NEIGHBOR_NOT_READSEQ);
    if (flights_.size() >= pipeline_depth_.target) return reject(SQLITE_NEIGHBOR_SQE_CREDIT);
    if (inflight_bytes_ >= pipeline_depth_.byte_limit) return reject(SQLITE_NEIGHBOR_BYTE_CREDIT);
    const size_t credits = pipeline_depth_.target - flights_.size();
    const uint64_t bytes = pipeline_depth_.byte_limit - inflight_bytes_;
    size_t pending = 0;
    uint64_t used = 0;
    for (const auto& plan : pipeline_batches_)
      for (size_t i = plan->next; i < plan->operations.size(); ++i) {
        const auto& group = plan->groups[plan->operation_groups[i]];
        if (!same_planning_scope(*group.tasks.front(), first)) return reject(SQLITE_NEIGHBOR_SCOPE);
        if (++pending >= credits) return reject(SQLITE_NEIGHBOR_SQE_CREDIT);
        if (plan->operations[i].expected > bytes - used) return reject(SQLITE_NEIGHBOR_BYTE_CREDIT);
        used += plan->operations[i].expected;
      }
    if (!pending) return reject(SQLITE_NEIGHBOR_NO_PENDING_PLAN);
    const size_t limit = std::min(arrived, pipeline_logical_target(first.request.workload));
    size_t examined = 0;
    for (const Task& task : queue_) {
      if (examined >= limit || !same_planning_scope(first, task)) break;
      if (!task.request.length) return reject(SQLITE_NEIGHBOR_INVALID_LENGTH);
      if (task.request.length > bytes - used) return reject(SQLITE_NEIGHBOR_BYTE_CREDIT);
      if (pending >= credits) return reject(SQLITE_NEIGHBOR_SQE_CREDIT);
      ++pending; ++examined; used += task.request.length;
    }
    if (!examined) return reject(SQLITE_NEIGHBOR_EMPTY_BATCH);
    if (reason) *reason = SQLITE_NEIGHBOR_ACCEPT;
    return true;
  }

  // Queue lock held; diagnostics observe the existing decision, never select
  // additional requests or resolve metadata to manufacture candidates.
  void pipeline_trace_admission(SqliteNeighborAdmissionReason reason,
      size_t arrived, size_t admitted,
      const group_pmp_sqlite_vfs_request* head = nullptr) const {
    if (!sqlite_gantt_trace().neighborDiagnostic()) return;
    uint64_t pending = 0;
    for (const auto& plan : pipeline_batches_)
      pending += plan->operations.size() - plan->next;
    const uint64_t state[9] = {queue_.size(), arrived, pending, flights_.size(),
        pipeline_depth_.target, inflight_bytes_, pipeline_depth_.byte_limit,
        pipeline_batches_.size(), admitted};
    sqlite_gantt_trace().recordAdmission(head ? head :
        (queue_.empty() ? nullptr : &queue_.front().request), reason, state);
  }

  bool pipeline_admit_ready() {
    size_t arrived;
    { std::lock_guard<std::mutex> lock(queue_mutex_); arrived = queue_.size();
      if (!arrived) pipeline_trace_admission(SQLITE_NEIGHBOR_NO_ARRIVALS, 0, 0); }
    if (!arrived) return false;
    pipeline_perf_[SQLITE_PIPELINE_ADMIT_ROUNDS].fetch_add(1);
    bool progressed = false;
    size_t admitted_plans = 0;
    // Random I/O still admits one plan. Sequential I/O admits only compatible
    // requests already in the arrival snapshot, bounded by four plans/8 MB.
    while (arrived) {
      std::vector<Task> batch;
      uint64_t selection_started = 0;
      bool readseq_share = false;
      {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (queue_.empty()) break;
        selection_started = now_ns();
        if (admitted_plans) {
          if (admitted_plans >= 4) {
            pipeline_trace_admission(SQLITE_NEIGHBOR_TWO_PLAN_LIMIT, arrived, admitted_plans);
            break;
          }
          SqliteNeighborAdmissionReason reason = SQLITE_NEIGHBOR_NOT_READSEQ;
          readseq_share = pipeline_arrived_readseq_share(arrived, &reason);
          if (!readseq_share && !pipeline_arrived_sequential_peer(arrived)) {
            pipeline_trace_admission(reason, arrived, admitted_plans);
            break;
          }
        }
        if (pipeline_batches_.size() >= 4) {
          pipeline_trace_admission(SQLITE_NEIGHBOR_ACTIVE_PLAN_LIMIT, arrived, admitted_plans);
          pipeline_perf_[SQLITE_PIPELINE_PLAN_LIMITED].fetch_add(1);
          break;
        }
        if (!pipeline_compatible(queue_.front())) {
          pipeline_trace_admission(SQLITE_NEIGHBOR_BARRIER, arrived, admitted_plans);
          pipeline_perf_[SQLITE_PIPELINE_BARRIER_BLOCKED].fetch_add(1);
          break;
        }
        // Once enough random SQEs are ready to fill the credits, submit them
        // instead of spending another plan's metadata/CPU time first.
        if (planning_policy(queue_.front()) != IoPlanningPolicy::kSequentialContiguous) {
          size_t pending = 0;
          for (const auto& plan : pipeline_batches_) pending += plan->operations.size() - plan->next;
          if (pending && pending >= pipeline_depth_.target - std::min(flights_.size(), pipeline_depth_.target)) {
            pipeline_trace_admission(SQLITE_NEIGHBOR_PENDING_FILLS_CREDIT, arrived, admitted_plans);
            break;
          }
        }
        const size_t target = pipeline_logical_target(queue_.front().request.workload);
        pipeline_perf_[SQLITE_PIPELINE_LOGICAL_TARGET].store(target);
        batch = take_ready_batch_locked(target, true, arrived);
        if (pipeline_write_conflict(batch)) {
          for (auto it = batch.rbegin(); it != batch.rend(); ++it) queue_.push_front(std::move(*it));
          pipeline_perf_[SQLITE_PIPELINE_WRITE_CONFLICT].fetch_add(1);
          pipeline_trace_admission(SQLITE_NEIGHBOR_WRITE_CONFLICT, arrived, admitted_plans);
          break;
        }
        if (batch.empty()) {
          pipeline_trace_admission(SQLITE_NEIGHBOR_EMPTY_BATCH, arrived, admitted_plans);
          break;
        }
        pipeline_trace_admission(SQLITE_NEIGHBOR_ACCEPT, arrived - batch.size(), admitted_plans, &batch.front().request);
        arrived -= batch.size();
        processing_batch_ = true;
      }
      condition_.notify_all();
      const bool data = batch.front().request.operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
          batch.front().request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE;
      if (data) {
        const uint64_t started = admitted_plans ? now_ns() : 0;
        pipeline_begin(std::move(batch), selection_started);
        if (readseq_share) pipeline_perf_[SQLITE_PIPELINE_SEQ_READ_READY_ADMISSIONS].fetch_add(1);
        if (admitted_plans) {
          pipeline_perf_[SQLITE_PIPELINE_SEQ_LOOKAHEAD_PLANS].fetch_add(1);
          pipeline_perf_[SQLITE_PIPELINE_SEQ_LOOKAHEAD_NS].fetch_add(now_ns() - started);
        }
        ++admitted_plans;
        pipeline_perf_[SQLITE_PIPELINE_ADMITTED_PLANS].fetch_add(1);
      } else {
        process_controls(batch);
        task_count_.fetch_add(batch.size());
        atomic_update_max(window_last_completion_ns_, now_ns());
      }
      progressed = true;
      if (!data) break;
    }
    return progressed;
  }

  void pipeline_loop() {
    bool owns_processing = false;
    for (;;) {
      uint64_t counter;
      while (read(wake_fd_, &counter, sizeof(counter)) == sizeof(counter)) {}
      bool progressed = pipeline_reap();
      progressed = pipeline_publish() || progressed;
      pipeline_retire();
      const bool admitted = pipeline_admit_ready();
      progressed = admitted || progressed;
      {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (admitted || !pipeline_batches_.empty())
          processing_batch_ = owns_processing = true;
        else if (owns_processing)
          processing_batch_ = owns_processing = false;
        if (stopping_ && queue_.empty() && !processing_batch_) return;
      }
      condition_.notify_all();
      progressed = pipeline_refill() || progressed;
      if (progressed) continue;
      // The request eventfd and the CQ fd are level-triggered. Arrivals and
      // completions cannot be lost between checking predicates and sleeping.
      struct pollfd fds[2] = {{wake_fd_, POLLIN, 0}, {ring_.descriptor(), POLLIN, 0}};
      {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if ((stopping_ && queue_.empty() && pipeline_batches_.empty()) ||
            (!queue_.empty() && pipeline_batches_.empty())) continue;
      }
      const uint64_t started = now_ns();
      int result;
      do { result = poll(fds, 2, -1); } while (result < 0 && errno == EINTR);
      if (result < 0) throw std::runtime_error("SQLite reactor poll failed");
      const uint64_t waited = now_ns() - started;
      if (!flights_.empty()) {
        pipeline_perf_[SQLITE_PIPELINE_EVENT_WAIT_NS].fetch_add(waited);
        completion_wait_ns_.fetch_add(waited);
        disk_io_ns_.fetch_add(waited);
      }
    }
  }
#endif

  void worker_loop() {
#ifdef __linux__
    cpu_set_t housekeeping;
    CPU_ZERO(&housekeeping);
    CPU_SET(0, &housekeeping);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(housekeeping),
                                 &housekeeping);
    if (pipeline_mode()) {
      pipeline_loop();
      return;
    }
#endif
    for (;;) {
      std::vector<Task> batch;
      uint64_t collection_started = 0;
      uint64_t collection_finished = 0;
      uint64_t batch_workload = 0;
      {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        condition_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
        if (stopping_ && queue_.empty())
          return;
        const bool data = queue_.front().request.operation ==
                GROUP_PMP_SQLITE_VFS_OP_READ ||
            queue_.front().request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE;
        const uint64_t operation = queue_.front().request.operation;
        const uint64_t file_id = queue_.front().request.file_id;
        const uint64_t run_id = queue_.front().request.run_id;
        const uint64_t workload = queue_.front().request.workload;
        batch_workload = workload;
        const bool batched_sync = operation == GROUP_PMP_SQLITE_VFS_OP_SYNC;
        const bool adaptive = adaptive_extent_mode();
        const bool adaptive_write = adaptive && random_write_workload(workload);
        size_t target = adaptive ? workload_batch_target(
            workload,
            static_cast<size_t>(adaptive_batch_target_.load(
                std::memory_order_relaxed)), adaptive_batch_max_) :
            std::min(kAsyncNoExtentBatch, adaptive_batch_max_);
        uint64_t collect_usec = adaptive ?
            adaptive_collect_usec_.load(std::memory_order_relaxed) :
            kDefaultCollectUsec;
        if (adaptive_write) {
          target = write_feedback_.target;
          collect_usec = 0;
          adaptive_batch_target_.store(target, std::memory_order_relaxed);
          adaptive_queue_depth_.store(write_queue_depth_.load(std::memory_order_relaxed),
                                       std::memory_order_relaxed);
        }
        const bool sequential = adaptive && data &&
            planning_policy(queue_.front()) ==
                IoPlanningPolicy::kSequentialContiguous;
        if (sequential) {
          target = std::min<size_t>(target,
              std::max<uint64_t>(2, queue_.front().request.worker_count * 2));
          // Never wait for hypothetical adjacent arrivals just to reach 8 MB.
          collect_usec = 0;
        }
        if (data)
          collect_usec = collection_window(adaptive,
              planning_policy(queue_.front()), collect_usec);
        if ((data || batched_sync) && collect_usec) {
          collection_started = now_ns();
          const uint64_t deadline = queue_.front().enqueue_ns +
              collect_usec * UINT64_C(1000);
          const uint64_t current = now_ns();
          if (current < deadline)
            condition_.wait_for(
                lock, std::chrono::nanoseconds(deadline - current),
                [this, target, operation, file_id, run_id, workload] {
                  size_t compatible = 0;
                  for (std::deque<Task>::const_iterator it = queue_.begin();
                       it != queue_.end(); ++it)
                    if (it->request.operation == operation &&
                        it->request.file_id == file_id &&
                        it->request.run_id == run_id &&
                        it->request.workload == workload &&
                        ++compatible >= target)
                      return true;
                  return stopping_;
                });
          collection_finished = now_ns();
        }
        batch = take_ready_batch_locked(target);
        processing_batch_ = !batch.empty();
      }
      condition_.notify_all();
      if (collection_finished >= collection_started)
        collect_ns_.fetch_add(collection_finished - collection_started,
                              std::memory_order_relaxed);
      uint64_t started = now_ns();
      uint64_t batch_wait_sum = 0;
      uint64_t oldest_enqueue = started;
      const uint64_t physical_before =
          physical_io_bytes_.load(std::memory_order_relaxed);
      const uint64_t useful_before = useful_io_bytes_.load(std::memory_order_relaxed);
      const uint64_t requests_before =
          physical_request_count_.load(std::memory_order_relaxed);
      for (size_t index = 0; index < batch.size(); ++index) {
        batch[index].dequeue_ns = started;
        sqlite_gantt_trace().recordRequest(
            SQLITE_GANTT_QUEUE_SERVICE_BEGIN, batch[index].request,
            batch[index].completion ? batch[index].completion->trace_id : 0,
            0, batch.size(), started);
        const uint64_t wait = started >= batch[index].enqueue_ns ?
            started - batch[index].enqueue_ns : 0;
        atomic_update_max(max_queue_wait_ns_, wait);
        batch_wait_sum += wait;
        if (batch[index].enqueue_ns < oldest_enqueue)
          oldest_enqueue = batch[index].enqueue_ns;
        queue_wait_ns_.fetch_add(wait, std::memory_order_relaxed);
        submit_to_host_dequeue_ns_.fetch_add(wait,
                                             std::memory_order_relaxed);
      }
      if (!batch.empty() &&
          (batch[0].request.operation == GROUP_PMP_SQLITE_VFS_OP_READ ||
           batch[0].request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE))
        process_data(batch);
      else if (!batch.empty())
        process_controls(batch);
      const uint64_t finished = now_ns();
      task_count_.fetch_add(batch.size(), std::memory_order_relaxed);
      size_t queued = 0;
      {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        queued = queue_.size();
      }
      size_t target = static_cast<size_t>(
          adaptive_batch_target_.load(std::memory_order_relaxed));
      const bool adaptive_write_policy = adaptive_extent_mode() &&
          random_write_workload(batch_workload);
      const bool adaptive_write = adaptive_write_policy && !batch.empty() &&
          batch[0].request.operation == GROUP_PMP_SQLITE_VFS_OP_WRITE &&
          random_write_workload(batch_workload);
      if (adaptive_extent_mode() && !adaptive_write_policy) {
        target = adaptive_batch_next(target, batch.size(), queued,
                                     adaptive_batch_min_,
                                     adaptive_batch_max_);
        adaptive_batch_target_.store(target, std::memory_order_relaxed);
      } else if (!adaptive_extent_mode()) {
        target = std::min(kAsyncNoExtentBatch, adaptive_batch_max_);
      }
      const uint64_t physical_delta =
          physical_io_bytes_.load(std::memory_order_relaxed) - physical_before;
      const uint64_t request_delta =
          physical_request_count_.load(std::memory_order_relaxed) -
          requests_before;
      const uint64_t service_ns = finished >= started ? finished - started : 0;
      const uint64_t queue_sample = batch.empty() ? 0 :
          batch_wait_sum / batch.size();
      const uint64_t completion_sample = finished >= oldest_enqueue ?
          finished - oldest_enqueue : 0;
      if (adaptive_write) {
        const int action = write_feedback_.observe(
            batch.size(), queued, useful_io_bytes_.load(std::memory_order_relaxed) - useful_before,
            service_ns, completion_sample,
            std::min(kWriteBatchMaximum, adaptive_batch_min_),
            std::min(kWriteBatchMaximum, adaptive_batch_max_));
        (action > 0 ? adaptive_write_grow_count_ : action < 0 ?
             adaptive_write_shrink_count_ : adaptive_write_hold_count_).fetch_add(
                 1, std::memory_order_relaxed);
        target = write_feedback_.target;
        adaptive_batch_target_.store(target, std::memory_order_relaxed);
        write_queue_depth_.store(target * 2, std::memory_order_relaxed);
      }
      if (adaptive_write_policy)
        adaptive_batch_target_.store(write_feedback_.target, std::memory_order_relaxed);
      atomic_update_max(max_batch_service_ns_, service_ns);
      atomic_update_max(max_completion_latency_ns_, completion_sample);
      atomic_update_max(window_last_completion_ns_, finished);
      if (physical_delta && service_ns) {
        const uint64_t bandwidth = physical_delta >
                UINT64_MAX / UINT64_C(1000000000) ?
            UINT64_MAX : physical_delta * UINT64_C(1000000000) / service_ns;
        ewma_bandwidth_bytes_per_sec_.store(
            ewma_update(ewma_bandwidth_bytes_per_sec_.load(
                            std::memory_order_relaxed), bandwidth),
            std::memory_order_relaxed);
      }
      if (request_delta && service_ns)
        ewma_request_latency_ns_.store(
            ewma_update(ewma_request_latency_ns_.load(
                            std::memory_order_relaxed),
                        service_ns / request_delta),
            std::memory_order_relaxed);
      ewma_queue_wait_ns_.store(
          ewma_update(ewma_queue_wait_ns_.load(std::memory_order_relaxed),
                      queue_sample),
          std::memory_order_relaxed);
      ewma_completion_latency_ns_.store(
          ewma_update(ewma_completion_latency_ns_.load(
                          std::memory_order_relaxed), completion_sample),
          std::memory_order_relaxed);

      const uint64_t request_latency = ewma_request_latency_ns_.load(
          std::memory_order_relaxed);
      const uint64_t completion_latency =
          ewma_completion_latency_ns_.load(std::memory_order_relaxed);
      uint64_t collect = adaptive_collect_usec_.load(
          std::memory_order_relaxed);
      if (adaptive_write_policy) {
        adaptive_collect_usec_.store(0, std::memory_order_relaxed);
        adaptive_queue_depth_.store(write_queue_depth_.load(std::memory_order_relaxed),
                                     std::memory_order_relaxed);
      } else if (adaptive_extent_mode()) {
        if (queued >= target) {
          const uint64_t collect_step =
              batch_workload == GROUP_PMP_SQLITE_READRAND100K ? 5 : 25;
          const uint64_t collect_limit =
              batch_workload == GROUP_PMP_SQLITE_READRAND100K ? 50 : 500;
          collect = std::min<uint64_t>(collect + collect_step,
                                       collect_limit);
        } else if (request_latency &&
                   completion_latency > request_latency * UINT64_C(4)) {
          collect = 0;
        } else if (!queued) {
          collect /= 2;
        }
        if (!batch.empty())
          collect = collection_window(true, planning_policy(batch.front()), collect);
        adaptive_collect_usec_.store(collect, std::memory_order_relaxed);
        adaptive_queue_depth_.store(
            std::max<uint64_t>(512, std::min<uint64_t>(
                UINT64_C(8192),
                static_cast<uint64_t>(target) * UINT64_C(8))),
            std::memory_order_relaxed);
      } else {
        adaptive_collect_usec_.store(kDefaultCollectUsec,
                                      std::memory_order_relaxed);
        adaptive_queue_depth_.store(kAsyncNoExtentBatch * 4,
                                     std::memory_order_relaxed);
      }
      const uint64_t bandwidth = ewma_bandwidth_bytes_per_sec_.load(
          std::memory_order_relaxed);
      const uint64_t effective_bandwidth = bandwidth && copy_bandwidth_ ?
          (bandwidth / (bandwidth + copy_bandwidth_)) * copy_bandwidth_ +
              ((bandwidth % (bandwidth + copy_bandwidth_)) *
               copy_bandwidth_) / (bandwidth + copy_bandwidth_) : 0;
      uint64_t profitable_gap = effective_bandwidth && request_latency <=
              UINT64_MAX / effective_bandwidth ?
          request_latency * effective_bandwidth / UINT64_C(1000000000) :
          maximum_gap_;
      adaptive_gap_bytes_.store(
          adaptive_extent_mode() ? maximum_gap_ :
              std::min<uint64_t>(maximum_gap_, profitable_gap),
          std::memory_order_relaxed);
      {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        processing_batch_ = false;
      }
      condition_.notify_all();
    }
  }

  bool stopping_;
  PipelineDepthFeedback pipeline_depth_;
  bool online_execution_ = false;
  std::map<uint64_t, OnlineClusterFeedback> online_feedback_;
  std::array<std::atomic<uint64_t>, SQLITE_PIPELINE_METRICS> pipeline_perf_;
  PublicationHistogram publication_histogram_;
  PublicationHistogram buffer_latency_histogram_;
#ifdef __linux__
  std::vector<RawIoUring::Operation> submission_operations_;
  std::vector<uint64_t> submission_tokens_;
  int wake_fd_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  std::deque<std::shared_ptr<PipelineBatch> > pipeline_batches_;
  bool pipeline_publication_dirty_ = true;
  std::map<uint64_t, Flight> flights_;
  std::map<std::pair<uint64_t, uint64_t>, uint64_t> pipeline_write_ranges_;
  std::set<std::tuple<uint64_t, uint64_t, uint64_t, uint64_t> > pipeline_write_keys_;
  uint64_t next_token_ = 1, inflight_bytes_ = 0;
  uint64_t next_diagnostic_plan_ = 1;
#endif
  mutable std::mutex queue_mutex_;
  std::condition_variable condition_;
  std::deque<Task> queue_;
  uint64_t case_epoch_ = 0; // Protected by queue_mutex_, advanced after drained prepareCase.
  std::mutex database_mutex_;
  sqlite3* db_;
  sqlite3_stmt* reset_statement_;
  sqlite3_stmt* write_statement_;
  sqlite3_stmt* adaptive_write_statement_;
  sqlite3_stmt* read_statement_;
  static constexpr size_t kMetadataReadBatch = 64;
  sqlite3_stmt* read_begin_statement_;
  std::vector<size_t> release_order_scratch_;
  sqlite3_stmt* begin_statement_;
  sqlite3_stmt* commit_statement_;
  sqlite3_stmt* rollback_statement_;
  std::map<uint64_t, int> files_;
  std::map<uint64_t, int> direct_files_;
#ifdef __linux__
  std::mutex ring_mutex_;
  RawIoUring ring_{kHostBatchExtents};
  std::map<int, int> fixed_file_indices_;
  std::vector<struct iovec> registered_utm_buffers_;
#endif
  uint64_t merge_limit_;
  uint64_t read_amplification_permille_;
  uint64_t copy_bandwidth_;
  uint64_t maximum_gap_;
  uint64_t merge_delay_budget_ns_;
  size_t adaptive_batch_min_;
  size_t adaptive_batch_max_;
  WriteBatchFeedback write_feedback_;
  std::map<uint64_t, ReadMergeFeedback> read_merge_feedback_;
  ReadMergeFeedback* pending_read_feedback_ = nullptr;
  uint64_t pending_read_started_ = 0, pending_read_bytes_ = 0;
  bool pending_read_merged_ = false;
  uint64_t merge_plan_cost_ns_ = 200, merge_completion_cost_ns_ = 200, candidate_cost_ns_ = 0;
  bool merge_calibrated_ = false;
  uint64_t calibrated_saved_ns_[2][2] = {};
  void load_merge_calibration() {
    const char* path = std::getenv("GROUP_PMP_SQLITE_MERGE_PROFILE");
    if (!path || !*path) return;
    FILE* file = std::fopen(path, "r");
    unsigned long long policy = 0, common = 0, batch = 0, costs[4] = {};
    unsigned cache = 0;
    bool valid = file && std::fscanf(file,
        "keystone-mixed-calibration-v1 %llu %llu %llu %u %llu %llu %llu %llu",
        &policy, &common, &batch, &cache, &costs[0], &costs[1], &costs[2], &costs[3]) == 8;
    if (file) {
      int c;
      while ((c = std::fgetc(file)) != EOF)
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t') valid = false;
      std::fclose(file);
    }
    valid = valid && policy == kGroupPmpSqliteExtentIoPolicyVersion &&
        common == kGroupPmpSqliteCommonPathVersion && batch == GROUP_PMP_SQLITE_VFS_BATCH_MAX &&
        cache == static_cast<unsigned>(configured_cache_mode());
    for (auto cost : costs) valid = valid && cost <= UINT64_C(1000000000);
    if (!valid) throw std::runtime_error("invalid/stale SQLite mixed-batch calibration profile");
    for (size_t read = 0; read < 2; ++read)
      for (size_t vector = 0; vector < 2; ++vector)
        calibrated_saved_ns_[read][vector] = costs[read * 2 + vector];
    merge_calibrated_ = true;
  }
  uint64_t read_saved_op_ns_ = env_u64("GROUP_PMP_SQLITE_MERGE_READ_SAVED_NS", 3500, 0, 1000000000);
  uint64_t write_saved_op_ns_ = env_u64("GROUP_PMP_SQLITE_MERGE_WRITE_SAVED_NS", 8500, 0, 1000000000);
  uint64_t extra_member_ns_ = env_u64("GROUP_PMP_SQLITE_MERGE_MEMBER_COST_NS", 400, 0, 100000);
  std::array<std::atomic<uint64_t>, SQLITE_READ100K_METRICS> read100k_;
  SparsePagePrecheck sparse_precheck_;
  // Reactor-owned scratch; live SQEs only reference their heap-owned plans.
  std::vector<Task*> candidate_scratch_, isolated_scratch_, ordered_scratch_;
  std::vector<uint8_t> join_scratch_;
  std::atomic<uint64_t> write_queue_depth_{kWriteBatchInitial * 2};
  std::atomic<uint64_t> adaptive_batch_target_;
  std::atomic<uint64_t> adaptive_collect_usec_;
  std::atomic<uint64_t> adaptive_queue_depth_;
  std::atomic<uint64_t> adaptive_gap_bytes_;
  std::atomic<uint64_t> ewma_bandwidth_bytes_per_sec_;
  std::atomic<uint64_t> ewma_request_latency_ns_;
  std::atomic<uint64_t> ewma_queue_wait_ns_;
  std::atomic<uint64_t> ewma_completion_latency_ns_;
  std::atomic<uint64_t> task_count_;
  std::atomic<uint64_t> batch_count_;
  std::atomic<uint64_t> queue_wait_ns_;
  std::atomic<uint64_t> writer_wait_ns_;
  std::atomic<uint64_t> read_service_ns_;
  std::atomic<uint64_t> write_service_ns_;
  std::atomic<uint64_t> control_service_ns_;
  std::atomic<uint64_t> commit_ns_;
  std::atomic<uint64_t> commit_count_;
  std::atomic<uint64_t> queue_depth_peak_;
  std::atomic<uint64_t> io_uring_submissions_;
  std::atomic<uint64_t> registered_file_operations_;
  std::atomic<uint64_t> registered_buffer_operations_;
  std::atomic<uint64_t> fixed_buffer_operations_;
  std::atomic<uint64_t> buffer_registration_attempts_;
  std::atomic<uint64_t> buffer_registration_failures_;
  std::atomic<uint64_t> direct_io_operations_;
  std::atomic<uint64_t> direct_alignment_fallback_operations_;
  std::atomic<uint64_t> posix_fallback_operations_;
  std::atomic<uint64_t> merged_io_count_;
  std::atomic<uint64_t> sparse_io_count_;
  std::atomic<uint64_t> useful_io_bytes_;
  std::atomic<uint64_t> physical_io_bytes_;
  std::atomic<uint64_t> logical_request_count_;
  std::atomic<uint64_t> physical_request_count_;
  std::atomic<uint64_t> deduplicated_request_count_;
  std::atomic<uint64_t> cache_full_hit_count_;
  std::atomic<uint64_t> cache_partial_hit_count_;
  std::atomic<uint64_t> cache_miss_count_;
  std::atomic<uint64_t> cache_hit_bytes_;
  std::atomic<uint64_t> collect_ns_;
  std::atomic<uint64_t> sort_ns_;
  std::atomic<uint64_t> cluster_ns_;
  std::atomic<uint64_t> write_overlap_check_ns_;
  std::atomic<uint64_t> write_overlap_checks_;
  std::atomic<uint64_t> write_disjoint_batches_;
  std::atomic<uint64_t> write_overlap_batches_;
  std::atomic<uint64_t> adaptive_write_grow_count_;
  std::atomic<uint64_t> adaptive_write_shrink_count_;
  std::atomic<uint64_t> adaptive_write_hold_count_;
  std::atomic<uint64_t> sequential_ready_single_batches_;
  std::atomic<uint64_t> sequential_ready_multi_batches_;
  std::atomic<uint64_t> sequential_ready_adjacent_pairs_;
  std::atomic<uint64_t> sequential_ready_nonadjacent_pairs_;
  std::atomic<uint64_t> random_sparse_fast_batches_;
  std::atomic<uint64_t> random_sparse_fast_requests_;
  std::atomic<uint64_t> random_planned_batches_;
  std::atomic<uint64_t> random_precheck_fallbacks_;
  std::atomic<uint64_t> random_precheck_ns_;
  std::atomic<uint64_t> random_local_plan_batches_;
  std::atomic<uint64_t> random_local_candidate_requests_;
  std::atomic<uint64_t> cache_fill_bytes_;
  std::atomic<uint64_t> cache_fill_ns_;
  std::atomic<uint64_t> cache_fill_skipped_bytes_;
  std::atomic<uint64_t> cache_admission_disables_;
  std::atomic<uint64_t> cache_admission_reenables_;
  std::atomic<uint64_t> readseq_initial_requests_;
  std::atomic<uint64_t> readseq_refill_peer_io_requests_;
  std::atomic<uint64_t> readseq_refill_peer_ready_requests_;
  std::atomic<uint64_t> readseq_refill_peer_idle_requests_;
  std::atomic<uint64_t> submit_ns_;
  std::atomic<uint64_t> disk_io_ns_;
  std::atomic<uint64_t> completion_wait_ns_;
  std::atomic<uint64_t> storage_sync_ns_;
  std::atomic<uint64_t> sequential_extent_count_;
  std::atomic<uint64_t> sequential_8mb_extent_count_;
  std::atomic<uint64_t> cross_worker_extent_count_;
  std::atomic<uint64_t> utm_copy_ns_;
  std::atomic<uint64_t> completion_publish_ns_;
  std::atomic<uint64_t> wakeup_ns_;
  std::atomic<uint64_t> submit_to_host_dequeue_ns_;
  std::atomic<uint64_t> host_dequeue_to_io_submit_ns_;
  std::atomic<uint64_t> io_submit_to_complete_ns_;
  std::atomic<uint64_t> io_complete_to_publish_ns_;
  std::atomic<uint64_t> publish_to_host_resume_request_ns_;
  std::atomic<uint64_t> wakeup_eligible_to_host_resume_request_ns_;
  std::atomic<uint64_t> host_resume_ioctl_ns_;
  std::atomic<uint64_t> completion_wakeup_count_;
  std::atomic<uint64_t> completion_ready_before_wait_count_;
  std::atomic<uint64_t> window_first_enqueue_ns_;
  std::atomic<uint64_t> window_last_completion_ns_;
  std::atomic<uint64_t> max_queue_wait_ns_;
  std::atomic<uint64_t> max_batch_service_ns_;
  std::atomic<uint64_t> max_completion_latency_ns_;
  std::map<CipherCacheKey, CipherCacheEntry> cipher_cache_;
  std::map<uint64_t, CacheAdmission> cache_admission_;
  bool processing_batch_;
  bool utm_buffers_registered_;
  std::thread worker_;
};

SqliteExtentIoService::SqliteExtentIoService() : impl_(new Impl()) {}
SqliteExtentIoService::~SqliteExtentIoService() {}

bool SqliteExtentIoService::planIntents(const group_pmp_sqlite_intent_plan& plan,
                                        uint8_t* utm, size_t utm_size) {
  return impl_->planIntents(plan, utm, utm_size);
}

bool SqliteExtentIoService::submit(
    const struct group_pmp_sqlite_vfs_request& request,
    uint8_t* utm, size_t utm_size,
    const std::shared_ptr<SqliteAsyncCompletion>& completion) {
  return impl_->submitBatch(&request, 1, utm, utm_size, completion);
}

bool SqliteExtentIoService::submitBatch(
    const struct group_pmp_sqlite_vfs_request* requests, uint64_t count,
    uint8_t* utm, size_t utm_size,
    const std::shared_ptr<SqliteAsyncCompletion>& completion) {
  return impl_->submitBatch(requests, count, utm, utm_size, completion);
}

SqliteIoPerfSnapshot SqliteExtentIoService::snapshot() const {
  return impl_->snapshot();
}

SqliteIoPerfSnapshot SqliteExtentIoService::drainAndSnapshot() {
  return impl_->drainAndSnapshot();
}

bool SqliteExtentIoService::submitReadPair(
    const struct group_pmp_sqlite_vfs_request* requests,
    uint8_t* utm, size_t utm_size,
    const std::shared_ptr<SqliteAsyncCompletion>* completions) {
  if (!completions)
    return false;
  return impl_->submitBatch(requests, 2, utm, utm_size,
                             std::shared_ptr<SqliteAsyncCompletion>(), completions);
}

bool SqliteExtentIoService::resetPerf() { return impl_->resetPerf(); }

void SqliteExtentIoService::cleanup_case(uint64_t worker_count,
                                         uint64_t workload) {
  impl_->cleanup_case(worker_count, workload);
}

bool SqliteExtentIoService::prepareCase(uint64_t file_id,
                                        uint8_t* const* utms,
                                        const size_t* utm_sizes,
                                        size_t count) {
  return impl_->prepareCase(file_id, utms, utm_sizes, count);
}

void SqliteExtentIoService::clearRegisteredUtmBuffers() {
  impl_->clearRegisteredUtmBuffers();
}

void SqliteExtentIoService::recordWakeupTimeline(uint64_t publish_ns,
                                                 uint64_t eligible_ns,
                                                 uint64_t wake_ns,
                                                 uint64_t resume_ns) {
  impl_->recordWakeupTimeline(publish_ns, eligible_ns, wake_ns, resume_ns);
}

SqliteExtentIoService& sqlite_async_io_service() {
  static SqliteExtentIoService service;
  return service;
}

uint64_t sqlite_extent_io_policy_version() {
  return kGroupPmpSqliteExtentIoPolicyVersion;
}

#ifdef __linux__
static int sqlite_io_cross_buffer_probe(RawIoUring* ring, int fd,
                                        uint8_t* first, uint8_t* second,
                                        unsigned iterations) {
  struct Sample {
    uint64_t plan, submit, publish[2], full;
  };
  std::vector<Sample> samples[2][2];
  std::memset(first, 0x5a, 4096);
  std::memset(second, 0xa5, 4096);
  if (pwrite(fd, first, 4096, 0) != 4096 ||
      pwrite(fd, second, 4096, 4096) != 4096)
    return 1;

  for (unsigned sample = 0; sample < iterations + 5; ++sample) {
    for (unsigned turn = 0; turn < 4; ++turn) {
      const unsigned mode = (turn + sample) % 4;
      const bool read = mode >= 2, merged = (mode & 1) != 0;
      std::memset(first, read ? 0 : 0x5a, 4096);
      std::memset(second, read ? 0 : 0xa5, 4096);
      const uint64_t begin = now_ns();
      std::array<InlineOneList<iovec>, 2> vectors;
      std::vector<RawIoUring::Operation> operations;
      operations.reserve(merged ? 1 : 2);
      for (unsigned buffer = 0; buffer < 2; ++buffer) {
        const unsigned owner = merged ? 0 : buffer;
        vectors[owner].push_back({buffer ? second : first, 4096});
        if (merged && buffer == 0) continue;
        RawIoUring::Operation operation;
        operation.fd = fd;
        operation.fixed_file_index = 0;
        operation.fixed_buffer_index = merged ? -1 : static_cast<int>(buffer);
        operation.offset = merged ? 0 : buffer * 4096;
        operation.vectors = &vectors[owner];
        operation.expected = merged ? 8192 : 4096;
        operation.read = read;
        operations.push_back(operation);
      }
      const std::vector<uint64_t> tokens = merged ?
          std::vector<uint64_t>{1} : std::vector<uint64_t>{1, 2};
      const uint64_t planned = now_ns();
      int error = 0;
      const size_t accepted = ring->submitAsync(operations, tokens, &error);
      const uint64_t submitted = now_ns();
      if (accepted != operations.size()) {
        while (ring->inflight()) {
          if (!ring->waitAsync()) return 1;
          (void)ring->reapAsync();
        }
        std::fprintf(stderr,
            "[sqlite-io-probe] cross-buffer submission failed: accepted=%zu error=%d\n",
            accepted, error);
        return 1;
      }
      uint64_t published[2] = {0, 0};
      while (!published[0] || !published[1]) {
        if (!ring->waitAsync()) return 1;
        const auto completions = ring->reapAsync();
        const uint64_t observed = now_ns();
        for (const auto& completion : completions) {
          if (completion.result != static_cast<int>(merged ? 8192 : 4096) ||
              completion.token == 0 || completion.token > operations.size())
            return 1;
          if (merged) {
            if (published[0] || published[1]) return 1;
            published[0] = observed;
            published[1] = observed;
          } else {
            const size_t buffer = static_cast<size_t>(completion.token - 1);
            if (published[buffer]) return 1;
            published[buffer] = observed;
          }
        }
      }
      const uint64_t finished = now_ns();
      if (read) {
        for (size_t index = 0; index < 4096; ++index)
          if (first[index] != 0x5a || second[index] != 0xa5)
            return 1;
      }
      if (sample >= 5)
        samples[read ? 1 : 0][merged ? 1 : 0].push_back(Sample{
            planned - begin, submitted - planned,
            {published[0] - begin, published[1] - begin}, finished - begin});
    }
  }

  const auto percentile = [](std::vector<uint64_t> values, unsigned percent) {
    std::sort(values.begin(), values.end());
    return values[(values.size() * percent + 99) / 100 - 1];
  };
  const auto field = [&](const std::vector<Sample>& values, unsigned which,
                         unsigned percent) {
    std::vector<uint64_t> durations;
    durations.reserve(values.size());
    for (const auto& value : values)
      durations.push_back(which == 0 ? value.plan : which == 1 ? value.submit :
          which == 2 ? value.publish[0] : which == 3 ? value.publish[1] : value.full);
    return percentile(durations, percent);
  };
  std::fprintf(stderr,
      "[sqlite-io-probe] cross-buffer scope: two registered 2MB regions, "
      "two arrived 4KB requests, buffered hot file; plan=operation construction "
      "only, publish=Host CQE observation; no enclave scheduling or cluster search\n");
  std::printf("scenario,operation,path,data_ops,samples,representation_plan_median_ns,"
              "submit_median_ns,buffer0_publish_median_ns,buffer1_publish_median_ns,"
              "buffer0_publish_p95_ns,buffer1_publish_p95_ns,full_median_ns,full_p95_ns\n");
  for (unsigned read = 0; read < 2; ++read)
    for (unsigned merged = 0; merged < 2; ++merged) {
      const auto& values = samples[read][merged];
      std::printf("cross-buffer,%s,%s,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
          read ? "read" : "write", merged ? "merged-readv-writev" : "discrete-fixed",
          merged ? 1 : 2, iterations,
          static_cast<unsigned long long>(field(values, 0, 50)),
          static_cast<unsigned long long>(field(values, 1, 50)),
          static_cast<unsigned long long>(field(values, 2, 50)),
          static_cast<unsigned long long>(field(values, 3, 50)),
          static_cast<unsigned long long>(field(values, 2, 95)),
          static_cast<unsigned long long>(field(values, 3, 95)),
          static_cast<unsigned long long>(field(values, 4, 50)),
          static_cast<unsigned long long>(field(values, 4, 95)));
    }
  for (unsigned read = 0; read < 2; ++read) {
    const auto& discrete = samples[read][0];
    const auto& merged = samples[read][1];
    std::vector<int64_t> full_saved, plan_extra, buffer0_delay, buffer1_delay;
    for (size_t index = 0; index < discrete.size(); ++index) {
      full_saved.push_back(static_cast<int64_t>(discrete[index].full) -
                           static_cast<int64_t>(merged[index].full));
      plan_extra.push_back(static_cast<int64_t>(merged[index].plan) -
                           static_cast<int64_t>(discrete[index].plan));
      buffer0_delay.push_back(static_cast<int64_t>(merged[index].publish[0]) -
                              static_cast<int64_t>(discrete[index].publish[0]));
      buffer1_delay.push_back(static_cast<int64_t>(merged[index].publish[1]) -
                              static_cast<int64_t>(discrete[index].publish[1]));
    }
    const auto signed_median = [](std::vector<int64_t> values) {
      std::sort(values.begin(), values.end());
      return values[(values.size() * 50 + 99) / 100 - 1];
    };
    const int64_t full_gain = signed_median(full_saved);
    const int64_t plan_cost = signed_median(plan_extra);
    const int64_t first_delay = signed_median(buffer0_delay);
    const int64_t second_delay = signed_median(buffer1_delay);
    std::printf("cross-buffer-delta,%s,full_saved_median_ns=%lld,"
                "plan_extra_median_ns=%lld,buffer0_extra_publish_median_ns=%lld,"
                "buffer1_extra_publish_median_ns=%lld,host_group_gain=%d,"
                "both_buffers_no_median_delay=%d\n",
        read ? "read" : "write",
        static_cast<long long>(full_gain),
        static_cast<long long>(plan_cost),
        static_cast<long long>(first_delay),
        static_cast<long long>(second_delay),
        full_gain > 0 ? 1 : 0,
        first_delay <= 0 && second_delay <= 0 ? 1 : 0);
  }
  return 0;
}
#endif

struct CalibrationPublicationPair {
  uint64_t discrete[2];
  uint64_t merged[2];
};

struct CalibrationTailGuard {
  unsigned windows = 0;
  unsigned bad_windows[2] = {};
  int64_t worst_window_p95_excess_ns[2] = {};
  bool persistent = false;
};

CalibrationTailGuard paired_publication_guard(
    const std::vector<CalibrationPublicationPair>& pairs) {
  CalibrationTailGuard guard;
  if (pairs.empty()) return guard;
  guard.windows = static_cast<unsigned>(std::min<size_t>(3, pairs.size()));
  for (unsigned window = 0; window < guard.windows; ++window) {
    const size_t first = pairs.size() * window / guard.windows;
    const size_t last = pairs.size() * (window + 1) / guard.windows;
    for (unsigned buffer = 0; buffer < 2; ++buffer) {
      std::vector<uint64_t> discrete, merged;
      discrete.reserve(last - first);
      merged.reserve(last - first);
      for (size_t i = first; i < last; ++i) {
        discrete.push_back(pairs[i].discrete[buffer]);
        merged.push_back(pairs[i].merged[buffer]);
      }
      std::sort(discrete.begin(), discrete.end());
      std::sort(merged.begin(), merged.end());
      const size_t rank = (discrete.size() * 95 + 99) / 100 - 1;
      const uint64_t limit = discrete[rank] + discrete[rank] / 10;
      const int64_t p95 = static_cast<int64_t>(merged[rank]) -
                          static_cast<int64_t>(limit);
      guard.worst_window_p95_excess_ns[buffer] =
          std::max(guard.worst_window_p95_excess_ns[buffer], p95);
      guard.bad_windows[buffer] += p95 > 0;
    }
  }
  const unsigned required = guard.windows / 2 + 1;
  guard.persistent = guard.bad_windows[0] >= required ||
                     guard.bad_windows[1] >= required;
  return guard;
}

// The microbenchmark deliberately stops at Host ring publication: it includes
// the production planner and publisher, not SQLite metadata or enclave wakeup.
int sqlite_io_mixed_batch_probe(unsigned iterations, const char* profile) {
#ifdef __linux__
  struct HostAffinity {
    cpu_set_t previous;
    bool changed = false;
    ~HostAffinity() { if (changed) (void)sched_setaffinity(0, sizeof(previous), &previous); }
  } affinity;
  if (profile) {
    cpu_set_t host; CPU_ZERO(&host); CPU_SET(0, &host);
    if (sched_getaffinity(0, sizeof(affinity.previous), &affinity.previous) ||
        sched_setaffinity(0, sizeof(host), &host)) {
      std::fprintf(stderr, "[sqlite-io-probe] cannot calibrate on Host CPU0: errno=%d\n", errno);
      return 1;
    }
    affinity.changed = true;
  }
  struct RestoreEnv {
    const char* name;
    bool present;
    std::string value;
    explicit RestoreEnv(const char* n) : name(n), present(std::getenv(n) != nullptr),
        value(present ? std::getenv(n) : "") {}
    ~RestoreEnv() { if (present) setenv(name, value.c_str(), 1); else unsetenv(name); }
  } mode_env("GROUP_PMP_SQLITE_IO_MODE"), cluster_env("GROUP_PMP_SQLITE_CLUSTER_MODE"),
    cache_env("GROUP_PMP_SQLITE_CACHE_MODE"), profile_env("GROUP_PMP_SQLITE_MERGE_PROFILE");
  unsetenv("GROUP_PMP_SQLITE_MERGE_PROFILE");
  if (!profile) setenv("GROUP_PMP_SQLITE_CACHE_MODE", "hot", 1);
  const CacheMode cache_mode = configured_cache_mode();
  const char* directory = std::getenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  std::string path = std::string(directory && directory[0] ? directory : "/tmp") +
      "/keystone-sqlite-mixed-probe-XXXXXX";
  std::vector<char> filename(path.begin(), path.end()); filename.push_back(0);
  const int fd = mkstemp(filename.data());
  if (fd < 0) return 1;
  unlink(filename.data());
  struct Resources {
    int fd;
    uint8_t* utm[2] = {nullptr, nullptr};
    explicit Resources(int f) : fd(f) {}
    ~Resources() { close(fd); for (auto p : utm) free(p); }
  } resources(fd);
  for (auto& p : resources.utm)
    if (posix_memalign(reinterpret_cast<void**>(&p), 4096,
                       GROUP_PMP_SQLITE_VFS_UTM_BYTES)) return 1;
  // Mixed pairs and isolated requests from two full descriptor rings. Refills
  // use the production depth (64), rather than one tiny all-at-once submission.
  // Reverse owner for alternating pairs; no sorting or future addresses in Async.
  constexpr size_t count = GROUP_PMP_SQLITE_VFS_BATCH_MAX * 2;
  constexpr size_t blocks = count / 4;
  static_assert(count % 4 == 0, "mixed calibration needs paired descriptors");
  std::array<Task, count> prototype;
  std::vector<Task*> input;
  for (size_t i = 0; i < count; ++i) {
    Task& t = prototype[i];
    const size_t block = i / 4, part = i % 4;
    const size_t owner = (i + block) % 2;
    t.utm = resources.utm[owner]; t.utm_size = GROUP_PMP_SQLITE_VFS_UTM_BYTES;
    t.request.file_id = t.stored_file_id = 1;
    t.request.run_id = owner + 1; t.request.worker_index = owner;
    t.request.worker_count = 2; t.request.task_id = i + 1;
    t.request.sequence = i + 1; t.case_epoch = 1;
    t.request.file_offset = t.storage_offset =
        ((block * 7 % blocks) * 16 + (part < 2 ? part : part * 4)) * 4096;
    t.request.length = t.storage_length = t.request.logical_size = 4096;
    t.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + (i / 2) * 4096;
    t.request.buffer_id = 0; t.request.ring_slot = 0; t.request.descriptor_id = i;
    t.request.reserved[0] = GROUP_PMP_SQLITE_STORE_RING | GROUP_PMP_SQLITE_STORE_MEASURED;
    std::memset(t.data(), static_cast<int>(i + 1), 4096);
    if (pwrite(fd, t.data(), 4096, t.storage_offset) != 4096) return 1;
    input.push_back(&t);
  }
  struct Sample { uint64_t full, plan, submit, publish[2], release[2], ops; };
  const char* names[] = {"discrete-fixed", "plan-only", "cluster-merge"};
  SqliteExtentIoService::Impl service(false);
  if (!service.ring_.available()) return 77;
  // Calibrate the benefit gate, so exercise legal candidates even when the
  // previous board estimate would reject them. Safety/delay limits still apply.
  service.read_saved_op_ns_ = service.write_saved_op_ns_ = UINT64_C(1000000);
  if (fdatasync(fd)) return 1;
  if (cache_mode == CacheMode::kDirect && fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_DIRECT)) return 1;
  const int owned_fd = dup(fd);
  if (owned_fd < 0) return 1;
  (cache_mode == CacheMode::kDirect ? service.direct_files_ : service.files_)[1] = owned_fd;
  service.prepare_registered_buffers(input);
  service.prepare_registered_files();
  if (!service.utm_buffers_registered_ || service.fixed_file_indices_.empty()) return 77;
  uint64_t calibrated_costs[2][2] = {};
  for (bool cross_buffer : {false, true}) {
  std::vector<Sample> samples[2][3];
  for (unsigned sample = 0; sample < iterations + 5; ++sample) {
    for (unsigned turn = 0; turn < 6; ++turn) {
      const unsigned mode = (sample + turn) % 6, strategy = mode % 3;
      const bool read = mode >= 3;
      setenv("GROUP_PMP_SQLITE_IO_MODE", strategy ? "adaptive-extent" : "async-no-extent", 1);
      setenv("GROUP_PMP_SQLITE_CLUSTER_MODE", strategy == 1 ? "plan-only" : "merge", 1);
      auto tasks = prototype;
      size_t buffer_position[2] = {};
      input.clear();
      std::array<std::vector<Task*>, 2> by_buffer;
      std::shared_ptr<SqliteAsyncCompletion> completions[2] = {
          std::make_shared<SqliteAsyncCompletion>(count / 2),
          std::make_shared<SqliteAsyncCompletion>(count / 2)};
      for (auto& t : tasks) {
        const size_t i = static_cast<size_t>(t.request.task_id - 1);
        const size_t owner = cross_buffer ? (i + i / 4) % 2 : (i / 4 + (i % 4) / 2) % 2;
        t.utm = resources.utm[owner];
        t.request.descriptor_id = buffer_position[owner];
        t.request.buffer_offset = GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET + buffer_position[owner]++ * 4096;
        t.request.run_id = owner + 1; t.request.worker_index = owner;
        t.request.operation = read ? GROUP_PMP_SQLITE_VFS_OP_READ : GROUP_PMP_SQLITE_VFS_OP_WRITE;
        t.request.workload = read ? GROUP_PMP_SQLITE_READRANDOM : GROUP_PMP_SQLITE_FILLRANDOM;
        t.completion = completions[t.request.worker_index];
        std::memset(t.data(), read ? 0 : static_cast<int>(t.request.task_id), 4096);
        by_buffer[t.request.worker_index].push_back(&t);
      }
      // Production captures each arrived ring as a unit, not interleaved by
      // file locality. In particular an early isolated tail must stay early.
      for (const auto& buffer : by_buffer) input.insert(input.end(), buffer.begin(), buffer.end());
      for (auto p : resources.utm) {
        auto* header = reinterpret_cast<group_pmp_sqlite_vfs_ring_header*>(
            p + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0));
        std::memset(header, 0, sizeof(*header));
        header->magic = GROUP_PMP_SQLITE_VFS_RING_MAGIC;
        header->version = GROUP_PMP_SQLITE_VFS_VERSION;
        header->producer = header->consumer = count / 2;
      }
      PipelineBatch plan;
      if (cache_mode != CacheMode::kHot &&
          (fdatasync(fd) || posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED))) return 1;
      const uint64_t begin = now_ns();
      for (auto& t : tasks) t.enqueue_ns = t.dequeue_ns = begin;
      if (!service.execute_io(input, true, &plan)) return 1;
      std::vector<uint64_t> tokens(plan.operations.size());
      for (size_t i = 0; i < tokens.size(); ++i) tokens[i] = i + 1;
      const uint64_t planned = now_ns();
      int error = 0;
      size_t next = 0;
      uint64_t submit_total = 0;
      const auto refill = [&]() {
        const size_t available = service.ring_.inflight() < 64 ? 64 - service.ring_.inflight() : 0;
        const size_t amount = std::min(available, plan.operations.size() - next);
        if (!amount) return true;
        std::vector<RawIoUring::Operation> ready(plan.operations.begin() + next, plan.operations.begin() + next + amount);
        std::vector<uint64_t> ids(tokens.begin() + next, tokens.begin() + next + amount);
        const uint64_t at = now_ns();
        const size_t accepted = service.ring_.submitAsync(ready, ids, &error);
        submit_total += now_ns() - at;
        next += accepted;
        return accepted == amount;
      };
      const bool accepted = refill();
      if (!accepted) {
        while (service.ring_.inflight()) {
          if (!service.ring_.waitAsync()) return 1;
          (void)service.ring_.reapAsync();
        }
        std::fprintf(stderr, "[sqlite-io-probe] mixed submit failed: accepted=%zu error=%d\n", next, error);
        return 1;
      }
      size_t pending[2] = {count / 2, count / 2};
      uint64_t published[2] = {}, last_cqe[2] = {};
      size_t remaining = plan.operations.size();
      std::vector<Task*> ready;
      while (remaining) {
        if (!service.ring_.waitAsync()) return 1;
        const auto cqes = service.ring_.reapAsync();
        const uint64_t observed = now_ns();
        bool invalid = false;
        for (const auto& cqe : cqes) {
          if (!cqe.token || cqe.token > plan.operations.size()) return 1;
          const size_t operation = cqe.token - 1;
          auto& group = plan.groups[plan.operation_groups[operation]];
          const int result = cqe.result == static_cast<int>(plan.operations[operation].expected) ? 0 : -EIO;
          invalid = invalid || result;
          for (Task* t : group.tasks) {
            const size_t owner = t->request.worker_index;
            if (!pending[owner]) return 1;
            --pending[owner]; t->io_complete_ns = last_cqe[owner] = observed;
            t->result = result;
          }
          --remaining;
        }
        ready.clear();
        for (unsigned owner = 0; owner < 2; ++owner)
          if (!pending[owner] && !published[owner])
            ready.insert(ready.end(), by_buffer[owner].begin(), by_buffer[owner].end());
        if (!ready.empty()) service.publishBatch(ready);
        for (unsigned owner = 0; owner < 2; ++owner)
          if (!pending[owner] && !published[owner])
            published[owner] = completions[owner]->publishedAtNs();
        if (invalid) {
          while (service.ring_.inflight()) {
            if (!service.ring_.waitAsync()) return 1;
            (void)service.ring_.reapAsync();
          }
          return 1;
        }
        if (!refill()) return 1;
      }
      const uint64_t finished = now_ns();
      for (auto utm : resources.utm) {
        const auto* header = reinterpret_cast<const group_pmp_sqlite_vfs_ring_header*>(
            utm + GROUP_PMP_SQLITE_VFS_RING_SLOT_OFFSET(0));
        if (header->completion_count != count / 2) return 1;
      }
      for (const auto& t : tasks) {
        if (!t.completion->isComplete() || !t.publish_ns) return 1;
        if (read) for (size_t b = 0; b < 4096; ++b)
          if (t.data()[b] != static_cast<uint8_t>(t.request.task_id)) return 1;
      }
      if (sample >= 5) samples[read][strategy].push_back({finished - begin,
          planned - begin, submit_total,
          {published[0] - begin, published[1] - begin},
          {published[0] - last_cqe[0], published[1] - last_cqe[1]}, plan.operations.size()});
    }
  }
  const auto percentile = [](std::vector<uint64_t> values, unsigned p) {
    std::sort(values.begin(), values.end()); return values[(values.size() * p + 99) / 100 - 1];
  };
  const char* scenario = cross_buffer ? "mixed-cross-buffer" : "mixed-same-buffer";
  std::printf("[sqlite-io-probe] %s scope: %zu arrived 4KB requests, pairs+isolated, depth=64; production planner/vector preparation/publisher; legal candidates forced for cost calibration, safety budgets retained; cache=%u; excludes SQLite metadata, enclave and lane scheduling\n", scenario, count, static_cast<unsigned>(cache_mode));
  std::puts("scenario,operation,path,logical_ops,host_ops_median,samples,plan_median_ns,submit_median_ns,buffer0_publish_p95_ns,buffer1_publish_p95_ns,last_cqe_to_publish_p95_ns,full_median_ns,full_p95_ns");
  for (unsigned read = 0; read < 2; ++read) {
    uint64_t medians[3] = {}, tails[3][2] = {}, counts[3] = {}, plan_medians[3] = {};
    for (unsigned strategy = 0; strategy < 3; ++strategy) {
      std::vector<uint64_t> full, plan, submit, pub0, pub1, release, ops;
      for (const auto& s : samples[read][strategy]) {
        full.push_back(s.full); plan.push_back(s.plan); submit.push_back(s.submit);
        pub0.push_back(s.publish[0]); pub1.push_back(s.publish[1]); ops.push_back(s.ops);
        release.push_back(std::max(s.release[0], s.release[1]));
      }
      medians[strategy] = percentile(full, 50); counts[strategy] = percentile(ops, 50);
      plan_medians[strategy] = percentile(plan, 50);
      tails[strategy][0] = percentile(pub0, 95);
      tails[strategy][1] = percentile(pub1, 95);
      std::printf("%s,%s,%s,%zu,%llu,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
          scenario, read ? "read" : "write", names[strategy], count, (unsigned long long)counts[strategy], iterations,
          (unsigned long long)plan_medians[strategy], (unsigned long long)percentile(submit, 50),
          (unsigned long long)percentile(pub0, 95), (unsigned long long)percentile(pub1, 95),
          (unsigned long long)percentile(release, 95), (unsigned long long)medians[strategy],
          (unsigned long long)percentile(full, 95));
    }
    std::vector<CalibrationPublicationPair> pairs;
    pairs.reserve(samples[read][0].size());
    for (size_t sample = 0; sample < samples[read][0].size(); ++sample) {
      const Sample& discrete = samples[read][0][sample];
      const Sample& merged = samples[read][2][sample];
      pairs.push_back({{discrete.publish[0], discrete.publish[1]},
                       {merged.publish[0], merged.publish[1]}});
      if (profile)
        std::printf("mixed-paired-sample,%s,%s,%zu,discrete_buffer0_ns=%llu,merged_buffer0_ns=%llu,delta_buffer0_ns=%lld,discrete_buffer1_ns=%llu,merged_buffer1_ns=%llu,delta_buffer1_ns=%lld\n",
            scenario, read ? "read" : "write", sample,
            (unsigned long long)discrete.publish[0],
            (unsigned long long)merged.publish[0],
            (long long)(static_cast<int64_t>(merged.publish[0]) -
                        static_cast<int64_t>(discrete.publish[0])),
            (unsigned long long)discrete.publish[1],
            (unsigned long long)merged.publish[1],
            (long long)(static_cast<int64_t>(merged.publish[1]) -
                        static_cast<int64_t>(discrete.publish[1])));
    }
    const CalibrationTailGuard tail_guard = paired_publication_guard(pairs);
    const bool gain = counts[2] < counts[0] && medians[2] < medians[0] &&
        !tail_guard.persistent;
    const uint64_t saved = counts[0] > counts[2] ? counts[0] - counts[2] : 0;
    const uint64_t execution0 = medians[1] > plan_medians[1] ? medians[1] - plan_medians[1] : 0;
    const uint64_t execution1 = medians[2] > plan_medians[2] ? medians[2] - plan_medians[2] : 0;
    const uint64_t calibrated = gain && saved && execution0 > execution1 ?
        (execution0 - execution1) / saved * 3 / 4 : 0;
    calibrated_costs[read][cross_buffer] = calibrated;
    const char* reason = counts[2] >= counts[0] ? "no_operations_saved" :
        medians[2] >= medians[0] ? "full_host_time" :
        tail_guard.persistent ? "paired_buffer_publish_p95" :
        execution0 <= execution1 ? "no_execution_saving" : "accepted";
    std::printf("mixed-calibration,%s,%s,host_group_gain=%d,recommended_saved_op_ns=%llu,reason=%s,discrete_full_median_ns=%llu,merged_full_median_ns=%llu,discrete_buffer0_p95_ns=%llu,merged_buffer0_p95_ns=%llu,discrete_buffer1_p95_ns=%llu,merged_buffer1_p95_ns=%llu,paired_windows=%u,paired_buffer0_bad_windows=%u,paired_buffer1_bad_windows=%u,paired_buffer0_worst_p95_excess_ns=%lld,paired_buffer1_worst_p95_excess_ns=%lld,auto_applied=0\n",
        scenario, read ? "read" : "write", gain ? 1 : 0,
        (unsigned long long)calibrated, reason,
        (unsigned long long)medians[0], (unsigned long long)medians[2],
        (unsigned long long)tails[0][0], (unsigned long long)tails[2][0],
        (unsigned long long)tails[0][1], (unsigned long long)tails[2][1],
        tail_guard.windows, tail_guard.bad_windows[0], tail_guard.bad_windows[1],
        (long long)tail_guard.worst_window_p95_excess_ns[0],
        (long long)tail_guard.worst_window_p95_excess_ns[1]);
  }
  }
  if (profile) {
    const std::string temporary = std::string(profile) + ".tmp";
    FILE* output = std::fopen(temporary.c_str(), "w");
    if (!output) return 1;
    bool ok = std::fprintf(output, "keystone-mixed-calibration-v1 %llu %llu %llu %u %llu %llu %llu %llu\n",
        (unsigned long long)kGroupPmpSqliteExtentIoPolicyVersion,
        (unsigned long long)kGroupPmpSqliteCommonPathVersion,
        (unsigned long long)GROUP_PMP_SQLITE_VFS_BATCH_MAX, static_cast<unsigned>(cache_mode),
        (unsigned long long)calibrated_costs[0][0], (unsigned long long)calibrated_costs[0][1],
        (unsigned long long)calibrated_costs[1][0], (unsigned long long)calibrated_costs[1][1]) > 0;
    ok = std::fclose(output) == 0 && ok;
    if (!ok || std::rename(temporary.c_str(), profile)) { std::remove(temporary.c_str()); return 1; }
    std::printf("[sqlite-io-probe] calibrated profile=%s scope=random-4KB host_cpu=0 (zero cost disables an unprofitable representation; other sizes retain their existing gate)\n", profile);
  }
  return 0;
#else
  (void)iterations; (void)profile;
  return 77;
#endif
}

int sqlite_io_path_probe(unsigned iterations) {
#ifdef __linux__
  RawIoUring ring;
  if (!ring.available()) {
    std::fprintf(stderr, "[sqlite-io-probe] io_uring unavailable: errno=%d\n", errno);
    return 77;
  }
  const char* directory = std::getenv("GROUP_PMP_SQLITE_STORAGE_DIR");
  std::string path = std::string(directory && directory[0] ? directory : "/tmp") +
      "/keystone-sqlite-io-probe-XXXXXX";
  std::vector<char> filename(path.begin(), path.end());
  filename.push_back('\0');
  int fd = mkstemp(filename.data());
  if (fd < 0) return 1;
  unlink(filename.data());
  void* first = nullptr;
  void* second = nullptr;
  const bool allocated = posix_memalign(&first, 4096, 2000000) == 0 &&
      posix_memalign(&second, 4096, 2000000) == 0;
  const auto cleanup = [&]() {
    ring.unregisterBuffers();
    close(fd);
    free(first);
    free(second);
  };
  if (!allocated || ftruncate(fd, 2000000) != 0) {
    cleanup();
    return 1;
  }
  std::memset(first, 0x5a, 2000000);
  std::memset(second, 0xa5, 2000000);
  if (pwrite(fd, first, 16384, 0) != 16384 ||
      !ring.registerFiles(std::vector<int>(1, fd)) ||
      !ring.registerBuffers(std::vector<iovec>{{first, 2000000}, {second, 2000000}})) {
    std::fprintf(stderr, "[sqlite-io-probe] registered I/O unavailable: errno=%d\n", errno);
    cleanup();
    return 77;
  }
  struct ProbeStats {
    std::vector<uint64_t> full, submit, completion;
  } stats[2][3];
  const char* names[] = {"discrete-fixed", "merged-readv-writev", "merged-fixed"};
  for (unsigned sample = 0; sample < iterations + 5; ++sample) {
    for (unsigned turn = 0; turn < 6; ++turn) {
      const unsigned mode = (turn + sample) % 6;
      const bool read = mode >= 3;
      const unsigned strategy = mode % 3;
      const uint64_t begin = now_ns();
      std::array<InlineOneList<iovec>, 4> vectors;
      std::vector<RawIoUring::Operation> operations;
      operations.reserve(strategy == 0 ? 4 : 1);
      for (unsigned part = 0; part < 4; ++part) {
        const unsigned owner = strategy == 0 ? part : 0;
        if (strategy == 2 && part != 0) continue;
        vectors[owner].push_back({static_cast<uint8_t*>(first) + part * 4096,
                                  strategy == 2 ? size_t(16384) : size_t(4096)});
        if (strategy == 1 && part != 3) continue;
        RawIoUring::Operation op;
        op.fd = fd;
        op.fixed_file_index = 0;
        op.fixed_buffer_index = strategy == 1 ? -1 : 0;
        op.offset = strategy == 0 ? part * 4096 : 0;
        op.vectors = &vectors[owner];
        op.expected = strategy == 0 ? 4096 : 16384;
        op.read = read;
        operations.push_back(op);
      }
      std::vector<int> results;
      uint64_t submitted_ns = 0, completed_ns = 0;
      if (!ring.submit(operations, &results, &submitted_ns, &completed_ns)) {
        std::fprintf(stderr, "[sqlite-io-probe] submit failed: errno=%d\n", errno);
        cleanup();
        return 1;
      }
      std::array<int, 4> child_status{};
      for (unsigned part = 0; part < 4; ++part) {
        const int result = results[strategy == 0 ? part : 0];
        child_status[part] = result == static_cast<int>(
            strategy == 0 ? 4096 : 16384) ? 0 : -EIO;
      }
      const uint64_t full_ns = now_ns() - begin;
      if (std::any_of(child_status.begin(), child_status.end(),
                      [](int status) { return status != 0; })) {
        cleanup();
        return 1;
      }
      if (sample >= 5) {
        auto& result = stats[read ? 1 : 0][strategy];
        result.full.push_back(full_ns);
        result.submit.push_back(submitted_ns);
        result.completion.push_back(completed_ns);
      }
    }
  }
  const auto percentile = [](std::vector<uint64_t> values, unsigned percent) {
    std::sort(values.begin(), values.end());
    return values[(values.size() * percent + 99) / 100 - 1];
  };
  std::printf("operation,path,data_ops,samples,full_median_ns,full_p95_ns,submit_median_ns,completion_median_ns\n");
  for (unsigned read = 0; read < 2; ++read)
    for (unsigned strategy = 0; strategy < 3; ++strategy) {
      const auto& result = stats[read][strategy];
      std::printf("%s,%s,%u,%u,%llu,%llu,%llu,%llu\n",
          read ? "read" : "write", names[strategy], strategy == 0 ? 4 : 1,
          iterations,
          static_cast<unsigned long long>(percentile(result.full, 50)),
          static_cast<unsigned long long>(percentile(result.full, 95)),
          static_cast<unsigned long long>(percentile(result.submit, 50)),
          static_cast<unsigned long long>(percentile(result.completion, 50)));
    }
  const int cross_result = sqlite_io_cross_buffer_probe(
      &ring, fd, static_cast<uint8_t*>(first),
      static_cast<uint8_t*>(second), iterations);
  cleanup();
  return cross_result ? cross_result : sqlite_io_mixed_batch_probe(iterations);
#else
  (void)iterations;
  return 77;
#endif
}
