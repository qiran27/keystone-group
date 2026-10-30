#ifndef KEYSTONE_ONLINE_CLUSTER_FEEDBACK_HPP
#define KEYSTONE_ONLINE_CLUSTER_FEEDBACK_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

// Passive telemetry, not Algorithm 3 admission. Legal arrived candidates may
// merge from the first buffer. Legacy trial/reference fields stay zero for CSV
// compatibility; neither service cost nor publication P95 toggles clustering.
struct OnlineClusterFeedback {
  static constexpr size_t kInitialSamples = 8;
  static constexpr size_t kMaxSamples = 32;
  bool merging = true;
  uint64_t epoch = 1, clean_after = 0;
  uint64_t reference_cost = 0, reference_p95 = 0;
  uint64_t last_cost = 0, last_p95 = 0;
  uint64_t windows = 0, probes = 0, accepts = 0, rejects = 0;
  uint64_t unexposed = 0, stale = 0, mixed = 0;
  uint64_t samples_total = 0, candidates_total = 0, exposed_total = 0;
  uint64_t evaluated_buffers = 0, window_grows = 0;
  unsigned cooldown = 0, accepted_windows = 0;
  size_t samples = 0, candidates = 0, exposed = 0;
  size_t window_target = kInitialSamples, last_window_samples = 0, reference_samples = 0;
  uint64_t useful_bytes = 0;
  long double service_sum = 0;
  std::array<uint64_t, kMaxSamples> publication{};

  void reset_window() {
    samples = candidates = exposed = 0;
    useful_bytes = 0;
    service_sum = 0;
  }

  void settle(uint64_t published) {
    ++stale;
    clean_after = std::max(clean_after, published);
    reset_window();
  }

  void grow_observation_window() {
    const size_t next = evaluated_buffers >= 128 ? kMaxSamples :
        evaluated_buffers >= 32 ? 16 : kInitialSamples;
    if (next <= window_target) return;
    window_target = next;
    reference_samples = 0;
    reference_cost = reference_p95 = 0;
    ++window_grows;
  }

  // Durations start at Host ready-request selection and enqueue, respectively, and end
  // at this buffer's release-publication. No device or enclave-resume timestamp
  // is inferred. The cost is buffer residency/byte, not device throughput.
  int observe(uint64_t sample_epoch, bool sample_merging, uint64_t started,
              uint64_t bytes, uint64_t service_ns, uint64_t publication_ns,
              bool has_candidate, bool did_merge) {
    if (sample_epoch != epoch || sample_merging != merging || started < clean_after) {
      ++stale;
      return 0;
    }
    if (!bytes || !service_ns || publication_ns < service_ns ||
        bytes > UINT64_MAX - useful_bytes) return 0;
    useful_bytes += bytes;
    service_sum += service_ns;
    publication[samples++] = publication_ns;
    candidates += has_candidate;
    exposed += did_merge;
    ++samples_total;
    candidates_total += has_candidate;
    exposed_total += did_merge;
    if (samples != window_target) return 0;

    last_window_samples = samples;
    evaluated_buffers += samples;
    last_cost = static_cast<uint64_t>(service_sum * 1000000 / useful_bytes);
    std::sort(publication.begin(), publication.begin() + samples);
    // Nearest-rank P95 is the maximum for the 8/16-buffer screening windows.
    last_p95 = publication[(95 * samples + 99) / 100 - 1];
    ++windows;
    reset_window();
    grow_observation_window();
    return 0;
  }
};

#endif
