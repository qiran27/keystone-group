#include "../host/online-cluster-feedback.hpp"
#include <cassert>
#include <cstdio>
#include <limits>

static void sample(OnlineClusterFeedback& f, uint64_t cost = 1000000,
                   uint64_t tail = 2000000, bool candidate = false, bool merged = false) {
  assert(f.observe(f.epoch, f.merging, f.clean_after + 1,
      1000000, cost, tail, candidate, merged) == 0);
  assert(f.merging && f.epoch == 1);
  assert(!f.probes && !f.accepts && !f.rejects && !f.cooldown);
  assert(!f.reference_cost && !f.reference_p95 && !f.reference_samples);
}

static void growing_telemetry() {
  for (unsigned buffers : {30, 50, 100, 150, 200, 250}) {
    OnlineClusterFeedback f;
    for (unsigned i = 0; i < buffers; ++i) {
      // Worsening cost/tail or zero exposure cannot disable clustering.
      sample(f, 1000000 + i * 1000000, 2000000 + i * 2000000, i % 2, i % 2);
    }
    assert(f.samples_total == buffers);
    assert(f.candidates_total == buffers / 2 && f.exposed_total == buffers / 2);
    assert(f.evaluated_buffers + f.samples == buffers);
    assert(f.window_target == (buffers < 32 ? 8 : buffers < 128 ? 16 : 32));
    assert(f.samples < f.window_target);
  }
  for (size_t target : {size_t(8), size_t(16), size_t(32)}) {
    OnlineClusterFeedback f;
    while (f.window_target < target) sample(f);
    assert(!f.samples);
    f.publication.fill(999999999);
    for (size_t i = 0; i < target; ++i)
      sample(f, 1000000, i + 1 == target ? 9000000 : 2000000, true, true);
    assert(f.last_p95 == (target < 32 ? 9000000 : 2000000));
    assert(f.last_cost == 1000000 && f.last_window_samples == target);
  }
}

static void invalid_samples_and_cost() {
  OnlineClusterFeedback f;
  f.observe(2, true, 1, 1, 1, 1, true, true);
  f.observe(1, false, 1, 1, 1, 1, true, true);
  f.settle(10);
  f.observe(1, true, 9, 1, 1, 1, true, true);
  f.observe(1, true, 11, 0, 100, 200, true, false);
  f.observe(1, true, 11, 1, 0, 200, true, false);
  f.observe(1, true, 11, 1, 200, 100, true, false);
  assert(!f.samples && !f.samples_total && !f.evaluated_buffers);
  f.useful_bytes = std::numeric_limits<uint64_t>::max();
  sample(f);
  assert(!f.samples);
  f = OnlineClusterFeedback();
  for (unsigned i = 0; i < 8; ++i)
    f.observe(1, true, 1, i % 2 ? 2000000 : 1000000,
        3000000, 4000000, true, true);
  assert(f.last_cost == 2000000 && f.last_p95 == 4000000);
  assert(f.merging && f.epoch == 1 && !f.probes && !f.rejects);
}

int main() {
  growing_telemetry();
  invalid_samples_and_cost();
  puts("passive telemetry: byte-normalized cost, P95, 8/16/32 windows, validation, no admission decisions PASS");
}
