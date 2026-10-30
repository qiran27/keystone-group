#ifndef KEYSTONE_SQLITE_SUBMISSION_TIMING_HPP
#define KEYSTONE_SQLITE_SUBMISSION_TIMING_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include "../eapp/group-pmp-sqlite-vfs-shared.h"

// A submission ACK releases the CPU, not ownership of the ciphertext buffer.
// All diagnostic stores precede resume, so a worker cannot overwrite a ring
// while Host is still updating timestamps belonging to its previous generation.
struct SqliteSubmissionTiming {
  uint64_t received = 0;
  size_t count = 0;
  bool waiting = false;
  std::array<group_pmp_sqlite_vfs_ring_header*, 2> rings = {{nullptr, nullptr}};

  void begin(uint64_t now) { received = now; count = 0; waiting = false; }
  void acceptWait(group_pmp_sqlite_vfs_ring_header* ring) {
    waiting = true;
    accept(ring);
  }
  void accept(group_pmp_sqlite_vfs_ring_header* ring) {
    if (count < rings.size())
      rings[count++] = ring;
  }
  void publishAck(uint64_t now) const {
    for (size_t i = 0; i < count; ++i) {
      __atomic_store_n(waiting ? &rings[i]->wait_host_received_ticks :
          &rings[i]->host_received_ticks, received, __ATOMIC_RELAXED);
      __atomic_store_n(waiting ? &rings[i]->wait_host_ack_ticks :
          &rings[i]->host_ack_ticks, now, __ATOMIC_RELEASE);
    }
  }
  void requestResume(uint64_t now) const {
    for (size_t i = 0; i < count; ++i)
      __atomic_store_n(waiting ? &rings[i]->wait_host_resume_request_ticks :
          &rings[i]->host_resume_request_ticks, now, __ATOMIC_RELEASE);
  }
};

inline bool sqlite_submission_buffers_disjoint(
    const group_pmp_sqlite_vfs_request* requests, size_t count) {
  struct Range { uint64_t begin, end; };
  std::array<Range, GROUP_PMP_SQLITE_VFS_BATCH_MAX> ranges;
  if (!count || count > ranges.size())
    return false;
  bool ordered = true;
  for (size_t i = 0; i < count; ++i) {
    const auto& r = requests[i];
    if (!r.length || r.length > UINT64_MAX - r.buffer_offset)
      return false;
    ranges[i] = Range{r.buffer_offset, r.buffer_offset + r.length};
    if (i && ranges[i].begin < ranges[i - 1].end)
      ordered = false;
  }
  // Packed producer order is already non-overlapping: no sort or pair scan.
  if (ordered)
    return true;
  std::sort(ranges.begin(), ranges.begin() + count,
      [](const Range& a, const Range& b) { return a.begin < b.begin; });
  for (size_t i = 1; i < count; ++i)
    if (ranges[i].begin < ranges[i - 1].end)
      return false;
  return true;
}

#endif
