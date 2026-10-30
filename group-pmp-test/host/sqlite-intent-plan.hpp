#ifndef KEYSTONE_SQLITE_INTENT_PLAN_HPP
#define KEYSTONE_SQLITE_INTENT_PLAN_HPP

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <vector>
#include "../eapp/group-pmp-sqlite-vfs-shared.h"

/* Reorder only disjoint, independent intents inside one declared window.
 * Contiguous components retain their earliest arrival position relative to
 * other components. Isolated requests are not globally offset-sorted. */
inline bool sqlite_plan_intent_order(
    const std::vector<group_pmp_sqlite_io_intent>& intents,
    std::vector<uint32_t>* order, uint64_t* adjacent_pairs) {
  if (intents.empty() || intents.size() > GROUP_PMP_SQLITE_INTENT_MAX)
    return false;
  std::vector<uint32_t> spatial(intents.size());
  std::iota(spatial.begin(), spatial.end(), 0);
  for (const auto& x : intents)
    if (!x.length || x.length > GROUP_PMP_SQLITE_VFS_BUFFER_BYTES ||
        x.file_offset > UINT64_MAX - x.length)
      return false;
  std::sort(spatial.begin(), spatial.end(), [&](uint32_t a, uint32_t b) {
    return intents[a].file_offset < intents[b].file_offset;
  });
  struct Component { size_t first, end; uint32_t arrival; };
  std::vector<Component> components;
  uint64_t pairs = 0;
  for (size_t i = 0; i < spatial.size();) {
    const size_t first = i++;
    uint32_t arrival = spatial[first];
    uint64_t end = intents[spatial[first]].file_offset + intents[spatial[first]].length;
    const uint64_t begin = intents[spatial[first]].file_offset;
    while (i < spatial.size()) {
      const auto& next = intents[spatial[i]];
      // Overlapping writes are not independent. Never authorize their reorder.
      if (next.file_offset < end) return false;
      if (next.file_offset != end || next.length > UINT64_C(8000000) - (end - begin))
        break;
      end += next.length;
      arrival = std::min(arrival, spatial[i++]);
      ++pairs;
    }
    if (i < spatial.size() && intents[spatial[i]].file_offset < end) return false;
    components.push_back(Component{first, i, arrival});
  }
  std::sort(components.begin(), components.end(), [](const Component& a, const Component& b) {
    return a.arrival < b.arrival;
  });
  order->clear();
  order->reserve(intents.size());
  for (const auto& c : components)
    order->insert(order->end(), spatial.begin() + c.first, spatial.begin() + c.end);
  *adjacent_pairs = pairs;
  return true;
}

#endif
