#ifndef MOTIVATION_SYSTEM_TRACE_H
#define MOTIVATION_SYSTEM_TRACE_H
#include <stdint.h>
#define MOT_SYSTEM_MARKER "keystone-motivation-real-system-v1"
#define MOT_SYSTEM_TRACE_FLAG UINT64_C(64)
#define MOT_SYSTEM_TRACE_MAGIC UINT64_C(0x4d4f545359535431)
#define MOT_SYSTEM_TRACE_MAX 512
struct mot_system_event {
  uint64_t begin_ticks, end_ticks, logical_offset, bytes, runtime_ticks, operation;
};
struct mot_system_trace {
  uint64_t magic, version, count, dropped;
  struct mot_system_event events[MOT_SYSTEM_TRACE_MAX];
};
static inline void mot_system_append(struct mot_system_trace* log,
    uint64_t begin, uint64_t end, uint64_t offset, uint64_t bytes,
    uint64_t runtime, uint64_t operation) {
  if (log->count >= MOT_SYSTEM_TRACE_MAX) { ++log->dropped; return; }
  struct mot_system_event* e = &log->events[log->count++];
  e->begin_ticks=begin; e->end_ticks=end; e->logical_offset=offset;
  e->bytes=bytes; e->runtime_ticks=runtime; e->operation=operation;
}
#endif
