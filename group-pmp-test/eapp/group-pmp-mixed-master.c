#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "group-pmp-common.h"

struct mixed_slot_progress {
  uint64_t lane_id;
  uint64_t slot_id;
  uint64_t worker_index;
  uint64_t target_bytes;
  uint64_t next_offset;
  uint64_t batches_completed;
};

static const volatile char mixed_lane_dynamic_artifact_marker[]
    __attribute__((used)) = GROUP_PMP_MIXED_ARTIFACT_MARKER;

static int
publish_result(struct group_pmp_mixed_master_result* result, uint64_t state) {
  uint64_t published = state;

  result->status = GROUP_PMP_MIXED_STATE_EMPTY;
  if (copy_to_shared_utm(GROUP_PMP_MIXED_RESULT_OFFSET,
                         result, sizeof(*result)) != 0)
    return -1;
  __sync_synchronize();
  result->status = state;
  return copy_to_shared_utm(
      GROUP_PMP_MIXED_RESULT_OFFSET +
          offsetof(struct group_pmp_mixed_master_result, status),
      &published, sizeof(published));
}

static int
control_ocall(void) {
  uint64_t payload = UINT64_C(0x4f43414c4c424c4b);
  uint64_t ack = 0;

  return ocall(1, &payload, sizeof(payload), &ack, sizeof(ack)) == 0 &&
         ack == UINT64_C(0x47504d504f43414c) ? 0 : -1;
}

static int
query_slot(uint64_t lane_id, uint64_t slot_id,
           struct keystone_yxstm_slot_info* info) {
  return group_pmp_yxstm_query_slot_info(info, lane_id, slot_id);
}

static void
fill_payload_wide(volatile uint8_t* payload, uint64_t worker_index,
                  uint64_t task_offset, uint64_t length) {
  volatile uint64_t* words = (volatile uint64_t*)(uintptr_t)payload;
  uint64_t pattern[32];
  uint64_t word_count = length / sizeof(uint64_t);
  uint64_t offset;

  /* The byte generator repeats every 256 bytes. Build that pattern once per
   * dispatch instead of recomputing eight bytes for every destination word. */
  for (offset = 0; offset < 32; ++offset)
    pattern[offset] = group_pmp_mixed_task_plain_word(
        worker_index, task_offset + offset * sizeof(uint64_t));
  for (offset = 0; offset < word_count; ++offset)
    words[offset] = pattern[offset & UINT64_C(31)];
  offset = word_count * sizeof(uint64_t);
  for (; offset < length; ++offset)
    payload[offset] = group_pmp_mixed_task_plain_byte(
        worker_index, task_offset + offset);
}

static uint64_t
payload_digest(const volatile uint8_t* payload, uint64_t length) {
  uint8_t block[16];
  uint64_t digest = UINT64_C(0xcbf29ce484222325);
  const uint64_t offsets[4] = {
      0, length > 4096 ? 4096 : 0, length / 2, length - 16};
  uint64_t sample;

  for (sample = 0; sample < 4; ++sample) {
    memcpy(block, (const void*)(uintptr_t)(payload + offsets[sample]),
           sizeof(block));
    digest = group_pmp_bench_digest_block(digest, block);
  }
  return digest ? digest : UINT64_C(1);
}

static int
validate_frozen_slots(const struct group_pmp_mixed_master_config* config) {
  uint64_t lane;

  for (lane = 0; lane < GROUP_PMP_MIXED_LANES; ++lane) {
    struct keystone_yxstm_slot_info summary;
    uint64_t expected_size = group_pmp_mixed_slot_size(
        config->lane_depth[lane]);
    uint64_t slot_id;

    if (query_slot(lane, KEYSTONE_YXSTM_INVALID_SLOT, &summary) != 0 ||
        summary.lane_id != lane ||
        summary.slot_id != KEYSTONE_YXSTM_INVALID_SLOT ||
        summary.slot_count != config->lane_depth[lane] || !summary.epoch)
      return -1;
    if (!config->lane_depth[lane]) {
      if (summary.slot_size || summary.payload_size)
        return -1;
      continue;
    }
    if (summary.slot_size != expected_size ||
        summary.payload_size !=
            keystone_yxstm_slot_payload_capacity(
                config->lane_depth[lane]) ||
        summary.slot_count * summary.slot_size >
            KEYSTONE_YXSTM_WORKER_LANE_SIZE)
      return -1;
    for (slot_id = 0; slot_id < summary.slot_count; ++slot_id) {
      struct keystone_yxstm_slot_info slot;

      if (query_slot(lane, slot_id, &slot) != 0 ||
          slot.lane_id != lane || slot.slot_id != slot_id ||
          slot.slot_count != summary.slot_count ||
          slot.slot_offset != slot_id * expected_size ||
          slot.slot_size != expected_size || !slot.epoch ||
          slot.state != YXSTM_SLOT_FREE || slot.payload_size != 0 ||
          slot.batch_id != 0 || slot.task_id != 0 ||
          slot.sequence != 0 || slot.permissions != 0 || slot.digest != 0)
        return -1;
    }
  }
  return 0;
}

static int
fill_dispatch_payload(
    const struct keystone_yxstm_layout_info* layout,
    const struct mixed_slot_progress* progress, uint64_t slot_offset,
    uint64_t bytes) {
  volatile uint8_t* payload = group_pmp_mixed_slot_payload(
      layout, progress->lane_id, slot_offset);

  fill_payload_wide(payload, progress->worker_index,
                    progress->next_offset, bytes);
  __sync_synchronize();
  return 0;
}

static int
fill_and_publish_dispatch(
    const struct keystone_yxstm_layout_info* layout,
    struct mixed_slot_progress* progress, uint64_t slot_offset,
    uint64_t bytes, struct keystone_yxstm_slot_command* command,
    uint64_t started, uint64_t started_time,
    struct group_pmp_mixed_master_result* result) {
  uint64_t command_started_time;
  uint64_t command_started;

  if (fill_dispatch_payload(layout, progress, slot_offset, bytes) != 0)
    return -1;
  command->operation = KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_PUBLISH;
  command->permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
  command_started_time = group_pmp_rdtime();
  command_started = group_pmp_rdcycle();
  if (group_pmp_yxstm_slot_command(command) != 0 ||
      command->state != YXSTM_SLOT_READY)
    return -1;
  result->protocol_cycles += group_pmp_rdcycle() - command_started;
  result->protocol_time_ticks +=
      group_pmp_rdtime() - command_started_time;
  result->dispatch_cycles += group_pmp_rdcycle() - started;
  result->dispatch_time_ticks += group_pmp_rdtime() - started_time;
  result->dispatch_bytes += bytes;
  result->slot_dispatches++;
  result->lane_dispatches[progress->lane_id]++;
  result->lane_dispatch_bytes[progress->lane_id] += bytes;
  return 0;
}

static int
dispatch_slot(const struct keystone_yxstm_layout_info* layout,
              struct mixed_slot_progress* progress,
              const struct keystone_yxstm_slot_info* info,
              uint64_t* sequence,
              struct group_pmp_mixed_master_result* result) {
  struct keystone_yxstm_slot_command command;
  uint64_t capacity = keystone_yxstm_slot_payload_capacity(
      info->slot_count);
  uint64_t remaining = progress->target_bytes - progress->next_offset;
  uint64_t bytes = remaining < capacity ? remaining : capacity;
  uint64_t started_time = group_pmp_rdtime();
  uint64_t started = group_pmp_rdcycle();
  uint64_t command_started;
  uint64_t command_started_time;

  if (!bytes || (bytes & 15))
    return -1;
  memset(&command, 0, sizeof(command));
  command.operation = KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_ACQUIRE;
  command.lane_id = progress->lane_id;
  command.slot_id = progress->slot_id;
  command.expected_epoch = info->epoch;
  command.batch_id = progress->batches_completed + 1;
  command.task_id = progress->worker_index + 1;
  command.sequence = ++*sequence;
  command.payload_size = bytes;
  command.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
  command_started_time = group_pmp_rdtime();
  command_started = group_pmp_rdcycle();
  if (group_pmp_yxstm_slot_command(&command) != 0 ||
      command.state != YXSTM_SLOT_DISPATCHING)
    return -1;
  result->protocol_cycles += group_pmp_rdcycle() - command_started;
  result->protocol_time_ticks +=
      group_pmp_rdtime() - command_started_time;

  return fill_and_publish_dispatch(
      layout, progress, info->slot_offset, bytes, &command,
      started, started_time, result);
}

static uint64_t
order_independent_digest(uint64_t digest, uint64_t worker_index,
                         uint64_t chunk_index) {
  uint64_t value = digest ^ (worker_index * UINT64_C(0x9e3779b97f4a7c15)) ^
      (chunk_index * UINT64_C(0xd6e8feb86659fd93));
  value ^= value >> 30;
  value *= UINT64_C(0xbf58476d1ce4e5b9);
  value ^= value >> 27;
  value *= UINT64_C(0x94d049bb133111eb);
  return value ^ (value >> 31);
}

static int
aggregate_slot(const struct keystone_yxstm_layout_info* layout,
               struct mixed_slot_progress* progress,
               const struct keystone_yxstm_slot_info* info,
               uint64_t* sequence,
               struct group_pmp_mixed_master_result* result) {
  struct keystone_yxstm_slot_command command;
  volatile uint8_t* payload;
  uint64_t started_time = group_pmp_rdtime();
  uint64_t started = group_pmp_rdcycle();
  uint64_t command_started;
  uint64_t command_started_time;

  memset(&command, 0, sizeof(command));
  command.operation = KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_ACQUIRE;
  command.lane_id = progress->lane_id;
  command.slot_id = progress->slot_id;
  command.expected_epoch = info->epoch;
  command.batch_id = info->batch_id;
  command.task_id = info->task_id;
  command.sequence = info->sequence;
  command.payload_size = info->payload_size;
  command.permissions = KEYSTONE_YXSTM_PERM_R;
  command.digest = info->digest;
  command_started_time = group_pmp_rdtime();
  command_started = group_pmp_rdcycle();
  if (group_pmp_yxstm_slot_command(&command) != 0 ||
      command.state != YXSTM_SLOT_AGGREGATING)
    return -1;
  result->protocol_cycles += group_pmp_rdcycle() - command_started;
  result->protocol_time_ticks +=
      group_pmp_rdtime() - command_started_time;
  payload = group_pmp_mixed_slot_payload(
      layout, progress->lane_id, info->slot_offset);
  if (info->task_id != progress->worker_index + 1 ||
      info->batch_id != progress->batches_completed + 1 ||
      progress->next_offset + info->payload_size >
          progress->target_bytes ||
      payload_digest(payload, info->payload_size) != info->digest) {
    return -1;
  }
  result->aggregate_digest ^=
      order_independent_digest(info->digest,
                               progress->worker_index,
                               progress->batches_completed);
  result->aggregate_bytes += UINT64_C(64);
  if (progress->next_offset + info->payload_size <
      progress->target_bytes) {
    uint64_t dispatch_started;
    uint64_t dispatch_started_time;
    uint64_t next_offset = progress->next_offset + info->payload_size;
    uint64_t remaining = progress->target_bytes - next_offset;
    uint64_t capacity = keystone_yxstm_slot_payload_capacity(
        info->slot_count);
    uint64_t next_bytes = remaining < capacity ? remaining : capacity;

    memset(&command, 0, sizeof(command));
    command.operation = KEYSTONE_YXSTM_SLOT_MASTER_FINISH_AND_ACQUIRE;
    command.lane_id = progress->lane_id;
    command.slot_id = progress->slot_id;
    command.expected_epoch = info->epoch + 1;
    if (!command.expected_epoch)
      command.expected_epoch = 1;
    command.batch_id = progress->batches_completed + 2;
    command.task_id = progress->worker_index + 1;
    command.sequence = ++*sequence;
    command.payload_size = next_bytes;
    command.permissions = KEYSTONE_YXSTM_PERM_R |
                          KEYSTONE_YXSTM_PERM_W;
    command_started_time = group_pmp_rdtime();
    command_started = group_pmp_rdcycle();
    if (!next_bytes || (next_bytes & 15) ||
        group_pmp_yxstm_slot_command(&command) != 0 ||
        command.state != YXSTM_SLOT_DISPATCHING)
      return -1;
    result->protocol_cycles += group_pmp_rdcycle() - command_started;
    result->protocol_time_ticks +=
        group_pmp_rdtime() - command_started_time;
    progress->next_offset = next_offset;
    progress->batches_completed++;
    result->aggregate_cycles += group_pmp_rdcycle() - started;
    result->aggregate_time_ticks += group_pmp_rdtime() - started_time;
    result->slot_aggregates++;
    result->lane_aggregates[progress->lane_id]++;
    dispatch_started_time = group_pmp_rdtime();
    dispatch_started = group_pmp_rdcycle();
    return fill_and_publish_dispatch(
        layout, progress, info->slot_offset, next_bytes, &command,
        dispatch_started, dispatch_started_time, result);
  }

  command.operation = KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_COMPLETE;
  command_started_time = group_pmp_rdtime();
  command_started = group_pmp_rdcycle();
  if (group_pmp_yxstm_slot_command(&command) != 0 ||
      command.state != YXSTM_SLOT_FREE)
    return -1;
  result->protocol_cycles += group_pmp_rdcycle() - command_started;
  result->protocol_time_ticks +=
      group_pmp_rdtime() - command_started_time;
  progress->next_offset += info->payload_size;
  progress->batches_completed++;
  result->aggregate_cycles += group_pmp_rdcycle() - started;
  result->aggregate_time_ticks += group_pmp_rdtime() - started_time;
  result->slot_aggregates++;
  result->lane_aggregates[progress->lane_id]++;
  return 0;
}

int
main(void) {
  struct group_pmp_mixed_master_config config;
  struct group_pmp_mixed_master_result result;
  struct keystone_yxstm_layout_info layout;
  struct mixed_slot_progress slots[GROUP_PMP_MIXED_MAX_WORKERS];
  uint64_t slot_count = 0;
  uint64_t sequence = 0;
  uint64_t completed_workers = 0;
  uint64_t task_started;
  uint64_t task_started_time;
  uint64_t lane;

  if (mixed_lane_dynamic_artifact_marker[0] != 'k')
    return 12;
  memset(&config, 0, sizeof(config));
  memset(&result, 0, sizeof(result));
  memset(&layout, 0, sizeof(layout));
  memset(slots, 0, sizeof(slots));
  if (copy_from_shared(&config, GROUP_PMP_MIXED_CONFIG_OFFSET,
                       sizeof(config)) != 0 ||
      config.magic != GROUP_PMP_MIXED_MAGIC ||
      config.version != GROUP_PMP_MIXED_VERSION ||
      config.worker_count < 1 ||
      config.worker_count > GROUP_PMP_MIXED_MAX_WORKERS ||
      config.active_lanes < 1 || config.active_lanes > GROUP_PMP_MIXED_LANES ||
      config.max_lane_depth < 1 ||
      config.max_lane_depth > GROUP_PMP_MIXED_MAX_LANE_DEPTH ||
      config.data_bytes_per_worker != GROUP_PMP_MIXED_WORKER_BYTES ||
      config.total_data_bytes !=
          config.worker_count * GROUP_PMP_MIXED_WORKER_BYTES)
    return 1;
  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0 ||
      layout.role != GROUP_ROLE_MASTER ||
      layout.worker_lane_count != GROUP_PMP_MIXED_LANES ||
      layout.worker_lane_size != KEYSTONE_YXSTM_WORKER_LANE_SIZE ||
      validate_frozen_slots(&config) != 0)
    return 2;

  for (lane = 0; lane < GROUP_PMP_MIXED_LANES; ++lane) {
    uint64_t slot_id;
    for (slot_id = 0; slot_id < config.lane_depth[lane]; ++slot_id) {
      uint64_t worker_index = slot_id * GROUP_PMP_MIXED_LANES + lane;
      struct mixed_slot_progress* progress;

      if (worker_index >= config.worker_count)
        return 3;
      progress = &slots[worker_index];
      slot_count++;
      progress->lane_id = lane;
      progress->slot_id = slot_id;
      progress->worker_index = worker_index;
      progress->target_bytes = config.worker_data_bytes[worker_index];
      if (!progress->target_bytes ||
          (progress->target_bytes & UINT64_C(15)))
        return 3;
    }
  }
  if (slot_count != config.worker_count)
    return 3;
  for (uint64_t index = 0; index < slot_count; ++index) {
    struct keystone_yxstm_slot_info info;

    if (query_slot(slots[index].lane_id, slots[index].slot_id,
                   &info) != 0 || info.state != YXSTM_SLOT_FREE ||
        info.lane_id != slots[index].lane_id ||
        info.slot_id != slots[index].slot_id)
      return 4;
  }
  {
    uint64_t configured_bytes = 0;
    for (uint64_t index = 0; index < slot_count; ++index)
      configured_bytes += slots[index].target_bytes;
    if (configured_bytes != config.total_data_bytes)
      return 4;
  }

  result.magic = GROUP_PMP_MIXED_MAGIC;
  result.version = GROUP_PMP_MIXED_VERSION;
  result.worker_count = config.worker_count;
  result.active_lanes = config.active_lanes;
  if (publish_result(&result, GROUP_PMP_MIXED_STATE_WARMED) != 0 ||
      control_ocall() != 0)
    return 5;

  task_started_time = group_pmp_rdtime();
  task_started = group_pmp_rdcycle();
  while (completed_workers < slot_count) {
    struct keystone_yxstm_slot_info info_cache[GROUP_PMP_MIXED_MAX_WORKERS];
    uint8_t info_valid[GROUP_PMP_MIXED_MAX_WORKERS];
    uint64_t lane_inflight[GROUP_PMP_MIXED_LANES] = {0, 0, 0};
    uint64_t progress_made = 0;
    uint64_t scan;
    uint64_t scan_base = sequence % slot_count;

    memset(info_valid, 0, sizeof(info_valid));
    completed_workers = 0;
    /* Retire completed work before spending CPU0 time generating payload. */
    for (scan = 0; scan < slot_count; ++scan) {
      uint64_t index = (scan + scan_base) % slot_count;
      struct mixed_slot_progress* progress = &slots[index];

      if (progress->next_offset == progress->target_bytes) {
        completed_workers++;
        continue;
      }
      if (query_slot(progress->lane_id, progress->slot_id,
                     &info_cache[index]) != 0)
        return 6;
      info_valid[index] = 1;
      if (info_cache[index].state != YXSTM_SLOT_FREE)
        lane_inflight[progress->lane_id]++;
      if (info_cache[index].state == YXSTM_SLOT_DONE) {
        uint64_t terminal = progress->next_offset +
            info_cache[index].payload_size == progress->target_bytes;

        if (aggregate_slot(&layout, progress, &info_cache[index],
                           &sequence, &result) != 0)
          return 7;
        if (terminal && lane_inflight[progress->lane_id])
          lane_inflight[progress->lane_id]--;
        info_valid[index] = 0;
        progress_made++;
      } else if (info_cache[index].state != YXSTM_SLOT_FREE &&
                 info_cache[index].state != YXSTM_SLOT_DISPATCHING &&
                 info_cache[index].state != YXSTM_SLOT_READY &&
                 info_cache[index].state != YXSTM_SLOT_COMPUTING &&
                 info_cache[index].state != YXSTM_SLOT_AGGREGATING) {
        return 9;
      }
    }

    /* One slot computes while one prefetched slot waits. Capping in-flight
     * work at two per lane prevents an O(worker_count) startup burst. */
    {
      uint64_t lane_scan_base = sequence % config.active_lanes;

      for (uint64_t lane_scan = 0; lane_scan < config.active_lanes;
           ++lane_scan) {
        uint64_t current_lane =
            (lane_scan + lane_scan_base) % config.active_lanes;
        uint64_t inflight_limit = config.lane_depth[current_lane] < 2 ?
            config.lane_depth[current_lane] : UINT64_C(2);

        while (lane_inflight[current_lane] < inflight_limit) {
          uint64_t selected = slot_count;

          for (scan = 0; scan < slot_count; ++scan) {
            uint64_t index = (scan + scan_base) % slot_count;
            if (info_valid[index] &&
                slots[index].lane_id == current_lane &&
                slots[index].next_offset < slots[index].target_bytes &&
                info_cache[index].state == YXSTM_SLOT_FREE) {
              selected = index;
              break;
            }
          }
          if (selected == slot_count)
            break;
          if (dispatch_slot(&layout, &slots[selected], &info_cache[selected],
                            &sequence, &result) != 0)
            return 8;
          info_cache[selected].state = YXSTM_SLOT_READY;
          lane_inflight[current_lane]++;
          progress_made++;
        }
      }
    }
    if (!progress_made && completed_workers < slot_count) {
      result.slot_wait_yields++;
      if (group_pmp_master_host_yield() != 0)
        return 10;
    }
  }

  result.task_e2e_cycles = group_pmp_rdcycle() - task_started;
  result.task_e2e_time_ticks =
      group_pmp_rdtime() - task_started_time;
  result.compute_wall_cycles = result.task_e2e_cycles >
      result.dispatch_cycles + result.aggregate_cycles ?
      result.task_e2e_cycles - result.dispatch_cycles -
          result.aggregate_cycles : 0;
  result.compute_wall_time_ticks = result.task_e2e_time_ticks >
      result.dispatch_time_ticks + result.aggregate_time_ticks ?
      result.task_e2e_time_ticks - result.dispatch_time_ticks -
          result.aggregate_time_ticks : 0;
  result.sequence = sequence;
  result.validation_ok = result.aggregate_digest != 0 &&
      result.slot_dispatches == result.slot_aggregates;
  for (lane = 0; lane < config.active_lanes; ++lane) {
    uint64_t expected_dispatches = 0;
    uint64_t expected_bytes = 0;
    uint64_t capacity = keystone_yxstm_slot_payload_capacity(
        config.lane_depth[lane]);

    for (uint64_t index = 0; index < slot_count; ++index) {
      if (slots[index].lane_id != lane)
        continue;
      expected_dispatches +=
          (slots[index].target_bytes + capacity - 1) / capacity;
      expected_bytes += slots[index].target_bytes;
    }
    if (!capacity || result.lane_dispatches[lane] != expected_dispatches ||
        result.lane_aggregates[lane] != expected_dispatches ||
        result.lane_dispatch_bytes[lane] != expected_bytes)
      result.validation_ok = 0;
  }
  if (control_ocall() != 0)
    return 11;
  if (!result.validation_ok ||
      publish_result(&result, GROUP_PMP_MIXED_STATE_COMPLETED) != 0)
    return 11;
  return 0;
}
