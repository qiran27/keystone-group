#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "group-pmp-common.h"
#include "group-pmp-sqlite-shared.h"

struct sqlite_slot_progress {
  uint64_t lane_id;
  uint64_t slot_id;
  uint64_t worker_index;
  uint64_t target_bytes;
  uint64_t logical_base;
  uint64_t next_bytes;
  uint64_t batches;
};

struct sqlite_slot_request {
  uint64_t slot_index;
  struct keystone_yxstm_slot_info info;
};

static const volatile char sqlite_artifact_marker[] __attribute__((used)) =
    GROUP_PMP_SQLITE_ARTIFACT_MARKER;
static const volatile char sqlite_full_flow_baseline_marker[]
    __attribute__((used)) = GROUP_PMP_SQLITE_FULL_FLOW_BASELINE_MARKER;
static const volatile char sqlite_group_abi_marker[] __attribute__((used)) =
    KEYSTONE_GROUP_ABI_MARKER;

static int publish_result(struct group_pmp_mixed_master_result* result,
                          uint64_t state) {
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

static int control_ocall(void) {
  uint64_t payload = UINT64_C(0x4f43414c4c424c4b);
  uint64_t ack = 0;
  return ocall(1, &payload, sizeof(payload), &ack, sizeof(ack)) == 0 &&
      ack == UINT64_C(0x47504d504f43414c) ? 0 : -1;
}

static uint64_t packet_digest(const volatile uint8_t* packet,
                              uint64_t packet_size) {
  uint64_t digest = UINT64_C(1469598103934665603);
  uint64_t offset;
  for (offset = 0; offset < packet_size; offset += 64) {
    uint64_t sample = 0;
    uint64_t remaining = packet_size - offset;
    uint64_t width = remaining < sizeof(sample) ? remaining : sizeof(sample);
    memcpy(&sample, (const void*)(uintptr_t)(packet + offset), (size_t)width);
    digest ^= sample;
    digest *= UINT64_C(1099511628211);
  }
  return digest ? digest : UINT64_C(1);
}

static int dispatch_slot(const struct keystone_yxstm_layout_info* layout,
                         struct sqlite_slot_progress* progress,
                         const struct keystone_yxstm_slot_info* info,
                         uint64_t workload, uint64_t* sequence,
                         struct group_pmp_mixed_master_result* result) {
  struct keystone_yxstm_slot_command command;
  struct group_pmp_sqlite_packet_header header;
  volatile uint8_t* packet;
  uint64_t remaining = progress->target_bytes - progress->next_bytes;
  uint64_t capacity = group_pmp_sqlite_task_chunk_bytes(
      workload, progress->target_bytes);
  uint64_t logical = remaining < capacity ? remaining : capacity;
  uint64_t value_size = group_pmp_sqlite_value_size(workload);
  uint64_t started = group_pmp_rdcycle();
  uint64_t time_started = group_pmp_rdtime();

  if (!logical || logical % value_size != 0)
    return -1;
  memset(&header, 0, sizeof(header));
  header.magic = GROUP_PMP_SQLITE_PACKET_MAGIC;
  header.version = GROUP_PMP_SQLITE_PACKET_VERSION;
  header.workload = workload;
  header.worker_index = progress->worker_index;
  header.batch_id = progress->batches + 1;
  header.first_record = progress->next_bytes / value_size;
  header.record_count = logical / value_size;
  header.value_size = value_size;
  header.logical_bytes = logical;
  header.sequence = ++*sequence;
  header.reserved[0] = progress->logical_base + progress->next_bytes;

  memset(&command, 0, sizeof(command));
  command.operation = KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_ACQUIRE;
  command.lane_id = progress->lane_id;
  command.slot_id = progress->slot_id;
  command.expected_epoch = info->epoch;
  command.batch_id = header.batch_id;
  command.task_id = progress->worker_index + 1;
  command.sequence = header.sequence;
  command.payload_size = sizeof(header);
  command.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
  if (group_pmp_yxstm_slot_command(&command) != 0 ||
      command.state != YXSTM_SLOT_DISPATCHING)
    return -1;
  packet = group_pmp_mixed_slot_payload(
      layout, progress->lane_id, info->slot_offset);
  memcpy((void*)(uintptr_t)packet, &header, sizeof(header));
  __sync_synchronize();
  command.operation = KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_PUBLISH;
  if (group_pmp_yxstm_slot_command(&command) != 0 ||
      command.state != YXSTM_SLOT_READY)
    return -1;
  result->dispatch_cycles += group_pmp_rdcycle() - started;
  result->dispatch_time_ticks += group_pmp_rdtime() - time_started;
  result->dispatch_bytes += sizeof(header);
  result->slot_dispatches++;
  result->lane_dispatches[progress->lane_id]++;
  result->lane_dispatch_bytes[progress->lane_id] += logical;
  return 0;
}

static int aggregate_slot(const struct keystone_yxstm_layout_info* layout,
                          struct sqlite_slot_progress* progress,
                          const struct keystone_yxstm_slot_info* info,
                          uint64_t workload,
                          struct group_pmp_mixed_master_result* result) {
  struct keystone_yxstm_slot_command command;
  struct group_pmp_sqlite_packet_header header;
  volatile uint8_t* packet;
  uint64_t digest;
  uint64_t started = group_pmp_rdcycle();
  uint64_t time_started = group_pmp_rdtime();

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
  if (group_pmp_yxstm_slot_command(&command) != 0 ||
      command.state != YXSTM_SLOT_AGGREGATING ||
      info->payload_size != sizeof(header))
    return -1;
  packet = group_pmp_mixed_slot_payload(
      layout, progress->lane_id, info->slot_offset);
  memcpy(&header, (const void*)(uintptr_t)packet, sizeof(header));
  digest = packet_digest(packet, sizeof(header));
  if (header.magic != GROUP_PMP_SQLITE_PACKET_MAGIC ||
      header.version != GROUP_PMP_SQLITE_PACKET_VERSION ||
      header.workload != workload ||
      header.worker_index != progress->worker_index ||
      header.batch_id != progress->batches + 1 ||
      header.logical_bytes != header.record_count * header.value_size ||
      header.value_size != group_pmp_sqlite_value_size(workload) ||
      !header.payload_digest || progress->next_bytes + header.logical_bytes >
          progress->target_bytes || digest != info->digest)
    return -1;
  result->aggregate_digest ^= header.payload_digest +
      progress->worker_index * UINT64_C(0x9e3779b97f4a7c15) +
      progress->batches;
  command.operation = KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_COMPLETE;
  if (group_pmp_yxstm_slot_command(&command) != 0 ||
      command.state != YXSTM_SLOT_FREE)
    return -1;
  progress->next_bytes += header.logical_bytes;
  progress->batches++;
  result->aggregate_cycles += group_pmp_rdcycle() - started;
  result->aggregate_time_ticks += group_pmp_rdtime() - time_started;
  result->aggregate_bytes += sizeof(header);
  result->slot_aggregates++;
  result->lane_aggregates[progress->lane_id]++;
  return 0;
}

int main(void) {
  struct group_pmp_mixed_master_config config;
  struct group_pmp_mixed_master_result result;
  struct keystone_yxstm_layout_info layout;
  struct sqlite_slot_progress slots[GROUP_PMP_MIXED_MAX_WORKERS];
  struct sqlite_slot_request requests[GROUP_PMP_MIXED_MAX_WORKERS];
  uint64_t workload;
  uint64_t slot_count = 0;
  uint64_t sequence = 0;
  uint64_t completed = 0;
  uint64_t task_started;
  uint64_t task_time_started;
  int rc = 1;

  if (sqlite_artifact_marker[0] != 'k' ||
      sqlite_full_flow_baseline_marker[0] != 'k' ||
      sqlite_group_abi_marker[0] != 'k')
    return 90;
  memset(&config, 0, sizeof(config));
  memset(&result, 0, sizeof(result));
  memset(&layout, 0, sizeof(layout));
  memset(slots, 0, sizeof(slots));
  memset(requests, 0, sizeof(requests));
  if (copy_from_shared(&config, GROUP_PMP_MIXED_CONFIG_OFFSET,
                       sizeof(config)) != 0 ||
      config.magic != GROUP_PMP_MIXED_MAGIC ||
      config.version != GROUP_PMP_MIXED_VERSION ||
      config.worker_count < 1 ||
      config.worker_count > GROUP_PMP_MIXED_MAX_WORKERS)
    goto out;
  workload = config.reserved[0];
  if (!group_pmp_sqlite_valid_workload(workload) ||
      group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0 ||
      layout.role != GROUP_ROLE_MASTER)
    goto out;
  for (uint64_t lane = 0; lane < GROUP_PMP_MIXED_LANES; ++lane) {
    for (uint64_t slot_id = 0; slot_id < config.lane_depth[lane]; ++slot_id) {
      uint64_t worker = slot_id * GROUP_PMP_MIXED_LANES + lane;
      if (worker >= config.worker_count)
        goto out;
      slots[worker].lane_id = lane;
      slots[worker].slot_id = slot_id;
      slots[worker].worker_index = worker;
      slots[worker].target_bytes = config.worker_data_bytes[worker];
      for (uint64_t prior = 0; prior < worker; ++prior)
        slots[worker].logical_base += config.worker_data_bytes[prior];
      if (!slots[worker].target_bytes ||
          slots[worker].target_bytes %
              group_pmp_sqlite_value_size(workload) != 0)
        goto out;
      slot_count++;
    }
  }
  if (slot_count != config.worker_count)
    goto out;

  result.magic = GROUP_PMP_MIXED_MAGIC;
  result.version = GROUP_PMP_MIXED_VERSION;
  result.worker_count = config.worker_count;
  result.active_lanes = config.active_lanes;
  if (publish_result(&result, GROUP_PMP_MIXED_STATE_WARMED) != 0 ||
      control_ocall() != 0)
    goto out;
  /* Full-flow baseline: first dispatch through final aggregate. */
  task_time_started = group_pmp_rdtime();
  task_started = group_pmp_rdcycle();

  while (completed < slot_count) {
    uint64_t progress_made = 0;
    uint64_t request_count = 0;
    completed = 0;

    for (uint64_t index = 0; index < slot_count; ++index) {
      struct keystone_yxstm_slot_info info;
      struct sqlite_slot_progress* progress = &slots[index];
      if (progress->next_bytes == progress->target_bytes) {
        completed++;
        continue;
      }
      if (group_pmp_yxstm_query_slot_info(
              &info, progress->lane_id, progress->slot_id) != 0)
        goto out;
      if (info.state == YXSTM_SLOT_DONE) {
        requests[request_count].slot_index = index;
        requests[request_count].info = info;
        request_count++;
      }
    }
    for (uint64_t request = 0; request < request_count; ++request) {
      uint64_t index = requests[request].slot_index;
      struct sqlite_slot_progress* progress = &slots[index];
      if (aggregate_slot(&layout, &slots[index], &requests[request].info,
                         workload, &result) != 0)
        goto out;
      progress_made++;
      /* Refill the just-freed slot before aggregating another lane. This keeps
       * at least one READY owner queued while peers encrypt or wait for I/O. */
      if (progress->next_bytes < progress->target_bytes) {
        struct keystone_yxstm_slot_info free_info;
        if (group_pmp_yxstm_query_slot_info(
                &free_info, progress->lane_id, progress->slot_id) != 0 ||
            free_info.state != YXSTM_SLOT_FREE ||
            dispatch_slot(&layout, progress, &free_info, workload,
                          &sequence, &result) != 0)
          goto out;
        progress_made++;
      }
    }

    /* Keep every available slot READY. SQLite executes in the worker EPM, so
     * master dispatch is only a fixed-size descriptor write. */
    for (uint64_t lane = 0; lane < config.active_lanes; ++lane) {
      request_count = 0;
      for (uint64_t index = 0; index < slot_count; ++index) {
        struct keystone_yxstm_slot_info info;
        if (slots[index].lane_id != lane ||
            slots[index].next_bytes == slots[index].target_bytes)
          continue;
        if (group_pmp_yxstm_query_slot_info(
                &info, lane, slots[index].slot_id) != 0)
          goto out;
        if (info.state == YXSTM_SLOT_FREE) {
          requests[request_count].slot_index = index;
          requests[request_count].info = info;
          request_count++;
        }
      }
      for (uint64_t request = 0; request < request_count; ++request) {
        uint64_t index = requests[request].slot_index;
        if (dispatch_slot(&layout, &slots[index], &requests[request].info,
                          workload, &sequence, &result) != 0)
          goto out;
        progress_made++;
      }
    }
    if (!progress_made && completed < slot_count) {
      result.slot_wait_yields++;
      if (group_pmp_master_host_yield() != 0)
        goto out;
    }
  }

  result.task_e2e_cycles = group_pmp_rdcycle() - task_started;
  result.task_e2e_time_ticks = group_pmp_rdtime() - task_time_started;
  result.compute_wall_cycles = result.task_e2e_cycles >
      result.dispatch_cycles + result.aggregate_cycles ?
      result.task_e2e_cycles - result.dispatch_cycles -
          result.aggregate_cycles : 1;
  result.compute_wall_time_ticks = result.task_e2e_time_ticks >
      result.dispatch_time_ticks + result.aggregate_time_ticks ?
      result.task_e2e_time_ticks - result.dispatch_time_ticks -
          result.aggregate_time_ticks : 1;
  result.protocol_cycles = result.dispatch_cycles + result.aggregate_cycles;
  result.protocol_time_ticks =
      result.dispatch_time_ticks + result.aggregate_time_ticks;
  result.sequence = sequence;
  result.validation_ok = result.aggregate_digest != 0 &&
      result.slot_dispatches == result.slot_aggregates;
  for (uint64_t index = 0; index < slot_count; ++index) {
    uint64_t expected_batches = group_pmp_sqlite_task_batch_count(
        workload, slots[index].target_bytes);
    if (!expected_batches || slots[index].batches != expected_batches)
      result.validation_ok = 0;
  }
  if (!result.validation_ok || control_ocall() != 0 ||
      publish_result(&result, GROUP_PMP_MIXED_STATE_COMPLETED) != 0)
    goto out;
  rc = 0;

out:
  return rc;
}
