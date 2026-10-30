#include <stdint.h>
#include <string.h>
#include "group-pmp-common.h"
#include "group-pmp-sqlite-shared.h"
#include "group-pmp-sqlite-vfs-shared.h"
#include "rv8-kernels.h"

GROUP_PMP_DEFINE_PROTOCOL_MAILBOX(rv8_clock_page);
static uint8_t input[RV8_KERNEL_BLOCK_BYTES] __attribute__((aligned(64)));
_Static_assert(RV8_RESULT_OFFSET + sizeof(struct rv8_kernel_stats) <= 4096,
               "RV8 statistics must fit in control UTM");
_Static_assert(GROUP_PMP_SQLITE_VFS_RESULT_OFFSET +
    sizeof(struct group_pmp_mixed_worker_result) <= RV8_RESULT_OFFSET,
    "RV8 statistics overlap the control result");

static int publish(struct group_pmp_mixed_worker_result* result, uint64_t state) {
  result->status = GROUP_PMP_MIXED_STATE_EMPTY;
  if (copy_to_shared_utm(GROUP_PMP_SQLITE_VFS_RESULT_OFFSET, result, sizeof(*result)))
    return -1;
  __sync_synchronize();
  result->status = state;
  return copy_to_shared_utm(GROUP_PMP_SQLITE_VFS_RESULT_OFFSET +
      offsetof(struct group_pmp_mixed_worker_result, status), &state, sizeof(state));
}

static uint64_t packet_digest(const struct group_pmp_sqlite_packet_header* packet) {
  const uint8_t* bytes = (const uint8_t*)packet;
  uint64_t digest = UINT64_C(1469598103934665603);
  for (size_t offset = 0; offset < sizeof(*packet); offset += 64) {
    uint64_t value = 0;
    size_t n = sizeof(*packet) - offset;
    memcpy(&value, bytes + offset, n < sizeof(value) ? n : sizeof(value));
    digest = (digest ^ value) * UINT64_C(1099511628211);
  }
  return digest ? digest : 1;
}

int main(void) {
  struct group_pmp_mixed_worker_config config = {0};
  struct group_pmp_mixed_worker_result result = {0};
  struct keystone_yxstm_layout_info layout = {0};
  struct keystone_yxstm_slot_info slot = {0};
  struct rv8_kernel_stats stats;
  uint64_t processed = 0, stage = 1;
  if (copy_from_shared(&config, GROUP_PMP_SQLITE_VFS_CONFIG_OFFSET, sizeof(config)) ||
      config.magic != GROUP_PMP_MIXED_MAGIC || config.version != GROUP_PMP_MIXED_VERSION ||
      config.worker_index >= config.worker_count || !config.data_bytes ||
      config.lane_id >= GROUP_PMP_MIXED_LANES || config.lane_rank >= config.lane_depth ||
      config.reserved[0] != GROUP_PMP_SQLITE_FILLSEQ || (config.data_bytes & 15)) return 1;
  result.magic = GROUP_PMP_MIXED_MAGIC;
  result.version = GROUP_PMP_MIXED_VERSION;
  result.worker_index = config.worker_index;
  result.worker_count = config.worker_count;
  result.lane_id = config.lane_id;
  result.lane_rank = config.lane_rank;
  result.data_bytes = config.data_bytes;
  if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) ||
      layout.role != GROUP_ROLE_WORKER || layout.slot_id != config.lane_rank ||
      layout.worker_slice_id != config.lane_id + 1 ||
      group_pmp_yxstm_query_slot_info(&slot, config.lane_id, config.lane_rank) ||
      slot.state != YXSTM_SLOT_FREE) goto fail;
  stage = 2;
  if (group_pmp_register_protocol_mailbox(rv8_clock_page,
        KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK | KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK_ONLY) ||
      rv8_kernel_init()) goto fail;
  /* Fixed private input, identical for both labels; no data UTM is allocated. */
  for (size_t i = 0; i < sizeof(input); ++i)
    input[i] = (uint8_t)((i * 37u) ^ (i >> 8));
  struct keystone_yxstm_slot_command denied = {0};
  denied.operation = KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_ACQUIRE;
  denied.lane_id = config.lane_id;
  denied.slot_id = config.lane_depth > 1 ?
      (config.lane_rank + 1) % config.lane_depth : config.lane_depth;
  denied.expected_epoch = slot.epoch;
  denied.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
  result.cross_slot_denied = group_pmp_yxstm_slot_command(&denied) != 0;
  result.known_answer_ok = 1;
  if (!result.cross_slot_denied || publish(&result, GROUP_PMP_MIXED_STATE_WARMED)) goto fail;
  volatile uint8_t* packet = group_pmp_mixed_slot_payload(&layout, config.lane_id, layout.slot_offset);
  const volatile struct keystone_member_exec_clock* clock =
      (const volatile struct keystone_member_exec_clock*)(rv8_clock_page + KEYSTONE_EXEC_CLOCK_OFFSET);
  result.observed_payload_va = (uintptr_t)packet;
  result.start_cycle = group_pmp_rdcycle();
  if (publish(&result, GROUP_PMP_MIXED_STATE_RUNNING)) goto fail;
  while (processed < config.data_bytes) {
    struct keystone_yxstm_slot_command command = {0};
    struct group_pmp_sqlite_packet_header header;
    struct keystone_exec_clock_sample before, after;
    uint64_t started = group_pmp_rdtime();
    stage = 3;
    command.operation = KEYSTONE_YXSTM_SLOT_WORKER_WAIT_ACQUIRE_BEGIN;
    command.lane_id = config.lane_id;
    command.slot_id = config.lane_rank;
    command.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
    if (group_pmp_yxstm_slot_command(&command) || command.state != YXSTM_SLOT_COMPUTING ||
        command.result != KEYSTONE_YXSTM_SLOT_RESULT_READY || command.payload_size != sizeof(header)) goto fail;
    result.ready_wait_time_ticks += group_pmp_rdtime() - started;
    memcpy(&header, (const void*)(uintptr_t)packet, sizeof(header));
    if (header.magic != GROUP_PMP_SQLITE_PACKET_MAGIC || header.version != GROUP_PMP_SQLITE_PACKET_VERSION ||
        header.workload != config.reserved[0] || header.worker_index != config.worker_index ||
        header.batch_id != result.batch_count + 1 || !header.logical_bytes ||
        command.task_id != config.worker_index + 1 || command.batch_id != header.batch_id ||
        command.sequence != header.sequence ||
        header.value_size != group_pmp_sqlite_value_size(header.workload) ||
        header.record_count != header.logical_bytes / header.value_size ||
        header.logical_bytes % header.value_size ||
        header.logical_bytes > config.data_bytes - processed || (header.logical_bytes & 15) ||
        header.reserved[0] != config.reserved[1] + processed) goto fail;
    stage = 4;
    if (keystone_exec_clock_read(clock, group_pmp_rdtime, &before)) goto fail;
    for (uint64_t done = 0; done < header.logical_bytes;) {
      size_t n = header.logical_bytes - done;
      if (n > sizeof(input)) n = sizeof(input);
      if (rv8_kernel_process(input, n)) goto fail;
      done += n;
    }
    if (keystone_exec_clock_read(clock, group_pmp_rdtime, &after) ||
        before.generation != after.generation || after.runtime_ticks < before.runtime_ticks ||
        after.wall_ticks < before.wall_ticks ||
        after.runtime_ticks - before.runtime_ticks > after.wall_ticks - before.wall_ticks) goto fail;
    rv8_kernel_account(after.runtime_ticks - before.runtime_ticks, after.wall_ticks - before.wall_ticks);
    rv8_kernel_get_stats(&stats);
    header.payload_digest = stats.digest ? stats.digest : 1;
    memcpy((void*)(uintptr_t)packet, &header, sizeof(header));
    __sync_synchronize();
    command.operation = KEYSTONE_YXSTM_SLOT_WORKER_AES_EXEC_END;
    if (group_pmp_yxstm_slot_command(&command)) goto fail;
    command.operation = KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_DONE;
    command.digest = packet_digest(&header);
    started = group_pmp_rdtime();
    uint64_t cycles = group_pmp_rdcycle();
    if (group_pmp_yxstm_slot_command(&command) || command.state != YXSTM_SLOT_DONE || command.permissions) goto fail;
    result.protocol_cycles += group_pmp_rdcycle() - cycles;
    result.protocol_time_ticks += group_pmp_rdtime() - started;
    result.grant_revoke_ok = 1;
    processed += header.logical_bytes;
    ++result.batch_count;
  }
  stage = 5;
  rv8_kernel_get_stats(&stats);
  if (stats.bytes != config.data_bytes || !stats.validated || !stats.cpu_ticks ||
      copy_to_shared_utm(RV8_RESULT_OFFSET, &stats, sizeof(stats))) goto fail;
  result.end_cycle = group_pmp_rdcycle();
  result.digest = stats.digest;
  return publish(&result, GROUP_PMP_MIXED_STATE_COMPLETED) ? 1 : 0;
fail:
  result.digest = stage;
  (void)publish(&result, GROUP_PMP_MIXED_STATE_FAILED);
  return 1;
}
