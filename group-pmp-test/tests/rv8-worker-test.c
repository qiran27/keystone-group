/* Execute the production worker with only the SM/UTM boundary simulated. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "shared/sm_call.h"
#include "group-pmp-mixed-shared.h"
#include "group-pmp-sqlite-shared.h"
#include "group-pmp-sqlite-vfs-shared.h"
#include "rv8-kernels.h"
#define GROUP_PMP_COMMON_H
#define GROUP_PMP_DEFINE_PROTOCOL_MAILBOX(name) static uint8_t name[4096]
static struct group_pmp_mixed_worker_config setup;
static struct group_pmp_sqlite_packet_header task;
static uint8_t control[4096];
static uint64_t ticks, completed, dispatches;
static int corrupt;
static uint64_t group_pmp_rdtime(void) { return ++ticks; }
static uint64_t group_pmp_rdcycle(void) { return ++ticks; }
static int copy_from_shared(void* out, uintptr_t offset, size_t size) {
  assert(offset == GROUP_PMP_SQLITE_VFS_CONFIG_OFFSET && size == sizeof(setup));
  memcpy(out, &setup, size); return 0;
}
static int copy_to_shared_utm(uintptr_t offset, const void* data, size_t size) {
  /* Only statistics/state, never a kernel buffer or algorithm output. */
  assert((offset == GROUP_PMP_SQLITE_VFS_RESULT_OFFSET && size == sizeof(struct group_pmp_mixed_worker_result)) ||
         (offset == GROUP_PMP_SQLITE_VFS_RESULT_OFFSET + offsetof(struct group_pmp_mixed_worker_result, status) && size == 8) ||
         (offset == RV8_RESULT_OFFSET && size == sizeof(struct rv8_kernel_stats)));
  assert(offset + size <= sizeof(control));
  memcpy(control + offset, data, size); return 0;
}
static int group_pmp_register_protocol_mailbox(uint8_t* page, uint64_t flags) {
  assert(flags == (KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK | KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK_ONLY));
  struct keystone_member_exec_clock* c = (void*)(page + KEYSTONE_EXEC_CLOCK_OFFSET);
  memset(c, 0, sizeof(*c));
  c->sequence = 2; c->version = KEYSTONE_EXEC_CLOCK_VERSION;
  c->generation = 1; c->running = 1; return 0;
}
static int group_pmp_yxstm_query_layout(struct keystone_yxstm_layout_info* l, size_t size) {
  assert(size == sizeof(*l));
  l->role = GROUP_ROLE_WORKER; l->worker_slice_id = setup.lane_id + 1;
  l->slot_id = setup.lane_rank; return 0;
}
static int group_pmp_yxstm_query_slot_info(struct keystone_yxstm_slot_info* s, uint64_t lane, uint64_t rank) {
  assert(lane == setup.lane_id && rank == setup.lane_rank);
  s->state = YXSTM_SLOT_FREE; return 0;
}
static volatile uint8_t* group_pmp_mixed_slot_payload(const struct keystone_yxstm_layout_info* l, uint64_t lane, uint64_t offset) {
  (void)l; (void)lane; (void)offset; return (volatile uint8_t*)&task;
}
static int group_pmp_yxstm_slot_command(struct keystone_yxstm_slot_command* c) {
  if (c->operation == KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_ACQUIRE) return 1;
  assert(c->lane_id == setup.lane_id && c->slot_id == setup.lane_rank);
  if (c->operation == KEYSTONE_YXSTM_SLOT_WORKER_WAIT_ACQUIRE_BEGIN) {
    memset(&task, 0, sizeof(task));
    task.magic = GROUP_PMP_SQLITE_PACKET_MAGIC;
    task.version = GROUP_PMP_SQLITE_PACKET_VERSION;
    task.workload = setup.reserved[0]; task.worker_index = setup.worker_index;
    task.batch_id = ++dispatches; task.logical_bytes = setup.data_bytes - completed;
    if (task.logical_bytes > 1999920) task.logical_bytes = 1999920;
    task.value_size = group_pmp_sqlite_value_size(task.workload);
    task.record_count = task.logical_bytes / task.value_size;
    task.sequence = dispatches;
    c->task_id = setup.worker_index + 1; c->batch_id = task.batch_id; c->sequence = task.sequence;
    task.reserved[0] = setup.reserved[1] + completed + (corrupt ? 16 : 0);
    c->result = KEYSTONE_YXSTM_SLOT_RESULT_READY; c->state = YXSTM_SLOT_COMPUTING;
    c->payload_size = sizeof(task);
  } else if (c->operation == KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_DONE) {
    assert(task.payload_digest && c->digest);
    completed += task.logical_bytes; c->state = YXSTM_SLOT_DONE; c->permissions = 0;
  } else assert(c->operation == KEYSTONE_YXSTM_SLOT_WORKER_AES_EXEC_END);
  return 0;
}
#define main rv8_worker_main
#include "../eapp/group-pmp-rv8-worker.c"
#undef main
int main(void) {
  for (unsigned workers = 1; workers <= 4; workers += 3) {
    for (unsigned index = 0; index < workers; ++index) {
      for (corrupt = 0; corrupt <= 1; ++corrupt) {
        memset(&setup, 0, sizeof(setup)); memset(control, 0, sizeof(control));
        ticks = completed = dispatches = 0;
        setup.magic = GROUP_PMP_MIXED_MAGIC; setup.version = GROUP_PMP_MIXED_VERSION;
        setup.worker_count = workers; setup.worker_index = index;
        setup.lane_id = index % 3; setup.lane_rank = index / 3; setup.lane_depth = workers == 4 ? 2 : 1;
        setup.data_bytes = 4000080; setup.reserved[0] = GROUP_PMP_SQLITE_FILLSEQ;
        setup.reserved[1] = index * setup.data_bytes;
        assert((rv8_worker_main() != 0) == corrupt);
        struct group_pmp_mixed_worker_result result;
        struct rv8_kernel_stats stats;
        memcpy(&result, control + GROUP_PMP_SQLITE_VFS_RESULT_OFFSET, sizeof(result));
        memcpy(&stats, control + RV8_RESULT_OFFSET, sizeof(stats));
        assert(!result.ocall_count && !result.vfs_submit_count && !result.aes_cycles && !result.hidden_copy_bytes);
        if (corrupt) assert(result.status == GROUP_PMP_MIXED_STATE_FAILED && completed == 0);
        else {
          assert(result.status == GROUP_PMP_MIXED_STATE_COMPLETED && completed == setup.data_bytes);
          assert(stats.version == 2 && stats.bytes == completed && stats.cpu_ticks && stats.validated);
          assert(result.batch_count == dispatches && result.grant_revoke_ok);
        }
      }
    }
  }
  puts("RV8 worker N=1/4 identities, multi-task tails, zero data-UTM/I/O/AES, malformed-task rejection PASS");
}
