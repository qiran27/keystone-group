#include <stdio.h>
#include "group-pmp-common.h"
#include "../security/security-sentinel.h"
#ifndef SECURITY_TARGET
#define SECURITY_TARGET 1
#endif
#ifndef SECURITY_WRITE
#define SECURITY_WRITE 0
#endif
int main(void) {
  uintptr_t target = 0;
  struct keystone_yxstm_layout_info layout;
  struct group_pmp_security_probe record = {0};
  if (SECURITY_TARGET == 1) {
    struct group_private_region_info info;
    if (SYSCALL_2(RUNTIME_SYSCALL_GROUP_PRIVATE_REGION_INFO,
                   &info, sizeof(info)) != 0 || !info.private_size) return 90;
    target = info.private_va_base + info.private_size;
  } else {
    if (group_pmp_yxstm_query_layout(&layout, sizeof(layout)) != 0) return 91;
    if (SECURITY_TARGET == 4) {
      struct keystone_yxstm_slot_info slot;
      struct keystone_yxstm_slot_command command = {0};
      if (layout.role != GROUP_ROLE_MASTER ||
          group_pmp_yxstm_query_slot_info(&slot, 0, 0) != 0 ||
          slot.state != YXSTM_SLOT_FREE || !slot.epoch) return 92;
      command.operation = KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_ACQUIRE;
      command.lane_id = slot.lane_id;
      command.slot_id = slot.slot_id;
      command.expected_epoch = slot.epoch;
      command.batch_id = command.task_id = command.sequence = 1;
      command.payload_size = 16;
      command.permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
      if (group_pmp_yxstm_slot_command(&command) != 0 ||
          command.state != YXSTM_SLOT_DISPATCHING) return 93;
      target = (uintptr_t)group_pmp_mixed_slot_payload(&layout, slot.lane_id, slot.slot_offset);
      volatile uint64_t* owned = (volatile uint64_t*)target;
      *owned = UINT64_C(0x7245636f6e74726f);
      if (*owned != UINT64_C(0x7245636f6e74726f)) return 94;
      __sync_synchronize();
      /* PUBLISH releases the Master's grant; the READY permission is the
       * Worker's future permission, not a retained grant for the Master. */
      command.operation = KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_PUBLISH;
      if (group_pmp_yxstm_slot_command(&command) != 0 ||
          command.state != YXSTM_SLOT_READY) return 94;
      record.permission_state = 2; /* control succeeded, grant revoked */
    } else {
      if (layout.role != GROUP_ROLE_WORKER || !layout.slot_size) return 95;
      record.permission_state = 1; /* never acquired */
      const uint64_t lane = SECURITY_TARGET == 3 ?
          (layout.lane_id + 1) % GROUP_PMP_MIXED_LANES : layout.lane_id;
      target = (uintptr_t)group_pmp_mixed_slot_payload(&layout, lane,
          SECURITY_TARGET == 3 ? 0 : layout.slot_offset);
    }
  }
  record.magic = GROUP_PMP_SECURITY_PROBE_MAGIC;
  record.operation = SECURITY_WRITE ? 2 : 1;
  record.target = target;
  record.attempted = 1;
  if (copy_to_shared_utm(GROUP_PMP_SECURITY_PROBE_OFFSET,
                         &record, sizeof(record)) != 0) return 96;
  printf("[security-access] target_kind=%d operation=%s target=0x%lx state=%lu attempt=1\n",
         SECURITY_TARGET, SECURITY_WRITE ? "write" : "read", target,
         record.permission_state);
  fflush(stdout);
  __sync_synchronize();
  if (SECURITY_WRITE) *(volatile uint64_t*)target = UINT64_C(0xbadacc355);
  else { volatile uint64_t value = *(volatile uint64_t*)target; (void)value; }
  return 97; /* An ordinary return is NOT a denial. */
}
