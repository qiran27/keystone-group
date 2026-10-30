#include "group-pmp-common.h"
#include "../motivation/core.h"
#include "../motivation/architecture.h"
static const volatile char arch_marker[] __attribute__((used))=MOT_ARCH_MARKER;
static struct keystone_yxstm_layout_info arch_layout;
static struct mot_arch_worker arch_worker;
static int mot_exchange(const struct mot_call* c, struct mot_reply* r) {
  return ocall(MOT_OCALL,(void*)c,sizeof(*c),r,sizeof(*r));
}
static int mot_capture(void* dest,size_t offset,size_t n) { return copy_from_shared(dest,offset,n); }
static int mot_publish(size_t offset,const void* src,size_t n) { return copy_to_shared_utm(offset,(void*)src,n); }
static int arch_query(unsigned lane,struct keystone_yxstm_slot_info* slot) {
  return group_pmp_yxstm_query_slot_info(slot,lane,0);
}
static int arch_command(struct keystone_yxstm_slot_command* c) { return group_pmp_yxstm_slot_command(c); }
static volatile uint8_t* arch_payload(unsigned lane) {
  struct keystone_yxstm_slot_info slot;
  if(arch_query(lane,&slot) || slot.payload_size!=sizeof(struct mot_arch_packet)) return 0;
  return group_pmp_mixed_slot_payload(&arch_layout,lane,slot.slot_offset);
}
static int arch_load(unsigned lane,struct mot_arch_packet* p) {
  volatile uint8_t* ptr=arch_payload(lane);if(!ptr) return -1;
  memcpy(p,(const void*)(uintptr_t)ptr,sizeof(*p));return 0;
}
static int arch_store(unsigned lane,const struct mot_arch_packet* p) {
  volatile uint8_t* ptr=arch_payload(lane);if(!ptr) return -1;
  memcpy((void*)(uintptr_t)ptr,p,sizeof(*p));__sync_synchronize();return 0;
}
static int arch_wait(uint64_t aggregated) {
  struct mot_call call={0};struct mot_reply reply;
  call.op=MOT_ARCH_WAIT;call.blocks=aggregated;
  return mot_exchange(&call,&reply) || reply.status ? -1 : 0;
}
static const struct mot_arch_api arch_api={arch_query,arch_command,arch_load,arch_store,
    arch_wait,mot_exchange,group_pmp_rdtime};
static int arch_acquire(struct mot_config* cfg) { return mot_arch_worker_acquire(&arch_worker,cfg); }
static int arch_complete(const struct mot_config* cfg,const struct mot_call* r) { return mot_arch_worker_complete(&arch_worker,cfg,r); }
int main(void) {
  const struct mot_api api={mot_exchange,mot_capture,mot_publish,group_pmp_rdtime};
  struct mot_arch_boot boot;
  if(arch_marker[0]!='k' || copy_from_shared(&boot,MOT_ARCH_BOOT_OFFSET,sizeof(boot))) return 60;
  if(boot.magic==MOT_ARCH_MAGIC) {
    if(!mot_arch_valid_boot(&boot) || group_pmp_yxstm_query_layout(&arch_layout,sizeof(arch_layout)) ||
        arch_layout.role!=boot.role || arch_layout.bank_slice_size==0 ||
        (boot.role==GROUP_ROLE_WORKER && (arch_layout.worker_slice_id!=boot.worker+1 ||
          arch_layout.slot_id || arch_layout.slot_count!=1 || arch_layout.slot_payload_size<sizeof(struct mot_arch_packet)))) return 61;
    if(boot.role==GROUP_ROLE_MASTER) {
      struct mot_arch_result result;
      struct mot_call call={0};struct mot_reply reply;
      int rc=mot_arch_master(&boot,&arch_api,&result);if(rc) return rc;
      if(mot_publish(MOT_ARCH_RESULT_OFFSET,&result,sizeof(result))) return 62;
      call.op=MOT_ARCH_DONE;call.digest=result.digest;call.processed=result.processed;call.blocks=result.blocks;
      return mot_exchange(&call,&reply) || reply.status ? 63 : 0;
    }
    arch_worker.boot=boot;arch_worker.api=&arch_api;
    const struct mot_task_api task={arch_acquire,arch_complete};
    return mot_run_task(&api,&task);
  }
  return mot_run(&api);
}
