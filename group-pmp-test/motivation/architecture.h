#ifndef MOTIVATION_ARCHITECTURE_H
#define MOTIVATION_ARCHITECTURE_H
#include "core.h"
#include "shared/sm_call.h"
#define MOT_ARCH_MARKER "keystone-motivation-protected-task-v4"
#define MOT_ARCH_VERSION 4u
#define MOT_ARCH_MAGIC UINT64_C(0x4d4f545453523031)
#define MOT_ARCH_BOOT_OFFSET 512u
#define MOT_ARCH_RESULT_OFFSET 1024u
#define MOT_ARCH_START 9u
#define MOT_ARCH_DONE 10u
#define MOT_ARCH_DISPATCHED 11u
#define MOT_ARCH_WAIT 12u
struct mot_arch_boot {
  uint64_t magic,version,role,workers,worker;
  struct mot_config config;
};
struct mot_arch_packet {
  uint64_t magic,version,worker,lane,epoch,sequence;
  struct mot_config config;
  uint64_t processed,blocks,digest,valid,acquire_ticks,done_ticks;
};
struct mot_arch_witness {
  uint64_t worker,lane,epoch,sequence,dispatch_begin,dispatch_end;
  uint64_t acquire_ticks,done_ticks,aggregate_begin,aggregate_end;
};
struct mot_arch_result {
  uint64_t magic,version,valid,workers,dispatches,aggregates,releases;
  uint64_t processed,blocks,digest,begin_ticks,end_ticks;
  struct mot_arch_witness tasks[3];
};
/* Thin interfaces: board callbacks call the existing SDK/SM slot operations.
 * Native tests inject a strict shared-memory protocol model, not PMP emulation. */
struct mot_arch_api {
  int (*query)(unsigned,struct keystone_yxstm_slot_info*);
  int (*command)(struct keystone_yxstm_slot_command*);
  int (*load)(unsigned,struct mot_arch_packet*);
  int (*store)(unsigned,const struct mot_arch_packet*);
  int (*yield)(uint64_t aggregated);
  int (*exchange)(const struct mot_call*,struct mot_reply*);
  uint64_t (*ticks)(void);
};
struct mot_arch_worker {
  struct mot_arch_boot boot;
  const struct mot_arch_api* api;
  struct keystone_yxstm_slot_command identity;
  struct mot_arch_packet packet;
  int acquired,completed;
};
#ifdef __cplusplus
extern "C" {
#endif
int mot_arch_valid_boot(const struct mot_arch_boot*);
uint64_t mot_arch_digest(const struct mot_arch_packet*);
int mot_arch_master(const struct mot_arch_boot*,const struct mot_arch_api*,struct mot_arch_result*);
int mot_arch_worker_acquire(struct mot_arch_worker*,struct mot_config*);
int mot_arch_worker_complete(struct mot_arch_worker*,const struct mot_config*,const struct mot_call*);
#ifdef __cplusplus
}
#endif
#endif
