#include "architecture.h"
#include <string.h>
_Static_assert(MOT_ARCH_BOOT_OFFSET+sizeof(struct mot_arch_boot)<=MOT_ARCH_RESULT_OFFSET,"bootstrap overlap");
_Static_assert(MOT_ARCH_RESULT_OFFSET+sizeof(struct mot_arch_result)<=MOT_META_OFFSET,"result overlap");
static int valid_config(const struct mot_config* c) {
  return c->magic==MOT_MAGIC && c->object && c->input_bytes && c->input_bytes<=500000000 &&
      c->mode>=MOT_SYNC && c->mode<=MOT_ASYNC && c->cipher<=MOT_CIPHER_ECB && c->timebase_hz>=1000 &&
      mot_valid_geometry(c) && c->first_block<c->limit_block && c->limit_block<=mot_count(c);
}
int mot_arch_valid_boot(const struct mot_arch_boot* b) {
  return b && b->magic==MOT_ARCH_MAGIC && b->version==MOT_ARCH_VERSION && (b->workers==1 || b->workers==3) &&
      (b->role==GROUP_ROLE_MASTER || (b->role==GROUP_ROLE_WORKER && b->worker<b->workers)) &&
      valid_config(&b->config) && !(b->workers==3 && b->config.mode==MOT_SYNC) &&
      (b->role!=GROUP_ROLE_MASTER || (!b->config.first_block && b->config.limit_block==mot_count(&b->config)));
}
uint64_t mot_arch_digest(const struct mot_arch_packet* p) {
  const unsigned char* bytes=(const unsigned char*)p;
  uint64_t digest=UINT64_C(1469598103934665603);
  for(size_t i=0;i<sizeof(*p);++i) digest=(digest^bytes[i])*UINT64_C(1099511628211);
  return digest?digest:1;
}
static void identity(struct keystone_yxstm_slot_command* c,unsigned lane,
    const struct keystone_yxstm_slot_info* info) {
  memset(c,0,sizeof(*c));c->lane_id=lane;c->slot_id=0;
  c->expected_epoch=info->epoch;c->batch_id=info->batch_id;c->task_id=info->task_id;
  c->sequence=info->sequence;c->payload_size=info->payload_size;c->digest=info->digest;
}
static int same_packet(const struct mot_arch_packet* p,const struct mot_arch_boot* b,
    unsigned w,const struct keystone_yxstm_slot_info* slot) {
  struct mot_config part=b->config;
  if(mot_partition(&part,w,b->workers)) return 0;
  return p->magic==MOT_ARCH_MAGIC && p->version==MOT_ARCH_VERSION && p->worker==w && p->lane==w &&
      p->epoch==slot->epoch && p->sequence==w+1 && slot->batch_id==1 && slot->task_id==w+1 &&
      slot->sequence==w+1 && slot->payload_size==sizeof(*p) && !memcmp(&p->config,&part,sizeof(part));
}
int mot_arch_master(const struct mot_arch_boot* b,const struct mot_arch_api* a,struct mot_arch_result* r) {
  struct mot_call call={0};struct mot_reply reply;
  unsigned done[3]={0,0,0};
  if(!mot_arch_valid_boot(b) || b->role!=GROUP_ROLE_MASTER) return 40;
  memset(r,0,sizeof(*r));r->magic=MOT_ARCH_MAGIC;r->version=MOT_ARCH_VERSION;r->workers=b->workers;
  for(unsigned w=0;w<b->workers;++w) {
    struct keystone_yxstm_slot_info slot;
    if(a->query(w,&slot) || slot.state!=YXSTM_SLOT_FREE || slot.slot_count!=1) return 41;
  }
  call.op=MOT_ARCH_START;
  if(a->exchange(&call,&reply) || reply.status) return 42;
  r->begin_ticks=a->ticks();
  for(unsigned w=0;w<b->workers;++w) {
    struct keystone_yxstm_slot_info slot;struct keystone_yxstm_slot_command c;
    struct mot_arch_packet p={0};struct mot_arch_witness* t=&r->tasks[w];
    t->worker=w;t->lane=w;t->sequence=w+1;t->dispatch_begin=a->ticks();
    if(a->query(w,&slot) || slot.state!=YXSTM_SLOT_FREE) return 43;
    identity(&c,w,&slot);c.operation=KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_ACQUIRE;
    c.batch_id=1;c.task_id=w+1;c.sequence=w+1;c.payload_size=sizeof(p);
    c.permissions=KEYSTONE_YXSTM_PERM_R|KEYSTONE_YXSTM_PERM_W;
    if(a->command(&c) || c.state!=YXSTM_SLOT_DISPATCHING) return 44;
    p.magic=MOT_ARCH_MAGIC;p.version=MOT_ARCH_VERSION;p.worker=w;p.lane=w;p.epoch=c.expected_epoch;p.sequence=w+1;
    p.config=b->config;if(mot_partition(&p.config,w,b->workers) || a->store(w,&p)) return 45;
    __sync_synchronize();c.operation=KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_PUBLISH;
    if(a->command(&c) || c.state!=YXSTM_SLOT_READY || c.permissions!=KEYSTONE_YXSTM_PERM_R) return 46;
    t->epoch=p.epoch;t->dispatch_end=a->ticks();++r->dispatches;
  }
  call.op=MOT_ARCH_DISPATCHED;call.blocks=r->dispatches;
  if(a->exchange(&call,&reply) || reply.status) return 53;
  while(r->aggregates<b->workers) {
    unsigned progress=0;
    for(unsigned w=0;w<b->workers;++w) if(!done[w]) {
      struct keystone_yxstm_slot_info slot;struct keystone_yxstm_slot_command c;
      struct mot_arch_packet p;struct mot_arch_witness* t=&r->tasks[w];
      if(a->query(w,&slot)) return 47;
      if(slot.state!=YXSTM_SLOT_DONE) continue;
      t->aggregate_begin=a->ticks();identity(&c,w,&slot);
      c.operation=KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_ACQUIRE;c.permissions=KEYSTONE_YXSTM_PERM_R;
      if(a->command(&c) || c.state!=YXSTM_SLOT_AGGREGATING || a->load(w,&p)) return 48;
      if(!same_packet(&p,b,w,&slot) || p.epoch!=t->epoch || !p.valid ||
          p.processed!=mot_range_bytes(&p.config) || p.blocks!=p.config.limit_block-p.config.first_block ||
          mot_arch_digest(&p)!=slot.digest || p.acquire_ticks<t->dispatch_begin ||
          p.done_ticks<p.acquire_ticks || p.done_ticks>t->aggregate_begin) return 49;
      r->processed+=p.processed;r->blocks+=p.blocks;r->digest^=p.digest;
      t->acquire_ticks=p.acquire_ticks;t->done_ticks=p.done_ticks;
      c.operation=KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_COMPLETE;
      if(a->command(&c) || c.state!=YXSTM_SLOT_FREE || c.permissions) return 50;
      t->aggregate_end=a->ticks();++r->aggregates;++r->releases;done[w]=1;progress=1;
    }
    if(r->aggregates<b->workers && !progress && a->yield(r->aggregates)) return 51;
  }
  r->end_ticks=a->ticks();
  if(r->processed!=b->config.input_bytes || r->blocks!=mot_count(&b->config) ||
      r->end_ticks<=r->begin_ticks) return 52;
  r->valid=1;return 0;
}
int mot_arch_worker_acquire(struct mot_arch_worker* w,struct mot_config* config) {
  struct keystone_yxstm_slot_command c={0};struct keystone_yxstm_slot_info slot;
  if(!w || !mot_arch_valid_boot(&w->boot) || w->boot.role!=GROUP_ROLE_WORKER || w->acquired ||
      memcmp(config,&w->boot.config,sizeof(*config))) return -1;
  unsigned lane=(unsigned)w->boot.worker;
  c.operation=KEYSTONE_YXSTM_SLOT_WORKER_WAIT_READY;c.lane_id=lane;c.slot_id=0;
  if(w->api->command(&c) || c.result!=KEYSTONE_YXSTM_SLOT_RESULT_READY ||
      w->api->query(lane,&slot) || slot.state!=YXSTM_SLOT_READY) return -1;
  identity(&c,lane,&slot);c.operation=KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_ACQUIRE;
  c.permissions=KEYSTONE_YXSTM_PERM_R|KEYSTONE_YXSTM_PERM_W;
  if(w->api->command(&c) || c.state!=YXSTM_SLOT_COMPUTING || w->api->load(lane,&w->packet)) return -1;
  /* Task identity comes from the protected slot, not from an ordinary-world
   * descriptor. Bootstrap config is only a bounds/fixture consistency check. */
  struct mot_arch_boot whole=w->boot;whole.config.first_block=0;whole.config.limit_block=mot_count(config);
  if(!same_packet(&w->packet,&whole,lane,&slot) || w->packet.valid ||
      memcmp(&w->packet.config,config,sizeof(*config))) return -1;
  w->identity=c;w->packet.acquire_ticks=w->api->ticks();*config=w->packet.config;w->acquired=1;return 0;
}
int mot_arch_worker_complete(struct mot_arch_worker* w,const struct mot_config* config,const struct mot_call* result) {
  if(!w || !w->acquired || w->completed || memcmp(config,&w->packet.config,sizeof(*config)) ||
      result->processed!=mot_range_bytes(config) || result->blocks!=config->limit_block-config->first_block) return -1;
  w->packet.processed=result->processed;w->packet.blocks=result->blocks;w->packet.digest=result->digest;
  w->packet.valid=1;w->packet.done_ticks=w->api->ticks();
  if(w->api->store((unsigned)w->boot.worker,&w->packet)) return -1;
  __sync_synchronize();
  w->identity.operation=KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_DONE;w->identity.digest=mot_arch_digest(&w->packet);
  if(w->api->command(&w->identity) || w->identity.state!=YXSTM_SLOT_DONE || w->identity.permissions) return -1;
  w->completed=1;return 0;
}
