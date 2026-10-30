#ifndef MOTIVATION_TSR_MODEL_HPP
#define MOTIVATION_TSR_MODEL_HPP
// Test-only slot/permission model. It is NOT PMP or a malicious-Host proof.
// The production C protocol below is shared; board callbacks invoke real SM.
#include "../motivation/architecture.h"
#include <pthread.h>
#include <sys/mman.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
namespace NativeTsr {
struct Slot { keystone_yxstm_slot_info info;mot_arch_packet packet;int grant; };
struct Shared { pthread_mutex_t mutex;pthread_cond_t changed;unsigned workers,waiters;Slot slots[3]; };
static Shared* shared=nullptr;
static thread_local int actor=-1; // Master=-1, Worker=zero-based index
struct Lock {
  Lock() {if(pthread_mutex_lock(&shared->mutex)) throw std::runtime_error("TSR model lock");}
  ~Lock() {pthread_mutex_unlock(&shared->mutex);}
};
inline Shared* create(unsigned workers) {
  void* memory=mmap(nullptr,sizeof(Shared),PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED,-1,0);
  if(memory==MAP_FAILED) throw std::runtime_error("TSR model allocation");
  auto* s=static_cast<Shared*>(memory);std::memset(s,0,sizeof(*s));s->workers=workers;
  pthread_mutexattr_t m;pthread_condattr_t c;
  if(pthread_mutexattr_init(&m) || pthread_condattr_init(&c) ||
      pthread_mutexattr_setpshared(&m,PTHREAD_PROCESS_SHARED) || pthread_condattr_setpshared(&c,PTHREAD_PROCESS_SHARED) ||
      pthread_mutex_init(&s->mutex,&m) || pthread_cond_init(&s->changed,&c)) throw std::runtime_error("TSR model synchronization");
  pthread_mutexattr_destroy(&m);pthread_condattr_destroy(&c);
  for(unsigned w=0;w<workers;++w) {s->slots[w].info.lane_id=w;s->slots[w].info.slot_count=1;s->slots[w].info.epoch=1;s->slots[w].grant=-2;}
  return s;
}
inline void destroy(Shared* s) {pthread_cond_destroy(&s->changed);pthread_mutex_destroy(&s->mutex);munmap(s,sizeof(*s));}
inline bool accessible(unsigned lane) {return shared && lane<shared->workers && (actor<0 || actor==static_cast<int>(lane));}
inline int query(unsigned lane,keystone_yxstm_slot_info* out) {
  if(!accessible(lane)) return -1;
  Lock lock;*out=shared->slots[lane].info;return 0;
}
inline bool matches(const Slot& s,const keystone_yxstm_slot_command* c) {
  return c->expected_epoch==s.info.epoch && c->batch_id==s.info.batch_id && c->task_id==s.info.task_id &&
      c->sequence==s.info.sequence && c->payload_size==s.info.payload_size;
}
inline int command(keystone_yxstm_slot_command* c) {
  if(!accessible(c->lane_id) || c->slot_id) return -1;
  Lock lock;Slot& s=shared->slots[c->lane_id];auto& i=s.info;
  const unsigned rw=KEYSTONE_YXSTM_PERM_R|KEYSTONE_YXSTM_PERM_W;
  switch(c->operation) {
    case KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_ACQUIRE:
      if(actor!=-1 || i.state!=YXSTM_SLOT_FREE || c->expected_epoch!=i.epoch || !c->batch_id || !c->task_id ||
          !c->sequence || c->payload_size!=sizeof(mot_arch_packet) || c->permissions!=rw) return -1;
      for(unsigned w=0;w<shared->workers;++w) if(shared->slots[w].grant==actor) return -1;
      i.state=YXSTM_SLOT_DISPATCHING;i.batch_id=c->batch_id;i.task_id=c->task_id;i.sequence=c->sequence;
      i.payload_size=c->payload_size;i.permissions=rw;i.digest=0;s.grant=actor;break;
    case KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_PUBLISH:
      if(actor!=-1 || i.state!=YXSTM_SLOT_DISPATCHING || !matches(s,c) || s.grant!=actor) return -1;
      i.state=YXSTM_SLOT_READY;i.permissions=KEYSTONE_YXSTM_PERM_R;s.grant=-2;break;
    case KEYSTONE_YXSTM_SLOT_WORKER_WAIT_READY:
      // A Worker may wait while its Master still owns DISPATCHING. The SM
      // rejects the caller's own outstanding grant, not the Master's grant.
      if(actor<0 || s.grant==actor || (c->expected_epoch && c->expected_epoch!=i.epoch)) return -1;
      while(i.state!=YXSTM_SLOT_READY) {
        ++shared->waiters;
        int error=pthread_cond_wait(&shared->changed,&shared->mutex);
        --shared->waiters;
        if(error) return -1;
      }
      break;
    case KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_ACQUIRE:
      if(actor<0 || i.state!=YXSTM_SLOT_READY || !matches(s,c) || c->permissions!=rw || s.grant!=-2) return -1;
      i.state=YXSTM_SLOT_COMPUTING;i.permissions=rw;s.grant=actor;break;
    case KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_DONE:
      if(actor<0 || i.state!=YXSTM_SLOT_COMPUTING || !matches(s,c) || !c->digest || s.grant!=actor) return -1;
      i.state=YXSTM_SLOT_DONE;i.permissions=0;i.digest=c->digest;s.grant=-2;break;
    case KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_ACQUIRE:
      if(actor!=-1 || i.state!=YXSTM_SLOT_DONE || !matches(s,c) || c->digest!=i.digest || c->permissions!=KEYSTONE_YXSTM_PERM_R || s.grant!=-2) return -1;
      for(unsigned w=0;w<shared->workers;++w) if(shared->slots[w].grant==actor) return -1;
      i.state=YXSTM_SLOT_AGGREGATING;i.permissions=KEYSTONE_YXSTM_PERM_R;s.grant=actor;break;
    case KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_COMPLETE:
      if(actor!=-1 || i.state!=YXSTM_SLOT_AGGREGATING || !matches(s,c) || c->digest!=i.digest || s.grant!=actor) return -1;
      i.state=YXSTM_SLOT_FREE;i.permissions=0;i.batch_id=i.task_id=i.sequence=i.payload_size=i.digest=0;
      ++i.epoch;s.grant=-2;break;
    default:return -1;
  }
  c->state=i.state;c->expected_epoch=i.epoch;c->batch_id=i.batch_id;c->task_id=i.task_id;c->sequence=i.sequence;
  c->payload_size=i.payload_size;c->digest=i.digest;c->permissions=i.permissions;c->result=KEYSTONE_YXSTM_SLOT_RESULT_READY;
  pthread_cond_broadcast(&shared->changed);return 0;
}
inline int load(unsigned lane,mot_arch_packet* out) {
  if(!accessible(lane)) return -1;
  Lock lock;const Slot& s=shared->slots[lane];
  if(s.grant!=actor || !(s.info.permissions&KEYSTONE_YXSTM_PERM_R)) return -1;
  *out=s.packet;return 0;
}
inline int store(unsigned lane,const mot_arch_packet* in) {
  if(!accessible(lane)) return -1;
  Lock lock;Slot& s=shared->slots[lane];
  if(s.grant!=actor || !(s.info.permissions&KEYSTONE_YXSTM_PERM_W)) return -1;
  s.packet=*in;return 0;
}
inline int yield(uint64_t) {
  Lock lock;
  for(;;) {
    for(unsigned w=0;w<shared->workers;++w) if(shared->slots[w].info.state==YXSTM_SLOT_DONE) return 0;
    if(pthread_cond_wait(&shared->changed,&shared->mutex)) return -1;
  }
}
}
#endif
