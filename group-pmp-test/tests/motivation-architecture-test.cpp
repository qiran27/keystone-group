#include "motivation-tsr-model.hpp"
#include "../motivation/read-engine.hpp"
#include <cassert>
#include <thread>
#include <iostream>
#include <atomic>
static int exchange(const mot_call*,mot_reply* r) {r->status=0;return 0;}
static const mot_arch_api api={NativeTsr::query,NativeTsr::command,NativeTsr::load,NativeTsr::store,
    NativeTsr::yield,exchange,Motivation::ticks};
int main() {
  // Force the legal arrival order that the old native model rejected.
  NativeTsr::shared=NativeTsr::create(1);NativeTsr::actor=-1;
  keystone_yxstm_slot_command dispatch={};
  dispatch.operation=KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_ACQUIRE;dispatch.expected_epoch=1;
  dispatch.batch_id=dispatch.task_id=dispatch.sequence=1;dispatch.payload_size=sizeof(mot_arch_packet);
  dispatch.permissions=KEYSTONE_YXSTM_PERM_R|KEYSTONE_YXSTM_PERM_W;
  assert(!NativeTsr::command(&dispatch));
  std::atomic<bool> returned{false};int wait_result=-99;
  std::thread waiting([&]{
    NativeTsr::actor=0;keystone_yxstm_slot_command c={};c.operation=KEYSTONE_YXSTM_SLOT_WORKER_WAIT_READY;
    wait_result=NativeTsr::command(&c);returned=true;
  });
  bool blocked=false;const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
  while(!returned && std::chrono::steady_clock::now()<deadline) {
    {NativeTsr::Lock lock;blocked=NativeTsr::shared->waiters==1;}
    if(blocked) break;
    std::this_thread::yield();
  }
  assert(blocked && !returned);
  dispatch.operation=KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_PUBLISH;assert(!NativeTsr::command(&dispatch));
  waiting.join();assert(!wait_result);NativeTsr::destroy(NativeTsr::shared);
  for(uint64_t block_size:{UINT64_C(4096),UINT64_C(16384),UINT64_C(65536)}) for(unsigned workers:{1u,3u}) {
    NativeTsr::shared=NativeTsr::create(workers);
    mot_config config={MOT_MAGIC,600003,19,MOT_ASYNC,1000000000,0,0,MOT_CIPHER_ECB,block_size,0};
    config.limit_block=mot_count(&config);
    mot_arch_boot master={MOT_ARCH_MAGIC,MOT_ARCH_VERSION,GROUP_ROLE_MASTER,workers,0,config};mot_arch_result result={};
    std::thread tasks[3];
    for(unsigned w=0;w<workers;++w) tasks[w]=std::thread([&,w]{
      NativeTsr::actor=w;mot_arch_worker worker={};worker.boot=master;worker.boot.role=GROUP_ROLE_WORKER;worker.boot.worker=w;
      assert(!mot_partition(&worker.boot.config,w,workers));worker.api=&api;
      mot_config cfg=worker.boot.config;
      mot_arch_packet denied={};assert(NativeTsr::load(w,&denied)); // no grant before READY/acquire
      if(workers==3) {keystone_yxstm_slot_info foreign;assert(NativeTsr::query((w+1)%3,&foreign));}
      assert(!mot_arch_worker_acquire(&worker,&cfg));
      auto stale=worker.identity;stale.operation=KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_DONE;stale.expected_epoch++;stale.digest=1;
      assert(NativeTsr::command(&stale));
      mot_call value={};value.processed=mot_range_bytes(&cfg);value.blocks=cfg.limit_block-cfg.first_block;value.digest=w+1;
      assert(!mot_arch_worker_complete(&worker,&cfg,&value));
      assert(mot_arch_worker_complete(&worker,&cfg,&value)); // cannot duplicate a result
      assert(NativeTsr::load(w,&denied)); // revoked immediately, even before aggregate
      assert(NativeTsr::store(w,&denied));
    });
    NativeTsr::actor=-1;assert(!mot_arch_master(&master,&api,&result));
    for(unsigned w=0;w<workers;++w) tasks[w].join();
    assert(result.valid && result.processed==config.input_bytes && result.blocks==mot_count(&config));
    assert(result.dispatches==workers && result.aggregates==workers && result.releases==workers);
    uint64_t digest=0;for(unsigned w=0;w<workers;++w) digest^=w+1;assert(result.digest==digest);
    for(unsigned w=0;w<workers;++w) {
      keystone_yxstm_slot_info slot;assert(!NativeTsr::query(w,&slot));assert(slot.state==YXSTM_SLOT_FREE && slot.epoch==2 && !slot.permissions);
      assert(result.tasks[w].epoch==1 && result.tasks[w].sequence==w+1);
    }
    NativeTsr::destroy(NativeTsr::shared);
  }
  mot_arch_boot bad={};assert(!mot_arch_valid_boot(&bad));
  std::cout<<"actual C Master/Worker task protocol: dispatch/acquire/result/aggregate/free, 1/3 partitions, stale/foreign/duplicate/revoked access model PASS (not hardware PMP)\n";
}
