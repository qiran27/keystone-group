/* Included inside the runner namespace. Auxiliary and protected-task entries. */
#include "motivation-enclave-config.hpp"
#include "../motivation/architecture.h"
static bool run_motivation_architecture(const char* runtime,const char* loader);
struct MotivationRun {
  std::vector<std::unique_ptr<Motivation::Backend>> services;
  std::vector<std::shared_ptr<SqliteAsyncCompletion>> starts;
  std::shared_ptr<Motivation::Counters> counters=std::make_shared<Motivation::Counters>();
  size_t current=0;
  uint64_t begin=0,end=0;
  mot_call aggregate={};
  bool handler_failed=false;
};
static MotivationRun* motivation_run=nullptr;
static void motivation_ocall(void* buffer) {
  auto* edge=static_cast<edge_call*>(buffer);
  uintptr_t args=0; size_t size=0; mot_call c={}; mot_reply r={}; r.status=-1;
  if(!motivation_run || motivation_run->current>=motivation_run->services.size() ||
     edge_call_args_ptr(edge,&args,&size) || size!=sizeof(c)) {
    edge->return_data.call_status=CALL_STATUS_BAD_OFFSET;
    if(motivation_run) motivation_run->handler_failed=true;
    return;
  }
  auto& run=*motivation_run;
  auto& backend=*run.services[run.current];
  std::memcpy(&c,reinterpret_cast<void*>(args),sizeof(c));
  int error=0;
  if(c.op==MOT_WAIT_ANY) {
    // The existing deferred resume mechanism leaves the dispatcher available
    // while this Worker waits for file I/O.
    auto completion=std::make_shared<SqliteAsyncCompletion>();
    error=backend.wait_async([completion]{completion->completeOne();},r);
    if(!error) sqlite_dispatched_completion=completion;
  } else {
    error=backend.handle(c,r);
    if(!error && c.op==MOT_START) {
      auto completion=std::make_shared<SqliteAsyncCompletion>();
      if(run.starts[run.current]) throw std::runtime_error("duplicate START barrier arrival");
      run.starts[run.current]=completion;
      sqlite_dispatched_completion=completion;
      bool all=true;
      for(const auto& ready:run.starts) all=all && static_cast<bool>(ready);
      if(all) {
        if(!run.services[0]->prepare_group_cache()) throw std::runtime_error("cohort cache preparation");
        for(auto& service:run.services)
          if(!service->enable_group_start()) throw std::runtime_error("cohort start state");
        run.begin=Motivation::ticks();
        for(const auto& ready:run.starts) ready->completeOne();
      }
    }
    if(!error && c.op==MOT_DONE) {
      bool all=true;
      for(const auto& service:run.services) all=all && service->finished;
      if(all) {
        run.aggregate={};
        for(const auto& service:run.services) {
          const auto& value=service->result;
          run.aggregate.processed+=value.processed; run.aggregate.blocks+=value.blocks;
          run.aggregate.digest^=value.digest; run.aggregate.waits+=value.waits;
          run.aggregate.early_returns+=value.early_returns; run.aggregate.out_of_order+=value.out_of_order;
        }
        if(run.aggregate.processed!=backend.config.input_bytes ||
           run.aggregate.blocks!=mot_count(&backend.config) || run.counters->outstanding.load())
          throw std::runtime_error("cohort total/ownership mismatch");
        for(const auto& service:run.services)
          if(service->completed_reads()!=service->result.blocks ||
             service->data_operations!=service->result.blocks || !service->submit_calls())
            throw std::runtime_error("cohort registered I/O accounting mismatch");
        run.end=Motivation::ticks();
      }
    }
  }
  if(error) {
    run.handler_failed=true;
    std::cerr<<"[motivation] protocol/file/cache failure worker="<<run.current+1
             <<" op="<<c.op<<" block="<<c.block<<" slot="<<c.slot<<" errno="<<errno<<std::endl;
  }
  uintptr_t out=edge_call_data_ptr(); std::memcpy(reinterpret_cast<void*>(out),&r,sizeof(r));
  edge->return_data.call_status=edge_call_setup_ret(edge,reinterpret_cast<void*>(out),sizeof(r)) ? CALL_STATUS_BAD_PTR : CALL_STATUS_OK;
}
static std::string motivation_env(const char* name,const char* fallback="") {
  const char* v=std::getenv(name); return v?v:fallback;
}
static uint64_t motivation_cipher() {
  const std::string value=motivation_env("MOT_CIPHER","aes-gcm-128");
  if(value=="aes-gcm-128" || value=="aes-128-gcm" || value=="gcm") return MOT_CIPHER_GCM;
  if(value=="aes-ecb-128" || value=="aes-128-ecb" || value=="ecb") return MOT_CIPHER_ECB;
  return UINT64_MAX;
}
static bool run_motivation(const char* runtime,const char* loader) {
  if(motivation_env("MOT_ARCHITECTURE")=="1" && motivation_env("MOT_MODE")!="prepare")
    return run_motivation_architecture(runtime,loader);
  static const volatile char marker[] __attribute__((used))=MOT_MARKER;
  static const char cohort_marker[] __attribute__((used))="keystone-motivation-three-config-v2";
  static const char transport_marker[] __attribute__((used))="keystone-motivation-shared-uring-v3";
  static const char blocking_marker[] __attribute__((used))="keystone-motivation-blocking-ocall-v4";
  const std::string mode=motivation_env("MOT_MODE"),path=motivation_env("MOT_FILE"),cache=motivation_env("MOT_CACHE","cold");
  const bool prep=mode=="prepare",diag=motivation_env("MOT_DIAGNOSTIC")=="1";
  const unsigned workers=static_cast<unsigned>(env_u64("MOT_WORKERS",1,1,3));
  mot_config cfg={MOT_MAGIC,env_u64("MOT_BYTES",60000000,1,500000000),
      env_u64("MOT_OBJECT",0,0,UINT64_MAX),prep?MOT_PREPARE:mode=="sync"?MOT_SYNC:MOT_ASYNC,0,0,0,motivation_cipher(),env_u64("MOT_BLOCK_BYTES",65536,1,65536),diag?UINT64_C(1):UINT64_C(0)};
  if(marker[0]!='k' || path.empty() || !cfg.object || cfg.cipher>MOT_CIPHER_ECB || (workers!=1 && workers!=3) ||
     (workers==3 && mode!="async") || (!prep && mode!="sync" && mode!="async") ||
     (cache!="cold" && cache!="hot")) return false;
  if(!std::getenv("GROUP_PMP_TIMEBASE_HZ")) {
    std::ifstream f("/proc/device-tree/cpus/timebase-frequency",std::ios::binary);
    std::vector<unsigned char> b((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
    if(b.size()!=4 && b.size()!=8) return false;
    for(auto v:b) cfg.timebase_hz=(cfg.timebase_hz<<8)|v;
  } else cfg.timebase_hz=env_u64("GROUP_PMP_TIMEBASE_HZ",0,0,UINT64_MAX);
  if(cfg.timebase_hz<1000 || mot_count(&cfg)<workers) return false;
  std::vector<EnclaveInstance> enclaves;
  MotivationRun run; run.starts.resize(workers);
  Keystone::KeystoneDevice device; Params params; keystone_group_lease lease={};
  const uint64_t flags=KEYSTONE_GROUP_LEASE_FLAG_REQUIRE_ISOLATION |
      KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE | KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
  bool leased=false,ok=false; uint64_t terminal_value=UINT64_MAX;
  try {
    if(!pin_current_thread_to_cpu(kHousekeepingCpu,"motivation-host") || !configure_default_group())
      throw std::runtime_error("group/CPU setup");
    std::cout<<"[motivation] epm_reservation=matched-worker-image-v2 group_capacity="<<workers+1
             <<" member_free_mem_bytes=4194304 active_workers="<<workers
             <<" marker="<<motivation_epm_reservation_marker<<" cohort="<<cohort_marker<<std::endl;
    add_motivation_instances(enclaves,workers);
    if(!init_all(enclaves,runtime,loader) || !finalize_all(enclaves)) throw std::runtime_error("enclave initialization");
    for(unsigned w=0;w<workers;++w) {
      auto* utm=static_cast<uint8_t*>(enclaves[w+1].enclave->getOcallBuffer());
      if(!utm || enclaves[w+1].enclave->getOcallBufferSize()<MOT_UTM_BYTES) throw std::runtime_error("motivation UTM size");
      std::memset(utm+MOT_ARCH_BOOT_OFFSET,0,sizeof(mot_arch_boot));
      mot_config part=cfg;
      if(mot_partition(&part,w,workers)) throw std::runtime_error("block partition");
      run.services.emplace_back(new Motivation::Backend(static_cast<uint8_t*>(enclaves[w+1].enclave->getOcallBuffer()),
          enclaves[w+1].enclave->getOcallBufferSize(),path.c_str(),part,cache,diag,!prep,run.counters,
          std::unique_ptr<Motivation::ReadEngine>(prep?nullptr:new Motivation::UringReadEngine())));
      std::cout<<"[motivation-worker] worker="<<w+1<<" first_block="<<part.first_block
               <<" limit_block="<<part.limit_block<<" assigned_bytes="<<mot_range_bytes(&part)<<std::endl;
    }
    motivation_run=&run;
    if(register_call(MOT_OCALL,motivation_ocall) || !device.initDevice(params)) throw std::runtime_error("OCALL/device setup");
    for(unsigned w=0;w<workers;++w)
      if(!bind_and_enqueue(enclaves[w+1],sm_hart_id_for_cpu(w+1))) throw std::runtime_error("worker enqueue");
    if(device.groupLeaseWorkers(kDefaultGroupId,flags,&lease)!=Error::Success) throw std::runtime_error("worker lease");
    leased=true;
    std::cout<<"[motivation] version=4 mode="<<mode<<" bytes="<<cfg.input_bytes<<" object="<<cfg.object
      <<" workers="<<workers<<" inactive_owner=1 host_cpu=0 io_threads="<<(prep?0:workers)
      <<" worker_cpus=1.."<<workers<<" crypto="<<mot_cipher_name(cfg.cipher)<<" key_bits=128 authenticated="<<(cfg.cipher==MOT_CIPHER_GCM)
      <<" block_bytes=65536 slots_per_worker=2 backend=shared-io-uring-fixed marker="<<transport_marker
      <<" ocall_contract="<<blocking_marker<<" read_ocall="<<(mode=="sync"?"blocking-until-read-complete":"admission-only")<<" cache="<<cache
      <<" timebase_hz="<<cfg.timebase_hz<<" diagnostic="<<diag
      <<" timing=shared-Host-start-release-to-final-validated-DONE"
      <<" compiler="<<__VERSION__<<" built="<<__DATE__<<" "<<__TIME__
      <<" worker_march="<<GROUP_PMP_AES_MARCH_STRING<<" worker_mabi="<<GROUP_PMP_AES_MABI_STRING<<std::endl;
    uint64_t mask=KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_OCALL) |
        KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_EXIT) | KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_FAULT) |
        KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WATCHDOG);
    std::vector<bool> exited(workers,false); unsigned exits=0;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3600);
    auto last_event=std::chrono::steady_clock::now();
    const auto idle_limit=std::chrono::seconds(env_u64("MOT_EVENT_TIMEOUT_SEC",600,10,3600));
    while(!stop_requested && std::chrono::steady_clock::now()<deadline && exits<workers) {
      if(!resume_completed_group_ocalls(device,kDefaultGroupId,"motivation-completions")) throw std::runtime_error("completion resume");
      keystone_group_wait_event event={};
      Error e=device.groupWaitEvent(kDefaultGroupId,mask,1000,&event);
      if(e==Error::GroupEventTimeout) {
        if(std::chrono::steady_clock::now()-last_event>idle_limit) throw std::runtime_error("worker event timeout");
        continue;
      }
      last_event=std::chrono::steady_clock::now();
      if(e!=Error::Success || event.queue_overflows) throw std::runtime_error("worker event failure");
      unsigned w=0;
      while(w<workers && static_cast<uintptr_t>(enclaves[w+1].enclave->getEid())!=event.eid) ++w;
      if(w==workers || exited[w] || event.hart_id!=sm_hart_id_for_cpu(w+1)) throw std::runtime_error("unexpected worker identity");
      run.current=w;
      if(event.event==KEYSTONE_GROUP_EVENT_EXIT) {
        terminal_value=event.value;
        if(event.value || !run.services[w]->finished) throw std::runtime_error("worker exited without valid result");
        exited[w]=true; ++exits; continue;
      }
      edge_call header; std::memcpy(&header,enclaves[w+1].enclave->getOcallBuffer(),sizeof(header));
      if(event.event!=KEYSTONE_GROUP_EVENT_OCALL || header.call_id!=MOT_OCALL || !event.value ||
         !dispatch_and_resume_group_ocall(device,kDefaultGroupId,event.hart_id,event.eid,event.value,&enclaves,"motivation",true))
        throw std::runtime_error("worker fault or OCALL dispatch");
    }
    ok=exits==workers && !run.handler_failed && (prep || (run.begin && run.end>run.begin));
  } catch(const std::exception& e) { std::cerr<<"[motivation] error="<<e.what()<<std::endl; }
  // Join callbacks/I/O before releasing the lease, device or UTM mappings.
  for(auto& service:run.services) service->shutdown();
  clear_deferred_group_ocalls(kDefaultGroupId);
  if(leased && device.groupReleaseWorkers(kDefaultGroupId,flags,&lease)!=Error::Success) ok=false;
  if(prep && run.services.size()==1) run.aggregate=run.services[0]->result;
  uint64_t operations=0,submit_calls=0,cqes=0;
  for(unsigned w=0;w<run.services.size();++w) {
    const auto& service=*run.services[w]; operations+=service.data_operations;
    submit_calls+=service.submit_calls(); cqes+=service.completed_reads();
    std::cout<<"[motivation-worker-result] worker="<<w+1<<" finished="<<service.finished
             <<" processed="<<service.result.processed<<" blocks="<<service.result.blocks
             <<" digest="<<service.result.digest<<std::endl;
  }
  if(diag && !prep) {
    std::ofstream out(motivation_env("MOT_TRACE"));
    out<<"worker,block,slot,generation,admit_ticks,io_begin_ticks,io_end_ticks,publish_ticks,submit_return_ticks,compute_begin_ticks,compute_end_ticks,release_ticks,capture_end_ticks,decrypt_end_ticks\n";
    for(unsigned w=0;w<run.services.size();++w) for(const auto& t:run.services[w]->trace)
      out<<w+1<<','<<t.block<<','<<t.slot<<','<<t.generation<<','<<t.admit<<','<<t.begin<<','<<t.end<<','<<t.publish<<','<<t.returned<<','<<t.compute_begin<<','<<t.compute_end<<','<<t.release<<','<<t.capture_end<<','<<t.decrypt_end<<'\n';
    if(!out) ok=false;
  }
  const uint64_t elapsed=run.end>run.begin?run.end-run.begin:0;
  if(!prep) {
    const std::string csv=motivation_env("MOT_CSV"); bool exists=std::ifstream(csv).good();
    std::ofstream out(csv,std::ios::app);
    if(!exists) out<<"run_id,experiment_block,order,mode,input_bytes,ciphertext_bytes,block_bytes,block_count,worker_enclaves,slots,crypto_algorithm,compute_task,cache_policy,elapsed_ns,processed_bytes,result_ok,error_code,timebase_hz,result_digest,host_data_operations,wait_calls,max_outstanding,max_active_reads,submit_return_before_io_done,out_of_order_consumed,diagnostic,csv_schema,total_data_slots,host_io_threads,timing_scope,cohort_start_ticks,cohort_end_ticks,io_backend,submit_syscalls,completion_cqes,read_ocall_semantics,execution_environment\n";
    const auto& r=run.aggregate;
    out<<motivation_env("MOT_RUN_ID")<<','<<motivation_env("MOT_EXPERIMENT_BLOCK")<<','<<motivation_env("MOT_ORDER")<<','<<mode<<','<<cfg.input_bytes<<','
       <<mot_file_bytes(&cfg)<<','<<mot_block_bytes(&cfg)<<','<<mot_count(&cfg)<<','<<workers<<",2,"<<mot_cipher_name(cfg.cipher)<<",fnv1a64-block-check,"<<cache<<',';
    if(elapsed) out<<std::fixed<<std::setprecision(0)<<(static_cast<long double>(elapsed)*1000000000.0L/cfg.timebase_hz);
    out<<','<<r.processed<<','<<ok<<','<<(ok?0:terminal_value)<<','<<cfg.timebase_hz<<','<<r.digest<<','<<operations<<','
       <<r.waits<<','<<run.counters->peak_outstanding.load()<<','<<run.counters->peak_active.load()<<','
       <<r.early_returns<<','<<r.out_of_order<<','<<diag<<",4,"<<2*workers<<','<<workers
       <<",shared-start-to-final-validated-DONE,"<<run.begin<<','<<run.end
       <<",shared-io-uring-fixed,"<<submit_calls<<','<<cqes<<','
       <<(mode=="sync"?"blocking-until-read-complete":"admission-only")<<",riscv-enclave\n";
    if(!out) ok=false;
  }
  std::cout<<"[motivation] result="<<(ok?"PASS":"FAIL")<<" mode="<<mode<<" workers="<<workers
           <<" processed="<<run.aggregate.processed<<" digest="<<run.aggregate.digest<<" host_data_operations="<<operations
           <<" max_outstanding="<<run.counters->peak_outstanding.load()<<" elapsed_ticks="<<elapsed
           <<" submit_syscalls="<<submit_calls<<" completion_cqes="<<cqes
           <<" worker_return="<<terminal_value<<std::endl;
  motivation_run=nullptr; run.services.clear(); destroy_instances(enclaves);
  return ok;
}
#include "motivation-architecture.hpp"
