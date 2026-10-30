/* Minimal real task-handoff experiment. Included inside the runner namespace. */
#include "../motivation/architecture.h"
struct MotivationArchitectureRun {
  std::vector<std::unique_ptr<Motivation::Backend>> services;
  std::vector<std::shared_ptr<SqliteAsyncCompletion>> starts;
  std::shared_ptr<Motivation::Counters> counters=std::make_shared<Motivation::Counters>();
  size_t actor=0;
  uint8_t* master_utm=nullptr;
  bool failed=false,master_started=false,dispatched=false,master_done=false;
  uint64_t ready_events=0,wait_aggregated=0;
  bool wait_requested=false;
  mot_arch_result master={};
  bool workers_ready() const {
    for(const auto& s:starts) if(!s) return false;
    return !starts.empty();
  }
};
static MotivationArchitectureRun* motivation_architecture_run=nullptr;
static void motivation_architecture_ocall(void* buffer) {
  auto* edge=static_cast<edge_call*>(buffer);
  auto* run=motivation_architecture_run;
  uintptr_t args=0;size_t size=0;mot_call c={};mot_reply r={};r.status=-1;
  if(!run || run->actor>run->services.size() || edge_call_args_ptr(edge,&args,&size) || size!=sizeof(c)) {
    if(run) run->failed=true;
    edge->return_data.call_status=CALL_STATUS_BAD_OFFSET;return;
  }
  std::memcpy(&c,reinterpret_cast<void*>(args),sizeof(c));
  int error=-1;
  if(run->actor==0) {
    if(c.op==MOT_ARCH_START && !run->master_started && run->workers_ready()) {
      if(run->services[0]->prepare_group_cache()) {
        bool ok=true;for(auto& b:run->services) ok=ok && b->enable_group_start();
        if(ok) {
          run->master_started=true;error=0;
          for(auto& s:run->starts) s->completeOne();
        }
      }
    } else if(c.op==MOT_ARCH_DISPATCHED && run->master_started && !run->dispatched && c.blocks==run->services.size()) {
      run->dispatched=true;error=0;
    } else if(c.op==MOT_ARCH_WAIT && run->dispatched && !run->master_done && c.blocks<run->services.size()) {
      run->wait_aggregated=c.blocks;
      run->wait_requested=run->ready_events<=c.blocks;
      error=0;
    } else if(c.op==MOT_ARCH_DONE && run->dispatched && !run->master_done && run->master_utm) {
      std::memcpy(&run->master,run->master_utm+MOT_ARCH_RESULT_OFFSET,sizeof(run->master));
      const auto& m=run->master;
      if(m.magic==MOT_ARCH_MAGIC && m.version==MOT_ARCH_VERSION && m.valid==1 && m.workers==run->services.size() &&
          m.dispatches==m.workers && m.aggregates==m.workers && m.releases==m.workers &&
          m.processed==c.processed && m.blocks==c.blocks && m.digest==c.digest &&
          m.begin_ticks && m.end_ticks>m.begin_ticks) {run->master_done=true;error=0;}
    }
    r.status=error;
  } else {
    size_t w=run->actor-1;auto& b=*run->services[w];
    if(c.op==MOT_WAIT_ANY && b.config.mode!=MOT_SYNC) {
      auto completion=std::make_shared<SqliteAsyncCompletion>();
      error=b.wait_async([completion]{completion->completeOne();},r);
      if(!error) sqlite_dispatched_completion=completion;
    } else {
      error=b.handle(c,r);
      if(!error && c.op==MOT_START) {
        if(run->starts[w]) error=-1;
        else {
          auto completion=std::make_shared<SqliteAsyncCompletion>();
          run->starts[w]=completion;sqlite_dispatched_completion=completion;
        }
      }
    }
  }
  if(error) {
    run->failed=true;r.status=-1;
    std::cerr<<"[motivation-architecture] rejected actor="<<run->actor<<" op="<<c.op<<std::endl;
  }
  uintptr_t out=edge_call_data_ptr();std::memcpy(reinterpret_cast<void*>(out),&r,sizeof(r));
  edge->return_data.call_status=edge_call_setup_ret(edge,reinterpret_cast<void*>(out),sizeof(r))?CALL_STATUS_BAD_PTR:CALL_STATUS_OK;
}
static bool run_motivation_architecture(const char* runtime,const char* loader) {
  static const volatile char marker[] __attribute__((used))=MOT_ARCH_MARKER;
  const std::string mode=motivation_env("MOT_MODE"),path=motivation_env("MOT_FILE"),cache=motivation_env("MOT_CACHE","cold");
  bool diagnostic=motivation_env("MOT_DIAGNOSTIC")=="1";
  unsigned workers=static_cast<unsigned>(env_u64("MOT_WORKERS",1,1,3));
  mot_config cfg={MOT_MAGIC,env_u64("MOT_BYTES",500000000,1,500000000),
      env_u64("MOT_OBJECT",0,0,UINT64_MAX),mode=="sync"?MOT_SYNC:MOT_ASYNC,riscv_timebase_hz(),0,0,motivation_cipher(),env_u64("MOT_BLOCK_BYTES",65536,1,65536),diagnostic?UINT64_C(1):UINT64_C(0)};
  cfg.limit_block=mot_count(&cfg);
  mot_arch_boot boot={MOT_ARCH_MAGIC,MOT_ARCH_VERSION,GROUP_ROLE_MASTER,workers,0,cfg};
  if(marker[0]!='k' || !mot_arch_valid_boot(&boot) || path.empty() ||
      (mode!="sync" && mode!="async") || (cache!="cold" && cache!="hot")) return false;
  MotivationArchitectureRun run;run.starts.resize(workers);
  std::vector<EnclaveInstance> enclaves;
  Keystone::KeystoneDevice device;Params params;keystone_group_lease lease={};
  const uint64_t flags=KEYSTONE_GROUP_LEASE_FLAG_REQUIRE_ISOLATION|KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE|KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
  bool leased=false,ok=false;uint64_t terminal=UINT64_MAX;
  try {
    if(!pin_current_thread_to_cpu(kHousekeepingCpu,"motivation-architecture-host") || !configure_default_group())
      throw std::runtime_error("architecture group/CPU setup");
    add_motivation_instances(enclaves,workers,true);
    if(!init_all(enclaves,runtime,loader) || !finalize_all(enclaves)) throw std::runtime_error("architecture enclave initialization");
    for(unsigned actor=0;actor<=workers;++actor) {
      mot_arch_boot part=boot;
      if(actor) {part.role=GROUP_ROLE_WORKER;part.worker=actor-1;if(mot_partition(&part.config,actor-1,workers)) throw std::runtime_error("architecture partition");}
      auto* utm=static_cast<uint8_t*>(enclaves[actor].enclave->getOcallBuffer());
      if(!utm || enclaves[actor].enclave->getOcallBufferSize()<MOT_UTM_BYTES) throw std::runtime_error("architecture UTM size");
      std::memcpy(utm+MOT_ARCH_BOOT_OFFSET,&part,sizeof(part));
      if(!actor) {
        run.master_utm=utm;std::memset(utm+MOT_ARCH_RESULT_OFFSET,0,sizeof(mot_arch_result));
      } else run.services.emplace_back(new Motivation::Backend(utm,enclaves[actor].enclave->getOcallBufferSize(),
          path.c_str(),part.config,cache,diagnostic,true,run.counters,
          std::unique_ptr<Motivation::ReadEngine>(new Motivation::UringReadEngine())));
    }
    motivation_architecture_run=&run;
    if(register_call(MOT_OCALL,motivation_architecture_ocall) || !device.initDevice(params)) throw std::runtime_error("architecture edge setup");
    for(unsigned actor=0;actor<=workers;++actor)
      if(!bind_and_enqueue(enclaves[actor],sm_hart_id_for_cpu(actor))) throw std::runtime_error("architecture enqueue");
    if(device.groupLeaseWorkers(kDefaultGroupId,flags,&lease)!=Error::Success) throw std::runtime_error("architecture worker lease");
    leased=true;
    std::cout<<"[motivation-architecture] version="<<MOT_ARCH_VERSION<<" marker="<<MOT_ARCH_MARKER<<" mode="<<mode<<" workers="<<workers
             <<" active_master=1 task_transport=protected-TSR-slot storage=shared-io-uring-fixed"
             <<" crypto="<<mot_cipher_name(cfg.cipher)<<" authenticated="<<(cfg.cipher==MOT_CIPHER_GCM)
             <<" block_bytes="<<mot_block_bytes(&cfg)<<" input_bytes="<<cfg.input_bytes<<" timebase_hz="<<cfg.timebase_hz
             <<" sqlite_business=0 diagnostic="<<diagnostic<<std::endl;
    const uint64_t mask=KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_OCALL)|KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_EXIT)|
        KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_FAULT)|KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WATCHDOG)|
        KEYSTONE_GROUP_EVENT_MASK(KEYSTONE_GROUP_EVENT_WORKERS_READY);
    std::vector<bool> exited(workers,false);unsigned exits=0;bool master_exited=false,master_waiting=false;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3600);
    auto last=std::chrono::steady_clock::now();
    auto idle=std::chrono::seconds(env_u64("MOT_EVENT_TIMEOUT_SEC",600,10,3600));
    const uint64_t master_eid=static_cast<uint64_t>(enclaves[0].enclave->getEid());
    while(!stop_requested && std::chrono::steady_clock::now()<deadline && (!master_exited || exits<workers)) {
      if(!resume_completed_group_ocalls(device,kDefaultGroupId,"motivation-architecture-completions")) throw std::runtime_error("architecture resume");
      if(!master_exited && !master_waiting && run.workers_ready()) {
        uintptr_t value=0;uint64_t eid=0,event=KEYSTONE_GROUP_EVENT_NONE,overflows=0;
        Error error=device.groupRunMaster(kDefaultGroupId,&eid,&event,&value,nullptr,nullptr,&overflows);
        if(overflows || error==Error::EnclaveFatalFault || event==KEYSTONE_GROUP_EVENT_FAULT || event==KEYSTONE_GROUP_EVENT_WATCHDOG)
          throw std::runtime_error("architecture Master fault");
        if(event==KEYSTONE_GROUP_EVENT_OCALL) {
          run.actor=0;
          run.wait_requested=false;
          if(eid!=master_eid || !value || !dispatch_and_resume_group_ocall(device,kDefaultGroupId,kHousekeepingHart,eid,value,&enclaves,"motivation-task-master",true))
            throw std::runtime_error("architecture Master OCALL");
          master_waiting=run.wait_requested;
          last=std::chrono::steady_clock::now();continue;
        }
        if(event==KEYSTONE_GROUP_EVENT_EXIT) {
          if(eid!=master_eid || value || !run.master_done) throw std::runtime_error("architecture Master exit");
          master_exited=true;last=std::chrono::steady_clock::now();
        } else if(error==Error::EnclaveInterrupted || error==Error::GroupNotRunnable ||
                  error==Error::Success || event==KEYSTONE_GROUP_EVENT_INTERRUPTED) {
          // Only an explicit Master WAIT creates a dependency. A timer event
          // cannot park the Master after the last Worker has already finished.
          master_waiting=false;
        } else throw std::runtime_error("architecture Master run");
      }
      if(master_exited && exits==workers) break;
      keystone_group_wait_event event={};
      const unsigned wait_ms=master_exited || master_waiting || !run.workers_ready()?1000:0;
      Error e=device.groupWaitEvent(kDefaultGroupId,mask,wait_ms,&event);
      if(e==Error::GroupEventTimeout) {
        if(std::chrono::steady_clock::now()-last>idle) throw std::runtime_error("architecture event timeout");
        continue;
      }
      if(e!=Error::Success || event.queue_overflows) throw std::runtime_error("architecture event/overflow");
      last=std::chrono::steady_clock::now();
      if(event.event==KEYSTONE_GROUP_EVENT_WORKERS_READY) {
        if(event.eid!=master_eid || (event.value>>56)!=YXSTM_PHASE_COMPUTE || !(event.value&UINT64_C(0x0000ffffffffffff)))
          throw std::runtime_error("architecture slot-ready identity");
        ++run.ready_events;
        if(run.ready_events>workers) throw std::runtime_error("architecture duplicate slot-ready event");
        if(run.ready_events>run.wait_aggregated) master_waiting=false;
        if(master_exited) {
          // Commit a late HSM ready ACK, as the production Master pump does,
          // so a completing Worker can expose its following DONE/EXIT event.
          uintptr_t value=0;uint64_t eid=0,kind=0,overflows=0;
          Error commit=device.groupRunMaster(kDefaultGroupId,&eid,&kind,&value,nullptr,nullptr,&overflows);
          if(overflows || kind==KEYSTONE_GROUP_EVENT_FAULT || kind==KEYSTONE_GROUP_EVENT_WATCHDOG ||
              (commit!=Error::Success && commit!=Error::EnclaveInterrupted && commit!=Error::GroupNotRunnable))
            throw std::runtime_error("architecture terminal ready ACK");
        }
        continue;
      }
      unsigned w=0;while(w<workers && static_cast<uint64_t>(enclaves[w+1].enclave->getEid())!=event.eid) ++w;
      if(w==workers || exited[w] || event.hart_id!=sm_hart_id_for_cpu(w+1)) throw std::runtime_error("architecture Worker identity");
      run.actor=w+1;
      if(event.event==KEYSTONE_GROUP_EVENT_EXIT) {
        terminal=event.value;
        if(event.value || !run.services[w]->finished) throw std::runtime_error("architecture Worker exit");
        exited[w]=true;++exits;continue;
      }
      edge_call header;std::memcpy(&header,enclaves[w+1].enclave->getOcallBuffer(),sizeof(header));
      if(event.event!=KEYSTONE_GROUP_EVENT_OCALL || header.call_id!=MOT_OCALL || !event.value ||
          !dispatch_and_resume_group_ocall(device,kDefaultGroupId,event.hart_id,event.eid,event.value,&enclaves,"motivation-task-worker",true))
        throw std::runtime_error("architecture Worker fault/OCALL");
    }
    mot_call aggregate={};uint64_t operations=0,cqes=0;
    for(const auto& b:run.services) {
      if(!b->finished || b->completed_reads()!=b->result.blocks || b->data_operations!=b->result.blocks || !b->submit_calls())
        throw std::runtime_error("architecture read/result accounting");
      aggregate.processed+=b->result.processed;aggregate.blocks+=b->result.blocks;aggregate.digest^=b->result.digest;
      operations+=b->data_operations;cqes+=b->completed_reads();
    }
    ok=master_exited && exits==workers && !run.failed && run.master_done && !run.counters->outstanding.load() &&
       aggregate.processed==cfg.input_bytes && aggregate.blocks==mot_count(&cfg) &&
       aggregate.processed==run.master.processed && aggregate.blocks==run.master.blocks && aggregate.digest==run.master.digest;
    if(!ok || operations!=aggregate.blocks || cqes!=operations) throw std::runtime_error("architecture protected aggregate mismatch");
  } catch(const std::exception& e) {std::cerr<<"[motivation-architecture] error="<<e.what()<<std::endl;ok=false;}
  for(auto& b:run.services) b->shutdown();
  clear_deferred_group_ocalls(kDefaultGroupId);
  if(leased && device.groupReleaseWorkers(kDefaultGroupId,flags,&lease)!=Error::Success) ok=false;
  mot_call total={};uint64_t ops=0,submits=0,cqes=0,reads=0,releases=0,recycles=0;
  for(const auto& b:run.services) {
    total.processed+=b->result.processed;total.blocks+=b->result.blocks;total.digest^=b->result.digest;
    total.waits+=b->result.waits;total.early_returns+=b->result.early_returns;total.out_of_order+=b->result.out_of_order;
    ops+=b->data_operations;submits+=b->submit_calls();cqes+=b->completed_reads();
    reads+=b->read_ocalls;releases+=b->release_only_ocalls;recycles+=b->release_submit_ocalls;
  }
  const auto& m=run.master;
  if(diagnostic && ok) {
    const std::string trace_path=motivation_env("MOT_TRACE"),suffix="-trace.csv";
    if(trace_path.size()<=suffix.size() || trace_path.compare(trace_path.size()-suffix.size(),suffix.size(),suffix)) ok=false;
    else {
      std::ofstream trace(trace_path);
      trace<<"worker,block,slot,generation,admit_ticks,io_begin_ticks,io_end_ticks,publish_ticks,submit_return_ticks,compute_begin_ticks,compute_end_ticks,release_ticks,capture_end_ticks,decrypt_end_ticks\n";
      for(unsigned w=0;w<workers;++w) for(const auto& t:run.services[w]->trace)
        trace<<w+1<<','<<t.block<<','<<t.slot<<','<<t.generation<<','<<t.admit<<','<<t.begin<<','<<t.end<<','<<t.publish<<','<<t.returned<<','<<t.compute_begin<<','<<t.compute_end<<','<<t.release<<','<<t.capture_end<<','<<t.decrypt_end<<'\n';
      std::ofstream evidence(trace_path.substr(0,trace_path.size()-suffix.size())+"-tasks.csv");
      evidence<<"worker,lane,epoch,sequence,dispatch_begin,dispatch_end,acquire_ticks,done_ticks,aggregate_begin,aggregate_end\n";
      for(unsigned w=0;w<workers;++w) {const auto& t=m.tasks[w];evidence<<t.worker+1<<','<<t.lane<<','<<t.epoch<<','<<t.sequence<<','<<t.dispatch_begin<<','<<t.dispatch_end<<','<<t.acquire_ticks<<','<<t.done_ticks<<','<<t.aggregate_begin<<','<<t.aggregate_end<<'\n';}
      trace.flush();evidence.flush();
      if(!trace || !evidence) ok=false;
    }
  }
  std::string csv=motivation_env("MOT_CSV");bool exists=std::ifstream(csv).good();std::ofstream out(csv,std::ios::app);
  if(!exists) out<<"run_id,experiment_block,order,mode,input_bytes,ciphertext_bytes,block_bytes,block_count,worker_enclaves,slots,crypto_algorithm,compute_task,cache_policy,elapsed_ns,processed_bytes,result_ok,error_code,timebase_hz,result_digest,host_data_operations,wait_calls,max_outstanding,max_active_reads,submit_return_before_io_done,out_of_order_consumed,diagnostic,csv_schema,total_data_slots,host_io_threads,timing_scope,cohort_start_ticks,cohort_end_ticks,io_backend,submit_syscalls,completion_cqes,read_ocall_semantics,execution_environment,active_master,tsr_dispatches,tsr_aggregates,tsr_releases,master_aggregate_digest,read_ocalls,release_only_ocalls,release_submit_ocalls,data_path_ocalls\n";
  out<<motivation_env("MOT_RUN_ID")<<','<<motivation_env("MOT_EXPERIMENT_BLOCK")<<','<<motivation_env("MOT_ORDER")<<','<<mode<<','<<cfg.input_bytes<<','
     <<mot_file_bytes(&cfg)<<','<<mot_block_bytes(&cfg)<<','<<mot_count(&cfg)<<','<<workers<<",2,"<<mot_cipher_name(cfg.cipher)<<",fnv1a64-block-check,"<<cache<<',';
  if(m.end_ticks>m.begin_ticks) out<<std::fixed<<std::setprecision(0)<<static_cast<long double>(m.end_ticks-m.begin_ticks)*1000000000.0L/cfg.timebase_hz;
  out<<','<<total.processed<<','<<ok<<','<<(ok?0:terminal)<<','<<cfg.timebase_hz<<','<<total.digest<<','<<ops<<','<<total.waits
     <<','<<run.counters->peak_outstanding.load()<<','<<run.counters->peak_active.load()<<','<<total.early_returns<<','<<total.out_of_order
     <<','<<diagnostic<<",8,"<<2*workers<<','<<workers<<",master-first-dispatch-to-final-protected-aggregate,"<<m.begin_ticks<<','<<m.end_ticks
     <<",shared-io-uring-fixed,"<<submits<<','<<cqes<<','<<(mode=="sync"?"blocking-until-read-complete":"admission-only")
     <<",riscv-enclave,1,"<<m.dispatches<<','<<m.aggregates<<','<<m.releases<<','<<m.digest
     <<','<<reads<<','<<releases<<','<<recycles<<','<<reads+releases<<'\n';
  if(!out) ok=false;
  std::cout<<"[motivation-architecture] protected_tasks="<<m.dispatches<<" aggregates="<<m.aggregates<<" released="<<m.releases
           <<" master_digest="<<m.digest<<" worker_digest="<<total.digest<<std::endl;
  std::cout<<"[motivation] result="<<(ok?"PASS":"FAIL")<<" mode="<<mode<<" workers="<<workers<<" active_master=1 processed="<<total.processed
           <<" digest="<<total.digest<<" host_data_operations="<<ops<<" max_outstanding="<<run.counters->peak_outstanding.load()
           <<" elapsed_ticks="<<(m.end_ticks>m.begin_ticks?m.end_ticks-m.begin_ticks:0)<<" submit_syscalls="<<submits<<" completion_cqes="<<cqes
           <<" release_submit_ocalls="<<recycles<<" release_only_ocalls="<<releases<<" data_path_ocalls="<<reads+releases<<std::endl;
  motivation_architecture_run=nullptr;run.services.clear();destroy_instances(enclaves);return ok;
}
