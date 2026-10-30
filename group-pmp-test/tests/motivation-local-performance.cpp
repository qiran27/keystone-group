// Native Linux measurement of the real task/backend. No enclave or OCALL-cost
// simulation: results must never be presented as board/enclave measurements.
#include "../motivation/core.h"
#include "../motivation/backend.hpp"
#include "../motivation/uring-io.hpp"
#include "motivation-tsr-model.hpp"
#include <cassert>
#include <iomanip>
#include <iostream>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>

static Motivation::Backend* service;
static std::vector<uint64_t> memory((MOT_UTM_BYTES+7)/8);
static int channel=-1;
static bool architecture=false;
static mot_arch_worker task_worker={};
static uint8_t* base() { return reinterpret_cast<uint8_t*>(memory.data()); }
static void require(bool value,const char* what) { if(!value) throw std::runtime_error(what); }
static void wire(int fd,void* data,size_t n,bool send) {
  size_t done=0;
  while(done<n) {
    ssize_t v=send?write(fd,static_cast<char*>(data)+done,n-done):read(fd,static_cast<char*>(data)+done,n-done);
    if(v<0 && errno==EINTR) continue;
    require(v>0,"cohort pipe closed or failed"); done+=v;
  }
}
static int exchange(const mot_call* c,mot_reply* r) {
  int rc=service->handle(*c,*r);
  if(!rc && c->op==MOT_START && channel>=0) {
    uint64_t ready=1;wire(channel,&ready,sizeof(ready),true);wire(channel,&ready,sizeof(ready),false);
    if(ready!=1 || !service->enable_group_start()) return -1;
  }
  return rc;
}
static int capture(void* dst,size_t off,size_t n) {
  if(off>MOT_UTM_BYTES || n>MOT_UTM_BYTES-off) return -1;
  if(off>=MOT_META_OFFSET && off<MOT_DATA_OFFSET &&
      !__atomic_load_n(&reinterpret_cast<mot_completion*>(base()+off)->ready,__ATOMIC_ACQUIRE)) {
    std::memset(dst,0,n);return 0;
  }
  std::memcpy(dst,base()+off,n);return 0;
}
static int publish(size_t off,const void* src,size_t n) {
  if(off>MOT_UTM_BYTES || n>MOT_UTM_BYTES-off) return -1;
  std::memcpy(base()+off,src,n);return 0;
}
static const mot_api api={exchange,capture,publish,Motivation::ticks};
static int master_exchange(const mot_call* c,mot_reply* r) {
  r->status=-1;
  if(c->op==MOT_ARCH_START) {
    uint64_t ready=1;wire(channel,&ready,sizeof(ready),true);wire(channel,&ready,sizeof(ready),false);
    if(ready!=1) return -1;
  } else if(c->op!=MOT_ARCH_DISPATCHED) return -1;
  r->status=0;return 0;
}
static const mot_arch_api task_api={NativeTsr::query,NativeTsr::command,NativeTsr::load,NativeTsr::store,
    NativeTsr::yield,master_exchange,Motivation::ticks};
static int task_acquire(mot_config* cfg) {return mot_arch_worker_acquire(&task_worker,cfg);}
static int task_complete(const mot_config* cfg,const mot_call* result) {return mot_arch_worker_complete(&task_worker,cfg,result);}
static const mot_task_api task_hooks={task_acquire,task_complete};
static void pin(int cpu) {
  cpu_set_t set;CPU_ZERO(&set);CPU_SET(cpu,&set);
  require(!sched_setaffinity(0,sizeof(set),&set),"CPU affinity");
}
struct Result { int rc=1;bool finished=false;mot_call value={};uint64_t ops=0,submits=0,cqes=0,reads=0,releases=0,recycles=0; };
struct ChildGuard {
  pid_t ids[4]={0,0,0,0};
  ~ChildGuard() {
    for(pid_t pid:ids) if(pid>0) kill(pid,SIGKILL);
    for(pid_t pid:ids) if(pid>0) {int status;while(waitpid(pid,&status,0)<0 && errno==EINTR) {}}
  }
};
static void cache_prepare(const std::string& path,uint64_t bytes,const std::string& policy) {
  int fd=open(path.c_str(),O_RDWR|O_CLOEXEC);require(fd>=0,"cache open");
  if(policy=="hot") {
    std::vector<uint8_t> buf(MOT_BLOCK);
    for(uint64_t off=0;off<bytes;off+=buf.size())
      require(Motivation::transfer(fd,buf.data(),std::min<uint64_t>(buf.size(),bytes-off),off,false),"cache warm");
  } else {
    require(!fdatasync(fd) && !posix_fadvise(fd,0,0,POSIX_FADV_DONTNEED),"cache eviction");
    void* map=mmap(nullptr,bytes,PROT_READ,MAP_SHARED,fd,0);require(map!=MAP_FAILED,"cache map");
    long page=sysconf(_SC_PAGESIZE);require(page>0,"page size");
    std::vector<unsigned char> resident((bytes+page-1)/page);
    bool ok=!mincore(map,bytes,resident.data());uint64_t count=0;
    for(auto value:resident) count+=(value&1)!=0;
    require(!munmap(map,bytes) && ok && !count,"cold cache not established");
  }
  close(fd);
}
static void save_trace(const std::string& path,const std::vector<Motivation::Trace>& trace,unsigned worker) {
  std::ofstream out(path);
  for(const auto& t:trace)
    out<<worker+1<<','<<t.block<<','<<t.slot<<','<<t.generation<<','<<t.admit<<','<<t.begin<<','
       <<t.end<<','<<t.publish<<','<<t.returned<<','<<t.compute_begin<<','<<t.compute_end<<','<<t.release<<','<<t.capture_end<<','<<t.decrypt_end<<'\n';
  require(static_cast<bool>(out),"trace write");
}
static uint64_t cohort(const std::string& dir,const std::string& path,mot_config cfg,
    const std::string& cache,unsigned workers,const std::vector<int>& cpus,
    const std::string& id,const std::string& block,unsigned order,bool diagnostic,uint64_t expected) {
  cfg.diagnostic=diagnostic?1:0;
  void* shared=mmap(nullptr,sizeof(Motivation::Counters),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
  require(shared!=MAP_FAILED,"shared counters");
  auto* counts=new(shared) Motivation::Counters();
  unsigned actors=workers+(architecture?1:0);
  if(architecture) NativeTsr::shared=NativeTsr::create(workers);
  int sockets[4][2];ChildGuard children;
  for(unsigned w=0;w<actors;++w) require(!socketpair(AF_UNIX,SOCK_STREAM,0,sockets[w]),"cohort socket");
  for(unsigned w=0;w<actors;++w) {
    children.ids[w]=fork();require(children.ids[w]>=0,"fork");
    if(!children.ids[w]) {
      for(unsigned k=0;k<actors;++k) {close(sockets[k][0]);if(k!=w) close(sockets[k][1]);}
      channel=sockets[w][1];Result value;
      try {
        pin(cpus[0]); // reactor inherits the same Host CPU in every configuration
        if(architecture && w==workers) {
          NativeTsr::actor=-1;
          mot_arch_boot boot={MOT_ARCH_MAGIC,MOT_ARCH_VERSION,GROUP_ROLE_MASTER,workers,0,cfg};mot_arch_result result={};
          int rc=mot_arch_master(&boot,&task_api,&result);
          wire(channel,&result,sizeof(result),true);close(channel);_exit(rc?rc:0);
        }
        mot_config part=cfg;require(!mot_partition(&part,w,workers),"partition");
        std::shared_ptr<Motivation::Counters> reference(counts,[](Motivation::Counters*){});
        Motivation::Backend backend(base(),MOT_UTM_BYTES,path.c_str(),part,cache,diagnostic,true,reference,
            std::unique_ptr<Motivation::ReadEngine>(new Motivation::UringReadEngine()));
        service=&backend;pin(cpus[w+1]);
        if(architecture) {
          NativeTsr::actor=w;task_worker={};
          task_worker.boot={MOT_ARCH_MAGIC,MOT_ARCH_VERSION,GROUP_ROLE_WORKER,workers,w,part};task_worker.api=&task_api;
        }
        value.rc=architecture?mot_run_task(&api,&task_hooks):mot_run(&api);value.finished=backend.finished;value.value=backend.result;
        value.ops=backend.data_operations;value.submits=backend.submit_calls();value.cqes=backend.completed_reads();
        value.reads=backend.read_ocalls;value.releases=backend.release_only_ocalls;value.recycles=backend.release_submit_ocalls;
        // Publish validated DONE before trace serialization / process teardown.
        wire(channel,&value,sizeof(value),true);
        if(diagnostic) save_trace(dir+"/"+id+"-w"+std::to_string(w)+".tmp",backend.trace,w);
        backend.shutdown();close(channel);_exit(value.rc?1:0);
      } catch(const std::exception& e) {std::cerr<<"native child: "<<e.what()<<std::endl;_exit(1);}
    }
  }
  for(unsigned w=0;w<actors;++w) close(sockets[w][1]);
  for(unsigned w=0;w<actors;++w) {uint64_t ready=0;wire(sockets[w][0],&ready,sizeof(ready),false);require(ready==1,"START");}
  cache_prepare(path,mot_file_bytes(&cfg),cache);
  uint64_t begin=Motivation::ticks();
  for(unsigned w=0;w<actors;++w) {uint64_t go=1;wire(sockets[w][0],&go,sizeof(go),true);}
  mot_call total={};uint64_t ops=0,submits=0,cqes=0,reads=0,releases=0,recycles=0;
  for(unsigned w=0;w<workers;++w) {
    Result r;wire(sockets[w][0],&r,sizeof(r),false);close(sockets[w][0]);
    if(r.rc || !r.finished || r.ops!=r.value.blocks || r.cqes!=r.value.blocks || !r.submits)
      std::cerr<<"native Worker failure id="<<id<<" worker="<<w+1<<" rc="<<r.rc<<" finished="<<r.finished
               <<" blocks="<<r.value.blocks<<" ops="<<r.ops<<" cqes="<<r.cqes<<" submits="<<r.submits<<std::endl;
    require(!r.rc && r.finished && r.ops==r.value.blocks && r.cqes==r.value.blocks && r.submits,"worker correctness/accounting");
    mot_config part=cfg;require(!mot_partition(&part,w,workers),"counter partition");
    require(r.reads==r.value.blocks && r.releases==mot_initial_reads(&part) &&
        r.recycles==r.value.blocks-r.releases,"combined OCALL accounting");
    total.processed+=r.value.processed;total.blocks+=r.value.blocks;total.digest^=r.value.digest;
    total.waits+=r.value.waits;total.early_returns+=r.value.early_returns;total.out_of_order+=r.value.out_of_order;
    ops+=r.ops;submits+=r.submits;cqes+=r.cqes;
    reads+=r.reads;releases+=r.releases;recycles+=r.recycles;
  }
  require(total.processed==cfg.input_bytes && total.blocks==mot_count(&cfg) &&
      total.digest==expected && !counts->outstanding.load(),"cohort correctness");
  bool sync=cfg.mode==MOT_SYNC;
  require(!sync || (!total.waits && !total.early_returns && counts->peak_outstanding==1),"blocking OCALL contract");
  uint64_t end=Motivation::ticks();
  mot_arch_result master={};
  if(architecture) {
    wire(sockets[workers][0],&master,sizeof(master),false);close(sockets[workers][0]);
    require(master.magic==MOT_ARCH_MAGIC && master.version==MOT_ARCH_VERSION && master.valid && master.workers==workers &&
        master.dispatches==workers && master.aggregates==workers && master.releases==workers &&
        master.digest==total.digest && master.digest==expected && master.processed==cfg.input_bytes &&
        master.blocks==mot_count(&cfg) && master.end_ticks>master.begin_ticks,"real C protected aggregate");
    begin=master.begin_ticks;end=master.end_ticks;
    for(unsigned w=0;w<workers;++w) require(NativeTsr::shared->slots[w].info.state==YXSTM_SLOT_FREE &&
        NativeTsr::shared->slots[w].info.epoch==2 && NativeTsr::shared->slots[w].grant==-2,"TSR cleanup");
  }
  for(unsigned w=0;w<actors;++w) {
    int status;pid_t result;
    do {result=waitpid(children.ids[w],&status,0);} while(result<0 && errno==EINTR);
    require(result==children.ids[w],"waitpid");children.ids[w]=0;
    require(WIFEXITED(status) && !WEXITSTATUS(status),"child exit");
  }
  if(diagnostic) {
    std::ofstream out(dir+"/"+id+"-trace.csv");
    out<<"worker,block,slot,generation,admit_ticks,io_begin_ticks,io_end_ticks,publish_ticks,submit_return_ticks,compute_begin_ticks,compute_end_ticks,release_ticks,capture_end_ticks,decrypt_end_ticks\n";
    for(unsigned w=0;w<workers;++w) {
      std::string file=dir+"/"+id+"-w"+std::to_string(w)+".tmp";std::ifstream in(file);
      require(static_cast<bool>(in),"trace missing");out<<in.rdbuf();in.close();require(!unlink(file.c_str()),"trace cleanup");
    }
    require(static_cast<bool>(out),"trace merge");
    if(architecture) {
      std::ofstream tasks(dir+"/"+id+"-tasks.csv");
      tasks<<"worker,lane,epoch,sequence,dispatch_begin,dispatch_end,acquire_ticks,done_ticks,aggregate_begin,aggregate_end\n";
      for(unsigned w=0;w<workers;++w) {const auto& t=master.tasks[w];tasks<<t.worker+1<<','<<t.lane<<','<<t.epoch<<','<<t.sequence<<','<<t.dispatch_begin<<','<<t.dispatch_end<<','<<t.acquire_ticks<<','<<t.done_ticks<<','<<t.aggregate_begin<<','<<t.aggregate_end<<'\n';}
      require(static_cast<bool>(tasks),"task witness write");
    }
  }
  bool exists=std::ifstream(dir+"/samples.csv").good();std::ofstream out(dir+"/samples.csv",std::ios::app);
  if(!exists) {
    out<<"run_id,experiment_block,order,mode,input_bytes,ciphertext_bytes,block_bytes,block_count,worker_enclaves,slots,crypto_algorithm,compute_task,cache_policy,elapsed_ns,processed_bytes,result_ok,error_code,timebase_hz,result_digest,host_data_operations,wait_calls,max_outstanding,max_active_reads,submit_return_before_io_done,out_of_order_consumed,diagnostic,csv_schema,total_data_slots,host_io_threads,timing_scope,cohort_start_ticks,cohort_end_ticks,io_backend,submit_syscalls,completion_cqes,read_ocall_semantics,execution_environment";
    if(architecture) out<<",active_master,tsr_dispatches,tsr_aggregates,tsr_releases,master_aggregate_digest,read_ocalls,release_only_ocalls,release_submit_ocalls,data_path_ocalls";
    out<<'\n';
  }
  out<<id<<','<<block<<','<<order<<','<<(sync?"sync":"async")<<','<<cfg.input_bytes<<','
     <<mot_file_bytes(&cfg)<<','<<mot_block_bytes(&cfg)<<','<<mot_count(&cfg)<<','<<workers
     <<",2,"<<mot_cipher_name(cfg.cipher)<<",fnv1a64-block-check,"<<cache<<','<<end-begin<<','<<total.processed
     <<",1,0,1000000000,"<<total.digest<<','<<ops<<','<<total.waits<<','<<counts->peak_outstanding
     <<','<<counts->peak_active<<','<<total.early_returns<<','<<total.out_of_order<<','<<diagnostic<<','<<(architecture?8:4)<<','
     <<2*workers<<','<<workers<<','<<(architecture?"master-first-dispatch-to-final-protected-aggregate":"shared-start-to-final-validated-DONE")<<','<<begin<<','<<end
     <<",shared-io-uring-fixed,"<<submits<<','<<cqes<<','<<(sync?"blocking-until-read-complete":"admission-only")
     <<",native-linux-no-enclave";
  if(architecture) out<<",1,"<<master.dispatches<<','<<master.aggregates<<','<<master.releases<<','<<master.digest
                     <<','<<reads<<','<<releases<<','<<recycles<<','<<reads+releases;
  out<<'\n';
  require(static_cast<bool>(out),"sample write");
  std::cout<<id<<" elapsed_s="<<std::fixed<<std::setprecision(6)<<(end-begin)/1e9
           <<" MB_s="<<cfg.input_bytes*1000.0/(end-begin)<<" ops="<<ops<<" peak="<<counts->peak_outstanding
           <<" waits="<<total.waits<<" digest="<<total.digest<<" recycle_submit="<<recycles
           <<" release_only="<<releases<<" data_ocalls="<<reads+releases<<std::endl;
  counts->~Counters();require(!munmap(shared,sizeof(Motivation::Counters)),"shared cleanup");
  if(architecture) NativeTsr::destroy(NativeTsr::shared);
  return end-begin;
}
int main(int argc,char** argv) {
  try {
    require(argc==5,"usage: local-performance output-directory bytes repetitions cold|hot");
    const std::string dir=argv[1],path=dir+"/cipher.bin",cache=argv[4];
    architecture=std::getenv("MOT_LOCAL_ARCHITECTURE") && std::string(std::getenv("MOT_LOCAL_ARCHITECTURE"))=="1";
    uint64_t bytes=std::stoull(argv[2]);unsigned repetitions=std::stoul(argv[3]);
    const uint64_t block_bytes=std::getenv("MOT_BLOCK_BYTES")?std::stoull(std::getenv("MOT_BLOCK_BYTES")):65536;
    require(bytes>=MOT_BLOCK*3 && bytes<=500000000 && repetitions>=1 && repetitions<=100 &&
        (cache=="hot" || cache=="cold") && access((dir+"/samples.csv").c_str(),F_OK),"invalid input/existing samples");
    cpu_set_t set;require(!sched_getaffinity(0,sizeof(set),&set),"affinity inventory");std::vector<int> cpus;
    for(int c=0;c<CPU_SETSIZE;++c) if(CPU_ISSET(c,&set)) cpus.push_back(c);
    require(cpus.size()>=4,"four available logical CPUs required");pin(cpus[0]);
    std::ofstream env(dir+"/native-environment.txt");
    env<<"execution_environment=native-linux-no-enclave\nclock=steady_clock-nanoseconds\n"
       <<"host_cpu="<<cpus[0]<<" worker_cpus="<<cpus[1]<<','<<cpus[2]<<','<<cpus[3]
       <<"\ncompiler="<<__VERSION__<<"\nno_sleep_no_io_delay_no_added_compute=1\n"
       <<"active_master="<<architecture<<"\ntsr_permissions="<<(architecture?"native-test-model-not-PMP":"not-used")
       <<"\ninput_bytes="<<bytes<<"\nobject=0x1234abcddcba4321\nblock_bytes="<<block_bytes<<'\n';
    require(static_cast<bool>(env),"environment write");env.close();
    const std::string cipher=std::getenv("MOT_CIPHER")?std::getenv("MOT_CIPHER"):(architecture?"aes-ecb-128":"aes-gcm-128");
    require(cipher=="aes-ecb-128" || cipher=="aes-gcm-128","invalid cipher");
    mot_config cfg={MOT_MAGIC,bytes,UINT64_C(0x1234abcddcba4321),MOT_PREPARE,1000000000,0,0,
        cipher=="aes-ecb-128"?MOT_CIPHER_ECB:MOT_CIPHER_GCM,block_bytes,0};
    require(mot_valid_geometry(&cfg),"invalid block size");cfg.limit_block=mot_count(&cfg);
    std::ofstream geometry_env(dir+"/geometry.txt");geometry_env<<"block_bytes="<<block_bytes<<'\n';geometry_env.close();
    std::ofstream crypto_env(dir+"/cipher.txt");crypto_env<<mot_cipher_name(cfg.cipher)<<'\n';crypto_env.close();
    uint64_t expected;
    { Motivation::Backend prep(base(),MOT_UTM_BYTES,path.c_str(),cfg,cache,false);service=&prep;
      require(!mot_run(&api) && prep.finished,"encrypted fixture preparation");expected=prep.result.digest; }
    for(unsigned r=1;r<=repetitions+1;++r) {
      bool diagnostic=r>repetitions;std::string block=std::to_string(bytes/1000000)+"MB-r"+std::to_string(r);
      for(unsigned order=1;order<=3;++order) {
        unsigned which=(r-1+order-1)%3;unsigned workers=which==2?3:1;
        cfg.mode=which==0?MOT_SYNC:MOT_ASYNC;
        std::string id=block+"-"+(which==0?"sync-1":which==1?"async-1":"async-3");
        cohort(dir,path,cfg,cache,workers,cpus,id,block,order,diagnostic,expected);
      }
    }
    if(!std::getenv("MOT_LOCAL_KEEP_INPUT")) require(!unlink(path.c_str()),"owned ciphertext cleanup");
    return 0;
  } catch(const std::exception& e) {std::cerr<<"local performance FAIL: "<<e.what()<<std::endl;return 1;}
}
