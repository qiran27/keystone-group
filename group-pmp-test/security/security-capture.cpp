#include "security-sentinel.h"
#include "kernel/evidence-uapi.h"
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>
/* Collector performs no marker construction/search operation. Regional control
 * injection is executed by the separate, explicitly positive Host workload. */
static volatile sig_atomic_t stop_capture;
static void interrupted(int) { stop_capture = 1; }
static uint64_t now_ns() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
}
static std::string q(const std::string& s) {
  std::string out = "\""; for (char c : s) { if(c=='"') out+='"'; out+=c; } return out+'"';
}
class StoppedProcess {
  pid_t pid;
  bool resume_needed = false;
  std::ostream& evidence;
  uint64_t snapshot, requested = 0, stopped = 0;
  std::string phase;
public:
  StoppedProcess(pid_t target, std::ostream& log, uint64_t id, const std::string& stage)
      : pid(target), evidence(log), snapshot(id), phase(stage) {
    if(pid <= 0 || pid == getpid()) throw std::runtime_error("invalid-snapshot-target");
    requested = now_ns();
    if(kill(pid, SIGSTOP)) throw std::runtime_error("snapshot-stop-request-failed");
    resume_needed = true;
    try {
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
      for(;;) {
        int status = 0;
        const pid_t result = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if(result == pid) {
          if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
            stopped = now_ns();
            break;
          }
          if(WIFEXITED(status) || WIFSIGNALED(status)) resume_needed = false;
          throw std::runtime_error("snapshot-target-not-stopped");
        }
        if(result < 0 && errno != EINTR) throw std::runtime_error("snapshot-stop-wait-failed");
        if(stop_capture || std::chrono::steady_clock::now() >= deadline)
          throw std::runtime_error("snapshot-stop-timeout-or-interrupted");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    } catch(...) { resume(); throw; }
  }
  StoppedProcess(const StoppedProcess&) = delete;
  StoppedProcess& operator=(const StoppedProcess&) = delete;
  ~StoppedProcess() { resume(); }
  bool resume() {
    if(!resume_needed) return true;
    // Timestamp precedes SIGCONT: every recorded read must be inside this interval.
    const uint64_t end = now_ns();
    const bool ok = kill(pid, SIGCONT) == 0;
    resume_needed = false;
    evidence << snapshot << ',' << q(phase) << ',' << pid << ',' << requested << ','
             << stopped << ',' << end << ',' << (ok && stopped ? "resumed" : "failed")
             << ",SIGSTOP-waitpid-SIGCONT\n";
    evidence.flush();
    return ok && bool(evidence);
  }
};
struct BlobStore {
  int fd; uint64_t length = 0, limit;
  std::map<uint64_t, std::vector<uint64_t>> index;
  explicit BlobStore(const std::string& path) {
    fd = open(path.c_str(), O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC, 0600);
    if (fd < 0) throw std::runtime_error("cannot create evidence contents");
    const char* setting = getenv("SECURITY_CAPTURE_MAX_BYTES");
    limit = setting ? strtoull(setting, nullptr, 10) : UINT64_C(2147483648);
    if (limit < 4096) throw std::runtime_error("invalid capture byte budget");
  }
  ~BlobStore() { close(fd); }
  uint64_t save(const unsigned char* data, size_t n) {
    uint64_t hash = UINT64_C(1469598103934665603) ^ n;
    for(size_t i=0;i<n;++i) {hash^=data[i];hash*=UINT64_C(1099511628211);}
    unsigned char prior[4096];
    // Hash is only an index: exact comparison prevents collision-based omission.
    for(uint64_t off:index[hash])
      if(pread(fd,prior,n,off)==static_cast<ssize_t>(n) && !memcmp(prior,data,n)) return off;
    if(length+n>limit) throw std::runtime_error("capture-budget-exhausted");
    if(pwrite(fd,data,n,length)!=static_cast<ssize_t>(n)) throw std::runtime_error("evidence-write-failed");
    uint64_t off=length;length+=n;index[hash].push_back(off);return off;
  }
};
struct Collector {
  std::string dir, storage, manifest;
  pid_t pid; int kernel, mem=-1, pagemap=-1;
  BlobStore blobs;
  std::ofstream inventory, reads, phases, gaps, protected_log, process_stops;
  uint64_t snapshot=0, errors=0, read_bytes=0;
  std::set<std::string> registered_files;
  std::set<unsigned> observed_phases;
  std::vector<ke_range> protected_objects;
  Collector(const std::string& d,const std::string& s,pid_t p):dir(d),storage(s),manifest(d+"/regions.log"),pid(p),
    kernel(open("/dev/keystone-evidence",O_RDWR|O_CLOEXEC)),blobs(d+"/contents.bin"),
    inventory(d+"/inventory.csv"),reads(d+"/reads.csv"),phases(d+"/phases.csv"),
    gaps(d+"/gaps.csv"),protected_log(d+"/protected.csv"),process_stops(d+"/process-stops.csv") {
    inventory<<"snapshot,phase,time_ns,region,object,address,length,pfn,status,basis\n";
    reads<<"snapshot,phase,time_ns,region,object,address,length,pfn,bytes_read,blob_offset,status,reason\n";
    phases<<"snapshot,phase,time_ns,kind,checkpoint_id\n";
    gaps<<"phase,region,reason\n";
    protected_log<<"snapshot,start,length,group,epoch,type,permissions,basis\n";
    process_stops<<"snapshot,phase,pid,requested_ns,stopped_ns,resume_ns,status,method\n";
    struct statfs fs;
    std::ofstream filesystem(d+"/filesystem.csv");
    filesystem<<"magic,source\n";
    if(!statfs(s.c_str(),&fs))filesystem<<static_cast<uint64_t>(fs.f_type)<<','<<q(s)<<'\n';
    else gap("setup","storage","statfs-failed");
    if(kernel>=0 && ioctl(kernel,KE_RESET)) gap("setup","kernel","reset-failed");
    if(kernel<0) gap("setup","kernel","module-interface-unavailable");
  }
  ~Collector(){ if(mem>=0)close(mem);if(pagemap>=0)close(pagemap);if(kernel>=0)close(kernel); }
  void gap(const std::string& phase,const std::string& kind,const std::string& reason) {
    ++errors;gaps<<q(phase)<<','<<q(kind)<<','<<q(reason)<<'\n';gaps.flush();
  }
  uint64_t pfn(uint64_t va) {
    uint64_t entry=0;
    if(pagemap<0 || pread(pagemap,&entry,8,(va/4096)*8)!=8 || !(entry&(UINT64_C(1)<<63))) return 0;
    return entry&((UINT64_C(1)<<55)-1);
  }
  bool absent_page(uint64_t va) {
    uint64_t entry=0;
    return pagemap>=0 && pread(pagemap,&entry,8,(va/4096)*8)==8 &&
        !(entry&((UINT64_C(1)<<63)|(UINT64_C(1)<<62)));
  }
  void object(const std::string& phase,const std::string& region,const std::string& id,
              uint64_t address,uint64_t length,uint64_t phys,const std::string& basis) {
    inventory<<snapshot<<','<<q(phase)<<','<<now_ns()<<','<<q(region)<<','<<q(id)<<','
      <<address<<','<<length<<','<<phys<<",required,"<<q(basis)<<'\n';
  }
  void record(const std::string& phase,const std::string& region,const std::string& id,
              uint64_t address,uint64_t length,uint64_t phys,const unsigned char* data,
              ssize_t n,const std::string& reason="") {
    std::string status=n>0 && uint64_t(n)==length ? "covered" : "unreadable";
    uint64_t off=0;
    if(n>0) {
      try{off=blobs.save(data,n);read_bytes+=n;}
      catch(const std::exception& e){gap(phase,region,e.what());status="unreadable";n=0;}
    }
    std::string detail = reason;
    if(status!="covered") {
      ++errors;
      if(detail.empty()) detail=n==0 ? "zero-byte-read-object-unavailable" :
          (n<0 ? "read-failed" : "short-read");
    }
    reads<<snapshot<<','<<q(phase)<<','<<now_ns()<<','<<q(region)<<','<<q(id)<<','
      <<address<<','<<length<<','<<phys<<','<<std::max<ssize_t>(0,n)<<','<<off<<','<<status<<','<<q(detail)<<'\n';
  }
  void protected_ranges(const std::string& phase) {
    ke_ranges r={};
    if(kernel<0 || ioctl(kernel,KE_PROTECTED,&r)) {gap(phase,"protected","driver-range-metadata-unavailable");return;}
    protected_objects.clear();
    for(uint64_t i=0;i<r.count;++i) {
      const ke_range& x=r.ranges[i];
      protected_objects.push_back(x);
      protected_log<<snapshot<<','<<x.start<<','<<x.size<<','<<x.group<<','<<x.epoch<<','<<x.type<<','<<x.permissions
        <<",driver-live-group-metadata;SM-task-grants-in-run.log\n";
    }
  }
  void kernel_record(const std::string& phase,const std::string& kind,const std::string& id,ke_page& page,unsigned long cmd) {
    int rc=kernel<0 ? -1 : ioctl(kernel,cmd,&page);
    // Inventory is distinct from the successful-read ledger. Absent page-cache
    // entries are not allocated objects; busy/failed reads are coverage gaps.
    if(cmd==KE_FILE_PAGE && rc<0 && page.status==-ENOENT) {
      inventory<<snapshot<<','<<q(phase)<<','<<now_ns()<<','<<q(kind)<<','<<q(id)<<','
        <<page.index*4096<<",4096,0,not-applicable,cache-entry-absent-at-referenced-lookup\n";
      reads<<snapshot<<','<<q(phase)<<','<<now_ns()<<','<<q(kind)<<','<<q(id)<<','
        <<page.index*4096<<",4096,0,0,0,not-applicable,cache-entry-absent\n";
      return;
    }
    object(phase,kind,id,page.index*4096,4096,page.pfn,"held-page-reference;kernel-observer-v1");
    record(phase,kind,id,page.index*4096,4096,page.pfn,page.data,rc<0?0:page.length,
      rc<0?"kernel-status-"+std::to_string(page.status):"");
  }
  void process(const std::string& phase) {
    // Hold Host threads still from maps enumeration through the final page read.
    // Kernel I/O and enclave execution are not claimed to be atomically frozen.
    StoppedProcess pause(pid, process_stops, snapshot, phase);
    protected_ranges(phase);
    const std::string proc="/proc/"+std::to_string(pid);
    if(mem<0)mem=open((proc+"/mem").c_str(),O_RDONLY|O_CLOEXEC);
    if(pagemap<0)pagemap=open((proc+"/pagemap").c_str(),O_RDONLY|O_CLOEXEC);
    std::ifstream maps(proc+"/maps");
    std::ofstream saved(dir+"/maps-"+std::to_string(snapshot)+".txt");
    if(!maps){gap(phase,"host-process","maps-unreadable");return;}
    std::string line;
    unsigned char data[4096];
    while(std::getline(maps,line)) {
      saved<<line<<'\n';
      unsigned long long start,end,offset;char perms[5]={};
      if(sscanf(line.c_str(),"%llx-%llx %4s %llx",&start,&end,perms,&offset)!=4){gap(phase,"host-process","invalid-mapping");continue;}
      uint64_t absent_start=0,absent_length=0;
      const auto flush_absent = [&]() {
        if(!absent_length)return;
        // An unbacked PROT_NONE reservation has no resident/swapped payload.
        // Preserve the VMA and the pagemap basis rather than faulting it in.
        inventory<<snapshot<<','<<q(phase)<<','<<now_ns()<<",host-process,"<<q(line)<<','
          <<absent_start<<','<<absent_length<<",0,not-applicable,pagemap-no-present-or-swapped-page;PROT_NONE\n";
        reads<<snapshot<<','<<q(phase)<<','<<now_ns()<<",host-process,"<<q(line)<<','
          <<absent_start<<','<<absent_length<<",0,0,0,not-applicable,unbacked-PROT_NONE-reservation\n";
        absent_length=0;
      };
      for(uint64_t at=start;at<end;at+=4096) {
        const uint64_t length=std::min<uint64_t>(4096,end-at),phys=pfn(at);
        if(!strncmp(perms,"---",3) && absent_page(at)) {
          if(!absent_length)absent_start=at;
          absent_length+=length;
          continue;
        }
        flush_absent();
        bool excluded=false;
        for(const auto& range:protected_objects)
          if(phys && phys*4096>=range.start && phys*4096-range.start<range.size)excluded=true;
        if(excluded){
          inventory<<snapshot<<','<<q(phase)<<','<<now_ns()<<",host-process,"<<q(line)<<','<<at<<','<<length<<','<<phys<<",protected,driver-physical-range\n";
          continue;
        }
        object(phase,"host-process",line,at,length,phys,"proc-maps-all-mappings;no-registration-filter");
        ssize_t n=mem<0?-1:pread(mem,data,length,at);
        if(n<0 && (line.find("io_uring")!=std::string::npos || line.find("[vvar]")!=std::string::npos || line.find("[vdso]")!=std::string::npos) && kernel>=0) {
          ke_page page={};page.pid=pid;page.address=at;page.index=at/4096;
          const char* kind=line.find("io_uring")!=std::string::npos ? "kernel-io-uring" : "kernel-vma";
          kernel_record(phase,kind,line,page,KE_RING_PAGE);
          // Preserve the /proc failure, with an explicitly linked alternative.
          reads<<snapshot<<','<<q(phase)<<','<<now_ns()<<",host-process,"<<q(line)<<','<<at<<','<<length<<','<<phys
            <<",0,0,alternative,"<<kind<<'\n';
          continue;
        }
        record(phase,"host-process",line,at,length,n>0?pfn(at):phys,data,n,n<0?"proc-mem-error-"+std::to_string(errno):"");
      }
      flush_absent();
    }
    if(!pause.resume()) throw std::runtime_error("snapshot-resume-or-ledger-failed");
  }
  void files(const std::string& phase) {
    DIR* directory=opendir(storage.c_str());
    if(!directory){gap(phase,"files","storage-directory-unreadable");return;}
    while(dirent* e=readdir(directory)) {
      if(e->d_name[0]=='.')continue;
      std::string path=storage+"/"+e->d_name;struct stat st;
      if(lstat(path.c_str(),&st) || !S_ISREG(st.st_mode))continue;
      int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
      if(fd<0){gap(phase,"files",path+":open-failed");continue;}
      if(fstat(fd,&st) || !S_ISREG(st.st_mode)){gap(phase,"files",path+":changed-object-type");close(fd);continue;}
      if(kernel>=0 && registered_files.insert(path+":"+std::to_string(st.st_ino)).second) {
        ke_page page={};page.fd=fd;
        if(ioctl(kernel,KE_REGISTER_FILE,&page))gap(phase,"kernel-bio",path+":registration-failed");
        // Events before registration cannot be retroactively covered.
        phases<<snapshot<<','<<q(path)<<','<<now_ns()<<",file-lifecycle-registration\n";
      }
      unsigned char data[4096];
      for(uint64_t at=0;at<uint64_t(st.st_size);at+=4096) {
        size_t length=std::min<uint64_t>(4096,st.st_size-at);
        if(kernel>=0){ke_page page={};page.fd=fd;page.index=at/4096;kernel_record(phase,"kernel-page-cache",path,page,KE_FILE_PAGE);}
        object(phase,"ciphertext-file",path,at,length,0,"regular-file-read;cache-inventory-precedes-this-read");
        ssize_t n=pread(fd,data,length,at);
        record(phase,"ciphertext-file",path,at,length,0,data,n,n<0?"file-read-failed":"");
        // File reads can generate BIO events too. Drain the bounded observer
        // while walking a large file, not only after all its pages were read.
        if((at/4096+1)%64==0)bios(phase);
      }
      close(fd);
    }
    closedir(directory);
  }
  void bios(const std::string& phase) {
    if(kernel<0)return;
    ke_page p={};
    while(!ioctl(kernel,KE_BIO_NEXT,&p)) {
      std::string id="inode-"+std::to_string(p.inode)+"@"+std::to_string(p.timestamp_ns);
      object(phase,"kernel-bio",id,p.index*4096,4096,p.pfn,"bio-owner-live-at-block_bio_queue;sampled-not-device-atomic");
      record(phase,"kernel-bio",id,p.index*4096,4096,p.pfn,p.data,p.length);
      memset(&p,0,sizeof(p));
    }
    if(p.status!=-EAGAIN)gap(phase,"kernel-bio","drain-failed");
    memset(&p,0,sizeof(p));
    if(ioctl(kernel,KE_STATS,&p))gap(phase,"kernel-bio","stats-failed");
    else {
      phases<<snapshot<<",bio-pages="<<p.index<<";lost="<<p.pfn<<','<<now_ns()<<",kernel-lifecycle-stats\n";
      if(p.pfn)gap(phase,"kernel-bio","bounded-ring-overflow-"+std::to_string(p.pfn));
      if(!(p.reserved&1))gap(phase,"kernel-bio","block_bio_queue-unavailable");
      if(!(p.reserved&2))gap(phase,"kernel-bio","bounce-observation-unavailable");
      if(p.offset)gap(phase,"kernel-bounce","unassociated-bounce-events-"+std::to_string(p.offset));
    }
  }
  void snapshot_run(const std::string& phase,const std::string& kind,uint64_t checkpoint=0) {
    ++snapshot;phases<<snapshot<<','<<q(phase)<<','<<now_ns()<<','<<q(kind)<<','<<checkpoint<<'\n';
    bios(phase);process(phase);files(phase);bios(phase);
    inventory.flush();reads.flush();phases.flush();protected_log.flush();
    if(!inventory||!reads||!phases||!protected_log)throw std::runtime_error("evidence-ledger-write-failed");
  }
};
static int preflight() {
  int fd = open("/dev/keystone-evidence", O_RDWR|O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr,"[security-preflight] observer unavailable: %s; deploy/load keystone_evidence.ko built for this board kernel\n",strerror(errno));
    return 2;
  }
  ke_ranges ranges = {};
  if (ioctl(fd,KE_PROTECTED,&ranges)) {
    fprintf(stderr,"[security-preflight] protected-range provider unavailable: %s; deploy/load the matching updated Keystone driver\n",strerror(errno));
    close(fd);return 2;
  }
  // Read the dedicated control page without planting a marker in this process.
  ke_page page = {};
  if (ioctl(fd,KE_CONTROL,&page) || page.length != KE_PAGE_BYTES) {
    fprintf(stderr,"[security-preflight] kernel control page unavailable; load observer with controls=1\n");
    close(fd);return 2;
  }
  close(fd);
  puts("[security-preflight] observer, protected-range provider and control page ready; coverage remains subject to capture and offline verification");
  return 0;
}
int main(int argc,char** argv) {
  if(argc==2 && !strcmp(argv[1],"--preflight"))return preflight();
  if(argc==2 && !strcmp(argv[1],"--capture-info")){puts("security_capture_version=1 security_capture_preflight=1 security_capture_checkpoint_ids=1 security_capture_lifecycle=2 security_capture_compact=1 security_capture_process_stop=1 marker_search=offline scope=process+registered+kernel-referenced-pages");return 0;}
  if(argc<6 || strcmp(argv[4],"--")){fprintf(stderr,"usage: capture nonce evidence-dir storage-dir -- command [args...]\n");return 2;}
  const std::string dir=argv[2],storage=argv[3];
  std::ofstream manifest(dir+"/regions.log");manifest.close();
  pid_t child=fork();if(child<0)return 2;
  if(!child){
    // Do not dump unrelated operator credentials inherited in the environment.
    // The target is a dedicated fixture with public benchmark keys and inputs.
    const char* names[]={"GROUP_PMP_TEST_MODE","GROUP_PMP_SQLITE_IO_MODE","GROUP_PMP_SQLITE_MAX_WORKERS",
      "GROUP_PMP_SQLITE_REPETITIONS","GROUP_PMP_SQLITE_TOTAL_BYTES","GROUP_PMP_SQLITE_CACHE_MODE",
      "GROUP_PMP_SQLITE_RANDOM_SEED","GROUP_PMP_SQLITE_WORKLOAD_SET","GROUP_PMP_SQLITE_STORAGE_DIR",
      "GROUP_PMP_SQLITE_CSV","GROUP_PMP_SQLITE_IO_RANGE_CSV","GROUP_PMP_SECURITY_CAPTURE_WORKERS",
      "GROUP_PMP_SECURITY_CAPTURE_WORKLOAD","GROUP_PMP_SECURITY_CAPTURE_POSITIVE",
      "GROUP_PMP_MIXED_TIMEOUT_SEC","GROUP_PMP_MIXED_WARMUP_TIMEOUT_MS"};
    std::map<std::string,std::string> environment;
    for(const char* name:names)if(const char* value=getenv(name))environment[name]=value;
    clearenv();
    for(const auto& x:environment)setenv(x.first.c_str(),x.second.c_str(),1);
    setenv("GROUP_PMP_SECURITY_NONCE",argv[1],1);
    setenv("GROUP_PMP_SECURITY_REGIONS",(dir+"/regions.log").c_str(),1);
    setenv("GROUP_PMP_SECURITY_CAPTURE_DIR",dir.c_str(),1);
    execvp(argv[5],argv+5);_exit(127);
  }
  signal(SIGTERM,interrupted);signal(SIGINT,interrupted);signal(SIGHUP,interrupted);
  int status=0;bool positive=getenv("SECURITY_CAPTURE_POSITIVE")!=nullptr;bool reaped=false;
  const char* total=getenv("GROUP_PMP_SQLITE_TOTAL_BYTES");
  const bool compact=total && !strcmp(total,"1000000");
  try {
    Collector c(dir,storage,child);uint64_t ack=0;
    bool cleanup_captured=false,running_sampled=false;
    auto last=std::chrono::steady_clock::now();auto deadline=last+std::chrono::minutes(60);
    for(;;){
      pid_t state=waitpid(child,&status,WNOHANG);if(state==child){reaped=true;break;}
      if(state<0 && errno!=EINTR)throw std::runtime_error("waitpid-failed");
      if(stop_capture||std::chrono::steady_clock::now()>deadline)throw std::runtime_error("capture-interrupted-or-timeout");
      uint64_t request=0;std::string phase;std::ifstream ready(dir+"/regions.log.ready");ready>>request>>phase;
      if(request>ack) {
        c.snapshot_run(phase,"checkpoint",request);
        if(positive && c.kernel>=0){ke_page p={};c.kernel_record(phase,"kernel-control","dedicated-positive-page",p,KE_CONTROL);}
        // The final snapshot completes while the child is still waiting for ACK.
        // Do not race its address-space teardown with another periodic snapshot.
        if(phase=="after-cleanup") {
          cleanup_captured=true;
          printf("[security-capture] final checkpoint=%llu captured; periodic sampling stopped before ACK\n",
                 (unsigned long long)request);
          fflush(stdout);
        }
        ack=request;std::ofstream f(dir+"/regions.log.ack");f<<ack<<'\n';f.flush();if(!f)throw std::runtime_error("checkpoint-ack-failed");
        printf("[security-capture] checkpoint=%llu phase=%s captured\n",
               (unsigned long long)request,phase.c_str());fflush(stdout);
        if(compact && !positive && !running_sampled && phase=="worker-milestone-1") {
          // Sample after ACK lets the small workload advance; its later
          // checkpoints keep the process alive while this sample is collected.
          c.snapshot_run("during","running-sample");
          running_sampled=true;
        }
        last=std::chrono::steady_clock::now();
      } else if(!positive && !cleanup_captured && std::chrono::steady_clock::now()-last>std::chrono::seconds(1)) {
        c.snapshot_run("during","periodic");last=std::chrono::steady_clock::now();
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    c.bios("after-exit");
    std::ofstream result(dir+"/capture.csv");
    result<<"workload_ok,snapshots,capture_errors,repeated_read_bytes,negative_hits\n"
      <<(WIFEXITED(status)&&WEXITSTATUS(status)==0)<<','<<c.snapshot<<','<<c.errors<<','<<c.read_bytes<<",\n";
    // Unknown hits remain blank until independent matching; this is not PASS.
    printf("[security-capture] captured snapshots=%llu errors=%llu; hits=unverified; offline verifier required\n",(unsigned long long)c.snapshot,(unsigned long long)c.errors);
    return WIFEXITED(status)&&WEXITSTATUS(status)==0?0:2;
  } catch(const std::exception& e) {
    std::ofstream failure(dir+"/capture-failure.txt");failure<<e.what()<<'\n';
    fprintf(stderr,"[security-capture] %s\n",e.what());
    if(!reaped){kill(child,SIGTERM);std::this_thread::sleep_for(std::chrono::seconds(2));kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}}
    return 2;
  }
}
