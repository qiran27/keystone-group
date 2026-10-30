#ifndef MOTIVATION_BACKEND_HPP
#define MOTIVATION_BACKEND_HPP
#include "protocol.h"
#include "read-engine.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
namespace Motivation {
inline bool transfer(int fd,void* data,size_t bytes,uint64_t offset,bool write) {
  size_t done=0;
  while (done<bytes) {
    ssize_t n=write ? pwrite(fd,static_cast<char*>(data)+done,bytes-done,offset+done)
                    : pread(fd,static_cast<char*>(data)+done,bytes-done,offset+done);
    if (n<0 && errno==EINTR) continue;
    if (n<=0) return false;
    done+=static_cast<size_t>(n);
  }
  return true;
}
struct Trace { uint64_t block,slot,generation,admit,begin,end,publish,returned,compute_begin,compute_end,release,capture_end,decrypt_end; };
struct Counters {
  std::atomic<uint64_t> outstanding{0},active{0},peak_outstanding{0},peak_active{0};
  static void enter(std::atomic<uint64_t>& current,std::atomic<uint64_t>& peak) {
    uint64_t value=current.fetch_add(1)+1,old=peak.load();
    while (old<value && !peak.compare_exchange_weak(old,value)) {}
  }
};
class Backend {
  struct Slot {
    unsigned state=0;
    uint64_t block=0,generation=0,bytes=0,admit=0,begin=0,end=0,publish=0;
    int error=0;
  } slots[2];
  uint8_t* utm;
  int fd=-1;
  std::mutex mutex;
  std::condition_variable cv;
  std::unique_ptr<ReadEngine> io;
  bool stopping=false,configured=false,warmed=false,started=false;
  uint64_t written=0,next=0,released=0,running=0;
  std::string cache;
  bool diagnostic;
  bool collective,start_requested=false;
  std::function<void()> waiter;
  std::shared_ptr<Counters> counters;
  void complete(unsigned s,int error,uint64_t begin,uint64_t end) {
    std::unique_lock<std::mutex> lock(mutex);
    Slot& v=slots[s]; v.begin=begin;
    --running;
    --counters->active;
    ++data_operations;
    v.error=error; v.end=end; v.publish=ticks();
    mot_completion result={0,v.block,v.generation,v.bytes,end,v.error};
    auto* out=reinterpret_cast<mot_completion*>(utm+mot_meta(s));
    std::memcpy(out,&result,sizeof(result));
    __atomic_store_n(&out->ready,UINT64_C(1),__ATOMIC_RELEASE);
    v.state=3; cv.notify_all();
    auto notify=std::move(waiter);
    lock.unlock();
    if (notify) notify();
  }
  bool cache_prepare() {
    if (cache=="hot") {
      std::vector<uint8_t> buf(MOT_BLOCK);
      for (uint64_t off=0;off<file_bytes;off+=buf.size())
        if (!transfer(fd,buf.data(),std::min<uint64_t>(buf.size(),file_bytes-off),off,false)) return false;
      return true;
    }
    if (cache!="cold" || fdatasync(fd) || posix_fadvise(fd,0,0,POSIX_FADV_DONTNEED)) return false;
    void* map=mmap(nullptr,file_bytes,PROT_READ,MAP_SHARED,fd,0);
    if (map==MAP_FAILED) return false;
    long page=sysconf(_SC_PAGESIZE);
    if (page<=0) { munmap(map,file_bytes); return false; }
    std::vector<unsigned char> resident((file_bytes+page-1)/page);
    bool ok=mincore(map,file_bytes,resident.data())==0;
    resident_pages=0;
    for (auto v:resident) resident_pages+=(v&1)!=0;
    if (munmap(map,file_bytes)) ok=false;
    /* Do not silently label a non-evicted file (e.g. tmpfs) cold. */
    return ok && resident_pages==0;
  }
  bool valid_release(const mot_call& c) const {
    if(c.slot>=2) return false;
    const Slot& v=slots[c.slot];
    return v.state==3 && !v.error && c.block==v.block && c.generation==v.generation &&
        c.compute_end>=c.compute_begin && c.compute_begin>=v.end && c.submit_return>=v.admit &&
        (config.mode!=MOT_SYNC || c.submit_return>=v.publish) &&
        (diagnostic ? c.compute_begin<=c.capture_end && c.capture_end<=c.decrypt_end && c.decrypt_end<=c.compute_end
                    : !c.capture_end && !c.decrypt_end);
  }
  bool valid_submit(const mot_call& c,bool reclaim=false) const {
    if(c.slot>=2 || c.block!=next || next>=config.limit_block) return false;
    const Slot& v=slots[c.slot];
    return (reclaim || !v.state) && v.generation!=UINT64_MAX && c.generation==v.generation+1 &&
        c.bytes==mot_wire_bytes(&config,next) &&
        (config.mode!=MOT_SYNC || (!c.slot && next-config.first_block==released+(reclaim?1:0)));
  }
  void retire(const mot_call& c) {
    Slot& v=slots[c.slot];
    if(diagnostic) trace.push_back({v.block,c.slot,v.generation,v.admit,v.begin,v.end,v.publish,
        c.submit_return,c.compute_begin,c.compute_end,ticks(),c.capture_end,c.decrypt_end});
    v.state=0; ++released; --counters->outstanding;
  }
  int submit(const mot_call& c,std::unique_lock<std::mutex>& lock) {
    if(!valid_submit(c)) return -1;
    Slot& v=slots[c.slot];
    auto* out=reinterpret_cast<mot_completion*>(utm+mot_meta(c.slot));
    __atomic_store_n(&out->ready,UINT64_C(0),__ATOMIC_RELEASE);
    v.block=c.block; v.generation=c.generation; v.bytes=c.bytes; v.admit=ticks(); v.state=1;
    ++next; max_outstanding=std::max(max_outstanding,next-config.first_block-released);
    Counters::enter(counters->outstanding,counters->peak_outstanding);
    ++running; Counters::enter(counters->active,counters->peak_active);
    max_active_reads=std::max(max_active_reads,running);
    const unsigned submitted_slot=static_cast<unsigned>(c.slot);
    if(!io->submit(c.slot,c.block*(mot_block_bytes(&config)+sizeof(mot_header)),c.bytes,
        [this,submitted_slot](int e,uint64_t b,uint64_t end){complete(submitted_slot,e,b,end);})) {
      --running; --counters->active; --counters->outstanding; --next; v.state=0; return -1;
    }
    ++read_ocalls;
    if(config.mode==MOT_SYNC) {
      // Recycle+submit shares this blocking path: never resume before its CQE publication.
      if(!cv.wait_for(lock,std::chrono::seconds(600),[&]{return stopping || v.state==3;}) ||
          stopping || v.error) return -1;
    }
    cv.notify_all(); return 0;
  }
 public:
  mot_config config;
  mot_call result={};
  uint64_t file_bytes=0,max_outstanding=0,max_active_reads=0,resident_pages=0,data_operations=0;
  uint64_t read_ocalls=0,release_only_ocalls=0,release_submit_ocalls=0;
  bool finished=false;
  std::vector<Trace> trace;
  Backend(uint8_t* buffer,size_t size,const char* path,mot_config cfg,std::string policy,bool diag,
          bool shared_start=false,std::shared_ptr<Counters> shared_counters=std::shared_ptr<Counters>(),
          std::unique_ptr<ReadEngine> engine=std::unique_ptr<ReadEngine>())
      : utm(buffer),io(std::move(engine)),cache(policy),diagnostic(diag),collective(shared_start),
        counters(shared_counters?shared_counters:std::make_shared<Counters>()),config(cfg) {
    if (size<MOT_UTM_BYTES || !cfg.input_bytes || cfg.input_bytes>500000000 || !mot_valid_geometry(&cfg) ||
        cfg.cipher>MOT_CIPHER_ECB || mot_count(&cfg)>MOT_MAX_BLOCKS || cfg.first_block>=cfg.limit_block ||
        cfg.limit_block>mot_count(&cfg) || diagnostic!=(cfg.diagnostic!=0) ||
        (cfg.mode==MOT_PREPARE && (cfg.first_block || cfg.limit_block!=mot_count(&cfg))))
      throw std::runtime_error("invalid motivation configuration/UTM");
    next=cfg.first_block;
    file_bytes=mot_file_bytes(&cfg);
    std::memset(utm+MOT_META_OFFSET,0,2*sizeof(mot_completion));
    fd=open(path,cfg.mode==MOT_PREPARE ? O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC : O_RDWR|O_CLOEXEC,0600);
    if (fd<0) throw std::runtime_error("cannot open ciphertext file");
    struct stat st={};
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) ||
        (cfg.mode!=MOT_PREPARE && static_cast<uint64_t>(st.st_size)!=file_bytes)) {
      close(fd); fd=-1; throw std::runtime_error("ciphertext size/type mismatch");
    }
    try {
      if (diagnostic) trace.reserve(cfg.limit_block-cfg.first_block);
      if (cfg.mode!=MOT_PREPARE && (!io || !io->configure(fd,{
          iovec{utm+mot_data(0),MOT_BLOCK+sizeof(mot_header)},
          iovec{utm+mot_data(1),MOT_BLOCK+sizeof(mot_header)}})))
        throw std::runtime_error("shared registered io_uring transport unavailable; no pread fallback");
    } catch (...) { shutdown(); close(fd); fd=-1; throw; }
  }
  void shutdown() {
    { std::lock_guard<std::mutex> lock(mutex); stopping=true; waiter={}; cv.notify_all(); }
    if(io) io->shutdown();
  }
  ~Backend() { shutdown(); if (fd>=0) close(fd); }
  uint64_t submit_calls() const { return io?io->submit_calls():0; }
  uint64_t completed_reads() const { return io?io->completed_reads():0; }
  bool prepare_group_cache() {
    std::lock_guard<std::mutex> lock(mutex);
    return collective && start_requested && !started && cache_prepare();
  }
  bool enable_group_start() {
    std::lock_guard<std::mutex> lock(mutex);
    if (!collective || !start_requested || started || stopping) return false;
    started=true; return true;
  }
  int wait_async(std::function<void()> notify,mot_reply& r) {
    std::unique_lock<std::mutex> lock(mutex);
    r={}; r.status=-1; r.config=config;
    if (!started || stopping || finished || waiter || next-config.first_block<=released) return -1;
    r.status=0;
    if (slots[0].state==3 || slots[1].state==3) { lock.unlock(); notify(); }
    else waiter=std::move(notify);
    return 0;
  }
  int handle(const mot_call& c,mot_reply& r) {
    std::unique_lock<std::mutex> lock(mutex);
    r={}; r.status=-1; r.config=config;
    if (finished || stopping) return -1;
    const uint64_t count=config.limit_block-config.first_block;
    if (c.op==MOT_CONFIG && !configured) { configured=true; r.status=0; return 0; }
    if (!configured) return -1;
    if (config.mode==MOT_PREPARE) {
      if (c.op==MOT_PUT && c.slot==0 && c.block==written && written<count &&
          c.bytes==mot_wire_bytes(&config,written)) {
        mot_header h; std::memcpy(&h,utm+mot_data(0),sizeof(h));
        if (h.magic!=MOT_MAGIC || h.object!=config.object || h.block!=written ||
            h.length!=mot_block_length(&config,written) || h.reserved[0]!=config.cipher) return -1;
        if (!transfer(fd,utm+mot_data(0),c.bytes,written*(mot_block_bytes(&config)+sizeof(mot_header)),true)) return -1;
        ++written; r.status=0; return 0;
      }
      if (c.op==MOT_PREPARED && written==count && !fdatasync(fd)) {
        finished=true; result=c; r.status=0; return 0;
      }
      return -1;
    }
    if (c.op==MOT_WARM && !warmed && !started) {
      if (!transfer(fd,utm+mot_data(0),mot_wire_bytes(&config,config.first_block),
                    config.first_block*(mot_block_bytes(&config)+sizeof(mot_header)),false)) return -1;
      warmed=true; r.status=0; return 0;
    }
    if (c.op==MOT_START && warmed && !started && !start_requested) {
      start_requested=true;
      if (collective) { r.status=0; return 0; }
      if (!cache_prepare()) return -1;
      started=true; r.status=0; return 0;
    }
    if (!started) return -1;
    if(c.op==MOT_SUBMIT) {
      r.status=submit(c,lock); return static_cast<int>(r.status);
    }
    if(c.op==MOT_RELEASE_SUBMIT) {
      mot_call read={};read.op=MOT_SUBMIT;read.slot=c.slot;
      read.block=c.next_block;read.generation=c.next_generation;read.bytes=c.next_bytes;
      // Reject either identity before changing ownership. An actual submit failure
      // after retirement is fatal to the run, never a successful recycled read.
      if(!valid_release(c) || !valid_submit(read,true)) return -1;
      retire(c);
      r.status=submit(read,lock);
      if(!r.status) ++release_submit_ocalls;
      return static_cast<int>(r.status);
    }
    if (c.op==MOT_WAIT_ANY && next-config.first_block>released) {
      if (!cv.wait_for(lock,std::chrono::seconds(600),[&]{return stopping || slots[0].state==3 || slots[1].state==3;}) || stopping) return -1;
      r.status=0; return 0;
    }
    if(c.op==MOT_RELEASE) {
      if(!valid_release(c) || c.next_block || c.next_generation || c.next_bytes) return -1;
      retire(c); ++release_only_ocalls; r.status=0; return 0;
    }
    if (c.op==MOT_DONE && next==config.limit_block && released==count && !slots[0].state && !slots[1].state &&
        c.processed==mot_range_bytes(&config) && c.blocks==count && c.elapsed_ticks &&
        read_ocalls==count && release_only_ocalls==mot_initial_reads(&config) &&
        release_submit_ocalls==count-mot_initial_reads(&config)) {
      result=c; finished=true; r.status=0; return 0;
    }
    return -1;
  }
};
}
#endif
