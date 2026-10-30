#ifndef MOTIVATION_URING_IO_HPP
#define MOTIVATION_URING_IO_HPP
#include "read-engine.hpp"
#include "../host/io-uring-transport.hpp"
#include <atomic>
#include <array>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <poll.h>
#include <sys/eventfd.h>
namespace Motivation {
// The same registered-file/FIXED SQE and per-CQE transport as SQLite/FIO.
// Both modes use the same reactor. Sync waits inside its OCALL handler; Async
// returns on admission and only blocks when neither owned buffer is complete.
class UringReadEngine final : public ReadEngine {
  struct Request {
    bool pending=false,busy=false;
    uint64_t offset=0,begin=0;
    size_t bytes=0;
    Callback done;
    GroupIo::InlineOneList<iovec> vectors;
  } requests[2];
  GroupIo::RawIoUring ring{64};
  std::vector<iovec> buffers;
  std::mutex mutex;
  std::condition_variable initialized;
  std::thread reactor;
  bool stopping=false,ready=false;
  int wake=-1,file=-1;
  std::atomic<uint64_t> enters{0},completed{0};
  void signal() {
    uint64_t one=1;
    ssize_t rc;
    do { rc=write(wake,&one,sizeof(one)); } while(rc<0 && errno==EINTR);
    if(rc<0 && errno!=EAGAIN) std::terminate();
  }
  void finish(unsigned s,int result) {
    Callback done; uint64_t begin=0,end=ticks(); int error=EIO;
    {
      std::lock_guard<std::mutex> lock(mutex);
      auto& r=requests[s];
      if(!r.busy) return;
      error=result==static_cast<int>(r.bytes)?0:(result<0?-result:EIO);
      begin=r.begin; done=std::move(r.done); r.busy=false; r.pending=false;
    }
    if(done) done(error,begin,end);
  }
  void loop() {
    std::vector<GroupIo::RawIoUring::Operation> ops;
    std::vector<uint64_t> tokens;
    ops.reserve(2); tokens.reserve(2);
    { std::lock_guard<std::mutex> lock(mutex); ready=true; initialized.notify_all(); }
    for(;;) {
      ops.clear(); tokens.clear(); bool stop;
      {
        std::lock_guard<std::mutex> lock(mutex);
        stop=stopping;
        for(unsigned s=0;s<2;++s) if(requests[s].pending) {
          auto& r=requests[s]; r.pending=false; r.begin=ticks();
          r.vectors={iovec{buffers[s].iov_base,r.bytes}};
          GroupIo::RawIoUring::Operation op;
          op.fd=file; op.fixed_file_index=0; op.fixed_buffer_index=s;
          op.offset=r.offset; op.vectors=&r.vectors; op.expected=r.bytes; op.read=true;
          ops.push_back(op); tokens.push_back(s+1);
        }
      }
      if(!ops.empty()) {
        int error=0; size_t calls=0;
        size_t accepted=ring.submitAsync(ops,tokens,&error,&calls);
        enters+=calls;
        // Accepted SQEs retain storage until their own CQE, including partial
        // submission. Never replay a read or release a registered slot early.
        for(size_t i=accepted;i<ops.size();++i)
          finish(static_cast<unsigned>(tokens[i]-1),error?error:-EIO);
      }
      for(const auto& c:ring.reapAsync()) {
        ++completed;
        if(c.token>=1 && c.token<=2) finish(static_cast<unsigned>(c.token-1),c.result);
        else std::terminate(); // impossible token is a transport invariant failure
      }
      if(stop && !ring.inflight()) break;
      pollfd fds[2]={{wake,POLLIN,0},{ring.descriptor(),POLLIN,0}};
      int rc;
      do { rc=poll(fds,2,-1); } while(rc<0 && errno==EINTR);
      if(rc<0) std::terminate();
      if(fds[0].revents&POLLIN) {
        uint64_t value; ssize_t drained;
        do { drained=read(wake,&value,sizeof(value)); } while(drained<0 && errno==EINTR);
        if(drained<0 && errno!=EAGAIN) std::terminate();
      }
    }
  }
 public:
  ~UringReadEngine() { shutdown(); if(wake>=0) close(wake); }
  bool configure(int fd,const std::vector<iovec>& regions) override {
    if(file>=0 || regions.size()!=2 || !ring.available() ||
       !ring.registerFiles({fd}) || !ring.registerBuffers(regions)) return false;
    wake=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
    if(wake<0) return false;
    buffers=regions; file=fd;
    reactor=std::thread(&UringReadEngine::loop,this);
    std::unique_lock<std::mutex> lock(mutex);
    initialized.wait(lock,[&]{return ready;});
    return true;
  }
  bool submit(unsigned s,uint64_t offset,size_t bytes,Callback done) override {
    std::lock_guard<std::mutex> lock(mutex);
    if(file<0 || stopping || s>=2 || requests[s].busy || !bytes || bytes>buffers[s].iov_len) return false;
    auto& r=requests[s]; r.busy=r.pending=true; r.offset=offset; r.bytes=bytes; r.done=std::move(done);
    signal(); return true;
  }
  void shutdown() override {
    { std::lock_guard<std::mutex> lock(mutex); stopping=true; if(wake>=0) signal(); }
    if(reactor.joinable()) reactor.join();
  }
  uint64_t submit_calls() const override { return enters.load(); }
  uint64_t completed_reads() const override { return completed.load(); }
};
}
#endif
