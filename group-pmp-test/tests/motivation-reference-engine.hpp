#ifndef MOTIVATION_REFERENCE_ENGINE_HPP
#define MOTIVATION_REFERENCE_ENGINE_HPP
// Native protocol-test fixture only. Never selected by the production runner.
#include "../motivation/backend.hpp"
class MotivationReferenceEngine final : public Motivation::ReadEngine {
  struct Task { bool pending=false; uint64_t offset=0; size_t bytes=0; Callback done; } tasks[2];
  std::vector<iovec> regions;
  std::thread threads[2]; std::mutex mutex; std::condition_variable cv;
  bool stopping=false; int fd=-1;
  std::atomic<uint64_t> submits{0},completions{0};
  void run(unsigned s) {
    for(;;) {
      Task job;
      {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock,[&]{return stopping || tasks[s].pending;});
        if(!tasks[s].pending) return;
        job=std::move(tasks[s]); tasks[s].pending=false;
      }
      uint64_t begin=Motivation::ticks();
      bool ok=Motivation::transfer(fd,regions[s].iov_base,job.bytes,job.offset,false);
      ++completions; job.done(ok?0:EIO,begin,Motivation::ticks());
    }
  }
 public:
  ~MotivationReferenceEngine() { shutdown(); }
  bool configure(int file,const std::vector<iovec>& buffers) override {
    fd=file; regions=buffers;
    for(unsigned s=0;s<2;++s) threads[s]=std::thread(&MotivationReferenceEngine::run,this,s);
    return true;
  }
  bool submit(unsigned s,uint64_t off,size_t n,Callback done) override {
    std::lock_guard<std::mutex> lock(mutex);
    if(stopping || s>=2 || tasks[s].pending) return false;
    auto& t=tasks[s]; t.offset=off; t.bytes=n; t.done=std::move(done); t.pending=true;
    ++submits; cv.notify_all(); return true;
  }
  void shutdown() override {
    { std::lock_guard<std::mutex> lock(mutex); stopping=true; cv.notify_all(); }
    for(auto& t:threads) if(t.joinable()) t.join();
  }
  uint64_t submit_calls() const override { return submits.load(); }
  uint64_t completed_reads() const override { return completions.load(); }
};
#endif
