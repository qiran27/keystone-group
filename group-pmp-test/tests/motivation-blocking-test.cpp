// Deterministic protocol witness, NOT a performance test. The test controls a
// completion callback so a blocking OCALL cannot pass just because I/O is fast.
#include "motivation-reference-engine.hpp"
#include <cassert>
#include <iostream>
class GateEngine final : public Motivation::ReadEngine {
  MotivationReferenceEngine inner;
  std::mutex mutex;std::condition_variable cv;
  bool reached=false,allowed=false;
  std::atomic<bool> refuse{false};
 public:
  bool configure(int fd,const std::vector<iovec>& buffers) override {return inner.configure(fd,buffers);}
  bool submit(unsigned slot,uint64_t off,size_t bytes,Callback done) override {
    if(refuse.exchange(false)) return false;
    return inner.submit(slot,off,bytes,[this,done](int e,uint64_t begin,uint64_t end){
      {std::unique_lock<std::mutex> lock(mutex);reached=true;cv.notify_all();cv.wait(lock,[&]{return allowed;});}
      done(e,begin,end);
    });
  }
  void wait_at_completion() {std::unique_lock<std::mutex> lock(mutex);assert(cv.wait_for(lock,std::chrono::seconds(5),[&]{return reached;}));}
  void release() {std::lock_guard<std::mutex> lock(mutex);allowed=true;cv.notify_all();}
  void reset() {std::lock_guard<std::mutex> lock(mutex);reached=allowed=false;}
  void refuse_next() {refuse=true;}
  void shutdown() override {release();inner.shutdown();}
  ~GateEngine() {shutdown();}
  uint64_t submit_calls() const override {return inner.submit_calls();}
  uint64_t completed_reads() const override {return inner.completed_reads();}
};
int main(int argc,char** argv) {
  assert(argc==2);std::string path=std::string(argv[1])+"/blocking-witness.bin";
  int fd=open(path.c_str(),O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(fd>=0);
  std::vector<uint8_t> fixture(2*(MOT_BLOCK+64),42);assert(Motivation::transfer(fd,fixture.data(),fixture.size(),0,true));close(fd);
  for(unsigned mode:{MOT_SYNC,MOT_ASYNC}) {
    std::vector<uint64_t> memory((MOT_UTM_BYTES+7)/8);GateEngine* gate=new GateEngine();
    mot_config cfg={MOT_MAGIC,2*MOT_BLOCK,123,mode,1000000000,0,2,MOT_CIPHER_GCM,0,0};
    Motivation::Backend backend(reinterpret_cast<uint8_t*>(memory.data()),MOT_UTM_BYTES,path.c_str(),cfg,"hot",false,
        false,{},std::unique_ptr<Motivation::ReadEngine>(gate));
    mot_call c={};mot_reply r={};assert(!backend.handle(c,r));c.op=MOT_WARM;assert(!backend.handle(c,r));
    c.op=MOT_START;assert(!backend.handle(c,r));c.op=MOT_SUBMIT;c.bytes=MOT_BLOCK+64;c.generation=1;
    std::atomic<bool> returned{false};int rc=-1;
    std::thread handler([&]{rc=backend.handle(c,r);returned=true;});
    gate->wait_at_completion();
    mot_call premature={};premature.op=MOT_RELEASE_SUBMIT;premature.generation=1;
    premature.next_block=1;premature.next_generation=2;premature.next_bytes=MOT_BLOCK+64;
    mot_reply rejected={};assert(backend.handle(premature,rejected));
    assert(backend.read_ocalls==1 && !backend.release_submit_ocalls);
    if(mode==MOT_SYNC) assert(!returned.load());
    else {handler.join();assert(returned.load() && !rc);}
    gate->release();if(handler.joinable())handler.join();assert(!rc);
    c={};c.op=MOT_WAIT_ANY;assert(!backend.handle(c,r));
    auto* completion=reinterpret_cast<mot_completion*>(reinterpret_cast<uint8_t*>(memory.data())+mot_meta(0));
    assert(completion->ready==1 && !completion->error);
    mot_call recycle={};recycle.op=MOT_RELEASE_SUBMIT;recycle.generation=1;
    recycle.submit_return=Motivation::ticks();recycle.compute_begin=Motivation::ticks();recycle.compute_end=Motivation::ticks();
    recycle.next_block=1;recycle.next_generation=2;recycle.next_bytes=MOT_BLOCK+64;
    // Malformed old/new identities must not retire a valid old buffer or issue I/O.
    for(unsigned bad=0;bad<6;++bad) {
      mot_call invalid=recycle;
      if(bad==0) invalid.generation=2;
      if(bad==1) invalid.block=1;
      if(bad==2) invalid.next_block=2;
      if(bad==3) invalid.next_generation=3;
      if(bad==4) invalid.next_bytes--;
      if(bad==5) invalid.slot=1;
      assert(backend.handle(invalid,r) && completion->ready==1 && completion->generation==1);
      assert(backend.read_ocalls==1 && !backend.release_submit_ocalls && backend.completed_reads()==1);
    }
    gate->reset();returned=false;rc=-1;
    std::thread combined([&]{rc=backend.handle(recycle,r);returned=true;});
    gate->wait_at_completion();
    assert(completion->ready==0);
    if(mode==MOT_SYNC) assert(!returned.load());
    else {combined.join();assert(returned.load() && !rc);}
    gate->release();if(combined.joinable())combined.join();assert(!rc);
    c={};c.op=MOT_WAIT_ANY;assert(!backend.handle(c,r));
    assert(completion->ready==1 && completion->generation==2 && completion->block==1);
    assert(backend.read_ocalls==2 && backend.release_submit_ocalls==1);
    // No future record exists: reject a combined request without freeing the tail.
    recycle.block=1;recycle.generation=2;recycle.next_block=2;recycle.next_generation=3;
    recycle.submit_return=Motivation::ticks();recycle.compute_begin=Motivation::ticks();recycle.compute_end=Motivation::ticks();
    assert(backend.handle(recycle,r) && completion->generation==2);
    recycle.op=MOT_RELEASE;recycle.next_block=recycle.next_generation=recycle.next_bytes=0;
    assert(!backend.handle(recycle,r) && backend.release_only_ocalls==1);
    assert(backend.handle(recycle,r)); // double release
    backend.shutdown();
  }
  {
    std::vector<uint64_t> memory((MOT_UTM_BYTES+7)/8);GateEngine* gate=new GateEngine();
    mot_config cfg={MOT_MAGIC,2*MOT_BLOCK,123,MOT_ASYNC,1000000000,0,2,MOT_CIPHER_GCM,0,0};
    auto counts=std::make_shared<Motivation::Counters>();
    Motivation::Backend backend(reinterpret_cast<uint8_t*>(memory.data()),MOT_UTM_BYTES,path.c_str(),cfg,"hot",false,
        false,counts,std::unique_ptr<Motivation::ReadEngine>(gate));
    mot_call c={};mot_reply r={};assert(!backend.handle(c,r));c.op=MOT_WARM;assert(!backend.handle(c,r));
    c.op=MOT_START;assert(!backend.handle(c,r));c.op=MOT_SUBMIT;c.bytes=MOT_BLOCK+64;c.generation=1;
    assert(!backend.handle(c,r));gate->wait_at_completion();gate->release();c.op=MOT_WAIT_ANY;assert(!backend.handle(c,r));
    c={};c.op=MOT_RELEASE_SUBMIT;c.generation=1;c.next_block=1;c.next_generation=2;c.next_bytes=MOT_BLOCK+64;
    c.submit_return=Motivation::ticks();c.compute_begin=Motivation::ticks();c.compute_end=Motivation::ticks();
    gate->refuse_next();assert(backend.handle(c,r));
    assert(!backend.finished && backend.read_ocalls==1 && !backend.release_submit_ocalls &&
        backend.data_operations==1 && !counts->outstanding.load() && !counts->active.load());
    assert(backend.handle(c,r)); // the retired old identity cannot be reused after submission failure
    c={};c.op=MOT_DONE;c.blocks=2;c.processed=2*MOT_BLOCK;c.elapsed_ticks=1;assert(backend.handle(c,r));
    backend.shutdown();
  }
  assert(!unlink(path.c_str()));
  std::cout<<"standalone and recycle+submit: Sync blocks until new publication, Async returns early; premature/invalid/tail rejected; submit failure drains without success PASS\n";
}
