#include "../motivation/core.h"
#include "../motivation/backend.hpp"
#include "../motivation/uring-io.hpp"
#include "motivation-reference-engine.hpp"
#include <cassert>
#include <iostream>
#include <memory>
#include <cstdlib>
#include <sys/wait.h>
static std::vector<uint64_t> memory((MOT_UTM_BYTES+7)/8);
static Motivation::Backend* backend;
static bool started,released_second,force_second_first;
static int corrupt;
static uint64_t test_block=65536;
static uint64_t test_count(uint64_t bytes) {return (bytes+test_block-1)/test_block;}
static uint64_t test_cipher() {return std::getenv("MOT_TEST_ECB")?MOT_CIPHER_ECB:MOT_CIPHER_GCM;}
static std::vector<uint64_t> completion_order;
static std::unique_ptr<Motivation::ReadEngine> engine() {
  if(std::getenv("MOT_TEST_SHARED_URING")) return std::unique_ptr<Motivation::ReadEngine>(new Motivation::UringReadEngine());
  return std::unique_ptr<Motivation::ReadEngine>(new MotivationReferenceEngine());
}
static int call(const mot_call* c,mot_reply* r) {
  int rc=backend->handle(*c,*r);
  if (!rc && c->op==MOT_START) started=true;
  if (!rc && (c->op==MOT_RELEASE || c->op==MOT_RELEASE_SUBMIT)) {
    completion_order.push_back(c->block);
    if (c->block==1) released_second=true;
  }
  return rc;
}
static int capture(void* dst,size_t off,size_t n) {
  if (off>MOT_UTM_BYTES || n>MOT_UTM_BYTES-off) return -1;
  auto* base=reinterpret_cast<uint8_t*>(memory.data());
  if (off>=MOT_META_OFFSET && off<MOT_DATA_OFFSET) {
    auto* m=reinterpret_cast<mot_completion*>(base+off);
    if (!__atomic_load_n(&m->ready,__ATOMIC_ACQUIRE)) { std::memset(dst,0,n); return 0; }
    if (force_second_first && m->block==0 && !released_second) { std::memset(dst,0,n); return 0; }
  }
  std::memcpy(dst,base+off,n);
  if (started && corrupt==5 && off>=MOT_META_OFFSET && off<MOT_DATA_OFFSET)
    ++static_cast<mot_completion*>(dst)->generation;
  if (started && corrupt>0 && corrupt<5 && off>=MOT_DATA_OFFSET) {
    auto* b=static_cast<uint8_t*>(dst);
    const size_t positions[]={0,64,44,32,8}; // ciphertext, tag, nonce, authenticated identity
    b[positions[corrupt]]^=1;
  }
  return 0;
}
static int publish(size_t off,const void* src,size_t n) {
  if (off>MOT_UTM_BYTES || n>MOT_UTM_BYTES-off) return -1;
  std::memcpy(reinterpret_cast<uint8_t*>(memory.data())+off,src,n); return 0;
}
static const mot_api api={call,capture,publish,Motivation::ticks};
struct Result { int code; bool finished; mot_call value; uint64_t outstanding,operations; };
static Result run(const char* path,uint64_t bytes,unsigned mode,int damage=0,bool reorder=false,unsigned worker=0,unsigned workers=1) {
  started=false; released_second=false; force_second_first=reorder; corrupt=damage; completion_order.clear();
  mot_config cfg={MOT_MAGIC,bytes,UINT64_C(0xabcdef),mode,1000000000,0,0,test_cipher(),test_block,1};
  assert(!mot_partition(&cfg,worker,workers));
  Motivation::Backend b(reinterpret_cast<uint8_t*>(memory.data()),MOT_UTM_BYTES,path,cfg,"hot",true,false,{},engine());
  backend=&b;
  int rc=mot_run(&api);
  b.shutdown();
  if(!rc && mode!=MOT_PREPARE) {
    assert(b.completed_reads()==b.result.blocks && b.submit_calls()>0);
    assert(b.data_operations==b.completed_reads());
    assert(b.read_ocalls==b.result.blocks && b.release_only_ocalls==mot_initial_reads(&cfg));
    assert(b.release_submit_ocalls==b.result.blocks-mot_initial_reads(&cfg));
    assert(b.trace.size()==b.result.blocks);
    if (mode==MOT_SYNC) assert(!b.result.waits && !b.result.early_returns);
    for(const auto& t:b.trace)
      assert(t.admit<=t.begin && t.begin<=t.end && t.end<=t.publish &&
             t.publish<=t.compute_begin && t.compute_begin<=t.capture_end &&
             t.capture_end<=t.decrypt_end && t.decrypt_end<=t.compute_end && t.compute_end<=t.release);
    if (mode==MOT_SYNC) for(const auto& t:b.trace) assert(t.publish<=t.returned);
  }
  return {rc,b.finished,b.result,b.max_outstanding,b.data_operations};
}
int main(int argc,char** argv) {
  assert(argc==2);
  const std::string path=std::string(argv[1])+"/cipher-test.bin";
  if(std::getenv("MOT_TEST_SHARED_URING")) {
    std::string probe=std::string(argv[1])+"/uring-registration-probe.bin";
    int fd=open(probe.c_str(),O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600); assert(fd>=0);
    auto io=engine();
    bool available=io->configure(fd,{
        iovec{reinterpret_cast<uint8_t*>(memory.data())+mot_data(0),MOT_BLOCK+64},
        iovec{reinterpret_cast<uint8_t*>(memory.data())+mot_data(1),MOT_BLOCK+64}});
    io->shutdown(); io.reset(); close(fd); assert(!unlink(probe.c_str()));
    if(!available) { std::cout<<"SKIP shared io_uring: local kernel registration unavailable\n"; return 77; }
  }
  // This is a test-owned file inside the test runner's temporary directory.
  for (uint64_t block_size: {UINT64_C(4096),UINT64_C(16384),UINT64_C(65536)}) {
   test_block=block_size;
   for (uint64_t bytes: {UINT64_C(1),UINT64_C(65536),UINT64_C(131109),UINT64_C(1048579)}) {
    assert(access(path.c_str(),F_OK)!=0);
    auto p=run(path.c_str(),bytes,MOT_PREPARE); assert(p.code==0 && p.finished);
    auto s=run(path.c_str(),bytes,MOT_SYNC);
    auto a=run(path.c_str(),bytes,MOT_ASYNC);
    assert(!s.code && !a.code && s.finished && a.finished);
    assert(s.value.digest==a.value.digest && s.value.digest==p.value.digest);
    assert(s.value.processed==bytes && a.value.processed==bytes);
    assert(s.outstanding==1 && a.outstanding==std::min<uint64_t>(2,test_count(bytes)));
    assert(s.operations==test_count(bytes) && a.operations==test_count(bytes));
    if(bytes==MOT_BLOCK) {
      const bool was_ecb=test_cipher()==MOT_CIPHER_ECB;
      if(was_ecb) unsetenv("MOT_TEST_ECB");else setenv("MOT_TEST_ECB","1",1);
      auto wrong_cipher=run(path.c_str(),bytes,MOT_ASYNC);
      assert(wrong_cipher.code==17 && !wrong_cipher.finished);
      if(was_ecb) setenv("MOT_TEST_ECB","1",1);else unsetenv("MOT_TEST_ECB");
    }
    if(test_count(bytes)>=3) {
      // Separate processes preserve the real enclave-private C workspace.
      Result parts[3]; int pipes[3][2]; pid_t children[3];
      for(unsigned w=0;w<3;++w) {
        assert(pipe(pipes[w])==0); children[w]=fork(); assert(children[w]>=0);
        if(!children[w]) {
          close(pipes[w][0]); auto value=run(path.c_str(),bytes,MOT_ASYNC,0,false,w,3);
          assert(write(pipes[w][1],&value,sizeof(value))==sizeof(value));
          close(pipes[w][1]); _exit(0);
        }
        close(pipes[w][1]);
      }
      uint64_t total=0,digest=0,ops=0,blocks=0;
      for(unsigned w=0;w<3;++w) {
        assert(read(pipes[w][0],&parts[w],sizeof(Result))==sizeof(Result)); close(pipes[w][0]);
        int status; assert(waitpid(children[w],&status,0)==children[w] && WIFEXITED(status) && WEXITSTATUS(status)==0);
        assert(!parts[w].code && parts[w].finished);
        total+=parts[w].value.processed; digest^=parts[w].value.digest;
        ops+=parts[w].operations; blocks+=parts[w].value.blocks;
      }
      assert(total==bytes && digest==s.value.digest && ops==s.operations && blocks==test_count(bytes));
    }
    if (test_count(bytes)>1) {
      auto o=run(path.c_str(),bytes,MOT_ASYNC,0,true);
      assert(!o.code && completion_order.front()==1 && o.value.out_of_order>0);
    }
    for (int corrupt=1;corrupt<=5;++corrupt) {
      auto bad=run(path.c_str(),bytes,MOT_ASYNC,corrupt);
      assert(bad.code==(corrupt==5?22:25) && !bad.finished);
    }
    assert(unlink(path.c_str())==0);
   }
  }
  test_block=65536;
  mot_config bounds={MOT_MAGIC,500000000,1,MOT_ASYNC,1000000000,0,0,test_cipher(),4096,0};
  assert(mot_count(&bounds)==MOT_MAX_BLOCKS && !mot_partition(&bounds,2,3));
  bounds.block_bytes=8192;assert(!mot_valid_geometry(&bounds) && mot_partition(&bounds,0,1));
  // Reject stale generations, duplicate slot admission, wrong identity/release.
  assert(!run(path.c_str(),131109,MOT_PREPARE).code);
  {
    mot_config cfg={MOT_MAGIC,131109,0xabcdef,MOT_ASYNC,1000000000,0,3,test_cipher(),0,0};
    Motivation::Backend b(reinterpret_cast<uint8_t*>(memory.data()),MOT_UTM_BYTES,path.c_str(),cfg,"hot",false,false,{},engine());
    mot_call c={}; mot_reply r={}; assert(!b.handle(c,r));
    c.op=MOT_START; assert(b.handle(c,r));
    c.op=MOT_WARM; assert(!b.handle(c,r)); c.op=MOT_START; assert(!b.handle(c,r));
    c.op=MOT_SUBMIT; c.bytes=MOT_BLOCK+64; c.generation=0; assert(b.handle(c,r));
    c.generation=1; assert(!b.handle(c,r));
    c.block=1; c.generation=2; assert(b.handle(c,r));
    c.op=MOT_RELEASE; assert(b.handle(c,r));
    c.op=MOT_DONE; assert(b.handle(c,r));
    b.shutdown();
  }
  {
    mot_config cfg={MOT_MAGIC,131109,0xabcdef,MOT_ASYNC,1000000000,0,3,test_cipher(),0,0};
    auto counts=std::make_shared<Motivation::Counters>();
    Motivation::Backend b(reinterpret_cast<uint8_t*>(memory.data()),MOT_UTM_BYTES,path.c_str(),cfg,"hot",false,true,counts,engine());
    mot_call c={}; mot_reply r={}; assert(!b.handle(c,r));
    c.op=MOT_WARM; assert(!b.handle(c,r)); c.op=MOT_START; assert(!b.handle(c,r));
    c.op=MOT_SUBMIT; c.bytes=MOT_BLOCK+64; c.generation=1;
    assert(b.handle(c,r)); // no measured admission before shared release
    assert(b.prepare_group_cache() && b.enable_group_start());
    std::atomic<unsigned> notified{0};
    assert(b.wait_async([&]{++notified;},r)); // no outstanding read
    assert(!b.handle(c,r));
    assert(!b.wait_async([&]{++notified;},r));
    c={}; c.op=MOT_WAIT_ANY; assert(!b.handle(c,r));
    b.shutdown();
    assert(notified.load()==1 && counts->peak_outstanding.load()==1 && counts->peak_active.load()==1);
  }
  assert(unlink(path.c_str())==0);
  // Missing production engine must fail closed, not silently select pread.
  assert(!run(path.c_str(),131109,MOT_PREPARE).code);
  bool rejected=false;
  try {
    mot_config cfg={MOT_MAGIC,131109,0xabcdef,MOT_ASYNC,1000000000,0,3,test_cipher(),0,0};
    Motivation::Backend b(reinterpret_cast<uint8_t*>(memory.data()),MOT_UTM_BYTES,path.c_str(),cfg,"hot",false);
  } catch(const std::runtime_error&) { rejected=true; }
  assert(rejected); assert(!unlink(path.c_str()));
  // Short reads and shutdown must complete callbacks before buffers disappear.
  {
    int fd=open(path.c_str(),O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600); assert(fd>=0);
    uint8_t byte=42; assert(pwrite(fd,&byte,1,0)==1);
    auto io=engine();
    assert(io->configure(fd,{iovec{reinterpret_cast<uint8_t*>(memory.data())+mot_data(0),MOT_BLOCK+64},
                             iovec{reinterpret_cast<uint8_t*>(memory.data())+mot_data(1),MOT_BLOCK+64}}));
    std::atomic<unsigned> callbacks{0},errors{0};
    auto done=[&](int error,uint64_t begin,uint64_t end) {
      assert(begin && end>=begin); if(error) ++errors; ++callbacks;
    };
    assert(io->submit(0,0,MOT_BLOCK+64,done));
    assert(io->submit(1,MOT_BLOCK+64,MOT_BLOCK+64,done));
    assert(!io->submit(2,0,1,done));
    io->shutdown();
    assert(callbacks==2 && errors==2 && io->completed_reads()==2);
    assert(!io->submit(0,0,1,done));
    io.reset(); close(fd); assert(!unlink(path.c_str()));
  }
  std::cout<<"motivation backend="<<(std::getenv("MOT_TEST_SHARED_URING")?"shared-io-uring-fixed":"test-reference-only")
           <<" cipher="<<mot_cipher_name(test_cipher())
           <<": three private partitions match one Worker total/digest/IO; shared-start, callback wait, tails, expected-data/corruption checks, ownership, no fallback and failure drain PASS\n";
}
