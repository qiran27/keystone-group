#ifndef MOTIVATION_READ_ENGINE_HPP
#define MOTIVATION_READ_ENGINE_HPP
#include <chrono>
#include <cstdint>
#include <functional>
#include <vector>
#include <sys/uio.h>
namespace Motivation {
inline uint64_t ticks() {
#if defined(__riscv)
  uint64_t v; __asm__ volatile("fence rw,rw\n\trdtime %0" : "=r"(v) :: "memory"); return v;
#else
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
#endif
}
class ReadEngine {
 public:
  using Callback = std::function<void(int,uint64_t,uint64_t)>;
  virtual ~ReadEngine() {}
  virtual bool configure(int fd,const std::vector<iovec>& buffers)=0;
  virtual bool submit(unsigned slot,uint64_t offset,size_t bytes,Callback done)=0;
  // Must drain/cancel and join before registered UTM storage can be destroyed.
  virtual void shutdown()=0;
  virtual uint64_t submit_calls() const=0;
  virtual uint64_t completed_reads() const=0;
};
}
#endif
