#ifndef GROUP_WARMUP_WATCHDOG_HPP
#define GROUP_WARMUP_WATCHDOG_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <mutex>
#include <sstream>
#include <thread>

// Diagnostic only: no ioctl, UTM access or service locks on the observer thread.
struct GroupWarmupDiagnostics {
  enum { MAIN = 0, RESUME = 1, WRITER = 2, READER0 = 3, CHANNELS = 6 };
  struct Stage {
    std::atomic<const char*> name;
    std::atomic<uint64_t> eid, request, since_ms, updates;
    Stage() : name("idle"), eid(0), request(0), since_ms(0), updates(0) {}
  };
  std::atomic<bool> enabled;
  Stage stages[CHANNELS];
  GroupWarmupDiagnostics() : enabled(false) {}
  static uint64_t nowMs() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
  }
  void mark(unsigned channel, const char* name, uint64_t eid = 0,
            uint64_t request = 0) {
    if (!enabled.load(std::memory_order_relaxed))
      return;
    Stage& s = stages[channel];
    s.eid.store(eid, std::memory_order_relaxed);
    s.request.store(request, std::memory_order_relaxed);
    s.since_ms.store(nowMs(), std::memory_order_relaxed);
    s.name.store(name, std::memory_order_release);
    s.updates.fetch_add(1, std::memory_order_relaxed);
  }
};

class GroupWarmupWatchdog {
 public:
  GroupWarmupWatchdog(GroupWarmupDiagnostics& d, uint64_t group, uint64_t workers)
      : diagnostics_(d), stopping_(false) {
    for (auto& stage : d.stages) {
      stage.name.store("idle");
      stage.updates.store(0);
    }
    d.enabled.store(true, std::memory_order_release);
    thread_ = std::thread([this, group, workers] {
      const char* labels[] = {"main", "resume", "writer", "reader0", "reader1", "reader2"};
      std::unique_lock<std::mutex> lock(mutex_);
      while (!condition_.wait_for(lock, std::chrono::seconds(10),
                                   [this] { return stopping_; })) {
        std::ostringstream line;
        line << "[P10][warmup-watch] group=" << group << " workers=" << workers;
        const uint64_t now = GroupWarmupDiagnostics::nowMs();
        for (unsigned i = 0; i < GroupWarmupDiagnostics::CHANNELS; ++i) {
          const auto& stage = diagnostics_.stages[i];
          const char* name = stage.name.load(std::memory_order_acquire);
          const uint64_t since = stage.since_ms.load(std::memory_order_relaxed);
          line << " " << labels[i] << "=" << name
               << "/age_ms=" << (since && now >= since ? now - since : 0)
               << "/id=" << stage.eid.load(std::memory_order_relaxed)
               << "/request=" << stage.request.load(std::memory_order_relaxed)
               << "/steps=" << stage.updates.load(std::memory_order_relaxed);
        }
        std::fprintf(stderr, "%s\n", line.str().c_str());
      }
    });
  }
  ~GroupWarmupWatchdog() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
    }
    condition_.notify_all();
    thread_.join();
    diagnostics_.enabled.store(false, std::memory_order_release);
  }
  GroupWarmupWatchdog(const GroupWarmupWatchdog&) = delete;
  GroupWarmupWatchdog& operator=(const GroupWarmupWatchdog&) = delete;
 private:
  GroupWarmupDiagnostics& diagnostics_;
  std::mutex mutex_;
  std::condition_variable condition_;
  bool stopping_;
  std::thread thread_;
};

#endif
