#ifndef GROUP_PMP_SECURITY_CHECKPOINT_CLOCK_HPP
#define GROUP_PMP_SECURITY_CHECKPOINT_CLOCK_HPP
#include <chrono>
#include <mutex>

// Only explicit collector waits pause the workload watchdog. Wall deadlines
// and the collector's own ACK timeout remain independent and bounded.
class SecurityCheckpointClock {
 public:
  using Clock = std::chrono::steady_clock;
  using Time = Clock::time_point;
  void begin(Time now = Clock::now()) {
    std::lock_guard<std::mutex> lock(mutex_);
    started_ = now;
    active_ = true;
  }
  void end(Time now = Clock::now()) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_) paused_ += now - started_;
    active_ = false;
  }
  Time workload_now(Time now = Clock::now()) {
    std::lock_guard<std::mutex> lock(mutex_);
    return now - paused_ - (active_ ? now - started_ : Clock::duration::zero());
  }
 private:
  std::mutex mutex_;
  Time started_{};
  Clock::duration paused_{};
  bool active_ = false;
};
inline SecurityCheckpointClock& security_checkpoint_clock() {
  static SecurityCheckpointClock clock;
  return clock;
}
#endif
