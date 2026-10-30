#include "../security/security-checkpoint-clock.hpp"
#include <cassert>
#include <chrono>
#include <iostream>

int main() {
  using Seconds = std::chrono::seconds;
  const SecurityCheckpointClock::Time origin{};
  SecurityCheckpointClock clock;
  assert(clock.workload_now(origin + Seconds(10)) == origin + Seconds(10));
  clock.begin(origin + Seconds(10));
  // A 90-second collector wait is not a 60-second workload stall.
  assert(clock.workload_now(origin + Seconds(100)) == origin + Seconds(10));
  clock.end(origin + Seconds(100));
  assert(clock.workload_now(origin + Seconds(105)) == origin + Seconds(15));
  clock.begin(origin + Seconds(105));
  clock.end(origin + Seconds(125));
  assert(clock.workload_now(origin + Seconds(130)) == origin + Seconds(20));
  // After ACK, a real 60-second stall still reaches the watchdog threshold.
  assert(clock.workload_now(origin + Seconds(185)) == origin + Seconds(75));
  clock.end(origin + Seconds(190));
  assert(clock.workload_now(origin + Seconds(190)) == origin + Seconds(80));
  std::cout << "Checkpoint clock: pauses excluded, genuine stalls retained\n";
}
