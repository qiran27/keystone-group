#ifndef GROUP_PMP_SECURITY_HOST_HOOKS_HPP
#define GROUP_PMP_SECURITY_HOST_HOOKS_HPP
#include "security-sentinel.h"
#include "security-checkpoint-clock.hpp"
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#ifdef __linux__
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "kernel/evidence-uapi.h"
#endif
inline uint64_t security_scan_nonce() {
  const char* text = std::getenv("GROUP_PMP_SECURITY_NONCE");
  if (!text) return 0;
  char* end = nullptr;
  errno = 0;
  const unsigned long long value = std::strtoull(text, &end, 10);
  if (*text < '0' || *text > '9' || !end || *end || !value || errno == ERANGE)
    throw std::runtime_error("invalid security nonce");
  return value;
}
inline std::mutex& security_manifest_mutex() { static std::mutex m; return m; }
inline std::map<uintptr_t, std::pair<std::string, size_t>>& security_live_regions() {
  static std::map<uintptr_t, std::pair<std::string, size_t>> regions;
  return regions;
}
inline void security_region(const char* action, const char* label,
                            const void* pointer, size_t length) {
  const char* path = std::getenv("GROUP_PMP_SECURITY_REGIONS");
  if (!path) return;
  std::lock_guard<std::mutex> lock(security_manifest_mutex());
  std::ofstream file(path, std::ios::app);
  file << action << ' ' << label << ' ' << (uintptr_t)pointer << ' '
       << length << '\n';
  file.flush();
  if (!file) throw std::runtime_error("cannot record security region");
  if (!std::strcmp(action, "add")) security_live_regions()[(uintptr_t)pointer] = {label, length};
  else if (!std::strcmp(action, "remove")) security_live_regions().erase((uintptr_t)pointer);
}
/* Allocation/lifetime evidence supplements, but does not restrict, whole-process
 * capture. Owner destruction removes a range before freeing it. */
class SecurityCipherRegion {
 public:
  SecurityCipherRegion(const void* data, size_t size) : data_(data), size_(size) {
    security_region("add", "host-ciphertext-buffer", data_, size_);
  }
  ~SecurityCipherRegion() {
    try { security_region("remove", "host-ciphertext-buffer", data_, size_); }
    catch (...) {
      std::fprintf(stderr, "[security-scan] cannot remove ciphertext buffer range\n");
      std::abort();
    }
  }
  SecurityCipherRegion(const SecurityCipherRegion&) = delete;
  SecurityCipherRegion& operator=(const SecurityCipherRegion&) = delete;
 private:
  const void* data_;
  size_t size_;
};
#ifdef __linux__
class SecurityRegionalControls {
  std::unique_ptr<uint8_t[]> temporary_;
  void *anonymous_ = MAP_FAILED, *shared_ = MAP_FAILED;
 public:
  SecurityRegionalControls(const char* directory, uint8_t* stack) : temporary_(new uint8_t[4096]()) {
    uint8_t marker[64]; group_pmp_security_sentinel(security_scan_nonce(), marker);
    std::ofstream injected(std::string(directory) + "/positive-injected.csv");
    injected << "region,address,length,marker_offset\n";
    auto plant = [&](const char* kind, void* p, size_t n, size_t off) {
      if (n < off + sizeof(marker)) throw std::runtime_error("positive range too short");
      std::memcpy(static_cast<uint8_t*>(p) + off, marker, sizeof(marker));
      injected << kind << ',' << uintptr_t(p) << ',' << n << ',' << off << '\n';
    };
    plant("host-temp", temporary_.get(), 4096, 128);
    plant("host-stack", stack, 4096, 128);
    anonymous_ = mmap(nullptr, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    shared_ = mmap(nullptr, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (anonymous_ == MAP_FAILED || shared_ == MAP_FAILED) throw std::runtime_error("positive mapping failed");
    plant("host-unregistered", anonymous_, 4096, 128);
    plant("host-shared", shared_, 4096, 128);
    {
      std::lock_guard<std::mutex> lock(security_manifest_mutex());
      for (const auto& r : security_live_regions())
        if (r.second.first == "control-utm" || r.second.first == "data-utm")
          plant(r.second.first.c_str(), reinterpret_cast<void*>(r.first), r.second.second,
              r.second.first == "control-utm" ? GROUP_PMP_SECURITY_PROBE_OFFSET : 128);
    }
    int fd = open("/dev/keystone-evidence", O_RDWR|O_CLOEXEC);
    ke_page page = {};page.reserved=1;std::memcpy(page.data,marker,sizeof(marker));
    int rc = fd < 0 ? -1 : ioctl(fd,KE_CONTROL,&page);
    if(fd>=0)close(fd);
    if(rc)throw std::runtime_error("kernel positive injection failed");
    injected << "kernel-control," << page.pfn << ",4096,128\n";
    injected.flush();
    if(!injected)throw std::runtime_error("cannot record positive injections");
    std::memset(marker,0,sizeof(marker));
  }
  ~SecurityRegionalControls() {
    std::memset(temporary_.get(),0,4096);
    if(anonymous_!=MAP_FAILED){std::memset(anonymous_,0,4096);munmap(anonymous_,4096);}
    if(shared_!=MAP_FAILED){std::memset(shared_,0,4096);munmap(shared_,4096);}
    std::lock_guard<std::mutex> lock(security_manifest_mutex());
    for(const auto& r:security_live_regions())
      if(r.second.first=="control-utm" || r.second.first=="data-utm")
        std::memset(reinterpret_cast<uint8_t*>(r.first)+
            (r.second.first=="control-utm"?GROUP_PMP_SECURITY_PROBE_OFFSET:128),0,64);
    // UTM is destroyed immediately after the positive checkpoint. No negative
    // run shares this process or its allocations; observer reset clears control.
  }
};
#endif
inline void security_scan_checkpoint(const char* phase = "completed-before-destroy") {
  const char* path = std::getenv("GROUP_PMP_SECURITY_REGIONS");
  if (!path) return;
  static std::mutex checkpoint_mutex;
  std::lock_guard<std::mutex> checkpoint_lock(checkpoint_mutex);
  static uint64_t sequence = 0;
  const uint64_t current = ++sequence;
  const char* capture = std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR");
  struct CheckpointWait {
    bool enabled;
    uint64_t id;
    const char* phase;
    std::chrono::steady_clock::time_point start;
    bool acknowledged = false;
    CheckpointWait(bool on, uint64_t value, const char* name)
        : enabled(on), id(value), phase(name), start(std::chrono::steady_clock::now()) {
      if (enabled) {
        security_checkpoint_clock().begin(start);
        std::fprintf(stderr, "[security-checkpoint] id=%llu phase=%s state=begin\n",
                     (unsigned long long)id, phase);
      }
    }
    ~CheckpointWait() {
      if (!enabled) return;
      const auto now = std::chrono::steady_clock::now();
      security_checkpoint_clock().end(now);
      std::fprintf(stderr, "[security-checkpoint] id=%llu phase=%s state=%s wait_ms=%lld\n",
                   (unsigned long long)id, phase, acknowledged ? "acknowledged" : "failed",
                   (long long)std::chrono::duration_cast<std::chrono::milliseconds>(now-start).count());
    }
  } wait(capture != nullptr, current, phase);
#ifdef __linux__
  uint8_t positive_stack[4096] = {};
  std::unique_ptr<SecurityRegionalControls> positive;
  if (capture && std::getenv("GROUP_PMP_SECURITY_CAPTURE_POSITIVE") &&
      !std::strcmp(phase, "quiesced-before-destroy"))
    positive.reset(new SecurityRegionalControls(capture, positive_stack));
#endif
  if (capture) {
    /* Registered PFN UTM mappings may be unreadable via /proc/pid/mem.
     * The owning Host can read its live mapping. Keep allocation lifetime
     * synchronized, dump bytes without holding any search marker. */
    std::lock_guard<std::mutex> lock(security_manifest_mutex());
    const std::string prefix = std::string(capture) + "/self-" + std::to_string(current);
    std::ofstream records(std::string(capture) + "/self.csv", std::ios::app);
    std::ofstream dump(prefix + ".bin", std::ios::binary);
    uint64_t offset = 0;
    for (const auto& r : security_live_regions()) {
      dump.write(reinterpret_cast<const char*>(r.first), r.second.second);
      records << current << ',' << phase << ',' << r.second.first << ',' << r.first
              << ',' << r.second.second << ',' << offset << ",self-" << current << ".bin,"
              << std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() << '\n';
      offset += r.second.second;
    }
    dump.flush(); records.flush();
    if (!dump || !records) throw std::runtime_error("cannot capture live Host mappings");
  }
  {
    std::ofstream ready(std::string(path) + ".ready");
    ready << current << ' ' << phase << '\n';
    ready.flush();
    if (!ready) throw std::runtime_error("cannot request security scan");
  }
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
  while (std::chrono::steady_clock::now() < deadline) {
    uint64_t ack = 0;
    std::ifstream file(std::string(path) + ".ack");
    if (file >> ack && ack == current) { wait.acknowledged = true; return; }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  throw std::runtime_error("security scanner did not acknowledge checkpoint");
}
inline void security_positive_control() {
#ifdef __linux__
  // Extended negative runs must not construct the marker in the Host.
  if (std::getenv("GROUP_PMP_SECURITY_CAPTURE_DIR")) return;
  if (!security_scan_nonce()) return;
  void* page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) throw std::runtime_error("positive control mmap failed");
  group_pmp_security_sentinel(security_scan_nonce(), static_cast<uint8_t*>(page));
  security_region("add", "positive-control", page, 4096);
  // Intentional control stays live until exit and is scanned separately.
#else
  if (security_scan_nonce()) throw std::runtime_error("scanner requires Linux");
#endif
}
#endif
