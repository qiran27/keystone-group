#include "security-sentinel.h"
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

struct Region { std::string kind; uint64_t start, size; };
struct ScanTotals {
  uint64_t negative_hits = 0, positive_hits = 0, strict_errors = 0;
  uint64_t control_bytes = 0, data_bytes = 0, file_bytes = 0;
  uint64_t snapshots = 0, checkpoints = 0;
  uint64_t during_utm_bytes = 0;
  uint64_t host_buffer_bytes = 0;
  uint64_t scan_start_ns = 0;
};
static volatile sig_atomic_t interrupted = 0;
static void interrupt_scan(int) { interrupted = 1; }

static std::string quote(const std::string& s) {
  std::string out = "\"";
  for (char c : s) { if (c == '"') out += '"'; out += c; }
  return out + '"';
}

/* Retain the last 63 bytes across chunks, so markers spanning a page or
 * scan chunk boundary are not missed. Report offsets, never plaintext. */
static uint64_t scan_range(int fd, uint64_t start, uint64_t size,
                           const uint8_t* marker, uint64_t* bytes,
                           uint64_t* errors) {
  std::vector<uint8_t> chunk(65536 + GROUP_PMP_SECURITY_SENTINEL_BYTES);
  size_t carry = 0;
  uint64_t hits = 0;
  for (uint64_t offset = 0; offset < size;) {
    const size_t want = static_cast<size_t>(std::min<uint64_t>(65536, size - offset));
    ssize_t n = pread(fd, chunk.data() + carry, want,
                      static_cast<off_t>(start + offset));
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      ++*errors;
      offset += std::min<uint64_t>(4096, size - offset);
      carry = 0;
      continue;
    }
    *bytes += static_cast<uint64_t>(n);
    const size_t available = carry + static_cast<size_t>(n);
    for (size_t i = 0; i + GROUP_PMP_SECURITY_SENTINEL_BYTES <= available; ++i)
      if (!memcmp(chunk.data() + i, marker, GROUP_PMP_SECURITY_SENTINEL_BYTES)) ++hits;
    carry = std::min<size_t>(GROUP_PMP_SECURITY_SENTINEL_BYTES - 1, available);
    memmove(chunk.data(), chunk.data() + available - carry, carry);
    offset += static_cast<uint64_t>(n);
  }
  return hits;
}

static std::vector<Region> regions(const std::string& path) {
  std::ifstream file(path);
  std::map<uint64_t, Region> current;
  std::string action, kind;
  uint64_t start, size;
  while (file >> action >> kind >> start >> size) {
    if (!size || start > UINT64_MAX - size) throw std::runtime_error("invalid region");
    if (kind != "positive-control" && kind != "control-utm" &&
        kind != "data-utm" && kind != "host-ciphertext-buffer")
      throw std::runtime_error("region outside registered ciphertext scan scope");
    if (action == "add") current[start] = {kind, start, size};
    else if (action == "remove") current.erase(start);
    else throw std::runtime_error("invalid region action");
  }
  std::vector<Region> out;
  for (const auto& pair : current) out.push_back(pair.second);
  return out;
}

static void inspect(int fd, const Region& r, const uint8_t* marker,
                    const std::string& phase, const std::string& path,
                    bool strict, std::ofstream& evidence, ScanTotals& total) {
  uint64_t bytes = 0, errors = 0;
  const uint64_t hits = scan_range(fd, r.start, r.size, marker, &bytes, &errors);
  evidence << total.snapshots << ',' << phase << ',' << total.scan_start_ns << ',' << r.kind << ',' << r.start
           << ',' << r.size << ',' << bytes << ',' << hits << ',' << errors
           << ',' << quote(path) << '\n';
  if (r.kind == "positive-control") total.positive_hits += hits;
  else total.negative_hits += hits;
  if (strict) total.strict_errors += errors;
  if (r.kind == "control-utm") total.control_bytes += bytes;
  if (r.kind == "data-utm") total.data_bytes += bytes;
  if (phase == "during" && (r.kind == "control-utm" || r.kind == "data-utm"))
    total.during_utm_bytes += bytes;
  if (r.kind == "ciphertext-file") total.file_bytes += bytes;
  if (r.kind == "host-ciphertext-buffer") total.host_buffer_bytes += bytes;
}

static void snapshot(pid_t pid, const std::string& manifest,
                     const std::string& storage, const uint8_t* marker,
                     bool checkpoint, std::ofstream& evidence, ScanTotals& total) {
  ++total.snapshots;
  total.scan_start_ns = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count());
  if (checkpoint) ++total.checkpoints;
  const std::string phase = checkpoint ? "completed-before-destroy" : "during";
  const auto registered = regions(manifest);
  const std::string proc = "/proc/" + std::to_string(pid);
  int mem = open((proc + "/mem").c_str(), O_RDONLY | O_CLOEXEC);
  if (mem < 0) { if (checkpoint) ++total.strict_errors; return; }
  // This deliberately bounded test does not claim whole-process coverage.
  for (const Region& r : registered)
    inspect(mem, r, marker, phase, proc + "/mem", checkpoint, evidence, total);
  close(mem);
  DIR* directory = opendir(storage.c_str());
  if (!directory) { if (checkpoint) ++total.strict_errors; return; }
  while (dirent* entry = readdir(directory)) {
    const std::string name = entry->d_name;
    if (name == "." || name == "..") continue;
    // Storage directory is dedicated to this run, not the evidence directory.
    const std::string path = storage + "/" + name;
    struct stat info;
    if (lstat(path.c_str(), &info) != 0) { if (checkpoint) ++total.strict_errors; continue; }
    if (!S_ISREG(info.st_mode)) continue;
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { if (checkpoint) ++total.strict_errors; continue; }
    inspect(fd, {"ciphertext-file", 0, static_cast<uint64_t>(info.st_size)},
            marker, phase, path, checkpoint, evidence, total);
    close(fd);
  }
  closedir(directory);
  evidence.flush();
}

int main(int argc, char** argv) {
  if (argc == 2 && !strcmp(argv[1], "--security-scan-info")) {
    puts("security_scanner_fixture_version=4 scope=registered-ciphertext-only kernel_ring_snapshots=0");
    return 0;
  }
  // Parent scanner owns the marker; the executed Host receives only the nonce.
  if (argc < 7 || strcmp(argv[5], "--")) {
    fprintf(stderr, "usage: %s nonce storage-dir evidence.csv regions.log -- program [args...]\n", argv[0]);
    return 2;
  }
  char* end = nullptr;
  errno = 0;
  const uint64_t nonce = strtoull(argv[1], &end, 10);
  if (argv[1][0] < '0' || argv[1][0] > '9' || !nonce || !end || *end || errno == ERANGE) return 2;
  uint8_t marker[GROUP_PMP_SECURITY_SENTINEL_BYTES];
  group_pmp_security_sentinel(nonce, marker);
  std::ofstream evidence(argv[3]);
  std::ofstream clear(argv[4]); clear.close();
  unlink((std::string(argv[4]) + ".ready").c_str());
  unlink((std::string(argv[4]) + ".ack").c_str());
  if (!evidence) return 2;
  evidence << "snapshot,phase,scan_start_monotonic_ns,region,address,length,bytes_scanned,hits,read_errors,evidence\n";
  // Fork before scanning buffers are allocated. exec removes the inherited
  // scanner marker from the target address space before any snapshot.
  pid_t child = fork();
  if (child < 0) return 2;
  if (!child) {
    setenv("GROUP_PMP_SECURITY_NONCE", argv[1], 1);
    setenv("GROUP_PMP_SECURITY_REGIONS", argv[4], 1);
    execvp(argv[6], argv + 6);
    _exit(127);
  }
  signal(SIGINT, interrupt_scan);
  signal(SIGTERM, interrupt_scan);
  signal(SIGHUP, interrupt_scan);
  ScanTotals total;
  printf("[security-scan] scope=registered-ciphertext-only excluded=EPM,TSR,unregistered-process-memory,kernel-mappings\n");
  int status = 0;
  uint64_t acknowledged = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(5);
  try {
    for (;;) {
      pid_t state = waitpid(child, &status, WNOHANG);
      if (state == child) break;
      if (state < 0) {
        if (errno == EINTR) continue;
        throw std::runtime_error("cannot observe security workload");
      }
      if (interrupted) throw std::runtime_error("scan interrupted");
      if (std::chrono::steady_clock::now() > deadline)
        throw std::runtime_error("security workload timeout");
      uint64_t requested = 0;
      std::ifstream ready(std::string(argv[4]) + ".ready"); ready >> requested;
      if (!regions(argv[4]).empty()) {
        const bool checkpoint = requested > acknowledged;
        snapshot(child, argv[4], argv[2], marker, checkpoint, evidence, total);
        if (checkpoint) {
          acknowledged = requested;
          std::ofstream ack(std::string(argv[4]) + ".ack"); ack << acknowledged << '\n';
          ack.flush();
          if (!ack) throw std::runtime_error("cannot acknowledge scan");
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  } catch (const std::exception& error) {
    fprintf(stderr, "[security-scan] error=%s\n", error.what());
    kill(child, SIGTERM);
    bool reaped = false;
    for (unsigned i = 0; i < 100; ++i) {
      if (waitpid(child, &status, WNOHANG) == child) { reaped = true; break; }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!reaped) {
      kill(child, SIGKILL);
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    ++total.strict_errors;
  }
  const bool workload_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
  const bool coverage = total.positive_hits && total.control_bytes && total.data_bytes &&
                        total.file_bytes && total.during_utm_bytes && total.checkpoints &&
                        !total.strict_errors && evidence.good();
  const char* result = total.negative_hits ? "FAIL" :
                      (coverage && workload_ok ? "PASS_OBSERVED_SCOPE" : "INCOMPLETE");
  printf("[security-scan] result=%s snapshots=%llu checkpoints=%llu negative_hits=%llu positive_hits=%llu control_bytes=%llu data_bytes=%llu file_bytes=%llu strict_errors=%llu workload_ok=%d host_buffer_bytes=%llu\n",
      result, (unsigned long long)total.snapshots, (unsigned long long)total.checkpoints,
      (unsigned long long)total.negative_hits, (unsigned long long)total.positive_hits,
      (unsigned long long)total.control_bytes, (unsigned long long)total.data_bytes,
      (unsigned long long)total.file_bytes, (unsigned long long)total.strict_errors, workload_ok,
      (unsigned long long)total.host_buffer_bytes);
  return total.negative_hits ? 1 : (coverage && workload_ok ? 0 : 2);
}
