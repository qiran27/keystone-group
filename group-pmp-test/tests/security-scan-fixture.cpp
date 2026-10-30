#include "../security/security-host-hooks.hpp"
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <unistd.h>
int main(int argc, char** argv) {
  if (argc != 3) return 2;
  if (strcmp(argv[2], "no-control")) security_positive_control();
  if (!strcmp(argv[2], "compact-runtime")) {
    void* guard=mmap(nullptr,1048576,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(guard==MAP_FAILED)return 2;
    memset(guard,0x55,4096);
    if(mprotect(guard,1048576,PROT_NONE))return 2;
  }
  uint8_t* page = static_cast<uint8_t*>(mmap(nullptr, 131072, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (page == MAP_FAILED) return 2;
  memset(page, 0xa7, 131072);
  security_region("add", "control-utm", page, 4096);
  security_region("add", "data-utm", page + 4096, 131072 - 4096);
  int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0 || write(fd, page, 131072) != 131072) return 2;
  close(fd);
  const bool host = !strncmp(argv[2], "host-", 5);
  uint8_t* host_page = nullptr;
  std::unique_ptr<SecurityCipherRegion> host_region;
  if (host) {
    host_page = static_cast<uint8_t*>(mmap(nullptr, 8192, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (host_page == MAP_FAILED) return 2;
    memset(host_page, 0x71, 8192);
    host_region.reset(new SecurityCipherRegion(host_page, 8192));
    if (!strcmp(argv[2], "host-leak"))
      group_pmp_security_sentinel(security_scan_nonce(), host_page + 4064);
    if (!strcmp(argv[2], "host-removed")) {
      host_region.reset();
      munmap(host_page, 8192);
      host_page = nullptr;
    }
  }
  /* /proc/pid/mem can bypass PROT_NONE on ordinary private pages. A retained
   * manifest entry for an unmapped page models actual missing coverage. */
  if (!strcmp(argv[2], "unreadable-control") && munmap(page, 4096)) return 2;
  if (!strcmp(argv[2], "leak"))
    group_pmp_security_sentinel(security_scan_nonce(), page + 4096 + 65504);
  if (!strcmp(argv[2], "file-leak")) {
    uint8_t marker[GROUP_PMP_SECURITY_SENTINEL_BYTES];
    group_pmp_security_sentinel(security_scan_nonce(), marker);
    fd = open(argv[1], O_WRONLY);
    if (fd < 0 || pwrite(fd, marker, sizeof(marker), 65504) != sizeof(marker)) return 2;
    close(fd);
  }
  // This leak is deliberately outside the declared scope: PASS here must not
  // be interpreted as absence of plaintext in all ordinary-world memory.
  if (!strcmp(argv[2], "unregistered-leak")) {
    void* unregistered = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (unregistered == MAP_FAILED) return 2;
    group_pmp_security_sentinel(security_scan_nonce(), static_cast<uint8_t*>(unregistered));
  }
  if (!strcmp(argv[2], "compact-runtime")) security_scan_checkpoint("worker-milestone-1");
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  if (strcmp(argv[2], "no-checkpoint")) security_scan_checkpoint();
  if (host_page) {
    host_region.reset();
    munmap(host_page, 8192);
  }
  security_region("remove", "control-utm", page, 4096);
  security_region("remove", "data-utm", page + 4096, 131072 - 4096);
  munmap(page, 131072);
  if (!strcmp(argv[2], "final-cleanup") || !strcmp(argv[2], "compact-runtime")) {
    security_scan_checkpoint("after-cleanup");
    // Remain alive past the periodic interval to catch an unwanted late scan.
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
  }
  return 0;
}
