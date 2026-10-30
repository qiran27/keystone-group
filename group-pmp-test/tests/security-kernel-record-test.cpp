#include <cassert>
#include <cstdarg>
#define main capture_program_main
#include "../security/security-capture.cpp"
#undef main

static int sample_status;
static unsigned sample_length;
static unsigned long last_request;
extern "C" int __wrap_ioctl(int, unsigned long request, ...) {
  last_request = request;
  va_list args;
  va_start(args, request);
  ke_page* page = va_arg(args, ke_page*);
  va_end(args);
  page->status = sample_status;
  page->length = sample_length;
  if (sample_status) { errno = -sample_status; return -1; }
  memset(page->data, 0x5a, sizeof(page->data));
  return 0;
}

int main(int argc, char** argv) {
  assert(argc == 2);
  {
    Collector c(argv[1], argv[1], getpid());
    if (c.kernel >= 0) close(c.kernel);
    c.kernel = dup(STDERR_FILENO);
    assert(c.kernel >= 0);
    const uint64_t before = c.errors;
    ke_page page = {};
    sample_status = -ENOENT; sample_length = 0;
    c.kernel_record("test", "kernel-page-cache", "absent", page, KE_FILE_PAGE);
    assert(last_request == KE_FILE_PAGE && c.errors == before);
    sample_status = -EBUSY;
    c.kernel_record("test", "kernel-page-cache", "busy", page, KE_FILE_PAGE);
    assert(c.errors == before + 1);
    sample_status = 0; sample_length = 128;
    c.kernel_record("test", "kernel-page-cache", "short", page, KE_FILE_PAGE);
    assert(c.errors == before + 2);
    sample_length = 4096;
    c.kernel_record("test", "kernel-page-cache", "read", page, KE_FILE_PAGE);
    assert(c.errors == before + 2 && c.read_bytes == 4224);
    sample_status = -ENOENT; sample_length = 0;
    c.kernel_record("test", "kernel-io-uring", "ring-error", page, KE_RING_PAGE);
    assert(last_request == KE_RING_PAGE && c.errors == before + 3);
  }
  std::ifstream reads(std::string(argv[1]) + "/reads.csv");
  const std::string text((std::istreambuf_iterator<char>(reads)), {});
  assert(text.find("not-applicable,cache-entry-absent") != std::string::npos);
  assert(text.find("unreadable,\"kernel-status--16\"") != std::string::npos);
  assert(text.find("unreadable,\"short-read\"") != std::string::npos);
  assert(text.find("unreadable,\"kernel-status--2\"") != std::string::npos);
  puts("kernel ledger: absent cache entries distinguished; busy, short and ring failures retained PASS");
}
