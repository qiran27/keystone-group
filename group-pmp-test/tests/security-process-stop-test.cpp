#include <cassert>
#define main capture_program_main
#include "../security/security-capture.cpp"
#undef main

int main() {
  int commands[2], replies[2];
  assert(pipe(commands) == 0 && pipe(replies) == 0);
  auto* ticks = static_cast<uint64_t*>(mmap(nullptr,4096,PROT_READ|PROT_WRITE,
      MAP_SHARED|MAP_ANONYMOUS,-1,0));
  auto* pages = static_cast<unsigned char*>(mmap(nullptr,16384,PROT_READ|PROT_WRITE,
      MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
  assert(ticks != MAP_FAILED && pages != MAP_FAILED);
  *ticks = 0;
  memset(pages,0x71,16384);
  const pid_t child = fork();
  assert(child >= 0);
  if(!child) {
    close(commands[1]); close(replies[0]);
    bool done = false;
    std::thread other([&]() {
      while(!__atomic_load_n(&done,__ATOMIC_RELAXED)) {
        __atomic_fetch_add(ticks,1,__ATOMIC_RELAXED);
        std::this_thread::yield();
      }
    });
    char command = 'r';
    assert(write(replies[1],&command,1) == 1);
    assert(read(commands[0],&command,1) == 1 && command == 's');
    assert(munmap(pages+8192,8192) == 0);
    assert(write(replies[1],&command,1) == 1);
    assert(read(commands[0],&command,1) == 1 && command == 'q');
    __atomic_store_n(&done,true,__ATOMIC_RELAXED);
    other.join();
    _exit(0);
  }
  close(commands[0]); close(replies[1]);
  char command;
  assert(read(replies[0],&command,1) == 1);
  const std::string proc = "/proc/"+std::to_string(child)+"/mem";
  const int mem = open(proc.c_str(),O_RDONLY);
  assert(mem >= 0);
  std::ostringstream evidence;
  {
    StoppedProcess pause(child,evidence,1,"during");
    const auto before = __atomic_load_n(ticks,__ATOMIC_RELAXED);
    command = 's'; assert(write(commands[1],&command,1) == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(before == __atomic_load_n(ticks,__ATOMIC_RELAXED));
    unsigned char data[8192];
    assert(pread(mem,data,sizeof(data),reinterpret_cast<uintptr_t>(pages+8192)) == 8192);
    for(auto value:data) assert(value == 0x71);
    assert(pause.resume());
  }
  assert(read(replies[0],&command,1) == 1 && command == 's');
  unsigned char data[4096];
  errno = 0;
  assert(pread(mem,data,sizeof(data),reinterpret_cast<uintptr_t>(pages+8192)) == -1 && errno == EIO);
  uint64_t stopped_ticks = 0;
  try {
    StoppedProcess pause(child,evidence,2,"exception-test");
    stopped_ticks = __atomic_load_n(ticks,__ATOMIC_RELAXED);
    throw std::runtime_error("simulated-read-failure");
  } catch(const std::runtime_error&) {}
  for(unsigned i=0;i<1000 && stopped_ticks==__atomic_load_n(ticks,__ATOMIC_RELAXED);++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  assert(stopped_ticks != __atomic_load_n(ticks,__ATOMIC_RELAXED));
  assert(evidence.str().find(",resumed,SIGSTOP-waitpid-SIGCONT") != std::string::npos);
  command = 'q'; assert(write(commands[1],&command,1) == 1);
  int status = 0;
  assert(waitpid(child,&status,0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  close(mem); close(commands[1]); close(replies[0]);
  munmap(ticks,4096); munmap(pages,16384);
  puts("Host snapshot: all threads stopped, pending tail unmap deferred, exception resumes target PASS");
}
