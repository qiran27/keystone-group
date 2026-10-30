#include "../host/motivation-system.hpp"
#include <cassert>
#include <cstdio>
#include <string>
int main(int argc,char** argv) {
  assert(argc==2);
  unsetenv("GROUP_PMP_MOTIVATION_INTERFACE");
  assert(MotivationSystem::valid_selection("motivation-readseq",nullptr));
  assert(!MotivationSystem::valid_selection("motivation-readseq","seq-read-2m"));
  setenv("GROUP_PMP_MOTIVATION_INTERFACE","fio",1);
  assert(MotivationSystem::valid_selection("fio-seq-read-2m","seq-read-2m"));
  assert(!MotivationSystem::valid_selection("motivation-readseq","seq-read-2m"));
  assert(!MotivationSystem::valid_selection("fio-rand-read-4k","rand-read-4k"));
  assert(!MotivationSystem::valid_selection("fio-seq-read-2m",nullptr));
  setenv("GROUP_PMP_MOTIVATION_INTERFACE","invalid",1);
  assert(!MotivationSystem::valid_selection("motivation-readseq",nullptr));
  unsetenv("GROUP_PMP_MOTIVATION_INTERFACE");
  MotivationSystem::Anchor a={1000,500000,10}; uint64_t ns=0;
  assert(MotivationSystem::convert(1100,a,1000000,&ns) && ns==600000);
  assert(MotivationSystem::convert(900,a,1000000,&ns) && ns==400000);
  assert(!MotivationSystem::convert(900,a,0,&ns));
  assert(!MotivationSystem::convert(0,a,1000,&ns));
  std::vector<uint8_t> utm(GROUP_PMP_SQLITE_VFS_UTM_BYTES);
  mot_system_trace log={}; log.magic=MOT_SYSTEM_TRACE_MAGIC; log.version=1;
  uint64_t t=Motivation::ticks();
  mot_system_append(&log,t,t,0,16,0,0); mot_system_append(&log,t,t,16,16,0,0);
  auto put=[&]{std::memcpy(utm.data()+GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET,&log,sizeof(log));};
  std::vector<std::pair<const void*,size_t>> buffers={{utm.data(),utm.size()}};
  std::string path=std::string(argv[1])+"/crypto.csv";
  assert(!MotivationSystem::export_trace(path.c_str(),{}, {},1000000000));
  assert(!MotivationSystem::export_trace(path.c_str(),buffers,{32},0));
  put(); assert(MotivationSystem::export_trace(path.c_str(),buffers,{32},1000000000));
  assert(!MotivationSystem::export_trace(path.c_str(),buffers,{32},1000000000));
  assert(!std::remove(path.c_str()));
  log.dropped=1; put(); assert(!MotivationSystem::export_trace(path.c_str(),buffers,{32},1000000000));
  assert(!std::remove(path.c_str()));
  log.dropped=0; log.events[1].logical_offset=32; put();
  assert(!MotivationSystem::export_trace(path.c_str(),buffers,{32},1000000000));
  assert(!std::remove(path.c_str()));
  puts("Extent-I/O clock alignment and post-drain trace export: bounds, coverage, overflow and overwrite guards PASS");
}
