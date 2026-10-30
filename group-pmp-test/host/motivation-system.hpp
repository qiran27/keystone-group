#ifndef MOTIVATION_SYSTEM_HOST_HPP
#define MOTIVATION_SYSTEM_HOST_HPP
#include "../motivation/system-trace.h"
#include "../motivation/read-engine.hpp"
#include "../eapp/group-pmp-sqlite-vfs-shared.h"
#include <chrono>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <utility>
#include <vector>
namespace MotivationSystem {
#define MOT_PRODUCTION_INTERFACE_MARKER "keystone-motivation-production-interface-v1"
inline bool valid_selection(const char* selection,const char* profile) {
  const char* interface=std::getenv("GROUP_PMP_MOTIVATION_INTERFACE");
  if(!interface || !std::strcmp(interface,"sqlite"))
    return selection && !std::strcmp(selection,"motivation-readseq") && (!profile || !*profile);
  return !std::strcmp(interface,"fio") && profile && !std::strcmp(profile,"seq-read-2m") &&
      selection && !std::strcmp(selection,"fio-seq-read-2m");
}
inline bool enabled() {
  const char* value=std::getenv("GROUP_PMP_MOTIVATION_SYSTEM");
  return value && !std::strcmp(value,"1");
}
inline const char* trace_path() { return std::getenv("GROUP_PMP_MOTIVATION_CRYPTO_CSV"); }
struct Anchor { uint64_t ticks,ns,uncertainty; };
inline uint64_t steady_ns() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline Anchor anchor() {
  Anchor best={0,0,UINT64_MAX};
  for(unsigned i=0;i<8;++i) {
    uint64_t lo=steady_ns(),tick=Motivation::ticks(),hi=steady_ns();
    if(hi>=lo && hi-lo<best.uncertainty) best={tick,lo+(hi-lo)/2,hi-lo};
  }
  return best;
}
inline bool convert(uint64_t tick,const Anchor& a,uint64_t hz,uint64_t* ns) {
  if(!hz || a.uncertainty==UINT64_MAX) return false;
  const long double value=static_cast<long double>(a.ns)+
      (static_cast<long double>(tick)-a.ticks)*1000000000.0L/hz;
  if(value<0 || value>UINT64_MAX) return false;
  *ns=static_cast<uint64_t>(value); return true;
}
inline bool export_trace(const char* path,
    const std::vector<std::pair<const void*,size_t>>& buffers,
    const std::vector<uint64_t>& assigned,uint64_t hz) {
  if(!path || !*path || !hz || buffers.empty() || buffers.size()!=assigned.size() || std::ifstream(path).good()) return false;
  std::ofstream out(path);
  if(!out) return false;
  const Anchor a=anchor();
  out<<"worker,sequence,logical_offset,bytes,begin_ticks,end_ticks,runtime_ticks,timebase_hz,begin_ns,end_ns,clock_uncertainty_ns\n";
  for(size_t w=0;w<buffers.size();++w) {
    if(!buffers[w].first || buffers[w].second<GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET+sizeof(mot_system_trace)) return false;
    mot_system_trace log;
    std::memcpy(&log,static_cast<const uint8_t*>(buffers[w].first)+GROUP_PMP_SQLITE_VFS_BUFFER0_OFFSET,sizeof(log));
    if(log.magic!=MOT_SYSTEM_TRACE_MAGIC || log.version!=1 || log.dropped ||
       !log.count || log.count>MOT_SYSTEM_TRACE_MAX) return false;
    uint64_t next=0,last=0;
    std::vector<std::pair<uint64_t,uint64_t>> ranges;
    for(uint64_t i=0;i<log.count;++i) {
      const auto& e=log.events[i]; uint64_t lo,hi;
      if(!e.bytes || e.bytes>GROUP_PMP_SQLITE_VFS_BUFFER_BYTES ||
         e.logical_offset>assigned[w] || e.bytes>assigned[w]-e.logical_offset || e.bytes>assigned[w]-next ||
         e.end_ticks<e.begin_ticks || e.begin_ticks<last ||
         e.runtime_ticks>e.end_ticks-e.begin_ticks ||
         !convert(e.begin_ticks,a,hz,&lo) || !convert(e.end_ticks,a,hz,&hi)) return false;
      out<<w<<','<<i<<','<<e.logical_offset<<','<<e.bytes<<','<<e.begin_ticks<<','<<e.end_ticks
         <<','<<e.runtime_ticks<<','<<hz<<','<<lo<<','<<hi<<','
         <<a.uncertainty+(1000000000/hz+1)<<'\n';
      next+=e.bytes; last=e.end_ticks;
      ranges.push_back({e.logical_offset,e.logical_offset+e.bytes});
    }
    if(next!=assigned[w]) return false;
    std::sort(ranges.begin(),ranges.end()); next=0;
    for(const auto& range:ranges) { if(range.first!=next) return false; next=range.second; }
  }
  return out.good();
}
}
#endif
