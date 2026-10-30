#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include "../motivation/protocol.h"

// Allocation and locks are stubbed; slice admission below is the actual driver C routine.
#define PAGE_SIZE 4096UL
#define KEYSTONE_GROUP_MEMBER_LIMIT 96
#define KEYSTONE_MAX_ENABLED_GROUPS 2
#define KEYSTONE_GROUP_SLICE_ALIGN_SIZE (KEYSTONE_GROUP_SLICE_ALIGN_PAGES * PAGE_SIZE)
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
#define IS_ALIGNED(x,a) (!((x)&((a)-1)))
#define mutex_lock(x) ((void)(x))
#define mutex_unlock(x) ((void)(x))
#define keystone_err(...) ((void)0)
#define keystone_info(...) ((void)0)
using pte_t=unsigned long;
struct epm {
  pte_t* root_page_table;
  unsigned long ptr,pa,dma_handle,size,group_id,group_pa,group_size;
  bool is_cma,is_dma_pages,is_group_slice;
};
struct EPM_GROUP_SLOT {
  epm pool;
  unsigned long long engine_id,member_capacity,member_count;
  size_t minimum_slice_size,next_offset,ref_count;
};
static struct { EPM_GROUP_SLOT slots[KEYSTONE_MAX_ENABLED_GROUPS]; } global_epm_groups;
static int EPM_GROUP_mutex;
static int epm_init(epm* pool,unsigned pages) {
  *pool={}; pool->pa=0x10000000; pool->ptr=pool->pa; pool->size=pages*PAGE_SIZE; return 0;
}
static int epm_destroy(epm*) { return 0; }
#include "motivation-epm-driver.inc"

constexpr uint64_t kDefaultGroupId=1,kYxstmSize=64*1024*1024;
#define KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT 16
struct EnclaveInstance {
  std::string name,eapp;
  uint64_t group,capacity,shared,utm,slice,free_mem;
};
static void add_instance(std::vector<EnclaveInstance>& out,const char* name,const char* eapp,
    uint64_t group,uint64_t capacity,uint64_t shared,uint64_t utm,uint64_t slice,uint64_t free_mem) {
  out.push_back({name,eapp,group,capacity,shared,utm,slice,free_mem});
}
#include "../host/motivation-enclave-config.hpp"

int main() {
  epm owner={},worker={};
  // Exact board failure: owner 500 pages -> 2MiB slice, Worker 1273 -> 6MiB.
  assert(!epm_group_slice_init(&owner,500,2,1));
  assert(global_epm_groups.slots[0].pool.size==4*1024*1024);
  assert(epm_group_slice_init(&worker,1273,2,1)==-ENOSPC);

  std::vector<EnclaveInstance> members;
  add_motivation_instances(members);
  assert(members.size()==2 && members[0].name=="motivation-inactive-owner" && members[1].name=="motivation-worker-1");
  const auto& first=members[0]; const auto& second=members[1];
  assert(first.eapp=="group-pmp-motivation-worker.eapp_riscv" && first.eapp==second.eapp);
  assert(first.group==second.group && first.capacity==2 && second.capacity==2);
  assert(first.free_mem==4*1024*1024 && first.free_mem==second.free_mem);
  assert(first.utm==MOT_UTM_BYTES && first.utm==second.utm);
  assert(first.shared==second.shared && first.slice==second.slice);
  // Same ELF + runtime + loader and free memory gives equal SDK min_pages.
  for (unsigned image_pages: {128U,249U,500U,1024U,4096U}) {
    std::memset(&global_epm_groups,0,sizeof(global_epm_groups));
    owner={}; worker={};
    unsigned required=image_pages+first.free_mem/PAGE_SIZE;
    assert(!epm_group_slice_init(&owner,required,2,1));
    assert(!epm_group_slice_init(&worker,required,2,1));
    assert(owner.size==worker.size);
    assert(owner.group_pa==worker.group_pa && owner.pa+owner.size==worker.pa);
    assert(global_epm_groups.slots[0].next_offset==global_epm_groups.slots[0].pool.size);
    if(image_pages==249) assert(owner.group_size==12*1024*1024);
  }
  members.clear(); add_motivation_instances(members,1,true);
  assert(members.size()==2 && members[0].name=="motivation-task-master" && members[0].eapp==members[1].eapp);
  assert(members[0].free_mem==members[1].free_mem && members[0].capacity==2);
  members.clear(); add_motivation_instances(members,3,true);
  assert(members.size()==4 && members[0].name=="motivation-task-master");
  std::memset(&global_epm_groups,0,sizeof(global_epm_groups));
  for(const auto& m:members) {
    epm item={}; assert(m.capacity==4 && m.free_mem==4*1024*1024 && m.eapp==members[0].eapp);
    assert(!epm_group_slice_init(&item,249+m.free_mem/PAGE_SIZE,4,1));
  }
  assert(global_epm_groups.slots[0].pool.size==24*1024*1024);
  std::cout<<"motivation EPM: board 500/1273-page failure reproduced; matched images/Params admit both members using driver reservation routine PASS\n";
}
