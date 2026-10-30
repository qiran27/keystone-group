//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <asm/sbi.h>
#include <asm/csr.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/idr.h>
#include <linux/mutex.h>

#include <linux/file.h>
#include <linux/atomic.h>

/* IMPORTANT: This code assumes Sv39 */
#include "riscv64.h"
#include "sm_call.h"

#define PAGE_UP(addr)	(((addr)+((PAGE_SIZE)-1))&(~((PAGE_SIZE)-1)))

typedef uintptr_t vaddr_t;
typedef uintptr_t paddr_t;

extern struct miscdevice keystone_dev;

long keystone_ioctl(struct file* filep, unsigned int cmd, unsigned long arg);
int keystone_release(struct inode *inode, struct file *file);
int keystone_mmap(struct file *filp, struct vm_area_struct *vma);
int keystone_group_driver_init(void);
void keystone_group_driver_exit(void);
int keystone_group_config_topology_ioctl(unsigned long data);
int keystone_group_query_topology_ioctl(unsigned long data);
int keystone_group_lease_workers_ioctl(struct file *filep,
                                       unsigned long data);
int keystone_group_release_workers_ioctl(unsigned long data);
int keystone_group_run_master_ioctl(unsigned long data);
int keystone_group_wait_event_ioctl(unsigned long data);
int keystone_group_pause_master_ioctl(unsigned long data);
int keystone_group_heartbeat_ack_ioctl(unsigned long data);
void keystone_group_kick(unsigned long group_id);
void keystone_group_kick_hart(unsigned long group_id,
                              unsigned long hart_id);
void keystone_group_commit_event(unsigned long group_id,
                                 unsigned long event,
                                 unsigned long hart_id,
                                 unsigned long eid);
bool keystone_group_worker_is_leased(unsigned long group_id,
                                     unsigned long hart_id);
int keystone_group_release_for_destroy(unsigned long group_id);
int keystone_group_release_for_file(struct file *filep);

/* enclave private memory */
struct epm {
  pte_t* root_page_table;
  vaddr_t ptr;
  size_t size;
  unsigned long order;
  paddr_t pa;
  dma_addr_t dma_handle;
  bool is_cma;
  bool is_dma_pages;
  bool is_group_slice;
  unsigned long long group_id;
  paddr_t group_pa;
  size_t group_size;
};

extern spinlock_t YXSTM_spinlock;
extern struct mutex EPM_GROUP_mutex;
/* Lock order: GROUP_LIFECYCLE_mutex -> EPM_GROUP_mutex/YXSTM resource lock. */
extern struct mutex GROUP_LIFECYCLE_mutex;

#define KEYSTONE_MAX_ENABLED_GROUPS 4
#define KEYSTONE_GROUP_MAX_REGIONS 8
#define KEYSTONE_GROUP_REGION_PERM_R 0x1
#define KEYSTONE_GROUP_REGION_PERM_W 0x2
#define KEYSTONE_GROUP_REGION_PERM_X 0x4

enum keystone_group_region_type {
  KEYSTONE_GROUP_REGION_INVALID = 0,
  KEYSTONE_GROUP_REGION_PRIVATE_EPM,
  KEYSTONE_GROUP_REGION_SHARED,
  KEYSTONE_GROUP_REGION_METADATA,
  KEYSTONE_GROUP_REGION_CHANNEL,
  KEYSTONE_GROUP_REGION_UTM,
  KEYSTONE_GROUP_REGION_SHARED_UTM,
  KEYSTONE_GROUP_REGION_SEC,
};

struct keystone_group_region_descriptor {
  bool valid;
  unsigned long long region_id;
  enum keystone_group_region_type type;
  paddr_t paddr;
  size_t size;
  unsigned long long owner_group;
  unsigned long long permissions;
};

struct YXSTM {
  pte_t* root_page_table;
  void* ptr;
  size_t size;
  unsigned long order;
  /* CMA support */
  bool is_cma;
  phys_addr_t pa;
  void* cma_ptr;
  phys_addr_t cma_pa;
  size_t cma_size;
  size_t bank_slice_size;
  unsigned long bank_count;
};

struct YXSTM_GROUP_SLOT {
  unsigned long long engine_id;
  struct YXSTM yxstm;
  struct keystone_group_region_descriptor region;
  volatile unsigned long long ref_count;
};

struct GLOBAL_YXSTM {
  struct YXSTM_GROUP_SLOT slots[KEYSTONE_MAX_ENABLED_GROUPS];
};

struct EPM_GROUP_SLOT {
  unsigned long long engine_id;
  unsigned long long member_capacity;
  unsigned long long member_count;
  size_t minimum_slice_size;
  struct epm pool;
  size_t next_offset;
  unsigned long long ref_count;
  unsigned long long next_region_id;
  unsigned long long region_count;
  unsigned long long permission_epoch;
  struct keystone_group_region_descriptor region_table[KEYSTONE_GROUP_MAX_REGIONS];
};

struct GLOBAL_EPM_GROUPS {
  struct EPM_GROUP_SLOT slots[KEYSTONE_MAX_ENABLED_GROUPS];
};

struct utm {
  pte_t* root_page_table;
  void* ptr;
  size_t size;
  unsigned long order;
  paddr_t pa;      /* physical address (for CMA) */
  bool is_cma;     /* true if allocated via CMA */
  /* Fields for tracking original CMA allocation (for NAPOT alignment) */
  void* cma_ptr;   /* original CMA allocation pointer */
  paddr_t cma_pa;  /* original CMA physical address */
  size_t cma_size; /* original CMA allocation size (2x size for alignment) */
  /* Reference count for shared UTM */
  atomic_t ref_count;  /* number of enclaves sharing this UTM */
};

extern struct GLOBAL_EPM_GROUPS global_epm_groups;


struct enclave
{
  unsigned long eid;
  unsigned long sm_generation;
  int close_on_pexit;
  struct utm* utm;           /* 自己的 UTM（主 Enclave 使用） */
  struct utm* shared_utm;    /* 共享的 UTM（从 Enclave 使用，指向主 Enclave 的 UTM） */
  unsigned long owner_eid;   /* 共享 UTM 的所有者 Enclave ID（0 表示自己是所有者或无共享） */
  struct epm* epm;
  struct YXSTM* YXSTM;
  unsigned long long ms;
  unsigned long long engine_id;
  unsigned long long yxstm_group_id;
  size_t yxstm_bank_slice_size;
  unsigned long yxstm_bank_count;
  unsigned long long group_generation;
  bool is_init;
};


// global debug functions
void debug_dump(char* ptr, unsigned long size);

// runtime/app loader
int keystone_rtld_init_runtime(struct enclave* enclave, void* __user rt_ptr, size_t rt_sz, unsigned long rt_stack_sz, unsigned long* rt_offset);

int keystone_rtld_init_app(struct enclave* enclave, void* __user app_ptr, size_t app_sz, size_t app_stack_sz, unsigned long stack_offset);

// untrusted memory mapper
int keystone_rtld_init_untrusted(struct enclave* enclave, void* untrusted_ptr, size_t untrusted_size);

struct enclave* get_enclave_by_id(unsigned int ueid);
struct enclave* create_enclave(unsigned long min_pages, unsigned long long ms, unsigned long long engine_id);
int destroy_enclave(struct enclave* enclave);

unsigned int enclave_idr_alloc(struct enclave* enclave);
struct enclave* enclave_idr_remove(unsigned int ueid);
struct enclave* get_enclave_by_id(unsigned int ueid);
unsigned int enclave_idr_find_by_sm_eid(unsigned long sm_eid);

static inline uintptr_t  epm_satp(struct epm* epm) {
  return ((uintptr_t)epm->root_page_table >> RISCV_PGSHIFT | SATP_MODE_CHOICE);
}

int epm_destroy(struct epm* epm);
int epm_init(struct epm* epm, unsigned int count);
int epm_group_slice_init(struct epm* epm, unsigned int min_pages,
                         unsigned long long ms, unsigned long long engine_id);
int utm_destroy(struct utm* utm);
int utm_init(struct utm* utm, size_t untrusted_size);
int YXSTM_destroy(struct YXSTM* YXSTM);
int YXSTM_init(struct YXSTM* YXSTM, size_t YXSTrusted_size);
int yxstm_group_get(unsigned long long engine_id, size_t size,
                    size_t bank_slice_size, unsigned long bank_count,
                    struct YXSTM* out);
int yxstm_group_put(unsigned long long engine_id);
paddr_t epm_va_to_pa(struct epm* epm, vaddr_t addr);

#define keystone_info(fmt, ...) \
  pr_info("keystone_enclave: " fmt, ##__VA_ARGS__)
#define keystone_err(fmt, ...) \
  pr_err("keystone_enclave: " fmt, ##__VA_ARGS__)
#define keystone_warn(fmt, ...) \
  pr_warn("keystone_enclave: " fmt, ##__VA_ARGS__)
#endif
