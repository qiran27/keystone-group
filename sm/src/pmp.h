//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _PMP_H_
#define _PMP_H_

#include "sm.h"
#include <sbi/riscv_atomic.h>

#define SET_BIT(bitmap, n) (bitmap |= (0x1 << (n)))
#define UNSET_BIT(bitmap, n) (bitmap &= ~(0x1 << (n)))
#define TEST_BIT(bitmap, n) (bitmap & (0x1 << (n)))

enum pmp_priority {
  PMP_PRI_ANY,
  PMP_PRI_TOP,
  PMP_PRI_BOTTOM,
};

/* VisionFive2 per-hart hardware layout; region descriptors are separate. */
#define KEYSTONE_PMP_HW_ENTRY_COUNT       8
#define KEYSTONE_PMP_SLOT_SM              0
#define KEYSTONE_PMP_SLOT_GROUP_EPM_LO    1
#define KEYSTONE_PMP_SLOT_GROUP_EPM_HI    2
#define KEYSTONE_PMP_SLOT_YXSTM_LO        3
#define KEYSTONE_PMP_SLOT_YXSTM_HI        4
#define KEYSTONE_PMP_SLOT_YXSTM           KEYSTONE_PMP_SLOT_YXSTM_HI
#define KEYSTONE_PMP_SLOT_SEC_LO          5
#define KEYSTONE_PMP_SLOT_SEC_HI          6
#define KEYSTONE_PMP_SLOT_DYNAMIC_END     KEYSTONE_PMP_SLOT_SEC_HI
#define KEYSTONE_PMP_SLOT_OS_UTM          7
#ifndef KEYSTONE_PMP_DEBUG_DUMP
#define KEYSTONE_PMP_DEBUG_DUMP            0
#endif

#define PMP_ALL_PERM  (PMP_W | PMP_X | PMP_R)
#define PMP_NO_PERM   0

#if __riscv_xlen == 64
# define LIST_OF_PMP_REGS  X(0,0)  X(1,0)  X(2,0)  X(3,0) \
                           X(4,0)  X(5,0)  X(6,0)  X(7,0) \
                           X(8,2)  X(9,2)  X(10,2) X(11,2) \
                          X(12,2) X(13,2) X(14,2) X(15,2)
# define PMP_PER_GROUP  8
#else
# define LIST_OF_PMP_REGS  X(0,0)  X(1,0)  X(2,0)  X(3,0) \
                           X(4,1)  X(5,1)  X(6,1)  X(7,1) \
                           X(8,2)  X(9,2)  X(10,2) X(11,2) \
                           X(12,3) X(13,3) X(14,3) X(15,3)
# define PMP_PER_GROUP  4
#endif

#define PMP_SET(n, g, addr, pmpc) \
{ uintptr_t oldcfg = csr_read(pmpcfg##g); \
  pmpc |= (oldcfg & ~((uintptr_t)0xff << (uintptr_t)8*(n%PMP_PER_GROUP))); \
  asm volatile ("la t0, 1f\n\t" \
                "csrrw t0, mtvec, t0\n\t" \
                "csrw pmpaddr"#n", %0\n\t" \
                "csrw pmpcfg"#g", %1\n\t" \
                "fence rw,rw\n\t" \
                "sfence.vma\n\t" \
                "fence.i\n\t"\
                ".align 2\n\t" \
                "1: csrw mtvec, t0 \n\t" \
                : : "r" (addr), "r" (pmpc) : "t0"); \
}

#define PMP_UNSET(n, g) \
{ uintptr_t pmpc = csr_read(pmpcfg##g); \
  pmpc &= ~((uintptr_t)0xff << (uintptr_t)8*(n%PMP_PER_GROUP)); \
  asm volatile ("la t0, 1f \n\t" \
                "csrrw t0, mtvec, t0 \n\t" \
                "csrw pmpaddr"#n", %0\n\t" \
                "csrw pmpcfg"#g", %1\n\t" \
                "fence rw,rw\n\t" \
                "sfence.vma\n\t" \
                "fence.i\n\t"\
                ".align 2\n\t" \
                "1: csrw mtvec, t0" \
                : : "r" (0), "r" (pmpc) : "t0"); \
}

#define PMP_ERROR(error, msg) {\
  sbi_printf("%s:" msg "\n", __func__);\
  return error; \
}

/* PMP IPI mailbox */
struct ipi_msg{
  atomic_t pending;
  uint8_t perm;
};

/* PMP region type */
struct pmp_region
{
  uint64_t size;
  uint8_t addrmode;
  uintptr_t addr;
  int allow_overlap;
  int reg_idx;
  int owns_reg;
};

struct keystone_pmp_budget {
  uint8_t sm_entries;
  uint8_t epm_entries;
  uint8_t yxstm_entries;
  uint8_t sec_entries;
  uint8_t os_utm_entries;
  uint8_t reserved_entries;
  uint8_t total_entries;
  uint8_t hardware_entries;
};

/*
 * Compact, pre-encoded PMP entry used by the same-group scheduler handoff.
 * The cache contains hardware CSR values, not a software region id, so the
 * timer path never walks the region table or recomputes NAPOT/TOR addresses.
 */
struct keystone_pmp_cached_entry {
  uintptr_t addr;
  uint8_t cfg;
  uint8_t slot;
  uint8_t valid;
  uint8_t reserved;
};

typedef int pmpreg_id;
typedef int region_id;

/* external functions */
void pmp_init(void);
int pmp_reserve_group_layout(void);
int pmp_region_init_atomic(uintptr_t start, uint64_t size, enum pmp_priority pri, region_id* rid, int allow_overlap);
int pmp_region_init(uintptr_t start, uint64_t size, enum pmp_priority pri, region_id* rid, int allow_overlap);
int pmp_region_init_fixed_atomic(uintptr_t start, uint64_t size,
                                 int first_slot, int slot_count,
                                 region_id* rid, int allow_overlap);
int pmp_region_free_atomic(region_id region);
int pmp_set_keystone(region_id n, uint8_t perm);
int pmp_set_keystone_napot(region_id n, uintptr_t addr, uint64_t size,
                           uint8_t perm);
int pmp_cache_region_entries(region_id n, uint8_t perm,
                             struct keystone_pmp_cached_entry* entries,
                             size_t entry_capacity, size_t* entry_count);
int pmp_cache_napot_entry(region_id n, uintptr_t addr, uint64_t size,
                          uint8_t perm,
                          struct keystone_pmp_cached_entry* entry);
int pmp_cache_tor_entries(region_id n, uintptr_t addr, uint64_t size,
                          uint8_t perm,
                          struct keystone_pmp_cached_entry* entries,
                          size_t entry_capacity, size_t* entry_count);
int pmp_apply_cached_entries(
    const struct keystone_pmp_cached_entry* entries, size_t entry_count);
int pmp_apply_cached_entries_deferred_fence(
    const struct keystone_pmp_cached_entry* entries, size_t entry_count);
int pmp_set_global(region_id n, uint8_t perm);
int pmp_unset(region_id n);
int pmp_unset_global(region_id n);
int pmp_detect_region_overlap_atomic(uintptr_t base, uintptr_t size);
void handle_pmp_ipi(void);

uintptr_t pmp_region_get_addr(region_id i);
uint64_t pmp_region_get_size(region_id i);
int pmp_region_get_reg_idx(region_id i);
int pmp_region_get_entry_count(region_id i);
int pmp_group_preflight(uintptr_t epm_base, uint64_t epm_size,
                        uintptr_t yxstm_base, uint64_t yxstm_size,
                        uintptr_t sec_base, uint64_t sec_size,
                        struct keystone_pmp_budget* budget);
int pmp_mask_is_contiguous(uintptr_t mask);
void pmp_clear_dynamic_slots(void);
int pmp_region_readback_matches(region_id region, uint8_t perm);
int pmp_dynamic_slots_are_clear(void);
void pmp_debug_dump_hart(const char* where);
unsigned long pmp_defined_region_count(void);
void pmp_perf_snapshot(unsigned long* count, unsigned long* cycles, int reset);

#endif
