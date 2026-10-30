//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm_assert.h"
#include "pmp.h"
#include "cpu.h"
#include "safe_math_util.h"
#include "sm-sbi-opensbi.h"
#include "page.h"
#include "ipi.h"
#include <sbi/sbi_hart.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_atomic.h>

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires a defined platform to build"
#endif

// Special target platform header, set by configure script
#include TARGET_PLATFORM_HEADER

/* PMP global spin locks */
static spinlock_t pmp_lock = SPIN_LOCK_INITIALIZER;

/* PMP region getter/setters */
static struct pmp_region regions[PMP_MAX_N_REGION];
static uint32_t reg_bitmap = 0;
#define PMP_REGION_BITMAP_WORD_BITS 32U
#define PMP_REGION_BITMAP_WORDS \
  ((PMP_MAX_N_REGION + PMP_REGION_BITMAP_WORD_BITS - 1U) / \
   PMP_REGION_BITMAP_WORD_BITS)
static uint32_t region_def_bitmap[PMP_REGION_BITMAP_WORDS];
struct pmp_perf_hart_local {
  unsigned long count;
  unsigned long cycles;
};
static struct pmp_perf_hart_local pmp_perf_harts[MAX_HARTS];
typedef char pmp_region_bitmap_must_not_be_empty[
    (PMP_REGION_BITMAP_WORDS > 0) ? 1 : -1];

static inline int region_bitmap_test(region_id region_idx)
{
  unsigned int index;
  unsigned int bit;

  if (region_idx < 0 || region_idx >= PMP_MAX_N_REGION)
    return 0;
  index = (unsigned int)region_idx / PMP_REGION_BITMAP_WORD_BITS;
  bit = (unsigned int)region_idx % PMP_REGION_BITMAP_WORD_BITS;
  return (region_def_bitmap[index] & (UINT32_C(1) << bit)) != 0;
}

static inline void region_bitmap_set(region_id region_idx)
{
  unsigned int index =
      (unsigned int)region_idx / PMP_REGION_BITMAP_WORD_BITS;
  unsigned int bit =
      (unsigned int)region_idx % PMP_REGION_BITMAP_WORD_BITS;

  region_def_bitmap[index] |= UINT32_C(1) << bit;
}

static inline void region_bitmap_unset(region_id region_idx)
{
  unsigned int index =
      (unsigned int)region_idx / PMP_REGION_BITMAP_WORD_BITS;
  unsigned int bit =
      (unsigned int)region_idx % PMP_REGION_BITMAP_WORD_BITS;

  region_def_bitmap[index] &= ~(UINT32_C(1) << bit);
}

static inline void pmp_perf_record(unsigned long cycles)
{
  unsigned long hartid = current_hartid();

  if (hartid >= MAX_HARTS)
    return;
  /* One writer per hart avoids cross-hart cache-line bouncing in PMP paths. */
  pmp_perf_harts[hartid].count++;
  pmp_perf_harts[hartid].cycles += cycles;
}

unsigned long pmp_defined_region_count(void)
{
  unsigned long count = 0;
  unsigned int word;

  for (word = 0; word < PMP_REGION_BITMAP_WORDS; word++) {
    uint32_t bitmap = region_def_bitmap[word];

    while (bitmap) {
      count += bitmap & 1U;
      bitmap >>= 1;
    }
  }
  return count;
}

void pmp_perf_snapshot(unsigned long* count, unsigned long* cycles, int reset)
{
  unsigned long total_count = 0;
  unsigned long total_cycles = 0;
  unsigned long hartid;

  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    total_count += pmp_perf_harts[hartid].count;
    total_cycles += pmp_perf_harts[hartid].cycles;
  }
  if (count)
    *count = total_count;
  if (cycles)
    *cycles = total_cycles;
  if (reset)
    sbi_memset(pmp_perf_harts, 0, sizeof(pmp_perf_harts));
}

static inline int region_register_idx(region_id i)
{
  return regions[i].reg_idx;
}

static inline int region_allows_overlap(region_id i)
{
  return regions[i].allow_overlap;
}

static inline uintptr_t region_get_addr(region_id i)
{
  return regions[i].addr;
}

static inline uint64_t region_get_size(region_id i)
{
  return regions[i].size;
}

static inline int region_is_napot(region_id i)
{
  return regions[i].addrmode == PMP_A_NAPOT;
}

static inline int region_is_tor(region_id i)
{
  return regions[i].addrmode == PMP_A_TOR;
}

static inline int region_needs_two_entries(region_id i)
{
  return region_is_tor(i) && regions[i].reg_idx > 0;
}

static inline int region_is_napot_all(region_id i)
{
  return regions[i].addr == 0 && regions[i].size == -1UL;
}

static inline uintptr_t region_pmpaddr_val(region_id i)
{
  if(region_is_napot_all(i))
    return (-1UL);
  else if(region_is_napot(i))
    return (regions[i].addr | (regions[i].size/2-1)) >> 2;
  else if(region_is_tor(i))
    return (regions[i].addr + regions[i].size) >> 2;
  else
    return 0;
}

static inline uintptr_t region_pmpcfg_val(region_id i, pmpreg_id reg_idx, uint8_t perm_bits)
{
  return (uintptr_t) (regions[i].addrmode | perm_bits) << (8*(reg_idx%PMP_PER_GROUP));
}

static void region_clear_all(region_id i)
{
  regions[i].addr = 0;
  regions[i].size = 0;
  regions[i].addrmode = 0;
  regions[i].allow_overlap = 0;
  regions[i].reg_idx = 0;
  regions[i].owns_reg = 0;
}

static void region_init(region_id i,
                        uintptr_t addr,
                        uint64_t size,
                        uint8_t addrmode,
                        int allow_overlap,
                        pmpreg_id reg_idx,
                        int owns_reg)
{
  regions[i].addr = addr;
  regions[i].size = size;
  regions[i].addrmode = addrmode;
  regions[i].allow_overlap = allow_overlap;
  regions[i].reg_idx = (addrmode == PMP_A_TOR && reg_idx > 0 ? reg_idx + 1 : reg_idx);
  regions[i].owns_reg = owns_reg;
}

static int is_pmp_region_valid(region_id region_idx)
{
  return region_bitmap_test(region_idx);
}

static int search_rightmost_unset(uint32_t bitmap, int max, uint32_t mask)
{
  int i = 0;

  sm_assert(max < 32);
  sm_assert(!((mask + 1) & mask));

  while(mask < (1UL << max)) {
    if((~bitmap & mask) == mask)
      return i;
    mask = mask << 1;
    i++;
  }

  return -1;
}

static region_id get_free_region_idx(void)
{
  region_id region_idx;

  for (region_idx = 0; region_idx < PMP_MAX_N_REGION; region_idx++)
    if (!region_bitmap_test(region_idx))
      return region_idx;
  return -1;
}

static pmpreg_id get_free_reg_idx(void)
{
  return search_rightmost_unset(reg_bitmap, PMP_N_REG, 0x1);
}

static pmpreg_id get_conseq_free_reg_idx(void)
{
  return search_rightmost_unset(reg_bitmap, PMP_N_REG, 0x3);
}

/* We do an integery overflow safety check here for the inputs (addr +
 * size).  We do NOT do a safety check on epm_base + epm_size, since
 * only valid region should have been created previously.
 *
 * On a failed addr + size overflow, we return failure, since this
 * cannot be a valid addr and size anyway.
 */
static int detect_region_overlap(uintptr_t addr, uintptr_t size)
{
  void* epm_base;
  size_t epm_size;
  int region_overlap = 0, i;

  // Safety check the addr+size
  uintptr_t input_end;
  if( CHECKED_ADD(addr, size, &input_end)){
    return 1;
  }

  for(i=0; i<PMP_MAX_N_REGION; i++)
  {
    if(!is_pmp_region_valid(i))
      continue;

    if(region_allows_overlap(i)) {
      continue;
    }

    epm_base = (void*) region_get_addr(i);
    epm_size = region_get_size(i);

    // Only looking at valid regions, no need to check epm_base+size
    region_overlap |= ((uintptr_t) epm_base < input_end) &&
                      ((uintptr_t) epm_base + epm_size > addr);
  }

  return region_overlap;
}

int pmp_detect_region_overlap_atomic(uintptr_t addr, uintptr_t size)
{
  int region_overlap = 0;
  spin_lock(&pmp_lock);
  region_overlap = detect_region_overlap(addr, size);
  spin_unlock(&pmp_lock);
  return region_overlap;
}

/*********************************
 *
 * External Functions
 *
 **********************************/

int pmp_unset_global(int region_idx)
{
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_INVALID, "Invalid PMP region index");

  send_and_sync_pmp_ipi(region_idx, SBI_PMP_IPI_TYPE_UNSET, PMP_NO_PERM);

  return SBI_ERR_SM_PMP_SUCCESS;
}

/* populate pmp set command to every other hart */
int pmp_set_global(int region_idx, uint8_t perm)
{
  // sbi_printf("[PMP] pmp_set_global: region=%d perm=0x%x\n", region_idx, perm);
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_INVALID, "Invalid PMP region index");

  send_and_sync_pmp_ipi(region_idx, SBI_PMP_IPI_TYPE_SET, perm);
  // sbi_printf("[PMP] pmp_set_global completed\n");

  return SBI_ERR_SM_PMP_SUCCESS;
}

void pmp_init(void)
{
  uintptr_t pmpaddr = 0;
  uintptr_t pmpcfg = 0;
  int i;
  for (i=0; i < PMP_N_REG; i++)
  {
    switch(i) {
#define X(n,g) case n: { PMP_SET(n, g, pmpaddr, pmpcfg); break; }
      LIST_OF_PMP_REGS
#undef X
    }
  }
}

int pmp_reserve_group_layout(void)
{
  int slot;

  if (PMP_N_REG != KEYSTONE_PMP_HW_ENTRY_COUNT)
    return SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED;

  spin_lock(&pmp_lock);
  for (slot = KEYSTONE_PMP_SLOT_GROUP_EPM_LO;
       slot <= KEYSTONE_PMP_SLOT_DYNAMIC_END; slot++)
    SET_BIT(reg_bitmap, slot);
  spin_unlock(&pmp_lock);

  sbi_printf("[SM][pmp] fixed layout reserved: hw_entries=%d metadata_regions=%d slots={sm:0 epm:1-2 yxstm:3-4 sec:5-6 os_utm:7}\n",
             PMP_N_REG, PMP_MAX_N_REGION);
  return SBI_ERR_SM_PMP_SUCCESS;
}

int pmp_set_keystone(int region_idx, uint8_t perm)
{
  unsigned long perf_start;
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_INVALID, "Invalid PMP region index");

  uint8_t perm_bits = perm & PMP_ALL_PERM;
  perf_start = csr_read(CSR_MCYCLE);
  pmpreg_id reg_idx = region_register_idx(region_idx);
  uintptr_t pmpcfg = region_pmpcfg_val(region_idx, reg_idx, perm_bits);
  uintptr_t pmpaddr;

  pmpaddr = region_pmpaddr_val(region_idx);

  //sbi_printf("pmp_set() [hart %d]: reg[%d], mode[%s], range[0x%lx-0x%lx], perm[0x%x]\r\n",
  //       current_hartid(), reg_idx, (region_is_tor(region_idx) ? "TOR":"NAPOT"),
  //       region_get_addr(region_idx), region_get_addr(region_idx) + region_get_size(region_idx), perm);
  //sbi_printf("  pmp[%d] = pmpaddr: 0x%lx, pmpcfg: 0x%lx\r\n", reg_idx, pmpaddr, pmpcfg);

  int n=reg_idx;

  switch(n) {
#define X(n,g) case n: { PMP_SET(n, g, pmpaddr, pmpcfg); break; }
  LIST_OF_PMP_REGS
#undef X
    default:
      sm_assert(false);
  }

  /* TOR decoding with 2 registers */
  if(region_needs_two_entries(region_idx))
  {
    n--;
    pmpcfg = 0;
    pmpaddr = region_get_addr(region_idx) >> 2;
    switch(n) {
#define X(n,g) case n: { PMP_SET(n, g, pmpaddr, pmpcfg); break; }
  LIST_OF_PMP_REGS
#undef X
    default:
      sm_assert(false);
    }
  }
  pmp_perf_record(csr_read(CSR_MCYCLE) - perf_start);
  return SBI_ERR_SM_PMP_SUCCESS;
}

int pmp_set_keystone_napot(int region_idx, uintptr_t addr, uint64_t size,
                           uint8_t perm)
{
  unsigned long perf_start;
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_INVALID, "Invalid PMP region index");

  if (region_needs_two_entries(region_idx))
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_INVALID,
              "Dynamic NAPOT cannot reuse a TOR region");

  if (!(size == -1UL && addr == 0)) {
    if (!size || (size & (size - 1)) || (addr & (size - 1)) ||
        (size & (RISCV_PGSIZE - 1)) || (addr & (RISCV_PGSIZE - 1)))
      PMP_ERROR(SBI_ERR_SM_PMP_REGION_SIZE_INVALID,
                "Invalid dynamic NAPOT PMP range");
  }

  uint8_t perm_bits = perm & PMP_ALL_PERM;
  perf_start = csr_read(CSR_MCYCLE);
  pmpreg_id reg_idx = region_register_idx(region_idx);
  uintptr_t pmpaddr;
  uintptr_t pmpcfg;

  if (addr == 0 && size == -1UL)
    pmpaddr = -1UL;
  else
    pmpaddr = (addr | (size / 2 - 1)) >> 2;
  pmpcfg = (uintptr_t)(PMP_A_NAPOT | perm_bits) <<
      (8 * (reg_idx % PMP_PER_GROUP));

  int n = reg_idx;
  switch(n) {
#define X(n,g) case n: { PMP_SET(n, g, pmpaddr, pmpcfg); break; }
  LIST_OF_PMP_REGS
#undef X
    default:
      sm_assert(false);
  }

  pmp_perf_record(csr_read(CSR_MCYCLE) - perf_start);
  return SBI_ERR_SM_PMP_SUCCESS;
}

static int pmp_cached_entry_set(struct keystone_pmp_cached_entry* entry,
                                int slot, uintptr_t addr, uint8_t cfg)
{
  if (!entry || slot < 0 || slot >= KEYSTONE_PMP_HW_ENTRY_COUNT)
    return SBI_ERR_SM_PMP_REGION_INVALID;

  entry->addr = addr;
  entry->cfg = cfg;
  entry->slot = (uint8_t)slot;
  entry->valid = 1;
  entry->reserved = 0;
  return SBI_ERR_SM_PMP_SUCCESS;
}

int pmp_cache_region_entries(region_id region_idx, uint8_t perm,
                             struct keystone_pmp_cached_entry* entries,
                             size_t entry_capacity, size_t* entry_count)
{
  int reg_idx;
  size_t required;
  uintptr_t cfg;

  if (entry_count)
    *entry_count = 0;
  if (!entries || !entry_count || !is_pmp_region_valid(region_idx))
    return SBI_ERR_SM_PMP_REGION_INVALID;

  reg_idx = region_register_idx(region_idx);
  required = region_needs_two_entries(region_idx) ? 2 : 1;
  if (entry_capacity < required || reg_idx < 0 ||
      reg_idx >= KEYSTONE_PMP_HW_ENTRY_COUNT ||
      (required == 2 && reg_idx == 0))
    return SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED;

  if (required == 2) {
    if (pmp_cached_entry_set(&entries[0], reg_idx - 1,
                             region_get_addr(region_idx) >> 2, 0))
      return SBI_ERR_SM_PMP_REGION_INVALID;
  }
  cfg = region_pmpcfg_val(region_idx, reg_idx, perm & PMP_ALL_PERM);
  if (pmp_cached_entry_set(
          &entries[required - 1], reg_idx, region_pmpaddr_val(region_idx),
          (uint8_t)(cfg >> (8 * (reg_idx % PMP_PER_GROUP)))))
    return SBI_ERR_SM_PMP_REGION_INVALID;

  *entry_count = required;
  return SBI_ERR_SM_PMP_SUCCESS;
}

int pmp_cache_napot_entry(region_id region_idx, uintptr_t addr, uint64_t size,
                          uint8_t perm,
                          struct keystone_pmp_cached_entry* entry)
{
  int reg_idx;
  uintptr_t pmpaddr;

  if (!entry || !is_pmp_region_valid(region_idx) ||
      region_needs_two_entries(region_idx))
    return SBI_ERR_SM_PMP_REGION_INVALID;
  if (!(size == -1UL && addr == 0) &&
      (!size || (size & (size - 1)) || (addr & (size - 1)) ||
       (size & (RISCV_PGSIZE - 1)) || (addr & (RISCV_PGSIZE - 1))))
    return SBI_ERR_SM_PMP_REGION_SIZE_INVALID;

  reg_idx = region_register_idx(region_idx);
  pmpaddr = addr == 0 && size == -1UL ?
      -1UL : (addr | (size / 2 - 1)) >> 2;
  return pmp_cached_entry_set(
      entry, reg_idx, pmpaddr, PMP_A_NAPOT | (perm & PMP_ALL_PERM));
}

int pmp_cache_tor_entries(region_id region_idx, uintptr_t addr, uint64_t size,
                          uint8_t perm,
                          struct keystone_pmp_cached_entry* entries,
                          size_t entry_capacity, size_t* entry_count)
{
  uintptr_t end;
  uintptr_t region_end;
  int reg_idx;

  if (entry_count)
    *entry_count = 0;
  if (!entries || !entry_count || entry_capacity < 2 ||
      !is_pmp_region_valid(region_idx) || !region_is_tor(region_idx) ||
      !size || (addr & (RISCV_PGSIZE - 1)) ||
      (size & (RISCV_PGSIZE - 1)) || CHECKED_ADD(addr, size, &end) ||
      CHECKED_ADD(region_get_addr(region_idx),
                  region_get_size(region_idx), &region_end) ||
      addr < region_get_addr(region_idx) || end > region_end)
    return SBI_ERR_SM_PMP_REGION_SIZE_INVALID;

  reg_idx = region_register_idx(region_idx);
  if (reg_idx <= 0 || reg_idx >= KEYSTONE_PMP_HW_ENTRY_COUNT)
    return SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED;
  if (pmp_cached_entry_set(&entries[0], reg_idx - 1, addr >> 2, 0) ||
      pmp_cached_entry_set(&entries[1], reg_idx, end >> 2,
                           PMP_A_TOR | (perm & PMP_ALL_PERM)))
    return SBI_ERR_SM_PMP_REGION_INVALID;
  *entry_count = 2;
  return SBI_ERR_SM_PMP_SUCCESS;
}

static int pmp_write_cached_addr(unsigned int slot, uintptr_t addr)
{
  switch (slot) {
    case 0: asm volatile("csrw pmpaddr0, %0" :: "r"(addr)); break;
    case 1: asm volatile("csrw pmpaddr1, %0" :: "r"(addr)); break;
    case 2: asm volatile("csrw pmpaddr2, %0" :: "r"(addr)); break;
    case 3: asm volatile("csrw pmpaddr3, %0" :: "r"(addr)); break;
    case 4: asm volatile("csrw pmpaddr4, %0" :: "r"(addr)); break;
    case 5: asm volatile("csrw pmpaddr5, %0" :: "r"(addr)); break;
    case 6: asm volatile("csrw pmpaddr6, %0" :: "r"(addr)); break;
    case 7: asm volatile("csrw pmpaddr7, %0" :: "r"(addr)); break;
    default: return SBI_ERR_SM_PMP_REGION_INVALID;
  }
  return SBI_ERR_SM_PMP_SUCCESS;
}

static int pmp_apply_cached_entries_internal(
    const struct keystone_pmp_cached_entry* entries, size_t entry_count,
    int defer_tlb_fence)
{
  uintptr_t cfg0;
  unsigned int seen = 0;
  unsigned long perf_start;
  size_t i;

  if (!entries || !entry_count)
    return SBI_ERR_SM_PMP_REGION_INVALID;
  cfg0 = csr_read(pmpcfg0);
  for (i = 0; i < entry_count; i++) {
    const struct keystone_pmp_cached_entry* entry = &entries[i];
    uintptr_t shift;

    if (!entry->valid || entry->slot >= KEYSTONE_PMP_HW_ENTRY_COUNT ||
        (seen & (1U << entry->slot)))
      return SBI_ERR_SM_PMP_REGION_INVALID;
    seen |= 1U << entry->slot;
    shift = 8 * entry->slot;
    cfg0 &= ~((uintptr_t)0xff << shift);
    cfg0 |= (uintptr_t)entry->cfg << shift;
  }

  perf_start = csr_read(CSR_MCYCLE);
  for (i = 0; i < entry_count; i++) {
    const struct keystone_pmp_cached_entry* entry = &entries[i];

    if (pmp_write_cached_addr(entry->slot, entry->addr))
      return SBI_ERR_SM_PMP_REGION_INVALID;
  }

  if (defer_tlb_fence) {
    /* The following SATP restore supplies the handoff's single sfence.vma. */
    asm volatile("csrw pmpcfg0, %0\n\t"
                 "fence rw,rw"
                 :: "r"(cfg0) : "memory");
  } else {
    /* One architectural commit point for a stand-alone cached update. */
    asm volatile("csrw pmpcfg0, %0\n\t"
                 "fence rw,rw\n\t"
                 "sfence.vma\n\t"
                 "fence.i"
                 :: "r"(cfg0) : "memory");
  }
  pmp_perf_record(csr_read(CSR_MCYCLE) - perf_start);
  return SBI_ERR_SM_PMP_SUCCESS;
}

int pmp_apply_cached_entries(
    const struct keystone_pmp_cached_entry* entries, size_t entry_count)
{
  return pmp_apply_cached_entries_internal(entries, entry_count, 0);
}

int pmp_apply_cached_entries_deferred_fence(
    const struct keystone_pmp_cached_entry* entries, size_t entry_count)
{
  return pmp_apply_cached_entries_internal(entries, entry_count, 1);
}

int pmp_unset(int region_idx)
{
  unsigned long perf_start;
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_INVALID,"Invalid PMP region index");

  pmpreg_id reg_idx = region_register_idx(region_idx);
  perf_start = csr_read(CSR_MCYCLE);
  int n=reg_idx;
  switch(n) {
#define X(n,g) case n: { PMP_UNSET(n, g); break;}
  LIST_OF_PMP_REGS
#undef X
    default:
      sm_assert(false);
  }

  if(region_needs_two_entries(region_idx))
  {
    n--;
    switch(n) {
#define X(n,g) case n: { PMP_UNSET(n,g); break; }
  LIST_OF_PMP_REGS
#undef X
    default:
      sm_assert(false);
    }
  }

  pmp_perf_record(csr_read(CSR_MCYCLE) - perf_start);
  return SBI_ERR_SM_PMP_SUCCESS;
}

int pmp_region_init_atomic(uintptr_t start, uint64_t size, enum pmp_priority priority, region_id* rid, int allow_overlap)
{
  int ret;
  spin_lock(&pmp_lock);
  ret = pmp_region_init(start, size, priority, rid, allow_overlap);
  spin_unlock(&pmp_lock);
  return ret;
}

static int tor_region_init(uintptr_t start, uint64_t size, enum pmp_priority priority, region_id* rid, int allow_overlap)
{
  pmpreg_id reg_idx = -1;
  region_id region_idx = -1;

  sm_assert(size);
  sm_assert(!(size & (RISCV_PGSIZE-1)));
  sm_assert(!(start & (RISCV_PGSIZE-1)));
  sm_assert(rid);
  
  /* Debug: Check if PMP_PRI_BOTTOM is being used with TOR mode (which is invalid) */
  if (priority == PMP_PRI_BOTTOM) {
    sbi_printf("[PMP] ERROR: tor_region_init called with PMP_PRI_BOTTOM!\n");
    sbi_printf("[PMP] This means UTM address is NOT NAPOT aligned!\n");
    sbi_printf("[PMP] start=0x%lx size=0x%lx\n", start, (unsigned long)size);
    sbi_printf("[PMP] NAPOT requires: (start %% size == 0) and (size is power of 2)\n");
  }
  sm_assert(priority != PMP_PRI_BOTTOM);

  region_idx = get_free_region_idx();
  if(region_idx < 0 || region_idx >= PMP_MAX_N_REGION)
    PMP_ERROR(SBI_ERR_SM_PMP_METADATA_EXHAUSTED, "Reached the software PMP region descriptor limit");

  *rid = region_idx;
  switch(priority)
  {
    case(PMP_PRI_ANY): {
      reg_idx = get_conseq_free_reg_idx();
      if(reg_idx < 0)
        PMP_ERROR(SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED, "No available hardware PMP entry");
      if(TEST_BIT(reg_bitmap, reg_idx) || TEST_BIT(reg_bitmap, reg_idx + 1) || reg_idx + 1 >= PMP_N_REG)
        PMP_ERROR(SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED, "Hardware PMP entry unavailable");

      break;
    }
    case(PMP_PRI_TOP): {
      sm_assert(start == 0);
      reg_idx = 0;
      if(TEST_BIT(reg_bitmap, reg_idx))
        PMP_ERROR(SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED, "Hardware PMP entry unavailable");
      break;
    }
    default: {
      sm_assert(0);
    }
  }

  // initialize the region
  region_init(region_idx, start, size, PMP_A_TOR, allow_overlap, reg_idx, 1);
  region_bitmap_set(region_idx);
  SET_BIT(reg_bitmap, reg_idx);

  if(reg_idx > 0)
    SET_BIT(reg_bitmap, reg_idx + 1);

  return SBI_ERR_SM_PMP_SUCCESS;
}

static int napot_region_init(uintptr_t start, uint64_t size, enum pmp_priority priority, region_id* rid, int allow_overlap)
{
  pmpreg_id reg_idx = -1;
  region_id region_idx = -1;

  sm_assert(size);
  sm_assert(rid);

  if(!(size == -1UL && start == 0))
  {
    sm_assert(!(size & (size-1)));
    sm_assert(!(start & (size - 1)));
    sm_assert(!(size & (RISCV_PGSIZE-1)));
    sm_assert(!(start & (RISCV_PGSIZE-1)));
  }

  //find avaiable pmp region idx
  region_idx = get_free_region_idx();
  if(region_idx < 0 || region_idx >= PMP_MAX_N_REGION)
    PMP_ERROR(SBI_ERR_SM_PMP_METADATA_EXHAUSTED, "Reached the software PMP region descriptor limit");

  *rid = region_idx;

  switch(priority)
  {
    case(PMP_PRI_ANY): {
      reg_idx = get_free_reg_idx();
      if(reg_idx < 0)
        PMP_ERROR(SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED, "No available hardware PMP entry");
      if(TEST_BIT(reg_bitmap, reg_idx) || reg_idx >= PMP_N_REG)
        PMP_ERROR(SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED, "Hardware PMP entry unavailable");
      break;
    }
    case(PMP_PRI_TOP): {
      reg_idx = 0;
      if(TEST_BIT(reg_bitmap, reg_idx))
        PMP_ERROR(SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED, "Hardware PMP entry unavailable");
      break;
    }
    case(PMP_PRI_BOTTOM): {
      /* the bottom register can be used by multiple regions,
       * so we don't check its availability */
      reg_idx = PMP_N_REG - 1;
      break;
    }
    default: {
      sm_assert(0);
    }
  }

  // initialize the region
  region_init(region_idx, start, size, PMP_A_NAPOT, allow_overlap, reg_idx,
              priority != PMP_PRI_BOTTOM);
  region_bitmap_set(region_idx);
  SET_BIT(reg_bitmap, reg_idx);

  return SBI_ERR_SM_PMP_SUCCESS;
}

int pmp_region_free_atomic(int region_idx)
{

  spin_lock(&pmp_lock);

  if(!is_pmp_region_valid(region_idx))
  {
    spin_unlock(&pmp_lock);
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_INVALID, "Invalid PMP region index");
  }

  pmpreg_id reg_idx = region_register_idx(region_idx);
  region_bitmap_unset(region_idx);
  if (regions[region_idx].owns_reg) {
    UNSET_BIT(reg_bitmap, reg_idx);
    if(region_needs_two_entries(region_idx))
      UNSET_BIT(reg_bitmap, reg_idx - 1);
  }

  region_clear_all(region_idx);

  spin_unlock(&pmp_lock);

  return SBI_ERR_SM_PMP_SUCCESS;
}

int pmp_region_init(uintptr_t start, uint64_t size, enum pmp_priority priority, int* rid, int allow_overlap)
{
  if(!size)
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_SIZE_INVALID, "Invalid PMP size");

  /* overlap detection */
  if (!allow_overlap) {
    if (detect_region_overlap(start, size)) {
      return SBI_ERR_SM_PMP_REGION_OVERLAP;
    }
  }

  /* PMP granularity check */
  if(size != -1UL && (size & (RISCV_PGSIZE - 1)))
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_NOT_PAGE_GRANULARITY, "PMP granularity is RISCV_PGSIZE");
  if(start & (RISCV_PGSIZE - 1))
    PMP_ERROR(SBI_ERR_SM_PMP_REGION_NOT_PAGE_GRANULARITY, "PMP granularity is RISCV_PGSIZE");

  /* Debug: Print NAPOT check details */
  // int is_full_ram = (size == -1UL && start == 0);
  // int is_power_of_2 = !(size & (size - 1));
  // int is_aligned = !(start & (size - 1));
  // sbi_printf("[PMP] pmp_region_init: start=0x%lx size=0x%lx priority=%d\n", start, (unsigned long)size, priority);
  // sbi_printf("[PMP] NAPOT check: full_ram=%d power_of_2=%d aligned=%d\n", is_full_ram, is_power_of_2, is_aligned);

  /* if the address covers the entire RAM or it's NAPOT */
  if ((size == -1UL && start == 0) ||
      (!(size & (size - 1)) && !(start & (size - 1)))) {
    // sbi_printf("[PMP] Using NAPOT mode\n");
    return napot_region_init(start, size, priority, rid, allow_overlap);
  }
  else
  {
    // sbi_printf("[PMP] Using TOR mode (priority=%d)\n", priority);
    if(priority != PMP_PRI_ANY &&
      (priority != PMP_PRI_TOP || start != 0)) {
      PMP_ERROR(SBI_ERR_SM_PMP_REGION_IMPOSSIBLE_TOR, "The top-priority TOR PMP entry must start from address 0");
    }

    return tor_region_init(start, size, priority, rid, allow_overlap);
  }
}

int pmp_region_init_fixed_atomic(uintptr_t start, uint64_t size,
                                 int first_slot, int slot_count,
                                 region_id* rid, int allow_overlap)
{
  int ret = SBI_ERR_SM_PMP_SUCCESS;
  int region_idx;
  int napot;

  spin_lock(&pmp_lock);
  if (!size || !rid || first_slot < 0 || slot_count <= 0 ||
      first_slot + slot_count > PMP_N_REG ||
      !((first_slot == KEYSTONE_PMP_SLOT_GROUP_EPM_LO && slot_count == 2) ||
        (first_slot == KEYSTONE_PMP_SLOT_YXSTM_LO && slot_count == 2) ||
        (first_slot == KEYSTONE_PMP_SLOT_SEC_LO && slot_count == 2)) ||
      (size != -1UL && (size & (RISCV_PGSIZE - 1))) ||
      (start & (RISCV_PGSIZE - 1))) {
    ret = SBI_ERR_SM_PMP_REGION_SIZE_INVALID;
    goto out;
  }
  if (!allow_overlap && detect_region_overlap(start, size)) {
    ret = SBI_ERR_SM_PMP_REGION_OVERLAP;
    goto out;
  }
  region_idx = get_free_region_idx();
  if (region_idx < 0 || region_idx >= PMP_MAX_N_REGION) {
    ret = SBI_ERR_SM_PMP_METADATA_EXHAUSTED;
    goto out;
  }

  napot = (size == -1UL && start == 0) ||
          (!(size & (size - 1)) && !(start & (size - 1)));
  /* YXSTM must remain a TOR pair so arbitrary page-aligned slots can reuse it. */
  if (first_slot == KEYSTONE_PMP_SLOT_YXSTM_LO)
    napot = 0;
  if (!napot && slot_count < 2) {
    ret = SBI_ERR_SM_PMP_REGION_IMPOSSIBLE_TOR;
    goto out;
  }

  region_init(region_idx, start, size,
              napot ? PMP_A_NAPOT : PMP_A_TOR,
              allow_overlap, first_slot, 0);
  region_bitmap_set(region_idx);
  *rid = region_idx;
out:
  spin_unlock(&pmp_lock);
  return ret;
}

static int pmp_range_entry_count(uintptr_t start, uint64_t size)
{
  if (!size || (size != -1UL && (size & (RISCV_PGSIZE - 1))) ||
      (start & (RISCV_PGSIZE - 1)))
    return -1;
  if ((size == -1UL && start == 0) ||
      (!(size & (size - 1)) && !(start & (size - 1))))
    return 1;
  return 2;
}

int pmp_group_preflight(uintptr_t epm_base, uint64_t epm_size,
                        uintptr_t yxstm_base, uint64_t yxstm_size,
                        uintptr_t sec_base, uint64_t sec_size,
                        struct keystone_pmp_budget* budget)
{
  int epm_entries = pmp_range_entry_count(epm_base, epm_size);
  int yxstm_entries = yxstm_size ?
      pmp_range_entry_count(yxstm_base, yxstm_size) : 0;
  int sec_entries = sec_size ?
      pmp_range_entry_count(sec_base, sec_size) : 0;
  int total;

  if (!budget || PMP_N_REG != KEYSTONE_PMP_HW_ENTRY_COUNT ||
      epm_entries < 1 || epm_entries > 2 ||
      yxstm_entries < 0 || yxstm_entries > 2 ||
      sec_entries < 0 || sec_entries > 2)
    return SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED;

  budget->sm_entries = 1;
  budget->epm_entries = (uint8_t)epm_entries;
  budget->yxstm_entries = yxstm_size ? 2 : 0;
  budget->sec_entries = (uint8_t)sec_entries;
  budget->os_utm_entries = 1;
  budget->reserved_entries = (uint8_t)((2 - epm_entries) +
                                       (2 - sec_entries));
  total = budget->sm_entries + budget->epm_entries +
          budget->yxstm_entries + budget->sec_entries +
          budget->os_utm_entries + budget->reserved_entries;
  budget->total_entries = (uint8_t)total;
  budget->hardware_entries = PMP_N_REG;
  if (total > PMP_N_REG)
    return SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED;
  return SBI_ERR_SM_PMP_SUCCESS;
}

int pmp_mask_is_contiguous(uintptr_t mask)
{
  if (!mask)
    return 0;
  while (!(mask & 1))
    mask >>= 1;
  while (mask & 1)
    mask >>= 1;
  return mask == 0;
}

void pmp_clear_dynamic_slots(void)
{
  int slot;

  for (slot = KEYSTONE_PMP_SLOT_GROUP_EPM_LO;
       slot <= KEYSTONE_PMP_SLOT_DYNAMIC_END && slot < PMP_N_REG;
       slot++) {
    switch (slot) {
#define X(n,g) case n: { PMP_UNSET(n, g); break; }
      LIST_OF_PMP_REGS
#undef X
      default: break;
    }
  }
}

static uintptr_t pmp_read_addr_slot(int slot)
{
  switch (slot) {
#define X(n,g) case n: return csr_read(pmpaddr##n);
    LIST_OF_PMP_REGS
#undef X
    default: return 0;
  }
}

static uint8_t pmp_read_cfg_slot(int slot)
{
#if __riscv_xlen == 64
  uintptr_t cfg = slot < 8 ? csr_read(pmpcfg0) : csr_read(pmpcfg2);
  return (uint8_t)((cfg >> (8 * (slot % 8))) & 0xff);
#else
  uintptr_t cfg;
  switch (slot / 4) {
    case 0: cfg = csr_read(pmpcfg0); break;
    case 1: cfg = csr_read(pmpcfg1); break;
    case 2: cfg = csr_read(pmpcfg2); break;
    default: cfg = csr_read(pmpcfg3); break;
  }
  return (uint8_t)((cfg >> (8 * (slot % 4))) & 0xff);
#endif
}

int pmp_region_readback_matches(region_id region, uint8_t perm)
{
  int reg;
  uint8_t expected_cfg;

  if (!is_pmp_region_valid(region))
    return 0;
  reg = region_register_idx(region);
  expected_cfg = (uint8_t)(regions[region].addrmode |
                           (perm & PMP_ALL_PERM));
  if (pmp_read_cfg_slot(reg) != expected_cfg ||
      pmp_read_addr_slot(reg) != region_pmpaddr_val(region))
    return 0;
  if (region_needs_two_entries(region) &&
      (pmp_read_cfg_slot(reg - 1) != 0 ||
       pmp_read_addr_slot(reg - 1) != (regions[region].addr >> 2)))
    return 0;
  return 1;
}

int pmp_dynamic_slots_are_clear(void)
{
  int slot;
  for (slot = KEYSTONE_PMP_SLOT_GROUP_EPM_LO;
       slot <= KEYSTONE_PMP_SLOT_DYNAMIC_END && slot < PMP_N_REG;
       slot++) {
    if (pmp_read_cfg_slot(slot) != 0 || pmp_read_addr_slot(slot) != 0)
      return 0;
  }
  return 1;
}

uintptr_t pmp_region_get_addr(region_id i)
{
  if(is_pmp_region_valid(i))
    return region_get_addr(i);
  return 0;
}

uint64_t pmp_region_get_size(region_id i)
{
  if(is_pmp_region_valid(i))
    return region_get_size(i);
  return 0;
}

int pmp_region_get_reg_idx(region_id i)
{
  if (is_pmp_region_valid(i))
    return region_register_idx(i);
  return -1;
}

int pmp_region_get_entry_count(region_id i)
{
  if (!is_pmp_region_valid(i))
    return 0;
  return region_needs_two_entries(i) ? 2 : 1;
}

static const char* pmp_slot_owner(int slot)
{
  switch (slot) {
    case KEYSTONE_PMP_SLOT_SM: return "sm";
    case KEYSTONE_PMP_SLOT_GROUP_EPM_LO: return "group-epm-lo";
    case KEYSTONE_PMP_SLOT_GROUP_EPM_HI: return "group-epm-hi";
    case KEYSTONE_PMP_SLOT_YXSTM_LO: return "yxstm-lo";
    case KEYSTONE_PMP_SLOT_YXSTM_HI: return "yxstm-hi";
    case KEYSTONE_PMP_SLOT_SEC_LO: return "sec-lo";
    case KEYSTONE_PMP_SLOT_SEC_HI: return "sec-hi";
    case KEYSTONE_PMP_SLOT_OS_UTM: return "os-utm";
    default: return "unassigned";
  }
}

void pmp_debug_dump_hart(const char* where)
{
  uintptr_t cfg;
  int slot;

#if __riscv_xlen == 64
  cfg = csr_read(pmpcfg0);
#else
  cfg = 0;
#endif
  sbi_printf("[SM][pmp] dump: hart=%lu where=%s hw_entries=%d metadata_regions=%d cfg0=0x%lx\n",
             (unsigned long)current_hartid(), where ? where : "unknown",
             PMP_N_REG, PMP_MAX_N_REGION, (unsigned long)cfg);
  for (slot = 0; slot < PMP_N_REG && slot < KEYSTONE_PMP_HW_ENTRY_COUNT;
       slot++) {
    uintptr_t addr = 0;
    switch (slot) {
#define X(n,g) case n: addr = csr_read(pmpaddr##n); break;
      LIST_OF_PMP_REGS
#undef X
      default: break;
    }
#if __riscv_xlen == 64
    sbi_printf("[SM][pmp] slot=%d owner=%s cfg=0x%lx addr=0x%lx\n",
               slot, pmp_slot_owner(slot),
               (unsigned long)((cfg >> (8 * slot)) & 0xff),
               (unsigned long)addr);
#else
    sbi_printf("[SM][pmp] slot=%d owner=%s addr=0x%lx\n",
               slot, pmp_slot_owner(slot), (unsigned long)addr);
#endif
  }
}
