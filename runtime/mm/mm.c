#include "mm/common.h"
#include "mm/mm.h"
#include "mm/vm.h"
#include "mm/freemem.h"
#include "mm/paging.h"

/* Page table utilities */
static pte*
__walk_create(pte* root, uintptr_t addr);

static pte*
__walk_create_to_level(pte* root, uintptr_t addr, int target_level)
{
  pte* table = root;
  int level;

  if (target_level < 1 || target_level > RISCV_PT_LEVELS)
    return 0;

  for (level = 1; level < target_level; level++) {
    size_t index = RISCV_GET_PT_INDEX(addr, level);

    if (!(table[index] & PTE_V)) {
      uintptr_t new_page = spa_get_zero();
      if (!new_page)
        return 0;
      table[index] = ptd_create(ppn(__pa(new_page)));
    } else if (table[index] & (PTE_R | PTE_W | PTE_X)) {
      return 0;
    }
    table = (pte*)__va(pte_ppn(table[index]) << RISCV_PAGE_BITS);
  }

  return &table[RISCV_GET_PT_INDEX(addr, target_level)];
}

/* Hacky storage of current u-mode break */
static uintptr_t current_program_break;
static int group_page_table_policy_active;

static inline void
runtime_sfence_vma(void)
{
  __asm__ __volatile__("sfence.vma" ::: "memory");
}

/*
 * Group enclaves use the measured-runtime trust model.  Every runtime leaf-PTE
 * update is re-audited by the SM and rolled back if it widens the member view.
 */
uintptr_t
group_page_table_policy_audit(void)
{
  if (!group_page_table_policy_active)
    return 0;
  return sbi_group_validate_page_table(__pa((uintptr_t)root_page_table));
}

void
group_page_table_policy_enable(void)
{
  group_page_table_policy_active = 1;
}

uintptr_t get_program_break()
{
  return current_program_break;
}

void set_program_break(uintptr_t new_break)
{
  current_program_break = new_break;
}

static pte*
__continue_walk_create(pte* root, uintptr_t addr, pte* pte)
{
  uintptr_t new_page = spa_get_zero();
  assert(new_page);

  unsigned long free_ppn = ppn(__pa(new_page));
  *pte = ptd_create(free_ppn);
  return __walk_create(root, addr);
}

static pte*
__walk_internal(pte* root, uintptr_t addr, int create)
{
  pte* t = root;
  int i;
  for (i = 1; i < RISCV_PT_LEVELS; i++)
  {
    size_t idx = RISCV_GET_PT_INDEX(addr, i);

    if (!(t[idx] & PTE_V))
      return create ? __continue_walk_create(root, addr, &t[idx]) : 0;

    /* 
     * CRITICAL FIX (2026-01-07): Check for leaf PTE (megapage/gigapage)
     * 
     * In RISC-V, if a PTE has PTE_V set AND any of PTE_R/W/X set,
     * it's a leaf PTE (large page mapping). We should NOT continue
     * walking the page table in this case.
     * 
     * Without this check, when encountering a megapage mapping for
     * shared UTM (PA 0x98000000), the code would try to use __va()
     * to convert the megapage's PA as if it were a page table address.
     * This causes page fault when PA < load_pa_start.
     */
    if (t[idx] & (PTE_R | PTE_W | PTE_X)) {
      /* This is a leaf PTE (megapage or gigapage), return it */
      return &t[idx];
    }

    t = (pte*) __va(pte_ppn(t[idx]) << RISCV_PAGE_BITS);
  }

  return &t[RISCV_GET_PT_INDEX(addr, RISCV_PT_LEVELS)];
}

/* walk the page table and return PTE
 * return 0 if no mapping exists */
static pte*
__walk(pte* root, uintptr_t addr)
{
  return __walk_internal(root, addr, 0);
}

/* walk the page table and return PTE
 * create the mapping if non exists */
static pte*
__walk_create(pte* root, uintptr_t addr)
{
  return __walk_internal(root, addr, 1);
}

/* Create a virtual memory mapping between a physical and virtual page */
uintptr_t 
map_page(uintptr_t vpn, uintptr_t ppn, int flags)
{
  pte* entry = __walk_create(root_page_table, vpn << RISCV_PAGE_BITS);
  pte old_pte;

  if (!entry)
    return -1;

  // TODO: what is supposed to happen if page is already allocated?
  if (*entry & PTE_V) {
    return -1;
  }

  old_pte = *entry;
  *entry = pte_create(ppn, PTE_D | PTE_A | PTE_V | flags);
  runtime_sfence_vma();
  if (group_page_table_policy_audit()) {
    *entry = old_pte;
    runtime_sfence_vma();
    return -1;
  }
  return 1;
}

/* Map one Sv39 2 MiB leaf (or one Sv32 4 MiB leaf). */
uintptr_t
map_large_page(uintptr_t va, uintptr_t pa, int flags)
{
  const int level = RISCV_PT_LEVELS - 1;
  pte* entry;
  pte old_pte;

  if (level < 1 || !IS_ALIGNED(va, RISCV_GET_LVL_PGSIZE_BITS(level)) ||
      !IS_ALIGNED(pa, RISCV_GET_LVL_PGSIZE_BITS(level)))
    return -1;

  entry = __walk_create_to_level(root_page_table, va, level);
  if (!entry || (*entry & PTE_V))
    return -1;

  old_pte = *entry;
  *entry = pte_create(ppn(pa), PTE_D | PTE_A | PTE_V | flags);
  runtime_sfence_vma();
  if (group_page_table_policy_audit()) {
    *entry = old_pte;
    runtime_sfence_vma();
    return -1;
  }
  return 1;
}

/* allocate a new page to a given vpn
 * returns VA of the page, (returns 0 if fails) */
uintptr_t
alloc_page(uintptr_t vpn, int flags)
{
  uintptr_t page;
  pte* pte = __walk_create(root_page_table, vpn << RISCV_PAGE_BITS);

  if (!pte)
    return 0;

	/* if the page has been already allocated, return the page */
  if(*pte & PTE_V) {
    return __va(*pte << RISCV_PAGE_BITS);
  }

	/* otherwise, allocate one from the freemem */
  page = spa_get_zero();
  assert(page);

  *pte = pte_create(ppn(__pa(page)), PTE_D | PTE_A | PTE_V | flags);
  runtime_sfence_vma();
  if (group_page_table_policy_audit()) {
    *pte = 0;
    runtime_sfence_vma();
    spa_put(page);
    return 0;
  }
#ifdef USE_PAGING
  paging_inc_user_page();
#endif

  return page;
}

uintptr_t
realloc_page(uintptr_t vpn, int flags)
{
  pte old_pte;
  assert(flags & PTE_U);

  pte *pte = __walk(root_page_table, vpn << RISCV_PAGE_BITS);
  if(!pte)
    return 0;

  if(*pte & PTE_V) {
    old_pte = *pte;
    *pte = pte_create(pte_ppn(*pte), flags);
    runtime_sfence_vma();
    if (group_page_table_policy_audit()) {
      *pte = old_pte;
      runtime_sfence_vma();
      return 0;
    }
    return __va(*pte << RISCV_PAGE_BITS);
  }

  return 0;
}

void
free_page(uintptr_t vpn)
{
  pte* entry = __walk(root_page_table, vpn << RISCV_PAGE_BITS);

  // No such PTE, or invalid
  if(!entry || !(*entry & PTE_V))
    return;

  assert(*entry & PTE_U);

  uintptr_t ppn = pte_ppn(*entry);
  pte old_pte = *entry;
  // Mark invalid
  // TODO maybe do more here
  *entry = 0;
  runtime_sfence_vma();
  if (group_page_table_policy_audit()) {
    *entry = old_pte;
    runtime_sfence_vma();
    return;
  }

#ifdef USE_PAGING
  paging_dec_user_page();
#endif
  // Return phys page
  spa_put(__va(ppn << RISCV_PAGE_BITS));

  return;

}

/* allocate n new pages from a given vpn
 * returns the number of pages allocated */
size_t
alloc_pages(uintptr_t vpn, size_t count, int flags)
{
  unsigned int i;
  for (i = 0; i < count; i++) {
    if(!alloc_page(vpn + i, flags))
      break;
  }

  return i;
}

void
free_pages(uintptr_t vpn, size_t count){
  unsigned int i;
  for (i = 0; i < count; i++) {
    free_page(vpn + i);
  }

}

/*
 * Check if a range of VAs contains any allocated pages, starting with
 * the given VA. Returns the number of sequential pages that meet the
 * conditions.
 */
size_t
test_va_range(uintptr_t vpn, size_t count){

  unsigned int i;
  /* Validate the region */
  for (i = 0; i < count; i++) {
    pte* pte = __walk_internal(root_page_table, (vpn+i) << RISCV_PAGE_BITS, 0);
    // If the page exists and is valid then we cannot use it
    if(pte && *pte){
      break;
    }
  }
  return i;
}

/* get a mapped physical address for a VA */
uintptr_t
translate(uintptr_t va)
{
  pte* pte = __walk(root_page_table, va);

  if(pte && (*pte & PTE_V))
    return (pte_ppn(*pte) << RISCV_PAGE_BITS) | (RISCV_PAGE_OFFSET(va));
  else
    return 0;
}

/* try to retrieve PTE for a VA, return 0 if fail */
pte*
pte_of_va(uintptr_t va)
{
  pte* pte = __walk(root_page_table, va);
  return pte;
}


void
__map_with_reserved_page_table_32(uintptr_t dram_base,
                               uintptr_t dram_size,
                               uintptr_t ptr,
                               pte* l2_pt)
{
  uintptr_t offset = 0;
  uintptr_t leaf_level = 2;
  pte* leaf_pt = l2_pt;
  unsigned long dram_max =  RISCV_GET_LVL_PGSIZE(leaf_level - 1);

  /* use megapage if l2_pt is null */
  if (!l2_pt) {
    leaf_level = 1;
    leaf_pt = root_page_table;
    dram_max = -1UL; 
  }

  assert(dram_size <= dram_max);
  assert(IS_ALIGNED(dram_base, RISCV_GET_LVL_PGSIZE_BITS(leaf_level)));
  assert(IS_ALIGNED(ptr, RISCV_GET_LVL_PGSIZE_BITS(leaf_level - 1)));

  if(l2_pt) {
       /* set root page table entry */
       root_page_table[RISCV_GET_PT_INDEX(ptr, 1)] =
       ptd_create(ppn(kernel_va_to_pa(l2_pt)));
  }

  for (offset = 0;
       offset < dram_size;
       offset += RISCV_GET_LVL_PGSIZE(leaf_level))
  {
        leaf_pt[RISCV_GET_PT_INDEX(ptr + offset, leaf_level)] =
        pte_create(ppn(dram_base + offset),
                 PTE_R | PTE_W | PTE_X | PTE_A | PTE_D);
  }

}

void
__map_with_reserved_page_table_64(uintptr_t dram_base,
                               uintptr_t dram_size,
                               uintptr_t ptr,
                               pte* l2_pt,
                               pte* l3_pt)
{
  uintptr_t offset = 0;
  uintptr_t leaf_level = 3;
  pte* leaf_pt = l3_pt;
  /* use megapage if l3_pt is null */
  if (!l3_pt) {
    leaf_level = 2;
    leaf_pt = l2_pt;
  }
  assert(dram_size <= RISCV_GET_LVL_PGSIZE(leaf_level - 1));
  assert(IS_ALIGNED(dram_base, RISCV_GET_LVL_PGSIZE_BITS(leaf_level)));
  assert(IS_ALIGNED(ptr, RISCV_GET_LVL_PGSIZE_BITS(leaf_level - 1)));

  /* set root page table entry */
  root_page_table[RISCV_GET_PT_INDEX(ptr, 1)] =
    ptd_create(ppn(kernel_va_to_pa(l2_pt)));

  /* set L2 if it's not leaf */
  if (leaf_pt != l2_pt) {
    l2_pt[RISCV_GET_PT_INDEX(ptr, 2)] =
      ptd_create(ppn(kernel_va_to_pa(l3_pt)));
  }

  /* set leaf level */
  for (offset = 0;
       offset < dram_size;
       offset += RISCV_GET_LVL_PGSIZE(leaf_level))
  {
    leaf_pt[RISCV_GET_PT_INDEX(ptr + offset, leaf_level)] =
      pte_create(ppn(dram_base + offset),
          PTE_R | PTE_W | PTE_X | PTE_A | PTE_D);
  }

}

void
map_with_reserved_page_table(uintptr_t dram_base,
                             uintptr_t dram_size,
                             uintptr_t ptr,
                             pte* l2_pt,
                             pte* l3_pt)
{
  #if __riscv_xlen == 64
  if (dram_size > RISCV_GET_LVL_PGSIZE(2))
    __map_with_reserved_page_table_64(dram_base, dram_size, ptr, l2_pt, 0);
  else
    __map_with_reserved_page_table_64(dram_base, dram_size, ptr, l2_pt, l3_pt);
  #elif __riscv_xlen == 32
  if (dram_size > RISCV_GET_LVL_PGSIZE(1))
    __map_with_reserved_page_table_32(dram_base, dram_size, ptr, 0);
  else
    __map_with_reserved_page_table_32(dram_base, dram_size, ptr, l2_pt);
  #endif
}
