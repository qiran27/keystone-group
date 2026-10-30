#ifndef __VM_H__
#define __VM_H__

#include "mm/common.h"
#include "util/printf.h"
#include "mm/vm_defs.h"

extern uintptr_t runtime_va_start;

/* root page table */
extern pte* root_page_table;

uintptr_t kernel_va_to_pa(void* ptr);
uintptr_t __va(uintptr_t pa);
uintptr_t __pa(uintptr_t va);

#ifndef LOADER_BIN

extern void* rt_base;
extern uintptr_t kernel_offset; // TODO: is this needed?
extern uintptr_t load_pa_start;
extern uintptr_t private_region_va_start;
extern uintptr_t private_region_size;

/* Program break */
extern uintptr_t program_break;

/* freemem */
extern uintptr_t freemem_va_start;
extern size_t freemem_size;

/* shared buffer */
extern uintptr_t shared_buffer;
extern uintptr_t shared_buffer_size;

/* OCALL buffer - always points to enclave's own UTM for edge_call communication
 * In shared UTM mode, shared_buffer points to Main's 64MB UTM for data transfer,
 * while ocall_buffer points to Slave's own 1MB UTM for OCALL communication.
 * In regular mode, both point to the same UTM.
 */
extern uintptr_t ocall_buffer;
extern uintptr_t ocall_buffer_size;

/* YX share trusted memory */
extern uintptr_t YXS_trusted_memory;
extern uintptr_t YXS_trusted_memory_size;

/* SEC MMIO mapping */
extern uintptr_t sec_mmio_base;
extern uintptr_t sec_mmio_size;

extern unsigned char kg[64];

/* test other enclave access epm */
extern uintptr_t test_other_enclave_access_epm;
// // morenzhixuyao8B
// extern uintptr_t test_other_enclave_access_epm_size;

#endif

static inline pte pte_create(uintptr_t ppn, int type)
{
  return (pte)((ppn << PTE_PPN_SHIFT) | PTE_V | (type & PTE_FLAG_MASK) );
}

static inline pte pte_create_invalid(uintptr_t ppn, int type)
{
  return (pte)((ppn << PTE_PPN_SHIFT) | (type & PTE_FLAG_MASK & ~PTE_V));
}

static inline pte ptd_create(uintptr_t ppn)
{
  return pte_create(ppn, PTE_V);
}

static inline uintptr_t ppn(uintptr_t pa)
{
  return pa >> RISCV_PAGE_BITS;
}

// this is identical to ppn, but separate it to avoid confusion between va/pa
static inline uintptr_t vpn(uintptr_t va)
{
  return va >> RISCV_PAGE_BITS;
}

static inline uintptr_t pte_ppn(pte pte)
{
  return pte >> PTE_PPN_SHIFT;
}

#endif
