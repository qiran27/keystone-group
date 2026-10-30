#include <stddef.h>
#include <stdint.h>
#include "mm/vm.h"

uintptr_t runtime_va_start;

/* root page table */
pte* root_page_table;

#ifdef LOADER_BIN

/* no-ops */

uintptr_t kernel_va_to_pa(void* ptr)
{
  return (uintptr_t) ptr;
}

uintptr_t __va(uintptr_t pa)
{
  return pa;
}

uintptr_t __pa(uintptr_t va)
{
  return va;
}

#else // !LOADER_BIN

uintptr_t kernel_va_to_pa(void* ptr)
{
  return (uintptr_t) ptr - kernel_offset;
}

uintptr_t __va(uintptr_t pa)
{
  return (pa - load_pa_start) + EYRIE_LOAD_START;
}

uintptr_t __pa(uintptr_t va)
{
  return (va - EYRIE_LOAD_START) + load_pa_start;
}

/* Program break */
uintptr_t program_break;

/* freemem */
uintptr_t freemem_va_start;
size_t freemem_size;

/* shared buffer */
uintptr_t shared_buffer;
uintptr_t shared_buffer_size;

/* OCALL buffer - always points to enclave's own UTM for edge_call communication
 * In shared UTM mode, shared_buffer points to Main's 64MB UTM for data transfer,
 * while ocall_buffer points to Slave's own 1MB UTM for OCALL communication.
 * In regular mode, both point to the same UTM.
 */
uintptr_t ocall_buffer;
uintptr_t ocall_buffer_size;

/* YX share trusted memory */
uintptr_t YXS_trusted_memory;
uintptr_t YXS_trusted_memory_size;

/* SEC MMIO mapping */
uintptr_t sec_mmio_base;
uintptr_t sec_mmio_size;

unsigned char kg[64] = {0,};

/* test other enclave access epm */
uintptr_t test_other_enclave_access_epm;
// // morenzhixuyao8B
// extern uintptr_t test_other_enclave_access_epm_size;

uintptr_t kernel_offset;
uintptr_t load_pa_start;
uintptr_t private_region_va_start;
uintptr_t private_region_size;

#endif // LOADER_BIN
