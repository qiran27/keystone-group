#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include <stdint.h>

#define PLATFORM_HAS_SEC 1

struct enclave;
struct keystone_sec_query;

struct platform_enclave_data{
  uintptr_t sec_mmio_base;
  uintptr_t sec_mmio_size;
  uint32_t sec_engine_id;
  uint32_t sec_flags;
  int sec_owned;
};

unsigned long platform_sec_acquire(struct enclave* enclave, uintptr_t engine_id, uintptr_t timeout_cycles);
unsigned long platform_sec_release(struct enclave* enclave);
unsigned long platform_sec_query(struct enclave* enclave, struct keystone_sec_query* out_info);

// Enclave configuration
#define ENCL_MAX                65
#define ENCLAVE_REGIONS_MAX     8

// SM configuration
#define SMM_BASE                0x80000000
#define SMM_SIZE                0x200000

// PMP configuration
/* Per-hart hardware CSR entries implemented by JH7110. */
#define PMP_N_REG               8
/* SM software descriptors; group members reuse the fixed per-hart CSR slots. */
#define PMP_MAX_N_REGION        96

// CPU configuration
#define MAX_HARTS               5


// Initialization functions
void sm_copy_key(void);

#endif // _PLATFORM_H_
