/* Default platform hooks, with VisionFive2 SEC support enabled through
 * TARGET_PLATFORM_HEADER when the build selects starfive/visionfive2.
 */
#include "../../enclave.h"
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_string.h>

#ifndef PLATFORM_HAS_SEC
#define PLATFORM_HAS_SEC 0
#endif

#if PLATFORM_HAS_SEC
static spinlock_t sec_lock = SPIN_LOCK_INITIALIZER;
static enclave_id sec_owner_eid = (enclave_id)-1;
static uintptr_t sec_owner_engine_id = 0;

static int platform_sec_region_index(struct enclave* enclave)
{
  return get_enclave_region_index(enclave->eid, REGION_OTHER);
}

static void platform_apply_sec_pmp(struct enclave* enclave, uint8_t perm)
{
  int memid = platform_sec_region_index(enclave);
  if (memid >= 0)
    pmp_set_keystone(enclave->regions[memid].pmp_rid, perm);
}
#endif

unsigned long platform_init_global_once(){
#if PLATFORM_HAS_SEC
  spin_lock(&sec_lock);
  sec_owner_eid = (enclave_id)-1;
  sec_owner_engine_id = 0;
  spin_unlock(&sec_lock);
#endif
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long platform_init_global(){
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_init_enclave(struct enclave* enclave){
#if PLATFORM_HAS_SEC
  enclave->ped.sec_mmio_base = 0;
  enclave->ped.sec_mmio_size = 0;
  enclave->ped.sec_engine_id = 0;
  enclave->ped.sec_flags = 0;
  enclave->ped.sec_owned = 0;
#else
  (void)enclave;
#endif
  return;
}

void platform_destroy_enclave(struct enclave* enclave){
#if PLATFORM_HAS_SEC
  if (enclave->ped.sec_mmio_size > 0)
    platform_sec_release(enclave);
#else
  (void)enclave;
#endif
  return;
}

unsigned long platform_create_enclave(struct enclave* enclave){
#if PLATFORM_HAS_SEC
  if (enclave->ped.sec_mmio_size == 0)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (!enclave->ped.sec_mmio_base)
    return SBI_ERR_SM_SEC_NOT_CONFIGURED;
#else
  (void)enclave;
#endif
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void platform_switch_to_enclave(struct enclave* enclave){
#if PLATFORM_HAS_SEC
  if (enclave->ped.sec_mmio_size == 0)
    return;

  spin_lock(&sec_lock);
  if (enclave->ped.sec_owned && sec_owner_eid == enclave->eid)
    platform_apply_sec_pmp(enclave, PMP_ALL_PERM);
  else
    platform_apply_sec_pmp(enclave, PMP_NO_PERM);
  spin_unlock(&sec_lock);
#else
  (void)enclave;
#endif
  return;
}

void platform_switch_from_enclave(struct enclave* enclave){
#if PLATFORM_HAS_SEC
  if (enclave->ped.sec_mmio_size == 0)
    return;

  platform_apply_sec_pmp(enclave, PMP_NO_PERM);
#else
  (void)enclave;
#endif
  return;
}

unsigned long platform_sec_acquire(struct enclave* enclave, uintptr_t engine_id, uintptr_t timeout_cycles)
{
#if PLATFORM_HAS_SEC
  uintptr_t start_cycle = 0;

  if (enclave->ped.sec_mmio_size == 0)
    return SBI_ERR_SM_SEC_NOT_CONFIGURED;

  if (engine_id != 0 && engine_id != enclave->ped.sec_engine_id)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (timeout_cycles > 0)
    start_cycle = csr_read(mcycle);

  for (;;) {
    unsigned long ret = SBI_ERR_SM_SEC_BUSY;

    spin_lock(&sec_lock);
    if (sec_owner_eid == (enclave_id)-1 || sec_owner_eid == enclave->eid) {
      sec_owner_eid = enclave->eid;
      sec_owner_engine_id = enclave->ped.sec_engine_id;
      enclave->ped.sec_owned = 1;
      platform_apply_sec_pmp(enclave, PMP_ALL_PERM);
      ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    }
    spin_unlock(&sec_lock);

    if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS)
      return ret;

    if (timeout_cycles == 0)
      return ret;

    if (csr_read(mcycle) - start_cycle >= timeout_cycles)
      return ret;
  }
#else
  (void)enclave;
  (void)engine_id;
  (void)timeout_cycles;
  return SBI_ERR_SM_SEC_NOT_CONFIGURED;
#endif
}

unsigned long platform_sec_release(struct enclave* enclave)
{
#if PLATFORM_HAS_SEC
  if (enclave->ped.sec_mmio_size == 0)
    return SBI_ERR_SM_SEC_NOT_CONFIGURED;

  spin_lock(&sec_lock);
  if (sec_owner_eid == enclave->eid) {
    sec_owner_eid = (enclave_id)-1;
    sec_owner_engine_id = 0;
  }
  enclave->ped.sec_owned = 0;
  platform_apply_sec_pmp(enclave, PMP_NO_PERM);
  spin_unlock(&sec_lock);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
#else
  (void)enclave;
  return SBI_ERR_SM_SEC_NOT_CONFIGURED;
#endif
}

unsigned long platform_sec_query(struct enclave* enclave, struct keystone_sec_query* out_info)
{
#if PLATFORM_HAS_SEC
  if (!out_info)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  sbi_memset(out_info, 0, sizeof(*out_info));
  out_info->sec_base = enclave->ped.sec_mmio_base;
  out_info->sec_size = enclave->ped.sec_mmio_size;
  out_info->sec_flags = enclave->ped.sec_flags;
  out_info->sec_engine_id = enclave->ped.sec_engine_id;
  out_info->configured = enclave->ped.sec_mmio_size ? 1 : 0;

  spin_lock(&sec_lock);
  out_info->owner_eid = (sec_owner_eid == (enclave_id)-1) ? (uintptr_t)-1 : sec_owner_eid;
  out_info->owned_by_caller = (sec_owner_eid == enclave->eid) ? 1 : 0;
  out_info->busy = (sec_owner_eid != (enclave_id)-1 && sec_owner_eid != enclave->eid) ? 1 : 0;
  spin_unlock(&sec_lock);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
#else
  (void)enclave;
  if (!out_info)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  sbi_memset(out_info, 0, sizeof(*out_info));
  return SBI_ERR_SM_SEC_NOT_CONFIGURED;
#endif
}

uint64_t platform_random(){
#pragma message("Platform has no entropy source, this is unsafe. TEST ONLY")
  static uint64_t w = 0, s = 0xb5ad4eceda1ce2a9;

  unsigned long cycles;
  asm volatile ("rdcycle %0" : "=r" (cycles));

  // from Middle Square Weyl Sequence algorithm
  uint64_t x = cycles;
  x *= x;
  x += (w += s);
  return (x>>32) | (x<<32);
}

// Initialization functions

// Not optimal, but otherwise we get undefined reference errors
#ifndef BOARD_VISIONFIVE2
/* from Sanctum BootROM */
extern byte sanctum_sm_hash[MDSIZE];
extern byte sanctum_sm_signature[SIGNATURE_SIZE];
extern byte sanctum_sm_secret_key[PRIVATE_KEY_SIZE];
extern byte sanctum_sm_public_key[PUBLIC_KEY_SIZE];
extern byte sanctum_dev_public_key[PUBLIC_KEY_SIZE];

extern byte sm_hash[MDSIZE];
extern byte sm_signature[SIGNATURE_SIZE];
extern byte sm_public_key[PUBLIC_KEY_SIZE];
extern byte sm_private_key[PRIVATE_KEY_SIZE];
extern byte dev_public_key[PUBLIC_KEY_SIZE];

void sm_copy_key(void)
{
  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  sbi_memcpy(sm_signature, sanctum_sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, PRIVATE_KEY_SIZE);
  sbi_memcpy(dev_public_key, sanctum_dev_public_key, PUBLIC_KEY_SIZE);
}
#endif
