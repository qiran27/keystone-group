//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "keystone.h"
#include "keystone-sbi.h"
#include "keystone_user.h"
#include "sm_err.h"
#include <asm/sbi.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/moduleparam.h>

/* Read-only deployment capability: scripts must not call the historical
 * destructive EPM ioctl against an older module. */
static bool security_nofault_epm = true;
module_param(security_nofault_epm, bool, 0444);
MODULE_PARM_DESC(security_nofault_epm, "Recoverable EPM read/write security probe");

extern spinlock_t YXSTM_spinlock;

static unsigned long testaccess_other_os_access_epm = -1UL;
static const char keystone_group_batched_ocall_resume_marker[] __used =
    "keystone-group-batched-ocall-resume-v1";

int __keystone_destroy_enclave(unsigned int ueid);

static void keystone_abi_init(struct keystone_abi_header *abi,
                              size_t expected_size,
                              unsigned long features)
{
  abi->version = KEYSTONE_ABI_VERSION;
  abi->struct_size = expected_size;
  abi->features = features;
  abi->status = 0;
  abi->detail = 0;
  abi->reserved = 0;
}

static int keystone_abi_validate(const struct keystone_abi_header *abi,
                                 size_t expected_size,
                                 unsigned long required_features)
{
  if (!abi)
    return -EINVAL;
  if (abi->version != KEYSTONE_ABI_VERSION)
    return -EOPNOTSUPP;
  if (abi->struct_size != expected_size ||
      (abi->struct_size & (KEYSTONE_ABI_ALIGN - 1)))
    return -EINVAL;
  if ((abi->features & required_features) != required_features)
    return -EINVAL;
  if (abi->status || abi->detail || abi->reserved)
    return -EINVAL;
  return 0;
}

static int keystone_group_sbi_result(
    struct sbiret ret,
    const struct keystone_abi_header *sm_abi,
    struct keystone_abi_header *user_abi)
{
  long detail = keystone_sbi_sm_detail(ret);
  int error = keystone_sbi_sm_errno(ret);

  if (user_abi && error) {
    user_abi->status = sm_abi && sm_abi->status ? sm_abi->status : detail;
    user_abi->detail = sm_abi && sm_abi->detail ? sm_abi->detail : detail;
  }
  return error;
}

static long keystone_sbi_user_detail(struct sbiret ret)
{
  long detail = keystone_sbi_sm_detail(ret);

  return detail ? detail : ret.error;
}

int keystone_create_enclave(struct file *filep, unsigned long arg)
{
  /* create parameters */
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;

  struct enclave *enclave;
  enclave = create_enclave(enclp->min_pages, enclp->ms, enclp->engine_id);

  if (enclave == NULL) {
    return -ENOMEM;
  }

  /* Pass base page table */
  enclp->epm_paddr = enclave->epm->pa;
  enclp->epm_size = enclave->epm->size;

  /* allocate UID */
  enclp->eid = enclave_idr_alloc(enclave);

  filep->private_data = (void *) enclp->eid;

  return 0;
}

int YXSTM_init_ioctl(struct file *filep, unsigned long arg)
{
  int ret = 0;
  struct YXSTM *YXSTM;
  struct enclave *enclave;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;
  long long unsigned YXSTrusted_size = enclp->YXSTM_size;
  long long unsigned ms_YXSTM = enclp->ms;
  unsigned long long engine_id = enclp->engine_id;
  unsigned long bank_count = enclp->YXSTM_bank_count ?
      enclp->YXSTM_bank_count : KEYSTONE_YXSTM_DEFAULT_BANK_COUNT;
  size_t bank_slice_size = enclp->YXSTM_slice_size;

  enclave = get_enclave_by_id(enclp->eid);

  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if(!ms_YXSTM) {
    keystone_err("%s, error ms_YXSTM\n", __func__);
    return -EINVAL;
  }
  if(!engine_id) {
    keystone_warn("%s: engine_id is 0, using legacy default group 1\n", __func__);
    engine_id = 1;
  }
  if (!bank_slice_size &&
      YXSTrusted_size %
          (KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT * bank_count) == 0)
    bank_slice_size = YXSTrusted_size /
        (KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT * bank_count);
  if (!bank_slice_size || bank_count > KEYSTONE_YXSTM_MAX_BANKS ||
      bank_slice_size > SIZE_MAX / KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT /
                            bank_count ||
      bank_slice_size * KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT * bank_count !=
          YXSTrusted_size)
    return -EINVAL;

  YXSTM = kmalloc(sizeof(struct YXSTM), GFP_KERNEL);
  if (!YXSTM) {
    ret = -ENOMEM;
    return ret;
  }

  ret = yxstm_group_get(engine_id, YXSTrusted_size, bank_slice_size,
                        bank_count, YXSTM);
  if (ret != 0) {
    kfree(YXSTM);
    keystone_err("YXSTM group init failed: engine_id=%llu size=%llu ret=%d\n",
                 engine_id, YXSTrusted_size, ret);
    return ret;
  }

  enclave->ms = ms_YXSTM;
  enclave->engine_id = engine_id;
  enclave->yxstm_group_id = engine_id;
  enclave->yxstm_bank_slice_size = bank_slice_size;
  enclave->yxstm_bank_count = bank_count;
  enclave->YXSTM = YXSTM;

  /* Use correct physical address based on allocation type (buddy vs CMA) */
  enclp->YXSTM_paddr = YXSTM->is_cma ? YXSTM->pa : __pa(YXSTM->ptr);

  return ret;

}

int keystone_finalize_enclave(unsigned long arg)
{
  struct sbiret ret;
  struct enclave *enclave;
  struct utm *utm;
  struct utm *shared_utm;
  struct YXSTM *YXSTM;
  struct keystone_sbi_create_t create_args;

  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;

  enclave = get_enclave_by_id(enclp->eid);
  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  enclave->is_init = false;
  memset(&create_args, 0, sizeof(create_args));

  /* SBI Call */
  create_args.epm_region.paddr = enclave->epm->pa;
  create_args.epm_region.size = enclave->epm->size;
  if (enclave->epm->is_group_slice) {
    create_args.group_epm_region.paddr = enclave->epm->group_pa;
    create_args.group_epm_region.size = enclave->epm->group_size;
  } else {
    create_args.group_epm_region.paddr = 0;
    create_args.group_epm_region.size = 0;
  }

  utm = enclave->utm;

  if (utm) {
    /* Use correct physical address based on allocation type (buddy vs CMA) */
    create_args.utm_region.paddr = utm->is_cma ? utm->pa : __pa(utm->ptr);
    create_args.utm_region.size = utm->size;
    
    /* Debug: Verify NAPOT alignment before calling SM */
    // keystone_info("UTM to SM: paddr=0x%lx size=0x%lx is_cma=%d\n",
    //               (unsigned long)create_args.utm_region.paddr,
    //               (unsigned long)create_args.utm_region.size,
    //               utm->is_cma);
    // if (create_args.utm_region.size > 0) {
    //   unsigned long napot_check = create_args.utm_region.paddr & (create_args.utm_region.size - 1);
    //   keystone_info("UTM NAPOT check: paddr %% size = 0x%lx (should be 0)\n", napot_check);
    // }
  } else {
    create_args.utm_region.paddr = 0;
    create_args.utm_region.size = 0;
  }

  /*
   * Shared UTM Support for Dual Enclave Parallel Encryption
   * ========================================================
   * 
   * If this enclave has a shared_utm pointer (set by keystone_share_utm),
   * pass the shared UTM physical address and size to SM.
   * 
   * This allows Slave Enclave's Runtime to map the Main Enclave's UTM
   * at EYRIE_SHARED_UTM_START virtual address, enabling direct access
   * to the 64MB shared buffer instead of being limited to its own 1MB UTM.
   */
  shared_utm = enclave->shared_utm;
  if (shared_utm) {
    /* Use correct physical address based on allocation type (buddy vs CMA) */
    create_args.shared_utm_region.paddr = shared_utm->is_cma ? shared_utm->pa : __pa(shared_utm->ptr);
    create_args.shared_utm_region.size = shared_utm->size;
    
    keystone_info("Shared UTM configured: paddr=0x%lx size=0x%lx owner_eid=%lu\n",
                  (unsigned long)create_args.shared_utm_region.paddr,
                  (unsigned long)create_args.shared_utm_region.size,
                  enclave->owner_eid);
  } else {
    create_args.shared_utm_region.paddr = 0;
    create_args.shared_utm_region.size = 0;
  }

  YXSTM = enclave->YXSTM;

  if (YXSTM) {
    /* Use correct physical address based on allocation type (buddy vs CMA) */
    create_args.YXSTM_region.paddr = YXSTM->is_cma ? YXSTM->pa : __pa(YXSTM->ptr);
    create_args.YXSTM_region.size = YXSTM->size;

    if(enclave->ms==0){
      keystone_err("%s, error enclp->ms\n", __func__);
      goto error_destroy_enclave;
    }

  } else {
    create_args.YXSTM_region.paddr = 0;
    create_args.YXSTM_region.size = 0;
    if(enclave->ms!=0){
      keystone_err("%s, error enclp->ms\n", __func__);
      goto error_destroy_enclave;
    }
  }

  // physical addresses for runtime, user, and freemem
  create_args.runtime_paddr = enclp->runtime_paddr;
  create_args.user_paddr = enclp->user_paddr;
  create_args.free_paddr = enclp->free_paddr;
  create_args.free_requested = enclp->free_requested;
  create_args.ms_YXSTM = enclave->ms;
  create_args.engine_id = enclave->engine_id;
  create_args.yxstm_slice_size = enclave->yxstm_bank_slice_size;
  create_args.yxstm_bank_count = enclave->yxstm_bank_count;
  create_args.sec_region.paddr = enclp->sec_paddr;
  create_args.sec_region.size = enclp->sec_size;
  create_args.sec_flags = enclp->sec_flags;
  create_args.sec_engine_id = enclp->sec_engine_id;

  keystone_info("Creating enclave: ms=%llu engine_id=%llu YXSTM_paddr=0x%lx YXSTM_size=0x%lx\n",
                enclave->ms, enclave->engine_id,
                (unsigned long)create_args.YXSTM_region.paddr,
                (unsigned long)create_args.YXSTM_region.size);

  // keystone_info("Calling sbi_sm_create_enclave...\n");
  ret = sbi_sm_create_enclave(&create_args);
  // keystone_info("sbi_sm_create_enclave returned: error=%ld, value=%ld\n", ret.error, ret.value);

  if (ret.error) {
    keystone_err("keystone_create_enclave: SBI call failed with error code %ld\n", ret.error);
    goto error_destroy_enclave;
  }

  // char testaccess[4*1024] = {0,};
  // memcpy((void*)testaccess, (void*)enclave->epm->ptr, 4*1024);
  // keystone_info("test os access epm fault! memcpy errors test %s\n",__func__);
  // memset((void*)enclave->epm->ptr, 0, 4 * 1024);
  // keystone_info("test os access epm fault! errors test %s\n",__func__);

  enclave->eid = ret.value & 0xffffffffUL;
  enclave->sm_generation = (ret.value >> 32) & 0xffffffffUL;
  // keystone_info("Enclave finalized successfully, eid=%d\n", enclave->eid);

  return 0;

error_destroy_enclave:
  /* This can handle partial initialization failure */
  enclave_idr_remove(enclp->eid);
  destroy_enclave(enclave);

  return -EINVAL;

}

int keystone_test_other_os_access_epm_create_enclave(struct file *filep, unsigned long arg)
{
  /* create parameters */
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;

  struct enclave *enclave;
  enclave = create_enclave(enclp->min_pages, enclp->ms, enclp->engine_id);

  if (enclave == NULL) {
    return -ENOMEM;
  }

  /* Pass base page table */
  enclp->epm_paddr = enclave->epm->pa;
  enclp->epm_size = enclave->epm->size;

  /* allocate UID */
  enclp->eid = enclave_idr_alloc(enclave);

  spin_lock(&YXSTM_spinlock);
  if (testaccess_other_os_access_epm == -1UL) {
    testaccess_other_os_access_epm = enclp->eid;
  }
  spin_unlock(&YXSTM_spinlock);

  filep->private_data = (void *) enclp->eid;

  return 0;
}

int keystone_test_other_os_access_epm_finalize_enclave(unsigned long arg)
{
  struct sbiret ret;
  struct enclave *enclave;
  struct utm *utm;
  struct YXSTM *YXSTM;
  struct keystone_sbi_create_t create_args;

  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;

  enclave = get_enclave_by_id(enclp->eid);
  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  enclave->is_init = false;
  memset(&create_args, 0, sizeof(create_args));

  /* SBI Call */
  create_args.epm_region.paddr = enclave->epm->pa;
  create_args.epm_region.size = enclave->epm->size;
  if (enclave->epm->is_group_slice) {
    create_args.group_epm_region.paddr = enclave->epm->group_pa;
    create_args.group_epm_region.size = enclave->epm->group_size;
  } else {
    create_args.group_epm_region.paddr = 0;
    create_args.group_epm_region.size = 0;
  }

  utm = enclave->utm;

  if (utm) {
    /* Use correct physical address based on allocation type (buddy vs CMA) */
    create_args.utm_region.paddr = utm->is_cma ? utm->pa : __pa(utm->ptr);
    create_args.utm_region.size = utm->size;
  } else {
    create_args.utm_region.paddr = 0;
    create_args.utm_region.size = 0;
  }

  YXSTM = enclave->YXSTM;

  if (YXSTM) {
    /* Use correct physical address based on allocation type (buddy vs CMA) */
    create_args.YXSTM_region.paddr = YXSTM->is_cma ? YXSTM->pa : __pa(YXSTM->ptr);
    create_args.YXSTM_region.size = YXSTM->size;

    if(enclave->ms==0){
      keystone_err("%s, error enclp->ms\n", __func__);
      goto error_destroy_enclave;
    }

  } else {
    create_args.YXSTM_region.paddr = 0;
    create_args.YXSTM_region.size = 0;
    if(enclave->ms!=0){
      keystone_err("%s, error enclp->ms\n", __func__);
      goto error_destroy_enclave;
    }
  }

  // physical addresses for runtime, user, and freemem
  create_args.runtime_paddr = enclp->runtime_paddr;
  create_args.user_paddr = enclp->user_paddr;
  create_args.free_paddr = enclp->free_paddr;
  create_args.free_requested = enclp->free_requested;
  create_args.ms_YXSTM = enclave->ms;
  create_args.engine_id = enclave->engine_id;
  create_args.yxstm_slice_size = enclave->yxstm_bank_slice_size;
  create_args.yxstm_bank_count = enclave->yxstm_bank_count;

  ret = sbi_sm_create_enclave(&create_args);

  spin_lock(&YXSTM_spinlock);
  struct enclave *testaccess_other_os_access_enclave = NULL;
  if (testaccess_other_os_access_epm != enclp->eid && testaccess_other_os_access_epm != -1UL) {
    testaccess_other_os_access_enclave = get_enclave_by_id(testaccess_other_os_access_epm);
  }
  spin_unlock(&YXSTM_spinlock);

  keystone_info("testaccess_other_os_access_epm:%lu, eid:%lu func:%s\n",
                testaccess_other_os_access_epm, enclp->eid, __func__);

  if (testaccess_other_os_access_enclave) {
    char testaccess[4*1024] = {0,};
    memcpy((void*)testaccess, (void*)testaccess_other_os_access_enclave->epm->ptr, 4*1024);
    // ruguokeyifangwenzehuishuchuxiamiandeyuju
    keystone_info("other_os_access_epm fault! memcpy test error, func:%s, cpy_dst_data:%02x\n", __func__, testaccess[5]);
		keystone_info("other_os_access_epm fault! memcpy test error, func:%s, cpy_src_data:%02x\n", __func__, *(((char *)testaccess_other_os_access_enclave->epm->ptr) + 5));
    memset((void*)testaccess_other_os_access_enclave->epm->ptr, 0, 4*1024);
    keystone_info("other_os_access_epm fault! memset test error, func:%s\n", __func__);
  }

  if (ret.error) {
    keystone_err("keystone_create_enclave: SBI call failed with error code %ld\n", ret.error);
    goto error_destroy_enclave;
  }

  enclave->eid = ret.value & 0xffffffffUL;
  enclave->sm_generation = (ret.value >> 32) & 0xffffffffUL;

  return 0;

error_destroy_enclave:
  /* This can handle partial initialization failure */
  enclave_idr_remove(enclp->eid);
  destroy_enclave(enclave);

  return -EINVAL;

}

int keystone_run_enclave(unsigned long data)
{
  struct sbiret ret;
  unsigned long ueid;
  struct enclave* enclave;
  struct keystone_ioctl_run_enclave *arg = (struct keystone_ioctl_run_enclave*) data;

  ueid = arg->eid;
  enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if (enclave->eid == (unsigned long)-1) {
    keystone_err("real enclave does not exist\n");
    return -EINVAL;
  }

  ret = sbi_sm_run_enclave(enclave->eid);

  arg->error = keystone_sbi_user_detail(ret);
  arg->value = ret.value;

  return 0;
}

int utm_init_ioctl(struct file *filp, unsigned long arg)
{
  int ret = 0;
  struct utm *utm;
  struct enclave *enclave;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;
  long long unsigned untrusted_size = enclp->utm_size;

  enclave = get_enclave_by_id(enclp->eid);

  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  utm = kmalloc(sizeof(struct utm), GFP_KERNEL);
  if (!utm) {
    ret = -ENOMEM;
    return ret;
  }

  ret = utm_init(utm, untrusted_size);

  if (ret) {
    kfree(utm);
    return ret;
  }

  /* prepare for mmap */
  enclave->utm = utm;

  /* Return correct physical address based on allocation type */
  enclp->utm_paddr = utm->is_cma ? utm->pa : __pa(utm->ptr);

  return ret;
}

/*
 * Share UTM from owner enclave to target enclave
 * This allows the target enclave to access the owner's UTM region
 * 
 * Enhanced logging for debugging shared UTM issues (Task 19.1)
 */
int keystone_share_utm(struct file *filep, unsigned long arg)
{
  struct keystone_ioctl_share_utm *share_arg = (struct keystone_ioctl_share_utm *)arg;
  struct enclave *owner_enclave;
  struct enclave *target_enclave;
  struct utm *owner_utm;
  unsigned long utm_paddr;

  /* =========================================================================
   * Enhanced Logging: Entry point with request parameters
   * Requirements: 17.1 - Driver error log enhancement
   * =========================================================================
   */
  keystone_info("keystone_share_utm: ENTRY - owner_eid=%lu target_eid=%lu\n",
                (unsigned long)share_arg->owner_eid,
                (unsigned long)share_arg->target_eid);

  /* Get owner enclave */
  owner_enclave = get_enclave_by_id(share_arg->owner_eid);
  if (!owner_enclave) {
    keystone_err("keystone_share_utm: FAILED - owner enclave %lu not found\n", 
                 (unsigned long)share_arg->owner_eid);
    keystone_err("  Possible cause: Owner enclave was not created or already destroyed\n");
    return -EINVAL;
  }
  keystone_info("keystone_share_utm: owner enclave %lu found (eid=%lu)\n",
                (unsigned long)share_arg->owner_eid, owner_enclave->eid);

  /* Check if owner has a valid UTM */
  owner_utm = owner_enclave->utm;
  if (!owner_utm) {
    keystone_err("keystone_share_utm: FAILED - owner enclave %lu has no UTM\n",
                 (unsigned long)share_arg->owner_eid);
    keystone_err("  Possible cause: UTM was not initialized for owner enclave\n");
    return -EINVAL;
  }

  /* Calculate UTM physical address */
  utm_paddr = owner_utm->is_cma ? owner_utm->pa : __pa(owner_utm->ptr);
  
  /* Enhanced logging: Print detailed UTM information */
  keystone_info("keystone_share_utm: owner UTM details:\n");
  keystone_info("  utm_paddr=0x%lx\n", utm_paddr);
  keystone_info("  utm_size=0x%lx (%lu MB)\n", 
                (unsigned long)owner_utm->size,
                (unsigned long)owner_utm->size / (1024 * 1024));
  keystone_info("  is_cma=%d\n", owner_utm->is_cma);
  keystone_info("  ref_count=%d (before share)\n", atomic_read(&owner_utm->ref_count));

  /* Get target enclave */
  target_enclave = get_enclave_by_id(share_arg->target_eid);
  if (!target_enclave) {
    keystone_err("keystone_share_utm: FAILED - target enclave %lu not found\n",
                 (unsigned long)share_arg->target_eid);
    keystone_err("  Possible cause: Target enclave was not created or already destroyed\n");
    return -EINVAL;
  }
  keystone_info("keystone_share_utm: target enclave %lu found (eid=%lu)\n",
                (unsigned long)share_arg->target_eid, target_enclave->eid);

  /* Check if target already has a shared UTM */
  if (target_enclave->shared_utm != NULL) {
    keystone_err("keystone_share_utm: FAILED - target enclave %lu already has shared UTM\n",
                 (unsigned long)share_arg->target_eid);
    keystone_err("  Current shared_utm owner_eid=%lu\n", target_enclave->owner_eid);
    return -EEXIST;
  }

  /* Check if target has its own UTM (should not share if it has its own) */
  if (target_enclave->utm != NULL) {
    unsigned long target_utm_paddr = target_enclave->utm->is_cma ? 
                                     target_enclave->utm->pa : 
                                     __pa(target_enclave->utm->ptr);
    keystone_warn("keystone_share_utm: WARNING - target enclave %lu has its own UTM\n",
                  (unsigned long)share_arg->target_eid);
    keystone_warn("  target's own utm_paddr=0x%lx utm_size=0x%lx\n",
                  target_utm_paddr, (unsigned long)target_enclave->utm->size);
    keystone_warn("  Proceeding with share anyway...\n");
  }

  /* Set up the shared UTM */
  target_enclave->shared_utm = owner_utm;
  target_enclave->owner_eid = share_arg->owner_eid;

  /* Increment reference count */
  atomic_inc(&owner_utm->ref_count);

  /* Return UTM info to userspace */
  share_arg->utm_paddr = utm_paddr;
  share_arg->utm_size = owner_utm->size;

  /* Enhanced logging: Success with complete details */
  keystone_info("keystone_share_utm: SUCCESS\n");
  keystone_info("  owner_eid=%lu (enclave eid=%lu)\n",
                (unsigned long)share_arg->owner_eid, owner_enclave->eid);
  keystone_info("  target_eid=%lu (enclave eid=%lu)\n",
                (unsigned long)share_arg->target_eid, target_enclave->eid);
  keystone_info("  utm_paddr=0x%lx\n", (unsigned long)share_arg->utm_paddr);
  keystone_info("  utm_size=0x%lx (%lu MB)\n", 
                (unsigned long)share_arg->utm_size,
                (unsigned long)share_arg->utm_size / (1024 * 1024));
  keystone_info("  ref_count=%d (after share)\n", atomic_read(&owner_utm->ref_count));

  return 0;
}


int keystone_destroy_enclave(struct file *filep, unsigned long arg)
{
  int ret;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;
  unsigned long ueid = enclp->eid;

  ret = __keystone_destroy_enclave(ueid);
  if (!ret) {
    filep->private_data = NULL;
  }
  return ret;
}

int __keystone_destroy_enclave(unsigned int ueid)
{
  struct sbiret ret;
  struct enclave *enclave;
  int release_ret;
  enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  /* A process can be terminated before its userspace lease guard runs.  The
   * first group enclave fd closed by exit_files() must return remote HSM
   * workers to Linux before SM teardown or memory reclamation begins. */
  if (enclave->ms && enclave->engine_id) {
    release_ret = keystone_group_release_for_destroy(enclave->engine_id);
    if (release_ret) {
      keystone_err("Cannot destroy enclave %u: worker lease release failed: %d\n",
                   ueid, release_ret);
      return release_ret;
    }
  }

  /* =========================================================================
   * Shared UTM Reference Count Check
   * =========================================================================
   * 
   * When destroying an enclave that owns a UTM (Main Enclave), we must check
   * if other enclaves (Slave Enclaves) are still sharing this UTM.
   * 
   * Reference count semantics:
   * - ref_count = 1: Only the owner is using the UTM (safe to destroy)
   * - ref_count > 1: Other enclaves are sharing the UTM (cannot destroy)
   * 
   * The correct cleanup order is:
   * 1. Destroy Slave Enclave first (decrements ref_count)
   * 2. Then destroy Main Enclave (ref_count should be 1)
   * 
   * Requirements: 16.1, 16.2, 16.3, 16.4
   * =========================================================================
   */
  
  /* Log enclave destruction attempt with detailed info */
  keystone_info("Destroying enclave %u: utm=%p, shared_utm=%p, owner_eid=%lu\n",
                ueid, enclave->utm, enclave->shared_utm, enclave->owner_eid);
  
  /* Check if this enclave is sharing another enclave's UTM */
  if (enclave->shared_utm) {
    int shared_ref_count = atomic_read(&enclave->shared_utm->ref_count);
    keystone_info("Enclave %u is sharing UTM from owner_eid=%lu (current ref_count=%d)\n",
                  ueid, enclave->owner_eid, shared_ref_count);
  }
  
  /* Check if this enclave's UTM is still being shared by other enclaves */
  if (enclave->utm) {
    int ref_count = atomic_read(&enclave->utm->ref_count);
    keystone_info("Enclave %u owns UTM with ref_count=%d\n", ueid, ref_count);
    
    if (ref_count > 1) {
      keystone_err("Cannot destroy enclave %u: UTM is still shared by %d other enclave(s)\n",
                   ueid, ref_count - 1);
      keystone_err("Please destroy the sharing enclave(s) first!\n");
      return -EBUSY;
    }
  }

  if (enclave->eid != (unsigned long)-1) {
    ret = sbi_sm_destroy_enclave(enclave->eid, enclave->sm_generation);
    if (ret.error) {
      keystone_err("fatal: cannot destroy enclave: SBI failed with error code %ld\n", ret.error);
      return -EINVAL;
    }
  } else {
    keystone_warn("keystone_destroy_enclave: skipping (enclave does not exist)\n");
  }

  enclave_idr_remove(ueid);
  destroy_enclave(enclave);
  
  keystone_info("Enclave %u destroyed successfully\n", ueid);

  return 0;
}

int keystone_resume_enclave(unsigned long data)
{
  struct sbiret ret;
  struct keystone_ioctl_run_enclave *arg = (struct keystone_ioctl_run_enclave*) data;
  unsigned long ueid = arg->eid;
  struct enclave* enclave;
  enclave = get_enclave_by_id(ueid);

  if (!enclave)
  {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if (enclave->eid == (unsigned long)-1) {
    keystone_err("real enclave does not exist\n");
    return -EINVAL;
  }

  ret = sbi_sm_resume_enclave(enclave->eid);

  arg->error = keystone_sbi_user_detail(ret);
  arg->value = ret.value;

  return 0;
}

static long keystone_put_kernel_u8_nofault(void *dst,
                                           const unsigned char *src)
{
  long error = 0;

  pagefault_disable();
  __put_user_nocheck(*src, (unsigned char *)dst, error);
  pagefault_enable();
  return error ? -EFAULT : 0;
}

static unsigned long keystone_test_os_access_region(void *pointer,
                                                    const char *region)
{
  unsigned long result = 0;
  unsigned char read_value = 0;
  unsigned char write_value = 0xa5;
  long read_ret;
  long write_ret;

  if (!pointer) {
    keystone_err("host %s access probe has no protected region\n", region);
    return 0;
  }

  /* These helpers carry RISC-V exception-table fixups.  A PMP access fault is
   * therefore reported as -EFAULT instead of killing the kernel thread. */
  read_ret = copy_from_kernel_nofault(&read_value,
                                      pointer,
                                      sizeof(read_value));
  write_ret = keystone_put_kernel_u8_nofault(pointer,
                                             &write_value);

  if (read_ret == -EFAULT)
    result |= KEYSTONE_OS_ACCESS_RESULT_READ_DENIED;
  else
    keystone_err("host %s read was not rejected by PMP: ret=%ld\n",
                 region, read_ret);

  if (write_ret == -EFAULT)
    result |= KEYSTONE_OS_ACCESS_RESULT_WRITE_DENIED;
  else
    keystone_err("host %s write was not rejected by PMP: ret=%ld\n",
                 region, write_ret);

  keystone_info("host %s nofault probe: read_ret=%ld write_ret=%ld result=0x%lx\n",
                region, read_ret, write_ret, result);
  return result;
}

static unsigned long keystone_test_os_access_yxstm(struct enclave *enclave)
{
  return keystone_test_os_access_region(
      enclave->YXSTM && enclave->ms ? enclave->YXSTM->ptr : NULL, "YXSTM");
}

int keystone_test_os_access_stm_run_enclave(unsigned long data)
{
  struct sbiret ret;
  unsigned long ueid;
  struct enclave* enclave;
  struct keystone_ioctl_run_enclave *arg = (struct keystone_ioctl_run_enclave*) data;

  ueid = arg->eid;
  enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if (enclave->eid == (unsigned long)-1) {
    keystone_err("real enclave does not exist\n");
    return -EINVAL;
  }

  ret = sbi_sm_run_enclave(enclave->eid);

  arg->error = keystone_sbi_user_detail(ret);
  arg->value = ret.error == SBI_ERR_SM_ENCLAVE_SUCCESS ?
      keystone_test_os_access_yxstm(enclave) : ret.value;

  return 0;
}

int keystone_test_os_access_stm_resume_enclave(unsigned long data)
{
  struct sbiret ret;
  struct keystone_ioctl_run_enclave *arg = (struct keystone_ioctl_run_enclave*) data;
  unsigned long ueid = arg->eid;
  struct enclave* enclave;
  enclave = get_enclave_by_id(ueid);

  if (!enclave)
  {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if (enclave->eid == (unsigned long)-1) {
    keystone_err("real enclave does not exist\n");
    return -EINVAL;
  }

  ret = sbi_sm_resume_enclave(enclave->eid);

  arg->error = keystone_sbi_user_detail(ret);
  arg->value = ret.error == SBI_ERR_SM_ENCLAVE_SUCCESS ?
      keystone_test_os_access_yxstm(enclave) : ret.value;

  return 0;
}

int keystone_test_os_access_epm_run_enclave(unsigned long data)
{
  struct sbiret ret;
  unsigned long ueid;
  struct enclave* enclave;
  struct keystone_ioctl_run_enclave *arg = (struct keystone_ioctl_run_enclave*) data;

  ueid = arg->eid;
  enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if (enclave->eid == (unsigned long)-1) {
    keystone_err("real enclave does not exist\n");
    return -EINVAL;
  }

  ret = sbi_sm_run_enclave(enclave->eid);

  arg->error = keystone_sbi_user_detail(ret);
  arg->value = ret.error == SBI_ERR_SM_ENCLAVE_SUCCESS ?
      keystone_test_os_access_region(enclave->epm ? enclave->epm->ptr : NULL,
                                    "EPM") : ret.value;

  return 0;
}

int keystone_test_os_access_epm_resume_enclave(unsigned long data)
{
  struct sbiret ret;
  struct keystone_ioctl_run_enclave *arg = (struct keystone_ioctl_run_enclave*) data;
  unsigned long ueid = arg->eid;
  struct enclave* enclave;
  enclave = get_enclave_by_id(ueid);

  if (!enclave)
  {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  if (enclave->eid == (unsigned long)-1) {
    keystone_err("real enclave does not exist\n");
    return -EINVAL;
  }

  ret = sbi_sm_resume_enclave(enclave->eid);

  arg->error = keystone_sbi_user_detail(ret);
  arg->value = ret.error == SBI_ERR_SM_ENCLAVE_SUCCESS ?
      keystone_test_os_access_region(enclave->epm ? enclave->epm->ptr : NULL,
                                    "EPM") : ret.value;

  return 0;
}

static int keystone_group_set_count(unsigned long data)
{
  struct keystone_ioctl_group_config *cfg =
      (struct keystone_ioctl_group_config *) data;
  struct sbiret ret;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  ret = sbi_sm_group_set_count(cfg->group_count);
  if (ret.error)
    return keystone_group_sbi_result(ret, NULL, &cfg->abi);

  return 0;
}

static int keystone_group_set_hart_count(unsigned long data)
{
  struct keystone_ioctl_group_config *cfg =
      (struct keystone_ioctl_group_config *) data;
  struct sbiret ret;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  ret = sbi_sm_group_set_hart_count(cfg->group_id, cfg->hart_count);
  if (ret.error)
    return keystone_group_sbi_result(ret, NULL, &cfg->abi);

  return 0;
}

static int keystone_group_query(unsigned long data)
{
  struct keystone_ioctl_group_config *cfg =
      (struct keystone_ioctl_group_config *) data;
  struct keystone_group_config sm_cfg;
  struct sbiret ret;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  memset(&sm_cfg, 0, sizeof(sm_cfg));
  keystone_abi_init(&sm_cfg.abi, sizeof(sm_cfg), KEYSTONE_GROUP_ABI_FEATURES);
  sm_cfg.group_id = cfg->group_id;

  ret = sbi_sm_group_query(&sm_cfg);
  if (ret.error) {
    int error = keystone_group_sbi_result(ret, &sm_cfg.abi, &cfg->abi);
    return error;
  }

  cfg->group_count = sm_cfg.group_count;
  cfg->group_id = sm_cfg.group_id;
  cfg->hart_count = sm_cfg.hart_count;
  cfg->hart_mask = sm_cfg.hart_mask;
  cfg->member_capacity = sm_cfg.member_capacity;
  cfg->member_count = sm_cfg.member_count;
  cfg->lifecycle_state = sm_cfg.lifecycle_state;
  cfg->generation = sm_cfg.generation;
  keystone_abi_init(&cfg->abi, sizeof(*cfg), KEYSTONE_GROUP_ABI_FEATURES);

  return 0;
}

static int keystone_group_lifecycle(unsigned long data, unsigned int operation)
{
  struct keystone_ioctl_group_config *cfg =
      (struct keystone_ioctl_group_config *) data;
  struct keystone_group_config sm_cfg;
  struct sbiret ret;
  int release_ret;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  memcpy(&sm_cfg, cfg, sizeof(sm_cfg));
  if (operation == KEYSTONE_IOC_GROUP_CREATE)
    ret = sbi_sm_group_create(&sm_cfg);
  else if (operation == KEYSTONE_IOC_GROUP_ACTIVATE)
    ret = sbi_sm_group_activate(&sm_cfg);
  else {
    release_ret = keystone_group_release_for_destroy(cfg->group_id);
    if (release_ret)
      return release_ret;
    ret = sbi_sm_group_destroy(&sm_cfg);
  }
  if (ret.error) {
    int error = keystone_group_sbi_result(ret, &sm_cfg.abi, &cfg->abi);
    return error;
  }
  memcpy(cfg, &sm_cfg, sizeof(*cfg));
  keystone_abi_init(&cfg->abi, sizeof(*cfg), KEYSTONE_GROUP_ABI_FEATURES);
  return 0;
}

static int keystone_group_generation(unsigned long group_id,
                                     unsigned long *generation)
{
  struct keystone_group_config cfg;
  struct sbiret ret;

  memset(&cfg, 0, sizeof(cfg));
  keystone_abi_init(&cfg.abi, sizeof(cfg), KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = group_id;
  ret = sbi_sm_group_query(&cfg);
  if (ret.error || !cfg.generation)
    return ret.error ? keystone_sbi_sm_errno(ret) : -EINVAL;
  *generation = cfg.generation;
  return 0;
}

static int keystone_group_bind_enclave(unsigned long data)
{
  struct keystone_ioctl_group_sched *cfg =
      (struct keystone_ioctl_group_sched *) data;
  struct enclave* enclave;
  struct sbiret ret;
  unsigned long group_generation;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  enclave = get_enclave_by_id(cfg->eid);
  if (!enclave || enclave->eid == (unsigned long)-1)
    return -EINVAL;
  if (keystone_group_generation(enclave->engine_id, &group_generation))
    return -EINVAL;

  ret = sbi_sm_group_bind_enclave(enclave->eid, cfg->hart_id,
                                  group_generation,
                                  enclave->sm_generation,
                                  cfg->priority,
                                  cfg->quantum_ticks);
  if (ret.error)
    return keystone_group_sbi_result(ret, NULL, &cfg->abi);

  keystone_group_kick(enclave->engine_id);

  return 0;
}

static int keystone_group_enqueue_enclave(unsigned long data)
{
  struct keystone_ioctl_group_sched *cfg =
      (struct keystone_ioctl_group_sched *) data;
  struct enclave* enclave;
  struct sbiret ret;
  unsigned long group_generation;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  enclave = get_enclave_by_id(cfg->eid);
  if (!enclave || enclave->eid == (unsigned long)-1)
    return -EINVAL;
  if (keystone_group_generation(enclave->engine_id, &group_generation))
    return -EINVAL;

  ret = sbi_sm_group_enqueue_enclave(enclave->eid, group_generation,
                                     enclave->sm_generation);
  if (ret.error)
    return keystone_group_sbi_result(ret, NULL, &cfg->abi);

  keystone_group_kick(enclave->engine_id);

  return 0;
}

static int keystone_group_poll_blocked_ocall(unsigned long data)
{
  struct keystone_ioctl_group_ocall *cfg =
      (struct keystone_ioctl_group_ocall *) data;
  struct keystone_group_ocall_status sm_status;
  struct sbiret ret;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  memset(&sm_status, 0, sizeof(sm_status));
  keystone_abi_init(&sm_status.abi, sizeof(sm_status),
                    KEYSTONE_GROUP_ABI_FEATURES);
  sm_status.group_id = cfg->group_id;
  sm_status.hart_id = cfg->hart_id;
  sm_status.eid = cfg->eid;
  sm_status.pending = cfg->pending;
  sm_status.pending_count = cfg->pending_count;
  sm_status.ocall_id = cfg->ocall_id;
  sm_status.action = cfg->action;
  sm_status.timeout_cycles = cfg->timeout_cycles;
  sm_status.result = cfg->result;
  sm_status.created_at = cfg->created_at;
  sm_status.deadline = cfg->deadline;
  sm_status.host_cookie = cfg->host_cookie;
  sm_status.flags = cfg->flags;

  ret = sbi_sm_group_poll_blocked_ocall(&sm_status);
  if (ret.error) {
    int error = keystone_group_sbi_result(ret, &sm_status.abi, &cfg->abi);
    return error;
  }

  cfg->group_id = sm_status.group_id;
  cfg->hart_id = sm_status.hart_id;
  if (sm_status.pending) {
    unsigned int ueid = enclave_idr_find_by_sm_eid(sm_status.eid);
    cfg->eid = ueid ? ueid : sm_status.eid;
  } else {
    cfg->eid = sm_status.eid;
  }
  cfg->pending = sm_status.pending;
  cfg->pending_count = sm_status.pending_count;
  cfg->ocall_id = sm_status.ocall_id;
  cfg->action = sm_status.action;
  cfg->timeout_cycles = sm_status.timeout_cycles;
  cfg->result = sm_status.result;
  cfg->created_at = sm_status.created_at;
  cfg->deadline = sm_status.deadline;
  cfg->host_cookie = sm_status.host_cookie;
  cfg->flags = sm_status.flags;
  keystone_abi_init(&cfg->abi, sizeof(*cfg), KEYSTONE_GROUP_ABI_FEATURES);

  return 0;
}

static int keystone_group_resume_blocked_ocall(unsigned long data)
{
  struct keystone_ioctl_group_ocall *cfg =
      (struct keystone_ioctl_group_ocall *) data;
  struct keystone_group_ocall_status sm_status;
  struct enclave* enclave;
  struct sbiret ret;
  unsigned long host_eid = cfg->eid;
  unsigned long host_flags = cfg->flags;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  enclave = get_enclave_by_id(cfg->eid);
  if (!enclave || enclave->eid == (unsigned long)-1)
    return -EINVAL;

  memset(&sm_status, 0, sizeof(sm_status));
  keystone_abi_init(&sm_status.abi, sizeof(sm_status),
                    KEYSTONE_GROUP_ABI_FEATURES);
  sm_status.group_id = cfg->group_id;
  sm_status.hart_id = cfg->hart_id;
  sm_status.eid = enclave->eid;
  sm_status.pending = cfg->pending;
  sm_status.pending_count = cfg->pending_count;
  sm_status.ocall_id = cfg->ocall_id;
  sm_status.action = cfg->action;
  sm_status.timeout_cycles = cfg->timeout_cycles;
  sm_status.result = cfg->result;
  sm_status.created_at = cfg->created_at;
  sm_status.deadline = cfg->deadline;
  sm_status.host_cookie = cfg->host_cookie;
  sm_status.flags = cfg->flags;

  ret = sbi_sm_group_resume_blocked_ocall(&sm_status);
  if (ret.error) {
    int error = keystone_group_sbi_result(ret, &sm_status.abi, &cfg->abi);
    return error;
  }

  keystone_group_commit_event(
      cfg->group_id, KEYSTONE_GROUP_EVENT_OCALL, cfg->hart_id, cfg->eid);
  if (!(host_flags & KEYSTONE_GROUP_OCALL_FLAG_DEFER_HOST_KICK))
    keystone_group_kick_hart(cfg->group_id, sm_status.hart_id);

  cfg->group_id = sm_status.group_id;
  cfg->hart_id = sm_status.hart_id;
  cfg->eid = host_eid;
  cfg->pending = sm_status.pending;
  cfg->pending_count = sm_status.pending_count;
  cfg->ocall_id = sm_status.ocall_id;
  cfg->action = sm_status.action;
  cfg->timeout_cycles = sm_status.timeout_cycles;
  cfg->result = sm_status.result;
  cfg->created_at = sm_status.created_at;
  cfg->deadline = sm_status.deadline;
  cfg->host_cookie = sm_status.host_cookie;
  cfg->flags = sm_status.flags;
  keystone_abi_init(&cfg->abi, sizeof(*cfg), KEYSTONE_GROUP_ABI_FEATURES);

  return 0;
}

static void keystone_group_kick_resume_harts(
    unsigned long group_id, const unsigned long *harts,
    unsigned long hart_count)
{
  unsigned long index;

  for (index = 0; index < hart_count; ++index)
    keystone_group_kick_hart(group_id, harts[index]);
}

static int keystone_group_resume_blocked_ocall_batch(unsigned long data)
{
  struct keystone_ioctl_group_ocall_batch *cfg =
      (struct keystone_ioctl_group_ocall_batch *)data;
  struct enclave *enclaves[KEYSTONE_GROUP_OCALL_RESUME_BATCH_MAX];
  unsigned long resumed_harts[KEYSTONE_GROUP_OCALL_RESUME_BATCH_MAX];
  unsigned long resumed_hart_count = 0;
  unsigned long index;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  if (!cfg->count || cfg->count > KEYSTONE_GROUP_OCALL_RESUME_BATCH_MAX ||
      cfg->flags)
    return -EINVAL;

  cfg->resumed_count = 0;
  cfg->failed_index = -1UL;

  /* Resolve every host eid before changing SM state, so malformed batches are
   * rejected atomically at the driver boundary. */
  for (index = 0; index < cfg->count; ++index) {
    enclaves[index] = get_enclave_by_id(cfg->entries[index].eid);
    if (!enclaves[index] || enclaves[index]->eid == (unsigned long)-1) {
      cfg->failed_index = index;
      return -EINVAL;
    }
  }

  for (index = 0; index < cfg->count; ++index) {
    struct keystone_group_ocall_status sm_status;
    struct sbiret ret;
    unsigned long hart_index;
    bool known_hart = false;

    memset(&sm_status, 0, sizeof(sm_status));
    keystone_abi_init(&sm_status.abi, sizeof(sm_status),
                      KEYSTONE_GROUP_ABI_FEATURES);
    sm_status.group_id = cfg->group_id;
    sm_status.hart_id = cfg->entries[index].hart_id;
    sm_status.eid = enclaves[index]->eid;
    sm_status.ocall_id = cfg->entries[index].ocall_id;
    sm_status.action = KEYSTONE_GROUP_OCALL_ACTION_RESUME;
    sm_status.result = cfg->entries[index].result;
    sm_status.flags = KEYSTONE_GROUP_OCALL_FLAG_DEFER_HOST_KICK;

    ret = sbi_sm_group_resume_blocked_ocall(&sm_status);
    if (ret.error) {
      int error;

      cfg->failed_index = index;
      error = keystone_group_sbi_result(ret, &sm_status.abi, &cfg->abi);
      keystone_group_kick_resume_harts(
          cfg->group_id, resumed_harts, resumed_hart_count);
      return error;
    }

    keystone_group_commit_event(
        cfg->group_id, KEYSTONE_GROUP_EVENT_OCALL, sm_status.hart_id,
        cfg->entries[index].eid);
    cfg->resumed_count++;
    for (hart_index = 0; hart_index < resumed_hart_count; ++hart_index) {
      if (resumed_harts[hart_index] == sm_status.hart_id) {
        known_hart = true;
        break;
      }
    }
    if (!known_hart)
      resumed_harts[resumed_hart_count++] = sm_status.hart_id;
  }

  /* One host wakeup per affected lane replaces one ioctl/IPI per enclave. */
  keystone_group_kick_resume_harts(
      cfg->group_id, resumed_harts, resumed_hart_count);
  keystone_abi_init(&cfg->abi, sizeof(*cfg), KEYSTONE_GROUP_ABI_FEATURES);
  return 0;
}

static int keystone_group_run_hart(unsigned long data)
{
  struct keystone_ioctl_group_run_hart *cfg =
      (struct keystone_ioctl_group_run_hart *) data;
  struct keystone_group_run_hart sm_run;
  struct sbiret ret;
  unsigned long group_generation;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  if (keystone_group_generation(cfg->group_id, &group_generation))
    return -EINVAL;
  if (keystone_group_worker_is_leased(cfg->group_id, cfg->hart_id))
    return -EBUSY;

  memset(&sm_run, 0, sizeof(sm_run));
  keystone_abi_init(&sm_run.abi, sizeof(sm_run),
                    KEYSTONE_GROUP_ABI_FEATURES);
  sm_run.group_id = cfg->group_id;
  sm_run.group_generation = group_generation;
  sm_run.hart_id = cfg->hart_id;
  sm_run.eid = cfg->eid;
  sm_run.event = cfg->event;
  sm_run.error = cfg->error;
  sm_run.value = cfg->value;
  sm_run.event_sequence = cfg->event_sequence;
  sm_run.scheduler_epoch = cfg->scheduler_epoch;
  sm_run.queue_overflows = cfg->queue_overflows;

  ret = sbi_sm_group_run_hart(&sm_run);

  if (!sm_run.event && ret.error &&
      KEYSTONE_GROUP_DIRECT_SEQUENCE_VALID(ret.value)) {
    sm_run.event = KEYSTONE_GROUP_EVENT_HOST_INTERRUPT;
    sm_run.error = SBI_ERR_SM_ENCLAVE_SUCCESS;
    sm_run.value = KEYSTONE_GROUP_DIRECT_SEQUENCE_DECODE(ret.value);
  } else if (keystone_sbi_sm_detail(ret) ==
             SBI_ERR_SM_GROUP_HOST_SERVICE) {
    if (!sm_run.event) {
      /* Refuse legacy untagged returns rather than fabricate an ACK sequence. */
      sm_run.event = KEYSTONE_GROUP_EVENT_HEARTBEAT;
      sm_run.error = SBI_ERR_SM_GROUP_HEARTBEAT_SEQUENCE;
      sm_run.value = 0;
    }
  }

  if (!sm_run.event &&
      (keystone_sbi_sm_detail(ret) == SBI_ERR_SM_ENCLAVE_FATAL_FAULT ||
       ret.error) &&
      (ret.value >> 32)) {
    sm_run.eid = (ret.value >> 32) - 1;
    sm_run.event = KEYSTONE_GROUP_EVENT_FAULT;
    sm_run.error = SBI_ERR_SM_ENCLAVE_FATAL_FAULT;
    sm_run.value = ret.value & 0xffffffffUL;
  }

  cfg->group_id = sm_run.group_id;
  cfg->group_generation = sm_run.group_generation;
  cfg->hart_id = sm_run.hart_id;
  cfg->event = sm_run.event;
  /*
   * A non-zero event is an atomic SM-owned event/error/value record.  In
   * particular, a successful EXIT legitimately carries error=0; falling
   * back to the register return in that case can pair EXIT with a stale
   * INTERRUPTED/HOST_SERVICE transport result from the restored host frame.
   */
  cfg->error = sm_run.event ? sm_run.error :
      (sm_run.error ? sm_run.error :
       (keystone_sbi_sm_detail(ret) ? keystone_sbi_sm_detail(ret) :
                                      ret.error));
  cfg->value = sm_run.value;
  cfg->event_sequence = sm_run.event_sequence;
  cfg->scheduler_epoch = sm_run.scheduler_epoch;
  cfg->queue_overflows = sm_run.queue_overflows;
  keystone_abi_init(&cfg->abi, sizeof(*cfg), KEYSTONE_GROUP_ABI_FEATURES);
  if (cfg->event == KEYSTONE_GROUP_EVENT_FAULT &&
      cfg->error == SBI_ERR_SM_ENCLAVE_SUCCESS)
    cfg->error = SBI_ERR_SM_ENCLAVE_FATAL_FAULT;
  if (!cfg->event && !cfg->value)
    cfg->value = ret.value;
  if (cfg->event || cfg->error) {
    unsigned int ueid = enclave_idr_find_by_sm_eid(sm_run.eid);
    cfg->eid = ueid ? ueid : sm_run.eid;
  } else {
    cfg->eid = sm_run.eid;
  }
  if (cfg->event == KEYSTONE_GROUP_EVENT_HOST_INTERRUPT)
    cond_resched();

  return 0;
}

static int keystone_group_control_enclave(unsigned long data)
{
  struct keystone_ioctl_group_control *cfg =
      (struct keystone_ioctl_group_control *)data;
  struct keystone_group_control control;
  struct enclave* enclave;
  struct sbiret ret;
  unsigned long group_generation;

  if (keystone_abi_validate(&cfg->abi, sizeof(*cfg),
                            KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  enclave = get_enclave_by_id(cfg->eid);
  if (!enclave || enclave->eid == (unsigned long)-1)
    return -EINVAL;
  if (keystone_group_generation(enclave->engine_id, &group_generation))
    return -EINVAL;

  memset(&control, 0, sizeof(control));
  keystone_abi_init(&control.abi, sizeof(control),
                    KEYSTONE_GROUP_ABI_FEATURES);
  control.group_id = enclave->engine_id;
  control.group_generation = group_generation;
  control.eid = enclave->eid;
  control.eid_generation = enclave->sm_generation;
  control.action = cfg->action;
  ret = sbi_sm_group_control_enclave(&control);
  if (ret.error) {
    int error = keystone_group_sbi_result(ret, &control.abi, &cfg->abi);
    return error;
  }

  if (cfg->action == KEYSTONE_GROUP_CONTROL_RESUME)
    keystone_group_kick(enclave->engine_id);

  cfg->group_id = control.group_id;
  cfg->group_generation = control.group_generation;
  cfg->eid_generation = control.eid_generation;
  cfg->status = control.status;
  cfg->scheduler_epoch = control.scheduler_epoch;
  keystone_abi_init(&cfg->abi, sizeof(*cfg), KEYSTONE_GROUP_ABI_FEATURES);
  return 0;
}

static int keystone_group_test_snapshot(unsigned long data)
{
  struct keystone_ioctl_group_test_snapshot *cfg =
      (struct keystone_ioctl_group_test_snapshot *)data;
  struct sbiret ret;

  if (keystone_abi_validate(&cfg->snapshot.abi, sizeof(cfg->snapshot),
                            KEYSTONE_GROUP_TEST_ABI_FEATURES))
    return -EINVAL;
  ret = sbi_sm_group_test_snapshot(&cfg->snapshot);
  if (ret.error)
    return keystone_group_sbi_result(ret, &cfg->snapshot.abi,
                                     &cfg->snapshot.abi);
  return 0;
}

static int keystone_group_test_inject(unsigned long data)
{
  struct keystone_ioctl_group_test_injection *cfg =
      (struct keystone_ioctl_group_test_injection *)data;
  struct sbiret ret;

  if (keystone_abi_validate(&cfg->injection.abi, sizeof(cfg->injection),
                            KEYSTONE_GROUP_TEST_ABI_FEATURES))
    return -EINVAL;
  ret = sbi_sm_group_test_inject(&cfg->injection);
  if (ret.error)
    return keystone_group_sbi_result(ret, &cfg->injection.abi,
                                     &cfg->injection.abi);
  return 0;
}

static int keystone_group_perf_query(unsigned long data)
{
  struct keystone_ioctl_group_perf_snapshot *cfg =
      (struct keystone_ioctl_group_perf_snapshot *)data;
  unsigned long host_member_eid = cfg->snapshot.member_eid;
  struct enclave *member_enclave = NULL;
  struct sbiret ret;

  if (keystone_abi_validate(&cfg->snapshot.abi, sizeof(cfg->snapshot),
                            KEYSTONE_GROUP_PERF_ABI_FEATURES))
    return -EINVAL;
  if (!!cfg->snapshot.member_query != !!host_member_eid)
    return -EINVAL;
  if (host_member_eid) {
    member_enclave = get_enclave_by_id(host_member_eid);
    if (!member_enclave || member_enclave->eid == (unsigned long)-1)
      return -ENOENT;
    cfg->snapshot.member_eid = member_enclave->eid;
  }
  ret = sbi_sm_group_perf_query(&cfg->snapshot);
  if (ret.error)
    return keystone_group_sbi_result(ret, &cfg->snapshot.abi,
                                     &cfg->snapshot.abi);
  if (host_member_eid)
    cfg->snapshot.member_eid = host_member_eid;
  return 0;
}

long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
  long ret;
  char data[1024];
  bool lifecycle_locked = false;

  size_t ioc_size;

  if (!arg)
    return -EINVAL;

  if (_IOC_TYPE(cmd) != KEYSTONE_IOC_MAGIC)
    return -ENOTTY;

  ioc_size = _IOC_SIZE(cmd);
  if (!ioc_size || ioc_size > sizeof(data))
    return -EINVAL;

  memset(data, 0, sizeof(data));
  if (copy_from_user(data,(void __user *) arg, ioc_size))
    return -EFAULT;

  switch (cmd) {
    case KEYSTONE_IOC_CREATE_ENCLAVE:
    case KEYSTONE_IOC_FINALIZE_ENCLAVE:
    case KEYSTONE_IOC_DESTROY_ENCLAVE:
    case KEYSTONE_IOC_RUN_ENCLAVE:
    case KEYSTONE_IOC_RESUME_ENCLAVE:
    case KEYSTONE_IOC_UTM_INIT:
    case KEYSTONE_IOC_YXSTM_INIT:
    case KEYSTONE_IOC_GROUP_SET_COUNT:
    case KEYSTONE_IOC_GROUP_SET_HART_COUNT:
    case KEYSTONE_IOC_GROUP_CREATE:
    case KEYSTONE_IOC_GROUP_ACTIVATE:
    case KEYSTONE_IOC_GROUP_DESTROY:
    case KEYSTONE_IOC_GROUP_BIND_ENCLAVE:
    case KEYSTONE_IOC_GROUP_ENQUEUE_ENCLAVE:
    case KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL:
    case KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL_BATCH:
    case KEYSTONE_IOC_GROUP_CONTROL_ENCLAVE:
    case KEYSTONE_IOC_GROUP_CONFIG_TOPOLOGY:
    case KEYSTONE_IOC_GROUP_LEASE_WORKERS:
    case KEYSTONE_IOC_GROUP_RELEASE_WORKERS:
    case KEYSTONE_IOC_GROUP_PAUSE_MASTER:
      mutex_lock(&GROUP_LIFECYCLE_mutex);
      lifecycle_locked = true;
      break;
    default:
      break;
  }

  switch (cmd) {
    case KEYSTONE_IOC_CREATE_ENCLAVE:
      ret = keystone_create_enclave(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_FINALIZE_ENCLAVE:
      ret = keystone_finalize_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_DESTROY_ENCLAVE:
      ret = keystone_destroy_enclave(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_RUN_ENCLAVE:
      ret = keystone_run_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_RESUME_ENCLAVE:
      ret = keystone_resume_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_TEST_OS_ACCESS_STM_RUN_ENCLAVE:
      ret = keystone_test_os_access_stm_run_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_TEST_OS_ACCESS_STM_RESUME_ENCLAVE:
      ret = keystone_test_os_access_stm_resume_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_TEST_OS_ACCESS_EPM_RUN_ENCLAVE:
      ret = keystone_test_os_access_epm_run_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_TEST_OS_ACCESS_EPM_RESUME_ENCLAVE:
      ret = keystone_test_os_access_epm_resume_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_TEST_OTHER_OS_ACCESS_EPM_CREATE_ENCLAVE:
      ret = keystone_test_other_os_access_epm_create_enclave(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_TEST_OTHER_OS_ACCESS_EPM_FINALIZE_ENCLAVE:
      ret = keystone_test_other_os_access_epm_finalize_enclave((unsigned long) data);
      break;
    /* Note that following commands could have been implemented as a part of ADD_PAGE ioctl.
     * However, there was a weird bug in compiler that generates a wrong control flow
     * that ends up with an illegal instruction if we combine switch-case and if statements.
     * We didn't identified the exact problem, so we'll have these until we figure out */
    case KEYSTONE_IOC_UTM_INIT:
      ret = utm_init_ioctl(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_YXSTM_INIT:
      ret = YXSTM_init_ioctl(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_UTM_SHARE:
      ret = keystone_share_utm(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_GROUP_SET_COUNT:
      ret = keystone_group_set_count((unsigned long) data);
      break;
    case KEYSTONE_IOC_GROUP_SET_HART_COUNT:
      ret = keystone_group_set_hart_count((unsigned long) data);
      break;
    case KEYSTONE_IOC_GROUP_QUERY:
      ret = keystone_group_query((unsigned long) data);
      break;
    case KEYSTONE_IOC_GROUP_CREATE:
    case KEYSTONE_IOC_GROUP_ACTIVATE:
    case KEYSTONE_IOC_GROUP_DESTROY:
      ret = keystone_group_lifecycle((unsigned long) data, cmd);
      break;
    case KEYSTONE_IOC_GROUP_BIND_ENCLAVE:
      ret = keystone_group_bind_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_GROUP_ENQUEUE_ENCLAVE:
      ret = keystone_group_enqueue_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_GROUP_POLL_BLOCKED_OCALL:
      ret = keystone_group_poll_blocked_ocall((unsigned long) data);
      break;
    case KEYSTONE_IOC_GROUP_RUN_HART:
      ret = keystone_group_run_hart((unsigned long) data);
      break;
    case KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL:
      ret = keystone_group_resume_blocked_ocall((unsigned long) data);
      break;
    case KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL_BATCH:
      ret = keystone_group_resume_blocked_ocall_batch((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_CONTROL_ENCLAVE:
      ret = keystone_group_control_enclave((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_TEST_SNAPSHOT:
      ret = keystone_group_test_snapshot((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_TEST_INJECT:
      ret = keystone_group_test_inject((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_PERF_QUERY:
      ret = keystone_group_perf_query((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_CONFIG_TOPOLOGY:
      ret = keystone_group_config_topology_ioctl((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_QUERY_TOPOLOGY:
      ret = keystone_group_query_topology_ioctl((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_LEASE_WORKERS:
      ret = keystone_group_lease_workers_ioctl(filep,
                                                (unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_RELEASE_WORKERS:
      ret = keystone_group_release_workers_ioctl((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_RUN_MASTER:
      ret = keystone_group_run_master_ioctl((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_WAIT_EVENT:
      ret = keystone_group_wait_event_ioctl((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_PAUSE_MASTER:
      ret = keystone_group_pause_master_ioctl((unsigned long)data);
      break;
    case KEYSTONE_IOC_GROUP_HOST_HEARTBEAT_ACK:
      ret = keystone_group_heartbeat_ack_ioctl((unsigned long)data);
      break;
    default:
      if (lifecycle_locked)
        mutex_unlock(&GROUP_LIFECYCLE_mutex);
      return -ENOSYS;
  }

  if (lifecycle_locked)
    mutex_unlock(&GROUP_LIFECYCLE_mutex);

  if (copy_to_user((void __user*) arg, data, ioc_size))
    return -EFAULT;

  return ret;
}

int keystone_release(struct inode *inode, struct file *file) {
  unsigned long ueid = (unsigned long)(file->private_data);
  struct enclave *enclave;

  /* enclave has been already destroyed */
  if (!ueid) {
    int ret;

    mutex_lock(&GROUP_LIFECYCLE_mutex);
    ret = keystone_group_release_for_file(file);
    mutex_unlock(&GROUP_LIFECYCLE_mutex);
    return ret;
  }

  /* We need to send destroy enclave just the eid to close. */
  enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    /* If eid is set to the invalid id, then we do not do anything. */
    return -EINVAL;
  }
  if (enclave->close_on_pexit) {
    int ret;
    mutex_lock(&GROUP_LIFECYCLE_mutex);
    ret = __keystone_destroy_enclave(ueid);
    mutex_unlock(&GROUP_LIFECYCLE_mutex);
    return ret;
  }
  return 0;
}
