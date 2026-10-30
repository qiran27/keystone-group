//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
//#include <asm/io.h>
//#include <asm/page.h>
#include "keystone.h"
#include "keystone-sbi.h"

#include <linux/version.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include "keystone_user.h"
#include <linux/spinlock.h>
spinlock_t YXSTM_spinlock;
struct mutex EPM_GROUP_mutex;
struct mutex GROUP_LIFECYCLE_mutex;
#define   DRV_DESCRIPTION   "keystone enclave"
#define   DRV_VERSION       "1.0.0-group-pmp-v6"

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Dayeol Lee <dayeol@berkeley.edu>");
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("Dual BSD/GPL");

static const struct file_operations keystone_fops = {
    .owner          = THIS_MODULE,
    .mmap           = keystone_mmap,
    .unlocked_ioctl = keystone_ioctl,
    .release        = keystone_release
};

struct miscdevice keystone_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "keystone_enclave",
  .fops = &keystone_fops,
  .mode = 0666,
};

/*
 * Magic page offset to force mapping own UTM instead of shared UTM.
 * This must match KEYSTONE_OWN_UTM_OFFSET in keystone_user.h
 */
#define KEYSTONE_OWN_UTM_PGOFF  0xDEAD0000UL

static const char keystone_utm_pinnable_mapping_marker[]
    __used = "keystone-utm-pinnable-vm-insert-page-v1";
static const char keystone_utm_io_uring_mapping_marker[]
    __used = "keystone-utm-io-uring-detached-file-vma-v1";

/*
 * Linux 5.15 io_uring rejects every registered-buffer VMA with vm_file set,
 * except shmem and hugetlb mappings. UTM is ordinary refcounted RAM inserted
 * by this driver, but mmap initially associates the VMA with the Keystone
 * device file. Transfer that file reference to vm_private_data so io_uring
 * can pin the pages while the VMA still keeps the enclave file alive.
 */
static void keystone_utm_vma_open(struct vm_area_struct *vma)
{
  struct file *owner = vma->vm_private_data;

  if (owner)
    get_file(owner);
}

static void keystone_utm_vma_close(struct vm_area_struct *vma)
{
  struct file *owner = vma->vm_private_data;

  if (owner) {
    vma->vm_private_data = NULL;
    fput(owner);
  }
}

static const struct vm_operations_struct keystone_utm_vm_ops = {
  .open = keystone_utm_vma_open,
  .close = keystone_utm_vma_close,
};

static int keystone_make_utm_io_uring_pinnable(struct vm_area_struct *vma)
{
  if (!vma->vm_file || vma->vm_private_data)
    return -EINVAL;

  /* mmap_region() owns this reference. The VMA close callback releases it. */
  vma->vm_private_data = vma->vm_file;
  vma->vm_file = NULL;
  vma->vm_ops = &keystone_utm_vm_ops;
  return 0;
}

/* UTM is ordinary buddy/CMA-backed RAM. Mapping it as VM_PFNMAP prevents
 * io_uring from pinning long-lived registered buffers, so expose its struct
 * pages explicitly. The VMA teardown path drops the inserted mapping refs. */
static int keystone_map_utm_pages(struct vm_area_struct *vma,
                                  vaddr_t paddr, unsigned long size)
{
  unsigned long address;
  unsigned long pfn;
  int ret;

  if (!PAGE_ALIGNED(paddr) || !PAGE_ALIGNED(size))
    return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
  vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP);
#else
  vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP;
#endif
  pfn = paddr >> PAGE_SHIFT;
  for (address = vma->vm_start; address < vma->vm_start + size;
       address += PAGE_SIZE, ++pfn) {
    if (!pfn_valid(pfn))
      return -EINVAL;
    ret = vm_insert_page(vma, address, pfn_to_page(pfn));
    if (ret) {
      keystone_err("UTM mmap page insertion failed: index=%lu pfn=0x%lx "
                   "page_count=%d ret=%d\n",
                   (address - vma->vm_start) >> PAGE_SHIFT, pfn,
                   page_count(pfn_to_page(pfn)), ret);
      return ret;
    }
  }
  return keystone_make_utm_io_uring_pinnable(vma);
}

int keystone_mmap(struct file* filp, struct vm_area_struct *vma)
{
  struct utm* utm;
  struct utm* shared_utm;
  struct epm* epm;
  struct enclave* enclave;
  unsigned long vsize, psize;
  vaddr_t paddr;
  bool force_own_utm = false;

  enclave = get_enclave_by_id((unsigned long) filp->private_data);
  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  utm = enclave->utm;
  shared_utm = enclave->shared_utm;
  epm = enclave->epm;
  vsize = vma->vm_end - vma->vm_start;

  /*
   * Check for magic offset that forces mapping own UTM.
   * This is used in shared UTM mode when the Host needs to access
   * the enclave's own UTM for OCALL communication, separate from
   * the shared UTM used for data transfer.
   */
  if (vma->vm_pgoff == KEYSTONE_OWN_UTM_PGOFF) {
    force_own_utm = true;
    vma->vm_pgoff = 0;  /* Reset offset for actual mapping */
  }

  if(enclave->is_init){
    if (vsize > PAGE_SIZE)
      return -EINVAL;
    /* EPM: small page mapping with offset - use remap_pfn_range with correct PA */
    /* epm->pa is always set correctly (for both buddy and CMA allocation) */
    paddr = epm->pa + (vma->vm_pgoff << PAGE_SHIFT);
    return remap_pfn_range(vma,
                           vma->vm_start,
                           paddr >> PAGE_SHIFT,
                           vsize, vma->vm_page_prot);
  }
  else
  {
    /*
     * Shared UTM Support for Dual Enclave Parallel Encryption
     * ========================================================
     * 
     * Memory mapping modes:
     * 
     * 1. force_own_utm=true (KEYSTONE_OWN_UTM_OFFSET):
     *    Always map the enclave's own UTM, regardless of shared_utm.
     *    Used for OCALL communication in shared UTM mode.
     * 
     * 2. force_own_utm=false, shared_utm exists:
     *    Map the shared UTM (from owner enclave) for data transfer.
     * 
     * 3. force_own_utm=false, no shared_utm:
     *    Map the enclave's own UTM (normal mode).
     */
    if (force_own_utm) {
      /* Force mapping own UTM for OCALL communication */
      if (!utm) {
        keystone_err("Own UTM mmap failed: no UTM allocated\n");
        return -EINVAL;
      }
      psize = utm->size;
      if (vsize > psize) {
        keystone_err("Own UTM mmap failed: vsize=%lu > psize=%lu\n", vsize, psize);
        return -EINVAL;
      }
      paddr = utm->pa;
      
      // keystone_info("Own UTM mmap (forced): is_cma=%d, pa=0x%lx, vsize=%lu\n", 
      //               utm->is_cma, (unsigned long)paddr, vsize);
    } else if (shared_utm && vsize <= shared_utm->size) {
      /* Map shared UTM (from owner enclave) */
      psize = shared_utm->size;
      paddr = shared_utm->pa;
      
      // keystone_info("Shared UTM mmap: is_cma=%d, pa=0x%lx, vsize=%lu, owner_eid=%lu\n", 
      //               shared_utm->is_cma, (unsigned long)paddr, vsize, enclave->owner_eid);
    } else {
      /* Map own UTM */
      if (!utm) {
        keystone_err("UTM mmap failed: no UTM allocated\n");
        return -EINVAL;
      }
      psize = utm->size;
      if (vsize > psize) {
        keystone_err("UTM mmap failed: vsize=%lu > psize=%lu (no shared_utm available)\n",
                     vsize, psize);
        return -EINVAL;
      }
      paddr = utm->pa;
      
      // keystone_info("UTM mmap: is_cma=%d, pa=0x%lx, vsize=%lu\n", 
      //               utm->is_cma, (unsigned long)paddr, vsize);
    }
    
    return keystone_map_utm_pages(vma, paddr, vsize);
  }
}

static int __init keystone_dev_init(void)
{
  int  ret;

  spin_lock_init(&YXSTM_spinlock); // 初始化锁
  mutex_init(&EPM_GROUP_mutex);
  mutex_init(&GROUP_LIFECYCLE_mutex);

  ret = keystone_group_driver_init();
  if (ret)
    return ret;

  ret = misc_register(&keystone_dev);
  if (ret < 0)
  {
    pr_err("keystone_enclave: misc_register() failed\n");
    keystone_group_driver_exit();
    return ret;  // Must return immediately on failure
  }

  /* misc_register() does not initialize a DMA mask.  Both masks are needed
   * before the EPM/UTM/YXSTM CMA paths can use the DMA API reliably. */
  ret = dma_coerce_mask_and_coherent(keystone_dev.this_device,
                                     DMA_BIT_MASK(32));
  if (ret) {
    pr_err("keystone_enclave: failed to configure 32-bit DMA mask: %d\n",
           ret);
    misc_deregister(&keystone_dev);
    keystone_group_driver_exit();
    return ret;
  }

  pr_info("keystone_enclave: " DRV_DESCRIPTION " v" DRV_VERSION "\n");
  return 0;
}

static void __exit keystone_dev_exit(void)
{
  pr_info("keystone_enclave: keystone_dev_exit()\n");
  keystone_group_driver_exit();
  misc_deregister(&keystone_dev);
  return;
}

module_init(keystone_dev_init);
module_exit(keystone_dev_exit);
