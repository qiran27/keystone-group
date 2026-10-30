//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "riscv64.h"
#include <linux/kernel.h>
#include "keystone.h"

static const char keystone_utm_compound_pinnable_marker[]
    __used = "keystone-utm-compound-pinnable-v2";
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/limits.h>

#define KEYSTONE_GROUP_MIN_SLICE_PAGES 512UL
/* The first member is the master and is expected to be at least as large as a
 * worker. Cap the future-member reservation to avoid multiplying a very large
 * master slice by the full group capacity. */
#define KEYSTONE_GROUP_FUTURE_SLICE_CAP_PAGES 5120UL
#define KEYSTONE_GROUP_SLICE_ALIGN_PAGES 512UL
#define KEYSTONE_GROUP_SLICE_ALIGN_SIZE \
  (KEYSTONE_GROUP_SLICE_ALIGN_PAGES * PAGE_SIZE)
#define KEYSTONE_EPM_BUDDY_MAX_PAGES 1024UL

/* Destroy all memory associated with an EPM */
int epm_destroy(struct epm* epm) {
  int i;

  if(!epm->ptr || !epm->size)
    return 0;

  if (epm->is_group_slice) {
    mutex_lock(&EPM_GROUP_mutex);
    for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
      if (global_epm_groups.slots[i].engine_id != epm->group_id)
        continue;

      if (global_epm_groups.slots[i].ref_count > 0)
        global_epm_groups.slots[i].ref_count--;
      if (global_epm_groups.slots[i].member_count > 0)
        global_epm_groups.slots[i].member_count--;

      if (global_epm_groups.slots[i].ref_count == 0) {
        struct epm pool = global_epm_groups.slots[i].pool;
        keystone_info("group EPM pool freed: group=%llu pa=0x%lx size=0x%lx\n",
                      epm->group_id,
                      (unsigned long)pool.pa,
                      (unsigned long)pool.size);
        memset(&global_epm_groups.slots[i], 0, sizeof(global_epm_groups.slots[i]));
        mutex_unlock(&EPM_GROUP_mutex);
        return epm_destroy(&pool);
      }
      mutex_unlock(&EPM_GROUP_mutex);
      memset(epm, 0, sizeof(*epm));
      return 0;
    }
    mutex_unlock(&EPM_GROUP_mutex);
    memset(epm, 0, sizeof(*epm));
    return 0;
  }

  /* free the EPM hold by the enclave */
  if (epm->is_cma) {
    if (epm->is_dma_pages) {
      dma_free_pages(keystone_dev.this_device,
                     epm->size,
                     virt_to_page((void*)epm->ptr),
                     epm->dma_handle,
                     DMA_BIDIRECTIONAL);
    } else {
      dma_free_coherent(keystone_dev.this_device,
                        epm->size,
                        (void*)epm->ptr,
                        epm->dma_handle);
    }
  } else {
    free_pages(epm->ptr, epm->order);
  }

  return 0;
}

int epm_group_slice_init(struct epm* epm, unsigned int min_pages,
                         unsigned long long ms, unsigned long long engine_id)
{
  int i;
  int free_slot = -1;
  size_t slice_size;
  size_t pool_pages;
  size_t slice_pages;
  size_t future_slice_pages;
  size_t remaining_pages;

  if (!epm || !min_pages || !ms || !engine_id)
    return -EINVAL;
  if (ms > KEYSTONE_GROUP_MEMBER_LIMIT) {
    keystone_err("group %llu capacity %llu exceeds ABI limit %u\n",
                 engine_id, ms,
                 (unsigned int)KEYSTONE_GROUP_MEMBER_LIMIT);
    return -ENOSPC;
  }

  slice_pages = min_pages;
  if (slice_pages < KEYSTONE_GROUP_MIN_SLICE_PAGES)
    slice_pages = KEYSTONE_GROUP_MIN_SLICE_PAGES;
  if (slice_pages >
      SIZE_MAX - (KEYSTONE_GROUP_SLICE_ALIGN_PAGES - 1))
    return -EINVAL;
  /* Keep every variable-size member slice suitable for 2 MiB leaf mappings. */
  slice_pages = ALIGN(slice_pages, KEYSTONE_GROUP_SLICE_ALIGN_PAGES);
  if (slice_pages > SIZE_MAX / PAGE_SIZE)
    return -EINVAL;
  slice_size = slice_pages * PAGE_SIZE;
  future_slice_pages = slice_pages;
  if (future_slice_pages > KEYSTONE_GROUP_FUTURE_SLICE_CAP_PAGES)
    future_slice_pages = KEYSTONE_GROUP_FUTURE_SLICE_CAP_PAGES;
  if (future_slice_pages < KEYSTONE_GROUP_MIN_SLICE_PAGES)
    future_slice_pages = KEYSTONE_GROUP_MIN_SLICE_PAGES;

  mutex_lock(&EPM_GROUP_mutex);

  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    struct EPM_GROUP_SLOT* slot = &global_epm_groups.slots[i];
    if (slot->engine_id == engine_id) {
      size_t reserved_tail;
      unsigned long long remaining_members;

      if (slot->member_capacity != ms) {
        keystone_err("group %llu capacity mismatch: existing=%llu requested=%llu\n",
                     engine_id, slot->member_capacity, ms);
        mutex_unlock(&EPM_GROUP_mutex);
        return -EINVAL;
      }
      if (slot->member_count >= slot->member_capacity) {
        keystone_err("group %llu member capacity exceeded: count=%llu capacity=%llu\n",
                     engine_id, slot->member_count, slot->member_capacity);
        mutex_unlock(&EPM_GROUP_mutex);
        return -ENOSPC;
      }
      remaining_members =
          slot->member_capacity - slot->member_count - 1;
      if (remaining_members > SIZE_MAX / slot->minimum_slice_size) {
        mutex_unlock(&EPM_GROUP_mutex);
        return -EINVAL;
      }
      reserved_tail =
          (size_t)remaining_members * slot->minimum_slice_size;
      if (slot->next_offset + slice_size < slot->next_offset ||
          slot->next_offset + slice_size > slot->pool.size ||
          reserved_tail >
              slot->pool.size - (slot->next_offset + slice_size)) {
        keystone_err("group %llu member slice reservation exhausted: requested=0x%lx remaining_members=%llu minimum_slice=0x%lx available=0x%lx\n",
                     engine_id, (unsigned long)slice_size,
                     remaining_members,
                     (unsigned long)slot->minimum_slice_size,
                     (unsigned long)(slot->pool.size - slot->next_offset));
        mutex_unlock(&EPM_GROUP_mutex);
        return -ENOSPC;
      }
      if (!IS_ALIGNED(slot->pool.pa + slot->next_offset,
                      KEYSTONE_GROUP_SLICE_ALIGN_SIZE)) {
        keystone_err("group %llu member slice is not 2 MiB aligned: pool_pa=0x%lx offset=0x%lx\n",
                     engine_id,
                     (unsigned long)slot->pool.pa,
                     (unsigned long)slot->next_offset);
        mutex_unlock(&EPM_GROUP_mutex);
        return -EINVAL;
      }

      memset(epm, 0, sizeof(*epm));
      epm->root_page_table = (pte_t*)(slot->pool.ptr + slot->next_offset);
      epm->ptr = slot->pool.ptr + slot->next_offset;
      epm->pa = slot->pool.pa + slot->next_offset;
      epm->dma_handle = slot->pool.dma_handle + slot->next_offset;
      epm->size = slice_size;
      epm->is_cma = slot->pool.is_cma;
      epm->is_dma_pages = slot->pool.is_dma_pages;
      epm->is_group_slice = true;
      epm->group_id = engine_id;
      epm->group_pa = slot->pool.pa;
      epm->group_size = slot->pool.size;
      keystone_info("group EPM slice assigned: group=%llu member=%llu/%llu requested=0x%lx slice_pa=0x%lx slice_size=0x%lx pool_pa=0x%lx pool_size=0x%lx\n",
                    engine_id,
                    slot->member_count + 1,
                    slot->member_capacity,
                    (unsigned long)(PAGE_SIZE * min_pages),
                    (unsigned long)epm->pa,
                    (unsigned long)epm->size,
                    (unsigned long)epm->group_pa,
                    (unsigned long)epm->group_size);
      slot->next_offset += slice_size;
      slot->ref_count++;
      slot->member_count++;
      mutex_unlock(&EPM_GROUP_mutex);
      /*
       * The whole group pool is zeroed by epm_init() before any member is
       * finalized.  After the first member finalizes, SM protects the whole
       * group EPM with PMP, so S-mode must not touch later slices here.
       */
      return 0;
    }

    if (!slot->engine_id && free_slot < 0)
      free_slot = i;
  }

  if (free_slot < 0) {
    mutex_unlock(&EPM_GROUP_mutex);
    return -ENOSPC;
  }

  if (ms - 1 > SIZE_MAX / future_slice_pages) {
    mutex_unlock(&EPM_GROUP_mutex);
    return -EINVAL;
  }
  remaining_pages = (size_t)(ms - 1) * future_slice_pages;
  if (slice_pages > SIZE_MAX - remaining_pages) {
    mutex_unlock(&EPM_GROUP_mutex);
    return -EINVAL;
  }
  /*
   * Group creation starts with the master. Reserve its actual (larger) EPM
   * slice plus one independently sized minimum slice for every future
   * member. Later members consume their own aligned requested size, rather
   * than inheriting the master's size. This avoids capacity * master-size
   * over-allocation for groups with a large master and small workers.
   */
  pool_pages = slice_pages + remaining_pages;
  if (pool_pages < slice_pages || pool_pages > UINT_MAX ||
      pool_pages > SIZE_MAX / PAGE_SIZE) {
    mutex_unlock(&EPM_GROUP_mutex);
    return -EINVAL;
  }

  if (epm_init(&global_epm_groups.slots[free_slot].pool, pool_pages)) {
    memset(&global_epm_groups.slots[free_slot], 0, sizeof(global_epm_groups.slots[free_slot]));
    mutex_unlock(&EPM_GROUP_mutex);
    return -ENOMEM;
  }
  if (!IS_ALIGNED(global_epm_groups.slots[free_slot].pool.pa,
                  KEYSTONE_GROUP_SLICE_ALIGN_SIZE)) {
    struct epm pool = global_epm_groups.slots[free_slot].pool;

    keystone_err("group %llu EPM pool is not 2 MiB aligned: pa=0x%lx size=0x%lx\n",
                 engine_id,
                 (unsigned long)pool.pa,
                 (unsigned long)pool.size);
    memset(&global_epm_groups.slots[free_slot], 0,
           sizeof(global_epm_groups.slots[free_slot]));
    mutex_unlock(&EPM_GROUP_mutex);
    epm_destroy(&pool);
    return -ENOMEM;
  }

  global_epm_groups.slots[free_slot].engine_id = engine_id;
  global_epm_groups.slots[free_slot].member_capacity = ms;
  global_epm_groups.slots[free_slot].member_count = 0;
  global_epm_groups.slots[free_slot].minimum_slice_size =
      future_slice_pages * PAGE_SIZE;
  global_epm_groups.slots[free_slot].next_offset = 0;
  global_epm_groups.slots[free_slot].ref_count = 0;
  keystone_info("group EPM pool allocated: group=%llu capacity=%llu requested_pages=%u first_slice_pages=%zu minimum_slice_pages=%lu pages=%zu pa=0x%lx size=0x%lx\n",
                engine_id,
                ms,
                min_pages,
                slice_pages,
                (unsigned long)future_slice_pages,
                pool_pages,
                (unsigned long)global_epm_groups.slots[free_slot].pool.pa,
                (unsigned long)global_epm_groups.slots[free_slot].pool.size);
  mutex_unlock(&EPM_GROUP_mutex);

  return epm_group_slice_init(epm, min_pages, ms, engine_id);
}

/* Create an EPM and initialize the free list */
int epm_init(struct epm* epm, unsigned int min_pages)
{
  vaddr_t epm_vaddr = 0;
  unsigned long order = 0;
  unsigned long count = min_pages;
  phys_addr_t device_phys_addr = 0;
  dma_addr_t dma_handle = 0;
  struct page* dma_pages = NULL;
  void* dma_ptr = NULL;

  if (!epm || !min_pages)
    return -EINVAL;

  /* try to allocate contiguous memory */
  epm->is_cma = 0;
  epm->is_dma_pages = 0;
  epm->dma_handle = 0;
  order = min_pages > 1 ? ilog2(min_pages - 1) + 1 : 0;
  count = 1UL << order;

  /* Keep the buddy fast path for pools supported by MAX_ORDER.  Larger pools
   * require a CMA-backed contiguous allocation. */
  if (min_pages <= KEYSTONE_EPM_BUDDY_MAX_PAGES) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    if (order < MAX_PAGE_ORDER)
#else
    if (order < MAX_ORDER)
#endif
      epm_vaddr = (vaddr_t)__get_free_pages(
          GFP_HIGHUSER | __GFP_NOWARN, order);
  }

  /* Try the page-based DMA API first.  Some vendor RISC-V 5.15 DMA paths do
   * not provide alloc_pages for a miscdevice, so retain the coherent CMA API
   * as the board-tested fallback used by UTM/YXSTM. */
  if (!epm_vaddr) {
    count = min_pages;
    dma_pages = dma_alloc_pages(keystone_dev.this_device,
                                count << PAGE_SHIFT,
                                &dma_handle,
                                DMA_BIDIRECTIONAL,
                                GFP_KERNEL | __GFP_NOWARN);
    if (dma_pages) {
      epm_vaddr = (vaddr_t)page_address(dma_pages);
      device_phys_addr = page_to_phys(dma_pages);
      epm->is_cma = 1;
      epm->is_dma_pages = 1;
      epm->dma_handle = dma_handle;
      keystone_info("EPM allocated via DMA/CMA pages: pages=%lu pa=0x%lx size=0x%lx\n",
                    count,
                    (unsigned long)device_phys_addr,
                    count << PAGE_SHIFT);
    }
  }

  if (!epm_vaddr) {
    count = min_pages;
    dma_ptr = dma_alloc_coherent(keystone_dev.this_device,
                                 count << PAGE_SHIFT,
                                 &dma_handle,
                                 GFP_KERNEL | __GFP_NOWARN);
    if (dma_ptr) {
      epm_vaddr = (vaddr_t)dma_ptr;
      device_phys_addr = (phys_addr_t)dma_handle;
      epm->is_cma = 1;
      epm->is_dma_pages = 0;
      epm->dma_handle = dma_handle;
      keystone_info("EPM allocated via coherent DMA/CMA: pages=%lu pa=0x%lx size=0x%lx\n",
                    count,
                    (unsigned long)device_phys_addr,
                    count << PAGE_SHIFT);
    }
  }

  if(!epm_vaddr) {
    keystone_err("failed to allocate %lu page(s)\n", count);
    return -ENOMEM;
  }

  /* zero out */
  memset((void*)epm_vaddr, 0, PAGE_SIZE*count);

  epm->root_page_table = (void*)epm_vaddr;
  epm->pa = (epm->is_cma) ? device_phys_addr : __pa(epm_vaddr);
  epm->order = order;
  epm->size = count << PAGE_SHIFT;
  epm->ptr = epm_vaddr;
  epm->is_group_slice = false;
  epm->group_id = 0;
  epm->group_pa = epm->pa;
  epm->group_size = epm->size;

  return 0;
}

int utm_destroy(struct utm* utm){

  if(utm->ptr != NULL){
    if (utm->is_cma) {
      /* Free CMA allocated memory */
      /* Note: We allocated extra memory for NAPOT alignment, so we need to free
       * the original allocation, not the aligned pointer. The original allocation
       * info is stored in utm->cma_ptr and utm->cma_size. */
      dma_free_coherent(keystone_dev.this_device,
          utm->cma_size,
          utm->cma_ptr,
          utm->cma_pa);
      keystone_info("UTM freed via CMA: size=%zu, pa=0x%lx\n",
                    utm->size, (unsigned long)utm->pa);
    } else {
      /* Free buddy allocator memory */
      free_pages((vaddr_t)utm->ptr, utm->order);
      keystone_info("UTM freed via buddy: order=%lu, pa=0x%lx\n",
                    utm->order, (unsigned long)utm->pa);
    }
    utm->ptr = NULL;
    utm->pa = 0;
  }

  return 0;
}

int utm_init(struct utm* utm, size_t untrusted_size)
{
  unsigned long req_pages = 0;
  unsigned long order = 0;
  unsigned long count;
  size_t size;
  phys_addr_t device_phys_addr = 0;
  const size_t buddy_threshold = 4UL * 1024 * 1024;
  bool prefer_buddy = false;

  req_pages += PAGE_UP(untrusted_size)/PAGE_SIZE;
  order = ilog2(req_pages - 1) + 1;
  count = 0x1 << order;
  size = count * PAGE_SIZE;

  utm->order = order;
  utm->size = size;
  utm->is_cma = false;
  utm->pa = 0;
  utm->ptr = NULL;
  utm->cma_ptr = NULL;
  utm->cma_pa = 0;
  utm->cma_size = 0;
  atomic_set(&utm->ref_count, 1);  /* Initialize reference count to 1 (owner) */

  /*
   * Temporary benchmark policy:
   * - small UTM (<= 4MB): prefer buddy for better CPU access performance
   * - large UTM (> 4MB): prefer CMA for contiguous allocation success rate
   */
  prefer_buddy = (size <= buddy_threshold);

  keystone_info("UTM allocation policy: size=%lu bytes, threshold=%lu bytes, prefer=%s\n",
                (unsigned long)size,
                (unsigned long)buddy_threshold,
                prefer_buddy ? "buddy" : "cma");

  if (prefer_buddy) {
    /* ========== 1) Buddy allocator first for small UTM ========== */
    /* Buddy allocator with order N guarantees 2^N page alignment,
     * which satisfies NAPOT requirements (size = 2^N pages, addr aligned to size) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    if (order < MAX_PAGE_ORDER)
#else
    if (order < MAX_ORDER)
#endif
    {
      /* vm_insert_page() requires high-order allocations to be represented as
       * compound pages so every tail page has a valid refcount. */
      utm->ptr = (void*) __get_free_pages(
          GFP_HIGHUSER | __GFP_ZERO | __GFP_COMP, order);
      if (utm->ptr) {
        utm->pa = __pa(utm->ptr);
        utm->is_cma = false;
        keystone_info("UTM allocated via buddy: %lu bytes (order=%lu, pa=0x%lx)\n",
                      (unsigned long)size, order, (unsigned long)utm->pa);
        return 0;
      }
    }

    keystone_warn("UTM: buddy allocation failed for %lu bytes, fallback to CMA\n",
                  (unsigned long)size);
  }

  /* ========== 2) CMA path (preferred for large UTM, fallback for small UTM) ========== */
  /* NAPOT mode requires: address aligned to size (addr % size == 0)
   * CMA doesn't guarantee this, so we allocate 2x size and align within.
   * This ensures UTM can use PMP_PRI_BOTTOM to share PMP register with OS. */
#ifdef CONFIG_CMA
  {
    size_t alloc_size = size * 2;  /* Allocate 2x to guarantee alignment */
    void* cma_ptr = dma_alloc_coherent(keystone_dev.this_device,
                                       alloc_size,
                                       &device_phys_addr,
                                       GFP_KERNEL);
    if (cma_ptr) {
      /* Find NAPOT-aligned address within the allocation */
      paddr_t aligned_pa = (device_phys_addr + size - 1) & ~(size - 1);
      size_t offset = aligned_pa - device_phys_addr;
      
      utm->cma_ptr = cma_ptr;
      utm->cma_pa = device_phys_addr;
      utm->cma_size = alloc_size;
      utm->ptr = (void*)((uintptr_t)cma_ptr + offset);
      utm->pa = aligned_pa;
      utm->is_cma = true;
      
      keystone_info("UTM allocated via CMA: %lu bytes (pa=0x%lx, aligned from 0x%lx, offset=%zu)\n",
                    (unsigned long)size, (unsigned long)utm->pa, 
                    (unsigned long)device_phys_addr, offset);
      return 0;
    }
    keystone_warn("UTM: dma_alloc_coherent(%lu) failed, fallback to buddy\n",
                  (unsigned long)alloc_size);
  }
#endif

  /* ========== 3) Final fallback: buddy allocator ========== */
  /* Needed when:
   * - large UTM prefers CMA but CMA fails
   * - small UTM prefers buddy, buddy fails, and CMA is unavailable or also fails */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
  if (order < MAX_PAGE_ORDER)
#else
  if (order < MAX_ORDER)
#endif
  {
    utm->ptr = (void*) __get_free_pages(
        GFP_HIGHUSER | __GFP_ZERO | __GFP_COMP, order);
    if (utm->ptr) {
      utm->pa = __pa(utm->ptr);
      utm->is_cma = false;
      keystone_info("UTM allocated via buddy: %lu bytes (order=%lu, pa=0x%lx)\n",
                    (unsigned long)size, order, (unsigned long)utm->pa);
      return 0;
    }
  }

  keystone_err("failed to allocate UTM (requested %lu bytes)\n", (unsigned long)size);
  return -ENOMEM;
}


int YXSTM_destroy(struct YXSTM* YXSTM){

  if(YXSTM->ptr != NULL){
    if (YXSTM->is_cma) {
      /* Free CMA allocated memory */
      dma_free_coherent(keystone_dev.this_device,
          YXSTM->cma_size,
          YXSTM->cma_ptr,
          YXSTM->cma_pa);
      keystone_info("YXSTM freed via CMA: size=%zu, pa=0x%lx\n",
                    YXSTM->size, (unsigned long)YXSTM->pa);
    } else {
      free_pages((vaddr_t)YXSTM->ptr, YXSTM->order);
      keystone_info("YXSTM freed via buddy: size=%zu\n", YXSTM->size);
    }
  }

  return 0;
}

int YXSTM_init(struct YXSTM* YXSTM, size_t YXSTrusted_size)
{
  unsigned long req_pages = 0;
  unsigned long order = 0;
  unsigned long count;
  req_pages += PAGE_UP(YXSTrusted_size)/PAGE_SIZE;
  
  /* Handle edge case: if req_pages is 0 or 1, set order to 0 */
  if (req_pages <= 1) {
    order = 0;
  } else {
    order = ilog2(req_pages - 1) + 1;
  }
  count = 0x1 << order;

  YXSTM->order = order;
  YXSTM->size = count * PAGE_SIZE;
  YXSTM->is_cma = false;
  YXSTM->pa = 0;
  YXSTM->ptr = NULL;
  YXSTM->cma_ptr = NULL;
  YXSTM->cma_pa = 0;
  YXSTM->cma_size = 0;

  /* For large allocations (order >= 10, i.e., >= 4MB), try CMA first */
  if (order >= 10 && keystone_dev.this_device) {
    /* YXSTM needs NAPOT alignment: paddr must be aligned to size */
    size_t alloc_size = YXSTM->size * 2;  /* Allocate 2x for alignment */
    dma_addr_t device_phys_addr;
    void* cma_ptr = dma_alloc_coherent(keystone_dev.this_device, alloc_size,
                                       &device_phys_addr, GFP_KERNEL);
    
    if (cma_ptr) {
      /* Find NAPOT-aligned address within the allocation */
      phys_addr_t aligned_pa = (device_phys_addr + YXSTM->size - 1) & ~(YXSTM->size - 1);
      size_t offset = aligned_pa - device_phys_addr;
      
      YXSTM->cma_ptr = cma_ptr;
      YXSTM->cma_pa = device_phys_addr;
      YXSTM->cma_size = alloc_size;
      YXSTM->ptr = (void*)((uintptr_t)cma_ptr + offset);
      YXSTM->pa = aligned_pa;
      YXSTM->is_cma = true;
      
      keystone_info("YXSTM allocated via CMA: %lu bytes (pa=0x%lx, aligned from 0x%lx, offset=%zu)\n",
                    (unsigned long)YXSTM->size, (unsigned long)YXSTM->pa, 
                    (unsigned long)device_phys_addr, offset);
      return 0;
    }
    keystone_warn("CMA allocation failed for YXSTM, falling back to buddy allocator\n");
  }

  /* Fallback to buddy allocator for smaller allocations or if CMA fails */
  YXSTM->ptr = (void*) __get_free_pages(GFP_HIGHUSER, order);
  if (!YXSTM->ptr) {
    keystone_err("failed to allocate YXSTM (requested = %zu bytes, order = %lu, pages = %lu)\n",
                 YXSTrusted_size, order, (1UL << order));
    return -ENOMEM;
  }

  YXSTM->pa = __pa(YXSTM->ptr);
  YXSTM->is_cma = false;
  
  keystone_info("YXSTM allocated via buddy: %lu bytes (order=%lu, pa=0x%lx)\n",
                (unsigned long)YXSTM->size, order, (unsigned long)YXSTM->pa);

  if (YXSTM->size != YXSTrusted_size) {
    /* Instead of failing, we just warn that the user has to fix the parameter. */
    keystone_warn("YX share trusted buffer size is not multiple of PAGE_SIZE\n");
  }

  return 0;
}
