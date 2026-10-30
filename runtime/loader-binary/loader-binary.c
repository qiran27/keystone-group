#include "loader/loader.h"
#include "mm/vm.h"
#include "mm/mm.h"
#include "mm/common.h"
#include "mm/freemem.h"
#include "call/sbi.h"
#include "eyrie_call.h"
#include "util/printf.h"
#include "util/string.h"
#include <asm/csr.h>

/* root page table */
pte root_page_table_storage[BIT(RISCV_PT_INDEX_BITS)] __attribute__((aligned(RISCV_PAGE_SIZE)));
/* page tables for loading physical memory */
pte load_l2_page_table_storage[BIT(RISCV_PT_INDEX_BITS)] __attribute__((aligned(RISCV_PAGE_SIZE)));
pte load_l3_page_table_storage[BIT(RISCV_PT_INDEX_BITS)] __attribute__((aligned(RISCV_PAGE_SIZE)));

uintptr_t free_base_final = 0;

typedef char yxstm_va_abi_must_match_runtime[
    EYRIE_YXSTRUSTED_START == KEYSTONE_YXSTM_ENCLAVE_VA_BASE ? 1 : -1];
static const char keystone_group_loader_abi_marker[]
    __attribute__((used)) = KEYSTONE_GROUP_ABI_MARKER;
static const char keystone_utm_direct_data_marker[]
    __attribute__((used)) = KEYSTONE_UTM_DIRECT_DATA_MARKER;
#if __riscv_xlen == 64
typedef char yxstm_sv39_large_leaf_must_be_2m[
    RISCV_GET_LVL_PGSIZE(RISCV_PT_LEVELS - 1) ==
        (2UL * 1024UL * 1024UL) ? 1 : -1];
#endif

/*
 * Debug function to print ALL UTM parameters received from SM
 * Called from loader.S at the very beginning of _start, BEFORE saving to stack
 * This helps diagnose if SM is passing correct values
 */
void debug_print_all_utm_params(uintptr_t untrusted_ptr, uintptr_t untrusted_size,
                                 uintptr_t shared_utm_paddr, uintptr_t shared_utm_size) {
  // printf("[loader.S] DEBUG: _start entry - ALL UTM params from SM:\n");
  // printf("[loader.S]   a6 (untrusted_ptr)    = 0x%lx (own UTM)\n", untrusted_ptr);
  // printf("[loader.S]   a7 (untrusted_size)   = %lu (0x%lx)\n", untrusted_size, untrusted_size);
  // printf("[loader.S]   t2 (shared_utm_paddr) = 0x%lx (shared UTM)\n", shared_utm_paddr);
  // printf("[loader.S]   t3 (shared_utm_size)  = %lu (0x%lx)\n", shared_utm_size, shared_utm_size);
  // if (shared_utm_size > 0) {
  //   printf("[loader.S]   -> This is a SLAVE Enclave with shared UTM\n");
  // } else {
  //   printf("[loader.S]   -> This is a MAIN/regular Enclave (no shared UTM)\n");
  // }
}

/*
 * Debug function to print shared UTM parameters received from SM
 * Called from loader.S at the very beginning of _start
 */
void debug_print_shared_utm_params(uintptr_t shared_utm_paddr, uintptr_t shared_utm_size) {
  // printf("[loader.S] DEBUG: _start entry - shared UTM params from SM:\n");
  // printf("[loader.S]   t2 (shared_utm_paddr) = 0x%lx\n", shared_utm_paddr);
  // printf("[loader.S]   t3 (shared_utm_size)  = %lu (0x%lx)\n", shared_utm_size, shared_utm_size);
  // if (shared_utm_size > 0) {
  //   printf("[loader.S]   -> This is a SLAVE Enclave with shared UTM\n");
  // } else {
  //   printf("[loader.S]   -> This is a MAIN/regular Enclave (no shared UTM)\n");
  // }
}

uintptr_t satp_new(uintptr_t pa)
{
  return (SATP_MODE | (pa >> RISCV_PAGE_BITS));
}

void map_physical_memory(uintptr_t dram_base, uintptr_t dram_size) {
  uintptr_t ptr = EYRIE_LOAD_START;
  /* load address should not override kernel address */
  assert(RISCV_GET_PT_INDEX(ptr, 1) != RISCV_GET_PT_INDEX(RUNTIME_VA_START, 1));
  map_with_reserved_page_table(dram_base, dram_size,
      ptr, load_l2_page_table_storage, load_l3_page_table_storage);
}

static int map_linear_memory(uintptr_t va, uintptr_t pa, uintptr_t size,
                             int flags) {
  const int large_level = RISCV_PT_LEVELS - 1;
  const uintptr_t large_size = RISCV_GET_LVL_PGSIZE(large_level);
  const int large_bits = RISCV_GET_LVL_PGSIZE_BITS(large_level);
  uintptr_t end;

  if (!size)
    return 0;
  end = va + size;
  if (end < va || pa + size < pa || (size & (RISCV_PAGE_SIZE - 1)))
    return -1;

  while (va < end) {
    uintptr_t step = RISCV_PAGE_SIZE;
    uintptr_t ret;

    /*
     * Sv39 level 1 is a 2 MiB leaf. Preserve 4 KiB mappings only for an
     * unaligned prefix/tail; aligned YXSTM and UTM spans use megapages.
     */
    if (end - va >= large_size && IS_ALIGNED(va, large_bits) &&
        IS_ALIGNED(pa, large_bits)) {
      ret = map_large_page(va, pa, flags);
      step = large_size;
    } else {
      ret = map_page(vpn(va), ppn(pa), flags);
    }
    if (ret != 1)
      return -1;
    va += step;
    pa += step;
  }
  return 0;
}

int map_untrusted_memory(uintptr_t untrusted_ptr, uintptr_t untrusted_size) {
  /* Keep the edge/OCALL control mapping supervisor-only. */
  return map_linear_memory(EYRIE_UNTRUSTED_START, untrusted_ptr,
                           untrusted_size, PTE_W | PTE_R | PTE_D);
}

static int map_untrusted_memory_direct_data(uintptr_t untrusted_ptr,
                                            uintptr_t untrusted_size) {
  const uintptr_t control_size = KEYSTONE_UTM_DIRECT_CONTROL_BYTES;

  if (keystone_utm_direct_data_marker[0] != 'k')
    return -1;
  if (untrusted_size <= control_size)
    return 0;
  return map_linear_memory(EYRIE_UTM_DIRECT_DATA_START,
                           untrusted_ptr + control_size,
                           untrusted_size - control_size,
                           PTE_W | PTE_R | PTE_D | PTE_A | PTE_U);
}

int map_untrusted_memory_readonly_alias(uintptr_t untrusted_ptr, uintptr_t untrusted_size) {
  /* Main eapps use this U-mode read-only alias for pre-generated input. */
  return map_linear_memory(EYRIE_SHARED_UTM_START, untrusted_ptr,
                           untrusted_size, PTE_R | PTE_D | PTE_U);
}

int map_untrusted_memory_output_alias(uintptr_t untrusted_ptr, uintptr_t untrusted_size) {
  const uintptr_t output_offset = (48UL * 1024 * 1024) + (8UL * 1024);
  if (untrusted_size <= output_offset) {
    return 0;
  }

  uintptr_t va = EYRIE_UNTRUSTED_OUTPUT_ALIAS_START + output_offset;
  uintptr_t pa = untrusted_ptr + output_offset;
  return map_linear_memory(va, pa, untrusted_size - output_offset,
                           PTE_W | PTE_R | PTE_D | PTE_U);
}

int map_YXStrusted_memory(uintptr_t YXSTM_ptr, uintptr_t YXSTM_size) {
  struct keystone_yxstm_layout_info layout;
  uintptr_t lane_id;
  uintptr_t valid_mask;

  memset(&layout, 0, sizeof(layout));
  if (sbi_yxstm_query_layout((uintptr_t)&layout, sizeof(layout)) != 0) {
    printf("[loader] YXSTM layout query failed\n");
    return -1;
  }

  if (layout.slice_count != KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT ||
      layout.slice_size == 0 ||
      layout.slice_size > (uintptr_t)-1 / layout.slice_count ||
      layout.yxstm_va_base != KEYSTONE_YXSTM_ENCLAVE_VA_BASE ||
      layout.yxstm_va_base != EYRIE_YXSTRUSTED_START) {
    printf("[loader] invalid YXSTM layout: count=%lu slice=0x%lx total=0x%lx va=0x%lx expected=0x%lx\n",
           layout.slice_count, layout.slice_size, YXSTM_size,
           layout.yxstm_va_base,
           (uintptr_t)KEYSTONE_YXSTM_ENCLAVE_VA_BASE);
    return -1;
  }

  if (layout.bank_count == 0 ||
      layout.bank_count > KEYSTONE_YXSTM_MAX_BANKS ||
      layout.bank_slice_size != layout.slice_size ||
      layout.bank_size != layout.slice_size * layout.slice_count ||
      layout.bank_stride != layout.bank_size ||
      layout.bank_size > YXSTM_size / layout.bank_count ||
      layout.bank_size * layout.bank_count != YXSTM_size) {
    printf("[loader] invalid YXSTM bank layout: banks=%lu bank=0x%lx stride=0x%lx slice=0x%lx total=0x%lx\n",
           layout.bank_count, layout.bank_size, layout.bank_stride,
           layout.bank_slice_size, YXSTM_size);
    return -1;
  }

  if (layout.worker_lane_count != KEYSTONE_YXSTM_WORKER_LANE_COUNT ||
      layout.worker_lane_size != KEYSTONE_YXSTM_WORKER_LANE_SIZE ||
      layout.worker_lane_size > layout.bank_slice_size ||
      layout.bank_count != 1) {
    printf("[loader] invalid dynamic YXSTM lane layout: lanes=%lu lane=0x%lx physical-slice=0x%lx banks=%lu\n",
           layout.worker_lane_count, layout.worker_lane_size,
           layout.bank_slice_size, layout.bank_count);
    return -1;
  }

  valid_mask = (1UL << layout.slice_count) - 1UL;
  if ((layout.allowed_slice_mask & ~valid_mask) != 0) {
    printf("[loader] invalid YXSTM slice mask: role=%lu mask=0x%lx valid=0x%lx\n",
           layout.role, layout.allowed_slice_mask, valid_mask);
    return -1;
  }
  if (layout.role == GROUP_ROLE_NONE) {
    if (layout.allowed_slice_mask != 0) {
      printf("[loader] ROLE_NONE cannot map YXSTM: mask=0x%lx\n",
             layout.allowed_slice_mask);
      return -1;
    }
  } else if (layout.role == GROUP_ROLE_MASTER ||
             layout.role == GROUP_ROLE_WORKER) {
    if (layout.allowed_slice_mask == 0) {
      printf("[loader] role=%lu requires a non-zero YXSTM slice mask\n",
             layout.role);
      return -1;
    }
  } else {
    printf("[loader] invalid YXSTM role: role=%lu\n", layout.role);
    return -1;
  }

  /*
   * YXSTM uses ordinary Sv39 R/W/U leaf flags and deliberately sets no X,
   * G, software-reserved, or Svpbmt bits. It therefore inherits the JH7110
   * platform's normal cacheability. The SM audit records the resulting leaf
   * sizes/flags and rejects executable, aliased, or non-linear views.
   */
  if (layout.role == GROUP_ROLE_MASTER) {
    if ((layout.allowed_slice_mask & UINT64_C(0xe)) != UINT64_C(0xe)) {
      printf("[loader] master does not own all worker lanes: mask=0x%lx\n",
             layout.allowed_slice_mask);
      return -1;
    }
    for (lane_id = 0; lane_id < layout.worker_lane_count; lane_id++) {
      struct keystone_yxstm_slot_info lane_info;
      uintptr_t physical_offset = (lane_id + 1) * layout.bank_slice_size;
      uintptr_t va = layout.yxstm_va_base + physical_offset;
      uintptr_t pa = YXSTM_ptr + physical_offset;

      memset(&lane_info, 0, sizeof(lane_info));
      KEYSTONE_ABI_INIT(&lane_info, KEYSTONE_YXSTM_ABI_FEATURES);
      lane_info.lane_id = lane_id;
      lane_info.slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
      if (sbi_yxstm_query_slot((uintptr_t)&lane_info,
                               sizeof(lane_info)) != 0 ||
          lane_info.lane_id != lane_id ||
          lane_info.slot_id != KEYSTONE_YXSTM_INVALID_SLOT ||
          (lane_info.slot_count && !lane_info.slot_size) ||
          (lane_info.slot_size & (RISCV_PAGE_SIZE - 1)) ||
          (lane_info.slot_count &&
           lane_info.slot_size > (uintptr_t)-1 / lane_info.slot_count))
        return -1;
      if (lane_info.slot_count * lane_info.slot_size >
              layout.worker_lane_size ||
          va + layout.worker_lane_size < va ||
          pa + layout.worker_lane_size < pa ||
          physical_offset + layout.worker_lane_size > YXSTM_size ||
          map_linear_memory(va, pa, layout.worker_lane_size,
                            PTE_W | PTE_R | PTE_D | PTE_U) != 0)
        return -1;
    }
  } else if (layout.role == GROUP_ROLE_WORKER) {
    uintptr_t physical_offset;
    uintptr_t va;
    uintptr_t pa;

    if (layout.worker_slice_id == 0 ||
        layout.worker_slice_id > layout.worker_lane_count ||
        layout.slot_id == KEYSTONE_YXSTM_INVALID_SLOT ||
        layout.slot_count == 0 || layout.slot_id >= layout.slot_count ||
        layout.slot_size == 0 ||
        (layout.slot_offset & (RISCV_PAGE_SIZE - 1)) ||
        (layout.slot_size & (RISCV_PAGE_SIZE - 1)) ||
        layout.slot_offset > layout.worker_lane_size ||
        layout.slot_size > layout.worker_lane_size - layout.slot_offset ||
        layout.slot_payload_size > layout.slot_size ||
        layout.slot_payload_size !=
            keystone_yxstm_slot_payload_capacity(layout.slot_count)) {
      printf("[loader] invalid worker YXSTM slot: slice=%lu slot=%lu/%lu offset=0x%lx size=0x%lx payload=0x%lx\n",
             layout.worker_slice_id, layout.slot_id, layout.slot_count,
             layout.slot_offset, layout.slot_size,
             layout.slot_payload_size);
      return -1;
    }
    physical_offset = layout.worker_slice_id * layout.bank_slice_size +
                      layout.slot_offset;
    va = layout.yxstm_va_base + physical_offset;
    pa = YXSTM_ptr + physical_offset;
    if (va + layout.slot_size < va || pa + layout.slot_size < pa ||
        physical_offset + layout.slot_size > YXSTM_size ||
        map_linear_memory(va, pa, layout.slot_size,
                          PTE_W | PTE_R | PTE_D | PTE_U) != 0)
      return -1;
  }

  return 0;
}

int map_sec_mmio_memory(uintptr_t sec_ptr, uintptr_t sec_size) {
  uintptr_t va = EYRIE_SEC_MMIO_START;
  uintptr_t end = EYRIE_SEC_MMIO_START + sec_size;

  if (sec_size == 0) {
    return 0;
  }

  if (sec_size > EYRIE_SEC_MMIO_SIZE_MAX) {
    return -1;
  }

  while (va < end) {
    if (!map_page(vpn(va), ppn(sec_ptr), PTE_R | PTE_W | PTE_D | PTE_A | PTE_U)) {
      return -1;
    }
    va += RISCV_PAGE_SIZE;
    sec_ptr += RISCV_PAGE_SIZE;
  }

  return 0;
}

/*
 * Map shared UTM memory for Slave Enclave using 4KB pages
 *
 * This function maps the Main Enclave's UTM (shared UTM) to the Slave Enclave's
 * virtual address space at EYRIE_SHARED_UTM_START.
 *
 * FIX: Uses 4KB pages instead of megapages to avoid L2 page table accessibility
 * issues. The megapage approach had problems because the L2 page table was in
 * EPM and MMU couldn't access it during page table walk.
 *
 * Requirements: 2.1, 2.4, 4.3, 5.1, 5.2, 5.3
 */

/*
 * debug_walk_page_table - 调试函数：遍历页表并打印映射信息
 *
 * Requirements: 1.2 - 验证页表映射正确性
 *
 * @param va 要查询的虚拟地址
 *
 * 在 loader 阶段，我们还在物理地址模式，可以直接访问页表
 */
void debug_walk_page_table(uintptr_t va) {
  printf("[DEBUG] Walking page table for VA=0x%lx\n", va);

  /* 获取 L1 索引 */
  size_t l1_idx = RISCV_GET_PT_INDEX(va, 1);
  pte l1_entry = root_page_table[l1_idx];
  printf("[DEBUG]   L1[%lu] = 0x%lx\n", l1_idx, l1_entry);

  if (!(l1_entry & PTE_V)) {
    printf("[DEBUG]   L1 entry not valid!\n");
    return;
  }

  /* 检查 L1 是否是叶子节点 (gigapage) */
  if (l1_entry & (PTE_R | PTE_W | PTE_X)) {
    uintptr_t pa = pte_ppn(l1_entry) << RISCV_PAGE_BITS;
    printf("[DEBUG]   Gigapage (1GB): VA 0x%lx -> PA 0x%lx\n", va, pa);
    return;
  }

  /* 获取 L2 页表地址 */
  uintptr_t l2_pt_pa = pte_ppn(l1_entry) << RISCV_PAGE_BITS;
  printf("[DEBUG]   L2 PT PA = 0x%lx\n", l2_pt_pa);

  /* 在 loader 阶段，我们还在物理地址模式，可以直接访问 */
  pte* l2_pt = (pte*)l2_pt_pa;

  /* 获取 L2 索引 */
  size_t l2_idx = RISCV_GET_PT_INDEX(va, 2);
  pte l2_entry = l2_pt[l2_idx];
  printf("[DEBUG]   L2[%lu] = 0x%lx\n", l2_idx, l2_entry);

  if (!(l2_entry & PTE_V)) {
    printf("[DEBUG]   L2 entry not valid!\n");
    return;
  }

  /* 检查是否是 megapage (R/W/X 位设置) */
  if (l2_entry & (PTE_R | PTE_W | PTE_X)) {
    uintptr_t pa = pte_ppn(l2_entry) << RISCV_PAGE_BITS;
    printf("[DEBUG]   Megapage (2MB): VA 0x%lx -> PA 0x%lx\n", va, pa);

    /* 验证 PPN[0] (bits 18:10) 是否为 0 (2MB 对齐要求) */
    uintptr_t ppn = pte_ppn(l2_entry);
    uintptr_t ppn_0 = (ppn >> 0) & 0x1FF;  /* bits 8:0 of PPN = bits 18:10 of PA */
    if (ppn_0 != 0) {
      printf("[DEBUG]   WARNING: PPN[0] = 0x%lx (should be 0 for 2MB alignment!)\n", ppn_0);
    } else {
      printf("[DEBUG]   PPN[0] = 0 (correct 2MB alignment)\n");
    }

    /* 读取物理地址的前 32 字节 */
    printf("[DEBUG]   First 32 bytes at PA 0x%lx: ", pa);
    uint8_t* data = (uint8_t*)pa;
    int i;
    for (i = 0; i < 32; i++) {
      printf("%02x", data[i]);
      if ((i + 1) % 4 == 0) printf(" ");
    }
    printf("\n");
    return;
  }

  /* L2 指向 L3 页表 */
  uintptr_t l3_pt_pa = pte_ppn(l2_entry) << RISCV_PAGE_BITS;
  printf("[DEBUG]   L3 PT PA = 0x%lx\n", l3_pt_pa);

  pte* l3_pt = (pte*)l3_pt_pa;

  /* 获取 L3 索引 */
  size_t l3_idx = RISCV_GET_PT_INDEX(va, 3);
  pte l3_entry = l3_pt[l3_idx];
  printf("[DEBUG]   L3[%lu] = 0x%lx\n", l3_idx, l3_entry);

  if (!(l3_entry & PTE_V)) {
    printf("[DEBUG]   L3 entry not valid!\n");
    return;
  }

  uintptr_t pa = pte_ppn(l3_entry) << RISCV_PAGE_BITS;
  printf("[DEBUG]   4KB Page: VA 0x%lx -> PA 0x%lx\n", va, pa);

  /* 读取物理地址的前 32 字节 */
  printf("[DEBUG]   First 32 bytes at PA 0x%lx: ", pa);
  uint8_t* data = (uint8_t*)pa;
  int i;
  for (i = 0; i < 32; i++) {
    printf("%02x", data[i]);
    if ((i + 1) % 4 == 0) printf(" ");
  }
  printf("\n");
}

/*
 * map_shared_utm_memory - Map shared UTM memory for Slave Enclave using megapages
 *
 * This function maps the Main Enclave's UTM (shared UTM) to the Slave Enclave's
 * virtual address space at EYRIE_SHARED_UTM_START.
 *
 * PERFORMANCE FIX (2026-01-07): Restored megapage (2MB) mapping for better performance.
 * The previous 4KB page mapping was a workaround for L2 page table accessibility issues.
 *
 * The key fix is to allocate the L2 page table from freemem (using spa_get()) instead
 * of using a static variable. This ensures the L2 page table is in a region accessible
 * by the MMU during page table walk.
 *
 * Requirements: 2.1, 2.4, 4.3, 5.1, 5.2, 5.3
 *
 * @param shared_utm_ptr   Physical address of the shared UTM
 * @param shared_utm_size  Size of the shared UTM in bytes
 * @return 0 on success, -1 on failure
 */
int map_shared_utm_memory(uintptr_t shared_utm_ptr, uintptr_t shared_utm_size) {
  //===========================================================================
  // DEBUG: Print mapping parameters
  //===========================================================================
  printf("[map_shared_utm_memory] DEBUG: Function entry (MEGAPAGE mode)\n");
  printf("[map_shared_utm_memory]   shared_utm_ptr (PA)  = 0x%lx\n", shared_utm_ptr);
  printf("[map_shared_utm_memory]   shared_utm_size      = %lu (0x%lx) = %lu MB\n",
         shared_utm_size, shared_utm_size, shared_utm_size / (1024 * 1024));
  printf("[map_shared_utm_memory]   EYRIE_SHARED_UTM_START (VA) = 0x%lx\n", (uintptr_t)EYRIE_SHARED_UTM_START);
  //===========================================================================

  if (shared_utm_size == 0) {
    printf("[map_shared_utm_memory]   -> No shared UTM to map (size=0), returning 0\n");
    return 0;  /* No shared UTM to map */
  }

  /*
   * MEGAPAGE MAPPING (2MB pages)
   *
   * Performance: Using megapages reduces TLB pressure and page table overhead.
   * - 4KB mapping: 16384 page table entries for 64MB
   * - 2MB mapping: 32 page table entries for 64MB
   *
   * Key fix: Allocate L2 page table from freemem (spa_get()) instead of using
   * a static variable. This ensures the L2 page table is accessible by MMU.
   */

  /* Megapage size is 2MB = 2^21 bytes */
  #define MEGAPAGE_SIZE (1UL << 21)
  #define MEGAPAGE_BITS 21

  /* Verify alignment - shared UTM must be 2MB aligned for megapage mapping */
  if (!IS_ALIGNED(shared_utm_ptr, MEGAPAGE_BITS)) {
    printf("[map_shared_utm_memory] WARNING: shared_utm_ptr not 2MB aligned, falling back to 4KB pages\n");
    goto fallback_4kb;
  }

  /* Allocate L2 page table from freemem */
  pte* l2_pt = (pte*)spa_get();
  if (!l2_pt) {
    printf("[map_shared_utm_memory] ERROR: Failed to allocate L2 page table from freemem\n");
    return -1;
  }

  /* Clear the L2 page table */
  size_t i;
  for (i = 0; i < BIT(RISCV_PT_INDEX_BITS); i++) {
    l2_pt[i] = 0;
  }

  printf("[map_shared_utm_memory]   -> Allocated L2 page table at PA 0x%lx\n", (uintptr_t)l2_pt);

  /* Calculate number of megapages needed */
  size_t num_megapages = (shared_utm_size + MEGAPAGE_SIZE - 1) / MEGAPAGE_SIZE;
  printf("[map_shared_utm_memory]   -> Using MEGAPAGE mapping: %lu x 2MB pages\n", num_megapages);

  /* Set up L1 page table entry to point to L2 page table */
  size_t l1_idx = RISCV_GET_PT_INDEX(EYRIE_SHARED_UTM_START, 1);
  root_page_table[l1_idx] = ptd_create(ppn((uintptr_t)l2_pt));
  printf("[map_shared_utm_memory]   -> L1[%lu] = 0x%lx (points to L2 PT)\n",
         l1_idx, root_page_table[l1_idx]);

  /* Set up L2 page table entries (megapages) */
  uintptr_t va = EYRIE_SHARED_UTM_START;
  uintptr_t pa = shared_utm_ptr;
  size_t megapages_mapped = 0;

  while (megapages_mapped < num_megapages && va < EYRIE_SHARED_UTM_START + shared_utm_size) {
    size_t l2_idx = RISCV_GET_PT_INDEX(va, 2);

    /*
     * shared UTM is currently accessed through runtime helpers/syscalls rather
     * than direct eapp pointer dereferences, so keep it supervisor-only like
     * the historical working configuration.
     */
    l2_pt[l2_idx] = pte_create(ppn(pa), PTE_R | PTE_W | PTE_D | PTE_A | PTE_U);

    if (megapages_mapped < 3 || megapages_mapped == num_megapages - 1) {
      printf("[map_shared_utm_memory]   -> L2[%lu] = 0x%lx (VA 0x%lx -> PA 0x%lx)\n",
             l2_idx, l2_pt[l2_idx], va, pa);
    } else if (megapages_mapped == 3) {
      printf("[map_shared_utm_memory]   -> ... (mapping %lu more megapages)\n",
             num_megapages - 4);
    }

    va += MEGAPAGE_SIZE;
    pa += MEGAPAGE_SIZE;
    megapages_mapped++;
  }

  /*
   * CRITICAL: Memory barrier to ensure all page table writes are visible
   * before any subsequent memory access through the new mapping.
   */
  __asm__ __volatile__ ("fence rw, rw" ::: "memory");

  printf("[map_shared_utm_memory]   -> Successfully mapped %lu megapages (2MB each)\n", megapages_mapped);
  printf("[map_shared_utm_memory]   -> VA range: 0x%lx - 0x%lx\n",
         (uintptr_t)EYRIE_SHARED_UTM_START,
         (uintptr_t)(EYRIE_SHARED_UTM_START + shared_utm_size));

  //===========================================================================
  // DIAGNOSTIC: Walk page table to verify megapage mapping correctness
  //===========================================================================
  printf("[map_shared_utm_memory] DEBUG: Verifying MEGAPAGE mapping...\n");
  debug_walk_page_table(EYRIE_SHARED_UTM_START);

  //===========================================================================
  // DIAGNOSTIC: Verify data accessibility after mapping
  //===========================================================================
  printf("[map_shared_utm_memory] DEBUG: Verifying data accessibility...\n");
  printf("[map_shared_utm_memory]   -> Reading first 32 bytes from PA 0x%lx:\n", shared_utm_ptr);
  printf("[map_shared_utm_memory]   -> Data: ");

  /* In loader stage, we're still in physical address mode, read directly from PA */
  uint8_t* data = (uint8_t*)shared_utm_ptr;
  for (i = 0; i < 32; i++) {
    printf("%02x", data[i]);
    if ((i + 1) % 4 == 0) printf(" ");
  }
  printf("\n");

  /* Also print as ASCII if printable */
  printf("[map_shared_utm_memory]   -> ASCII: ");
  for (i = 0; i < 32; i++) {
    if (data[i] >= 32 && data[i] < 127) {
      printf("%c", data[i]);
    } else {
      printf(".");
    }
  }
  printf("\n");
  //===========================================================================

  return 0;

fallback_4kb:
  /*
   * Fallback to 4KB page mapping if megapage requirements not met.
   * This is slower but more flexible.
   */
  printf("[map_shared_utm_memory]   -> Falling back to 4KB page mapping\n");

  uintptr_t va_4k = EYRIE_SHARED_UTM_START;
  uintptr_t pa_4k = shared_utm_ptr;
  size_t pages_mapped = 0;
  size_t total_pages = (shared_utm_size + RISCV_PAGE_SIZE - 1) / RISCV_PAGE_SIZE;

  while (va_4k < EYRIE_SHARED_UTM_START + shared_utm_size) {
    if (!map_page(vpn(va_4k), ppn(pa_4k), PTE_W | PTE_R | PTE_D | PTE_U)) {
      printf("[map_shared_utm_memory] ERROR: map_page failed at VA=0x%lx PA=0x%lx\n",
             va_4k, pa_4k);
      return -1;
    }
    va_4k += RISCV_PAGE_SIZE;
    pa_4k += RISCV_PAGE_SIZE;
    pages_mapped++;

    if (pages_mapped % 4096 == 0) {
      printf("[map_shared_utm_memory]   -> Mapped %lu/%lu pages (%lu MB)...\n",
             pages_mapped, total_pages, (pages_mapped * RISCV_PAGE_SIZE) / (1024 * 1024));
    }
  }

  __asm__ __volatile__ ("fence rw, rw" ::: "memory");

  printf("[map_shared_utm_memory]   -> Successfully mapped %lu pages (4KB each)\n", pages_mapped);
  return 0;
}

int load_runtime(uintptr_t dummy,
                uintptr_t dram_base, uintptr_t dram_size,
                uintptr_t runtime_base, uintptr_t user_base,
                uintptr_t free_base, uintptr_t untrusted_ptr,
                uintptr_t untrusted_size) {
  int ret = 0;

  root_page_table = root_page_table_storage;

  // initialize freemem
  spa_init(free_base, dram_base + dram_size - free_base);

  // validate runtime elf
  size_t runtime_size = user_base - runtime_base;
  if (((void*) runtime_base == NULL) || (runtime_size <= 0)) {
    return -1;
  }

  // create runtime elf struct
  elf_t runtime_elf;
  ret = elf_newFile((void*) runtime_base, runtime_size, &runtime_elf);
  if (ret != 0) {
    return ret;
  }

  // map runtime memory
  ret = loadElf(&runtime_elf, 0);
  if (ret != 0) {
    return ret;
  }

  // map enclave physical memory, so that runtime will be able to access all memory
  map_physical_memory(dram_base, dram_size);

  // map untrusted memory
  ret = map_untrusted_memory(untrusted_ptr, untrusted_size);
  if (ret != 0) {
    return ret;
  }
  ret = map_untrusted_memory_direct_data(untrusted_ptr, untrusted_size);
  if (ret != 0) {
    return ret;
  }

  ret = sbi_group_validate_page_table((uintptr_t)root_page_table_storage);
  if (ret != 0) {
    printf("[loader] SM group page-table validation failed: %d\n", ret);
    return -1;
  }

  free_base_final = dram_base + dram_size - spa_available() * RISCV_PAGE_SIZE;

  return ret;
}

int yx_load_runtime(uintptr_t dummy,
                    uintptr_t dram_base, uintptr_t dram_size,
                    uintptr_t runtime_base, uintptr_t user_base,
                    uintptr_t free_base, uintptr_t untrusted_ptr,
                    uintptr_t untrusted_size, uintptr_t YXSTM_ptr,
                    uintptr_t YXSTM_size, uintptr_t shared_utm_ptr,
                    uintptr_t shared_utm_size, uintptr_t sec_ptr,
                    uintptr_t sec_size) {
  int ret = 0;

  //===========================================================================
  // DEBUG: Print shared UTM parameters received from loader.S
  //===========================================================================
  // printf("[yx_load_runtime] DEBUG: Function entry - shared UTM params:\n");
  // printf("[yx_load_runtime]   shared_utm_ptr  = 0x%lx\n", shared_utm_ptr);
  // printf("[yx_load_runtime]   shared_utm_size = %lu (0x%lx)\n", shared_utm_size, shared_utm_size);
  // printf("[yx_load_runtime]   YXSTM_ptr       = 0x%lx\n", YXSTM_ptr);
  // printf("[yx_load_runtime]   YXSTM_size      = %lu\n", YXSTM_size);
  // printf("[yx_load_runtime]   untrusted_ptr   = 0x%lx\n", untrusted_ptr);
  // printf("[yx_load_runtime]   untrusted_size  = %lu\n", untrusted_size);
  //===========================================================================

  root_page_table = root_page_table_storage;

  // initialize freemem
  spa_init(free_base, dram_base + dram_size - free_base);

  // validate runtime elf
  size_t runtime_size = user_base - runtime_base;
  if (((void*) runtime_base == NULL) || (runtime_size <= 0)) {
    return -1;
  }

  // create runtime elf struct
  elf_t runtime_elf;
  ret = elf_newFile((void*) runtime_base, runtime_size, &runtime_elf);
  if (ret != 0) {
    return ret;
  }

  // map runtime memory
  ret = loadElf(&runtime_elf, 0);
  if (ret != 0) {
    return ret;
  }

  // map enclave physical memory, so that runtime will be able to access all memory
  map_physical_memory(dram_base, dram_size);

  // map untrusted memory (own UTM)
  ret = map_untrusted_memory(untrusted_ptr, untrusted_size);
  if (ret != 0) {
    return ret;
  }
  ret = map_untrusted_memory_direct_data(untrusted_ptr, untrusted_size);
  if (ret != 0) {
    return ret;
  }

  if (shared_utm_size == 0) {
    ret = map_untrusted_memory_readonly_alias(untrusted_ptr, untrusted_size);
    if (ret != 0) {
      return ret;
    }
    ret = map_untrusted_memory_output_alias(untrusted_ptr, untrusted_size);
    if (ret != 0) {
      return ret;
    }
  }

  // map YX share trusted memory
  if (YXSTM_ptr == YXSTM_size || YXSTM_size == 0) {
    // printf("[runtime] YXSTM testing 1 %s, YXSTM_ptr:%lu, YXSTM_size:%lu\n", __func__, YXSTM_ptr, YXSTM_size);
  } else {
    ret = map_YXStrusted_memory(YXSTM_ptr, YXSTM_size);
    // printf("[runtime] YXSTM testing 2 %s, YXSTM_ptr:%lu, YXSTM_size:%lu\n", __func__, YXSTM_ptr, YXSTM_size);
    if (ret != 0) {
      return ret;
    }
  }

  // map shared UTM memory (for Slave Enclave to access Main's UTM)
  if (shared_utm_size > 0) {
    // printf("[yx_load_runtime] DEBUG: About to call map_shared_utm_memory()\n");
    ret = map_shared_utm_memory(shared_utm_ptr, shared_utm_size);
    if (ret != 0) {
      printf("[yx_load_runtime] ERROR: map_shared_utm_memory() failed with ret=%d\n", ret);
      return ret;
    }
    // printf("[yx_load_runtime] DEBUG: map_shared_utm_memory() succeeded\n");
  } else {
    // printf("[yx_load_runtime] DEBUG: Skipping map_shared_utm_memory() (shared_utm_size=0)\n");
  }

  ret = map_sec_mmio_memory(sec_ptr, sec_size);
  if (ret != 0) {
    return ret;
  }

  ret = sbi_group_validate_page_table((uintptr_t)root_page_table_storage);
  if (ret != 0) {
    printf("[loader] SM group page-table validation failed: %d\n", ret);
    return -1;
  }

  free_base_final = dram_base + dram_size - spa_available() * RISCV_PAGE_SIZE;

  return ret;
}

void error_and_exit() {
  printf("[loader] FATAL: failed to load.\n");
  sbi_exit_enclave(-1);
}
