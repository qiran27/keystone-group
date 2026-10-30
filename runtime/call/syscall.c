//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <stdint.h>
#include <stddef.h>
#include <sys/select.h>
#include <asm/csr.h>
#include "call/sbi.h"
#include "call/syscall.h"
#include "sm_err.h"
#include "util/string.h"
#include "edge_call.h"
#include "uaccess.h"
#include "mm/mm.h"
#include "mm/vm.h"
#include "util/rt_util.h"

#include "call/syscall_nums.h"

#ifndef RUNTIME_SYSCALL_TEST_CORRUPT_ATTESTATION_KEY
#define RUNTIME_SYSCALL_TEST_CORRUPT_ATTESTATION_KEY 1027
#endif

#ifndef RUNTIME_SYSCALL_TEST_SET_ATTESTATION_MUTATION
#define RUNTIME_SYSCALL_TEST_SET_ATTESTATION_MUTATION 1028
#endif

#define TEST_ATTEST_MUTATION_NONE 0
#define TEST_ATTEST_MUTATION_REPLAY_SEQ 1
#define TEST_ATTEST_MUTATION_TAMPER_N_CH 2
#define TEST_ATTEST_MUTATION_TAMPER_HMAC 3
#define TEST_ATTEST_MUTATION_TAMPER_SM_ENDORSEMENT 4

#define YXSTM_SLOT_WAIT_RUNTIME_MARKER "keystone-yxstm-slot-wait-v5"
static const volatile char yxstm_slot_wait_runtime_marker[]
    __attribute__((used)) = YXSTM_SLOT_WAIT_RUNTIME_MARKER;
static const volatile char utm_direct_data_runtime_marker[]
    __attribute__((used)) = KEYSTONE_UTM_DIRECT_DATA_MARKER;

#ifdef USE_IO_SYSCALL
#include "call/io_wrap.h"
#endif /* USE_IO_SYSCALL */

#ifdef USE_LINUX_SYSCALL
#include "call/linux_wrap.h"
#endif /* USE_LINUX_SYSCALL */

#ifdef USE_NET_SYSCALL
#include "call/net_wrap.h"
#endif /* USE_NET_SYSCALL */

extern void exit_enclave(uintptr_t arg0);

uintptr_t dispatch_edgecall_syscall(struct edge_syscall* syscall_data_ptr, size_t data_len){
  int ret;

  // Syscall data should already be at the edge_call_data section
  /*
   * CRITICAL FIX: Use ocall_buffer for edge_call communication
   *
   * In shared UTM mode, edge_call must be written to ocall_buffer
   * (enclave's own UTM) because Host reads from there.
   */
  struct edge_call* edge_call = (struct edge_call*)ocall_buffer;

  edge_call->call_id = EDGECALL_SYSCALL;


  if(edge_call_setup_call(edge_call, (void*)syscall_data_ptr, data_len) != 0){
    return -1;
  }

  ret = sbi_stop_enclave(STOP_EDGE_CALL_HOST);

  if (ret != 0) {
    return -1;
  }

  if(edge_call->return_data.call_status != CALL_STATUS_OK){
    return -1;
  }

  uintptr_t return_ptr;
  size_t return_len;
  if(edge_call_ret_ptr(edge_call, &return_ptr, &return_len) != 0){
    return -1;
  }

  if(return_len < sizeof(uintptr_t)){
    return -1;
  }

  return *(uintptr_t*)return_ptr;
}

uintptr_t dispatch_edgecall_ocall( unsigned long call_id,
				   void* data, size_t data_len,
				   void* return_buffer, size_t return_len){

  uintptr_t ret;
  uintptr_t ocall_error_code = 1;
  /*
   * CRITICAL FIX: Use ocall_buffer for edge_call communication
   * ==========================================================
   *
   * In shared UTM mode, the Slave Enclave has two separate buffers:
   * 1. ocall_buffer (EYRIE_UNTRUSTED_START) - Enclave's own 1MB UTM for OCALL
   * 2. shared_buffer (EYRIE_SHARED_UTM_START) - Main's 64MB UTM for data transfer
   *
   * The edge_call structure must be written to ocall_buffer because:
   * - Host maps ocall_buffer separately using mapOwnUtm()
   * - Host reads edge_call from ocall_buffer in handle_ocall()
   *
   * Previously, this code used shared_buffer, which caused the Host to read
   * uninitialized memory (call_id = 0) instead of the actual OCALL request.
   */
  struct edge_call* edge_call = (struct edge_call*)ocall_buffer;

  /* We encode the call id, copy the argument data into the shared
   * region, calculate the offsets to the argument data, and then
   * dispatch the ocall to host */

  edge_call->call_id = call_id;
  uintptr_t buffer_data_start = edge_call_data_ptr();

  /*
   * CRITICAL FIX: Use ocall_buffer_size for bounds checking
   *
   * edge_call_data_ptr() returns a pointer within ocall_buffer (set by
   * edge_call_init_internals), so we must check against ocall_buffer_size.
   */
  if(data_len > (ocall_buffer_size - (buffer_data_start - ocall_buffer))){
    ocall_error_code = 2;
    goto ocall_error;
  }
  //TODO safety check on source
  copy_from_user((void*)buffer_data_start, (void*)data, data_len);

  if(edge_call_setup_call(edge_call, (void*)buffer_data_start, data_len) != 0){
    ocall_error_code = 3;
    goto ocall_error;
  }

  ret = sbi_stop_enclave(STOP_EDGE_CALL_HOST);

  if (ret != 0) {
    ocall_error_code = 10;
    goto ocall_error;
  }

  if(edge_call->return_data.call_status != CALL_STATUS_OK){
    ocall_error_code = 20 + edge_call->return_data.call_status;
    goto ocall_error;
  }

  if( return_len == 0 ){
    /* Done, no return */
    return (uintptr_t)NULL;
  }

  uintptr_t return_ptr;
  size_t ret_len_untrusted;
  if(edge_call_ret_ptr(edge_call, &return_ptr, &ret_len_untrusted) != 0){
    ocall_error_code = 30;
    goto ocall_error;
  }

  /* Done, there was a return value to copy out of shared mem */
  /* TODO This is currently assuming return_len is the length, not the
     value passed in the edge_call return data. We need to somehow
     validate these. The size in the edge_call return data is larger
     almost certainly.*/
  copy_to_user(return_buffer, (void*)return_ptr, ret_len_untrusted > return_len ? return_len : ret_len_untrusted);

  return 0;

 ocall_error:
  /* TODO In the future, this should fault */
  return ocall_error_code;
}

uintptr_t handle_copy_from_shared(void* dst, uintptr_t offset, size_t size){

  /* This is where we would handle cache side channels for a given
     platform */

  /* The only safety check we do is to confirm all data comes from the
   * shared region. */
  uintptr_t src_ptr;
  if(edge_call_get_ptr_from_offset(offset, size,
				   &src_ptr) != 0){
    return 1;
  }

  return copy_to_user(dst, (void*)src_ptr, size);
}

/*
 * debug_walk_page_table_runtime - 在 Runtime 阶段遍历页表并打印映射信息
 *
 * 【2026-01-07 禁用】此函数已被注释掉，原因：
 *
 * 问题根因：
 * - 此函数使用 __va() 转换页表的物理地址
 * - __va(pa) = (pa - load_pa_start) + EYRIE_LOAD_START
 * - 当 pa < load_pa_start 时（如共享 UTM 的 PA 0x98000000 < Slave 的 load_pa_start 0xa0c00000）
 * - 计算结果为负数偏移，产生无效的 VA（如 0xfffffffef7400000）
 * - 访问这个无效 VA 导致 page fault，Slave Enclave 崩溃
 *
 * 为什么 v1.0 版本没有这个问题：
 * - v1.0 使用 4KB 页面映射，所有页表（L1, L2, L3）都在 EPM 范围内
 * - 当前版本使用 2MB megapage 映射，触发了 __va() 的问题
 *
 * 解决方案：使用 translate() 函数代替页表遍历诊断
 *
 * 与 loader 阶段的 debug_walk_page_table 不同，这个函数在虚拟地址模式下运行，
 * 需要使用 __va() 来访问页表。
 *
 * @param va 要查询的虚拟地址
 */
#if 0  /* DISABLED: causes page fault in shared UTM mode with megapage mapping */
static void debug_walk_page_table_runtime(uintptr_t va) {
  printf("[Runtime-PT] Walking page table for VA=0x%lx\n", va);

  /* 获取 L1 索引 */
  size_t l1_idx = RISCV_GET_PT_INDEX(va, 1);
  pte l1_entry = root_page_table[l1_idx];
  printf("[Runtime-PT]   L1[%lu] = 0x%lx\n", l1_idx, l1_entry);

  if (!(l1_entry & PTE_V)) {
    printf("[Runtime-PT]   L1 entry not valid!\n");
    return;
  }

  /* 检查 L1 是否是叶子节点 (gigapage) */
  if (l1_entry & (PTE_R | PTE_W | PTE_X)) {
    uintptr_t pa = pte_ppn(l1_entry) << RISCV_PAGE_BITS;
    printf("[Runtime-PT]   Gigapage (1GB): VA 0x%lx -> PA 0x%lx\n", va, pa);
    return;
  }

  /* 获取 L2 页表地址 - 使用 __va() 转换 */
  uintptr_t l2_pt_pa = pte_ppn(l1_entry) << RISCV_PAGE_BITS;
  uintptr_t l2_pt_va = __va(l2_pt_pa);
  printf("[Runtime-PT]   L2 PT PA = 0x%lx, VA = 0x%lx\n", l2_pt_pa, l2_pt_va);

  pte* l2_pt = (pte*)l2_pt_va;

  /* 获取 L2 索引 */
  size_t l2_idx = RISCV_GET_PT_INDEX(va, 2);
  pte l2_entry = l2_pt[l2_idx];
  printf("[Runtime-PT]   L2[%lu] = 0x%lx\n", l2_idx, l2_entry);

  if (!(l2_entry & PTE_V)) {
    printf("[Runtime-PT]   L2 entry not valid!\n");
    return;
  }

  /* 检查是否是 megapage (R/W/X 位设置) */
  if (l2_entry & (PTE_R | PTE_W | PTE_X)) {
    uintptr_t pa = pte_ppn(l2_entry) << RISCV_PAGE_BITS;
    printf("[Runtime-PT]   Megapage (2MB): VA 0x%lx -> PA 0x%lx\n", va, pa);
    return;
  }

  /* L2 指向 L3 页表 - 使用 __va() 转换 */
  uintptr_t l3_pt_pa = pte_ppn(l2_entry) << RISCV_PAGE_BITS;
  uintptr_t l3_pt_va = __va(l3_pt_pa);
  printf("[Runtime-PT]   L3 PT PA = 0x%lx, VA = 0x%lx\n", l3_pt_pa, l3_pt_va);

  pte* l3_pt = (pte*)l3_pt_va;

  /* 获取 L3 索引 */
  size_t l3_idx = RISCV_GET_PT_INDEX(va, 3);
  pte l3_entry = l3_pt[l3_idx];
  printf("[Runtime-PT]   L3[%lu] = 0x%lx\n", l3_idx, l3_entry);

  if (!(l3_entry & PTE_V)) {
    printf("[Runtime-PT]   L3 entry not valid!\n");
    return;
  }

  uintptr_t pa = pte_ppn(l3_entry) << RISCV_PAGE_BITS;
  printf("[Runtime-PT]   4KB Page: VA 0x%lx -> PA 0x%lx\n", va, pa);
}
#endif /* DISABLED */

/*
 * handle_copy_from_shared_utm - 从共享 UTM 读取数据
 *
 * 与 handle_copy_from_shared 不同，这个函数直接使用 shared_buffer
 * 而不是通过 edge_call_get_ptr_from_offset（后者使用 ocall_buffer）
 *
 * 在共享 UTM 模式下：
 *   - handle_copy_from_shared() 使用 ocall_buffer（Enclave 自己的 1MB UTM）
 *   - handle_copy_from_shared_utm() 使用 shared_buffer（Main 的 64MB 共享 UTM）
 *
 * 在普通模式下，两者等价（shared_buffer == ocall_buffer）
 *
 * CRITICAL FIX (2026-01-06): 添加内存屏障确保缓存一致性
 * 在共享 UTM 模式下，Host 写入数据后，Slave Enclave 需要确保
 * 能够读取到最新的数据。添加 fence 指令来同步内存访问。
 */
uintptr_t handle_copy_from_shared_utm(void* dst, uintptr_t offset, size_t size){

  //===========================================================================
  // 【2026-01-10 性能优化】注释掉所有诊断日志
  // 这些 printf 语句在每次调用时都会执行，严重影响性能
  // 保留代码以便调试时重新启用
  //===========================================================================
  // printf("[Runtime] ========== copy_from_shared_utm DIAGNOSTIC ==========\n");
  // printf("[Runtime] copy_from_shared_utm: ENTRY\n");
  // printf("[Runtime]   shared_buffer (VA) = 0x%lx\n", shared_buffer);
  // printf("[Runtime]   shared_buffer_size = %lu (0x%lx)\n", shared_buffer_size, shared_buffer_size);
  // printf("[Runtime]   offset             = %lu (0x%lx)\n", offset, offset);
  // printf("[Runtime]   size               = %lu (0x%lx)\n", size, size);
  // printf("[Runtime]   ocall_buffer (VA)  = 0x%lx\n", ocall_buffer);
  // printf("[Runtime]   ocall_buffer_size  = %lu (0x%lx)\n", ocall_buffer_size, ocall_buffer_size);
  // printf("[Runtime]   load_pa_start      = 0x%lx\n", load_pa_start);

  // 检查 shared_buffer 和 ocall_buffer 是否相同
  // if (shared_buffer == ocall_buffer) {
  //   printf("[Runtime]   WARNING: shared_buffer == ocall_buffer (NOT shared UTM mode?)\n");
  // } else {
  //   printf("[Runtime]   OK: shared_buffer != ocall_buffer (shared UTM mode)\n");
  // }

  //===========================================================================
  // 【2026-01-10 性能优化】注释掉 translate() 诊断
  //===========================================================================
  // uintptr_t shared_buffer_pa = translate(shared_buffer);
  // uintptr_t ocall_buffer_pa = translate(ocall_buffer);
  // printf("[Runtime]   shared_buffer PA (via translate) = 0x%lx\n", shared_buffer_pa);
  // printf("[Runtime]   ocall_buffer PA (via translate)  = 0x%lx\n", ocall_buffer_pa);

  // 检查 PA 是否相同（这是问题的关键！）
  // if (shared_buffer_pa == ocall_buffer_pa) {
  //   printf("[Runtime]   *** CRITICAL: shared_buffer and ocall_buffer map to SAME PA! ***\n");
  //   printf("[Runtime]   *** This is the ROOT CAUSE of the data corruption! ***\n");
  // } else {
  //   printf("[Runtime]   OK: shared_buffer and ocall_buffer map to different PAs\n");
  // }
  //===========================================================================

  //===========================================================================
  // DIAGNOSTIC: Page table walking disabled to avoid page fault
  //
  // 【2026-01-07 修复】禁用 debug_walk_page_table_runtime 调用
  //
  // 问题根因：
  // - debug_walk_page_table_runtime 使用 __va() 转换页表的物理地址
  // - __va(pa) = (pa - load_pa_start) + EYRIE_LOAD_START
  // - 当 pa < load_pa_start 时（如共享 UTM 的 PA 0x98000000 < Slave 的 load_pa_start 0xa0c00000）
  // - 计算结果为负数偏移，产生无效的 VA（如 0xfffffffef7400000）
  // - 访问这个无效 VA 导致 page fault，Slave Enclave 崩溃
  //
  // 解决方案：禁用页表遍历诊断，使用 translate() 函数代替
  //===========================================================================
  // printf("[Runtime] Verifying page table mapping at runtime...\n");
  // debug_walk_page_table_runtime(shared_buffer);  // DISABLED: causes page fault

  // printf("[Runtime] Verifying ocall_buffer page table mapping...\n");
  // debug_walk_page_table_runtime(ocall_buffer);   // DISABLED: causes page fault
  //===========================================================================

  /* Validate that offset + size is within shared_buffer bounds */
  if (offset > shared_buffer_size || size > shared_buffer_size - offset) {
    printf("[Runtime] ERROR: copy_from_shared_utm: offset=%lu size=%lu exceeds buffer_size=%lu\n",
           offset, size, shared_buffer_size);
    return 1;
  }

  //===========================================================================
  // 【2026-01-10 性能优化】注释掉内存屏障
  //
  // 原因分析：
  // 1. fence rw, rw: 在单核系统上通常不需要，因为没有其他 CPU 并发访问
  // 2. sfence.vma: TLB flush 非常昂贵，每次调用都执行会严重影响性能
  //
  // 在共享 UTM 模式下，Host 和 Enclave 是串行执行的（通过 OCALL/ECALL 切换），
  // 所以不需要额外的内存屏障来保证一致性。
  //
  // 如果遇到数据一致性问题，可以重新启用这些屏障。
  //===========================================================================
  /*
   * CRITICAL: Memory barrier before reading from shared UTM
   * This ensures we see the latest data written by Host.
   * The fence instruction synchronizes memory accesses across
   * different privilege levels and hardware threads.
   */
  // __asm__ __volatile__ ("fence rw, rw" ::: "memory");

  /* Also flush TLB to ensure we're using the latest page table entries */
  // __asm__ __volatile__ ("sfence.vma" ::: "memory");

  /* Calculate source pointer directly from shared_buffer */
  uintptr_t src_ptr = shared_buffer + offset;

  //===========================================================================
  // 【2026-01-10 性能优化】注释掉数据打印诊断
  //===========================================================================
  // printf("[Runtime]   src_ptr (VA)       = 0x%lx\n", src_ptr);

  /* Print first 64 bytes of data at source (if size >= 64) */
  // printf("[Runtime]   First 64 bytes at src:\n");
  // printf("[Runtime]     ");
  // if (size >= 64) {
  //   volatile uint8_t* data = (volatile uint8_t*)src_ptr;
  //   int i;
  //   for (i = 0; i < 64; i++) {
  //     printf("%02x", data[i]);
  //     if ((i + 1) % 4 == 0) printf(" ");
  //     if ((i + 1) % 32 == 0 && i + 1 < 64) {
  //       printf("\n[Runtime]     ");
  //     }
  //   }
  //   printf("\n");
  // } else if (size > 0) {
  //   volatile uint8_t* data = (volatile uint8_t*)src_ptr;
  //   size_t j;
  //   for (j = 0; j < size; j++) {
  //     printf("%02x", data[j]);
  //     if ((j + 1) % 4 == 0) printf(" ");
  //   }
  //   printf("\n");
  // }

  /* Check if data looks like edge_call structure */
  // volatile uint8_t* check_data = (volatile uint8_t*)src_ptr;
  // if (size >= 4 && check_data[0] == 0x03 && check_data[1] == 0x00 &&
  //     check_data[2] == 0x00 && check_data[3] == 0x00) {
  //   printf("[Runtime]   *** CRITICAL: Data looks like edge_call structure! ***\n");
  //   printf("[Runtime]   *** call_id = 3 (OCALL_PRINT_STRING) ***\n");
  //   printf("[Runtime]   *** This indicates page table mapping error! ***\n");
  //   printf("[Runtime]   *** shared_buffer VA may be mapped to wrong PA ***\n");
  //
  //   /* Also check what's at ocall_buffer for comparison */
  //   printf("[Runtime]   Comparing with ocall_buffer content:\n");
  //   printf("[Runtime]     ocall_buffer first 64 bytes:\n");
  //   printf("[Runtime]     ");
  //   volatile uint8_t* ocall_data = (volatile uint8_t*)ocall_buffer;
  //   int k;
  //   for (k = 0; k < 64; k++) {
  //     printf("%02x", ocall_data[k]);
  //     if ((k + 1) % 4 == 0) printf(" ");
  //     if ((k + 1) % 32 == 0 && k + 1 < 64) {
  //       printf("\n[Runtime]     ");
  //     }
  //   }
  //   printf("\n");
  //
  //   /* Check if shared_buffer and ocall_buffer have same content */
  //   int same_content = 1;
  //   for (k = 0; k < 64 && k < (int)size; k++) {
  //     if (check_data[k] != ocall_data[k]) {
  //       same_content = 0;
  //       break;
  //     }
  //   }
  //   if (same_content) {
  //     printf("[Runtime]   *** shared_buffer and ocall_buffer have SAME content! ***\n");
  //     printf("[Runtime]   *** This confirms page table mapping error! ***\n");
  //   } else {
  //     printf("[Runtime]   shared_buffer and ocall_buffer have different content\n");
  //   }
  // }

  // printf("[Runtime] ========================================================\n");
  //===========================================================================

  return copy_to_user(dst, (void*)src_ptr, size);
}

/*
 * handle_copy_to_shared_utm - 写入数据到共享 UTM
 *
 * 与 handle_copy_from_shared_utm 对应，实现一次性写入大块数据
 * 消除传统 OCALL_WRITE_DATA_CHUNK 分块写入的开销（8MB 需要 128 次 OCALL）
 *
 * 在共享 UTM 模式下：
 *   - 传统方式：使用 OCALL_WRITE_DATA_CHUNK 分块写入（每次 64KB，8MB 需要 128 次）
 *   - 优化方式：使用 handle_copy_to_shared_utm() 一次性写入（1 次 syscall）
 *
 * 性能提升：消除 OCALL 上下文切换开销，预计提升 10-50x
 *
 * 参数：
 *   offset - 共享 UTM 中的目标偏移量
 *   src    - 源数据缓冲区（用户空间地址）
 *   size   - 要写入的字节数
 *
 * 返回：0=成功，1=失败
 */
uintptr_t handle_copy_to_shared_utm(uintptr_t offset, void* src, size_t size){

  //===========================================================================
  // 【2026-01-10 性能优化】注释掉所有诊断日志
  // 这些 printf 语句在每次调用时都会执行，严重影响性能
  // 保留代码以便调试时重新启用
  //===========================================================================
  // printf("[Runtime] ========== copy_to_shared_utm DIAGNOSTIC ==========\n");
  // printf("[Runtime] copy_to_shared_utm: ENTRY\n");
  // printf("[Runtime]   shared_buffer (VA) = 0x%lx\n", shared_buffer);
  // printf("[Runtime]   shared_buffer_size = %lu (0x%lx)\n", shared_buffer_size, shared_buffer_size);
  // printf("[Runtime]   offset             = %lu (0x%lx)\n", offset, offset);
  // printf("[Runtime]   size               = %lu (0x%lx)\n", size, size);
  // printf("[Runtime]   src (user VA)      = 0x%lx\n", (uintptr_t)src);

  // 检查 shared_buffer 和 ocall_buffer 是否相同
  // if (shared_buffer == ocall_buffer) {
  //   printf("[Runtime]   WARNING: shared_buffer == ocall_buffer (NOT shared UTM mode?)\n");
  // } else {
  //   printf("[Runtime]   OK: shared_buffer != ocall_buffer (shared UTM mode)\n");
  // }

  /* Validate that offset + size is within shared_buffer bounds */
  if (offset > shared_buffer_size || size > shared_buffer_size - offset) {
    printf("[Runtime] ERROR: copy_to_shared_utm: offset=%lu size=%lu exceeds buffer_size=%lu\n",
           offset, size, shared_buffer_size);
    return 1;
  }

  /* Calculate destination pointer directly from shared_buffer */
  uintptr_t dst_ptr = shared_buffer + offset;

  // printf("[Runtime]   dst_ptr (VA)       = 0x%lx\n", dst_ptr);

  /* Copy data from user space to shared UTM */
  uintptr_t ret = copy_from_user((void*)dst_ptr, src, size);

  if (ret != 0) {
    printf("[Runtime] ERROR: copy_to_shared_utm: copy_from_user failed\n");
    return 1;
  }

  //===========================================================================
  // 【2026-01-10 性能优化】注释掉内存屏障
  //
  // 原因分析：
  // 1. fence rw, rw: 在单核系统上通常不需要，因为没有其他 CPU 并发访问
  // 2. sfence.vma: TLB flush 非常昂贵，每次调用都执行会严重影响性能
  //
  // 在共享 UTM 模式下，Host 和 Enclave 是串行执行的（通过 OCALL/ECALL 切换），
  // 所以不需要额外的内存屏障来保证一致性。
  //
  // 如果遇到数据一致性问题，可以重新启用这些屏障。
  //===========================================================================
  /*
   * CRITICAL: Memory barrier after writing to shared UTM
   * This ensures the data is visible to Host and other Enclaves.
   * The fence instruction synchronizes memory accesses across
   * different privilege levels and hardware threads.
   */
  // __asm__ __volatile__ ("fence rw, rw" ::: "memory");

  /* Also flush TLB to ensure consistency */
  // __asm__ __volatile__ ("sfence.vma" ::: "memory");

  // printf("[Runtime] copy_to_shared_utm: SUCCESS, wrote %lu bytes to offset 0x%lx\n",
  //        size, offset);
  // printf("[Runtime] ========================================================\n");

  return 0;
}

static uintptr_t handle_utm_query_direct(void* output, size_t output_len) {
  struct keystone_utm_direct_info info;

  if (utm_direct_data_runtime_marker[0] != 'k' ||
      !output || output_len != sizeof(info) ||
      ocall_buffer_size <= KEYSTONE_UTM_DIRECT_CONTROL_BYTES)
    return 1;
  memset(&info, 0, sizeof(info));
  info.abi_version = KEYSTONE_UTM_DIRECT_ABI_VERSION;
  info.struct_size = sizeof(info);
  info.data_va = EYRIE_UTM_DIRECT_DATA_START;
  info.data_size = ocall_buffer_size - KEYSTONE_UTM_DIRECT_CONTROL_BYTES;
  info.data_utm_offset = KEYSTONE_UTM_DIRECT_CONTROL_BYTES;
  info.flags = KEYSTONE_UTM_DIRECT_FLAG_READ |
               KEYSTONE_UTM_DIRECT_FLAG_WRITE |
               KEYSTONE_UTM_DIRECT_FLAG_NX;
  return copy_to_user(output, &info, sizeof(info));
}

uintptr_t handle_group_private_region_info(void* dst, size_t size)
{
  struct group_private_region_info info;

  if (size != sizeof(info)) {
    return -1;
  }

  memset(&info, 0, sizeof(info));
  KEYSTONE_ABI_INIT(&info, KEYSTONE_GROUP_ABI_FEATURES);
  info.private_va_base = private_region_va_start;
  info.private_size = private_region_size;
  return copy_to_user(dst, &info, sizeof(info));
}

uintptr_t yxstm_runtime_acquire_rw(void)
{
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

uintptr_t yxstm_runtime_release_after(uintptr_t ret)
{
  return ret ? ret : SBI_ERR_SM_NOT_IMPLEMENTED;
}

// test other enclave access stm
// 不需要从other enclave eapp 中获取数据只需要让other enclave runtime 向stm中写入数据
uintptr_t handle_STM_TEST_OTHER_ENCLAVE_ACCESS() {

  unsigned long long *YXSTM_start_ptr = (unsigned long long *)YXS_trusted_memory;
  // unsigned long long YXSTM_size       = YXS_trusted_memory_size;

  // 本来是有权限的
  memset((void*)YXSTM_start_ptr, 0, 8);
  printf("pmp rwx=111 memset stm successed.\n");

  // 让SM将该enclave对stm的权限由rxw=111 ==> rwx=000
  if (sbi_other_enclave_access_stm_test_set_pmp()) {
    printf("pmp set error\n");
    return 1;
  }
  memset((void*)YXSTM_start_ptr, 0, 8);
  // 如果没出错则会输出下面
  printf("pmp rwx=000 memset stm successed.\n");

  return 0;
}

int map_TEST_OTHER_ENCLAVE_ACCESS_EPM(uintptr_t TEST_ACCESS_EPM_ptr, uintptr_t TEST_ACCESS_EPM_size) {
  uintptr_t va        = EYRIE_TEST_OTHER_ENCLAVE_ACCESS_EPM;
  while (va < EYRIE_TEST_OTHER_ENCLAVE_ACCESS_EPM + TEST_ACCESS_EPM_size) {
    if (!map_page(vpn(va), ppn(TEST_ACCESS_EPM_ptr), PTE_W | PTE_R | PTE_D)) {
      return -1;
    }
    va += RISCV_PAGE_SIZE;
    TEST_ACCESS_EPM_ptr += RISCV_PAGE_SIZE;
  }
  return 0;
}

// test other enclave access epm
// meixiewan
uintptr_t handle_TEST_OTHER_ENCLAVE_ACCESS_EPM_O(void* arg0) {

  // 通过stm接收epm物理地址
  //
  unsigned long long flag = 0;
  if (copy_from_user((void*)&flag, arg0, sizeof(unsigned long long))) {
    return 1;
  }

  unsigned long long *YXSTM_start_ptr = (unsigned long long *)YXS_trusted_memory;
  unsigned long long YXSTM_size       = YXS_trusted_memory_size;
  unsigned long long MAX_YXSTM_ptr    = (unsigned long long)((unsigned char*)YXSTM_start_ptr + YXSTM_size);

  struct YXSTM_USE {
    unsigned long long *YXSTM_USE_flag_ptr;
    unsigned long long YXSTM_USE_data_offset;
    unsigned long long YXSTM_USE_data_size;
  };

  struct YXSTM_USE YXSTM_use = {
    .YXSTM_USE_flag_ptr = YXSTM_start_ptr,
    .YXSTM_USE_data_offset = 1,
    .YXSTM_USE_data_size = 8
  };
  // YXSTM_use.YXSTM_USE_flag_ptr = YXSTM_start_ptr;
  // YXSTM_use.YXSTM_USE_data_offset = 1;

  uintptr_t epm_base_ptr = 0;

  int i = 0;
  for (i = 0; i < YXSTM_use.YXSTM_USE_data_offset; ++i) {
    if (*(YXSTM_use.YXSTM_USE_flag_ptr + i) == 0) {
      unsigned long long *YXSTM_USE_data_ptr = YXSTM_use.YXSTM_USE_flag_ptr + YXSTM_use.YXSTM_USE_data_offset*2 + i*YXSTM_use.YXSTM_USE_data_size;
      if ((unsigned long long)((unsigned char*)YXSTM_USE_data_ptr + sizeof(test_other_enclave_access_epm)) <= MAX_YXSTM_ptr) {
        epm_base_ptr = *YXSTM_USE_data_ptr;
        *(YXSTM_use.YXSTM_USE_flag_ptr + i) = 0;
        flag = 1;
        if (copy_to_user(arg0, (void*)&flag, sizeof(unsigned long long))) {
          return 1;
        }
      } else {
        printf("YXSTM size too small\n");
      }
      break;
    }
  }

  if (i >= YXSTM_use.YXSTM_USE_data_offset) {
    flag = 0;
    if (copy_to_user(arg0, (void*)&flag, sizeof(unsigned long long))) {
      return 1;
    }
  }

  // 将物理地址映射到EYRIE_TEST_OTHER_ENCLAVE_ACCESS_EPM
  // 默认使用8B大小
  uintptr_t test_other_enclave_access_epm_size = 8;
  //
  map_TEST_OTHER_ENCLAVE_ACCESS_EPM(epm_base_ptr, test_other_enclave_access_epm_size);

  uintptr_t test_other_enclave_access_epm_base_memory = EYRIE_TEST_OTHER_ENCLAVE_ACCESS_EPM;

  // 测试
  memset((void*)test_other_enclave_access_epm_base_memory, 0, test_other_enclave_access_epm_size);
  // 如果没出错则会输出下面
  printf("memset epm successed. test other enclave access epm error! \n");

  return 0;
}

// test other enclave access epm
// meixiewan
uintptr_t handle_TEST_OTHER_ENCLAVE_ACCESS_EPM_S(void* arg0) {

  // 通过stm发送epm物理地址
  //
  unsigned long long flag = 1;
  if (copy_from_user((void*)&flag, arg0, sizeof(unsigned long long))) {
    return 1;
  }

  unsigned long long *YXSTM_start_ptr = (unsigned long long *)YXS_trusted_memory;
  unsigned long long YXSTM_size       = YXS_trusted_memory_size;
  unsigned long long MAX_YXSTM_ptr    = (unsigned long long)((unsigned char*)YXSTM_start_ptr + YXSTM_size);

  struct YXSTM_USE {
    unsigned long long *YXSTM_USE_flag_ptr;
    unsigned long long YXSTM_USE_data_offset;
    unsigned long long YXSTM_USE_data_size;
  };

  struct YXSTM_USE YXSTM_use = {
    .YXSTM_USE_flag_ptr = YXSTM_start_ptr,
    .YXSTM_USE_data_offset = 1,
    .YXSTM_USE_data_size = 8
  };
  // YXSTM_use.YXSTM_USE_flag_ptr = YXSTM_start_ptr;
  // YXSTM_use.YXSTM_USE_data_offset = 1;

  int i = 0;
  for (i = 0; i < YXSTM_use.YXSTM_USE_data_offset; ++i) {
    if (*(YXSTM_use.YXSTM_USE_flag_ptr + i) == 0) {
      unsigned long long *YXSTM_USE_data_ptr = YXSTM_use.YXSTM_USE_flag_ptr + YXSTM_use.YXSTM_USE_data_offset*2 + i*YXSTM_use.YXSTM_USE_data_size;
      if ((unsigned long long)((unsigned char*)YXSTM_USE_data_ptr + sizeof(test_other_enclave_access_epm)) <= MAX_YXSTM_ptr) {
        *YXSTM_USE_data_ptr = test_other_enclave_access_epm;
        *(YXSTM_use.YXSTM_USE_flag_ptr + i) = 1;
        flag = 0;
        if (copy_to_user(arg0, (void*)&flag, sizeof(unsigned long long))) {
          return 1;
        }
      } else {
        printf("YXSTM size too small\n");
      }
      break;
    }
  }

  if (i >= YXSTM_use.YXSTM_USE_data_offset) {
    flag = 1;
    if (copy_to_user(arg0, (void*)&flag, sizeof(unsigned long long))) {
      return 1;
    }
  }

  // // 默认使用8B大小
  // int test_other_enclave_access_epm_size = 8;

  return 0;
}

uintptr_t handle_get_numberBlock_from_YXSTM(void* dst, uintptr_t get_number, size_t size){

  uintptr_t ret = 0;

  unsigned long long *YXSTM_start_ptr = (unsigned long long *)YXS_trusted_memory;
  unsigned long long YXSTM_size       = YXS_trusted_memory_size;

  // if (sbi_main_enclave_get_numberblock_set_pmp()) {
  //   ret = 1;
  //   goto YXSTM_error;
  // }

  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;

  if (number <= 0) {
    ret = 1;
    goto YXSTM_error;
  }

  unsigned long long * number_ptr = YXSTM_start_ptr;
  unsigned long long * length_ptr = YXSTM_start_ptr + number;
  unsigned char * src_ptr         = (unsigned char *)(YXSTM_start_ptr + number + number);

  unsigned long long src_offset = 0;

  int i;
  for (i = 0; i < number; ++i) {
    if (get_number == number_ptr[i]) {
      break;
    }
  }

  unsigned char temp[17] = {0,};

  if (i < number) {
    src_offset = i << 18;
    *((unsigned long long*)temp) = number_ptr[i];
    *(((unsigned long long*)temp) + 1) = length_ptr[i];
    temp[16] = 1;
    if (copy_to_user(dst+17, (void*)(src_ptr + src_offset), length_ptr[i])) {
      ret = 1;
      goto YXSTM_error;
    }

    /* copy_to_user clears SR_SUM; YXSTM is PTE_U, so re-enable before metadata writes. */
    csr_set(sstatus, SR_SUM);

    number_ptr[i] = 0;
    length_ptr[i] = 0;
  } else {
    *((unsigned long long*)temp) = 0;
    *(((unsigned long long*)temp) + 1) = 0;
    temp[16] = 0;
  }

  if (copy_to_user(dst, (void*)temp, 17)) {
    ret = 1;
    goto YXSTM_error;
  }

YXSTM_error:
  return ret;
}

uintptr_t handle_set_numberBlock_to_YXSTM(void* src, uintptr_t set_number, size_t size){

  uintptr_t ret = 0;

  // if (sbi_slave_enclave_set_numberblock_set_pmp()) {
  //   ret = 1;
  //   goto YXSTM_error;
  // }

  unsigned long long *YXSTM_start_ptr = (unsigned long long *)YXS_trusted_memory;
  unsigned long long YXSTM_size       = YXS_trusted_memory_size;

  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;

  if (number <= 0) {
    ret = 1;
    goto YXSTM_error;
  }

  unsigned long long * number_ptr = YXSTM_start_ptr;
  unsigned long long * length_ptr = YXSTM_start_ptr + number;
  unsigned char * dst_ptr         = (unsigned char *)(YXSTM_start_ptr + number + number);

  unsigned long long dst_offset = 0;

  int i;
  for (i = 0; i < number; ++i) {
    if ((number_ptr[i] == 0) && (length_ptr[i] == 0)) {
      break;
    }
  }

  unsigned char temp[17] = {0,};

  if (i < number) {
    dst_offset = i << 18;
    if (copy_from_user((void*)(dst_ptr + dst_offset), src+17, size)) {
      ret = 1;
      goto YXSTM_error;
    }

    /* copy_from_user clears SR_SUM; YXSTM is PTE_U, so re-enable before metadata writes. */
    csr_set(sstatus, SR_SUM);

    *(((unsigned long long*)temp) + 1) = length_ptr[i] = size;
    *((unsigned long long*)temp) = number_ptr[i] = set_number;
    temp[16] = 0;
  } else {
    *((unsigned long long*)temp) = 0;
    *(((unsigned long long*)temp) + 1) = 0;
    temp[16] = 1;
  }

  if (copy_to_user(src, (void*)temp, 17)) {
    ret = 1;
    goto YXSTM_error;
  }

YXSTM_error:
  return ret;
}

uintptr_t m_attestt_s_enclave(void *_attested_report) {
  // struct s_attested_report {
  //   unsigned int seq;
  //   unsigned long long nonce;
  //   unsigned char s_hash[64];
  //   unsigned char hmac[64];
  //   unsigned char signature[64];
  // }

  // struct s_attested_report* report = (struct s_attested_report*)_attested_report;
  uint64_t flag = 0;
  if (sbi_m_enclave_attest_s_enclave(_attested_report, kg, &flag)){
    return 1;
  }

  if (flag == 0) {
    printf("m_attest_s %s, flag err ,not match\n", __func__);
  }
  // return memcmp(kg, report->enclave.data, report->enclave.data_len);
  return 0;
}

uintptr_t handle_m_attestt_s_enclave(size_t slave_id, size_t flexible) {
  // 将kg作为 report中的nonce
  // data maxlen = 1024, sizeof(kg)=64

  // printf("[main runtime] %s start 1, slave_id:%d, flexible:%d\n", __func__, slave_id, flexible);

  uint64_t *YXSTM_start_ptr = (uint64_t *)YXS_trusted_memory;
  uint64_t YXSTM_size       = YXS_trusted_memory_size;

  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;
  if (number <= 0) {
    return 1;
  }

  size_t slave_stm_region = number / (flexible - 1);

  uint64_t *this_slave_flag_addr = YXSTM_start_ptr + (3 * slave_stm_region * (slave_id - 1));
  char *slave_stm_data_ptr_start = (char*)YXSTM_start_ptr + (sizeof(uint64_t) * 3 * slave_stm_region * (flexible - 1)) + ((slave_stm_region * (slave_id - 1)) << 11);

  // printf("[main runtime] %s start 2\n", __func__);

  size_t i = 0;
  while(1) {
    for (i = 0; i < slave_stm_region; i++) {
      // printf("[main runtime] %s start .1.. i:%d, slave_stm_region:%d\n", __func__, i, slave_stm_region);
      if (this_slave_flag_addr[(i*3)] == 1 && this_slave_flag_addr[(i*3) + 1] == 2048) {
        break;
      }
    }

    // printf("[main runtime] %s start .2.. i:%d, slave_stm_region:%d\n", __func__, i, slave_stm_region);

    if (i < slave_stm_region) {
      break;
    }
  }

  // printf("[main runtime] %s start 3\n", __func__);

  memcpy((void*)attested_report, (slave_stm_data_ptr_start + (i << 11)), 2048);
  this_slave_flag_addr[(i*3)] = 0;
  this_slave_flag_addr[(i*3) + 1] = 0;

  // printf("[main runtime] %s start 4\n", __func__);

  // attest s report
  if (m_attestt_s_enclave(attested_report)) {
    printf("attest not match %s, slave_id:%d\n", __func__, slave_id);
    this_slave_flag_addr[(i*3)] = 3;
    return 1;
  }

  this_slave_flag_addr[(i*3)] = 2;
  // printf("[main runtime] %s start 5\n", __func__);

  return 0;
}

struct test_s_attested_report {
  unsigned int seq;
  unsigned long long nonce;
  unsigned char s_hash[64];
  unsigned char hmac[64];
  unsigned char signature[64];
};

static uint64_t g_test_attestation_mutation = TEST_ATTEST_MUTATION_NONE;

static void apply_test_attestation_mutation(void* report_ptr) {
  struct test_s_attested_report* report = (struct test_s_attested_report*)report_ptr;

  switch (g_test_attestation_mutation) {
    case TEST_ATTEST_MUTATION_REPLAY_SEQ:
      report->seq = (report->seq == 0) ? 0xffffffffU : (report->seq - 1);
      break;
    case TEST_ATTEST_MUTATION_TAMPER_N_CH:
      report->nonce ^= 0x5a5a5a5a5a5a5a5aULL;
      break;
    case TEST_ATTEST_MUTATION_TAMPER_HMAC:
      report->hmac[0] ^= 0xa5;
      break;
    case TEST_ATTEST_MUTATION_TAMPER_SM_ENDORSEMENT:
      report->signature[0] ^= 0x3c;
      break;
    default:
      return;
  }

  printf("[runtime][TEST] applied slave attestation mutation mode=%lu\n",
         g_test_attestation_mutation);
  g_test_attestation_mutation = TEST_ATTEST_MUTATION_NONE;
}

uintptr_t handle_s_enclave_attestted(size_t slave_id, size_t flexible) {
  // 将kg作为 report中的nonce
  // data maxlen = 1024, sizeof(kg)=64
  // printf("[slave runtime] %s start 1, slave_id:%d, flexible:%d\n", __func__, slave_id, flexible);
  if (sbi_slave_enclave_attested(attested_report, sbi_random(), kg)) {
    return 1;
  }

  apply_test_attestation_mutation(attested_report);

  uint64_t *YXSTM_start_ptr = (uint64_t *)YXS_trusted_memory;
  uint64_t YXSTM_size       = YXS_trusted_memory_size;

  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;
  if (number <= 0) {
    return 1;
  }

  size_t slave_stm_region = number / (flexible - 1);

  uint64_t *this_slave_flag_addr = YXSTM_start_ptr + (3 * slave_stm_region * (slave_id - 1));
  char *slave_stm_data_ptr_start = (char*)YXSTM_start_ptr + (sizeof(uint64_t) * 3 * slave_stm_region * (flexible - 1)) + ((slave_stm_region * (slave_id - 1)) << 11);

  // printf("[slave runtime] %s start 2\n", __func__);
  size_t i = 0;
  while (1) {
    for (i = 0; i < slave_stm_region; i++) {
      // if decrypt, size = 0, 0: then send data
      if (this_slave_flag_addr[(i*3)] == 0 && this_slave_flag_addr[(i*3) + 1] == 0) {
        break;
      }
    }
    if (i < slave_stm_region) {
      break;
    }
  }

  // printf("[slave runtime] %s start 3\n", __func__);
  memcpy((slave_stm_data_ptr_start + (i << 11)), (void*)attested_report, 2048);
  this_slave_flag_addr[(i*3)] = 1;
  this_slave_flag_addr[(i*3) + 1] = 2048;

  while(1) {
    if (this_slave_flag_addr[(i*3)] == 2) {
      this_slave_flag_addr[(i*3)] = 0;
      this_slave_flag_addr[(i*3) + 1] = 0;
      memset(slave_stm_data_ptr_start + (i << 11), 0, 2048);
      break;
    }
    if (this_slave_flag_addr[(i*3)] == 3) {
      this_slave_flag_addr[(i*3)] = 0;
      this_slave_flag_addr[(i*3) + 1] = 0;
      memset(slave_stm_data_ptr_start + (i << 11), 0, 2048);
      return 1;
    }
  }

  // printf("[slave runtime] %s start 4\n", __func__);

  return 0;
}

uintptr_t handle_test_corrupt_attestation_key(void) {
  if (YXS_trusted_memory_size == 0) {
    return 1;
  }

  kg[0] ^= 0x5a;
  kg[17] ^= 0xa5;
  kg[63] ^= 0xff;
  return 0;
}

uintptr_t handle_test_set_attestation_mutation(uint64_t mode) {
  g_test_attestation_mutation = mode;
  return 0;
}

// slave
// decrypt, size = 1, !0 . slave recv data ==> decrypt = 2
uintptr_t handle_wait_main_dispatch(void* dest, void* block_id, void* block_size, uint64_t slave_id, uint64_t flexible) {
  // printf("[slave runtime] %s start\n", __func__);
  uint64_t *YXSTM_start_ptr = (uint64_t *)YXS_trusted_memory;
  uint64_t YXSTM_size       = YXS_trusted_memory_size;
  int ret;

  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;
  if (number <= 0) {
    return 1;
  }

  size_t slave_stm_region = number / (flexible - 1);

  uint64_t *this_slave_flag_addr = YXSTM_start_ptr + (3 * slave_stm_region * (slave_id - 1));
  char *slave_stm_data_ptr_start = (char*)YXSTM_start_ptr + (sizeof(uint64_t) * 3 * slave_stm_region * (flexible - 1)) + ((slave_stm_region * (slave_id - 1)) << 18);

  size_t i = 0;
  while (1) {
    for (i = 0; i < slave_stm_region; i++) {
      // // if decrypt, size = 1, !0 : then recv data
      // if (this_slave_flag_addr[i*3] == 1 && this_slave_flag_addr[(i*3) + 1] != 0) {
      //   break;
      // }
      // if decrypt, size = 1, !0 : then recv data
      // done care size
      if (this_slave_flag_addr[i*3] == 1) {
        break;
      }
    }
    if (i < slave_stm_region) {
      break;
    }
  }

  ret = copy_to_user(dest, (void*)(slave_stm_data_ptr_start + (i << 18)), this_slave_flag_addr[(i*3)+1]);
  if (ret) {
    return ret;
  }

  ret = copy_to_user(block_size, (void*)(&this_slave_flag_addr[(i*3) + 1]), sizeof(uint64_t));
  if (ret) {
    return ret;
  }

  ret = copy_to_user(block_id, (void*)(&this_slave_flag_addr[(i*3) + 2]), sizeof(uint64_t));
  if (ret) {
    return ret;
  }

  /* copy_to_user clears SR_SUM on return; YXSTM has PTE_U, so re-enable for writes */
  csr_set(sstatus, SR_SUM);

  this_slave_flag_addr[(i*3)] = 2;

  if (this_slave_flag_addr[(i*3) + 1] == 0) {
    this_slave_flag_addr[(i*3)] = 0;
    this_slave_flag_addr[(i*3)+2] = 0;
  }

  // printf("[slave runtime] %s, block_id:%d, block_size:%d\n", __func__, this_slave_flag_addr[(i*3) + 2], this_slave_flag_addr[(i*3) + 1]);

  return 0;
}

// main
// decrypt, size = 0, 0 . main send data ==> decrypt, size, id = 1, size, id
uintptr_t handle_main_dispatch_send(void* src, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible) {
  // printf("[main runtime] %s start\n", __func__);
  uint64_t *YXSTM_start_ptr = (uint64_t *)YXS_trusted_memory;
  uint64_t YXSTM_size       = YXS_trusted_memory_size;

  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;
  if (number <= 0) {
    return 1;
  }

  size_t slave_stm_region = number / (flexible - 1);

  uint64_t *this_slave_flag_addr = YXSTM_start_ptr + (3 * slave_stm_region * (slave_id - 1));
  char *slave_stm_data_ptr_start = (char*)YXSTM_start_ptr + (sizeof(uint64_t) * 3 * slave_stm_region * (flexible - 1)) + ((slave_stm_region * (slave_id - 1)) << 18);

  size_t i = 0;
  while (1) {
    for (i = 0; i < slave_stm_region; i++) {
      // if decrypt, size = 0, 0: then send data
      if (this_slave_flag_addr[(i*3)] == 0 && this_slave_flag_addr[(i*3) + 1] == 0) {
        break;
      }
    }
    if (i < slave_stm_region) {
      break;
    }
  }

  int ret = copy_from_user((void*)(slave_stm_data_ptr_start + (i << 18)), src, block_size);
  if (ret) {
    return ret;
  }

  /* copy_from_user clears SR_SUM on return; YXSTM has PTE_U, so re-enable for writes */
  csr_set(sstatus, SR_SUM);

  // this_slave_flag_addr[(i*3)] = 1;
  // this_slave_flag_addr[(i*3) + 1] = block_size;
  // this_slave_flag_addr[(i*3) + 2] = block_id;

  // dont care size
  this_slave_flag_addr[(i*3) + 1] = block_size;
  this_slave_flag_addr[(i*3) + 2] = block_id;
  this_slave_flag_addr[(i*3)] = 1;

  // printf("[main runtime] %s, block_id:%d, block_size:%d\n", __func__, block_id, block_size);

  return 0;
}

// slave
// decrypt, size, id = 2, size, id . slave set data ==> decrypt = 3
// 修改：匹配时只检查 flag 和 block_id，不检查 block_size
// 这样 Slave 可以传入加密后的大小 (8MB + 28B)，而不是原始大小 (8MB)
uintptr_t handle_slave_set_block(void* src, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible) {
  // printf("[slave runtime] %s start\n", __func__);
  uint64_t *YXSTM_start_ptr = (uint64_t *)YXS_trusted_memory;
  uint64_t YXSTM_size       = YXS_trusted_memory_size;

  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;
  if (number <= 0) {
    return 1;
  }

  size_t slave_stm_region = number / (flexible - 1);

  uint64_t *this_slave_flag_addr = YXSTM_start_ptr + (3 * slave_stm_region * (slave_id - 1));
  char *slave_stm_data_ptr_start = (char*)YXSTM_start_ptr + (sizeof(uint64_t) * 3 * slave_stm_region * (flexible - 1)) + ((slave_stm_region * (slave_id - 1)) << 18);

  size_t i = 0;
  while (1) {
    for (i = 0; i < slave_stm_region; i++) {
      // 修改：只匹配 flag == 2 和 block_id，不匹配 block_size
      // 这样 Slave 可以写入加密后的数据（大小不同于原始大小）
      if (this_slave_flag_addr[(i*3)] == 2 && this_slave_flag_addr[(i*3) + 2] == block_id) {
        break;
      }
    }
    if (i < slave_stm_region) {
      break;
    }
  }

  int ret = copy_from_user((void*)(slave_stm_data_ptr_start + (i << 18)), src, block_size);
  if (ret) {
    return ret;
  }

  /* copy_from_user clears SR_SUM on return; YXSTM has PTE_U, so re-enable for writes */
  csr_set(sstatus, SR_SUM);

  // 更新 block_size 为实际写入的大小（加密后的大小）
  this_slave_flag_addr[(i*3) + 1] = block_size;
  this_slave_flag_addr[(i*3)] = 3;

  // printf("[slave runtime] %s end\n", __func__);

  return 0;
}

// main
// decrypt, size, id = 3, size, id . main get data ==> decrypt, size, id = 0, 0, 0
// 修改：匹配时只检查 flag 和 block_id，不检查 block_size
// 复制数据时使用存储的 block_size（由 slave_set_block 更新为加密后的大小）
uintptr_t handle_get_slave_block(void* dest, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible) {
  // printf("[main runtime] %s start\n", __func__);
  uint64_t *YXSTM_start_ptr = (uint64_t *)YXS_trusted_memory;
  uint64_t YXSTM_size       = YXS_trusted_memory_size;

  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;
  if (number <= 0) {
    return 1;
  }

  size_t slave_stm_region = number / (flexible - 1);

  uint64_t *this_slave_flag_addr = YXSTM_start_ptr + (3 * slave_stm_region * (slave_id - 1));
  char *slave_stm_data_ptr_start = (char*)YXSTM_start_ptr + (sizeof(uint64_t) * 3 * slave_stm_region * (flexible - 1)) + ((slave_stm_region * (slave_id - 1)) << 18);

  size_t i = 0;
  while (1) {
    for (i = 0; i < slave_stm_region; i++) {
      // 修改：只匹配 flag == 3 和 block_id，不匹配 block_size
      if (this_slave_flag_addr[(i*3)] == 3 && this_slave_flag_addr[(i*3) + 2] == block_id) {
        break;
      }
    }
    if (i < slave_stm_region) {
      break;
    }
  }

  // 使用存储的 block_size（由 slave_set_block 更新为加密后的大小）
  uint64_t actual_size = this_slave_flag_addr[(i*3) + 1];
  int ret = copy_to_user(dest, (void*)(slave_stm_data_ptr_start + (i << 18)), actual_size);
  if (ret) {
    return ret;
  }

  /* copy_to_user clears SR_SUM on return; YXSTM has PTE_U, so re-enable for writes */
  csr_set(sstatus, SR_SUM);

  this_slave_flag_addr[(i*3)] = 0;
  this_slave_flag_addr[(i*3)+1] = 0;
  this_slave_flag_addr[(i*3)+2] = 0;

  // printf("[main runtime] %s end\n", __func__);

  return 0;
}

//==============================================================================
// 扩展 YXSTM API：支持 8MB 单块传输模式
//
// 新增 actual_size 字段用于存储加密后的实际数据大小
// 元数据布局变更：
//   原: [flag(8B)][block_size(8B)][block_id(8B)] × N slots
//   新: [flag(8B)][block_size(8B)][block_id(8B)][actual_size(8B)] × N slots
//
// 注意：为了向后兼容，扩展 API 使用独立的元数据区域
// 扩展元数据位于 YXSTM 的末尾部分
//==============================================================================

// 扩展元数据结构（每个 slot 32 字节）
typedef struct {
    volatile uint64_t flag;         // 状态标志: 0=空闲, 1=待处理, 2=处理中, 3=已完成
    uint64_t block_size;            // 原始明文大小
    uint64_t block_id;              // 数据块 ID
    uint64_t actual_size;           // 实际数据大小（加密后）
} YXSTMSlotMetaExt;

// 参数结构体（从用户空间传入）
typedef struct {
    uint64_t actual_size;
    uint64_t slave_id;
    uint64_t flexible;
} SlaveSetBlockExtParams;

typedef struct {
    uint64_t* actual_size_ptr;
    uint64_t slave_id;
    uint64_t flexible;
} GetSlaveBlockExtParams;

// slave
// 扩展版本：支持 actual_size 参数
// decrypt, size, id = 2, size, id . slave set data ==> decrypt = 3
uintptr_t handle_slave_set_block_ext(void* src, uint64_t block_id, uint64_t block_size, void* params_ptr) {
  // printf("[slave runtime] %s start\n", __func__);

  // 从用户空间读取参数结构体
  SlaveSetBlockExtParams params;
  int ret = copy_from_user(&params, params_ptr, sizeof(SlaveSetBlockExtParams));
  if (ret) {
    return ret;
  }

  uint64_t actual_size = params.actual_size;
  uint64_t slave_id = params.slave_id;
  uint64_t flexible = params.flexible;

  uint64_t *YXSTM_start_ptr = (uint64_t *)YXS_trusted_memory;
  uint64_t YXSTM_size       = YXS_trusted_memory_size;

  // 使用 4 个 uint64_t 作为元数据（32 字节）
  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;
  if (number <= 0) {
    return 1;
  }

  size_t slave_stm_region = number / (flexible - 1);

  // 扩展元数据：每个 slot 使用 4 个 uint64_t
  uint64_t *this_slave_flag_addr = YXSTM_start_ptr + (4 * slave_stm_region * (slave_id - 1));
  char *slave_stm_data_ptr_start = (char*)YXSTM_start_ptr + (sizeof(uint64_t) * 4 * slave_stm_region * (flexible - 1)) + ((slave_stm_region * (slave_id - 1)) << 18);

  size_t i = 0;
  while (1) {
    for (i = 0; i < slave_stm_region; i++) {
      // 匹配条件：flag=2, block_size 匹配, block_id 匹配
      if (this_slave_flag_addr[(i*4)] == 2 &&
          this_slave_flag_addr[(i*4) + 1] == block_size &&
          this_slave_flag_addr[(i*4) + 2] == block_id) {
        break;
      }
    }
    if (i < slave_stm_region) {
      break;
    }
  }

  // 复制 actual_size 字节数据（而非 block_size）
  ret = copy_from_user((void*)(slave_stm_data_ptr_start + (i << 18)), src, actual_size);
  if (ret) {
    return ret;
  }

  /* copy_from_user clears SR_SUM on return; YXSTM has PTE_U, so re-enable for writes */
  csr_set(sstatus, SR_SUM);

  // 设置 actual_size 并更新 flag
  this_slave_flag_addr[(i*4) + 3] = actual_size;
  this_slave_flag_addr[(i*4)] = 3;

  // printf("[slave runtime] %s end, actual_size=%lu\n", __func__, actual_size);

  return 0;
}

// main
// 扩展版本：返回 actual_size
// decrypt, size, id = 3, size, id . main get data ==> decrypt, size, id = 0, 0, 0
uintptr_t handle_get_slave_block_ext(void* dest, uint64_t block_id, void* params_ptr) {
  // printf("[main runtime] %s start\n", __func__);

  // 从用户空间读取参数结构体
  GetSlaveBlockExtParams params;
  int ret = copy_from_user(&params, params_ptr, sizeof(GetSlaveBlockExtParams));
  if (ret) {
    return ret;
  }

  uint64_t slave_id = params.slave_id;
  uint64_t flexible = params.flexible;

  uint64_t *YXSTM_start_ptr = (uint64_t *)YXS_trusted_memory;
  uint64_t YXSTM_size       = YXS_trusted_memory_size;

  int number = ((YXSTM_size + 0x3ffff) >> 18) - 1;
  if (number <= 0) {
    return 1;
  }

  size_t slave_stm_region = number / (flexible - 1);

  // 扩展元数据：每个 slot 使用 4 个 uint64_t
  uint64_t *this_slave_flag_addr = YXSTM_start_ptr + (4 * slave_stm_region * (slave_id - 1));
  char *slave_stm_data_ptr_start = (char*)YXSTM_start_ptr + (sizeof(uint64_t) * 4 * slave_stm_region * (flexible - 1)) + ((slave_stm_region * (slave_id - 1)) << 18);

  size_t i = 0;
  while (1) {
    for (i = 0; i < slave_stm_region; i++) {
      // 匹配条件：flag=3, block_id 匹配
      if (this_slave_flag_addr[(i*4)] == 3 &&
          this_slave_flag_addr[(i*4) + 2] == block_id) {
        break;
      }
    }
    if (i < slave_stm_region) {
      break;
    }
  }

  // 获取 actual_size
  uint64_t actual_size = this_slave_flag_addr[(i*4) + 3];

  // 复制 actual_size 字节数据
  ret = copy_to_user(dest, (void*)(slave_stm_data_ptr_start + (i << 18)), actual_size);
  if (ret) {
    return ret;
  }

  // 将 actual_size 返回给用户空间
  ret = copy_to_user(params.actual_size_ptr, &actual_size, sizeof(uint64_t));
  if (ret) {
    return ret;
  }

  /* copy_to_user clears SR_SUM on return; YXSTM has PTE_U, so re-enable for writes */
  csr_set(sstatus, SR_SUM);

  // 重置 slot
  this_slave_flag_addr[(i*4)] = 0;
  this_slave_flag_addr[(i*4)+1] = 0;
  this_slave_flag_addr[(i*4)+2] = 0;
  this_slave_flag_addr[(i*4)+3] = 0;

  // printf("[main runtime] %s end, actual_size=%lu\n", __func__, actual_size);

  return 0;
}

void init_edge_internals(){
  /*
   * CRITICAL FIX: Use ocall_buffer for edge_call communication
   * ==========================================================
   *
   * In shared UTM mode, the Slave Enclave has two separate buffers:
   * 1. ocall_buffer (EYRIE_UNTRUSTED_START) - Enclave's own 1MB UTM for OCALL
   * 2. shared_buffer (EYRIE_SHARED_UTM_START) - Main's 64MB UTM for data transfer
   *
   * The edge_call structures (OCALL_GET_REQUEST, OCALL_SEND_RESPONSE, etc.)
   * are always written to/read from the enclave's own UTM (ocall_buffer).
   *
   * The Host side maps the enclave's own UTM separately using mapOwnUtm()
   * and uses it for OCALL communication.
   *
   * copy_from_shared() and copy_to_shared() use shared_buffer for data transfer.
   *
   * In regular mode, ocall_buffer == shared_buffer, so this change is backward compatible.
   */
  edge_call_init_internals(ocall_buffer, ocall_buffer_size);
}

void handle_syscall(struct encl_ctx* ctx)
{
  uintptr_t n = ctx->regs.a7;
  uintptr_t arg0 = ctx->regs.a0;
  uintptr_t arg1 = ctx->regs.a1;
  uintptr_t arg2 = ctx->regs.a2;
  uintptr_t arg3 = ctx->regs.a3;
  uintptr_t arg4 = ctx->regs.a4;

  // We only use arg5 in these for now, keep warnings happy.
#if defined(USE_LINUX_SYSCALL) || defined(USE_NET_SYSCALL)
  uintptr_t arg5 = ctx->regs.a5;
#endif /* IO_SYSCALL */
  uintptr_t ret = 0;

  ctx->regs.sepc += 4;

  switch (n) {
  case(RUNTIME_SYSCALL_EXIT):
    sbi_exit_enclave(arg0);
    break;
  case(RUNTIME_SYSCALL_OCALL):
    ret = dispatch_edgecall_ocall(arg0, (void*)arg1, arg2, (void*)arg3, arg4);
    break;
  case(RUNTIME_SYSCALL_SHAREDCOPY):
    ret = handle_copy_from_shared((void*)arg0, arg1, arg2);
    break;
  case(RUNTIME_SYSCALL_SHAREDCOPY_UTM):
    // 从共享 UTM 读取数据（用于 Slave Enclave 访问 Main 的共享 UTM）
    ret = handle_copy_from_shared_utm((void*)arg0, arg1, arg2);
    break;
  case(RUNTIME_SYSCALL_SHAREDWRITE_UTM):
    // 写入数据到共享 UTM（消除 128 次 OCALL 开销）
    ret = handle_copy_to_shared_utm(arg0, (void*)arg1, arg2);
    break;
  case(RUNTIME_SYSCALL_UTM_QUERY_DIRECT):
    ret = handle_utm_query_direct((void*)arg0, arg1);
    break;
  case(RUNTIME_SYSCALL_SEC_ACQUIRE):
    ret = sbi_sec_acquire(arg0, arg1);
    break;
  case(RUNTIME_SYSCALL_SEC_RELEASE):
    ret = sbi_sec_release();
    break;
  case(RUNTIME_SYSCALL_SEC_QUERY):
    if (arg1 > sizeof(rt_copy_buffer_1)) {
      ret = -1;
      break;
    }
    memset(rt_copy_buffer_1, 0, arg1);
    ret = sbi_sec_query(translate((uintptr_t)rt_copy_buffer_1), arg1);
    if (!ret && arg0 && arg1) {
      copy_to_user((void*)arg0, (void*)rt_copy_buffer_1, arg1);
    }
    break;
  case(RUNTIME_SYSCALL_GROUP_PRIVATE_REGION_INFO):
    ret = handle_group_private_region_info((void*)arg0, arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_QUERY_LAYOUT):
    if (!arg0 || arg1 != sizeof(struct keystone_yxstm_layout_info) ||
        arg1 > sizeof(rt_copy_buffer_1)) {
      ret = -1;
      break;
    }
    memset(rt_copy_buffer_1, 0, arg1);
    ret = sbi_yxstm_query_layout(translate((uintptr_t)rt_copy_buffer_1), arg1);
    if (!ret) {
      copy_to_user((void*)arg0, (void*)rt_copy_buffer_1, arg1);
    }
    break;
  case(RUNTIME_SYSCALL_YXSTM_QUERY_SLOT):
    if (!arg0 || arg1 != sizeof(struct keystone_yxstm_slot_info) ||
        arg1 > sizeof(rt_copy_buffer_1) ||
        copy_from_user((void*)rt_copy_buffer_1, (void*)arg0, arg1)) {
      ret = -1;
      break;
    }
    KEYSTONE_ABI_INIT(
        (struct keystone_yxstm_slot_info*)rt_copy_buffer_1,
        KEYSTONE_YXSTM_ABI_FEATURES);
    ret = sbi_yxstm_query_slot(translate((uintptr_t)rt_copy_buffer_1), arg1);
    if (!ret)
      copy_to_user((void*)arg0, (void*)rt_copy_buffer_1, arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_SLOT_COMMAND): {
    struct keystone_yxstm_slot_command* command;
    /* Keep a deploy-time marker in eyrie-rt for stale runtime detection. */
    (void)yxstm_slot_wait_runtime_marker[0];

    if (!arg0 || arg1 != sizeof(struct keystone_yxstm_slot_command) ||
        arg1 > sizeof(rt_copy_buffer_1) ||
        copy_from_user(rt_copy_buffer_1, (void*)arg0, arg1)) {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      break;
    }
    command = (struct keystone_yxstm_slot_command*)rt_copy_buffer_1;
    KEYSTONE_ABI_INIT(command, KEYSTONE_YXSTM_ABI_FEATURES);
    for (;;) {
      ret = sbi_yxstm_slot_command(translate((uintptr_t)command), arg1);
      if (ret ||
          (command->operation != KEYSTONE_YXSTM_SLOT_WORKER_WAIT_READY &&
           command->operation !=
               KEYSTONE_YXSTM_SLOT_WORKER_WAIT_ACQUIRE_BEGIN) ||
          command->result != KEYSTONE_YXSTM_SLOT_RESULT_BLOCK)
        break;

      /*
       * Both wait operations must remain inside the runtime. A wake only
       * makes the saved member context runnable, so revalidate the slot after
       * resumption and never expose BLOCK to the eapp.
       */
      ret = sbi_stop_enclave(STOP_LANE_WAIT_ENCLAVE);
      /* STOP_LANE_WAIT resumes with zero; reissue to consume READY metadata. */
      if (ret == SBI_ERR_SM_ENCLAVE_INTERRUPTED)
        ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
      if (ret)
        break;
    }
    if (!ret && copy_to_user((void*)arg0, command, arg1))
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    break;
  }
  case(RUNTIME_SYSCALL_YXSTM_ACQUIRE_SLICE):
    ret = sbi_yxstm_acquire_slice(arg0, arg1, arg2, arg3);
    break;
  case(RUNTIME_SYSCALL_YXSTM_RELEASE_SLICE):
    ret = sbi_yxstm_release_slice(arg0, arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_ACQUIRE_MASK):
    ret = sbi_yxstm_acquire_mask(arg0, arg1, arg2, arg3);
    break;
  case(RUNTIME_SYSCALL_YXSTM_RELEASE_MASK):
    ret = sbi_yxstm_release_mask(arg0, arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_QUERY_PROTOCOL):
    if (!arg0 || arg1 != sizeof(struct keystone_yxstm_protocol_state) ||
        arg1 > sizeof(rt_copy_buffer_1)) {
      ret = -1;
      break;
    }
    memset(rt_copy_buffer_1, 0, arg1);
    ret = sbi_yxstm_query_protocol(translate((uintptr_t)rt_copy_buffer_1), arg1);
    if (!ret)
      copy_to_user((void*)arg0, (void*)rt_copy_buffer_1, arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_PHASE_TRANSITION):
    if (!arg0 || arg1 != sizeof(struct keystone_yxstm_phase_transition) ||
        arg1 > sizeof(rt_copy_buffer_1) ||
        copy_from_user((void*)rt_copy_buffer_1, (void*)arg0, arg1)) {
      ret = -1;
      break;
    }
    KEYSTONE_ABI_INIT((struct keystone_yxstm_phase_transition*)rt_copy_buffer_1,
                      KEYSTONE_YXSTM_ABI_FEATURES);
    ret = sbi_yxstm_phase_transition(
        translate((uintptr_t)rt_copy_buffer_1), arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_PHASE_ACK):
    ret = sbi_yxstm_phase_ack(arg0, arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_REGISTER_MAILBOX):
    if (!arg0 ||
        arg1 != sizeof(struct keystone_yxstm_mailbox_registration) ||
        arg1 > sizeof(rt_copy_buffer_1) ||
        copy_from_user((void*)rt_copy_buffer_1, (void*)arg0, arg1)) {
      ret = -1;
      break;
    }
    KEYSTONE_ABI_INIT(
        (struct keystone_yxstm_mailbox_registration*)rt_copy_buffer_1,
        KEYSTONE_YXSTM_ABI_FEATURES);
    ((struct keystone_yxstm_mailbox_registration*)rt_copy_buffer_1)->reserved = 0;
    ret = sbi_yxstm_register_mailbox(
        translate((uintptr_t)rt_copy_buffer_1), arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_TASK_BANK_TRANSITION):
    if (!arg0 ||
        arg1 != sizeof(struct keystone_yxstm_task_bank_transition) ||
        arg1 > sizeof(rt_copy_buffer_1) ||
        copy_from_user((void*)rt_copy_buffer_1, (void*)arg0, arg1)) {
      ret = -1;
      break;
    }
    KEYSTONE_ABI_INIT(
        (struct keystone_yxstm_task_bank_transition*)rt_copy_buffer_1,
        KEYSTONE_YXSTM_ABI_FEATURES);
    ret = sbi_yxstm_task_bank_transition(
        translate((uintptr_t)rt_copy_buffer_1), arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_TASK_BANK_ACQUIRE):
  case(RUNTIME_SYSCALL_YXSTM_TASK_BANK_RELEASE):
    if (!arg0 || arg1 != sizeof(struct keystone_yxstm_task_bank_grant) ||
        arg1 > sizeof(rt_copy_buffer_1) ||
        copy_from_user((void*)rt_copy_buffer_1, (void*)arg0, arg1)) {
      ret = -1;
      break;
    }
    KEYSTONE_ABI_INIT(
        (struct keystone_yxstm_task_bank_grant*)rt_copy_buffer_1,
        KEYSTONE_YXSTM_ABI_FEATURES);
    if (n == RUNTIME_SYSCALL_YXSTM_TASK_BANK_ACQUIRE)
      ret = sbi_yxstm_task_bank_acquire(
          translate((uintptr_t)rt_copy_buffer_1), arg1);
    else
      ret = sbi_yxstm_task_bank_release(
          translate((uintptr_t)rt_copy_buffer_1), arg1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_TASK_BANK_ACK):
    if (!arg0 || arg1 != sizeof(struct keystone_yxstm_task_bank_ack) ||
        arg1 > sizeof(rt_copy_buffer_1) ||
        copy_from_user((void*)rt_copy_buffer_1, (void*)arg0, arg1)) {
      ret = -1;
      break;
    }
    KEYSTONE_ABI_INIT(
        (struct keystone_yxstm_task_bank_ack*)rt_copy_buffer_1,
        KEYSTONE_YXSTM_ABI_FEATURES);
    ret = sbi_yxstm_task_bank_ack(
        translate((uintptr_t)rt_copy_buffer_1), arg1);
    break;
  case(RUNTIME_SYSCALL_GROUP_LANE_TURN): {
    struct keystone_group_lane_turn* request;

    if (!arg0 || arg1 != sizeof(struct keystone_group_lane_turn) ||
        copy_from_user(rt_copy_buffer_1, (void*)arg0, arg1)) {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      break;
    }
    request = (struct keystone_group_lane_turn*)rt_copy_buffer_1;
    KEYSTONE_ABI_INIT(request, KEYSTONE_YXSTM_ABI_FEATURES);
    ret = sbi_group_lane_turn(translate((uintptr_t)request), arg1);
    if (!ret && copy_to_user((void*)arg0, request, arg1)) {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      break;
    }
    if (!ret &&
        (request->operation == KEYSTONE_GROUP_LANE_TURN_WAIT ||
         request->operation == KEYSTONE_GROUP_LANE_TURN_WAIT_BANK) &&
        request->result == KEYSTONE_GROUP_LANE_TURN_BLOCK)
      ret = sbi_stop_enclave(STOP_LANE_WAIT_ENCLAVE);
    break;
  }
  case(RUNTIME_SYSCALL_YIELD):
    ret = sbi_stop_enclave(STOP_YIELD_ENCLAVE);
    break;
  case(RUNTIME_SYSCALL_CREATE_GROUP):
    copy_from_user((void*)rt_copy_identity, (void*)arg0, arg1);
    ret = sbi_m_enclave_create_group((void*)rt_copy_identity, arg1);
    break;
  case(RUNTIME_SYSCALL_JOIN_GROUP):
    copy_from_user((void*)rt_copy_identity, (void*)arg0, arg1);
    ret = sbi_s_enclave_join_group((void*)rt_copy_identity, arg1);
    //处理返回结果待写
    break;
  case(RUNTIME_SYSCALL_MAIN_ENCLAVE_GET_SLAVE_ENCLAVE_DATA):;
    copy_from_user((void*)rt_copy_slave_data, (void*)arg0, 16);
    ret = sbi_main_enclave_get_slave_enclave_data_yx((void*)rt_copy_slave_data, (void*)(rt_copy_slave_data+17));
    copy_to_user((void*)arg0, (void*)rt_copy_slave_data, 256*1024+8+8+1);
    break;
  case(RUNTIME_SYSCALL_SLAVE_ENCLAVE_SET_DATAPTR):;
    copy_from_user((void*)rt_copy_slave_data, (void*)arg0, 256*1024+8+8+1);
    ret = sbi_slave_enclave_set_dataptr_yx((void*)rt_copy_slave_data, (void*)(rt_copy_slave_data+17));
    copy_to_user((void*)arg0, (void*)rt_copy_slave_data, 8+8+1);
    break;
  case(RUNTIME_SYSCALL_YXSTM_SET_NUMBERBLOCK):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_set_numberBlock_to_YXSTM((void*)arg0, arg1, arg2);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_YXSTM_GET_NUMBERBLOCK):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_get_numberBlock_from_YXSTM((void*)arg0, arg1, arg2);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_STM_ACCESS_TEST):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_STM_TEST_OTHER_ENCLAVE_ACCESS();
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_TEST_OTHER_ENCLAVE_ACCESS_EPM_O):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_TEST_OTHER_ENCLAVE_ACCESS_EPM_O((void*)arg0);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_TEST_OTHER_ENCLAVE_ACCESS_EPM_S):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_TEST_OTHER_ENCLAVE_ACCESS_EPM_S((void*)arg0);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_M_ATTEST_S_ENCLAVE):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_m_attestt_s_enclave(arg0, arg1);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_S_ENCLAVE_ATTESTTED):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_s_enclave_attestted(arg0, arg1);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_TEST_CORRUPT_ATTESTATION_KEY):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_test_corrupt_attestation_key();
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_TEST_SET_ATTESTATION_MUTATION):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_test_set_attestation_mutation(arg0);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_WAIT_MAIN_DISPATCH):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_wait_main_dispatch((void*)arg0, (void*)arg1, (void*)arg2, arg3, arg4);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_MAIN_DISPATCH_SEND):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_main_dispatch_send((void*)arg0, arg1, arg2, arg3, arg4);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_SLAVE_SET_BLOCK):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_slave_set_block((void*)arg0, arg1, arg2, arg3, arg4);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_GET_SLAVE_BLOCK):;
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_get_slave_block((void*)arg0, arg1, arg2, arg3, arg4);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_SLAVE_SET_BLOCK_EXT):;
    // 扩展 API：arg0=src, arg1=block_id, arg2=block_size, arg3=params_ptr
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_slave_set_block_ext((void*)arg0, arg1, arg2, (void*)arg3);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_GET_SLAVE_BLOCK_EXT):;
    // 扩展 API：arg0=dest, arg1=block_id, arg2=params_ptr
    ret = yxstm_runtime_acquire_rw();
    if (ret) {
      break;
    }
    ret = handle_get_slave_block_ext((void*)arg0, arg1, (void*)arg2);
    ret = yxstm_runtime_release_after(ret);
    break;
  case(RUNTIME_SYSCALL_ATTEST_ENCLAVE):;
    copy_from_user((void*)rt_copy_buffer_2, (void*)arg1, arg2);

    ret = sbi_attest_enclave(rt_copy_buffer_1, rt_copy_buffer_2, arg2);

    /* TODO we consistently don't have report size when we need it */
    copy_to_user((void*)arg0, (void*)rt_copy_buffer_1, 2048);
    //print_strace("[ATTEST] p1 0x%p->0x%p p2 0x%p->0x%p sz %lx = %lu\r\n",arg0,arg0_trans,arg1,arg1_trans,arg2,ret);
    break;
  case(RUNTIME_SYSCALL_GET_SEALING_KEY):;
    /* Stores the key receive structure */
    uintptr_t buffer_1_pa = translate((uintptr_t) rt_copy_buffer_1);

    /* Stores the key identifier */
    uintptr_t buffer_2_pa = translate((uintptr_t) rt_copy_buffer_2);

    if (arg1 > sizeof(rt_copy_buffer_1) ||
        arg3 > sizeof(rt_copy_buffer_2)) {
      ret = -1;
      break;
    }

    copy_from_user(rt_copy_buffer_2, (void *)arg2, arg3);

    ret = sbi_get_sealing_key(buffer_1_pa, buffer_2_pa, arg3);

    if (!ret) {
      copy_to_user((void *)arg0, (void *)rt_copy_buffer_1, arg1);
    }

    /* Delete key from copy buffer */
    memset(rt_copy_buffer_1, 0x00, sizeof(rt_copy_buffer_1));

    break;


#ifdef USE_LINUX_SYSCALL
  case(SYS_clock_gettime):
    ret = linux_clock_gettime((__clockid_t)arg0, (struct timespec*)arg1);
    break;

  case(SYS_getrandom):
    ret = linux_getrandom((void*)arg0, (size_t)arg1, (unsigned int)arg2);
    break;

  case(SYS_rt_sigprocmask):
    ret = linux_rt_sigprocmask((int)arg0, (const sigset_t*)arg1, (sigset_t*)arg2);
    break;

  case(SYS_getpid):
    ret = linux_getpid();
    break;

  case(SYS_uname):
    ret = linux_uname((void*) arg0);
    break;

  case(SYS_rt_sigaction):
    ret = linux_RET_ZERO_wrap(n);
    break;

  case(SYS_set_tid_address):
    ret = linux_set_tid_address((int*) arg0);
    break;

  case(SYS_brk):
    ret = syscall_brk((void*) arg0);
    break;

  case(SYS_mmap):
    ret = syscall_mmap((void*) arg0, (size_t)arg1, (int)arg2,
                       (int)arg3, (int)arg4, (__off_t)arg5);
    break;

  case(SYS_munmap):
    ret = syscall_munmap((void*) arg0, (size_t)arg1);
    break;

  case(SYS_mprotect):
    ret = syscall_mprotect((void *) arg0, (size_t) arg1, (int) arg2);
    break;

  case(SYS_exit):
  case(SYS_exit_group):
    print_strace("[runtime] exit or exit_group (%lu)\r\n",n);
    sbi_exit_enclave(arg0);
    break;
#endif /* USE_LINUX_SYSCALL */

#ifdef USE_IO_SYSCALL
  case(SYS_read):
    ret = io_syscall_read((int)arg0, (void*)arg1, (size_t)arg2);
    break;
  case(SYS_write):
    ret = io_syscall_write((int)arg0, (void*)arg1, (size_t)arg2);
    break;
  case(SYS_writev):
    ret = io_syscall_writev((int)arg0, (const struct iovec*)arg1, (int)arg2);
    break;
  case(SYS_readv):
    ret = io_syscall_readv((int)arg0, (const struct iovec*)arg1, (int)arg2);
    break;
  case(SYS_openat):
    ret = io_syscall_openat((int)arg0, (char*)arg1, (int)arg2, (mode_t)arg3);
    break;
  case(SYS_unlinkat):
    ret = io_syscall_unlinkat((int)arg0, (char*)arg1, (int)arg2);
    break;
  case(SYS_fstatat):
    ret = io_syscall_fstatat((int)arg0, (char*)arg1, (struct stat*)arg2, (int)arg3);
    break;
  case(SYS_fstat):
    ret = io_syscall_fstat((int)arg0, (struct stat*)arg1);
    break;
  case(SYS_lseek):
    ret = io_syscall_lseek((int)arg0, (off_t)arg1, (int)arg2);
    break;
  case(SYS_ftruncate):
    ret = io_syscall_ftruncate((int)arg0, (off_t)arg1);
    break;
  case(SYS_sync):
    ret = io_syscall_sync();
    break;
  case(SYS_fsync):
    ret = io_syscall_fsync((int)arg0);
    break;
  case(SYS_close):
    ret = io_syscall_close((int)arg0);
    break;
  case(SYS_epoll_create1):
    ret = io_syscall_epoll_create((int) arg0);
    break;
  case(SYS_epoll_ctl):
    ret = io_syscall_epoll_ctl((int) arg0, (int) arg1, (int) arg2, (uintptr_t) arg3);
    break;
  case(SYS_epoll_pwait):
    ret = io_syscall_epoll_pwait((int) arg0, (uintptr_t) arg1, (int) arg2, (int) arg3);
    break;
  case(SYS_fcntl):
    ret = io_syscall_fcntl((int)arg0, (int)arg1, (uintptr_t)arg2);
    break;
  case(SYS_chdir):
    ret = io_syscall_chdir((char *) arg0);
    break;
  case(SYS_renameat2):
    ret = io_syscall_renameat2((int) arg0, (uintptr_t) arg1,  (int) arg2, (uintptr_t) arg3, (int) arg4);
    break;
  case(SYS_umask):
    ret = io_syscall_umask((int) arg0);
    break;
  case(SYS_getcwd):
    ret = io_syscall_getcwd((char *)arg0, (size_t)arg1);
    break;
  case(SYS_pipe2):
    ret = io_syscall_pipe((int*)arg0);
    break;

#endif /* USE_IO_SYSCALL */

#ifdef USE_NET_SYSCALL
  case(SYS_socket):
    ret = io_syscall_socket((int) arg0, (int) arg1, (int) arg2);
    break;
  case(SYS_setsockopt):
    ret = io_syscall_setsockopt((int) arg0, (int) arg1, (int) arg2, (int *) arg3, (int) arg4);
    break;
  case(SYS_connect):
    ret = io_syscall_connect((int) arg0, (uintptr_t) arg1, (int) arg2);
    break;
  case (SYS_bind):
    ret = io_syscall_bind((int) arg0, (uintptr_t) arg1, (int) arg2);
    break;
  case (SYS_listen):
    ret = io_syscall_listen((int) arg0, (uintptr_t) arg1);
    break;
  case (SYS_accept):
    ret = io_syscall_accept((int) arg0, (uintptr_t) arg1, (uintptr_t) arg2);
    break;
  case(SYS_recvfrom):
    ret = io_syscall_recvfrom((int) arg0, (uintptr_t) arg1, (int) arg2, (int) arg3, (uintptr_t) arg4, (uintptr_t) arg5);
    break;
  case(SYS_sendto):
    ret = io_syscall_sendto((int) arg0, (uintptr_t) arg1, (int) arg2, (int) arg3, (uintptr_t) arg4, (int) arg5);
    break;
  case(SYS_sendfile):
    ret = io_syscall_sendfile((int) arg0, (int) arg1, (uintptr_t) arg2, (int) arg3);
    break;
  case(SYS_getpeername):
    ret = io_syscall_getpeername((int) arg0,  (uintptr_t) arg1, (uintptr_t) arg2);
    break;
  case(SYS_getsockname):
    ret = io_syscall_getsockname((int) arg0,  (uintptr_t) arg1, (uintptr_t) arg2);
    break;
  case(SYS_getuid):
    ret = io_syscall_getuid();
    break;
  case(SYS_pselect6):
    ret = io_syscall_pselect((int) arg0, (uintptr_t) arg1, (uintptr_t) arg2, (uintptr_t) arg3, (uintptr_t) arg4, (uintptr_t) arg5);
    break;
#endif /* USE_NET_SYSCALL */


  case(RUNTIME_SYSCALL_UNKNOWN):
  default:
    print_strace("[runtime] syscall %ld not implemented\r\n", (unsigned long) n);
    ret = -1;
    break;
  }

  /* store the result in the stack */
  ctx->regs.a0 = ret;
  return;
}
