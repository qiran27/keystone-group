//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#include <stddef.h>
#include <stdint.h>
#include "sealing.h"

#include "shared/eyrie_call.h"
#include "shared/sm_call.h"

#define SYSCALL(which, arg0, arg1, arg2, arg3, arg4)           \
  ({                                                           \
    register uintptr_t a0 asm("a0") = (uintptr_t)(arg0);       \
    register uintptr_t a1 asm("a1") = (uintptr_t)(arg1);       \
    register uintptr_t a2 asm("a2") = (uintptr_t)(arg2);       \
    register uintptr_t a3 asm("a3") = (uintptr_t)(arg3);       \
    register uintptr_t a4 asm("a4") = (uintptr_t)(arg4);       \
    register uintptr_t a7 asm("a7") = (uintptr_t)(which);      \
    asm volatile("ecall"                                       \
                 : "+r"(a0)                                    \
                 : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7) \
                 : "memory");                                  \
    a0;                                                        \
  })

#define SYSCALL_0(which) SYSCALL(which, 0, 0, 0, 0, 0)
#define SYSCALL_1(which, arg0) SYSCALL(which, arg0, 0, 0, 0, 0)
#define SYSCALL_2(which, arg0, arg1) SYSCALL(which, arg0, arg1, 0, 0, 0)
#define SYSCALL_3(which, arg0, arg1, arg2) \
  SYSCALL(which, arg0, arg1, arg2, 0, 0)
#define SYSCALL_4(which, arg0, arg1, arg2, arg3) \
  SYSCALL(which, arg0, arg1, arg2, arg3, 0)
#define SYSCALL_5(which, arg0, arg1, arg2, arg3, arg4) \
  SYSCALL(which, arg0, arg1, arg2, arg3, arg4)

int
copy_from_shared(void* dst, uintptr_t offset, size_t data_len);

// 从共享 UTM 读取数据（用于 Slave Enclave 访问 Main 的共享 UTM）
// 与 copy_from_shared 不同，这个函数使用 shared_buffer 而不是 ocall_buffer
// 在共享 UTM 模式下：
//   - copy_from_shared() 使用 ocall_buffer（Enclave 自己的 1MB UTM）
//   - copy_from_shared_utm() 使用 shared_buffer（Main 的 64MB 共享 UTM）
// 在普通模式下，两者等价
int
copy_from_shared_utm(void* dst, uintptr_t offset, size_t data_len);

// 写入数据到共享 UTM（用于 Enclave 直接写入共享 UTM，消除 128 次 OCALL 开销）
// 与 copy_from_shared_utm 对应，实现一次性写入大块数据
// 在共享 UTM 模式下：
//   - 传统方式：使用 OCALL_WRITE_DATA_CHUNK 分块写入（8MB 需要 128 次 OCALL）
//   - 优化方式：使用 copy_to_shared_utm() 一次性写入（1 次 syscall）
// 性能提升：消除 OCALL 上下文切换开销，预计提升 10-50x
int
copy_to_shared_utm(uintptr_t offset, const void* src, size_t data_len);

/* Return the U-mode RW/NX alias of this enclave's own UTM data area. The
 * runtime-owned control page is deliberately excluded from this mapping. */
static inline int
utm_query_direct(struct keystone_utm_direct_info* info, size_t info_len) {
  return (int)SYSCALL_2(RUNTIME_SYSCALL_UTM_QUERY_DIRECT, info, info_len);
}

int
sec_acquire(uint64_t engine_id, uint64_t timeout_cycles);

int
sec_release(void);

int
sec_query(void* info, size_t info_len);

int
group_private_region_info(
    struct group_private_region_info* info, size_t info_len);

int
yxstm_query_layout(struct keystone_yxstm_layout_info* info, size_t info_len);

int
yxstm_query_slot(struct keystone_yxstm_slot_info* info, size_t info_len);

int
yxstm_slot_command(struct keystone_yxstm_slot_command* command,
                   size_t command_len);

int
yxstm_acquire_slice(uint64_t slice_id, uint64_t flags, uint64_t phase,
                    uint64_t expected_epoch);

int
yxstm_release_slice(uint64_t slice_id, uint64_t expected_epoch);

int
yxstm_acquire_mask(uint64_t slice_mask, uint64_t flags, uint64_t phase,
                   uint64_t expected_epoch);

int
yxstm_release_mask(uint64_t slice_mask, uint64_t expected_epoch);

int
yxstm_query_protocol(struct keystone_yxstm_protocol_state* state,
                     size_t state_len);

int
yxstm_phase_transition(const struct keystone_yxstm_phase_transition* request,
                       size_t request_len);

int
yxstm_phase_ack(uint64_t expected_epoch, uint64_t event);

int
yxstm_register_mailbox(
    const struct keystone_yxstm_mailbox_registration* registration,
    size_t registration_len);

int
yxstm_task_bank_transition(
    const struct keystone_yxstm_task_bank_transition* request,
    size_t request_len);

int
yxstm_task_bank_acquire(const struct keystone_yxstm_task_bank_grant* request,
                        size_t request_len);

int
yxstm_task_bank_release(const struct keystone_yxstm_task_bank_grant* request,
                        size_t request_len);

int
yxstm_task_bank_ack(const struct keystone_yxstm_task_bank_ack* request,
                    size_t request_len);

int
group_lane_turn(struct keystone_group_lane_turn* request,
                size_t request_len);

int
enclave_yield(void);

int
ocall(
    unsigned long call_id, void* data, size_t data_len, void* return_buffer,
    size_t return_len);
uintptr_t
untrusted_mmap();
int
attest_enclave(void* report, void* data, size_t size);

int
m_enclave_create_group(void* identity, size_t size);

int
s_enclave_join_group(void* identity, size_t size);

int
slave_enclave_set_dataptr(void* src, size_t size, size_t numbers);

int
main_enclave_get_slave_enclave_data(void* dest, size_t size, size_t numbers);

int
slave_enclave_set_dataptr_yx(void* src);

int
main_enclave_get_slave_enclave_data_yx(void* dest);

int
main_enclave_get_numberblock(void* dest, size_t set_number, size_t size);

int
slave_enclave_set_numberblock(void* src, size_t set_number, size_t size);

int
other_enclave_access_stm_test();

int
other_enclave_access_epm_test_o(void* flag);

int
other_enclave_access_epm_test_s(void* flag);

int
m_attestt_s_enclave(size_t slave_id, size_t flexible);

int
s_enclave_attestted(size_t slave_id, size_t flexible);

int
test_corrupt_attestation_key(void);

int
test_set_attestation_mutation(uint64_t mode);

int
wait_main_dispatch(void* dest, void* block_id, void* block_size, uint64_t slave_id, uint64_t flexible);

int
main_dispatch_send(void* src, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible);

int
slave_set_block(void* src, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible);

// 扩展 API：支持 actual_size 参数（用于 8MB 单块传输模式）
// block_size: 用于匹配的原始大小
// actual_size: 实际写入的数据大小（加密后 = 原始大小 + 28B GCM 开销）
int
slave_set_block_ext(void* src, uint64_t block_id, uint64_t block_size,
                    uint64_t actual_size, uint64_t slave_id, uint64_t flexible);

int
get_slave_block(void* dest, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible);

// 扩展 API：返回 actual_size（用于 8MB 单块传输模式）
// actual_size: 输出参数，返回实际数据大小
int
get_slave_block_ext(void* dest, uint64_t block_id, uint64_t* actual_size,
                    uint64_t slave_id, uint64_t flexible);

int
get_sealing_key(
    struct sealing_key* sealing_key_struct, size_t sealing_key_struct_size,
    void* key_ident, size_t key_ident_size);

#endif /* syscall.h */
