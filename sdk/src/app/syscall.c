//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "syscall.h"

#ifndef RUNTIME_SYSCALL_TEST_CORRUPT_ATTESTATION_KEY
#define RUNTIME_SYSCALL_TEST_CORRUPT_ATTESTATION_KEY 1027
#endif

#ifndef RUNTIME_SYSCALL_TEST_SET_ATTESTATION_MUTATION
#define RUNTIME_SYSCALL_TEST_SET_ATTESTATION_MUTATION 1028
#endif

/* this implementes basic system calls for the enclave */

int
ocall(
    unsigned long call_id, void* data, size_t data_len, void* return_buffer,
    size_t return_len) {
  return SYSCALL_5(RUNTIME_SYSCALL_OCALL,
      call_id, data, data_len, return_buffer, return_len);
}

int
copy_from_shared(void* dst, uintptr_t offset, size_t data_len) {
  return SYSCALL_3(RUNTIME_SYSCALL_SHAREDCOPY, dst, offset, data_len);
}

// 从共享 UTM 读取数据（用于 Slave Enclave 访问 Main 的共享 UTM）
// 与 copy_from_shared 不同，这个函数使用 shared_buffer 而不是 ocall_buffer
// 在共享 UTM 模式下：
//   - copy_from_shared() 使用 ocall_buffer（Enclave 自己的 1MB UTM）
//   - copy_from_shared_utm() 使用 shared_buffer（Main 的 64MB 共享 UTM）
// 在普通模式下，两者等价
int
copy_from_shared_utm(void* dst, uintptr_t offset, size_t data_len) {
  return SYSCALL_3(RUNTIME_SYSCALL_SHAREDCOPY_UTM, dst, offset, data_len);
}

// 写入数据到共享 UTM（用于 Enclave 直接写入共享 UTM，消除 128 次 OCALL 开销）
// 与 copy_from_shared_utm 对应，实现一次性写入大块数据
// 在共享 UTM 模式下：
//   - 传统方式：使用 OCALL_WRITE_DATA_CHUNK 分块写入（8MB 需要 128 次 OCALL）
//   - 优化方式：使用 copy_to_shared_utm() 一次性写入（1 次 syscall）
// 性能提升：消除 OCALL 上下文切换开销，预计提升 10-50x
int
copy_to_shared_utm(uintptr_t offset, const void* src, size_t data_len) {
  return SYSCALL_3(RUNTIME_SYSCALL_SHAREDWRITE_UTM, offset, src, data_len);
}

int
sec_acquire(uint64_t engine_id, uint64_t timeout_cycles) {
  return SYSCALL_2(RUNTIME_SYSCALL_SEC_ACQUIRE, engine_id, timeout_cycles);
}

int
sec_release(void) {
  return SYSCALL_0(RUNTIME_SYSCALL_SEC_RELEASE);
}

int
sec_query(void* info, size_t info_len) {
  return SYSCALL_2(RUNTIME_SYSCALL_SEC_QUERY, info, info_len);
}

int
group_private_region_info(
    struct group_private_region_info* info, size_t info_len) {
  return SYSCALL_2(RUNTIME_SYSCALL_GROUP_PRIVATE_REGION_INFO, info, info_len);
}

int
yxstm_query_layout(struct keystone_yxstm_layout_info* info, size_t info_len) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_QUERY_LAYOUT, info, info_len);
}

int
yxstm_query_slot(struct keystone_yxstm_slot_info* info, size_t info_len) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_QUERY_SLOT, info, info_len);
}

int
yxstm_slot_command(struct keystone_yxstm_slot_command* command,
                   size_t command_len) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_SLOT_COMMAND,
                   command, command_len);
}

int
yxstm_acquire_slice(uint64_t slice_id, uint64_t flags, uint64_t phase,
                    uint64_t expected_epoch) {
  return SYSCALL_4(RUNTIME_SYSCALL_YXSTM_ACQUIRE_SLICE,
                   slice_id, flags, phase, expected_epoch);
}

int
yxstm_release_slice(uint64_t slice_id, uint64_t expected_epoch) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_RELEASE_SLICE,
                   slice_id, expected_epoch);
}

int
yxstm_acquire_mask(uint64_t slice_mask, uint64_t flags, uint64_t phase,
                   uint64_t expected_epoch) {
  return SYSCALL_4(RUNTIME_SYSCALL_YXSTM_ACQUIRE_MASK,
                   slice_mask, flags, phase, expected_epoch);
}

int
yxstm_release_mask(uint64_t slice_mask, uint64_t expected_epoch) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_RELEASE_MASK,
                   slice_mask, expected_epoch);
}

int
yxstm_query_protocol(struct keystone_yxstm_protocol_state* state,
                     size_t state_len) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_QUERY_PROTOCOL, state, state_len);
}

int
yxstm_phase_transition(const struct keystone_yxstm_phase_transition* request,
                       size_t request_len) {
  struct keystone_yxstm_phase_transition local;
  if (!request || request_len != sizeof(local))
    return -1;
  local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_PHASE_TRANSITION,
                   &local, sizeof(local));
}

int
yxstm_phase_ack(uint64_t expected_epoch, uint64_t event) {
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_PHASE_ACK,
                   expected_epoch, event);
}

int
yxstm_register_mailbox(
    const struct keystone_yxstm_mailbox_registration* registration,
    size_t registration_len) {
  struct keystone_yxstm_mailbox_registration local;
  if (!registration || registration_len != sizeof(local))
    return -1;
  local = *registration;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  local.reserved = 0;
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_REGISTER_MAILBOX,
                   &local, sizeof(local));
}

int
yxstm_task_bank_transition(
    const struct keystone_yxstm_task_bank_transition* request,
    size_t request_len) {
  struct keystone_yxstm_task_bank_transition local;
  if (!request || request_len != sizeof(local))
    return -1;
  local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_TASK_BANK_TRANSITION,
                   &local, sizeof(local));
}

int
yxstm_task_bank_acquire(const struct keystone_yxstm_task_bank_grant* request,
                        size_t request_len) {
  struct keystone_yxstm_task_bank_grant local;
  if (!request || request_len != sizeof(local))
    return -1;
  local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_TASK_BANK_ACQUIRE,
                   &local, sizeof(local));
}

int
yxstm_task_bank_release(const struct keystone_yxstm_task_bank_grant* request,
                        size_t request_len) {
  struct keystone_yxstm_task_bank_grant local;
  if (!request || request_len != sizeof(local))
    return -1;
  local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_TASK_BANK_RELEASE,
                   &local, sizeof(local));
}

int
yxstm_task_bank_ack(const struct keystone_yxstm_task_bank_ack* request,
                    size_t request_len) {
  struct keystone_yxstm_task_bank_ack local;
  if (!request || request_len != sizeof(local))
    return -1;
  local = *request;
  KEYSTONE_ABI_INIT(&local, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_YXSTM_TASK_BANK_ACK,
                   &local, sizeof(local));
}

int
group_lane_turn(struct keystone_group_lane_turn* request,
                size_t request_len) {
  if (!request || request_len != sizeof(*request))
    return -1;
  KEYSTONE_ABI_INIT(request, KEYSTONE_YXSTM_ABI_FEATURES);
  return SYSCALL_2(RUNTIME_SYSCALL_GROUP_LANE_TURN,
                   request, sizeof(*request));
}

int
enclave_yield(void) {
  return SYSCALL_0(RUNTIME_SYSCALL_YIELD);
}

int
attest_enclave(void* report, void* data, size_t size) {
  return SYSCALL_3(RUNTIME_SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

int
m_enclave_create_group(void* identity, size_t size) {
  return SYSCALL_2(RUNTIME_SYSCALL_CREATE_GROUP, identity, size);
}

int
s_enclave_join_group(void* identity, size_t size) {
  return SYSCALL_2(RUNTIME_SYSCALL_JOIN_GROUP, identity, size);
}

int
slave_enclave_set_dataptr(void* src, size_t size, size_t numbers) {
  return SYSCALL_3(RUNTIME_SYSCALL_SLAVE_ENCLAVE_SET_DATAPTR, src, size, numbers);
}

int
main_enclave_get_slave_enclave_data(void* dest, size_t size, size_t numbers) {
  return SYSCALL_3(RUNTIME_SYSCALL_MAIN_ENCLAVE_GET_SLAVE_ENCLAVE_DATA, dest, size, numbers);
}

int
slave_enclave_set_dataptr_yx(void* src) {
  return SYSCALL_1(RUNTIME_SYSCALL_SLAVE_ENCLAVE_SET_DATAPTR, src);
}

int
main_enclave_get_slave_enclave_data_yx(void* dest) {
  return SYSCALL_1(RUNTIME_SYSCALL_MAIN_ENCLAVE_GET_SLAVE_ENCLAVE_DATA, dest);
}

int
slave_enclave_set_numberblock(void* src, size_t set_number, size_t size) {
  (void)src;
  (void)set_number;
  (void)size;
  return -1;
}

int
main_enclave_get_numberblock(void* dest, size_t set_number, size_t size) {
  (void)dest;
  (void)set_number;
  (void)size;
  return -1;
}

int
other_enclave_access_stm_test() {
  return SYSCALL_0(RUNTIME_SYSCALL_STM_ACCESS_TEST);
}

int
other_enclave_access_epm_test_o(void* flag) {
  return SYSCALL_1(RUNTIME_SYSCALL_TEST_OTHER_ENCLAVE_ACCESS_EPM_O, flag);
}

int
other_enclave_access_epm_test_s(void* flag) {
  return SYSCALL_1(RUNTIME_SYSCALL_TEST_OTHER_ENCLAVE_ACCESS_EPM_S, flag);
}

int
m_attestt_s_enclave(size_t slave_id, size_t flexible){
  return SYSCALL_2(RUNTIME_SYSCALL_M_ATTEST_S_ENCLAVE, slave_id, flexible);
}

int
s_enclave_attestted(size_t slave_id, size_t flexible){
  return SYSCALL_2(RUNTIME_SYSCALL_S_ENCLAVE_ATTESTTED, slave_id, flexible);
}

int
test_corrupt_attestation_key(void){
  return SYSCALL_0(RUNTIME_SYSCALL_TEST_CORRUPT_ATTESTATION_KEY);
}

int
test_set_attestation_mutation(uint64_t mode){
  return SYSCALL_1(RUNTIME_SYSCALL_TEST_SET_ATTESTATION_MUTATION, mode);
}

int
wait_main_dispatch(void* dest, void* block_id, void* block_size, uint64_t slave_id, uint64_t flexible) {
  return SYSCALL_5(RUNTIME_SYSCALL_WAIT_MAIN_DISPATCH, dest, block_id, block_size, slave_id, flexible);
}

int
main_dispatch_send(void* src, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible) {
  return SYSCALL_5(RUNTIME_SYSCALL_MAIN_DISPATCH_SEND, src, block_id, block_size, slave_id, flexible);
}

int
slave_set_block(void* src, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible) {
  return SYSCALL_5(RUNTIME_SYSCALL_SLAVE_SET_BLOCK, src, block_id, block_size, slave_id, flexible);
}

// 扩展 API：支持 actual_size 参数（用于 8MB 单块传输模式）
// 注意：由于 SYSCALL 最多支持 5 个参数，我们需要将 actual_size 和 slave_id/flexible 打包
// 方案：使用一个临时结构体传递额外参数
typedef struct {
    uint64_t actual_size;
    uint64_t slave_id;
    uint64_t flexible;
} SlaveSetBlockExtParams;

int
slave_set_block_ext(void* src, uint64_t block_id, uint64_t block_size,
                    uint64_t actual_size, uint64_t slave_id, uint64_t flexible) {
  // 将 actual_size, slave_id, flexible 打包到栈上的结构体
  SlaveSetBlockExtParams params;
  params.actual_size = actual_size;
  params.slave_id = slave_id;
  params.flexible = flexible;
  return SYSCALL_4(RUNTIME_SYSCALL_SLAVE_SET_BLOCK_EXT, src, block_id, block_size, &params);
}

int
get_slave_block(void* dest, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible) {
  return SYSCALL_5(RUNTIME_SYSCALL_GET_SLAVE_BLOCK, dest, block_id, block_size, slave_id, flexible);
}

// 扩展 API：返回 actual_size（用于 8MB 单块传输模式）
typedef struct {
    uint64_t* actual_size_ptr;
    uint64_t slave_id;
    uint64_t flexible;
} GetSlaveBlockExtParams;

int
get_slave_block_ext(void* dest, uint64_t block_id, uint64_t* actual_size,
                    uint64_t slave_id, uint64_t flexible) {
  // 将 actual_size_ptr, slave_id, flexible 打包到栈上的结构体
  GetSlaveBlockExtParams params;
  params.actual_size_ptr = actual_size;
  params.slave_id = slave_id;
  params.flexible = flexible;
  return SYSCALL_3(RUNTIME_SYSCALL_GET_SLAVE_BLOCK_EXT, dest, block_id, &params);
}

/* returns sealing key */
int
get_sealing_key(
    struct sealing_key* sealing_key_struct, size_t sealing_key_struct_size,
    void* key_ident, size_t key_ident_size) {
  return SYSCALL_4(RUNTIME_SYSCALL_GET_SEALING_KEY,
      sealing_key_struct, sealing_key_struct_size,
      key_ident, key_ident_size);
}
