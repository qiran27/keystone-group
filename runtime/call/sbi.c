#include "call/sbi.h"

#include "mm/vm_defs.h"
#include "sm_err.h"

#define SBI_CALL(___ext, ___which, ___arg0, ___arg1, ___arg2, ___arg3) \
  ({                                                             \
    register uintptr_t a0 __asm__("a0") = (uintptr_t)(___arg0);  \
    register uintptr_t a1 __asm__("a1") = (uintptr_t)(___arg1);  \
    register uintptr_t a2 __asm__("a2") = (uintptr_t)(___arg2);  \
    register uintptr_t a3 __asm__("a3") = (uintptr_t)(___arg3);  \
    register uintptr_t a6 __asm__("a6") = (uintptr_t)(___which); \
    register uintptr_t a7 __asm__("a7") = (uintptr_t)(___ext);   \
    __asm__ volatile("ecall"                                     \
                     : "+r"(a0)                                  \
                     : "r"(a1), "r"(a2), "r"(a3), "r"(a6), "r"(a7) \
                     : "memory");                                \
    a0;                                                          \
  })

/* Lazy implementations until SBI is finalized */
#define SBI_CALL_0(___ext, ___which) SBI_CALL(___ext, ___which, 0, 0, 0, 0)
#define SBI_CALL_1(___ext, ___which, ___arg0) SBI_CALL(___ext, ___which, ___arg0, 0, 0, 0)
#define SBI_CALL_2(___ext, ___which, ___arg0, ___arg1) \
  SBI_CALL(___ext, ___which, ___arg0, ___arg1, 0, 0)
#define SBI_CALL_3(___ext, ___which, ___arg0, ___arg1, ___arg2) \
  SBI_CALL(___ext, ___which, ___arg0, ___arg1, ___arg2, 0)
#define SBI_CALL_4(___ext, ___which, ___arg0, ___arg1, ___arg2, ___arg3) \
  SBI_CALL(___ext, ___which, ___arg0, ___arg1, ___arg2, ___arg3)

/*
 * Keystone transports SM-specific errors in SBI value (a1) while a0 carries
 * a standard negative SBI error.  Enclave-side callers historically observed
 * only a0, collapsing every useful protocol error to -1.  Keep the normal
 * success ABI, but recover a Keystone detail when OpenSBI supplied one.
 */
#define SBI_CALL_DETAIL(___ext, ___which, ___arg0, ___arg1, ___arg2, ___arg3) \
  ({                                                                        \
    register uintptr_t a0 __asm__("a0") = (uintptr_t)(___arg0);             \
    register uintptr_t a1 __asm__("a1") = (uintptr_t)(___arg1);             \
    register uintptr_t a2 __asm__("a2") = (uintptr_t)(___arg2);             \
    register uintptr_t a3 __asm__("a3") = (uintptr_t)(___arg3);             \
    register uintptr_t a6 __asm__("a6") = (uintptr_t)(___which);            \
    register uintptr_t a7 __asm__("a7") = (uintptr_t)(___ext);              \
    __asm__ volatile("ecall"                                                \
                     : "+r"(a0), "+r"(a1)                                 \
                     : "r"(a2), "r"(a3), "r"(a6), "r"(a7)                \
                     : "memory");                                           \
    ((intptr_t)a0 < 0 && a1 >= SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR) ? a1 : a0; \
  })

void
sbi_putchar(char character) {
  SBI_CALL_1(SBI_CONSOLE_PUTCHAR, 0, character);
}

void
sbi_set_timer(uint64_t stime_value) {
#if __riscv_xlen == 32
  SBI_CALL_2(SBI_SET_TIMER, 0, stime_value, stime_value >> 32);
#else
  SBI_CALL_1(SBI_SET_TIMER, 0, stime_value);
#endif
}

uintptr_t
sbi_stop_enclave(uint64_t request) {
  return SBI_CALL_DETAIL(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_STOP_ENCLAVE, request, 0, 0, 0);
}

void
sbi_exit_enclave(uint64_t retval) {
  SBI_CALL_1(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_EXIT_ENCLAVE, retval);
}

uintptr_t
sbi_random() {
  SBI_CALL_0(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_RANDOM);
  register uintptr_t a1 __asm__("a1");
  return a1;
}

uintptr_t
sbi_query_multimem(size_t *size) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_CALL_PLUGIN, SM_MULTIMEM_PLUGIN_ID, SM_MULTIMEM_CALL_GET_SIZE, size);
}

uintptr_t
sbi_query_multimem_addr(uintptr_t *addr) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_CALL_PLUGIN, SM_MULTIMEM_PLUGIN_ID, SM_MULTIMEM_CALL_GET_ADDR, addr);
}

uintptr_t
sbi_attest_enclave(void* report, void* buf, uintptr_t len) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_ATTEST_ENCLAVE, report, buf, len);
}

uintptr_t
sbi_m_enclave_create_group(void* identity, uintptr_t size) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_M_ENCLAVE_CREATE_GROUP, identity, size);
}

uintptr_t
sbi_s_enclave_join_group(void* identity, uintptr_t size) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_S_ENCLAVE_JOIN_GROUP, identity, size);
}

uintptr_t
sbi_slave_enclave_set_dataptr(void* src, uintptr_t size, uintptr_t numbers) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_SLAVE_ENCLAVE_SET_DATAPTR, src, size, numbers);
}

uintptr_t
sbi_main_enclave_get_slave_enclave_data(void* dest, uintptr_t size, uintptr_t numbers) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_MAIN_ENCLAVE_GET_SLAVE_ENCLAVE_DATA, dest, size, numbers);
}

uintptr_t
sbi_slave_enclave_set_dataptr_yx(void* state, void* src) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_SLAVE_ENCLAVE_SET_DATAPTR, state, src);
}

uintptr_t
sbi_main_enclave_get_slave_enclave_data_yx(void* state, void* dest) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_MAIN_ENCLAVE_GET_SLAVE_ENCLAVE_DATA, state, dest);
}

uintptr_t
sbi_slave_enclave_set_numberblock_set_pmp() {
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

uintptr_t
sbi_main_enclave_get_numberblock_set_pmp() {
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

uintptr_t
sbi_other_enclave_access_stm_test_set_pmp() {
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

uintptr_t
sbi_get_sealing_key(uintptr_t key_struct, uintptr_t key_ident, uintptr_t len) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_GET_SEALING_KEY, key_struct, key_ident, len);
}

uintptr_t
sbi_slave_enclave_attested(void* report, uintptr_t nonce, void* kg) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_S_ENCLAVE_ATTESTED, report, nonce, kg);
}

uintptr_t
sbi_m_enclave_attest_s_enclave(void* report, void* kg, void* flag) {
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_M_ENCLAVE_ATTEST_S_ENCLAVE, report, kg, flag);
}

uintptr_t
sbi_sec_acquire(uintptr_t engine_id, uintptr_t timeout_cycles) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_SEC_ACQUIRE, engine_id, timeout_cycles);
}

uintptr_t
sbi_sec_release(void) {
  return SBI_CALL_0(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_SEC_RELEASE);
}

uintptr_t
sbi_sec_query(uintptr_t out_pa, uintptr_t out_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_SEC_QUERY, out_pa, out_len);
}

uintptr_t
sbi_group_validate_page_table(uintptr_t page_table_root) {
  return SBI_CALL_1(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_VALIDATE_PAGE_TABLE, page_table_root);
}

uintptr_t
sbi_yxstm_query_layout(uintptr_t out_pa, uintptr_t out_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_QUERY_LAYOUT, out_pa, out_len);
}

uintptr_t
sbi_yxstm_query_slot(uintptr_t inout_pa, uintptr_t inout_len) {
  static const volatile char security_slot_detail_marker[] __attribute__((used)) =
      "keystone-security-slot-error-detail-v1";
  (void)security_slot_detail_marker[0];
  /* Preserve the SM ownership-denial reason for the security probe.
   * Successful metadata queries retain the existing zero return value. */
  return SBI_CALL_DETAIL(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_QUERY_SLOT, inout_pa, inout_len, 0, 0);
}

uintptr_t
sbi_yxstm_slot_command(uintptr_t inout_pa, uintptr_t inout_len) {
  return SBI_CALL_DETAIL(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_SLOT_COMMAND, inout_pa, inout_len, 0, 0);
}

uintptr_t
sbi_yxstm_acquire_slice(uintptr_t slice_id, uintptr_t flags, uintptr_t phase,
                        uintptr_t expected_epoch) {
  return SBI_CALL_4(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_ACQUIRE_SLICE, slice_id, flags, phase, expected_epoch);
}

uintptr_t
sbi_yxstm_release_slice(uintptr_t slice_id, uintptr_t expected_epoch) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_RELEASE_SLICE, slice_id, expected_epoch);
}

uintptr_t
sbi_yxstm_acquire_mask(uintptr_t slice_mask, uintptr_t flags, uintptr_t phase,
                       uintptr_t expected_epoch) {
  return SBI_CALL_4(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_ACQUIRE_MASK, slice_mask, flags, phase, expected_epoch);
}

uintptr_t
sbi_yxstm_release_mask(uintptr_t slice_mask, uintptr_t expected_epoch) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_RELEASE_MASK, slice_mask, expected_epoch);
}

uintptr_t
sbi_yxstm_query_protocol(uintptr_t out_pa, uintptr_t out_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_QUERY_PROTOCOL, out_pa, out_len);
}

uintptr_t
sbi_yxstm_phase_transition(uintptr_t request_pa, uintptr_t request_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_PHASE_TRANSITION, request_pa, request_len);
}

uintptr_t
sbi_yxstm_phase_ack(uintptr_t expected_epoch, uintptr_t event) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_PHASE_ACK, expected_epoch, event);
}

uintptr_t
sbi_yxstm_register_mailbox(uintptr_t request_pa, uintptr_t request_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_REGISTER_MAILBOX, request_pa, request_len);
}

uintptr_t
sbi_yxstm_task_bank_transition(uintptr_t request_pa, uintptr_t request_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_TASK_BANK_TRANSITION, request_pa, request_len);
}

uintptr_t
sbi_yxstm_task_bank_acquire(uintptr_t request_pa, uintptr_t request_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_TASK_BANK_ACQUIRE, request_pa, request_len);
}

uintptr_t
sbi_yxstm_task_bank_release(uintptr_t request_pa, uintptr_t request_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_TASK_BANK_RELEASE, request_pa, request_len);
}

uintptr_t
sbi_yxstm_task_bank_ack(uintptr_t request_pa, uintptr_t request_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_YXSTM_TASK_BANK_ACK, request_pa, request_len);
}

uintptr_t
sbi_group_lane_turn(uintptr_t request_pa, uintptr_t request_len) {
  return SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_LANE_TURN, request_pa, request_len);
}
