//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __SBI_H_
#define __SBI_H_

#include <stdint.h>
#include <stddef.h>

#include "sm_call.h"

void
sbi_putchar(char c);
void
sbi_set_timer(uint64_t stime_value);
uintptr_t
sbi_stop_enclave(uint64_t request);
void
sbi_exit_enclave(uint64_t retval);
uintptr_t
sbi_random();
uintptr_t
sbi_query_multimem(size_t *size);
uintptr_t
sbi_query_multimem_addr(uintptr_t *addr);
uintptr_t
sbi_attest_enclave(void* report, void* buf, uintptr_t len);
uintptr_t
sbi_get_sealing_key(uintptr_t key_struct, uintptr_t key_ident, uintptr_t len);
uintptr_t
sbi_m_enclave_create_group(void* identity, uintptr_t size);
uintptr_t
sbi_s_enclave_join_group(void* identity, uintptr_t size);
uintptr_t
sbi_main_enclave_get_slave_enclave_data(void* dest, uintptr_t size, uintptr_t numbers);
uintptr_t
sbi_slave_enclave_set_dataptr(void* src, uintptr_t size, uintptr_t numbers);
uintptr_t
sbi_main_enclave_get_slave_enclave_data_yx(void* state, void* dest);
uintptr_t
sbi_slave_enclave_set_dataptr_yx(void* state, void* src);
uintptr_t
sbi_slave_enclave_set_numberblock_set_pmp();
uintptr_t
sbi_main_enclave_get_numberblock_set_pmp();
uintptr_t
sbi_other_enclave_access_stm_test_set_pmp();
uintptr_t
sbi_slave_enclave_attested(void* report, uintptr_t nonce, void* kg);
uintptr_t
sbi_m_enclave_attest_s_enclave(void* report, void* kg, void* flag);
uintptr_t
sbi_sec_acquire(uintptr_t engine_id, uintptr_t timeout_cycles);
uintptr_t
sbi_sec_release(void);
uintptr_t
sbi_sec_query(uintptr_t out_pa, uintptr_t out_len);
uintptr_t
sbi_group_validate_page_table(uintptr_t page_table_root);
uintptr_t
sbi_yxstm_query_layout(uintptr_t out_pa, uintptr_t out_len);
uintptr_t
sbi_yxstm_query_slot(uintptr_t inout_pa, uintptr_t inout_len);
uintptr_t
sbi_yxstm_slot_command(uintptr_t inout_pa, uintptr_t inout_len);
uintptr_t
sbi_yxstm_acquire_slice(uintptr_t slice_id, uintptr_t flags, uintptr_t phase,
                        uintptr_t expected_epoch);
uintptr_t
sbi_yxstm_release_slice(uintptr_t slice_id, uintptr_t expected_epoch);
uintptr_t
sbi_yxstm_acquire_mask(uintptr_t slice_mask, uintptr_t flags, uintptr_t phase,
                       uintptr_t expected_epoch);
uintptr_t
sbi_yxstm_release_mask(uintptr_t slice_mask, uintptr_t expected_epoch);
uintptr_t
sbi_yxstm_query_protocol(uintptr_t out_pa, uintptr_t out_len);
uintptr_t
sbi_yxstm_phase_transition(uintptr_t request_pa, uintptr_t request_len);
uintptr_t
sbi_yxstm_phase_ack(uintptr_t expected_epoch, uintptr_t event);
uintptr_t
sbi_yxstm_register_mailbox(uintptr_t request_pa, uintptr_t request_len);
uintptr_t
sbi_yxstm_task_bank_transition(uintptr_t request_pa, uintptr_t request_len);
uintptr_t
sbi_yxstm_task_bank_acquire(uintptr_t request_pa, uintptr_t request_len);
uintptr_t
sbi_yxstm_task_bank_release(uintptr_t request_pa, uintptr_t request_len);
uintptr_t
sbi_yxstm_task_bank_ack(uintptr_t request_pa, uintptr_t request_len);
uintptr_t
sbi_group_lane_turn(uintptr_t request_pa, uintptr_t request_len);

#endif
