//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_SBI_H_
#define _KEYSTONE_SBI_H_

#include <sbi/sbi_types.h>
#include <sbi/sbi_trap.h>

unsigned long
sbi_sm_create_enclave(unsigned long *out_val, uintptr_t create_args);

unsigned long
sbi_sm_destroy_enclave(unsigned long eid, unsigned long eid_generation);

unsigned long
sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned long eid);

unsigned long
sbi_sm_exit_enclave(struct sbi_trap_regs *regs, unsigned long retval);

unsigned long
sbi_sm_fault_enclave(struct sbi_trap_regs *regs, unsigned long fault_code,
                     unsigned long fault_cause, unsigned long fault_tval);

unsigned long
sbi_sm_stop_enclave(struct sbi_trap_regs *regs, unsigned long request);

unsigned long
sbi_sm_resume_enclave(struct sbi_trap_regs *regs, unsigned long eid);

unsigned long
sbi_sm_group_set_count(uintptr_t group_count);

unsigned long
sbi_sm_group_set_hart_count(uintptr_t group_id, uintptr_t hart_count);

unsigned long
sbi_sm_group_query(uintptr_t out_config);
unsigned long sbi_sm_group_config_topology(uintptr_t inout_topology);
unsigned long sbi_sm_group_query_topology(uintptr_t inout_topology);
unsigned long sbi_sm_group_set_lease_state(uintptr_t inout_lease);
unsigned long sbi_sm_group_test_snapshot(uintptr_t out_snapshot);
unsigned long sbi_sm_group_test_inject(uintptr_t inout_injection);
unsigned long sbi_sm_group_perf_query(uintptr_t inout_snapshot);

unsigned long
sbi_sm_group_create(uintptr_t inout_config);

unsigned long
sbi_sm_group_activate(uintptr_t inout_config);

unsigned long
sbi_sm_group_destroy(uintptr_t inout_config);

unsigned long
sbi_sm_group_bind_enclave(uintptr_t eid, uintptr_t hart_id,
                          uintptr_t group_generation,
                          uintptr_t eid_generation,
                          uintptr_t priority,
                          uintptr_t quantum_ticks);

unsigned long
sbi_sm_group_host_heartbeat_ack(uintptr_t inout_heartbeat);

unsigned long
sbi_sm_group_enqueue_enclave(uintptr_t eid, uintptr_t group_generation,
                             uintptr_t eid_generation);

unsigned long
sbi_sm_group_poll_blocked_ocall(uintptr_t out_status);

unsigned long
sbi_sm_group_resume_blocked_ocall(uintptr_t inout_status);

unsigned long
sbi_sm_group_run_hart(struct sbi_trap_regs *regs, uintptr_t run_status);
unsigned long sbi_sm_group_run_master(struct sbi_trap_regs *regs,
                                      uintptr_t run_status);
unsigned long sbi_sm_group_pause_master(uintptr_t inout_control);

unsigned long
sbi_sm_group_control_enclave(uintptr_t inout_control);

unsigned long
sbi_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size);

unsigned long
sbi_sm_m_enclave_create_group(uintptr_t identity, uintptr_t size);

unsigned long
sbi_sm_s_enclave_join_group(uintptr_t identity, uintptr_t size);

unsigned long
sbi_sm_main_enclave_get_slave_enclave_data(uintptr_t dest, uintptr_t size, uintptr_t numbers);

unsigned long
sbi_sm_slave_enclave_set_dataptr(uintptr_t src, uintptr_t size, uintptr_t numbers);

unsigned long
sbi_sm_main_enclave_get_slave_enclave_data_yx(uintptr_t temp_ptr, uintptr_t dest_ptr);

unsigned long
sbi_sm_slave_enclave_set_dataptr_yx(uintptr_t temp_ptr, uintptr_t data_ptr);

unsigned long
sbi_sm_main_enclave_get_numberblock_set_pmp();

unsigned long
sbi_sm_slave_enclave_set_numberblock_set_pmp();

unsigned long
sbi_sm_other_enclave_access_stm_test_set_pmp();

unsigned long
sbi_sm_s_enclave_attested(uintptr_t report, uintptr_t nonce, uintptr_t kg);

unsigned long
sbi_sm_m_enclave_attest_s_enclave(uintptr_t report, uintptr_t kg, uintptr_t flag);

unsigned long
sbi_sm_sec_acquire(uintptr_t engine_id, uintptr_t timeout_cycles);

unsigned long
sbi_sm_sec_release(void);

unsigned long
sbi_sm_sec_query(uintptr_t out_buf, uintptr_t out_len);

unsigned long
sbi_sm_group_validate_page_table(uintptr_t page_table_root);

unsigned long
sbi_sm_yxstm_query_layout(uintptr_t out_buf, uintptr_t out_len);
unsigned long
sbi_sm_yxstm_query_slot(uintptr_t inout_buf, uintptr_t inout_len);
unsigned long
sbi_sm_yxstm_slot_command(uintptr_t inout_buf, uintptr_t inout_len);

unsigned long
sbi_sm_yxstm_acquire_slice(uintptr_t slice_id, uintptr_t flags, uintptr_t phase,
                           uintptr_t expected_epoch);

unsigned long
sbi_sm_yxstm_release_slice(uintptr_t slice_id, uintptr_t expected_epoch);

unsigned long
sbi_sm_yxstm_acquire_mask(uintptr_t slice_mask, uintptr_t flags, uintptr_t phase,
                          uintptr_t expected_epoch);

unsigned long
sbi_sm_yxstm_release_mask(uintptr_t slice_mask, uintptr_t expected_epoch);

unsigned long
sbi_sm_yxstm_query_protocol(uintptr_t out_buf, uintptr_t out_len);

unsigned long
sbi_sm_yxstm_phase_transition(uintptr_t request_buf, uintptr_t request_len);

unsigned long
sbi_sm_yxstm_phase_ack(uintptr_t expected_epoch, uintptr_t event);

unsigned long
sbi_sm_yxstm_register_mailbox(uintptr_t request_buf, uintptr_t request_len);

unsigned long
sbi_sm_yxstm_task_bank_transition(uintptr_t request_buf,
                                  uintptr_t request_len);

unsigned long
sbi_sm_yxstm_task_bank_acquire(uintptr_t request_buf,
                               uintptr_t request_len);

unsigned long
sbi_sm_yxstm_task_bank_release(uintptr_t request_buf,
                               uintptr_t request_len);

unsigned long
sbi_sm_yxstm_task_bank_ack(uintptr_t request_buf, uintptr_t request_len);

unsigned long
sbi_sm_group_lane_turn(uintptr_t request_buf, uintptr_t request_len);

unsigned long
sbi_sm_get_sealing_key(uintptr_t seal_key, uintptr_t key_ident, size_t key_ident_size);

unsigned long
sbi_sm_random(void);

unsigned long
sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1);

#endif
