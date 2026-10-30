//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include "page.h"
#include "cpu.h"
#include "sm_err.h"
#include "platform-hook.h"
#include "plugins/plugins.h"
#include "mprv.h"
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_string.h>

static int sbi_sm_group_standard_error(unsigned long detail)
{
  switch (detail) {
    case SBI_ERR_SM_ENCLAVE_SUCCESS:
      return SBI_OK;
    case SBI_ERR_SM_NOT_IMPLEMENTED:
    case SBI_ERR_SM_GROUP_VECTOR_UNSUPPORTED:
      return SBI_ENOTSUPP;
    case SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED:
    case SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE:
      return SBI_EDENIED;
    case SBI_ERR_SM_GROUP_COHERENCE_BUSY:
      return SBI_EALREADY;
    case SBI_ERR_SM_ENCLAVE_INVALID_ID:
    case SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT:
    case SBI_ERR_SM_GROUP_BAD_STATE:
    case SBI_ERR_SM_GROUP_STALE_GENERATION:
    case SBI_ERR_SM_ENCLAVE_STALE_GENERATION:
      return SBI_EINVAL;
    default:
      return SBI_EFAIL;
  }
}

static void sbi_sm_group_set_host_return(struct sbi_trap_regs *regs,
                                         unsigned long detail)
{
  if ((long)detail > 0 &&
      detail >= SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR) {
    regs->a0 = sbi_sm_group_standard_error(detail);
    regs->a1 = detail;
  } else {
    regs->a0 = detail;
    regs->a1 = 0;
  }
}

unsigned long sbi_sm_create_enclave(unsigned long* eid, uintptr_t create_args)
{
  struct keystone_sbi_create_t create_args_local;
  unsigned long ret;

  // sbi_printf("[SM-SBI] sbi_sm_create_enclave: copying args...\n");
  ret = copy_enclave_create_args(create_args, &create_args_local);

  if (ret) {
    sbi_printf("[SM-SBI] copy_enclave_create_args failed: ret=%ld\n", ret);
    return ret;
  }

  // sbi_printf("[SM-SBI] Calling create_enclave...\n");
  ret = create_enclave(eid, create_args_local);
  // sbi_printf("[SM-SBI] create_enclave returned: ret=%ld, eid=%ld\n", ret, *eid);
  // sbi_printf("[SM-SBI] sbi_sm_create_enclave returning to caller\n");
  return ret;
}

unsigned long sbi_sm_destroy_enclave(unsigned long eid,
                                     unsigned long eid_generation)
{
  unsigned long ret;
  if (eid >= ENCL_MAX || enclaves[eid].state < 0 ||
      enclaves[eid].generation != eid_generation)
    return SBI_ERR_SM_ENCLAVE_STALE_GENERATION;
  ret = destroy_enclave((unsigned int)eid);
  return ret;
}

unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  unsigned long ret = run_enclave(regs, (unsigned int)eid);

  if (!cpu_is_enclave_context() && enclave_is_group_enclave((enclave_id)eid))
    sbi_sm_group_set_host_return(regs, ret);
  else
    regs->a0 = ret;
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_resume_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  unsigned long ret;
  ret = resume_enclave(regs, (unsigned int) eid);
  if (!regs->zero) {
    if (enclave_is_group_enclave((enclave_id)eid))
      sbi_sm_group_set_host_return(regs, ret);
    else
      regs->a0 = ret;
  }
  regs->mepc += 4;

  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_group_set_count(uintptr_t group_count)
{
  return group_set_count(group_count);
}

unsigned long sbi_sm_group_set_hart_count(uintptr_t group_id,
                                          uintptr_t hart_count)
{
  return group_set_hart_count(group_id, hart_count);
}

unsigned long sbi_sm_group_query(uintptr_t out_config)
{
  return group_query(out_config);
}

unsigned long sbi_sm_group_test_snapshot(uintptr_t out_snapshot)
{
  return group_test_snapshot(out_snapshot);
}

unsigned long sbi_sm_group_test_inject(uintptr_t inout_injection)
{
  return group_test_inject(inout_injection);
}

unsigned long sbi_sm_group_perf_query(uintptr_t inout_snapshot)
{
  return group_perf_query(inout_snapshot);
}

unsigned long sbi_sm_group_create(uintptr_t inout_config)
{
  return group_create(inout_config);
}

unsigned long sbi_sm_group_activate(uintptr_t inout_config)
{
  return group_activate(inout_config);
}

unsigned long sbi_sm_group_destroy(uintptr_t inout_config)
{
  return group_destroy(inout_config);
}

unsigned long sbi_sm_group_bind_enclave(uintptr_t eid, uintptr_t hart_id,
                                        uintptr_t group_generation,
                                        uintptr_t eid_generation,
                                        uintptr_t priority,
                                        uintptr_t quantum_ticks)
{
  return group_bind_enclave_to_hart((enclave_id)eid, hart_id,
                                    group_generation, eid_generation,
                                    priority, quantum_ticks);
}

unsigned long sbi_sm_group_host_heartbeat_ack(uintptr_t inout_heartbeat)
{
  return group_host_heartbeat_ack(inout_heartbeat);
}

unsigned long sbi_sm_group_enqueue_enclave(uintptr_t eid,
                                           uintptr_t group_generation,
                                           uintptr_t eid_generation)
{
  return group_enqueue_enclave((enclave_id)eid, group_generation,
                               eid_generation);
}

unsigned long sbi_sm_group_poll_blocked_ocall(uintptr_t out_status)
{
  return group_poll_blocked_ocall(out_status);
}

unsigned long sbi_sm_group_resume_blocked_ocall(uintptr_t inout_status)
{
  return group_resume_blocked_ocall(inout_status);
}

unsigned long sbi_sm_group_run_hart(struct sbi_trap_regs *regs,
                                    uintptr_t run_status)
{
  unsigned long ret = group_run_hart(regs, run_status);

  /*
   * group_run_hart may either return to the host or install an enclave
   * context in this same trap frame. Only the host return receives the SBI
   * result; an enclave resume must preserve its saved a0 exactly.
   */
  if (!cpu_is_enclave_context())
    sbi_sm_group_set_host_return(regs, ret);
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_group_run_master(struct sbi_trap_regs *regs,
                                      uintptr_t run_status)
{
  unsigned long ret = group_run_master(regs, run_status);

  if (!cpu_is_enclave_context())
    sbi_sm_group_set_host_return(regs, ret);
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_group_config_topology(uintptr_t inout_topology)
{
  return group_config_topology(inout_topology);
}

unsigned long sbi_sm_group_query_topology(uintptr_t inout_topology)
{
  return group_query_topology(inout_topology);
}

unsigned long sbi_sm_group_set_lease_state(uintptr_t inout_lease)
{
  return group_set_lease_state(inout_lease);
}

unsigned long sbi_sm_group_pause_master(uintptr_t inout_control)
{
  return group_pause_master(inout_control);
}

unsigned long sbi_sm_group_control_enclave(uintptr_t inout_control)
{
  return group_control_enclave(inout_control);
}

unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs, unsigned long retval)
{
  enclave_id old_eid = cpu_get_enclave_id();
  unsigned long ret = exit_enclave(regs, old_eid, retval == 0);

  if (cpu_is_enclave_context() && cpu_get_enclave_id() != old_eid) {
    group_queue_host_event(old_eid, KEYSTONE_GROUP_EVENT_EXIT, ret, retval);
    sbi_trap_exit(regs);
    __builtin_unreachable();
  }

  group_record_host_event(old_eid, KEYSTONE_GROUP_EVENT_EXIT, ret, retval);
  if (enclave_is_group_enclave(old_eid)) {
    sbi_sm_group_set_host_return(regs, ret);
  } else {
    regs->a0 = ret;
    regs->a1 = retval;
  }
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_fault_enclave(struct sbi_trap_regs *regs,
                                   unsigned long fault_code,
                                   unsigned long fault_cause,
                                   unsigned long fault_tval)
{
  enclave_id old_eid = cpu_get_enclave_id();
  unsigned long fault_value = group_fault_return_value(old_eid, fault_code);
  unsigned long ret = fault_enclave(regs, old_eid, fault_code,
                                    fault_cause, fault_tval);

  group_record_host_event(old_eid, KEYSTONE_GROUP_EVENT_FAULT, ret,
                          fault_code);
  if (enclave_is_group_enclave(old_eid)) {
    /*
     * Preserve the packed eid/fault-code fallback in a1. The primary event
     * record still carries the full Keystone detail; if its writeback fails,
     * the driver can reconstruct a host-visible FAULT from this value.
     */
    regs->a0 = sbi_sm_group_standard_error(ret);
    regs->a1 = fault_value;
  } else {
    regs->a0 = ret;
    regs->a1 = fault_value;
  }
  regs->a2 = fault_cause;
  regs->a3 = fault_tval;
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_stop_enclave(struct sbi_trap_regs *regs, unsigned long request)
{
  enclave_id old_eid = cpu_get_enclave_id();
  unsigned long ret = stop_enclave(regs, request, old_eid);
  uintptr_t event =
      ret == SBI_ERR_SM_GROUP_OCALL_CANCELLED ?
          KEYSTONE_GROUP_EVENT_CANCELLED :
      ret == SBI_ERR_SM_GROUP_PAUSED ? KEYSTONE_GROUP_EVENT_PAUSED :
      request == STOP_EDGE_CALL_HOST ? KEYSTONE_GROUP_EVENT_OCALL :
      request == STOP_TIMER_INTERRUPT ? KEYSTONE_GROUP_EVENT_INTERRUPTED :
      request == STOP_YIELD_ENCLAVE ? KEYSTONE_GROUP_EVENT_INTERRUPTED :
      request == STOP_LANE_WAIT_ENCLAVE ? KEYSTONE_GROUP_EVENT_NONE :
                                       KEYSTONE_GROUP_EVENT_NONE;

  if (cpu_is_enclave_context() && cpu_get_enclave_id() != old_eid) {
    /*
     * A successful timer/yield switch is entirely scheduler-internal.  Do
     * not leave a legacy INTERRUPTED event for the next host-service return;
     * that would make group_run_hart terminate even though this hart still
     * has runnable enclave work.  Pause, cancel and OCALL remain host-visible.
     */
    if (event != KEYSTONE_GROUP_EVENT_NONE &&
        event != KEYSTONE_GROUP_EVENT_INTERRUPTED &&
        !(request == STOP_EDGE_CALL_HOST &&
          ret == SBI_ERR_SM_ENCLAVE_SUCCESS))
      group_queue_host_event(old_eid, event, ret, request);
    sbi_trap_exit(regs);
    __builtin_unreachable();
  }

  group_record_host_event(
      old_eid,
      event,
      ret,
      request);
  if (enclave_is_group_enclave(old_eid))
    sbi_sm_group_set_host_return(regs, ret);
  else
    regs->a0 = ret;
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size)
{
  unsigned long ret;
  ret = attest_enclave(report, data, size, cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_m_enclave_create_group(uintptr_t identity, uintptr_t size)
{
  unsigned long ret;
  ret = m_enclave_create_group(identity, size, cpu_get_enclave_id());
  // sbi_printf("sm testing %s\n", __func__);
  return ret;
}

unsigned long sbi_sm_s_enclave_join_group(uintptr_t identity, uintptr_t size)
{
  unsigned long ret;
  ret = s_enclave_join_group(identity, size, cpu_get_enclave_id());
  // sbi_printf("sm testing %s\n", __func__);
  return ret;
}

unsigned long sbi_sm_main_enclave_get_slave_enclave_data(uintptr_t dest, uintptr_t size, uintptr_t numbers)
{
  unsigned long ret;
  ret = main_enclave_get_slave_enclave_data(dest, size, numbers, cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_slave_enclave_set_dataptr(uintptr_t src, uintptr_t size, uintptr_t numbers)
{
  unsigned long ret;
  ret = slave_enclave_set_dataptr(src, size, numbers, cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_main_enclave_get_slave_enclave_data_yx(uintptr_t temp_ptr, uintptr_t dest_ptr)
{
  unsigned long ret;
  ret = main_enclave_get_slave_enclave_data_yx(temp_ptr, dest_ptr, cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_slave_enclave_set_dataptr_yx(uintptr_t temp_ptr, uintptr_t data_ptr)
{
  unsigned long ret;
  ret = slave_enclave_set_dataptr_yx(temp_ptr, data_ptr, cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_main_enclave_get_numberblock_set_pmp()
{
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

unsigned long sbi_sm_slave_enclave_set_numberblock_set_pmp()
{
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

unsigned long sbi_sm_other_enclave_access_stm_test_set_pmp() {
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

unsigned long sbi_sm_s_enclave_attested(uintptr_t report, uintptr_t nonce, uintptr_t kg) {
  unsigned long ret;
  ret = s_enclave_attested(cpu_get_enclave_id(), report, nonce, kg);
  return ret;
}

unsigned long sbi_sm_m_enclave_attest_s_enclave(uintptr_t report, uintptr_t kg, uintptr_t flag) {
  unsigned long ret;
  ret = m_enclave_attest_s_enclave(cpu_get_enclave_id(), report, kg, flag);
  return ret;
}

unsigned long sbi_sm_sec_acquire(uintptr_t engine_id, uintptr_t timeout_cycles)
{
  enclave_id eid = cpu_get_enclave_id();

  if (eid >= ENCL_MAX || enclaves[eid].state < 0)
    return SBI_ERR_SM_ENCLAVE_INVALID_ID;

  return platform_sec_acquire(&enclaves[eid], engine_id, timeout_cycles);
}

unsigned long sbi_sm_sec_release(void)
{
  enclave_id eid = cpu_get_enclave_id();

  if (eid >= ENCL_MAX || enclaves[eid].state < 0)
    return SBI_ERR_SM_ENCLAVE_INVALID_ID;

  return platform_sec_release(&enclaves[eid]);
}

unsigned long sbi_sm_sec_query(uintptr_t out_buf, uintptr_t out_len)
{
  enclave_id eid = cpu_get_enclave_id();
  struct keystone_sec_query info;

  if (eid >= ENCL_MAX || enclaves[eid].state < 0)
    return SBI_ERR_SM_ENCLAVE_INVALID_ID;

  if (out_len < sizeof(info))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  sbi_memset(&info, 0, sizeof(info));
  unsigned long ret = platform_sec_query(&enclaves[eid], &info);
  if (ret)
    return ret;

  if (copy_from_sm(out_buf, &info, sizeof(info)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long sbi_sm_group_validate_page_table(uintptr_t page_table_root)
{
  return group_member_register_page_table_root(cpu_get_enclave_id(),
                                               page_table_root);
}

unsigned long sbi_sm_yxstm_query_layout(uintptr_t out_buf, uintptr_t out_len)
{
  return yxstm_query_layout(cpu_get_enclave_id(), out_buf, out_len);
}

unsigned long sbi_sm_yxstm_query_slot(uintptr_t inout_buf,
                                      uintptr_t inout_len)
{
  return yxstm_query_slot(cpu_get_enclave_id(), inout_buf, inout_len);
}

unsigned long sbi_sm_yxstm_slot_command(uintptr_t inout_buf,
                                        uintptr_t inout_len)
{
  return yxstm_slot_command(cpu_get_enclave_id(), inout_buf, inout_len);
}

unsigned long sbi_sm_yxstm_acquire_slice(uintptr_t slice_id,
                                         uintptr_t flags,
                                         uintptr_t phase,
                                         uintptr_t expected_epoch)
{
  return yxstm_acquire_slice(cpu_get_enclave_id(), slice_id, flags, phase,
                             expected_epoch);
}

unsigned long sbi_sm_yxstm_release_slice(uintptr_t slice_id,
                                         uintptr_t expected_epoch)
{
  return yxstm_release_slice(cpu_get_enclave_id(), slice_id, expected_epoch);
}

unsigned long sbi_sm_yxstm_acquire_mask(uintptr_t slice_mask,
                                        uintptr_t flags,
                                        uintptr_t phase,
                                        uintptr_t expected_epoch)
{
  return yxstm_acquire_mask(cpu_get_enclave_id(), slice_mask, flags, phase,
                            expected_epoch);
}

unsigned long sbi_sm_yxstm_release_mask(uintptr_t slice_mask,
                                        uintptr_t expected_epoch)
{
  return yxstm_release_mask(cpu_get_enclave_id(), slice_mask, expected_epoch);
}

unsigned long sbi_sm_yxstm_query_protocol(uintptr_t out_buf,
                                          uintptr_t out_len)
{
  return yxstm_query_protocol(cpu_get_enclave_id(), out_buf, out_len);
}

unsigned long sbi_sm_yxstm_phase_transition(uintptr_t request_buf,
                                            uintptr_t request_len)
{
  return yxstm_phase_transition(cpu_get_enclave_id(), request_buf, request_len);
}

unsigned long sbi_sm_yxstm_phase_ack(uintptr_t expected_epoch,
                                     uintptr_t event)
{
  return yxstm_phase_ack(cpu_get_enclave_id(), expected_epoch, event);
}

unsigned long sbi_sm_yxstm_register_mailbox(uintptr_t request_buf,
                                             uintptr_t request_len)
{
  return yxstm_register_mailbox(cpu_get_enclave_id(), request_buf,
                                request_len);
}

unsigned long sbi_sm_yxstm_task_bank_transition(uintptr_t request_buf,
                                                 uintptr_t request_len)
{
  return yxstm_task_bank_transition(cpu_get_enclave_id(), request_buf,
                                    request_len);
}

unsigned long sbi_sm_yxstm_task_bank_acquire(uintptr_t request_buf,
                                              uintptr_t request_len)
{
  return yxstm_task_bank_acquire(cpu_get_enclave_id(), request_buf,
                                 request_len);
}

unsigned long sbi_sm_yxstm_task_bank_release(uintptr_t request_buf,
                                              uintptr_t request_len)
{
  return yxstm_task_bank_release(cpu_get_enclave_id(), request_buf,
                                 request_len);
}

unsigned long sbi_sm_yxstm_task_bank_ack(uintptr_t request_buf,
                                         uintptr_t request_len)
{
  return yxstm_task_bank_ack(cpu_get_enclave_id(), request_buf, request_len);
}

unsigned long sbi_sm_group_lane_turn(uintptr_t request_buf,
                                     uintptr_t request_len)
{
  return group_lane_turn(cpu_get_enclave_id(), request_buf, request_len);
}

unsigned long sbi_sm_get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                       size_t key_ident_size)
{
  unsigned long ret;
  ret = get_sealing_key(sealing_key, key_ident, key_ident_size,
                         cpu_get_enclave_id());
  return ret;
}

unsigned long sbi_sm_random(void)
{
  return (unsigned long) platform_random();
}

unsigned long sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1)
{
  unsigned long ret;
  ret = call_plugin(cpu_get_enclave_id(), plugin_id, call_id, arg0, arg1);
  return ret;
}
