#include <sbi/sbi_trap.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_scratch.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_ecall.h>
#include "sm-sbi-opensbi.h"
#include "pmp.h"
#include "sm-sbi.h"
#include "sm.h"
#include "cpu.h"
#include "mprv.h"
#include "sm_err.h"

static int keystone_host_standard_error(uintptr_t detail)
{
  switch (detail) {
    case SBI_ERR_SM_ENCLAVE_SUCCESS:
      return SBI_OK;
    case SBI_ERR_SM_DEPRECATED:
    case SBI_ERR_SM_NOT_IMPLEMENTED:
    case SBI_ERR_SM_GROUP_VECTOR_UNSUPPORTED:
      return SBI_ENOTSUPP;
    case SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED:
    case SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE:
      return SBI_EDENIED;
    case SBI_ERR_SM_SEC_BUSY:
    case SBI_ERR_SM_YXSTM_ALREADY_ACQUIRED:
    case SBI_ERR_SM_GROUP_COHERENCE_BUSY:
      return SBI_EALREADY;
    case SBI_ERR_SM_ENCLAVE_INVALID_ID:
    case SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT:
    case SBI_ERR_SM_GROUP_BAD_STATE:
    case SBI_ERR_SM_GROUP_STALE_GENERATION:
    case SBI_ERR_SM_ENCLAVE_STALE_GENERATION:
    case SBI_ERR_SM_ABI_UNSUPPORTED:
    case SBI_ERR_SM_ABI_BAD_SIZE:
    case SBI_ERR_SM_ABI_BAD_FEATURE:
      return SBI_EINVAL;
    default:
      return SBI_EFAIL;
  }
}

static uintptr_t keystone_host_abi_pointer(unsigned long funcid,
                                           const struct sbi_trap_regs *regs)
{
  switch (funcid) {
    case SBI_SM_GROUP_QUERY:
    case SBI_SM_GROUP_POLL_BLOCKED_OCALL:
    case SBI_SM_GROUP_RESUME_BLOCKED_OCALL:
    case SBI_SM_GROUP_CREATE:
    case SBI_SM_GROUP_ACTIVATE:
    case SBI_SM_GROUP_DESTROY:
    case SBI_SM_GROUP_CONTROL_ENCLAVE:
    case SBI_SM_GROUP_TEST_SNAPSHOT:
    case SBI_SM_GROUP_TEST_INJECT:
    case SBI_SM_GROUP_PERF_QUERY:
    case SBI_SM_GROUP_CONFIG_TOPOLOGY:
    case SBI_SM_GROUP_QUERY_TOPOLOGY:
    case SBI_SM_GROUP_SET_LEASE_STATE:
    case SBI_SM_GROUP_PAUSE_MASTER:
    case SBI_SM_GROUP_HOST_HEARTBEAT_ACK:
      return regs->a0;
    default:
      return 0;
  }
}

static void keystone_host_write_abi_error(unsigned long funcid,
                                          const struct sbi_trap_regs *regs,
                                          uintptr_t detail)
{
  struct keystone_abi_header abi;
  uintptr_t pointer = keystone_host_abi_pointer(funcid, regs);

  if (!pointer || copy_to_sm(&abi, pointer, sizeof(abi)))
    return;
  if (abi.version != KEYSTONE_ABI_VERSION ||
      abi.struct_size < sizeof(abi))
    return;
  abi.status = detail;
  abi.detail = detail;
  (void)copy_from_sm(pointer, &abi, sizeof(abi));
}

static int keystone_transport_result(unsigned long funcid,
                                     const struct sbi_trap_regs *regs,
                                     unsigned long *out_val,
                                     uintptr_t detail)
{
  if ((long)detail <= 0)
    return (int)(long)detail;
  if (detail < SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR)
    return SBI_EFAIL;
  if (out_val)
    *out_val = detail;
  keystone_host_write_abi_error(funcid, regs, detail);
  return keystone_host_standard_error(detail);
}

static int sbi_ecall_keystone_enclave_handler(unsigned long extid, unsigned long funcid,
                     const struct sbi_trap_regs *regs,
                     unsigned long *out_val,
                     struct sbi_trap_info *out_trap)
{
  uintptr_t retval;

  if (funcid <= FID_RANGE_DEPRECATED) {
    return keystone_transport_result(funcid, regs, out_val,
                                     SBI_ERR_SM_DEPRECATED);
  }
  else if (funcid <= FID_RANGE_HOST)
  {
    if (cpu_is_enclave_context())
      return keystone_transport_result(
          funcid, regs, out_val, SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED);
  }
  else if (funcid <= FID_RANGE_ENCLAVE)
  {
    if (!cpu_is_enclave_context())
      return keystone_transport_result(
          funcid, regs, out_val, SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED);
  }

  switch (funcid) {
    case SBI_SM_CREATE_ENCLAVE:
      // sbi_printf("[SBI-HANDLER] Calling sbi_sm_create_enclave...\n");
      retval = sbi_sm_create_enclave(out_val, regs->a0);
      // sbi_printf("[SBI-HANDLER] sbi_sm_create_enclave returned: retval=%ld, out_val=%ld\n", retval, *out_val);
      break;
    case SBI_SM_DESTROY_ENCLAVE:
      retval = sbi_sm_destroy_enclave(regs->a0, regs->a1);
      break;
    case SBI_SM_RUN_ENCLAVE:
      retval = sbi_sm_run_enclave((struct sbi_trap_regs*) regs, regs->a0);
      __builtin_unreachable();
      break;
    case SBI_SM_RESUME_ENCLAVE:
      retval = sbi_sm_resume_enclave((struct sbi_trap_regs*) regs, regs->a0);
      __builtin_unreachable();
      break;
    case SBI_SM_GROUP_SET_COUNT:
      retval = sbi_sm_group_set_count(regs->a0);
      break;
    case SBI_SM_GROUP_SET_HART_COUNT:
      retval = sbi_sm_group_set_hart_count(regs->a0, regs->a1);
      break;
    case SBI_SM_GROUP_QUERY:
      retval = sbi_sm_group_query(regs->a0);
      break;
    case SBI_SM_GROUP_CREATE:
      retval = sbi_sm_group_create(regs->a0);
      break;
    case SBI_SM_GROUP_ACTIVATE:
      retval = sbi_sm_group_activate(regs->a0);
      break;
    case SBI_SM_GROUP_DESTROY:
      retval = sbi_sm_group_destroy(regs->a0);
      break;
    case SBI_SM_GROUP_BIND_ENCLAVE:
      retval = sbi_sm_group_bind_enclave(regs->a0, regs->a1,
                                         regs->a2, regs->a3,
                                         regs->a4, regs->a5);
      break;
    case SBI_SM_GROUP_ENQUEUE_ENCLAVE:
      retval = sbi_sm_group_enqueue_enclave(regs->a0, regs->a1, regs->a2);
      break;
    case SBI_SM_GROUP_POLL_BLOCKED_OCALL:
      retval = sbi_sm_group_poll_blocked_ocall(regs->a0);
      break;
    case SBI_SM_GROUP_RESUME_BLOCKED_OCALL:
      retval = sbi_sm_group_resume_blocked_ocall(regs->a0);
      break;
    case SBI_SM_GROUP_RUN_HART:
      retval = sbi_sm_group_run_hart((struct sbi_trap_regs*) regs, regs->a0);
      __builtin_unreachable();
      break;
    case SBI_SM_GROUP_CONTROL_ENCLAVE:
      retval = sbi_sm_group_control_enclave(regs->a0);
      break;
    case SBI_SM_GROUP_TEST_SNAPSHOT:
      retval = sbi_sm_group_test_snapshot(regs->a0);
      break;
    case SBI_SM_GROUP_TEST_INJECT:
      retval = sbi_sm_group_test_inject(regs->a0);
      break;
    case SBI_SM_GROUP_PERF_QUERY:
      retval = sbi_sm_group_perf_query(regs->a0);
      break;
    case SBI_SM_GROUP_CONFIG_TOPOLOGY:
      retval = sbi_sm_group_config_topology(regs->a0);
      break;
    case SBI_SM_GROUP_QUERY_TOPOLOGY:
      retval = sbi_sm_group_query_topology(regs->a0);
      break;
    case SBI_SM_GROUP_SET_LEASE_STATE:
      retval = sbi_sm_group_set_lease_state(regs->a0);
      break;
    case SBI_SM_GROUP_RUN_MASTER:
      retval = sbi_sm_group_run_master((struct sbi_trap_regs*)regs,
                                       regs->a0);
      __builtin_unreachable();
      break;
    case SBI_SM_GROUP_PAUSE_MASTER:
      retval = sbi_sm_group_pause_master(regs->a0);
      break;
    case SBI_SM_GROUP_HOST_HEARTBEAT_ACK:
      retval = sbi_sm_group_host_heartbeat_ack(regs->a0);
      break;
    case SBI_SM_RANDOM:
      *out_val = sbi_sm_random();
      retval = 0;
      break;
    case SBI_SM_ATTEST_ENCLAVE:
      retval = sbi_sm_attest_enclave(regs->a0, regs->a1, regs->a2);
      break;
    case SBI_SM_M_ENCLAVE_CREATE_GROUP:
      retval = sbi_sm_m_enclave_create_group(regs->a0, regs->a1);
      break;
    case SBI_SM_S_ENCLAVE_JOIN_GROUP:
      retval = sbi_sm_s_enclave_join_group(regs->a0, regs->a1);
      break;
    case SBI_SM_MAIN_ENCLAVE_GET_SLAVE_ENCLAVE_DATA:
      retval = sbi_sm_main_enclave_get_slave_enclave_data_yx(regs->a0, regs->a1);
      break;
    case SBI_SM_SLAVE_ENCLAVE_SET_DATAPTR:
      retval = sbi_sm_slave_enclave_set_dataptr_yx(regs->a0, regs->a1);
      break;
    case SBI_SM_M_ENCLAVE_YXSTM_GET_NUMBERBLOCK_PMP:
      retval = sbi_sm_main_enclave_get_numberblock_set_pmp();
      break;
    case SBI_SM_S_ENCLAVE_YXSTM_SET_NUMBERBLOCK_PMP:
      retval = sbi_sm_slave_enclave_set_numberblock_set_pmp();
      break;
    case SBI_SM_O_ENCLAVE_ACCESS_STM_TEST_SET_PMP:
      retval = sbi_sm_other_enclave_access_stm_test_set_pmp();
      break;
    case SBI_SM_S_ENCLAVE_ATTESTED:
      retval = sbi_sm_s_enclave_attested(regs->a0, regs->a1, regs->a2);
      break;
    case SBI_SM_M_ENCLAVE_ATTEST_S_ENCLAVE:
      retval = sbi_sm_m_enclave_attest_s_enclave(regs->a0, regs->a1, regs->a2);
      break;
    case SBI_SM_SEC_ACQUIRE:
      retval = sbi_sm_sec_acquire(regs->a0, regs->a1);
      break;
    case SBI_SM_SEC_RELEASE:
      retval = sbi_sm_sec_release();
      break;
    case SBI_SM_SEC_QUERY:
      retval = sbi_sm_sec_query(regs->a0, regs->a1);
      break;
    case SBI_SM_GROUP_VALIDATE_PAGE_TABLE:
      retval = sbi_sm_group_validate_page_table(regs->a0);
      break;
    case SBI_SM_YXSTM_QUERY_LAYOUT:
      retval = sbi_sm_yxstm_query_layout(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_ACQUIRE_SLICE:
      retval = sbi_sm_yxstm_acquire_slice(regs->a0, regs->a1, regs->a2,
                                          regs->a3);
      break;
    case SBI_SM_YXSTM_RELEASE_SLICE:
      retval = sbi_sm_yxstm_release_slice(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_ACQUIRE_MASK:
      retval = sbi_sm_yxstm_acquire_mask(regs->a0, regs->a1, regs->a2,
                                         regs->a3);
      break;
    case SBI_SM_YXSTM_RELEASE_MASK:
      retval = sbi_sm_yxstm_release_mask(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_QUERY_PROTOCOL:
      retval = sbi_sm_yxstm_query_protocol(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_PHASE_TRANSITION:
      retval = sbi_sm_yxstm_phase_transition(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_PHASE_ACK:
      retval = sbi_sm_yxstm_phase_ack(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_REGISTER_MAILBOX:
      retval = sbi_sm_yxstm_register_mailbox(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_TASK_BANK_TRANSITION:
      retval = sbi_sm_yxstm_task_bank_transition(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_TASK_BANK_ACQUIRE:
      retval = sbi_sm_yxstm_task_bank_acquire(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_TASK_BANK_RELEASE:
      retval = sbi_sm_yxstm_task_bank_release(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_TASK_BANK_ACK:
      retval = sbi_sm_yxstm_task_bank_ack(regs->a0, regs->a1);
      break;
    case SBI_SM_GROUP_LANE_TURN:
      retval = sbi_sm_group_lane_turn(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_QUERY_SLOT:
      retval = sbi_sm_yxstm_query_slot(regs->a0, regs->a1);
      break;
    case SBI_SM_YXSTM_SLOT_COMMAND:
      retval = sbi_sm_yxstm_slot_command(regs->a0, regs->a1);
      break;
    case SBI_SM_GET_SEALING_KEY:
      retval = sbi_sm_get_sealing_key(regs->a0, regs->a1, regs->a2);
      break;
    case SBI_SM_STOP_ENCLAVE:
      retval = sbi_sm_stop_enclave((struct sbi_trap_regs*) regs, regs->a0);
      __builtin_unreachable();
      break;
    case SBI_SM_EXIT_ENCLAVE:
      retval = sbi_sm_exit_enclave((struct sbi_trap_regs*) regs, regs->a0);
      __builtin_unreachable();
      break;
    case SBI_SM_CALL_PLUGIN:
      retval = sbi_sm_call_plugin(regs->a0, regs->a1, regs->a2, regs->a3);
      break;
    default:
      retval = SBI_ERR_SM_NOT_IMPLEMENTED;
      break;
  }

  if (funcid <= FID_RANGE_ENCLAVE)
    return keystone_transport_result(funcid, regs, out_val, retval);
  return retval;

}

struct sbi_ecall_extension ecall_keystone_enclave = {
  .extid_start = SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
  .extid_end = SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
  .handle = sbi_ecall_keystone_enclave_handler,
};
