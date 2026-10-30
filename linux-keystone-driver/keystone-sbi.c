#include "keystone-sbi.h"
#include "sm_err.h"

#include <linux/errno.h>

#define KEYSTONE_SBI_ERR_FAILED          (-1L)
#define KEYSTONE_SBI_ERR_NOT_SUPPORTED   (-2L)
#define KEYSTONE_SBI_ERR_INVALID_PARAM   (-3L)
#define KEYSTONE_SBI_ERR_DENIED          (-4L)
#define KEYSTONE_SBI_ERR_INVALID_ADDRESS (-5L)
#define KEYSTONE_SBI_ERR_ALREADY         (-6L)

#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
int keystone_sbi_send_ipi_mask(unsigned long hart_mask) {
  struct sbiret ret = sbi_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI,
                                hart_mask, 0, 0, 0, 0, 0);

  return ret.error ? sbi_err_map_linux_errno(ret.error) : 0;
}

int keystone_sbi_hsm_hart_status(unsigned long hart_id,
                                 unsigned long *state) {
  struct sbiret ret;

  if (!state)
    return -EINVAL;
  ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STATUS,
                  hart_id, 0, 0, 0, 0, 0);
  if (ret.error)
    return sbi_err_map_linux_errno(ret.error);
  *state = ret.value;
  return 0;
}
#endif

long keystone_sbi_sm_detail(struct sbiret ret) {
  /* a1 is a detail channel only when a0 reports failure. Successful calls may
   * legitimately return large counters, event sequences, EIDs, or addresses.
   */
  if (ret.error && ret.value >= SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR &&
      ret.value <= 0xffffffffUL)
    return ret.value;
  if (ret.error >= SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR)
    return ret.error;
  return 0;
}

int keystone_sbi_sm_errno(struct sbiret ret) {
  long detail = keystone_sbi_sm_detail(ret);

  switch (detail) {
    case 0:
      break;
    case SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE:
    case SBI_ERR_SM_ENCLAVE_NOT_RUNNING:
    case SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE:
    case SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED:
    case SBI_ERR_SM_ENCLAVE_NOT_FRESH:
    case SBI_ERR_SM_GROUP_HEARTBEAT_SOURCE_PENDING:
      return -EAGAIN;
    case SBI_ERR_SM_GROUP_BAD_STATE:
    case SBI_ERR_SM_GROUP_COHERENCE_BUSY:
    case SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE:
    case SBI_ERR_SM_YXSTM_PHASE:
    case SBI_ERR_SM_YXSTM_ALREADY_ACQUIRED:
    case SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE:
    case SBI_ERR_SM_GROUP_HEARTBEAT_SEQUENCE:
      return -EBUSY;
    case SBI_ERR_SM_GROUP_STALE_GENERATION:
    case SBI_ERR_SM_ENCLAVE_STALE_GENERATION:
    case SBI_ERR_SM_YXSTM_STALE_EPOCH:
      return -ESTALE;
    case SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE:
    case SBI_ERR_SM_PMP_METADATA_EXHAUSTED:
    case SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED:
    case SBI_ERR_SM_PMP_REGION_MAX_REACHED:
      return -ENOSPC;
    case SBI_ERR_SM_GROUP_COHERENCE_TIMEOUT:
    case SBI_ERR_SM_GROUP_OCALL_TIMEOUT:
      return -ETIMEDOUT;
    case SBI_ERR_SM_GROUP_OCALL_CANCELLED:
    case SBI_ERR_SM_GROUP_OCALL_ABANDONED:
      return -ECANCELED;
    case SBI_ERR_SM_NOT_IMPLEMENTED:
    case SBI_ERR_SM_GROUP_VECTOR_UNSUPPORTED:
      return -EOPNOTSUPP;
    case SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED:
    case SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE:
      return -EACCES;
    case SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT:
    case SBI_ERR_SM_ENCLAVE_INVALID_ID:
    case SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS:
    case SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE:
    case SBI_ERR_SM_YXSTM_NOT_ACQUIRED:
    case SBI_ERR_SM_PMP_REGION_SIZE_INVALID:
    case SBI_ERR_SM_PMP_REGION_NOT_PAGE_GRANULARITY:
    case SBI_ERR_SM_PMP_REGION_NOT_ALIGNED:
    case SBI_ERR_SM_PMP_REGION_INVALID:
    case SBI_ERR_SM_PMP_REGION_OVERLAP:
    case SBI_ERR_SM_PMP_REGION_IMPOSSIBLE_TOR:
    case SBI_ERR_SM_ABI_UNSUPPORTED:
    case SBI_ERR_SM_ABI_BAD_SIZE:
    case SBI_ERR_SM_ABI_BAD_FEATURE:
      return -EINVAL;
    default:
      return -EIO;
  }

  switch (ret.error) {
    case 0:
      return 0;
    case KEYSTONE_SBI_ERR_NOT_SUPPORTED:
      return -EOPNOTSUPP;
    case KEYSTONE_SBI_ERR_INVALID_PARAM:
      return -EINVAL;
    case KEYSTONE_SBI_ERR_DENIED:
      return -EACCES;
    case KEYSTONE_SBI_ERR_INVALID_ADDRESS:
      return -EFAULT;
    case KEYSTONE_SBI_ERR_ALREADY:
      return -EBUSY;
    case KEYSTONE_SBI_ERR_FAILED:
    default:
      return -EIO;
  }
}

struct sbiret sbi_sm_create_enclave(struct keystone_sbi_create_t* args) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_CREATE_ENCLAVE,
      (unsigned long) args, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_run_enclave(unsigned long eid) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_RUN_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_destroy_enclave(unsigned long eid,
                                     unsigned long eid_generation) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_DESTROY_ENCLAVE,
      eid, eid_generation, 0, 0, 0, 0);
}

struct sbiret sbi_sm_resume_enclave(unsigned long eid) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_RESUME_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_set_count(unsigned long group_count) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_SET_COUNT,
      group_count, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_set_hart_count(unsigned long group_id,
                                          unsigned long hart_count) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_SET_HART_COUNT,
      group_id, hart_count, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_query(struct keystone_group_config* config) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_QUERY,
      (unsigned long) config, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_config_topology(
    struct keystone_group_topology* topology) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_CONFIG_TOPOLOGY,
      (unsigned long)topology, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_query_topology(
    struct keystone_group_topology* topology) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_QUERY_TOPOLOGY,
      (unsigned long)topology, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_set_lease_state(
    struct keystone_group_lease* lease) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_SET_LEASE_STATE,
      (unsigned long)lease, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_create(struct keystone_group_config* config) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_CREATE,
      (unsigned long) config, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_activate(struct keystone_group_config* config) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_ACTIVATE,
      (unsigned long) config, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_destroy(struct keystone_group_config* config) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_DESTROY,
      (unsigned long) config, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_bind_enclave(unsigned long eid,
                                        unsigned long hart_id,
                                        unsigned long group_generation,
                                        unsigned long eid_generation,
                                        unsigned long priority,
                                        unsigned long quantum_ticks) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_BIND_ENCLAVE,
      eid, hart_id, group_generation, eid_generation, priority,
      quantum_ticks);
}

struct sbiret sbi_sm_group_host_heartbeat_ack(
    struct keystone_group_heartbeat* heartbeat) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_HOST_HEARTBEAT_ACK,
      (unsigned long)heartbeat, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_enqueue_enclave(unsigned long eid,
                                           unsigned long group_generation,
                                           unsigned long eid_generation) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_ENQUEUE_ENCLAVE,
      eid, group_generation, eid_generation, 0, 0, 0);
}

struct sbiret sbi_sm_group_poll_blocked_ocall(
    struct keystone_group_ocall_status* status) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_POLL_BLOCKED_OCALL,
      (unsigned long) status, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_resume_blocked_ocall(
    struct keystone_group_ocall_status* status) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_RESUME_BLOCKED_OCALL,
      (unsigned long) status, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_run_hart(struct keystone_group_run_hart* run) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_RUN_HART,
      (unsigned long) run, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_run_master(struct keystone_group_run_hart* run) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_RUN_MASTER,
      (unsigned long)run, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_pause_master(
    struct keystone_group_control* control) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_PAUSE_MASTER,
      (unsigned long)control, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_control_enclave(
    struct keystone_group_control* control) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_CONTROL_ENCLAVE,
      (unsigned long) control, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_test_snapshot(
    struct keystone_group_test_snapshot* snapshot) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_TEST_SNAPSHOT,
      (unsigned long)snapshot, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_test_inject(
    struct keystone_group_test_injection* injection) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_TEST_INJECT,
      (unsigned long)injection, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_group_perf_query(
    struct keystone_group_perf_snapshot* snapshot) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
      SBI_SM_GROUP_PERF_QUERY,
      (unsigned long)snapshot, 0, 0, 0, 0, 0);
}
