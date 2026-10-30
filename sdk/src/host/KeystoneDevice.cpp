//******************************************************************************
// Copyright (c) 2020, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "KeystoneDevice.hpp"
#include <cerrno>
#include <sys/mman.h>

namespace Keystone {

static Error groupIoctlError(const struct keystone_abi_header* abi) {
  const uintptr_t detail = abi ? abi->detail : 0;
  const int saved_errno = errno;

  switch (detail) {
    case SBI_ERR_SM_GROUP_BAD_STATE:
    case SBI_ERR_SM_GROUP_COHERENCE_BUSY:
    case SBI_ERR_SM_YXSTM_PHASE:
    case SBI_ERR_SM_YXSTM_ALREADY_ACQUIRED:
    case SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE:
    case SBI_ERR_SM_GROUP_HEARTBEAT_SEQUENCE:
    case SBI_ERR_SM_GROUP_HEARTBEAT_SOURCE_PENDING:
      return Error::GroupBusy;
    case SBI_ERR_SM_GROUP_STALE_GENERATION:
    case SBI_ERR_SM_ENCLAVE_STALE_GENERATION:
    case SBI_ERR_SM_YXSTM_STALE_EPOCH:
      return Error::GroupStale;
    case SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE:
    case SBI_ERR_SM_PMP_METADATA_EXHAUSTED:
    case SBI_ERR_SM_PMP_HW_ENTRIES_EXHAUSTED:
      return Error::GroupNoSpace;
    case SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE:
    case SBI_ERR_SM_ENCLAVE_NOT_RUNNING:
    case SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE:
    case SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED:
    case SBI_ERR_SM_ENCLAVE_NOT_FRESH:
      return Error::GroupNotRunnable;
    case SBI_ERR_SM_GROUP_COHERENCE_TIMEOUT:
      return Error::GroupEventTimeout;
    case SBI_ERR_SM_GROUP_OCALL_TIMEOUT:
      return Error::GroupOcallTimeout;
    case SBI_ERR_SM_GROUP_OCALL_CANCELLED:
      return Error::GroupOcallCancelled;
    case SBI_ERR_SM_GROUP_OCALL_ABANDONED:
      return Error::GroupOcallAbandoned;
    case SBI_ERR_SM_GROUP_VECTOR_UNSUPPORTED:
      return Error::GroupVectorUnsupported;
    case SBI_ERR_SM_ENCLAVE_INTERRUPTED:
    case SBI_ERR_SM_GROUP_PAUSED:
      return Error::EnclaveInterrupted;
    case SBI_ERR_SM_NOT_IMPLEMENTED:
      return Error::GroupNotSupported;
    case SBI_ERR_SM_ENCLAVE_FATAL_FAULT:
    case SBI_ERR_SM_GROUP_WATCHDOG:
      return Error::EnclaveFatalFault;
    case SBI_ERR_SM_GROUP_COHERENCE_OFFLINE:
    case SBI_ERR_SM_GROUP_EVENT_QUEUE_FULL:
      return Error::GroupIOError;
    case SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT:
    case SBI_ERR_SM_ENCLAVE_INVALID_ID:
    case SBI_ERR_SM_ABI_UNSUPPORTED:
    case SBI_ERR_SM_ABI_BAD_SIZE:
    case SBI_ERR_SM_ABI_BAD_FEATURE:
      return Error::GroupInvalidArgument;
    default:
      break;
  }

  switch (saved_errno) {
    case EINVAL:
      return Error::GroupInvalidArgument;
    case EBUSY:
    case EALREADY:
      return Error::GroupBusy;
    case ENOSPC:
      return Error::GroupNoSpace;
    case ESTALE:
      return Error::GroupStale;
    case EAGAIN:
      return Error::GroupNotRunnable;
    case ETIMEDOUT:
      return Error::GroupEventTimeout;
    case ECANCELED:
      return Error::GroupOcallCancelled;
    case EOPNOTSUPP:
      return Error::GroupNotSupported;
    default:
      return Error::GroupIOError;
  }
}

KeystoneDevice::KeystoneDevice() {
  eid = -1;
  fd = -1;
  secPaddr = 0;
  secSize = 0;
  secFlags = 0;
  secEngineId = 0;
}

KeystoneDevice::~KeystoneDevice() {
  if (fd >= 0) {
    close(fd);
    fd = -1;
  }
}

Error
KeystoneDevice::create(uint64_t minPages, uint64_t ms, uint64_t engineId) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.min_pages = minPages;
  encl.ms = ms;
  encl.engine_id = engineId;

  if (ioctl(fd, KEYSTONE_IOC_CREATE_ENCLAVE, &encl)) {
    perror("ioctl error");
    eid = -1;
    return Error::IoctlErrorCreate;
  }

  eid      = encl.eid;
  physAddr = encl.epm_paddr;

  return Error::Success;
}

Error
KeystoneDevice::test_other_os_access_epm_create(uint64_t minPages, uint64_t ms, uint64_t engineId) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.min_pages = minPages;
  encl.ms = ms;
  encl.engine_id = engineId;

  if (ioctl(fd, KEYSTONE_IOC_TEST_OTHER_OS_ACCESS_EPM_CREATE_ENCLAVE, &encl)) {
    perror("ioctl error");
    eid = -1;
    return Error::IoctlErrorCreate;
  }

  eid      = encl.eid;
  physAddr = encl.epm_paddr;

  return Error::Success;
}

uintptr_t
KeystoneDevice::initYXSTM(size_t size, uint64_t _ms) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid        = eid;
  encl.YXSTM_size = size;
  encl.ms         = _ms;
  if (ioctl(fd, KEYSTONE_IOC_YXSTM_INIT, &encl)) {
    return 0;
  }

  return encl.YXSTM_paddr;
}

uintptr_t
KeystoneDevice::initYXSTM(size_t size, uint64_t _ms, uint64_t _engine_id,
                          uint64_t slice_size, uint64_t bank_count) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid        = eid;
  encl.YXSTM_size = size;
  encl.YXSTM_slice_size = slice_size;
  encl.YXSTM_bank_count = bank_count;
  encl.ms         = _ms;
  encl.engine_id  = _engine_id;
  if (ioctl(fd, KEYSTONE_IOC_YXSTM_INIT, &encl)) {
    return 0;
  }

  return encl.YXSTM_paddr;
}

uintptr_t
KeystoneDevice::initUTM(size_t size) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid      = eid;
  encl.utm_size = size;
  if (ioctl(fd, KEYSTONE_IOC_UTM_INIT, &encl)) {
    return 0;
  }

  return encl.utm_paddr;
}

Error
KeystoneDevice::shareUtm(unsigned long owner_eid, unsigned long target_eid,
                         uintptr_t* utm_paddr, size_t* utm_size) {
  struct keystone_ioctl_share_utm share_arg;
  share_arg.owner_eid = owner_eid;
  share_arg.target_eid = target_eid;
  share_arg.utm_paddr = 0;
  share_arg.utm_size = 0;

  if (ioctl(fd, KEYSTONE_IOC_UTM_SHARE, &share_arg)) {
    perror("ioctl error: shareUtm");
    ERROR("Failed to share UTM: owner_eid=%lu target_eid=%lu\n", owner_eid, target_eid);
    return Error::IoctlErrorUTMShare;
  }

  if (utm_paddr) {
    *utm_paddr = share_arg.utm_paddr;
  }
  if (utm_size) {
    *utm_size = share_arg.utm_size;
  }

  return Error::Success;
}

Error
KeystoneDevice::groupSetCount(uint64_t groupCount) {
  struct keystone_ioctl_group_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_count = groupCount;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_SET_COUNT, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupSetCount");
    return error;
  }

  return Error::Success;
}

Error
KeystoneDevice::groupSetHartCount(uint64_t groupId, uint64_t hartCount) {
  struct keystone_ioctl_group_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  cfg.hart_count = hartCount;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_SET_HART_COUNT, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupSetHartCount");
    return error;
  }

  return Error::Success;
}

Error
KeystoneDevice::groupQuery(uint64_t groupId, uint64_t* groupCount,
                           uint64_t* hartCount, uint64_t* hartMask,
                           uint64_t* memberCapacity, uint64_t* memberCount,
                           uint64_t* lifecycleState, uint64_t* generation) {
  struct keystone_ioctl_group_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_QUERY, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupQuery");
    return error;
  }

  if (groupCount)
    *groupCount = cfg.group_count;
  if (hartCount)
    *hartCount = cfg.hart_count;
  if (hartMask)
    *hartMask = cfg.hart_mask;
  if (memberCapacity)
    *memberCapacity = cfg.member_capacity;
  if (memberCount)
    *memberCount = cfg.member_count;
  if (lifecycleState)
    *lifecycleState = cfg.lifecycle_state;
  if (generation)
    *generation = cfg.generation;

  return Error::Success;
}

Error
KeystoneDevice::groupConfigTopology(
    struct keystone_group_topology* topology) {
  struct keystone_ioctl_group_topology cfg;
  if (!topology)
    return Error::GroupInvalidArgument;
  memset(&cfg, 0, sizeof(cfg));
  cfg.topology = *topology;
  KEYSTONE_ABI_INIT(&cfg.topology, KEYSTONE_GROUP_ABI_FEATURES);
  if (ioctl(fd, KEYSTONE_IOC_GROUP_CONFIG_TOPOLOGY, &cfg)) {
    Error error = groupIoctlError(&cfg.topology.abi);
    perror("ioctl error: groupConfigTopology");
    return error;
  }
  *topology = cfg.topology;
  return Error::Success;
}

Error
KeystoneDevice::groupQueryTopology(
    uint64_t groupId, struct keystone_group_topology* topology) {
  struct keystone_ioctl_group_topology cfg;
  if (!topology)
    return Error::GroupInvalidArgument;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg.topology, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.topology.group_id = groupId;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_QUERY_TOPOLOGY, &cfg)) {
    Error error = groupIoctlError(&cfg.topology.abi);
    perror("ioctl error: groupQueryTopology");
    return error;
  }
  *topology = cfg.topology;
  return Error::Success;
}

Error
KeystoneDevice::groupLeaseWorkers(uint64_t groupId, uint64_t flags,
                                   struct keystone_group_lease* lease) {
  struct keystone_ioctl_group_lease cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg.lease, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.lease.group_id = groupId;
  cfg.lease.flags = flags;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_LEASE_WORKERS, &cfg)) {
    Error error = groupIoctlError(&cfg.lease.abi);
    perror("ioctl error: groupLeaseWorkers");
    return error;
  }
  if (lease)
    *lease = cfg.lease;
  return Error::Success;
}

Error
KeystoneDevice::groupReleaseWorkers(uint64_t groupId, uint64_t flags,
                                    struct keystone_group_lease* lease) {
  struct keystone_ioctl_group_lease cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg.lease, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.lease.group_id = groupId;
  cfg.lease.flags = flags;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_RELEASE_WORKERS, &cfg)) {
    Error error = groupIoctlError(&cfg.lease.abi);
    perror("ioctl error: groupReleaseWorkers");
    return error;
  }
  if (lease)
    *lease = cfg.lease;
  return Error::Success;
}

Error
KeystoneDevice::groupCreate(uint64_t groupId, uint64_t memberCapacity) {
  struct keystone_ioctl_group_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  cfg.member_capacity = memberCapacity;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_CREATE, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupCreate");
    return error;
  }
  return Error::Success;
}

Error
KeystoneDevice::groupActivate(uint64_t groupId) {
  struct keystone_ioctl_group_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_QUERY, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupActivate query");
    return error;
  }
  if (ioctl(fd, KEYSTONE_IOC_GROUP_ACTIVATE, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupActivate");
    return error;
  }
  return Error::Success;
}

Error
KeystoneDevice::groupDestroy(uint64_t groupId) {
  struct keystone_ioctl_group_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_QUERY, &cfg))
    return Error::Success;
  if (cfg.lifecycle_state == KEYSTONE_GROUP_STATE_FREE)
    return Error::Success;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_DESTROY, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupDestroy");
    return error;
  }
  return Error::Success;
}

Error
KeystoneDevice::groupBindEnclave(uint64_t bindEid, uint64_t hartId,
                                 uint64_t priority,
                                 uint64_t quantumTicks) {
  struct keystone_ioctl_group_sched cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.eid = bindEid;
  cfg.hart_id = hartId;
  cfg.priority = priority;
  cfg.quantum_ticks = quantumTicks;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_BIND_ENCLAVE, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupBindEnclave");
    return error;
  }

  return Error::Success;
}

Error
KeystoneDevice::groupEnqueueEnclave(uint64_t enqueueEid) {
  struct keystone_ioctl_group_sched cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.eid = enqueueEid;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_ENQUEUE_ENCLAVE, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupEnqueueEnclave");
    return error;
  }

  return Error::Success;
}

Error
KeystoneDevice::groupPollBlockedOcall(uint64_t groupId, uint64_t hartId,
                                      uint64_t* pendingEid,
                                      uint64_t* pendingCount,
                                      uint64_t* ocallId,
                                      uint64_t* timeoutCycles,
                                      uint64_t* hostCookie,
                                      uint64_t* createdAt,
                                      uint64_t* deadline,
                                      uint64_t* flags) {
  struct keystone_ioctl_group_ocall cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  cfg.hart_id = hartId;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_POLL_BLOCKED_OCALL, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupPollBlockedOcall");
    return error;
  }

  if (pendingEid)
    *pendingEid = cfg.pending ? cfg.eid : 0;
  if (pendingCount)
    *pendingCount = cfg.pending_count;
  if (ocallId)
    *ocallId = cfg.ocall_id;
  if (timeoutCycles)
    *timeoutCycles = cfg.timeout_cycles;
  if (hostCookie)
    *hostCookie = cfg.host_cookie;
  if (createdAt)
    *createdAt = cfg.created_at;
  if (deadline)
    *deadline = cfg.deadline;
  if (flags)
    *flags = cfg.flags;

  return Error::Success;
}

Error
KeystoneDevice::groupResumeBlockedOcall(uint64_t groupId, uint64_t hartId,
                                        uint64_t resumeEid, uint64_t ocallId,
                                        uintptr_t result, uint64_t flags) {
  struct keystone_ioctl_group_ocall cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  cfg.hart_id = hartId;
  cfg.eid = resumeEid;
  cfg.ocall_id = ocallId;
  cfg.action = KEYSTONE_GROUP_OCALL_ACTION_RESUME;
  cfg.result = result;
  cfg.flags = flags;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupResumeBlockedOcall");
    return error;
  }

  return Error::Success;
}

Error
KeystoneDevice::groupResumeBlockedOcalls(
    uint64_t groupId,
    const struct keystone_group_ocall_resume_entry* entries,
    uint64_t count, uint64_t* resumedCount) {
  struct keystone_ioctl_group_ocall_batch cfg;

  if (!entries || count == 0 ||
      count > KEYSTONE_GROUP_OCALL_RESUME_BATCH_MAX)
    return Error::GroupInvalidArgument;

  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  cfg.count = count;
  cfg.failed_index = static_cast<uintptr_t>(-1);
  memcpy(cfg.entries, entries, count * sizeof(entries[0]));

  if (ioctl(fd, KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL_BATCH, &cfg)) {
    if (resumedCount)
      *resumedCount = cfg.resumed_count;
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupResumeBlockedOcalls");
    return error;
  }

  if (resumedCount)
    *resumedCount = cfg.resumed_count;
  return Error::Success;
}

Error
KeystoneDevice::groupCancelBlockedOcall(uint64_t groupId, uint64_t hartId,
                                        uint64_t eid, uint64_t ocallId) {
  struct keystone_ioctl_group_ocall cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  cfg.hart_id = hartId;
  cfg.eid = eid;
  cfg.ocall_id = ocallId;
  cfg.action = KEYSTONE_GROUP_OCALL_ACTION_CANCEL;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupCancelBlockedOcall");
    return error;
  }
  return Error::Success;
}

Error
KeystoneDevice::groupAbandonBlockedOcall(uint64_t groupId, uint64_t hartId,
                                          uint64_t eid, uint64_t ocallId,
                                          uint64_t hostCookie) {
  struct keystone_ioctl_group_ocall cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  cfg.hart_id = hartId;
  cfg.eid = eid;
  cfg.ocall_id = ocallId;
  cfg.host_cookie = hostCookie;
  cfg.action = KEYSTONE_GROUP_OCALL_ACTION_ABANDON;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupAbandonBlockedOcall");
    return error;
  }
  return Error::Success;
}

Error
KeystoneDevice::groupRunHart(uint64_t groupId, uint64_t hartId,
                             uint64_t* eventEid, uint64_t* event,
                             uintptr_t* ret, uint64_t* eventSequence,
                             uint64_t* schedulerEpoch,
                             uint64_t* queueOverflows) {
  struct keystone_ioctl_group_run_hart cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  cfg.hart_id = hartId;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_RUN_HART, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupRunHart");
    return error;
  }

  if (eventEid)
    *eventEid = cfg.eid;
  if (event)
    *event = cfg.event;
  if (ret)
    *ret = cfg.value;
  if (eventSequence)
    *eventSequence = cfg.event_sequence;
  if (schedulerEpoch)
    *schedulerEpoch = cfg.scheduler_epoch;
  if (queueOverflows)
    *queueOverflows = cfg.queue_overflows;

  if (cfg.event == KEYSTONE_GROUP_EVENT_FAULT ||
      cfg.event == KEYSTONE_GROUP_EVENT_WATCHDOG)
    return Error::EnclaveFatalFault;
  if (cfg.event == KEYSTONE_GROUP_EVENT_PAUSED)
    return Error::EnclaveInterrupted;
  if (cfg.event == KEYSTONE_GROUP_EVENT_CANCELLED)
    return Error::GroupOcallCancelled;
  if (cfg.event == KEYSTONE_GROUP_EVENT_OCALL_ABANDONED)
    return Error::GroupOcallAbandoned;
  if (cfg.event == KEYSTONE_GROUP_EVENT_HEARTBEAT)
    return Error::GroupIOError;

  switch (cfg.error) {
    case SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST:
      return Error::EdgeCallHost;
    case SBI_ERR_SM_ENCLAVE_INTERRUPTED:
    case SBI_ERR_SM_GROUP_PAUSED:
      return Error::EnclaveInterrupted;
    case SBI_ERR_SM_ENCLAVE_SUCCESS:
      return Error::Success;
    case SBI_ERR_SM_ENCLAVE_FATAL_FAULT:
      return Error::EnclaveFatalFault;
    case SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE:
      return Error::GroupNotRunnable;
    case SBI_ERR_SM_GROUP_COHERENCE_BUSY:
      return Error::GroupCoherenceBusy;
    case SBI_ERR_SM_GROUP_COHERENCE_TIMEOUT:
      return Error::GroupEventTimeout;
    case SBI_ERR_SM_GROUP_COHERENCE_OFFLINE:
    case SBI_ERR_SM_GROUP_EVENT_QUEUE_FULL:
      return Error::GroupIOError;
    case SBI_ERR_SM_GROUP_WATCHDOG:
      return Error::EnclaveFatalFault;
    case SBI_ERR_SM_GROUP_OCALL_TIMEOUT:
      return Error::GroupOcallTimeout;
    case SBI_ERR_SM_GROUP_OCALL_CANCELLED:
      return Error::GroupOcallCancelled;
    case SBI_ERR_SM_GROUP_OCALL_ABANDONED:
      return Error::GroupOcallAbandoned;
    case SBI_ERR_SM_GROUP_BAD_STATE:
      return Error::GroupBusy;
    case SBI_ERR_SM_GROUP_STALE_GENERATION:
    case SBI_ERR_SM_ENCLAVE_STALE_GENERATION:
      return Error::GroupStale;
    case SBI_ERR_SM_GROUP_VECTOR_UNSUPPORTED:
      return Error::GroupVectorUnsupported;
    case SBI_ERR_SM_NOT_IMPLEMENTED:
      return Error::GroupNotSupported;
    default:
      ERROR("Unknown SBI error (%lu) returned by group_run_hart\n",
            (unsigned long)cfg.error);
      return Error::DeviceError;
  }
}

Error
KeystoneDevice::groupRunMaster(uint64_t groupId, uint64_t* eventEid,
                               uint64_t* event, uintptr_t* ret,
                               uint64_t* eventSequence,
                               uint64_t* schedulerEpoch,
                               uint64_t* queueOverflows) {
  struct keystone_ioctl_group_run_hart cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;

  if (ioctl(fd, KEYSTONE_IOC_GROUP_RUN_MASTER, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupRunMaster");
    return error;
  }
  if (eventEid)
    *eventEid = cfg.eid;
  if (event)
    *event = cfg.event;
  if (ret)
    *ret = cfg.value;
  if (eventSequence)
    *eventSequence = cfg.event_sequence;
  if (schedulerEpoch)
    *schedulerEpoch = cfg.scheduler_epoch;
  if (queueOverflows)
    *queueOverflows = cfg.queue_overflows;

  if (cfg.event == KEYSTONE_GROUP_EVENT_FAULT ||
      cfg.event == KEYSTONE_GROUP_EVENT_WATCHDOG)
    return Error::EnclaveFatalFault;
  if (cfg.event == KEYSTONE_GROUP_EVENT_PAUSED)
    return Error::EnclaveInterrupted;
  if (cfg.event == KEYSTONE_GROUP_EVENT_CANCELLED)
    return Error::GroupOcallCancelled;
  if (cfg.event == KEYSTONE_GROUP_EVENT_OCALL_ABANDONED)
    return Error::GroupOcallAbandoned;
  if (cfg.event == KEYSTONE_GROUP_EVENT_HEARTBEAT)
    return Error::GroupIOError;
  switch (cfg.error) {
    case SBI_ERR_SM_ENCLAVE_SUCCESS:
      return Error::Success;
    case SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST:
      return Error::EdgeCallHost;
    case SBI_ERR_SM_ENCLAVE_INTERRUPTED:
    case SBI_ERR_SM_GROUP_PAUSED:
      return Error::EnclaveInterrupted;
    case SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE:
      return Error::GroupNotRunnable;
    case SBI_ERR_SM_ENCLAVE_FATAL_FAULT:
      return Error::EnclaveFatalFault;
    case SBI_ERR_SM_GROUP_COHERENCE_BUSY:
      return Error::GroupCoherenceBusy;
    case SBI_ERR_SM_GROUP_COHERENCE_TIMEOUT:
      return Error::GroupEventTimeout;
    case SBI_ERR_SM_GROUP_COHERENCE_OFFLINE:
    case SBI_ERR_SM_GROUP_EVENT_QUEUE_FULL:
      return Error::GroupIOError;
    case SBI_ERR_SM_GROUP_WATCHDOG:
      return Error::EnclaveFatalFault;
    case SBI_ERR_SM_GROUP_OCALL_TIMEOUT:
      return Error::GroupOcallTimeout;
    case SBI_ERR_SM_GROUP_OCALL_CANCELLED:
      return Error::GroupOcallCancelled;
    case SBI_ERR_SM_GROUP_OCALL_ABANDONED:
      return Error::GroupOcallAbandoned;
    case SBI_ERR_SM_GROUP_BAD_STATE:
      return Error::GroupBusy;
    case SBI_ERR_SM_GROUP_STALE_GENERATION:
    case SBI_ERR_SM_ENCLAVE_STALE_GENERATION:
      return Error::GroupStale;
    case SBI_ERR_SM_GROUP_VECTOR_UNSUPPORTED:
      return Error::GroupVectorUnsupported;
    case SBI_ERR_SM_NOT_IMPLEMENTED:
      return Error::GroupNotSupported;
    default:
      ERROR("Unknown SBI error (%lu) returned by group_run_master\n",
            (unsigned long)cfg.error);
      return Error::DeviceError;
  }
}

Error
KeystoneDevice::groupWaitEvent(
    uint64_t groupId, uint64_t eventMask, uint64_t timeoutMs,
    struct keystone_group_wait_event* event) {
  struct keystone_ioctl_group_wait_event cfg;
  if (!event)
    return Error::GroupInvalidArgument;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg.wait, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.wait.group_id = groupId;
  cfg.wait.event_mask = eventMask;
  cfg.wait.timeout_ms = timeoutMs;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_WAIT_EVENT, &cfg)) {
    int saved_errno = errno;
    Error error = groupIoctlError(&cfg.wait.abi);
    if (saved_errno == ETIMEDOUT || saved_errno == EAGAIN)
      return Error::GroupEventTimeout;
    perror("ioctl error: groupWaitEvent");
    return error;
  }
  *event = cfg.wait;
  if (cfg.wait.event == KEYSTONE_GROUP_EVENT_FAULT ||
      cfg.wait.event == KEYSTONE_GROUP_EVENT_WATCHDOG)
    return Error::EnclaveFatalFault;
  if (cfg.wait.event == KEYSTONE_GROUP_EVENT_PAUSED)
    return Error::EnclaveInterrupted;
  if (cfg.wait.event == KEYSTONE_GROUP_EVENT_CANCELLED)
    return Error::GroupOcallCancelled;
  if (cfg.wait.event == KEYSTONE_GROUP_EVENT_OCALL_ABANDONED)
    return Error::GroupOcallAbandoned;
  if (cfg.wait.event == KEYSTONE_GROUP_EVENT_HEARTBEAT)
    return Error::GroupIOError;

  switch (cfg.wait.error) {
    case SBI_ERR_SM_ENCLAVE_SUCCESS:
    case SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST:
      return Error::Success;
    case SBI_ERR_SM_ENCLAVE_INTERRUPTED:
    case SBI_ERR_SM_GROUP_PAUSED:
      return Error::EnclaveInterrupted;
    case SBI_ERR_SM_ENCLAVE_FATAL_FAULT:
      return Error::EnclaveFatalFault;
    case SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE:
      return Error::GroupNotRunnable;
    case SBI_ERR_SM_GROUP_COHERENCE_BUSY:
      return Error::GroupCoherenceBusy;
    case SBI_ERR_SM_GROUP_COHERENCE_TIMEOUT:
      return Error::GroupEventTimeout;
    case SBI_ERR_SM_GROUP_OCALL_TIMEOUT:
      return Error::GroupOcallTimeout;
    case SBI_ERR_SM_GROUP_OCALL_CANCELLED:
      return Error::GroupOcallCancelled;
    case SBI_ERR_SM_GROUP_OCALL_ABANDONED:
      return Error::GroupOcallAbandoned;
    case SBI_ERR_SM_GROUP_BAD_STATE:
      return Error::GroupBusy;
    case SBI_ERR_SM_GROUP_STALE_GENERATION:
    case SBI_ERR_SM_ENCLAVE_STALE_GENERATION:
      return Error::GroupStale;
    case SBI_ERR_SM_NOT_IMPLEMENTED:
      return Error::GroupNotSupported;
    case SBI_ERR_SM_GROUP_VECTOR_UNSUPPORTED:
      return Error::GroupVectorUnsupported;
    default:
      ERROR("Unknown group event error (%lu)\n",
            (unsigned long)cfg.wait.error);
      return Error::GroupIOError;
  }
}

Error
KeystoneDevice::groupPauseMaster(uint64_t groupId, uint64_t* status,
                                 uint64_t* schedulerEpoch) {
  struct keystone_ioctl_group_control cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.group_id = groupId;
  cfg.action = KEYSTONE_GROUP_CONTROL_PAUSE;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_PAUSE_MASTER, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupPauseMaster");
    return error;
  }
  if (status)
    *status = cfg.status;
  if (schedulerEpoch)
    *schedulerEpoch = cfg.scheduler_epoch;
  return Error::Success;
}

Error
KeystoneDevice::groupControlEnclave(uint64_t eid, uint64_t action,
                                    uint64_t* status,
                                    uint64_t* schedulerEpoch) {
  struct keystone_ioctl_group_control cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg, KEYSTONE_GROUP_ABI_FEATURES);
  cfg.eid = eid;
  cfg.action = action;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_CONTROL_ENCLAVE, &cfg)) {
    Error error = groupIoctlError(&cfg.abi);
    perror("ioctl error: groupControlEnclave");
    return error;
  }
  if (status)
    *status = cfg.status;
  if (schedulerEpoch)
    *schedulerEpoch = cfg.scheduler_epoch;
  return Error::Success;
}

Error
KeystoneDevice::groupTestSnapshot(
    uint64_t groupId, struct keystone_group_test_snapshot* snapshot) {
  struct keystone_ioctl_group_test_snapshot cfg;
  if (!snapshot)
    return Error::GroupInvalidArgument;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg.snapshot, KEYSTONE_GROUP_TEST_ABI_FEATURES);
  cfg.snapshot.group_id = groupId;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_TEST_SNAPSHOT, &cfg)) {
    Error error = groupIoctlError(&cfg.snapshot.abi);
    perror("ioctl error: groupTestSnapshot");
    return error;
  }
  *snapshot = cfg.snapshot;
  return Error::Success;
}

Error
KeystoneDevice::groupTestInject(uint64_t operation, uint64_t groupId,
                                uint64_t hartId, uint64_t count) {
  struct keystone_ioctl_group_test_injection cfg;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg.injection, KEYSTONE_GROUP_TEST_ABI_FEATURES);
  cfg.injection.operation = operation;
  cfg.injection.group_id = groupId;
  cfg.injection.hart_id = hartId;
  cfg.injection.count = count;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_TEST_INJECT, &cfg)) {
    Error error = groupIoctlError(&cfg.injection.abi);
    perror("ioctl error: groupTestInject");
    return error;
  }
  return Error::Success;
}

Error
KeystoneDevice::groupPerfQuery(
    uint64_t groupId, uint64_t operation,
    struct keystone_group_perf_snapshot* snapshot,
    uint64_t memberEid) {
  struct keystone_ioctl_group_perf_snapshot cfg;
  if (!snapshot)
    return Error::GroupInvalidArgument;
  memset(&cfg, 0, sizeof(cfg));
  KEYSTONE_ABI_INIT(&cfg.snapshot, KEYSTONE_GROUP_PERF_ABI_FEATURES);
  cfg.snapshot.group_id = groupId;
  cfg.snapshot.operation = operation;
  cfg.snapshot.member_query = memberEid ? 1 : 0;
  cfg.snapshot.member_eid = memberEid;
  if (ioctl(fd, KEYSTONE_IOC_GROUP_PERF_QUERY, &cfg)) {
    Error error = groupIoctlError(&cfg.snapshot.abi);
    perror("ioctl error: groupPerfQuery");
    return error;
  }
  *snapshot = cfg.snapshot;
  return Error::Success;
}

Error
KeystoneDevice::finalize(
    uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
    uintptr_t freeRequested) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid            = eid;
  encl.runtime_paddr  = runtimePhysAddr;
  encl.user_paddr     = eappPhysAddr;
  encl.free_paddr     = freePhysAddr;
  encl.free_requested = freeRequested;
  encl.sec_paddr      = secPaddr;
  encl.sec_size       = secSize;
  encl.sec_flags      = secFlags;
  encl.sec_engine_id  = secEngineId;

  if (ioctl(fd, KEYSTONE_IOC_FINALIZE_ENCLAVE, &encl)) {
    perror("ioctl error");
    eid = -1;
    return Error::IoctlErrorFinalize;
  }
  return Error::Success;
}

Error
KeystoneDevice::test_other_os_access_epm_finalize(
    uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
    uintptr_t freeRequested) {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid            = eid;
  encl.runtime_paddr  = runtimePhysAddr;
  encl.user_paddr     = eappPhysAddr;
  encl.free_paddr     = freePhysAddr;
  encl.free_requested = freeRequested;
  encl.sec_paddr      = secPaddr;
  encl.sec_size       = secSize;
  encl.sec_flags      = secFlags;
  encl.sec_engine_id  = secEngineId;

  if (ioctl(fd, KEYSTONE_IOC_TEST_OTHER_OS_ACCESS_EPM_FINALIZE_ENCLAVE, &encl)) {
    perror("ioctl error");
    eid = -1;
    return Error::IoctlErrorFinalize;
  }
  return Error::Success;
}

Error
KeystoneDevice::destroy() {
  struct keystone_ioctl_create_enclave encl;
  memset(&encl, 0, sizeof(encl));
  encl.eid = eid;

  /* if the enclave has never created */
  if (eid < 0) {
    return Error::Success;
  }

  if (ioctl(fd, KEYSTONE_IOC_DESTROY_ENCLAVE, &encl)) {
    perror("ioctl error");
    return Error::IoctlErrorDestroy;
  }

  eid = -1;
  return Error::Success;
}

Error
KeystoneDevice::__run(bool resume, uintptr_t* ret) {
  struct keystone_ioctl_run_enclave encl;
  encl.eid = eid;

  Error error;
  uint64_t request;

  if (resume) {
    error   = Error::IoctlErrorResume;
    request = KEYSTONE_IOC_RESUME_ENCLAVE;
  } else {
    error   = Error::IoctlErrorRun;
    request = KEYSTONE_IOC_RUN_ENCLAVE;
  }

  if (ioctl(fd, request, &encl)) {
    return error;
  }

  switch (encl.error) {
    case SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST:
      return Error::EdgeCallHost;
    case SBI_ERR_SM_ENCLAVE_INTERRUPTED:
      /*
       * Group-enclave timer preemption is owned by the SM scheduler and should
       * not reach this path. A host-visible interruption now means an explicit
       * host pause or another non-timer stop that the caller must handle.
       */
      return Error::EnclaveInterrupted;
    case SBI_ERR_SM_ENCLAVE_SUCCESS:
      if (ret) {
        *ret = encl.value;
      }
      return Error::Success;
    case SBI_ERR_SM_ENCLAVE_FATAL_FAULT:
      if (ret) {
        *ret = encl.value;
      }
      return Error::EnclaveFatalFault;
    default:
      ERROR(
          "Unknown SBI error (%lu) returned by %s_enclave\n",
          (unsigned long)encl.error,
          resume ? "resume" : "run");
      return error;
  }
}

Error
KeystoneDevice::run(uintptr_t* ret) {
  return __run(false, ret);
}

Error
KeystoneDevice::resume(uintptr_t* ret) {
  return __run(true, ret);
}

Error
KeystoneDevice::test_os_access_run(uintptr_t* ret, bool test_os_access_stm) {
  return __test_os_access_run(test_os_access_stm, false, ret);
}

Error
KeystoneDevice::test_os_access_resume(uintptr_t* ret, bool test_os_access_stm) {
  return __test_os_access_run(test_os_access_stm, true, ret);
}

Error
KeystoneDevice::__test_os_access_run(bool test_os_access_stm, bool resume, uintptr_t* ret) {
  struct keystone_ioctl_run_enclave encl;
  encl.eid = eid;

  Error error;
  uint64_t request;

  if (resume) {
    if (test_os_access_stm) {
      error   = Error::IoctlErrorResume;
      request = KEYSTONE_IOC_TEST_OS_ACCESS_STM_RESUME_ENCLAVE;
    } else {
      error   = Error::IoctlErrorResume;
      request = KEYSTONE_IOC_TEST_OS_ACCESS_EPM_RESUME_ENCLAVE;
    }
  } else {
    if (test_os_access_stm) {
      error   = Error::IoctlErrorRun;
      request = KEYSTONE_IOC_TEST_OS_ACCESS_STM_RUN_ENCLAVE;
    } else {
      error   = Error::IoctlErrorResume;
      request = KEYSTONE_IOC_TEST_OS_ACCESS_EPM_RUN_ENCLAVE;
    }
  }

  if (ioctl(fd, request, &encl)) {
    return error;
  }

  switch (encl.error) {
    case SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST:
      return Error::EdgeCallHost;
    case SBI_ERR_SM_ENCLAVE_INTERRUPTED:
      /*
       * Group-enclave timer preemption is owned by the SM scheduler and should
       * not reach this path. A host-visible interruption now means an explicit
       * host pause or another non-timer stop that the caller must handle.
       */
      return Error::EnclaveInterrupted;
    case SBI_ERR_SM_ENCLAVE_SUCCESS:
      if (ret) {
        *ret = encl.value;
      }
      return Error::Success;
    case SBI_ERR_SM_ENCLAVE_FATAL_FAULT:
      if (ret) {
        *ret = encl.value;
      }
      return Error::EnclaveFatalFault;
    default:
      ERROR(
          "Unknown SBI error (%lu) returned by %s_enclave\n",
          (unsigned long)encl.error,
          resume ? "resume" : "run");
      return error;
  }
}

void*
KeystoneDevice::map(uintptr_t addr, size_t size) {
  assert(fd >= 0);
  void* ret;
  ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, addr);
  if (ret == MAP_FAILED) {
    perror("KeystoneDevice::map: mmap");
    return NULL;
  }
  return ret;
}

void*
KeystoneDevice::mapOwnUtm(size_t size) {
  /*
   * Map the enclave's own UTM for OCALL communication.
   * 
   * In shared UTM mode, the enclave has two UTM regions:
   * 1. Shared UTM (from owner enclave) - for data transfer
   * 2. Own UTM - for OCALL edge_call communication
   * 
   * The Runtime uses the enclave's own UTM for edge_call structures,
   * so the Host must map this separately to handle OCALLs correctly.
   * 
   * We use a special offset (KEYSTONE_OWN_UTM_OFFSET) to tell the driver
   * to map the enclave's own UTM instead of the shared UTM.
   */
  assert(fd >= 0);
  void* ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 
                   KEYSTONE_OWN_UTM_OFFSET);
  if (ret == MAP_FAILED) {
    perror("mapOwnUtm: mmap failed");
    return NULL;
  }
  return ret;
}

bool
KeystoneDevice::initDevice(Params params) { // TODO: why does this need params
  /* open device driver */
  fd = open(KEYSTONE_DEV_PATH, O_RDWR);
  if (fd < 0) {
    PERROR("cannot open device file");
    return false;
  }
  secPaddr = params.getSecPaddr();
  secSize = params.getSecSize();
  secFlags = params.getSecFlags();
  secEngineId = params.getSecEngineID();
  return true;
}

Error
MockKeystoneDevice::create(uint64_t minPages, uint64_t ms, uint64_t engineId) {
  eid = -1;
  return Error::Success;
}

Error
MockKeystoneDevice::test_other_os_access_epm_create(uint64_t minPages, uint64_t ms, uint64_t engineId) {
  eid = -1;
  return Error::Success;
}

uintptr_t
MockKeystoneDevice::initUTM(size_t size) {
  return 0;
}

Error
MockKeystoneDevice::shareUtm(unsigned long owner_eid, unsigned long target_eid,
                             uintptr_t* utm_paddr, size_t* utm_size) {
  // Mock implementation - just return success
  if (utm_paddr) {
    *utm_paddr = 0;
  }
  if (utm_size) {
    *utm_size = 0;
  }
  return Error::Success;
}

Error
MockKeystoneDevice::groupSetCount(uint64_t groupCount) {
  return Error::Success;
}

Error
MockKeystoneDevice::groupSetHartCount(uint64_t groupId, uint64_t hartCount) {
  return Error::Success;
}

Error
MockKeystoneDevice::groupQuery(uint64_t groupId, uint64_t* groupCount,
                               uint64_t* hartCount, uint64_t* hartMask,
                               uint64_t* memberCapacity, uint64_t* memberCount,
                               uint64_t* lifecycleState, uint64_t* generation) {
  if (groupCount)
    *groupCount = 1;
  if (hartCount)
    *hartCount = 4;
  if (hartMask)
    *hartMask = (1UL << KEYSTONE_VF2_HOUSEKEEPING_HART) |
                KEYSTONE_VF2_WORKER_HART_MASK;
  if (memberCapacity)
    *memberCapacity = KEYSTONE_GROUP_MEMBER_LIMIT;
  if (memberCount)
    *memberCount = 0;
  if (lifecycleState)
    *lifecycleState = KEYSTONE_GROUP_STATE_ACTIVE;
  if (generation)
    *generation = 1;
  return Error::Success;
}

Error
MockKeystoneDevice::groupConfigTopology(
    struct keystone_group_topology* topology) {
  if (!topology)
    return Error::DeviceError;
  KEYSTONE_ABI_INIT(topology, KEYSTONE_GROUP_ABI_FEATURES);
  topology->group_generation = topology->group_generation ?
      topology->group_generation : 1;
  topology->status = 0;
  return Error::Success;
}

Error
MockKeystoneDevice::groupQueryTopology(
    uint64_t groupId, struct keystone_group_topology* topology) {
  if (!topology)
    return Error::DeviceError;
  memset(topology, 0, sizeof(*topology));
  KEYSTONE_ABI_INIT(topology, KEYSTONE_GROUP_ABI_FEATURES);
  topology->group_id = groupId;
  topology->group_generation = 1;
  topology->execution_mode = GROUP_MODE_3W_1HM;
  topology->housekeeping_cpu = KEYSTONE_VF2_HOUSEKEEPING_CPU;
  topology->housekeeping_hart = KEYSTONE_VF2_HOUSEKEEPING_HART;
  topology->master_hart = KEYSTONE_VF2_HOUSEKEEPING_HART;
  topology->worker_hart_mask = KEYSTONE_VF2_WORKER_HART_MASK;
  topology->worker_count = 3;
  topology->configured_hart_mask =
      (1UL << KEYSTONE_VF2_HOUSEKEEPING_HART) |
      KEYSTONE_VF2_WORKER_HART_MASK;
  topology->cpu_hart_offset = KEYSTONE_VF2_CPU_HART_OFFSET;
  topology->lease_state = KEYSTONE_GROUP_LEASE_FREE;
  topology->topology_epoch = 1;
  return Error::Success;
}

Error
MockKeystoneDevice::groupLeaseWorkers(
    uint64_t groupId, uint64_t flags, struct keystone_group_lease* lease) {
  if (lease) {
    memset(lease, 0, sizeof(*lease));
    KEYSTONE_ABI_INIT(lease, KEYSTONE_GROUP_ABI_FEATURES);
    lease->group_id = groupId;
    lease->group_generation = 1;
    lease->worker_hart_mask = KEYSTONE_VF2_WORKER_HART_MASK;
    lease->lease_state = KEYSTONE_GROUP_LEASE_LEASED;
    lease->flags = flags;
  }
  return Error::Success;
}

Error
MockKeystoneDevice::groupReleaseWorkers(
    uint64_t groupId, uint64_t flags, struct keystone_group_lease* lease) {
  if (lease) {
    memset(lease, 0, sizeof(*lease));
    KEYSTONE_ABI_INIT(lease, KEYSTONE_GROUP_ABI_FEATURES);
    lease->group_id = groupId;
    lease->group_generation = 1;
    lease->worker_hart_mask = KEYSTONE_VF2_WORKER_HART_MASK;
    lease->lease_state = KEYSTONE_GROUP_LEASE_FREE;
    lease->flags = flags;
  }
  return Error::Success;
}

Error
MockKeystoneDevice::groupCreate(uint64_t groupId, uint64_t memberCapacity) {
  return Error::Success;
}

Error
MockKeystoneDevice::groupActivate(uint64_t groupId) {
  return Error::Success;
}

Error
MockKeystoneDevice::groupDestroy(uint64_t groupId) {
  return Error::Success;
}

Error
MockKeystoneDevice::groupBindEnclave(uint64_t eid, uint64_t hartId,
                                     uint64_t priority,
                                     uint64_t quantumTicks) {
  (void)eid;
  (void)hartId;
  (void)priority;
  (void)quantumTicks;
  return Error::Success;
}

Error
MockKeystoneDevice::groupEnqueueEnclave(uint64_t eid) {
  return Error::Success;
}

Error
MockKeystoneDevice::groupPollBlockedOcall(uint64_t groupId, uint64_t hartId,
                                          uint64_t* pendingEid,
                                          uint64_t* pendingCount,
                                          uint64_t* ocallId,
                                          uint64_t* timeoutCycles,
                                          uint64_t* hostCookie,
                                          uint64_t* createdAt,
                                          uint64_t* deadline,
                                          uint64_t* flags) {
  if (pendingEid)
    *pendingEid = 0;
  if (pendingCount)
    *pendingCount = 0;
  if (ocallId)
    *ocallId = 0;
  if (timeoutCycles)
    *timeoutCycles = 0;
  if (hostCookie)
    *hostCookie = 0;
  if (createdAt)
    *createdAt = 0;
  if (deadline)
    *deadline = 0;
  if (flags)
    *flags = 0;
  return Error::Success;
}

Error
MockKeystoneDevice::groupResumeBlockedOcall(uint64_t groupId, uint64_t hartId,
                                            uint64_t eid, uint64_t ocallId,
                                            uintptr_t result,
                                            uint64_t flags) {
  (void)groupId;
  (void)hartId;
  (void)eid;
  (void)ocallId;
  (void)result;
  (void)flags;
  return Error::Success;
}

Error
MockKeystoneDevice::groupResumeBlockedOcalls(
    uint64_t groupId,
    const struct keystone_group_ocall_resume_entry* entries,
    uint64_t count, uint64_t* resumedCount) {
  (void)groupId;
  (void)entries;
  if (count == 0 || count > KEYSTONE_GROUP_OCALL_RESUME_BATCH_MAX)
    return Error::GroupInvalidArgument;
  if (resumedCount)
    *resumedCount = count;
  return Error::Success;
}

Error
MockKeystoneDevice::groupCancelBlockedOcall(uint64_t groupId, uint64_t hartId,
                                             uint64_t eid, uint64_t ocallId) {
  return Error::Success;
}

Error
MockKeystoneDevice::groupAbandonBlockedOcall(uint64_t groupId,
                                              uint64_t hartId,
                                              uint64_t eid,
                                              uint64_t ocallId,
                                              uint64_t hostCookie) {
  (void)groupId;
  (void)hartId;
  (void)eid;
  (void)ocallId;
  (void)hostCookie;
  return Error::Success;
}

Error
MockKeystoneDevice::groupRunHart(uint64_t groupId, uint64_t hartId,
                                 uint64_t* eventEid, uint64_t* event,
                                 uintptr_t* ret, uint64_t* eventSequence,
                                 uint64_t* schedulerEpoch,
                                 uint64_t* queueOverflows) {
  if (eventEid)
    *eventEid = 0;
  if (event)
    *event = KEYSTONE_GROUP_EVENT_NONE;
  if (ret)
    *ret = 0;
  if (eventSequence)
    *eventSequence = 0;
  if (schedulerEpoch)
    *schedulerEpoch = 0;
  if (queueOverflows)
    *queueOverflows = 0;
  return Error::Success;
}

Error
MockKeystoneDevice::groupRunMaster(
    uint64_t groupId, uint64_t* eventEid, uint64_t* event,
    uintptr_t* ret, uint64_t* eventSequence, uint64_t* schedulerEpoch,
    uint64_t* queueOverflows) {
  return groupRunHart(groupId, KEYSTONE_VF2_HOUSEKEEPING_HART,
                      eventEid, event, ret, eventSequence,
                      schedulerEpoch, queueOverflows);
}

Error
MockKeystoneDevice::groupWaitEvent(
    uint64_t groupId, uint64_t eventMask, uint64_t timeoutMs,
    struct keystone_group_wait_event* event) {
  (void)eventMask;
  (void)timeoutMs;
  if (!event)
    return Error::DeviceError;
  memset(event, 0, sizeof(*event));
  KEYSTONE_ABI_INIT(event, KEYSTONE_GROUP_ABI_FEATURES);
  event->group_id = groupId;
  event->group_generation = 1;
  event->event = KEYSTONE_GROUP_EVENT_WORKERS_READY;
  return Error::Success;
}

Error
MockKeystoneDevice::groupPauseMaster(uint64_t groupId, uint64_t* status,
                                     uint64_t* schedulerEpoch) {
  (void)groupId;
  if (status)
    *status = KEYSTONE_GROUP_CONTROL_APPLIED;
  if (schedulerEpoch)
    *schedulerEpoch = 0;
  return Error::Success;
}

Error
MockKeystoneDevice::groupControlEnclave(uint64_t eid, uint64_t action,
                                        uint64_t* status,
                                        uint64_t* schedulerEpoch) {
  if (status)
    *status = KEYSTONE_GROUP_CONTROL_APPLIED;
  if (schedulerEpoch)
    *schedulerEpoch = 0;
  return Error::Success;
}

Error
MockKeystoneDevice::groupTestSnapshot(
    uint64_t groupId, struct keystone_group_test_snapshot* snapshot) {
  if (!snapshot)
    return Error::DeviceError;
  memset(snapshot, 0, sizeof(*snapshot));
  KEYSTONE_ABI_INIT(snapshot, KEYSTONE_GROUP_TEST_ABI_FEATURES);
  snapshot->group_id = groupId;
  return Error::Success;
}

Error
MockKeystoneDevice::groupTestInject(uint64_t operation, uint64_t groupId,
                                    uint64_t hartId, uint64_t count) {
  (void)operation;
  (void)groupId;
  (void)hartId;
  (void)count;
  return Error::Success;
}

Error
MockKeystoneDevice::groupPerfQuery(
    uint64_t groupId, uint64_t operation,
    struct keystone_group_perf_snapshot* snapshot,
    uint64_t memberEid) {
  (void)operation;
  if (!snapshot)
    return Error::DeviceError;
  memset(snapshot, 0, sizeof(*snapshot));
  KEYSTONE_ABI_INIT(snapshot, KEYSTONE_GROUP_PERF_ABI_FEATURES);
  snapshot->group_id = groupId;
  snapshot->operation = operation;
  snapshot->member_query = memberEid ? 1 : 0;
  snapshot->member_eid = memberEid;
  snapshot->cycle_source = KEYSTONE_GROUP_PERF_CYCLE_MCYCLE;
  return Error::Success;
}

uintptr_t
MockKeystoneDevice::initYXSTM(size_t size, uint64_t _ms) {
  return 0;
}

uintptr_t
MockKeystoneDevice::initYXSTM(size_t size, uint64_t _ms, uint64_t _engine_id,
                              uint64_t slice_size, uint64_t bank_count) {
  (void)slice_size;
  (void)bank_count;
  return 0;
}

Error
MockKeystoneDevice::finalize(
    uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
    uintptr_t freeRequested) {
  return Error::Success;
}

Error
MockKeystoneDevice::test_other_os_access_epm_finalize(
    uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
    uintptr_t freeRequested) {
  return Error::Success;
}

Error
MockKeystoneDevice::destroy() {
  return Error::Success;
}

Error
MockKeystoneDevice::run(uintptr_t* ret) {
  return Error::Success;
}

Error
MockKeystoneDevice::resume(uintptr_t* ret) {
  return Error::Success;
}


Error
MockKeystoneDevice::test_os_access_run(uintptr_t* ret, bool test_os_access_stm) {
  return Error::Success;
}

Error
MockKeystoneDevice::test_os_access_resume(uintptr_t* ret, bool test_os_access_stm) {
  return Error::Success;
}

bool
MockKeystoneDevice::initDevice(Params params) {
  return true;
}

void*
MockKeystoneDevice::map(uintptr_t addr, size_t size) {
  sharedBuffer = malloc(size);
  return sharedBuffer;
}

void*
MockKeystoneDevice::mapOwnUtm(size_t size) {
  /* For mock device, just allocate a separate buffer */
  return malloc(size);
}

MockKeystoneDevice::~MockKeystoneDevice() {
  if (sharedBuffer) free(sharedBuffer);
}

}  // namespace Keystone
