//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_USER_H_
#define _KEYSTONE_USER_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#include "sm_call.h"

// Linux generic TEE subsystem magic defined in <linux/tee.h>
#define KEYSTONE_IOC_MAGIC 0xa4

// ioctl definition
#define KEYSTONE_IOC_CREATE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x00, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_DESTROY_ENCLAVE \
  _IOW(KEYSTONE_IOC_MAGIC, 0x01, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_RUN_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x04, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_RESUME_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x05, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_FINALIZE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x06, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_UTM_INIT \
  _IOR(KEYSTONE_IOC_MAGIC, 0x07, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_YXSTM_INIT \
  _IOR(KEYSTONE_IOC_MAGIC, 0x08, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OS_ACCESS_STM_RUN_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x09, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OS_ACCESS_STM_RESUME_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0a, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OS_ACCESS_EPM_RUN_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0b, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OS_ACCESS_EPM_RESUME_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0c, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OTHER_OS_ACCESS_EPM_CREATE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0d, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_TEST_OTHER_OS_ACCESS_EPM_FINALIZE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0e, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_UTM_SHARE \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x0f, struct keystone_ioctl_share_utm)
#define KEYSTONE_IOC_GROUP_SET_COUNT \
  _IOW(KEYSTONE_IOC_MAGIC, 0x10, struct keystone_ioctl_group_config)
#define KEYSTONE_IOC_GROUP_SET_HART_COUNT \
  _IOW(KEYSTONE_IOC_MAGIC, 0x11, struct keystone_ioctl_group_config)
#define KEYSTONE_IOC_GROUP_QUERY \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x12, struct keystone_ioctl_group_config)
#define KEYSTONE_IOC_GROUP_BIND_ENCLAVE \
  _IOW(KEYSTONE_IOC_MAGIC, 0x13, struct keystone_ioctl_group_sched)
#define KEYSTONE_IOC_GROUP_ENQUEUE_ENCLAVE \
  _IOW(KEYSTONE_IOC_MAGIC, 0x14, struct keystone_ioctl_group_sched)
#define KEYSTONE_IOC_GROUP_POLL_BLOCKED_OCALL \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x15, struct keystone_ioctl_group_ocall)
#define KEYSTONE_IOC_GROUP_RUN_HART \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x16, struct keystone_ioctl_group_run_hart)
#define KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x17, struct keystone_ioctl_group_ocall)
#define KEYSTONE_IOC_GROUP_CREATE \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x18, struct keystone_ioctl_group_config)
#define KEYSTONE_IOC_GROUP_ACTIVATE \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x19, struct keystone_ioctl_group_config)
#define KEYSTONE_IOC_GROUP_DESTROY \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x1a, struct keystone_ioctl_group_config)
#define KEYSTONE_IOC_GROUP_CONTROL_ENCLAVE \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x1b, struct keystone_ioctl_group_control)
#define KEYSTONE_IOC_GROUP_TEST_SNAPSHOT \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x1c, struct keystone_ioctl_group_test_snapshot)
#define KEYSTONE_IOC_GROUP_TEST_INJECT \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x1d, struct keystone_ioctl_group_test_injection)
#define KEYSTONE_IOC_GROUP_PERF_QUERY \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x1e, struct keystone_ioctl_group_perf_snapshot)
#define KEYSTONE_IOC_GROUP_CONFIG_TOPOLOGY \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x1f, struct keystone_ioctl_group_topology)
#define KEYSTONE_IOC_GROUP_QUERY_TOPOLOGY \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x20, struct keystone_ioctl_group_topology)
#define KEYSTONE_IOC_GROUP_LEASE_WORKERS \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x21, struct keystone_ioctl_group_lease)
#define KEYSTONE_IOC_GROUP_RELEASE_WORKERS \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x22, struct keystone_ioctl_group_lease)
#define KEYSTONE_IOC_GROUP_RUN_MASTER \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x23, struct keystone_ioctl_group_run_hart)
#define KEYSTONE_IOC_GROUP_WAIT_EVENT \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x24, struct keystone_ioctl_group_wait_event)
#define KEYSTONE_IOC_GROUP_PAUSE_MASTER \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x25, struct keystone_ioctl_group_control)
#define KEYSTONE_IOC_GROUP_HOST_HEARTBEAT_ACK \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x26, struct keystone_ioctl_group_heartbeat)
#define KEYSTONE_IOC_GROUP_RESUME_BLOCKED_OCALL_BATCH \
  _IOWR(KEYSTONE_IOC_MAGIC, 0x27, struct keystone_ioctl_group_ocall_batch)

/* Result bits returned in keystone_ioctl_run_enclave.value by the host
 * YXSTM access-denial test. */
#define KEYSTONE_OS_ACCESS_RESULT_READ_DENIED  (1UL << 0)
#define KEYSTONE_OS_ACCESS_RESULT_WRITE_DENIED (1UL << 1)
#define KEYSTONE_OS_ACCESS_RESULT_ALL_DENIED \
  (KEYSTONE_OS_ACCESS_RESULT_READ_DENIED | \
   KEYSTONE_OS_ACCESS_RESULT_WRITE_DENIED)

#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4

#define KEYSTONE_SEC_FLAG_REQUIRED  (1UL << 0)
#define KEYSTONE_SEC_FLAG_EXCLUSIVE (1UL << 1)
#define KEYSTONE_SEC_FLAG_PIO_ONLY  (1UL << 2)

struct keystone_ioctl_create_enclave {
  uintptr_t eid;

  // ms
  uintptr_t ms;
  // engine id
  uintptr_t engine_id;

  // host -> driver
  uintptr_t min_pages; // create
  uintptr_t utm_size; // utm_init
  uintptr_t YXSTM_size; // YXSTM_init
  uintptr_t YXSTM_slice_size;
  uintptr_t YXSTM_bank_count;

  // host -> driver // finalize
  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;
  uintptr_t free_requested;
  uintptr_t sec_paddr;
  uintptr_t sec_size;
  uintptr_t sec_flags;
  uintptr_t sec_engine_id;

  // driver -> host
  uintptr_t epm_paddr;
  uintptr_t epm_size;
  uintptr_t utm_paddr;
  uintptr_t YXSTM_paddr;
};

struct keystone_ioctl_run_enclave {
  uintptr_t eid;
  uintptr_t error;
  uintptr_t value;
  uintptr_t event_sequence;
  uintptr_t scheduler_epoch;
};

/*
 * Special mmap offset to force mapping the enclave's own UTM
 * instead of the shared UTM.
 * 
 * When using shared UTM mode, the default mmap (offset=0) maps the shared UTM.
 * To map the enclave's own UTM for OCALL communication, use this offset.
 * 
 * The value is chosen to be distinguishable from normal page offsets.
 * It represents a "magic" page number that the driver recognizes.
 * 
 * We use 12 for PAGE_SHIFT (4KB pages) which is standard for RISC-V.
 * The resulting offset is 0xDEAD0000000 which is well beyond any real UTM size.
 */
#define KEYSTONE_OWN_UTM_OFFSET  (0xDEAD0000UL << 12)

/* Structure for sharing UTM between enclaves */
struct keystone_ioctl_share_utm {
  uintptr_t owner_eid;    /* Enclave ID that owns the UTM */
  uintptr_t target_eid;   /* Enclave ID to share UTM with */
  uintptr_t utm_paddr;    /* Output: physical address of shared UTM */
  uintptr_t utm_size;     /* Output: size of shared UTM */
};

struct keystone_ioctl_group_config {
  struct keystone_abi_header abi;
  uintptr_t group_count;
  uintptr_t group_id;
  uintptr_t hart_count;
  uintptr_t hart_mask;
  uintptr_t member_capacity;
  uintptr_t member_count;
  uintptr_t lifecycle_state;
  uintptr_t generation;
};

struct keystone_ioctl_group_topology {
  struct keystone_group_topology topology;
};

struct keystone_ioctl_group_lease {
  struct keystone_group_lease lease;
};

struct keystone_ioctl_group_sched {
  struct keystone_abi_header abi;
  uintptr_t eid;
  uintptr_t hart_id;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t eid_generation;
  uintptr_t priority;
  uintptr_t quantum_ticks;
  uintptr_t flags;
  uintptr_t scheduler_epoch;
};

struct keystone_ioctl_group_ocall {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t hart_id;
  uintptr_t eid;
  uintptr_t pending;
  uintptr_t pending_count;
  uintptr_t ocall_id;
  uintptr_t action;
  uintptr_t timeout_cycles;
  uintptr_t result;
  uintptr_t created_at;
  uintptr_t deadline;
  uintptr_t host_cookie;
  uintptr_t flags;
};

#define KEYSTONE_GROUP_OCALL_RESUME_BATCH_MAX 16UL

struct keystone_group_ocall_resume_entry {
  uintptr_t hart_id;
  uintptr_t eid;
  uintptr_t ocall_id;
  uintptr_t result;
};

struct keystone_ioctl_group_ocall_batch {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t count;
  uintptr_t flags;
  uintptr_t resumed_count;
  uintptr_t failed_index;
  struct keystone_group_ocall_resume_entry
      entries[KEYSTONE_GROUP_OCALL_RESUME_BATCH_MAX];
};

struct keystone_ioctl_group_run_hart {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t hart_id;
  uintptr_t eid;
  uintptr_t event;
  uintptr_t error;
  uintptr_t value;
  uintptr_t event_sequence;
  uintptr_t scheduler_epoch;
  uintptr_t queue_overflows;
};

struct keystone_ioctl_group_wait_event {
  struct keystone_group_wait_event wait;
};

struct keystone_ioctl_group_heartbeat {
  struct keystone_group_heartbeat heartbeat;
};

struct keystone_ioctl_group_control {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t eid;
  uintptr_t eid_generation;
  uintptr_t action;
  uintptr_t status;
  uintptr_t scheduler_epoch;
};

struct keystone_ioctl_group_test_snapshot {
  struct keystone_group_test_snapshot snapshot;
};

struct keystone_ioctl_group_test_injection {
  struct keystone_group_test_injection injection;
};

struct keystone_ioctl_group_perf_snapshot {
  struct keystone_group_perf_snapshot snapshot;
};

KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_config_matches_sm,
    sizeof(struct keystone_ioctl_group_config) ==
    sizeof(struct keystone_group_config));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_topology_matches_sm,
    sizeof(struct keystone_ioctl_group_topology) ==
    sizeof(struct keystone_group_topology));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_lease_matches_sm,
    sizeof(struct keystone_ioctl_group_lease) ==
    sizeof(struct keystone_group_lease));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_sched_matches_sm,
    sizeof(struct keystone_ioctl_group_sched) ==
    sizeof(struct keystone_group_sched_config));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_ocall_matches_sm,
    sizeof(struct keystone_ioctl_group_ocall) ==
    sizeof(struct keystone_group_ocall_status));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_ocall_resume_entry_words,
    sizeof(struct keystone_group_ocall_resume_entry) ==
    4 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_ocall_batch_fits_driver_buffer,
    sizeof(struct keystone_ioctl_group_ocall_batch) <= 1024);
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_run_hart_matches_sm,
    sizeof(struct keystone_ioctl_group_run_hart) ==
    sizeof(struct keystone_group_run_hart));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_wait_event_matches_sm,
    sizeof(struct keystone_ioctl_group_wait_event) ==
    sizeof(struct keystone_group_wait_event));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_heartbeat_matches_sm,
    sizeof(struct keystone_ioctl_group_heartbeat) ==
    sizeof(struct keystone_group_heartbeat));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_control_matches_sm,
    sizeof(struct keystone_ioctl_group_control) ==
    sizeof(struct keystone_group_control));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_test_snapshot_matches_sm,
    sizeof(struct keystone_ioctl_group_test_snapshot) ==
    sizeof(struct keystone_group_test_snapshot));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_test_injection_matches_sm,
    sizeof(struct keystone_ioctl_group_test_injection) ==
    sizeof(struct keystone_group_test_injection));
KEYSTONE_ABI_STATIC_ASSERT(ioctl_group_perf_snapshot_matches_sm,
    sizeof(struct keystone_ioctl_group_perf_snapshot) ==
    sizeof(struct keystone_group_perf_snapshot));

#endif
