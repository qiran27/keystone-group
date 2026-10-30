//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include "ipi.h"
#include "platform-hook.h"
#include "safe_math_util.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_ipi.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_timer.h>

struct enclave enclaves[ENCL_MAX];

static const char group_deferred_wakeup_ipi_marker[]
    __attribute__((used)) = "keystone-group-deferred-wakeup-ipi-v1";

ms_group ms_group_list[MAX_MS_GROUP]; // 从属 enclave 组列表

static volatile int YXSTM_sm_init = 0;
static volatile int YXSTM_sm_fleible = 0;
static volatile int sm_engine_id = 0;
static volatile int kg_ready = 0;
static volatile int SEC_sm_init = -1;
static volatile int SEC_sm_fleible = 0;
static volatile uintptr_t SEC_sm_base = 0;
static volatile uintptr_t SEC_sm_size = 0;
static volatile uintptr_t SEC_sm_flags = 0;
static volatile uintptr_t SEC_sm_engine_id = 0;

#if ENCL_MAX != 65
#error "group scheduler ABI requires ENCL_MAX=65"
#endif
#if KEYSTONE_GROUP_MEMBER_LIMIT != ENCL_MAX
#error "group member ABI limit must match ENCL_MAX"
#endif
#define KEYSTONE_GROUP_MAX_MEMBERS KEYSTONE_GROUP_MEMBER_LIMIT
#define KEYSTONE_GROUP_MAX_REGIONS 8
#define KEYSTONE_GROUP_MAX_ALLOWED_SHARED_REGIONS \
  (KEYSTONE_GROUP_MAX_REGIONS + \
   KEYSTONE_YXSTM_MAX_BANKS * KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
#define KEYSTONE_GROUP_SCHED_MAX_RUNQUEUE KEYSTONE_GROUP_MAX_MEMBERS
#define KEYSTONE_GROUP_MAX_CONFIGURED_HARTS 4
#define KEYSTONE_GROUP_MAX_WORKER_LANES 3
#ifndef KEYSTONE_GROUP_SCHED_TIMER_DELTA
#define KEYSTONE_GROUP_SCHED_TIMER_DELTA 10000000
#endif
#ifndef KEYSTONE_GROUP_SCHED_QUANTUM_US
#define KEYSTONE_GROUP_SCHED_QUANTUM_US 10000UL
#endif
#ifndef KEYSTONE_GROUP_TIMER_PREEMPT
#define KEYSTONE_GROUP_TIMER_PREEMPT 1
#endif
#ifndef KEYSTONE_GROUP_HOST_SERVICE_INTERVAL_TICKS
#define KEYSTONE_GROUP_HOST_SERVICE_INTERVAL_TICKS 10UL
#endif
#ifndef KEYSTONE_GROUP_HOST_SERVICE_INTERVAL_US
#define KEYSTONE_GROUP_HOST_SERVICE_INTERVAL_US \
  (KEYSTONE_GROUP_SCHED_QUANTUM_US * \
   KEYSTONE_GROUP_HOST_SERVICE_INTERVAL_TICKS)
#endif
#ifndef KEYSTONE_GROUP_STARTUP_TRACE
#define KEYSTONE_GROUP_STARTUP_TRACE 0
#endif
#ifndef KEYSTONE_GROUP_TIMER_TRACE
#define KEYSTONE_GROUP_TIMER_TRACE 0
#endif
#ifndef KEYSTONE_GROUP_OCALL_TRACE
#define KEYSTONE_GROUP_OCALL_TRACE 0
#endif
#define KEYSTONE_GROUP_COHERENCE_TIMEOUT_CYCLES KEYSTONE_GROUP_SCHED_TIMER_DELTA
#define KEYSTONE_GROUP_EVENT_QUEUE_DEPTH 256
#define KEYSTONE_GROUP_WATCHDOG_CYCLES (KEYSTONE_GROUP_SCHED_TIMER_DELTA * 128UL)
#define KEYSTONE_GROUP_OCALL_TIMEOUT_CYCLES (KEYSTONE_GROUP_SCHED_TIMER_DELTA * 1024UL)
#define KEYSTONE_GROUP_HEARTBEAT_TIMEOUT_CYCLES \
  (KEYSTONE_GROUP_SCHED_TIMER_DELTA * 4UL)
#define KEYSTONE_GROUP_UNBOUND_HART ((uint64_t)-1)
#define KEYSTONE_GROUP_UNBOUND_LANE ((uint64_t)-1)
#define KEYSTONE_YXSTM_MASTER_SLICE_MASK \
  ((1UL << KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT) - 1UL)
#define GROUP_REGION_PERM_R 0x1
#define GROUP_REGION_PERM_W 0x2
#define GROUP_REGION_PERM_X 0x4
#define KEYSTONE_COUNTEREN_CY (1UL << 0)
#define KEYSTONE_COUNTEREN_TM (1UL << 1)
#define KEYSTONE_COUNTEREN_IR (1UL << 2)

/*
 * OpenSBI deployments used by Keystone do not expose a stable general-purpose
 * allocator to the SM.  Keep a bounded arena, but allocate group membership
 * and runqueue storage from it according to the configured capacity.  This
 * avoids multiplying ENCL_MAX-sized arrays by every group, hart and lane while
 * retaining deterministic firmware memory usage.
 */
#define KEYSTONE_GROUP_METADATA_ARENA_SIZE (512UL * 1024UL)
#define KEYSTONE_GROUP_METADATA_UNIT_SIZE 64UL
#define KEYSTONE_GROUP_METADATA_UNIT_COUNT \
  (KEYSTONE_GROUP_METADATA_ARENA_SIZE / KEYSTONE_GROUP_METADATA_UNIT_SIZE)
#define KEYSTONE_GROUP_METADATA_BITMAP_WORDS \
  ((KEYSTONE_GROUP_METADATA_UNIT_COUNT + 63UL) / 64UL)

static unsigned char group_metadata_arena[KEYSTONE_GROUP_METADATA_ARENA_SIZE]
    __attribute__((aligned(KEYSTONE_GROUP_METADATA_UNIT_SIZE)));
static uint64_t
    group_metadata_bitmap[KEYSTONE_GROUP_METADATA_BITMAP_WORDS];

static size_t group_metadata_units_for_size(size_t size)
{
  if (!size || size > KEYSTONE_GROUP_METADATA_ARENA_SIZE)
    return 0;
  return (size + KEYSTONE_GROUP_METADATA_UNIT_SIZE - 1) /
         KEYSTONE_GROUP_METADATA_UNIT_SIZE;
}

/* Caller holds encl_lock. */
static void* group_metadata_alloc_locked(size_t size)
{
  size_t units = group_metadata_units_for_size(size);
  size_t start;

  if (!units)
    return 0;
  for (start = 0; start + units <= KEYSTONE_GROUP_METADATA_UNIT_COUNT;
       start++) {
    size_t offset;

    for (offset = 0; offset < units; offset++) {
      size_t unit = start + offset;
      if (group_metadata_bitmap[unit / 64] &
          (UINT64_C(1) << (unit % 64)))
        break;
    }
    if (offset != units) {
      start += offset;
      continue;
    }
    for (offset = 0; offset < units; offset++) {
      size_t unit = start + offset;
      group_metadata_bitmap[unit / 64] |=
          UINT64_C(1) << (unit % 64);
    }
    sbi_memset(&group_metadata_arena[
                   start * KEYSTONE_GROUP_METADATA_UNIT_SIZE],
               0, units * KEYSTONE_GROUP_METADATA_UNIT_SIZE);
    return &group_metadata_arena[
        start * KEYSTONE_GROUP_METADATA_UNIT_SIZE];
  }
  return 0;
}

/* Caller holds encl_lock. */
static void group_metadata_free_locked(void* pointer, size_t size)
{
  uintptr_t base = (uintptr_t)group_metadata_arena;
  uintptr_t address = (uintptr_t)pointer;
  size_t units = group_metadata_units_for_size(size);
  size_t start;
  size_t offset;

  if (!pointer || !units || address < base ||
      address >= base + KEYSTONE_GROUP_METADATA_ARENA_SIZE ||
      ((address - base) % KEYSTONE_GROUP_METADATA_UNIT_SIZE))
    return;
  start = (address - base) / KEYSTONE_GROUP_METADATA_UNIT_SIZE;
  if (start + units > KEYSTONE_GROUP_METADATA_UNIT_COUNT)
    return;
  sbi_memset(pointer, 0, units * KEYSTONE_GROUP_METADATA_UNIT_SIZE);
  for (offset = 0; offset < units; offset++) {
    size_t unit = start + offset;
    group_metadata_bitmap[unit / 64] &=
        ~(UINT64_C(1) << (unit % 64));
  }
}

static size_t group_metadata_free_bytes_locked(void)
{
  size_t free_units = 0;
  size_t unit;

  for (unit = 0; unit < KEYSTONE_GROUP_METADATA_UNIT_COUNT; unit++)
    if (!(group_metadata_bitmap[unit / 64] &
          (UINT64_C(1) << (unit % 64))))
      free_units++;
  return free_units * KEYSTONE_GROUP_METADATA_UNIT_SIZE;
}

static unsigned long sm_abi_validate(const struct keystone_abi_header* abi,
                                     uintptr_t expected_size,
                                     uintptr_t required_features)
{
  if (!abi)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (abi->version != KEYSTONE_ABI_VERSION)
    return SBI_ERR_SM_ABI_UNSUPPORTED;
  if (abi->struct_size != expected_size ||
      (abi->struct_size & (KEYSTONE_ABI_ALIGN - 1)))
    return SBI_ERR_SM_ABI_BAD_SIZE;
  if ((abi->features & required_features) != required_features)
    return SBI_ERR_SM_ABI_BAD_FEATURE;
  if (abi->status || abi->detail || abi->reserved)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static void sm_abi_fill(struct keystone_abi_header* abi,
                        uintptr_t expected_size,
                        uintptr_t features)
{
  if (!abi)
    return;
  abi->version = KEYSTONE_ABI_VERSION;
  abi->struct_size = expected_size;
  abi->features = features;
  abi->status = SBI_ERR_SM_ENCLAVE_SUCCESS;
  abi->detail = SBI_ERR_SM_ENCLAVE_SUCCESS;
  abi->reserved = 0;
}

static void sm_abi_set_result(struct keystone_abi_header* abi,
                              unsigned long status,
                              unsigned long detail)
{
  if (!abi)
    return;
  abi->status = status;
  abi->detail = detail;
}

enum group_region_type {
  GROUP_REGION_INVALID = 0,
  GROUP_REGION_PRIVATE_EPM,
  GROUP_REGION_SHARED,
  GROUP_REGION_METADATA,
  GROUP_REGION_CHANNEL,
  GROUP_REGION_UTM,
  GROUP_REGION_SHARED_UTM,
  GROUP_REGION_SEC,
};

static const char* group_region_type_name(enum group_region_type type)
{
  switch (type) {
    case GROUP_REGION_PRIVATE_EPM:
      return "private_epm";
    case GROUP_REGION_SHARED:
      return "shared";
    case GROUP_REGION_METADATA:
      return "metadata";
    case GROUP_REGION_CHANNEL:
      return "channel";
    case GROUP_REGION_UTM:
      return "utm";
    case GROUP_REGION_SHARED_UTM:
      return "shared_utm";
    case GROUP_REGION_SEC:
      return "sec";
    default:
      return "invalid";
  }
}

static inline void group_scheduler_enable_smode_counters(void)
{
  /*
   * Eyrie initializes its timer in S-mode and reads the unprivileged time CSR
   * before the eapp starts. That access is controlled by M-mode mcounteren.
   * U-mode eapps are then gated by scounteren. Treat both as SM-owned hart
   * policy, not per-enclave saved state: every schedule-in reinstalls the
   * counter view required by the runtime and tests.
   */
  csr_set(mcounteren,
      KEYSTONE_COUNTEREN_CY | KEYSTONE_COUNTEREN_TM | KEYSTONE_COUNTEREN_IR);
  csr_set(scounteren,
      KEYSTONE_COUNTEREN_CY | KEYSTONE_COUNTEREN_TM | KEYSTONE_COUNTEREN_IR);
}

static int group_region_is_table_region(enum group_region_type type)
{
  return type == GROUP_REGION_SHARED ||
         type == GROUP_REGION_METADATA ||
         type == GROUP_REGION_CHANNEL;
}

struct group_region_descriptor {
  int valid;
  uint64_t region_id;
  uint64_t generation;
  enum group_region_type type;
  uintptr_t paddr;
  size_t size;
  uint64_t owner_group;
  uint64_t permissions;
};

struct yxstm_slot {
  int valid;
  uint64_t slot_id;
  enclave_id owner_eid;
  uint64_t owner_generation;
  uint64_t lane_id;
  uintptr_t base;
  size_t size;
  size_t payload_capacity;
  size_t payload_size;
  uint64_t state;
  uint64_t batch_id;
  uint64_t task_id;
  uint64_t sequence;
  uint64_t epoch;
  uint64_t permissions;
  uint64_t digest;
  int pmp_cache_valid;
  size_t pmp_entry_count;
  struct keystone_pmp_cached_entry pmp_grant[2][2];
};

#define GROUP_LANE_WAIT_KIND_TURN 0
#define GROUP_LANE_WAIT_KIND_TASK_BANK 1
#define GROUP_LANE_WAIT_KIND_SLOT_READY 2
#define GROUP_YXSTM_SLOT_GRANT_BANK (KEYSTONE_YXSTM_INVALID_BANK - 1)

struct group_member_descriptor {
  int valid;
  enclave_id eid;
  uint64_t eid_generation;
  uint64_t group_id;
  uint64_t group_generation;
  uint64_t role;
  uint64_t bound_hart;
  uint64_t lane_id;
  uint64_t lane_rank;
  uint64_t lane_wait_sequence;
  uint64_t lane_wait_turn;
  uint64_t lane_wait_phase;
  uint64_t lane_wait_task_epoch;
  uint64_t lane_wait_result;
  uint64_t lane_wait_started_at;
  int lane_wait_pending;
  int lane_wait_task_bank;
  int lane_wait_ready;
  int lane_wait_context_saved;
  int yxstm_completion_pending;
  uint64_t yxstm_completion_epoch;
  uint64_t task_epoch;
  uint64_t allowed_slice_mask;
  struct yxstm_slot yxstm_slot;
  uintptr_t private_epm_base;
  size_t private_epm_size;
  uintptr_t page_table_root;
  uintptr_t yxstm_base;
  size_t yxstm_size;
  size_t yxstm_bank_slice_size;
  uint64_t yxstm_bank_count;
  uint64_t page_table_trust_model;
  uint64_t page_table_audit_epoch;
  size_t audited_page_table_pages;
  size_t audited_leaf_mappings;
  uintptr_t audited_yxstm_pte_flags;
  size_t audited_yxstm_leaf_count;
  size_t audited_yxstm_min_leaf_size;
  size_t audited_yxstm_max_leaf_size;
  size_t audited_yxstm_alignment;
  uint64_t membership_epoch;
  uint64_t revoked_epoch;
  uintptr_t protocol_mailbox_va;
  uintptr_t protocol_mailbox_paddr;
  size_t protocol_mailbox_size;
  uint64_t protocol_mailbox_flags;
  int protocol_mailbox_registered;
  struct group_region_descriptor private_region;
  struct group_region_descriptor allowed_shared_regions[KEYSTONE_GROUP_MAX_ALLOWED_SHARED_REGIONS];
  size_t allowed_shared_region_count;
  uint64_t allowed_region_epoch;
  int yxstm_suspended_acquired;
  uint64_t yxstm_suspended_slice_mask;
  uint64_t yxstm_suspended_permissions;
  uint64_t yxstm_suspended_phase;
  uint64_t yxstm_suspended_bank_id;
  uint64_t yxstm_suspended_phase_epoch;
  uint64_t yxstm_suspended_permission_epoch;
  uint64_t yxstm_suspended_task_epoch;
  uint64_t yxstm_suspended_slot_lane;
  uint64_t yxstm_suspended_slot_id;
  uint64_t yxstm_suspended_slot_epoch;
  uint64_t yxstm_suspended_save_cycles;
  uint64_t sched_base_priority;
  uint64_t sched_weight;
  uint64_t sched_quantum_ticks;
  uint64_t sched_vruntime;
  uint64_t sched_sum_exec_time;
  uint64_t sched_exec_start_time;
  uint64_t sched_slice_ticks;
  uint64_t sched_last_run_epoch;
  uint64_t perf_window_exec_baseline;
  uint64_t perf_window_exec_runtime;
  uint64_t perf_aes_exec_start;
  uint64_t perf_aes_exec_runtime;
  uint64_t perf_aes_phase_epoch;
  int perf_aes_exec_active;
  uint64_t yxstm_ack_phase_epoch;
  uint64_t yxstm_ack_event_mask;
  int pmp_cache_valid;
  int pmp_utm_cache_valid;
  uint64_t pmp_cache_group_generation;
  struct keystone_pmp_cached_entry pmp_utm_allow;
  struct keystone_pmp_cached_entry pmp_utm_deny;
  size_t pmp_yxstm_deny_count;
  struct keystone_pmp_cached_entry pmp_yxstm_deny[2];
};

#define GROUP_PT_AUDIT_MAX_TABLE_PAGES 512
/*
 * A benchmark member can have a 24 MB private EPM plus its YXSTM slot and
 * UTM. With 4 KiB leaves, EPM alone needs 6144 audit records. Keep enough
 * headroom for a master view and mixed huge/small-page layouts; exhausting
 * this metadata must not be misreported as a mapping alias.
 */
#define GROUP_PT_AUDIT_MAX_LEAVES 16384

struct group_pt_leaf_record {
  uintptr_t paddr;
  size_t size;
  uint64_t region_id;
  int user_accessible;
};

struct group_pt_audit {
  uintptr_t table_pages[GROUP_PT_AUDIT_MAX_TABLE_PAGES];
  size_t table_page_count;
  struct group_pt_leaf_record leaves[GROUP_PT_AUDIT_MAX_LEAVES];
  size_t leaf_count;
  uintptr_t yxstm_pte_flags;
  size_t yxstm_leaf_count;
  size_t yxstm_min_leaf_size;
  size_t yxstm_max_leaf_size;
  size_t yxstm_alignment;
  int leaf_limit_exhausted;
};

typedef char group_pt_audit_must_fit_smm_half[
    sizeof(struct group_pt_audit) <= (SMM_SIZE / 2) ? 1 : -1];

struct group_pt_mapping_summary {
  uintptr_t pte_flags;
  size_t leaf_count;
  size_t min_leaf_size;
  size_t max_leaf_size;
  size_t alignment;
};

struct group_active_hart_state {
  int active;
  int pmp_installed;
  enclave_id eid;
  uint64_t eid_generation;
  uint64_t active_group_id;
  uint64_t group_generation;
  uint64_t active_epoch;
  uint64_t active_phase_epoch;
};

struct group_runqueue_entry {
  enclave_id eid;
  uint64_t eid_generation;
};

struct sm_hart_sched {
  int valid;
  uint64_t hart_id;
  uint64_t active_group_id;
  uint64_t active_group_generation;
  enclave_id active_eid;
  uint64_t active_eid_generation;
  struct group_runqueue_entry* runqueue;
  size_t runqueue_capacity;
  size_t runqueue_len;
  size_t current_index;
  uint64_t sched_epoch;
  uint64_t last_progress_epoch;
  uint64_t last_progress_time;
  uint64_t watchdog_count;
  uint64_t timer_tick_count;
  uint64_t cfs_min_vruntime;
  uint64_t cfs_slice_start;
  uint64_t cfs_slice_deadline;
  uint64_t cfs_current_slice_ticks;
  uint64_t cfs_runnable_weight;
  uint64_t cfs_avg_switch_ticks;
  size_t cfs_nr_running;
  int cfs_timer_enabled;
  int cfs_resched_pending;
  uint64_t host_service_deadline;
  int host_service_forced;
  int host_service_drop_grant;
  int host_service_pending;
  enclave_id host_service_eid;
  uint64_t host_service_eid_generation;
  uint64_t host_service_group_generation;
  uint64_t host_service_event_sequence;
  uint64_t host_service_start_cycle;
  int host_service_grant_suspended;
  uint64_t host_service_grant_cycles;
  int heartbeat_enabled;
  uint64_t heartbeat_request_sequence;
  uint64_t heartbeat_ack_sequence;
  uint64_t heartbeat_pending_sources;
  uint64_t heartbeat_handoff_sources;
  uint64_t heartbeat_cleared_sources;
  uint64_t heartbeat_deadline;
  uint64_t heartbeat_state;
};

struct group_scheduler_event {
  uint64_t group_id;
  uint64_t group_generation;
  uint64_t hart_id;
  enclave_id eid;
  uint64_t eid_generation;
  uintptr_t event;
  uintptr_t error;
  uintptr_t value;
  uint64_t sequence;
  uint64_t scheduler_epoch;
  uint64_t timestamp;
};

struct group_scheduler_event_queue {
  struct group_scheduler_event entries[KEYSTONE_GROUP_EVENT_QUEUE_DEPTH];
  size_t head;
  size_t tail;
  size_t count;
  uint64_t next_sequence;
  uint64_t overflow_count;
};

struct group_ocall_record {
  int valid;
  uint64_t ocall_id;
  uint64_t group_id;
  uint64_t group_generation;
  uint64_t hart_id;
  enclave_id eid;
  uint64_t eid_generation;
  uint64_t created_at;
  uint64_t deadline;
  uint64_t host_cookie;
  uint64_t flags;
  uint64_t perf_start_cycle;
  uint64_t perf_handler_cycles;
};

struct group_hart_slot {
  int valid;
  uint64_t hart_id;
  enclave_id active_eid;
  enclave_id yxstm_owner_eid;
  uintptr_t yxstm_slice_base;
  size_t yxstm_slice_size;
  int yxstm_slice_region;
  int yxstm_acquired;
  uint64_t yxstm_acquired_slice_mask;
  uint64_t yxstm_permissions;
  uint64_t yxstm_phase;
  uint64_t yxstm_bank_id;
  uint64_t yxstm_slot_lane;
  uint64_t yxstm_slot_id;
  uint64_t yxstm_slot_epoch;
  uint64_t active_epoch;
  uint64_t pmp_epoch;
  uint64_t phase_epoch;
};

enum group_worker_lane_state {
  GROUP_WORKER_LANE_FREE = 0,
  GROUP_WORKER_LANE_IDLE,
  GROUP_WORKER_LANE_RUNNING,
  GROUP_WORKER_LANE_DRAINING,
};

struct group_worker_lane {
  int valid;
  uint64_t lane_id;
  uint64_t hart_id;
  uint64_t slice_id;
  uint64_t slice_mask;
  enum group_worker_lane_state state;
  enclave_id active_eid;
  uint64_t active_eid_generation;
  struct group_runqueue_entry* runqueue;
  size_t runqueue_capacity;
  size_t runqueue_len;
  size_t current_index;
  uint64_t lane_epoch;
  uint64_t task_epoch;
  enclave_id last_owner_eid;
  uint64_t last_owner_generation;
  uint64_t owner_switch_count;
  uint64_t scrub_count;
  uint64_t stream_sequence;
  uint64_t stream_turn;
  uintptr_t yxstm_base;
  size_t yxstm_size;
  size_t slot_size;
  size_t slot_payload_size;
  size_t slot_count;
  size_t reserved_size;
  int slots_frozen;
};

struct group_task_bank_protocol {
  uint64_t phase;
  uint64_t phase_epoch;
  uint64_t task_epoch;
  uint64_t sequence;
  uint64_t published_sequence;
  uint64_t active_worker_mask;
  uint64_t ready_bitmap;
  uint64_t done_bitmap;
  size_t payload_length;
  uint64_t deadline;
  uint64_t rollback_reason;
  uint64_t commit_epoch;
  uint64_t task_digest;
  uint64_t lane_rank;
  uint64_t owner_generation_token;
  uintptr_t owner_worker_mask;
  uint64_t owner_lane_rank;
  int owner_valid;
};

struct enabled_group_slot {
  int valid;
  uint64_t group_id;
  uint64_t generation;
  uint64_t lifecycle_state;
  uint64_t member_capacity;
  uint64_t member_count;
  uint64_t registered_member_count;
  uint64_t pending_create_count;
  uint64_t configured_hart_mask;
  uint64_t hart_count;
  uint64_t active_hart_bitmap;
  uint64_t execution_mode;
  uint64_t housekeeping_cpu;
  uint64_t housekeeping_hart;
  uint64_t master_hart;
  uint64_t worker_hart_mask;
  uint64_t worker_count;
  uint64_t cpu_hart_offset;
  uint64_t topology_flags;
  uint64_t topology_epoch;
  uint64_t max_running_workers;
  uint64_t master_non_boundary_entries;
  uint64_t lease_state;
  uint64_t lease_epoch;
  uint64_t lease_flags;

  uintptr_t epm_base;
  size_t epm_size;
  int epm_region;
  uint64_t epm_refcount;

  uintptr_t yxstm_base;
  size_t yxstm_size;
  size_t yxstm_bank_slice_size;
  uint64_t yxstm_bank_count;
  int yxstm_region;
  uint64_t yxstm_refcount;

  int kg_ready;
  uint64_t next_region_id;
  uint64_t security_policy_version;
  uint64_t membership_epoch;
  uint64_t session_epoch;
  byte session_hash[MDSIZE];
  uint64_t permission_epoch;
  uint64_t coherence_sync_count;
  int coherence_inflight;
  uint64_t coherence_sequence;
  uint64_t coherence_target_permission_epoch;
  uint64_t coherence_target_phase_epoch;
  uint64_t coherence_target_hart_mask;
  uint64_t coherence_acked_hart_mask;
  int pmp_budget_valid;
  struct keystone_pmp_budget pmp_budget;
  uint64_t yxstm_phase;
  uint64_t yxstm_phase_epoch;
  uint64_t yxstm_task_epoch;
  uint64_t yxstm_sequence;
  uint64_t yxstm_published_sequence;
  uint64_t yxstm_active_worker_mask;
  uint64_t yxstm_ready_bitmap;
  uint64_t yxstm_done_bitmap;
  size_t yxstm_payload_length;
  uint64_t yxstm_deadline;
  uint64_t yxstm_rollback_reason;
  int yxstm_perf_quiet;
  uint64_t yxstm_dirty_slice_mask[KEYSTONE_YXSTM_MAX_BANKS];
  struct group_task_bank_protocol task_banks[KEYSTONE_YXSTM_MAX_BANKS];
  int yxstm_slots_frozen;
  uint64_t yxstm_slot_layout_epoch;
  size_t region_count;
  struct group_region_descriptor region_table[KEYSTONE_GROUP_MAX_REGIONS];
  struct group_member_descriptor* members;
  size_t member_metadata_capacity;
  size_t metadata_bytes;
  struct group_hart_slot hart_slots[MAX_HARTS];
  struct group_worker_lane worker_lanes[KEYSTONE_GROUP_MAX_WORKER_LANES];
};

struct group_coherence_snapshot {
  uint64_t group_id;
  uint64_t group_generation;
  uint64_t old_permission_epoch;
  uint64_t old_phase_epoch;
  uint64_t target_permission_epoch;
  uint64_t target_phase_epoch;
  uint64_t target_hart_mask;
  struct group_coherence_ipi_request request;
};

static struct enabled_group_slot enabled_groups[KEYSTONE_MAX_ENABLED_GROUPS];
static struct group_active_hart_state group_active_harts[MAX_HARTS];
static struct sm_hart_sched group_hart_schedulers[MAX_HARTS];
#if KEYSTONE_GROUP_STARTUP_TRACE
static int group_hart_enter_log_seen[ENCL_MAX];
static int group_hart_exit_log_seen[ENCL_MAX];
#endif
static int group_member_timer_ready[ENCL_MAX];
static int group_member_saved_mepc_advanced[ENCL_MAX];
static uint64_t group_ecall_switch_log_count[MAX_HARTS];
static uint64_t group_timer_retry_log_count[MAX_HARTS];
#if KEYSTONE_GROUP_TIMER_TRACE
static uint64_t group_timer_switch_log_count[MAX_HARTS];
static uint64_t group_timer_candidate_log_count[MAX_HARTS];
#endif
#if KEYSTONE_GROUP_STARTUP_TRACE
static int group_timer_config_log_seen[MAX_HARTS];
#endif
static uintptr_t group_hart_run_status_ptr[MAX_HARTS];
static struct group_scheduler_event_queue group_hart_event_queues[MAX_HARTS];
static spinlock_t group_event_lock = SPIN_LOCK_INITIALIZER;
static struct group_ocall_record group_ocalls[ENCL_MAX];
static uint64_t group_ocall_sequence;
static uint64_t group_ocall_resume_start_cycle[ENCL_MAX];
static uint64_t group_ocall_resume_generation[ENCL_MAX];
static atomic_t group_perf_acquire_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_acquire_cycles = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_release_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_release_cycles = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_ocall_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_ocall_cycles = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_ocall_handler_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_ocall_handler_cycles = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_ocall_wait_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_ocall_wait_ticks = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_lane_wait_block_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_lane_wait_wake_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_lane_wait_ticks = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_heartbeat_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_heartbeat_cycles = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_ipi_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_ipi_cycles = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_host_service_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_host_service_cycles = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_grant_suspend_restore_count =
    ATOMIC_INITIALIZER(0);
static atomic_t group_perf_grant_suspend_restore_cycles =
    ATOMIC_INITIALIZER(0);
static atomic_t group_perf_scrub_count = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_scrub_bytes = ATOMIC_INITIALIZER(0);
static atomic_t group_perf_scrub_cycles = ATOMIC_INITIALIZER(0);
static uintptr_t group_control_requests[ENCL_MAX];
static struct thread_state group_hart_host_threads[MAX_HARTS];
static int group_hart_host_context_valid[MAX_HARTS];

struct group_perf_hart_local {
  uint64_t context_switch_count;
  uint64_t context_switch_cycles;
  uint64_t context_switch_ticks;
  uint64_t context_gpr_cycles;
  uint64_t context_smode_csr_cycles;
  uint64_t context_fp_cycles;
  uint64_t context_pmp_cycles;
  uint64_t context_platform_cycles;
  uint64_t context_scheduler_lock_cycles;
  uint64_t pmp_grant_suspend_cycles;
  uint64_t pmp_epm_revoke_cycles;
  uint64_t pmp_epm_install_cycles;
  uint64_t pmp_yxstm_restore_cycles;
  uint64_t pmp_fence_cycles;
  uint64_t pmp_validation_cycles;
  uint64_t pmp_lock_wait_cycles;
  uint64_t cfs_pick_count;
  uint64_t cfs_preempt_count;
  uint64_t cfs_runtime_ticks;
  uint64_t cfs_vruntime_delta;
  uint64_t cfs_slice_ticks;
  uint64_t cfs_min_granularity_count;
  uint64_t cfs_dynamic_min_slice_ticks;
  uint64_t timer_trap_count;
  uint64_t timer_trap_cycles;
  uint64_t timer_nested_switch_cycles;
  uint64_t last_trap_cycle;
  uint64_t last_trap_time;
  uint64_t cycles_per_time_tick;
  int timer_sample_active;
};

static struct group_perf_hart_local group_perf_harts[MAX_HARTS];
static uint64_t group_perf_window_state = KEYSTONE_GROUP_PERF_WINDOW_IDLE;
static uint64_t group_perf_window_epoch;
static uint64_t group_perf_window_group_id;
static uint64_t group_perf_window_group_generation;
static uint64_t group_perf_window_start_ticks;
static uint64_t group_perf_window_stop_ticks;

static uint64_t group_perf_validated_cycle_delta(
    struct group_perf_hart_local* perf,
    uint64_t start_cycle, uint64_t start_time,
    uint64_t end_cycle, uint64_t end_time)
{
  uint64_t cycle_delta;
  uint64_t time_delta;
  uint64_t ratio_limit;

  if (!perf || end_cycle < start_cycle || end_time < start_time)
    return 0;
  cycle_delta = end_cycle - start_cycle;
  time_delta = end_time - start_time;
  if (!time_delta)
    return cycle_delta <= KEYSTONE_GROUP_SCHED_TIMER_DELTA ? cycle_delta : 0;

  /*
   * mcycle is hart-local while mtime is shared and monotonic.  A stale or
   * reset hart counter must not turn one short switch into billions of
   * cycles.  Calibrate the normal ratio from complete timer intervals and
   * use mtime as a sanity bound for every hot-path sample.
   */
  ratio_limit = perf->cycles_per_time_tick ?
      perf->cycles_per_time_tick * 8 : 4096;
  if (cycle_delta / time_delta > ratio_limit) {
    if (!perf->cycles_per_time_tick)
      return 0;
    if (time_delta > ~(uint64_t)0 / perf->cycles_per_time_tick)
      return 0;
    return time_delta * perf->cycles_per_time_tick;
  }
  return cycle_delta;
}

void group_perf_timer_trap_begin(uint64_t cycle, uint64_t time)
{
  unsigned long hartid = csr_read(mhartid);
  struct group_perf_hart_local* perf;

  if (hartid >= MAX_HARTS)
    return;
  perf = &group_perf_harts[hartid];
  if (perf->last_trap_time && time > perf->last_trap_time &&
      cycle >= perf->last_trap_cycle) {
    uint64_t time_delta = time - perf->last_trap_time;
    uint64_t cycle_delta = cycle - perf->last_trap_cycle;
    uint64_t ratio = cycle_delta / time_delta;

    if (ratio && ratio <= 4096)
      perf->cycles_per_time_tick = perf->cycles_per_time_tick ?
          (perf->cycles_per_time_tick * 7 + ratio) / 8 : ratio;
  }
  perf->last_trap_cycle = cycle;
  perf->last_trap_time = time;
  perf->timer_nested_switch_cycles = 0;
  perf->timer_sample_active = 1;
}

static void group_perf_record_context_switch(uint64_t start_cycle,
                                             uint64_t start_time)
{
  unsigned long hartid = csr_read(mhartid);
  struct group_perf_hart_local* perf;
  uint64_t cycles;
  uint64_t end_time;

  if (hartid >= MAX_HARTS)
    return;
  perf = &group_perf_harts[hartid];
  end_time = sbi_timer_value();
  cycles = group_perf_validated_cycle_delta(
      perf, start_cycle, start_time,
      csr_read(CSR_MCYCLE), end_time);
  perf->context_switch_count++;
  perf->context_switch_cycles += cycles;
  if (end_time >= start_time) {
    uint64_t ticks = end_time - start_time;
    struct sm_hart_sched* sched = &group_hart_schedulers[hartid];

    perf->context_switch_ticks =
        ticks > ~(uint64_t)0 - perf->context_switch_ticks ?
            ~(uint64_t)0 : perf->context_switch_ticks + ticks;
    if (ticks && sched->valid) {
      uint64_t average = sched->cfs_avg_switch_ticks;

      /* EWMA without multiplying the accumulated value by seven. */
      sched->cfs_avg_switch_ticks = average ?
          average - (average / 8) + (ticks / 8) : ticks;
    }
  }
  if (perf->timer_sample_active)
    perf->timer_nested_switch_cycles += cycles;
}

static void group_perf_add_context_components(
    const struct thread_state_profile* saved,
    const struct thread_state_profile* restored,
    uint64_t pmp_cycles, uint64_t platform_cycles,
    uint64_t scheduler_lock_cycles)
{
  unsigned long hartid = csr_read(mhartid);
  struct group_perf_hart_local* perf;

  if (hartid >= MAX_HARTS)
    return;
  perf = &group_perf_harts[hartid];
  if (saved) {
    perf->context_gpr_cycles += saved->gpr_cycles;
    perf->context_smode_csr_cycles += saved->smode_csr_cycles;
    perf->context_fp_cycles += saved->fp_cycles;
  }
  if (restored) {
    perf->context_gpr_cycles += restored->gpr_cycles;
    perf->context_smode_csr_cycles += restored->smode_csr_cycles;
    perf->context_fp_cycles += restored->fp_cycles;
  }
  perf->context_pmp_cycles += pmp_cycles;
  perf->context_platform_cycles += platform_cycles;
  perf->context_scheduler_lock_cycles += scheduler_lock_cycles;
}

enum group_perf_pmp_component {
  GROUP_PERF_PMP_GRANT_SUSPEND = 0,
  GROUP_PERF_PMP_EPM_REVOKE,
  GROUP_PERF_PMP_EPM_INSTALL,
  GROUP_PERF_PMP_YXSTM_RESTORE,
  GROUP_PERF_PMP_FENCE,
  GROUP_PERF_PMP_VALIDATION,
  GROUP_PERF_PMP_LOCK_WAIT,
};

static void group_perf_add_pmp_component(
    enum group_perf_pmp_component component, uint64_t cycles)
{
  unsigned long hartid = csr_read(mhartid);
  struct group_perf_hart_local* perf;

  if (hartid >= MAX_HARTS)
    return;
  perf = &group_perf_harts[hartid];
  switch (component) {
    case GROUP_PERF_PMP_GRANT_SUSPEND:
      perf->pmp_grant_suspend_cycles += cycles;
      break;
    case GROUP_PERF_PMP_EPM_REVOKE:
      perf->pmp_epm_revoke_cycles += cycles;
      break;
    case GROUP_PERF_PMP_EPM_INSTALL:
      perf->pmp_epm_install_cycles += cycles;
      break;
    case GROUP_PERF_PMP_YXSTM_RESTORE:
      perf->pmp_yxstm_restore_cycles += cycles;
      break;
    case GROUP_PERF_PMP_FENCE:
      perf->pmp_fence_cycles += cycles;
      break;
    case GROUP_PERF_PMP_VALIDATION:
      perf->pmp_validation_cycles += cycles;
      break;
    case GROUP_PERF_PMP_LOCK_WAIT:
      perf->pmp_lock_wait_cycles += cycles;
      break;
  }
}

void group_perf_record_timer_trap(uint64_t start_cycle, uint64_t start_time)
{
  unsigned long hartid = csr_read(mhartid);
  struct group_perf_hart_local* perf;
  uint64_t cycles;

  if (hartid >= MAX_HARTS)
    return;
  perf = &group_perf_harts[hartid];
  cycles = group_perf_validated_cycle_delta(
      perf, start_cycle, start_time,
      csr_read(CSR_MCYCLE), sbi_timer_value());
  if (cycles >= perf->timer_nested_switch_cycles)
    cycles -= perf->timer_nested_switch_cycles;
  else
    cycles = 0;
  perf->timer_trap_count++;
  perf->timer_trap_cycles += cycles;
  perf->timer_nested_switch_cycles = 0;
  perf->timer_sample_active = 0;
}
#if KEYSTONE_GROUP_STARTUP_TRACE
static int group_pmp_layout_dump_seen[MAX_HARTS];
#endif
static uint64_t configured_group_count;
static uint64_t group_generation_counter;
static uint64_t enclave_generation_counter;

typedef struct {
  volatile int YXSTM_sm_init;
  volatile int YXSTM_sm_fleible;
  volatile int sm_engine_id;
}sm_ms;

// Enclave IDs are unsigned ints, so we do not need to check if eid is
// greater than or equal to 0
#define ENCLAVE_EXISTS(eid) (eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;
static spinlock_t group_pt_audit_lock = SPIN_LOCK_INITIALIZER;
static struct group_pt_audit group_pt_audit_scratch;

int group_coherence_ipi_target_matches(unsigned long hartid,
                                       unsigned long group_id,
                                       unsigned long group_generation)
{
  struct group_active_hart_state* state = 0;

  if (hartid >= MAX_HARTS)
    return 0;
  asm volatile("fence r,rw" ::: "memory");
  state = &group_active_harts[hartid];
  return state->active && state->active_group_id == group_id &&
         state->group_generation == group_generation;
}

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];

static void group_release_yxstm_owner_metadata_locked(enclave_id eid);
static void yxstm_protocol_publish_mailboxes_locked(
    struct enabled_group_slot* group);

static inline int group_mode_enabled(uint64_t ms, uint64_t group_id)
{
  return ms != 0 && group_id != 0;
}

static int range_contains(uintptr_t base, size_t size,
                          uintptr_t child_base, size_t child_size)
{
  uintptr_t end;
  uintptr_t child_end;

  if (!size || !child_size)
    return 0;
  if (CHECKED_ADD(base, size, &end))
    return 0;
  if (CHECKED_ADD(child_base, child_size, &child_end))
    return 0;
  return base <= child_base && child_end <= end;
}

static int group_yxstm_layout_valid(const struct enabled_group_slot* group)
{
  size_t expected;

  if (!group || !group->yxstm_bank_count ||
      group->yxstm_bank_count > KEYSTONE_YXSTM_MAX_BANKS ||
      !group->yxstm_bank_slice_size ||
      group->yxstm_bank_slice_size >
          (size_t)-1 / KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT /
              group->yxstm_bank_count)
    return 0;
  expected = group->yxstm_bank_slice_size *
             KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT *
             group->yxstm_bank_count;
  return expected == group->yxstm_size;
}

static size_t group_yxstm_bank_size(const struct enabled_group_slot* group)
{
  return group && group_yxstm_layout_valid(group) ?
      group->yxstm_bank_slice_size * KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT : 0;
}

static uintptr_t group_yxstm_bank_slice_base(
    const struct enabled_group_slot* group, uintptr_t bank_id,
    uintptr_t slice_id)
{
  size_t bank_size = group_yxstm_bank_size(group);

  if (!bank_size || bank_id >= group->yxstm_bank_count ||
      slice_id >= KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
    return 0;
  return group->yxstm_base + bank_id * bank_size +
         slice_id * group->yxstm_bank_slice_size;
}

static uintptr_t group_yxstm_worker_lane_base(
    const struct enabled_group_slot* group, uint64_t lane_id)
{
  if (!group || lane_id >= KEYSTONE_YXSTM_WORKER_LANE_COUNT)
    return 0;
  /*
   * Keep one hardware-aligned backing allocation. Logical worker lanes expose
   * 12,000,000 task bytes in physical slices 1..3; page-alignment tails and
   * unused slice tails remain unavailable to tasks. Exact slot grants reuse
   * the fixed YXSTM TOR pair.
   */
  return group_yxstm_bank_slice_base(group, 0, lane_id + 1);
}

static struct group_member_descriptor*
group_yxstm_slot_member_locked(struct enabled_group_slot* group,
                               uint64_t lane_id, uint64_t slot_id)
{
  size_t i;

  if (!group || !group->members)
    return 0;
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];

    if (member->valid && member->role == GROUP_ROLE_WORKER &&
        member->lane_id == lane_id && member->yxstm_slot.valid &&
        member->yxstm_slot.slot_id == slot_id)
      return member;
  }
  return 0;
}

static struct group_member_descriptor*
group_yxstm_slot_member_for_slice_locked(
    struct enabled_group_slot* group, uint64_t slice_id, uint64_t slot_id)
{
  if (!slice_id || slice_id > KEYSTONE_YXSTM_WORKER_LANE_COUNT)
    return 0;
  return group_yxstm_slot_member_locked(group, slice_id - 1, slot_id);
}

static int group_yxstm_slot_metadata_valid(
    const struct group_worker_lane* lane,
    const struct group_member_descriptor* member)
{
  const struct yxstm_slot* slot;
  uint64_t expected_permissions;

  if (!lane || !member || !member->yxstm_slot.valid)
    return 0;
  slot = &member->yxstm_slot;
  if (slot->owner_eid != member->eid ||
      slot->owner_generation != member->eid_generation ||
      slot->lane_id != lane->lane_id ||
      slot->slot_id != member->lane_rank ||
      slot->base != lane->yxstm_base + slot->slot_id * lane->slot_size ||
      slot->size != lane->slot_size ||
      slot->payload_capacity != lane->slot_payload_size ||
      slot->payload_size > slot->payload_capacity || !slot->epoch ||
      !slot->pmp_cache_valid || slot->pmp_entry_count != 2 ||
      !slot->pmp_grant[0][0].valid || !slot->pmp_grant[0][1].valid ||
      !slot->pmp_grant[1][0].valid || !slot->pmp_grant[1][1].valid ||
      slot->pmp_grant[0][0].slot != KEYSTONE_PMP_SLOT_YXSTM_LO ||
      slot->pmp_grant[0][1].slot != KEYSTONE_PMP_SLOT_YXSTM_HI ||
      slot->pmp_grant[1][0].slot != KEYSTONE_PMP_SLOT_YXSTM_LO ||
      slot->pmp_grant[1][1].slot != KEYSTONE_PMP_SLOT_YXSTM_HI ||
      slot->state > YXSTM_SLOT_AGGREGATING ||
      !range_contains(lane->yxstm_base, lane->yxstm_size,
                      slot->base, slot->size))
    return 0;
  if (slot->state == YXSTM_SLOT_FREE)
    return !slot->batch_id && !slot->task_id && !slot->sequence &&
           !slot->payload_size && !slot->permissions && !slot->digest;
  if (!slot->batch_id || !slot->task_id || !slot->sequence ||
      !slot->payload_size)
    return 0;
  if ((slot->state == YXSTM_SLOT_DONE ||
       slot->state == YXSTM_SLOT_AGGREGATING) && !slot->digest)
    return 0;
  if ((slot->state == YXSTM_SLOT_DISPATCHING ||
       slot->state == YXSTM_SLOT_READY ||
       slot->state == YXSTM_SLOT_COMPUTING) && slot->digest)
    return 0;
  if (slot->state == YXSTM_SLOT_DISPATCHING ||
      slot->state == YXSTM_SLOT_COMPUTING)
    expected_permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
  else if (slot->state == YXSTM_SLOT_READY ||
           slot->state == YXSTM_SLOT_AGGREGATING)
    expected_permissions = KEYSTONE_YXSTM_PERM_R;
  else
    expected_permissions = 0;
  return slot->permissions == expected_permissions;
}

static void group_task_banks_init_locked(struct enabled_group_slot* group)
{
  uintptr_t bank_id;

  if (!group)
    return;
  for (bank_id = 0; bank_id < KEYSTONE_YXSTM_MAX_BANKS; bank_id++) {
    sbi_memset(&group->task_banks[bank_id], 0,
               sizeof(group->task_banks[bank_id]));
    group->task_banks[bank_id].phase = YXSTM_PHASE_IDLE;
    group->task_banks[bank_id].phase_epoch = 1;
    group->task_banks[bank_id].task_epoch = 1;
  }
}

static int group_context_validate_locked(struct enabled_group_slot* group,
                                         const char* where);
static struct group_member_descriptor*
group_member_find_locked(struct enabled_group_slot* group, enclave_id eid);
static unsigned long group_member_validate_initial_view(enclave_id eid);
static void group_update_yxstm_slices_locked(struct enabled_group_slot* group);
static int group_topology_validate_locked(
    struct enabled_group_slot* group);
static void group_scheduler_set_state_locked(enclave_id eid,
                                             enum group_sched_state state);
static int group_scheduler_transition_locked(enclave_id eid,
                                             enum group_sched_state next,
                                             const char* where);
static int group_scheduler_transition_ex_locked(enclave_id eid,
                                                enum group_sched_state next,
                                                const char* where,
                                                int defer_kick);
static void group_lane_wait_mark_context_saved(enclave_id eid);
static int group_worker_lane_shared_handoff_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    struct group_member_descriptor* member, int active_owner);
static int group_worker_lane_bank_wait_handoff_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    struct group_member_descriptor* previous,
    struct group_member_descriptor* next, int active_owner);
static int group_member_suspended_grant_valid_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    struct group_member_descriptor* member);
static int group_worker_lane_preemptible_grant_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    struct group_member_descriptor* member);
static int group_scheduler_same_lane_fast_eligible_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    enclave_id current, enclave_id next);

static int group_scheduler_set_active_locked(
    struct enabled_group_slot* group,
    unsigned long hartid,
    enclave_id eid);
static void group_scheduler_clear_active_locked(unsigned long hartid,
                                                enclave_id eid);
static void group_scheduler_remove_eid_locked(enclave_id eid);
static int group_scheduler_bind_locked(struct enabled_group_slot* group,
                                       enclave_id eid,
                                       unsigned long hartid);
static enclave_id group_scheduler_pick_next_locked(unsigned long hartid,
                                                   enclave_id current_eid);
static uint64_t group_scheduler_timer_delta_for_us_local(uint64_t interval_us);
static uint64_t group_scheduler_cfs_weight(uint64_t priority);
static void group_scheduler_cfs_place_entity_locked(
    struct sm_hart_sched* sched,
    struct group_member_descriptor* member,
    int waking);
static void group_scheduler_cfs_prepare_active_locked(
    struct enabled_group_slot* group,
    struct sm_hart_sched* sched,
    struct group_member_descriptor* member,
    uint64_t now);
static void group_member_publish_exec_clock_locked(
    struct group_member_descriptor* member, uint64_t now, int running);
static void group_scheduler_cfs_account_current_locked(
    struct enabled_group_slot* group,
    struct sm_hart_sched* sched,
    enclave_id eid,
    uint64_t now);
static unsigned long group_scheduler_schedule_in_local(enclave_id eid,
                                                        int timer_fast_path);
static void group_scheduler_schedule_out_local(enclave_id eid,
                                               const char* where,
                                               int timer_fast_path);
static unsigned long group_scheduler_suspend_yxstm_grant_local(
    enclave_id eid, const char* where, int defer_hardware_revoke);
static void group_scheduler_rearm_timer_local(const char* where);
static unsigned long yxstm_install_pmp_for_mask_locked(
    struct enabled_group_slot* group,
    const struct group_member_descriptor* member,
    uintptr_t slice_mask,
    uintptr_t flags);
static unsigned long yxstm_install_task_bank_pmp_locked(
    struct enabled_group_slot* group,
    const struct group_member_descriptor* member,
    uintptr_t bank_id,
    uintptr_t slice_mask,
    uintptr_t flags);
static unsigned long yxstm_validate_member_access_locked(
    struct enabled_group_slot* group,
    const struct group_member_descriptor* member,
    uintptr_t slice_mask,
    uintptr_t flags,
    uintptr_t phase);
static int yxstm_flags_valid(uintptr_t flags);
static void yxstm_protocol_member_gone_locked(
    struct enabled_group_slot* group, enclave_id eid, uint64_t reason);
static void yxstm_protocol_publish_mailboxes_locked(
    struct enabled_group_slot* group);
static int yxstm_protocol_any_acquired_locked(
    struct enabled_group_slot* group);
static int yxstm_task_bank_any_acquired_locked(
    struct enabled_group_slot* group, uintptr_t bank_id);
static inline unsigned long context_switch_to_enclave(
    struct sbi_trap_regs* regs,
    enclave_id eid,
    int load_parameters);
static inline void context_switch_to_host(struct sbi_trap_regs* regs,
                                          enclave_id eid,
                                          int return_on_resume,
                                          int preserve_member_gprs);

static struct enabled_group_slot* find_group_locked(uint64_t group_id)
{
  int i;
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    if (enabled_groups[i].valid && enabled_groups[i].group_id == group_id)
      return &enabled_groups[i];
  }
  return 0;
}

static uint64_t next_nonzero_generation(uint64_t* counter)
{
  *counter = (*counter + 1) & 0xffffffffUL;
  if (!*counter)
    *counter = 1;
  return *counter;
}

static void group_security_rekey_locked(struct enabled_group_slot* group,
                                         uint64_t reason)
{
  hash_ctx ctx;
  uint64_t policy;

  if (!group)
    return;

  if (!group->security_policy_version)
    group->security_policy_version = KEYSTONE_GROUP_SECURITY_POLICY_VERSION;
  group->session_epoch++;
  if (!group->session_epoch)
    group->session_epoch = 1;

  policy = group->security_policy_version;
  hash_init(&ctx);
  hash_extend(&ctx, (void*)&group->group_id, sizeof(group->group_id));
  hash_extend(&ctx, (void*)&group->generation, sizeof(group->generation));
  hash_extend(&ctx, (void*)&policy, sizeof(policy));
  hash_extend(&ctx, (void*)&group->membership_epoch,
              sizeof(group->membership_epoch));
  hash_extend(&ctx, (void*)&group->session_epoch,
              sizeof(group->session_epoch));
  hash_extend(&ctx, (void*)&group->yxstm_phase_epoch,
              sizeof(group->yxstm_phase_epoch));
  hash_extend(&ctx, (void*)&group->yxstm_sequence,
              sizeof(group->yxstm_sequence));
  hash_extend(&ctx, (void*)&group->yxstm_active_worker_mask,
              sizeof(group->yxstm_active_worker_mask));
  hash_extend(&ctx, (void*)&reason, sizeof(reason));
  hash_extend(&ctx, (void*)sm_hash, MDSIZE);
  hash_finalize(group->session_hash, &ctx);
  asm volatile("fence rw,rw" ::: "memory");
}

#define GROUP_YXSTM_SCRUB_CACHELINE_BYTES 64UL

static void group_secure_zero_range(uintptr_t base, size_t size)
{
  volatile uint8_t* byte_ptr = (volatile uint8_t*)base;
  volatile uintptr_t* word_ptr;
  size_t word_count;

  if (!base || !size)
    return;

  while (size && ((uintptr_t)byte_ptr & (sizeof(uintptr_t) - 1))) {
    *byte_ptr++ = 0;
    size--;
  }
  word_ptr = (volatile uintptr_t*)byte_ptr;
  word_count = size / sizeof(uintptr_t);
  while (word_count >=
         GROUP_YXSTM_SCRUB_CACHELINE_BYTES / sizeof(uintptr_t)) {
    size_t word;

    for (word = 0;
         word < GROUP_YXSTM_SCRUB_CACHELINE_BYTES / sizeof(uintptr_t);
         word++)
      word_ptr[word] = 0;
    word_ptr += GROUP_YXSTM_SCRUB_CACHELINE_BYTES / sizeof(uintptr_t);
    word_count -= GROUP_YXSTM_SCRUB_CACHELINE_BYTES / sizeof(uintptr_t);
  }
  while (word_count--)
    *word_ptr++ = 0;
  byte_ptr = (volatile uint8_t*)word_ptr;
  size &= sizeof(uintptr_t) - 1;
  while (size--)
    *byte_ptr++ = 0;
}

static uint64_t group_scrub_yxstm_bank_mask_locked(
    struct enabled_group_slot* group, uint64_t bank_id,
    uint64_t slice_mask, const char* where);

static void group_mark_yxstm_bank_dirty_locked(
    struct enabled_group_slot* group, uint64_t bank_id,
    uint64_t slice_mask)
{
  if (!group || bank_id >= group->yxstm_bank_count ||
      bank_id >= KEYSTONE_YXSTM_MAX_BANKS)
    return;
  group->yxstm_dirty_slice_mask[bank_id] |=
      slice_mask & KEYSTONE_YXSTM_MASTER_SLICE_MASK;
}

static void group_scrub_yxstm_mask_locked(struct enabled_group_slot* group,
                                          uint64_t slice_mask,
                                          const char* where)
{
  int lane_id;
  uint64_t bank_id;
  uint64_t scrubbed_mask = 0;

  if (!group)
    return;
  for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++)
    scrubbed_mask |= group_scrub_yxstm_bank_mask_locked(
        group, bank_id, slice_mask, where);
  for (lane_id = 0; lane_id < KEYSTONE_GROUP_MAX_WORKER_LANES; lane_id++) {
    struct group_worker_lane* lane = &group->worker_lanes[lane_id];

    if (lane->valid && (scrubbed_mask & lane->slice_mask))
      lane->scrub_count++;
  }
}

static uint64_t group_scrub_yxstm_bank_mask_locked(
    struct enabled_group_slot* group, uint64_t bank_id,
    uint64_t slice_mask, const char* where)
{
  size_t slice_size;
  uint64_t slice_id;
  uint64_t scrubbed_mask = 0;
  uint64_t scrubbed_bytes = 0;
  uint64_t started;

  if (!group || !group->yxstm_base || !group->yxstm_size || !slice_mask ||
      bank_id >= group->yxstm_bank_count ||
      bank_id >= KEYSTONE_YXSTM_MAX_BANKS)
    return 0;

  slice_mask &= group->yxstm_dirty_slice_mask[bank_id];
  if (!slice_mask)
    return 0;

  slice_size = group->yxstm_bank_slice_size;
  if (!slice_size)
    return 0;
  started = csr_read(CSR_MCYCLE);
  for (slice_id = 0; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    uintptr_t base;

    if (!(slice_mask & (1UL << slice_id)))
      continue;
    base = group_yxstm_bank_slice_base(group, bank_id, slice_id);
    if (base) {
      group_secure_zero_range(base, slice_size);
      scrubbed_mask |= 1UL << slice_id;
      scrubbed_bytes += slice_size;
    }
  }
  if (!scrubbed_mask)
    return 0;
  asm volatile("fence rw,rw" ::: "memory");
  group->yxstm_dirty_slice_mask[bank_id] &= ~scrubbed_mask;
  atomic_add_return(&group_perf_scrub_count, 1);
  atomic_add_return(&group_perf_scrub_bytes, (long)scrubbed_bytes);
  atomic_add_return(&group_perf_scrub_cycles,
                    (long)(csr_read(CSR_MCYCLE) - started));
  /* Keep secure clearing out of the serial-console hot path. */
  if (!group->yxstm_perf_quiet &&
      (!where || (sbi_strcmp(where, "lane_task_boundary") != 0 &&
                  sbi_strcmp(where, "task_bank_owner_change") != 0 &&
                  sbi_strcmp(where, "task_complete") != 0)))
    sbi_printf("[SM][group-sec] scrub yxstm: group=%lu bank=%lu mask=0x%lx where=%s session=%lu\n",
               (unsigned long)group->group_id,
               (unsigned long)bank_id,
               (unsigned long)scrubbed_mask,
               where ? where : "unknown",
               (unsigned long)group->session_epoch);
  return scrubbed_mask;
}

static void group_scrub_member_yxstm_locked(struct enabled_group_slot* group,
                                             struct group_member_descriptor* member,
                                             const char* where)
{
  uint64_t mask;
  uint64_t bank_id;

  if (!group || !member || !member->valid)
    return;

  mask = member->allowed_slice_mask;
  if (member->role == GROUP_ROLE_MASTER)
    mask = KEYSTONE_YXSTM_MASTER_SLICE_MASK;
  if (group->yxstm_phase != YXSTM_PHASE_IDLE ||
      yxstm_protocol_any_acquired_locked(group))
    return;
  for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++) {
    if (group->task_banks[bank_id].phase != YXSTM_PHASE_IDLE ||
        yxstm_task_bank_any_acquired_locked(group, bank_id))
      return;
  }
  for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++)
    group_scrub_yxstm_bank_mask_locked(group, bank_id, mask, where);
}

static int group_yxstm_slot_prepare_pmp_cache_locked(
    struct enabled_group_slot* group, struct yxstm_slot* slot)
{
  size_t read_count = 0;
  size_t write_count = 0;

  if (!group || !slot || !slot->valid || !slot->base || !slot->size ||
      group->yxstm_region < 0 ||
      !range_contains(group->yxstm_base, group->yxstm_size,
                      slot->base, slot->size))
    return -1;

  slot->pmp_cache_valid = 0;
  slot->pmp_entry_count = 0;
  sbi_memset(slot->pmp_grant, 0, sizeof(slot->pmp_grant));
  if (pmp_cache_tor_entries(group->yxstm_region, slot->base, slot->size,
                            PMP_R, slot->pmp_grant[0], 2, &read_count) ||
      pmp_cache_tor_entries(group->yxstm_region, slot->base, slot->size,
                            PMP_R | PMP_W, slot->pmp_grant[1], 2,
                            &write_count) ||
      read_count != 2 || write_count != 2 ||
      slot->pmp_grant[0][0].slot != KEYSTONE_PMP_SLOT_YXSTM_LO ||
      slot->pmp_grant[0][1].slot != KEYSTONE_PMP_SLOT_YXSTM_HI ||
      slot->pmp_grant[1][0].slot != KEYSTONE_PMP_SLOT_YXSTM_LO ||
      slot->pmp_grant[1][1].slot != KEYSTONE_PMP_SLOT_YXSTM_HI)
    return -1;

  slot->pmp_entry_count = 2;
  slot->pmp_cache_valid = 1;
  return 0;
}

static int group_member_prepare_pmp_cache_locked(
    struct enabled_group_slot* group,
    struct group_member_descriptor* member)
{
  struct keystone_pmp_cached_entry deny[2];
  struct keystone_pmp_cached_entry utm_allow[2];
  struct keystone_pmp_cached_entry utm_deny[2];
  struct enclave_region* utm_region = 0;
  size_t deny_count = 0;
  size_t utm_allow_count = 0;
  size_t utm_deny_count = 0;
  int region_index;

  if (!group || !member || !member->valid || group->yxstm_region < 0 ||
      !group_yxstm_layout_valid(group))
    return -1;

  member->pmp_cache_valid = 0;
  member->pmp_utm_cache_valid = 0;
  sbi_memset(&member->pmp_utm_allow, 0,
             sizeof(member->pmp_utm_allow));
  sbi_memset(&member->pmp_utm_deny, 0,
             sizeof(member->pmp_utm_deny));
  member->pmp_yxstm_deny_count = 0;
  sbi_memset(member->pmp_yxstm_deny, 0,
             sizeof(member->pmp_yxstm_deny));
  if (pmp_cache_region_entries(group->yxstm_region, PMP_NO_PERM,
                               deny, 2, &deny_count) || deny_count != 2 ||
      deny[0].slot != KEYSTONE_PMP_SLOT_YXSTM_LO ||
      deny[1].slot != KEYSTONE_PMP_SLOT_YXSTM_HI)
    return -1;
  member->pmp_yxstm_deny[0] = deny[0];
  member->pmp_yxstm_deny[1] = deny[1];
  member->pmp_yxstm_deny_count = deny_count;

  /* The member cache is built before create_enclave publishes FRESH state. */
  if (member->eid >= ENCL_MAX)
    return -1;
  for (region_index = 0; region_index < ENCLAVE_REGIONS_MAX;
       region_index++) {
    struct enclave_region* region =
        &enclaves[member->eid].regions[region_index];

    if (region->type == REGION_UTM && region->pmp_rid >= 0) {
      utm_region = region;
      break;
    }
  }
  if (utm_region) {
    if (pmp_cache_region_entries(utm_region->pmp_rid, PMP_ALL_PERM,
                                 utm_allow, 2, &utm_allow_count) ||
        pmp_cache_region_entries(utm_region->pmp_rid, PMP_NO_PERM,
                                 utm_deny, 2, &utm_deny_count) ||
        utm_allow_count != 1 || utm_deny_count != 1 ||
        utm_allow[0].slot != KEYSTONE_PMP_SLOT_OS_UTM ||
        utm_deny[0].slot != KEYSTONE_PMP_SLOT_OS_UTM)
      return -1;
    member->pmp_utm_allow = utm_allow[0];
    member->pmp_utm_deny = utm_deny[0];
    member->pmp_utm_cache_valid = 1;
  }

  if (member->role == GROUP_ROLE_WORKER && member->yxstm_slot.valid &&
      (!member->yxstm_slot.pmp_cache_valid ||
       member->yxstm_slot.pmp_entry_count != 2))
    return -1;
  member->pmp_cache_group_generation = group->generation;
  member->pmp_cache_valid = 1;
  return 0;
}

static const char* group_lifecycle_name(uint64_t state)
{
  switch (state) {
    case KEYSTONE_GROUP_STATE_CONFIGURING: return "configuring";
    case KEYSTONE_GROUP_STATE_READY: return "ready";
    case KEYSTONE_GROUP_STATE_ACTIVE: return "active";
    case KEYSTONE_GROUP_STATE_DRAINING: return "draining";
    default: return "free";
  }
}

static uint64_t group_next_region_id_locked(struct enabled_group_slot* group)
{
  uint64_t local_id;

  if (!group)
    return 0;
  if (!group->next_region_id)
    group->next_region_id = 1;
  local_id = group->next_region_id++ & 0xffffffffUL;
  return ((group->generation & 0xffffffffUL) << 32) | local_id;
}

static uint64_t group_hart_bit(unsigned long hartid)
{
  if (hartid >= 64)
    return 0;
  return 1ULL << hartid;
}

static int group_hart_mask_popcount(uint64_t mask)
{
  int count = 0;

  while (mask) {
    count += (int)(mask & 1);
    mask >>= 1;
  }

  return count;
}

static unsigned long group_first_hart_in_mask(uint64_t mask)
{
  unsigned long hartid;

  for (hartid = 0; hartid < MAX_HARTS; hartid++)
    if (mask & group_hart_bit(hartid))
      return hartid;
  return MAX_HARTS;
}

static struct group_worker_lane* group_lane_for_hart_locked(
    struct enabled_group_slot* group, unsigned long hartid)
{
  int i;

  if (!group)
    return 0;
  for (i = 0; i < KEYSTONE_GROUP_MAX_WORKER_LANES; i++)
    if (group->worker_lanes[i].valid &&
        group->worker_lanes[i].hart_id == hartid)
      return &group->worker_lanes[i];
  return 0;
}

static struct group_worker_lane* group_lane_for_id_locked(
    struct enabled_group_slot* group, uint64_t lane_id)
{
  if (!group || lane_id >= KEYSTONE_GROUP_MAX_WORKER_LANES ||
      !group->worker_lanes[lane_id].valid)
    return 0;
  return &group->worker_lanes[lane_id];
}

static int group_topology_rebuild_lanes_locked(
    struct enabled_group_slot* group)
{
  unsigned long hartid;
  uint64_t lane_id = 0;

  if (!group || group->member_count || group->registered_member_count ||
      group->members)
    return -1;

  sbi_memset(group->worker_lanes, 0, sizeof(group->worker_lanes));
  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct group_worker_lane* lane;

    if (!(group->worker_hart_mask & group_hart_bit(hartid)))
      continue;
    if (lane_id >= KEYSTONE_GROUP_MAX_WORKER_LANES)
      return -1;
    lane = &group->worker_lanes[lane_id];
    lane->valid = 1;
    lane->lane_id = lane_id;
    lane->hart_id = hartid;
    lane->slice_id = lane_id + 1;
    lane->slice_mask = 1UL << lane->slice_id;
    lane->state = GROUP_WORKER_LANE_IDLE;
    lane->active_eid = ENCL_MAX;
    lane->last_owner_eid = ENCL_MAX;
    lane->lane_epoch = 1;
    lane->task_epoch = group->yxstm_task_epoch;
    lane->yxstm_size = KEYSTONE_YXSTM_WORKER_LANE_SIZE;
    lane_id++;
  }
  return lane_id == group->worker_count ? 0 : -1;
}

static size_t group_metadata_align(size_t size)
{
  return (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
}

static int group_pointer_in_metadata_locked(
    const struct enabled_group_slot* group, const void* pointer)
{
  uintptr_t base;
  uintptr_t address;

  if (!group || !group->members || !group->metadata_bytes || !pointer)
    return 0;
  base = (uintptr_t)group->members;
  address = (uintptr_t)pointer;
  return address >= base && address < base + group->metadata_bytes;
}

/*
 * Reserve every member and runqueue byte before the first enclave is created.
 * Runtime enqueue therefore cannot fail because firmware metadata ran out.
 */
static int group_metadata_prepare_locked(struct enabled_group_slot* group,
                                         size_t capacity)
{
  size_t member_bytes;
  size_t runqueue_bytes;
  size_t queue_count;
  size_t total_bytes;
  unsigned char* cursor;
  unsigned long hartid;
  int lane_index;

  if (!group || !capacity || capacity > KEYSTONE_GROUP_MAX_MEMBERS ||
      capacity > ENCL_MAX || !group_topology_validate_locked(group))
    return -1;
  if (group->members)
    return group->member_metadata_capacity == capacity ? 0 : -1;
  if (group->member_count || group->registered_member_count ||
      group->pending_create_count)
    return -1;

  member_bytes = group_metadata_align(
      capacity * sizeof(struct group_member_descriptor));
  queue_count = group->worker_count + group->hart_count;
  if (!queue_count || capacity > (~(size_t)0) /
      sizeof(struct group_runqueue_entry) / queue_count)
    return -1;
  runqueue_bytes = group_metadata_align(
      capacity * sizeof(struct group_runqueue_entry));
  if (queue_count > ((~(size_t)0) - member_bytes) / runqueue_bytes)
    return -1;
  total_bytes = member_bytes + queue_count * runqueue_bytes;
  if (total_bytes > group_metadata_free_bytes_locked())
    return -1;

  group->members = group_metadata_alloc_locked(total_bytes);
  if (!group->members)
    return -1;
  group->member_metadata_capacity = capacity;
  group->metadata_bytes = total_bytes;
  cursor = (unsigned char*)group->members + member_bytes;

  for (lane_index = 0;
       lane_index < KEYSTONE_GROUP_MAX_WORKER_LANES;
       lane_index++) {
    struct group_worker_lane* lane = &group->worker_lanes[lane_index];
    size_t index;

    if (!lane->valid)
      continue;
    lane->runqueue = (struct group_runqueue_entry*)cursor;
    lane->runqueue_capacity = capacity;
    for (index = 0; index < capacity; index++)
      lane->runqueue[index].eid = ENCL_MAX;
    cursor += runqueue_bytes;
  }

  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct sm_hart_sched* sched;
    size_t index;

    if (!(group->configured_hart_mask & group_hart_bit(hartid)))
      continue;
    sched = &group_hart_schedulers[hartid];
    if (sched->runqueue || sched->runqueue_len ||
        (sched->valid && sched->active_group_id &&
         (sched->active_group_id != group->group_id ||
          sched->active_group_generation != group->generation)))
      goto rollback;
    sched->runqueue = (struct group_runqueue_entry*)cursor;
    sched->runqueue_capacity = capacity;
    sched->runqueue_len = 0;
    sched->current_index = 0;
    for (index = 0; index < capacity; index++)
      sched->runqueue[index].eid = ENCL_MAX;
    cursor += runqueue_bytes;
  }

  group->member_capacity = capacity;
  sbi_printf("[SM][group] metadata allocated: group=%lu generation=%lu capacity=%lu bytes=%lu free=%lu\n",
             (unsigned long)group->group_id,
             (unsigned long)group->generation,
             (unsigned long)capacity,
             (unsigned long)total_bytes,
             (unsigned long)group_metadata_free_bytes_locked());
  return 0;

rollback:
  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct sm_hart_sched* sched = &group_hart_schedulers[hartid];
    if (group_pointer_in_metadata_locked(group, sched->runqueue)) {
      sbi_memset(sched, 0, sizeof(*sched));
      sched->hart_id = hartid;
      sched->active_eid = ENCL_MAX;
      sched->host_service_eid = ENCL_MAX;
      sched->last_progress_time = sbi_timer_value();
    }
  }
  for (lane_index = 0;
       lane_index < KEYSTONE_GROUP_MAX_WORKER_LANES;
       lane_index++) {
    group->worker_lanes[lane_index].runqueue = 0;
    group->worker_lanes[lane_index].runqueue_capacity = 0;
    group->worker_lanes[lane_index].runqueue_len = 0;
  }
  group_metadata_free_locked(group->members, group->metadata_bytes);
  group->members = 0;
  group->member_metadata_capacity = 0;
  group->metadata_bytes = 0;
  return -1;
}

static void group_metadata_release_locked(struct enabled_group_slot* group)
{
  unsigned long hartid;
  int lane_index;

  if (!group || !group->members)
    return;
  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct sm_hart_sched* sched = &group_hart_schedulers[hartid];
    if (!group_pointer_in_metadata_locked(group, sched->runqueue))
      continue;
    sbi_memset(sched, 0, sizeof(*sched));
    sched->hart_id = hartid;
    sched->active_eid = ENCL_MAX;
    sched->host_service_eid = ENCL_MAX;
    sched->last_progress_time = sbi_timer_value();
  }
  for (lane_index = 0;
       lane_index < KEYSTONE_GROUP_MAX_WORKER_LANES;
       lane_index++) {
    group->worker_lanes[lane_index].runqueue = 0;
    group->worker_lanes[lane_index].runqueue_capacity = 0;
    group->worker_lanes[lane_index].runqueue_len = 0;
    group->worker_lanes[lane_index].current_index = 0;
  }
  group_metadata_free_locked(group->members, group->metadata_bytes);
  group->members = 0;
  group->member_metadata_capacity = 0;
  group->metadata_bytes = 0;
}

static int group_topology_validate_locked(struct enabled_group_slot* group)
{
  uint64_t topology_mask;

  if (!group ||
      (group->execution_mode != GROUP_MODE_3W_1HM &&
       group->execution_mode != GROUP_MODE_SATURATION_TEST))
    return 0;
  if (group->housekeeping_hart >= MAX_HARTS ||
      group->master_hart >= MAX_HARTS ||
      group->housekeeping_hart !=
          group->housekeeping_cpu + group->cpu_hart_offset ||
      group->master_hart != group->housekeeping_hart ||
      group->worker_count !=
          (uint64_t)group_hart_mask_popcount(group->worker_hart_mask) ||
      group->worker_count > KEYSTONE_GROUP_MAX_WORKER_LANES ||
      (group->worker_hart_mask & group_hart_bit(group->master_hart)))
    return 0;

  topology_mask = group_hart_bit(group->master_hart) |
                  group->worker_hart_mask;
  if (group->configured_hart_mask &&
      topology_mask != group->configured_hart_mask)
    return 0;

  if (group->execution_mode == GROUP_MODE_3W_1HM &&
      (group->housekeeping_cpu != KEYSTONE_VF2_HOUSEKEEPING_CPU ||
       group->housekeeping_hart != KEYSTONE_VF2_HOUSEKEEPING_HART ||
       group->master_hart != KEYSTONE_VF2_HOUSEKEEPING_HART ||
       group->worker_hart_mask != KEYSTONE_VF2_WORKER_HART_MASK ||
       group->worker_count != 3 ||
       group->cpu_hart_offset != KEYSTONE_VF2_CPU_HART_OFFSET ||
       (group->configured_hart_mask &&
        group->configured_hart_mask !=
            (group_hart_bit(KEYSTONE_VF2_HOUSEKEEPING_HART) |
             KEYSTONE_VF2_WORKER_HART_MASK))))
    return 0;

  return 1;
}

static int group_topology_apply_default_locked(
    struct enabled_group_slot* group)
{
  unsigned long master_hart;

  if (!group)
    return -1;
  if (group->execution_mode == GROUP_MODE_INVALID)
    group->execution_mode =
        configured_group_count == 1 && group->group_id == 1 ?
        GROUP_MODE_3W_1HM : GROUP_MODE_SATURATION_TEST;

  if (group->execution_mode == GROUP_MODE_3W_1HM) {
    group->housekeeping_cpu = KEYSTONE_VF2_HOUSEKEEPING_CPU;
    group->housekeeping_hart = KEYSTONE_VF2_HOUSEKEEPING_HART;
    group->master_hart = KEYSTONE_VF2_HOUSEKEEPING_HART;
    group->worker_hart_mask = KEYSTONE_VF2_WORKER_HART_MASK;
    group->worker_count = 3;
    group->cpu_hart_offset = KEYSTONE_VF2_CPU_HART_OFFSET;
    group->topology_flags |=
        KEYSTONE_GROUP_TOPOLOGY_FLAG_EXPLICIT_CPU_HART_MAP |
        KEYSTONE_GROUP_TOPOLOGY_FLAG_REQUIRE_ISOLATION;
  } else if (group->execution_mode == GROUP_MODE_SATURATION_TEST) {
    master_hart = group_first_hart_in_mask(group->configured_hart_mask);
    if (master_hart >= MAX_HARTS)
      return 0;
    group->master_hart = master_hart;
    group->housekeeping_hart = master_hart;
    group->cpu_hart_offset = KEYSTONE_VF2_CPU_HART_OFFSET;
    if (master_hart < group->cpu_hart_offset)
      return -1;
    group->housekeeping_cpu = master_hart - group->cpu_hart_offset;
    group->worker_hart_mask =
        group->configured_hart_mask & ~group_hart_bit(master_hart);
    group->worker_count =
        group_hart_mask_popcount(group->worker_hart_mask);
    group->topology_flags |=
        KEYSTONE_GROUP_TOPOLOGY_FLAG_EXPLICIT_CPU_HART_MAP;
  } else {
    return -1;
  }

  if (!group->configured_hart_mask)
    return 0;
  if (!group_topology_validate_locked(group))
    return -1;
  return group_topology_rebuild_lanes_locked(group);
}

static int group_lane_add_member_locked(struct group_worker_lane* lane,
                                        enclave_id eid,
                                        uint64_t generation)
{
  size_t i;

  if (!lane || !lane->valid || eid >= ENCL_MAX || !generation)
    return -1;
  if (!lane->runqueue || !lane->runqueue_capacity)
    return -1;
  for (i = 0; i < lane->runqueue_len; i++)
    if (lane->runqueue[i].eid == eid &&
        lane->runqueue[i].eid_generation == generation)
      return 0;
  if (lane->runqueue_len >= lane->runqueue_capacity)
    return -1;
  lane->runqueue[lane->runqueue_len].eid = eid;
  lane->runqueue[lane->runqueue_len].eid_generation = generation;
  lane->runqueue_len++;
  lane->lane_epoch++;
  if (!lane->lane_epoch)
    lane->lane_epoch = 1;
  return 0;
}

static void group_lane_remove_member_locked(struct enabled_group_slot* group,
                                            enclave_id eid)
{
  int lane_index;

  if (!group)
    return;
  for (lane_index = 0;
       lane_index < KEYSTONE_GROUP_MAX_WORKER_LANES;
       lane_index++) {
    struct group_worker_lane* lane = &group->worker_lanes[lane_index];
    size_t src;
    size_t dst = 0;

    if (!lane->valid)
      continue;
    for (src = 0; src < lane->runqueue_len; src++) {
      if (lane->runqueue[src].eid == eid)
        continue;
      lane->runqueue[dst] = lane->runqueue[src];
      dst++;
    }
    if (dst == lane->runqueue_len)
      continue;
    for (src = dst; src < lane->runqueue_capacity; src++) {
      lane->runqueue[src].eid = ENCL_MAX;
      lane->runqueue[src].eid_generation = 0;
    }
    lane->runqueue_len = dst;
    if (lane->current_index >= lane->runqueue_len)
      lane->current_index = 0;
    if (lane->active_eid == eid) {
      lane->active_eid = ENCL_MAX;
      lane->active_eid_generation = 0;
      lane->state = GROUP_WORKER_LANE_IDLE;
    }
    if (lane->last_owner_eid == eid) {
      lane->last_owner_eid = ENCL_MAX;
      lane->last_owner_generation = 0;
    }
    lane->lane_epoch++;
    if (!lane->lane_epoch)
      lane->lane_epoch = 1;
  }
}

static uint64_t group_hart_mask_from_offset(uint64_t offset,
                                            uint64_t hart_count)
{
  uint64_t mask = 0;
  uint64_t i;

  for (i = 0; i < hart_count; i++) {
    uint64_t hartid = (MAX_HARTS >= 5) ? (1 + offset + i) : (offset + i);
    if (hartid < MAX_HARTS)
      mask |= group_hart_bit(hartid);
  }

  return mask;
}

static void group_configure_hart_slots_locked(struct enabled_group_slot* group,
                                              uint64_t hart_mask)
{
  uint64_t hartid;

  if (!group)
    return;

  group->configured_hart_mask = hart_mask;
  group->hart_count = group_hart_mask_popcount(hart_mask);
  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct group_hart_slot* slot = &group->hart_slots[hartid];
    sbi_memset(slot, 0, sizeof(*slot));
    slot->yxstm_slice_region = -1;
    if (hart_mask & group_hart_bit(hartid)) {
      slot->valid = 1;
      slot->hart_id = hartid;
      slot->active_eid = ENCL_MAX;
      slot->yxstm_owner_eid = ENCL_MAX;
      slot->yxstm_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
      slot->yxstm_slot_lane = KEYSTONE_GROUP_UNBOUND_LANE;
      slot->yxstm_slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
    }
  }
}

static int group_hart_allowed_locked(struct enabled_group_slot* group,
                                     unsigned long hartid)
{
  if (!group || hartid >= MAX_HARTS)
    return 0;
  return (group->configured_hart_mask & group_hart_bit(hartid)) != 0;
}

static uint64_t group_default_role_for_hart_locked(
    struct enabled_group_slot* group,
    unsigned long hartid)
{
  if (!group || !group_hart_allowed_locked(group, hartid))
    return GROUP_ROLE_NONE;
  if (hartid == group->master_hart)
    return GROUP_ROLE_MASTER;
  return group_lane_for_hart_locked(group, hartid) ?
         GROUP_ROLE_WORKER : GROUP_ROLE_NONE;
}

static uint64_t group_default_slice_mask_for_hart_locked(
    struct enabled_group_slot* group,
    unsigned long hartid)
{
  uint64_t role = group_default_role_for_hart_locked(group, hartid);
  struct group_worker_lane* lane;

  if (role == GROUP_ROLE_MASTER)
    return KEYSTONE_YXSTM_MASTER_SLICE_MASK;

  if (role == GROUP_ROLE_WORKER) {
    lane = group_lane_for_hart_locked(group, hartid);
    if (lane)
      return lane->slice_mask;
  }

  return 0;
}

static unsigned long group_hart_for_slice_index_locked(
    struct enabled_group_slot* group,
    uint64_t slice_index)
{
  int i;

  if (!group || slice_index >= KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
    return MAX_HARTS;

  if (slice_index == KEYSTONE_YXSTM_MASTER_SLICE_ID)
    return group->master_hart;
  for (i = 0; i < KEYSTONE_GROUP_MAX_WORKER_LANES; i++)
    if (group->worker_lanes[i].valid &&
        group->worker_lanes[i].slice_id == slice_index)
      return group->worker_lanes[i].hart_id;

  return MAX_HARTS;
}

static unsigned long group_default_hart_for_member_index_locked(
    struct enabled_group_slot* group,
    size_t member_index)
{
  uint64_t configured_harts;
  uint64_t slice_index;

  if (!group)
    return MAX_HARTS;

  configured_harts = group_hart_mask_popcount(group->configured_hart_mask);
  if (!configured_harts)
    return MAX_HARTS;
  if (configured_harts > KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
    configured_harts = KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;

  if (group->execution_mode == GROUP_MODE_3W_1HM) {
    if (!member_index)
      return group->master_hart;
    if (!group->worker_count)
      return MAX_HARTS;
    slice_index = 1 + ((member_index - 1) % group->worker_count);
    return group_hart_for_slice_index_locked(group, slice_index);
  }

  slice_index = member_index % configured_harts;
  return group_hart_for_slice_index_locked(group, slice_index);
}

static int group_member_update_binding_locked(struct enabled_group_slot* group,
                                              enclave_id eid,
                                              unsigned long hartid)
{
  struct group_member_descriptor* member;
  struct group_worker_lane* lane = 0;
  uint64_t role;
  uint64_t slice_mask;
  uint64_t lane_id = KEYSTONE_GROUP_UNBOUND_LANE;
  uint64_t lane_rank = KEYSTONE_GROUP_UNBOUND_LANE;
  int i;

  if (!group || eid >= ENCL_MAX || hartid >= MAX_HARTS)
    return -1;

  member = group_member_find_locked(group, eid);
  if (!member || !member->valid)
    return -1;
  if (member->bound_hart != KEYSTONE_GROUP_UNBOUND_HART &&
      member->bound_hart != hartid)
    return -1;

  role = group_default_role_for_hart_locked(group, hartid);
  slice_mask = group_default_slice_mask_for_hart_locked(group, hartid);
  if (role == GROUP_ROLE_NONE || !slice_mask)
    return -1;

  if (role == GROUP_ROLE_WORKER) {
    lane = group_lane_for_hart_locked(group, hartid);
    if (!lane)
      return -1;
    lane_id = lane->lane_id;
  }

  for (i = 0; i < (int)group->member_metadata_capacity; i++) {
    struct group_member_descriptor* other = &group->members[i];
    if (!other->valid || other->eid == eid)
      continue;
    if (role == GROUP_ROLE_MASTER && other->role == GROUP_ROLE_MASTER) {
      if (group->execution_mode != GROUP_MODE_SATURATION_TEST)
        return -1;
      role = GROUP_ROLE_AUXILIARY;
      slice_mask = 0;
      lane_id = KEYSTONE_GROUP_UNBOUND_LANE;
      break;
    }
  }

  if (member->role != GROUP_ROLE_NONE &&
      member->allowed_slice_mask &&
      (member->role != role ||
       member->allowed_slice_mask != slice_mask))
    return -1;

  if (lane && group_lane_add_member_locked(lane, eid,
                                           member->eid_generation))
    return -1;
  if (lane) {
    size_t rank;

    for (rank = 0; rank < lane->runqueue_len; rank++)
      if (lane->runqueue[rank].eid == eid &&
          lane->runqueue[rank].eid_generation == member->eid_generation) {
        lane_rank = rank;
        break;
      }
    if (lane_rank == KEYSTONE_GROUP_UNBOUND_LANE)
      return -1;
  }

  member->role = role;
  member->bound_hart = hartid;
  member->lane_id = lane_id;
  member->lane_rank = lane_rank;
  member->lane_wait_sequence = 0;
  member->lane_wait_turn = 0;
  member->lane_wait_phase = 0;
  member->lane_wait_task_epoch = 0;
  member->lane_wait_result = SBI_ERR_SM_ENCLAVE_SUCCESS;
  member->lane_wait_started_at = 0;
  member->lane_wait_pending = 0;
  member->lane_wait_task_bank = 0;
  member->lane_wait_ready = 0;
  member->lane_wait_context_saved = 0;
  member->yxstm_completion_pending = 0;
  member->yxstm_completion_epoch = 0;
  member->task_epoch = lane ? lane->task_epoch : group->yxstm_task_epoch;
  member->allowed_slice_mask = slice_mask;
  return 0;
}

static void group_scheduler_reset_hart_locked(unsigned long hartid)
{
  struct sm_hart_sched* sched;

  if (hartid >= MAX_HARTS)
    return;

  sched = &group_hart_schedulers[hartid];
  sbi_memset(sched, 0, sizeof(*sched));
  sched->hart_id = hartid;
  sched->active_eid = ENCL_MAX;
  sched->host_service_eid = ENCL_MAX;
  sched->last_progress_time = sbi_timer_value();
}

static void group_scheduler_reset_locked(void)
{
  unsigned long hartid;

  for (hartid = 0; hartid < MAX_HARTS; hartid++)
    group_scheduler_reset_hart_locked(hartid);
  sbi_memset(group_member_timer_ready, 0,
             sizeof(group_member_timer_ready));
  sbi_memset(group_member_saved_mepc_advanced, 0,
             sizeof(group_member_saved_mepc_advanced));
  sbi_memset(group_ecall_switch_log_count, 0,
             sizeof(group_ecall_switch_log_count));
  sbi_memset(group_timer_retry_log_count, 0,
             sizeof(group_timer_retry_log_count));
#if KEYSTONE_GROUP_TIMER_TRACE
  sbi_memset(group_timer_switch_log_count, 0,
             sizeof(group_timer_switch_log_count));
  sbi_memset(group_timer_candidate_log_count, 0,
             sizeof(group_timer_candidate_log_count));
#endif
#if KEYSTONE_GROUP_STARTUP_TRACE
  sbi_memset(group_timer_config_log_seen, 0,
             sizeof(group_timer_config_log_seen));
#endif
  sbi_memset(group_hart_run_status_ptr, 0,
             sizeof(group_hart_run_status_ptr));
  sbi_memset(group_hart_event_queues, 0,
             sizeof(group_hart_event_queues));
  sbi_memset(group_ocalls, 0, sizeof(group_ocalls));
  group_ocall_sequence = 0;
  sbi_memset(group_control_requests, 0, sizeof(group_control_requests));
  sbi_memset(group_hart_host_threads, 0,
             sizeof(group_hart_host_threads));
  sbi_memset(group_hart_host_context_valid, 0,
             sizeof(group_hart_host_context_valid));
}

static int group_scheduler_event_enqueue(unsigned long hartid,
                                         uint64_t group_id,
                                         uint64_t group_generation,
                                         enclave_id eid,
                                         uint64_t eid_generation,
                                         uintptr_t event,
                                         uintptr_t error,
                                         uintptr_t value)
{
  struct group_scheduler_event_queue* queue;
  struct group_scheduler_event* entry;
  uint64_t scheduler_epoch = 0;

  if (hartid >= MAX_HARTS || !event)
    return -1;
  if (group_hart_schedulers[hartid].valid)
    scheduler_epoch = group_hart_schedulers[hartid].sched_epoch;

  spin_lock(&group_event_lock);
  queue = &group_hart_event_queues[hartid];
  if (queue->count >= KEYSTONE_GROUP_EVENT_QUEUE_DEPTH) {
    queue->overflow_count++;
    queue->head = (queue->head + 1) % KEYSTONE_GROUP_EVENT_QUEUE_DEPTH;
    queue->count--;
    sbi_printf("[SM][sched] event queue overflow: hart=%lu group=%lu eid=%u event=%lu overflows=%lu\n",
               hartid, (unsigned long)group_id, eid,
               (unsigned long)event,
               (unsigned long)queue->overflow_count);
  }

  entry = &queue->entries[queue->tail];
  sbi_memset(entry, 0, sizeof(*entry));
  entry->group_id = group_id;
  entry->group_generation = group_generation;
  entry->hart_id = hartid;
  entry->eid = eid;
  entry->eid_generation = eid_generation;
  entry->event = event;
  entry->error = error;
  entry->value = value;
  entry->sequence = ++queue->next_sequence;
  if (!entry->sequence)
    entry->sequence = ++queue->next_sequence;
  entry->scheduler_epoch = scheduler_epoch;
  entry->timestamp = sbi_timer_value();
  queue->tail = (queue->tail + 1) % KEYSTONE_GROUP_EVENT_QUEUE_DEPTH;
  queue->count++;
  spin_unlock(&group_event_lock);
  return 0;
}

static int group_scheduler_event_dequeue(
    unsigned long hartid, uint64_t group_id, uint64_t group_generation,
    struct keystone_group_run_hart* status)
{
  struct group_scheduler_event_queue* queue;

  if (hartid >= MAX_HARTS || !status)
    return 0;

  spin_lock(&group_event_lock);
  queue = &group_hart_event_queues[hartid];
  while (queue->count) {
    struct group_scheduler_event* entry = &queue->entries[queue->head];

    queue->head = (queue->head + 1) % KEYSTONE_GROUP_EVENT_QUEUE_DEPTH;
    queue->count--;
    if (entry->group_id != group_id ||
        entry->group_generation != group_generation)
      continue;
    sm_abi_fill(&status->abi, sizeof(*status),
                KEYSTONE_GROUP_ABI_FEATURES);
    status->group_id = entry->group_id;
    status->group_generation = entry->group_generation;
    status->hart_id = entry->hart_id;
    status->eid = entry->eid;
    status->event = entry->event;
    status->error = entry->error;
    status->value = entry->value;
    status->event_sequence = entry->sequence;
    status->scheduler_epoch = entry->scheduler_epoch;
    status->queue_overflows = queue->overflow_count;
    spin_unlock(&group_event_lock);
    return 1;
  }
  spin_unlock(&group_event_lock);
  return 0;
}

static void group_scheduler_event_purge_group(uint64_t group_id,
                                               uint64_t group_generation)
{
  unsigned long hartid;

  spin_lock(&group_event_lock);
  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct group_scheduler_event_queue* queue =
        &group_hart_event_queues[hartid];
    size_t original_count = queue->count;
    size_t read_index = queue->head;
    size_t write_index = queue->head;
    size_t kept = 0;
    size_t i;

    for (i = 0; i < original_count; i++) {
      struct group_scheduler_event entry = queue->entries[read_index];
      read_index = (read_index + 1) % KEYSTONE_GROUP_EVENT_QUEUE_DEPTH;
      /* A group id cannot have two live generations. Once its current
       * generation is quiesced, every queued event carrying the same id is
       * stale, including leftovers from older failed runs. */
      if (entry.group_id == group_id)
        continue;
      queue->entries[write_index] = entry;
      write_index = (write_index + 1) % KEYSTONE_GROUP_EVENT_QUEUE_DEPTH;
      kept++;
    }
    for (i = kept; i < original_count; i++) {
      size_t clear_index =
          (queue->head + i) % KEYSTONE_GROUP_EVENT_QUEUE_DEPTH;
      sbi_memset(&queue->entries[clear_index], 0,
                 sizeof(queue->entries[clear_index]));
    }
    queue->count = kept;
    queue->tail = (queue->head + kept) % KEYSTONE_GROUP_EVENT_QUEUE_DEPTH;
    /*
     * keystone-group-event-overflow-epoch-v3
     *
     * overflow_count describes loss in the events currently owned by this
     * per-hart queue.  Keeping it after the last event is purged makes a new
     * group generation inherit an unrelated historical overflow and causes
     * the host to reject its first otherwise valid OCALL.  Preserve the
     * counter while another group's events remain, but start a clean epoch
     * once the queue is empty.
     */
    if (!queue->count)
      queue->overflow_count = 0;
  }
  (void)group_generation;
  spin_unlock(&group_event_lock);
}

static int group_ocall_register_locked(enclave_id eid,
                                       uint64_t timeout_cycles)
{
  struct group_ocall_record* record;
  struct enabled_group_slot* group;
  uint64_t handler_started = csr_read(CSR_MCYCLE);
  uint64_t now;

  if (!ENCLAVE_EXISTS(eid) || enclaves[eid].group_id == 0 ||
      !enclaves[eid].hart_bound || enclaves[eid].assigned_hart >= MAX_HARTS)
    return -1;
  record = &group_ocalls[eid];
  if (record->valid)
    return -1;
  group = find_group_locked(enclaves[eid].group_id);
  if (!group)
    return -1;

  now = sbi_timer_value();
  if (!timeout_cycles)
    timeout_cycles = KEYSTONE_GROUP_OCALL_TIMEOUT_CYCLES;
  if (~(uint64_t)0 - now < timeout_cycles)
    return -1;
  sbi_memset(record, 0, sizeof(*record));
  record->valid = 1;
  record->ocall_id = ++group_ocall_sequence;
  if (!record->ocall_id)
    record->ocall_id = ++group_ocall_sequence;
  record->group_id = group->group_id;
  record->group_generation = group->generation;
  record->hart_id = enclaves[eid].assigned_hart;
  record->eid = eid;
  record->eid_generation = enclaves[eid].generation;
  record->created_at = now;
  record->deadline = now + timeout_cycles;
  /* The cookie is an opaque, generation-bound host completion token. */
  record->host_cookie = record->ocall_id ^ group->generation ^
                        enclaves[eid].generation;
  if (!record->host_cookie)
    record->host_cookie = record->ocall_id;
  record->flags = 0;
  record->perf_start_cycle = csr_read(CSR_MCYCLE);
  record->perf_handler_cycles =
      csr_read(CSR_MCYCLE) - handler_started;
  group_ocall_resume_start_cycle[eid] = 0;
  group_ocall_resume_generation[eid] = 0;
  return 0;
}

static void group_perf_complete_ocall_locked(
    const struct group_ocall_record* record,
    uint64_t terminal_handler_cycles)
{
  uint64_t now;
  uint64_t wait_ticks = 0;

  if (!record || !record->valid)
    return;
  now = sbi_timer_value();
  if (now >= record->created_at)
    wait_ticks = now - record->created_at;
  atomic_add_return(&group_perf_ocall_handler_count, 1);
  atomic_add_return(
      &group_perf_ocall_handler_cycles,
      (long)(record->perf_handler_cycles + terminal_handler_cycles));
  atomic_add_return(&group_perf_ocall_wait_count, 1);
  atomic_add_return(&group_perf_ocall_wait_ticks, (long)wait_ticks);
}

static void group_ocall_clear_locked(enclave_id eid,
                                     uint64_t terminal_handler_cycles)
{
  if (eid >= ENCL_MAX)
    return;
  group_perf_complete_ocall_locked(&group_ocalls[eid],
                                   terminal_handler_cycles);
  sbi_memset(&group_ocalls[eid], 0, sizeof(group_ocalls[eid]));
}

static void group_ocall_expire_locked(void)
{
  enclave_id eid;
  uint64_t now = sbi_timer_value();

  for (eid = 0; eid < ENCL_MAX; eid++) {
    struct group_ocall_record* record = &group_ocalls[eid];
    struct enabled_group_slot* group;

    if (!record->valid ||
        (int64_t)(now - record->deadline) < 0)
      continue;
    group = find_group_locked(record->group_id);
    if (group && group->generation == record->group_generation &&
        ENCLAVE_EXISTS(eid) &&
        enclaves[eid].generation == record->eid_generation &&
        enclaves[eid].sched_state == GROUP_SCHED_BLOCKED) {
      enclaves[eid].threads[0].prev_state.a0 =
          SBI_ERR_SM_GROUP_OCALL_TIMEOUT;
      (void)group_scheduler_transition_locked(eid, GROUP_SCHED_RUNNABLE,
                                              "ocall_timeout");
      group_member_timer_ready[eid] = 1;
      (void)group_scheduler_event_enqueue(
          record->hart_id, record->group_id, record->group_generation,
          eid, record->eid_generation, KEYSTONE_GROUP_EVENT_OCALL,
          SBI_ERR_SM_GROUP_OCALL_TIMEOUT, record->ocall_id);
    }
    group_ocall_clear_locked(eid, 0);
  }
}

static int group_scheduler_find_locked(struct sm_hart_sched* sched,
                                       enclave_id eid)
{
  size_t i;

  if (!sched)
    return -1;

  for (i = 0; i < sched->runqueue_len; i++) {
    if (sched->runqueue[i].eid == eid &&
        eid < ENCL_MAX && ENCLAVE_EXISTS(eid) &&
        sched->runqueue[i].eid_generation == enclaves[eid].generation)
      return (int)i;
  }

  return -1;
}

static int group_scheduler_active_matches_locked(
    const struct sm_hart_sched* sched, enclave_id eid)
{
  return sched && sched->valid && eid < ENCL_MAX && ENCLAVE_EXISTS(eid) &&
         sched->active_eid == eid &&
         sched->active_eid_generation == enclaves[eid].generation;
}

static void group_scheduler_progress_locked(struct sm_hart_sched* sched)
{
  if (!sched)
    return;
  sched->sched_epoch++;
  if (!sched->sched_epoch)
    sched->sched_epoch++;
  sched->last_progress_epoch = sched->sched_epoch;
  sched->last_progress_time = sbi_timer_value();
}

static void group_scheduler_clear_host_service_locked(
    struct sm_hart_sched* sched)
{
  if (!sched)
    return;
  sched->host_service_forced = 0;
  sched->host_service_drop_grant = 0;
  sched->host_service_deadline = 0;
  sched->host_service_pending = 0;
  sched->host_service_eid = ENCL_MAX;
  sched->host_service_eid_generation = 0;
  sched->host_service_group_generation = 0;
  sched->host_service_event_sequence = 0;
  sched->host_service_start_cycle = 0;
  sched->host_service_grant_suspended = 0;
  sched->host_service_grant_cycles = 0;
  sched->heartbeat_pending_sources = 0;
  sched->heartbeat_handoff_sources = 0;
  sched->heartbeat_cleared_sources = 0;
  sched->heartbeat_deadline = 0;
  sched->heartbeat_state = KEYSTONE_GROUP_HEARTBEAT_STATE_IDLE;
}

static int group_scheduler_commit_host_service_locked(
    struct sm_hart_sched* sched, uint64_t event_sequence)
{
  uint64_t started;

  if (!sched || !event_sequence || !sched->host_service_pending ||
      !sched->host_service_drop_grant ||
      sched->host_service_grant_suspended ||
      sched->host_service_event_sequence != event_sequence)
    return 0;

  /*
   * event_sequence is returned only after CPU0 has committed the phase edge.
   * No YXSTM grant is suspended in this path, so the interrupted worker no
   * longer needs an exclusive reentry reservation. Its saved context remains
   * RUNNABLE and competes normally with READY peers on the same lane.
   */
  started = sched->host_service_start_cycle;
  atomic_add_return(&group_perf_host_service_count, 1);
  if (started)
    atomic_add_return(&group_perf_host_service_cycles,
                      (long)(csr_read(CSR_MCYCLE) - started));
  group_scheduler_clear_host_service_locked(sched);
  group_scheduler_progress_locked(sched);
  return 1;
}

static int group_scheduler_validate_locked(struct sm_hart_sched* sched,
                                           const char* where)
{
  size_t i;
  size_t j;
  int active_found = 0;
  int running_count = 0;

  if (!sched || !sched->valid)
    return 1;
  if (sched->hart_id >= MAX_HARTS ||
      sched->runqueue_len > sched->runqueue_capacity ||
      (sched->runqueue_len && !sched->runqueue) ||
      (sched->runqueue_len && sched->current_index >= sched->runqueue_len))
    goto invalid;

  for (i = 0; i < sched->runqueue_len; i++) {
    enclave_id eid = sched->runqueue[i].eid;
    struct enabled_group_slot* group;
    struct group_member_descriptor* member;
    if (eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
        sched->runqueue[i].eid_generation != enclaves[eid].generation ||
        !enclaves[eid].hart_bound ||
        enclaves[eid].assigned_hart != sched->hart_id ||
        enclaves[eid].group_id != sched->active_group_id)
      goto invalid;
    group = find_group_locked(enclaves[eid].group_id);
    member = group ? group_member_find_locked(group, eid) : 0;
    if (!member ||
        member->sched_base_priority > KEYSTONE_GROUP_SCHED_PRIORITY_MAX ||
        member->sched_weight !=
            group_scheduler_cfs_weight(member->sched_base_priority) ||
        !member->sched_quantum_ticks ||
        member->sched_quantum_ticks > KEYSTONE_GROUP_SCHED_QUANTUM_MAX)
      goto invalid;
    if (enclaves[eid].sched_state == GROUP_SCHED_RUNNING)
      running_count++;
    for (j = i + 1; j < sched->runqueue_len; j++)
      if (sched->runqueue[j].eid == eid &&
          sched->runqueue[j].eid_generation ==
              sched->runqueue[i].eid_generation)
        goto invalid;
    if (sched->active_eid == eid &&
        sched->active_eid_generation == enclaves[eid].generation) {
      active_found++;
      if (enclaves[eid].sched_state != GROUP_SCHED_RUNNING &&
          !(sched->host_service_pending &&
            sched->host_service_eid == eid &&
            enclaves[eid].sched_state == GROUP_SCHED_RUNNABLE))
        goto invalid;
    }
  }
  if ((sched->active_eid == ENCL_MAX && active_found) ||
      (sched->active_eid != ENCL_MAX && active_found != 1))
    goto invalid;
  if ((!sched->host_service_pending &&
       running_count != (sched->active_eid == ENCL_MAX ? 0 : 1)) ||
      (sched->host_service_pending && running_count > 1))
    goto invalid;
  if (sched->host_service_pending) {
    enclave_id host_eid = sched->host_service_eid;
    if (host_eid >= ENCL_MAX || !ENCLAVE_EXISTS(host_eid) ||
        sched->host_service_eid_generation != enclaves[host_eid].generation ||
        sched->host_service_group_generation !=
            sched->active_group_generation ||
        enclaves[host_eid].group_id != sched->active_group_id ||
        !enclaves[host_eid].hart_bound ||
        enclaves[host_eid].assigned_hart != sched->hart_id ||
        group_scheduler_find_locked(sched, host_eid) < 0 ||
        (enclaves[host_eid].sched_state != GROUP_SCHED_RUNNABLE &&
         enclaves[host_eid].sched_state != GROUP_SCHED_RUNNING) ||
        (sched->active_eid != ENCL_MAX &&
         sched->active_eid != host_eid))
      goto invalid;
    if (sched->heartbeat_enabled &&
        (sched->heartbeat_state !=
             KEYSTONE_GROUP_HEARTBEAT_STATE_REQUESTED &&
         sched->heartbeat_state != KEYSTONE_GROUP_HEARTBEAT_STATE_ACKED &&
         sched->heartbeat_state != KEYSTONE_GROUP_HEARTBEAT_STATE_VERIFIED))
      goto invalid;
  }
  return 1;

invalid:
  sbi_printf("[SM][sched] invariant failure: where=%s hart=%lu group=%lu active=%u len=%lu index=%lu epoch=%lu\n",
             where, (unsigned long)sched->hart_id,
             (unsigned long)sched->active_group_id, sched->active_eid,
             (unsigned long)sched->runqueue_len,
             (unsigned long)sched->current_index,
             (unsigned long)sched->sched_epoch);
  return 0;
}

static int group_scheduler_transition_ex_locked(enclave_id eid,
                                                enum group_sched_state next,
                                                const char* where,
                                                int defer_kick)
{
  enum group_sched_state current;
  struct sm_hart_sched* sched = 0;
  int allowed = 0;
  int wake_idle_hart = 0;

  if (!ENCLAVE_EXISTS(eid) || enclaves[eid].group_id == 0)
    return -1;
  current = enclaves[eid].sched_state;
  if (current == next)
    return 0;
  switch (current) {
    case GROUP_SCHED_NONE:
      allowed = next == GROUP_SCHED_RUNNABLE;
      break;
    case GROUP_SCHED_RUNNABLE:
      allowed = next == GROUP_SCHED_RUNNING || next == GROUP_SCHED_EXITED ||
                next == GROUP_SCHED_PAUSED || next == GROUP_SCHED_FAULTED;
      break;
    case GROUP_SCHED_RUNNING:
      allowed = next == GROUP_SCHED_RUNNABLE ||
                 next == GROUP_SCHED_BLOCKED || next == GROUP_SCHED_EXITED ||
                 next == GROUP_SCHED_PAUSED || next == GROUP_SCHED_FAULTED;
      break;
    case GROUP_SCHED_BLOCKED:
      allowed = next == GROUP_SCHED_RUNNABLE || next == GROUP_SCHED_EXITED ||
                next == GROUP_SCHED_FAULTED;
      break;
    case GROUP_SCHED_PAUSED:
      allowed = next == GROUP_SCHED_RUNNABLE || next == GROUP_SCHED_EXITED ||
                next == GROUP_SCHED_FAULTED;
      break;
    case GROUP_SCHED_FAULTED:
      allowed = next == GROUP_SCHED_FAULTED || next == GROUP_SCHED_EXITED;
      break;
    case GROUP_SCHED_EXITED:
      allowed = next == GROUP_SCHED_EXITED;
      break;
    default:
      break;
  }
  if (!allowed) {
    sbi_printf("[SM][sched] illegal transition: where=%s eid=%u %u->%u\n",
               where, eid, (unsigned int)current, (unsigned int)next);
    return -1;
  }
  enclaves[eid].sched_state = next;
  if (enclaves[eid].hart_bound && enclaves[eid].assigned_hart < MAX_HARTS) {
    struct enabled_group_slot* group =
        find_group_locked(enclaves[eid].group_id);
    struct group_member_descriptor* member =
        group ? group_member_find_locked(group, eid) : 0;
    sched = &group_hart_schedulers[enclaves[eid].assigned_hart];
    if (next == GROUP_SCHED_RUNNABLE && current != GROUP_SCHED_RUNNABLE &&
        current != GROUP_SCHED_RUNNING && member) {
      uint64_t now = sbi_timer_value();
      uint64_t wakeup_delta = group_scheduler_timer_delta_for_us_local(
          KEYSTONE_GROUP_SCHED_CFS_WAKEUP_GRAN_US);

      group_scheduler_cfs_place_entity_locked(sched, member, 1);
      if (sched->active_eid == ENCL_MAX &&
          current != GROUP_SCHED_NONE) {
        /*
         * An HSM-leased idle lane has no running enclave or timer trap that
         * can discover this runnable transition. Wake it explicitly.
         */
        wake_idle_hart = 1;
      } else if (sched->active_eid != eid) {
        uint64_t deadline = now + wakeup_delta;
        if (deadline < now)
          deadline = ~(uint64_t)0;
        sched->cfs_timer_enabled = 1;
        if (!sched->cfs_slice_deadline ||
            deadline < sched->cfs_slice_deadline)
          sched->cfs_slice_deadline = deadline;
        sched->cfs_resched_pending = 1;
      }
    }
    group_scheduler_progress_locked(sched);
    if (!defer_kick && (wake_idle_hart || sched->cfs_resched_pending))
      (void)group_scheduler_ipi_kick(group_hart_bit(sched->hart_id));
  }
  return 0;
}

static int group_scheduler_transition_locked(enclave_id eid,
                                             enum group_sched_state next,
                                             const char* where)
{
  return group_scheduler_transition_ex_locked(eid, next, where, 0);
}

static void group_lane_wait_clear_locked(
    struct group_member_descriptor* member)
{
  if (!member)
    return;
  member->lane_wait_sequence = 0;
  member->lane_wait_turn = 0;
  member->lane_wait_phase = 0;
  member->lane_wait_task_epoch = 0;
  member->lane_wait_result = SBI_ERR_SM_ENCLAVE_SUCCESS;
  member->lane_wait_started_at = 0;
  member->lane_wait_pending = 0;
  member->lane_wait_task_bank = 0;
  member->lane_wait_ready = 0;
  member->lane_wait_context_saved = 0;
}

static void group_lane_wait_account_and_clear_locked(
    struct group_member_descriptor* member)
{
  uint64_t now;
  uint64_t waited;

  if (!member)
    return;
  now = sbi_timer_value();
  waited = member->lane_wait_started_at &&
                   now >= member->lane_wait_started_at ?
               now - member->lane_wait_started_at : 0;
  atomic_add_return(&group_perf_lane_wait_wake_count, 1);
  atomic_add_return(&group_perf_lane_wait_ticks, (long)waited);
  group_lane_wait_clear_locked(member);
}

/*
 * A slot can become READY before its owner has entered STOP_LANE_WAIT.  That
 * owner is already on the runqueue, but the active member may have armed no
 * CFS timer because it was the only runnable entity at schedule-in.  Publish
 * the new runnable work explicitly so an already-bootstrapped peer
 * participates in CFS immediately instead of waiting for the active worker
 * to finish its complete slot. A FRESH peer must first be launched from a
 * synchronous scheduler boundary; an asynchronous IPI cannot safely invent
 * its initial runtime/host return frame.
 */
static void group_scheduler_kick_ready_member_locked(
    struct group_member_descriptor* member)
{
  struct sm_hart_sched* sched;
  uint64_t now;
  uint64_t wakeup_delta;
  uint64_t deadline;

  if (!member || !member->valid || member->eid >= ENCL_MAX ||
      !ENCLAVE_EXISTS(member->eid) ||
      enclaves[member->eid].sched_state != GROUP_SCHED_RUNNABLE ||
      !enclaves[member->eid].hart_bound ||
      enclaves[member->eid].assigned_hart >= MAX_HARTS)
    return;

  sched = &group_hart_schedulers[enclaves[member->eid].assigned_hart];
  if (!sched->valid ||
      group_scheduler_active_matches_locked(sched, member->eid))
    return;

  /*
   * Timer/IPI switching is a saved-context operation.  A FRESH enclave has no
   * resumable frame yet, while timer_ready is set only after the runtime has
   * installed its timer/trap state.  Let the active member reach WAIT/YIELD,
   * where the synchronous direct-switch path can perform the first launch.
   */
  if (enclaves[member->eid].state == FRESH ||
      !group_member_timer_ready[member->eid] ||
      !enclaves[member->eid].threads[0].prev_mepc)
    return;
  now = sbi_timer_value();
  wakeup_delta = group_scheduler_timer_delta_for_us_local(
      KEYSTONE_GROUP_SCHED_CFS_WAKEUP_GRAN_US);
  deadline = now + wakeup_delta;
  if (deadline < now)
    deadline = ~(uint64_t)0;

  group_scheduler_cfs_place_entity_locked(sched, member, 1);
  group_scheduler_progress_locked(sched);
  /*
   * A leased lane can be parked in firmware after a phase-edge HOST handoff.
   * It has no active enclave or timer trap to observe the runnable owner, so
   * the scheduler IPI must wake the lane directly.  The owner checks above
   * guarantee that this is a saved context, never a FRESH direct launch.
   */
  if (sched->active_eid >= ENCL_MAX ||
      !ENCLAVE_EXISTS(sched->active_eid) ||
      !group_member_timer_ready[sched->active_eid]) {
    (void)group_scheduler_ipi_kick(group_hart_bit(sched->hart_id));
    return;
  }
  sched->cfs_timer_enabled = 1;
  if (!sched->cfs_slice_deadline || deadline < sched->cfs_slice_deadline)
    sched->cfs_slice_deadline = deadline;
  sched->cfs_resched_pending = 1;
  (void)group_scheduler_ipi_kick(group_hart_bit(sched->hart_id));
}

static void group_scheduler_kick_completion_locked(
    struct group_member_descriptor* member)
{
  struct sm_hart_sched* sched;

  if (!member || !member->valid || !member->yxstm_completion_pending ||
      member->eid >= ENCL_MAX || !ENCLAVE_EXISTS(member->eid) ||
      !enclaves[member->eid].hart_bound ||
      enclaves[member->eid].assigned_hart >= MAX_HARTS)
    return;
  sched = &group_hart_schedulers[enclaves[member->eid].assigned_hart];
  if (group_scheduler_active_matches_locked(sched, member->eid))
    return;

  /*
   * COMPUTE_DONE revokes the slot before returning to the eapp. A phase-edge
   * host handoff can save that post-ecall continuation while the member is
   * still marked RUNNING. Once the master frees the slot, preserve and wake
   * that continuation so it can account the batch and enter WAIT/OCALL/EXIT.
   */
  if (enclaves[member->eid].sched_state == GROUP_SCHED_RUNNING &&
      group_member_timer_ready[member->eid] &&
      enclaves[member->eid].threads[0].prev_mepc)
    (void)group_scheduler_transition_locked(
        member->eid, GROUP_SCHED_RUNNABLE, "slot_completion");
  group_scheduler_kick_ready_member_locked(member);
}

static void group_lane_wait_signal_locked(
    struct group_member_descriptor* member, unsigned long result,
    const char* where)
{
  struct sm_hart_sched* sched = 0;
  enum group_sched_state state;
  int runnable_without_transition = 0;

  if (!member || !member->valid || !member->lane_wait_pending)
    return;

  if (result == SBI_ERR_SM_ENCLAVE_SUCCESS &&
      member->role == GROUP_ROLE_WORKER && member->yxstm_slot.valid) {
    if (member->lane_wait_task_bank == GROUP_LANE_WAIT_KIND_TASK_BANK &&
        member->yxstm_slot.state != YXSTM_SLOT_READY &&
        member->yxstm_slot.state != YXSTM_SLOT_COMPUTING &&
        member->yxstm_slot.state != YXSTM_SLOT_AGGREGATING)
      return;
    if (member->lane_wait_task_bank == GROUP_LANE_WAIT_KIND_SLOT_READY &&
        member->yxstm_slot.state != YXSTM_SLOT_READY)
      return;
  }
  /*
   * Publish readiness only after validating the object that caused the wake.
   * Otherwise an early success notification leaves lane_wait_ready set and
   * STOP_LANE_WAIT can return while the worker slot is still FREE.
   */
  member->lane_wait_ready = 1;
  member->lane_wait_result = result;
  if (!member->lane_wait_context_saved || !ENCLAVE_EXISTS(member->eid) ||
      group_ocalls[member->eid].valid)
    return;

  state = enclaves[member->eid].sched_state;
  if (enclaves[member->eid].hart_bound &&
      enclaves[member->eid].assigned_hart < MAX_HARTS)
    sched = &group_hart_schedulers[enclaves[member->eid].assigned_hart];

  if (state == GROUP_SCHED_BLOCKED) {
    if (group_scheduler_transition_locked(member->eid, GROUP_SCHED_RUNNABLE,
                                          where))
      return;
  } else if (state == GROUP_SCHED_RUNNABLE && sched &&
             !group_scheduler_active_matches_locked(sched, member->eid)) {
    /*
     * A timer/IPI accepted just before STOP_LANE_WAIT can publish RUNNABLE
     * after the wait context has been saved. lane_wait_pending then keeps the
     * member out of every picker even though its slot is READY. Treat this as
     * an already-completed BLOCKED -> RUNNABLE edge and explicitly wake the
     * idle lane after clearing the wait predicate below.
     */
    runnable_without_transition = 1;
  } else {
    return;
  }

  enclaves[member->eid].threads[0].prev_state.a0 = result;
  group_member_timer_ready[member->eid] = 1;
  group_lane_wait_account_and_clear_locked(member);

  if (runnable_without_transition) {
    group_scheduler_progress_locked(sched);
    if (sched->active_eid != member->eid) {
      sched->cfs_resched_pending = 1;
      (void)group_scheduler_ipi_kick(group_hart_bit(sched->hart_id));
    }
  }
}

static void group_lane_wait_reconcile_slot_ready_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    const char* where)
{
  size_t index;

  if (!group || hartid >= MAX_HARTS)
    return;

  /*
   * Slot readiness is a level condition. DISPATCH_PUBLISH also sends an
   * immediate wake, but that edge may race with the worker saving its
   * STOP_LANE_WAIT context or with a peer/host handoff. Reconcile against the
   * authoritative slot table before every scheduler pick so a READY slot
   * cannot leave its owner permanently BLOCKED.
   */
  for (index = 0; index < group->member_metadata_capacity; index++) {
    struct group_member_descriptor* member = &group->members[index];

    if (!member->valid || member->role != GROUP_ROLE_WORKER ||
        member->bound_hart != hartid || !member->lane_wait_pending ||
        member->lane_wait_task_bank != GROUP_LANE_WAIT_KIND_SLOT_READY ||
        !member->yxstm_slot.valid ||
        member->lane_wait_phase != member->yxstm_slot.lane_id ||
        member->lane_wait_turn != member->yxstm_slot.slot_id)
      continue;

    if (member->lane_wait_task_epoch &&
        member->lane_wait_task_epoch != member->yxstm_slot.epoch) {
      group_lane_wait_signal_locked(member, SBI_ERR_SM_YXSTM_STALE_EPOCH,
                                    where);
      continue;
    }
    if (member->yxstm_slot.state == YXSTM_SLOT_READY) {
      /*
       * A direct peer handoff saves prev_mepc before publishing the scheduler
       * state. If the one-shot context-saved bookkeeping was missed, a stopped
       * non-active member with a saved frame is sufficient to repair it here.
       * This includes the RUNNABLE + lane_wait_pending race handled by
       * group_lane_wait_signal_locked().
       */
      if (!member->lane_wait_context_saved &&
          member->eid < ENCL_MAX && ENCLAVE_EXISTS(member->eid) &&
          enclaves[member->eid].state == STOPPED &&
          (enclaves[member->eid].sched_state == GROUP_SCHED_BLOCKED ||
           (enclaves[member->eid].sched_state == GROUP_SCHED_RUNNABLE &&
            enclaves[member->eid].hart_bound &&
            enclaves[member->eid].assigned_hart < MAX_HARTS &&
            !group_scheduler_active_matches_locked(
                &group_hart_schedulers[enclaves[member->eid].assigned_hart],
                member->eid))) &&
          enclaves[member->eid].threads[0].prev_mepc)
        member->lane_wait_context_saved = 1;
      group_lane_wait_signal_locked(member, SBI_ERR_SM_ENCLAVE_SUCCESS,
                                    where);
    }
  }
}

static void group_lane_wait_mark_context_saved(enclave_id eid)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;

  spin_lock(&encl_lock);
  group = ENCLAVE_EXISTS(eid) ? find_group_locked(enclaves[eid].group_id) : 0;
  member = group ? group_member_find_locked(group, eid) : 0;
  if (member && member->lane_wait_pending) {
    member->lane_wait_context_saved = 1;
    /*
     * STOP_LANE_WAIT is a scheduler control transfer, not the result of the
     * eapp syscall. Seed the suspended runtime frame explicitly so the host's
     * standard SBI error cannot leak back through a0. A later wake carrying a
     * real cancellation/stale error overwrites this value in the signal path.
     */
    enclaves[eid].threads[0].prev_state.a0 =
        SBI_ERR_SM_ENCLAVE_SUCCESS;
    if (member->lane_wait_ready)
      group_lane_wait_signal_locked(member, member->lane_wait_result,
                                    "lane_wait_context_saved");
  }
  spin_unlock(&encl_lock);
}

static void group_scheduler_set_state_locked(enclave_id eid,
                                             enum group_sched_state state)
{
  if (ENCLAVE_EXISTS(eid) && enclaves[eid].group_id != 0)
    enclaves[eid].sched_state = state;
}

static int group_scheduler_enqueue_locked(struct enabled_group_slot* group,
                                          unsigned long hartid,
                                          enclave_id eid)
{
  struct sm_hart_sched* sched;

  if (!group || hartid >= MAX_HARTS || eid >= ENCL_MAX)
    return -1;
  if (!group_hart_allowed_locked(group, hartid))
    return -1;

  sched = &group_hart_schedulers[hartid];
  if (!sched->valid) {
    sched->valid = 1;
    sched->hart_id = hartid;
    sched->active_eid = ENCL_MAX;
  }

  if (sched->active_group_id &&
      sched->active_group_id != group->group_id)
    return -1;
  if (sched->active_group_id &&
      sched->active_group_generation != group->generation)
    return -1;

  sched->active_group_id = group->group_id;
  sched->active_group_generation = group->generation;

  if (group_scheduler_find_locked(sched, eid) >= 0)
    return 0;

  if (!sched->runqueue ||
      sched->runqueue_len >= sched->runqueue_capacity) {
    sbi_printf("[SM][sched] enqueue failed: hart=%lu group=%lu eid=%u runqueue_full=%lu\n",
               hartid,
               (unsigned long)group->group_id,
               eid,
               (unsigned long)sched->runqueue_len);
    return -1;
  }

  sched->runqueue[sched->runqueue_len].eid = eid;
  sched->runqueue[sched->runqueue_len].eid_generation =
      enclaves[eid].generation;
  sched->runqueue_len++;
  {
    struct group_member_descriptor* member =
        group_member_find_locked(group, eid);
    if (member)
      group_scheduler_cfs_place_entity_locked(sched, member, 0);
  }
  group_scheduler_progress_locked(sched);
  if (KEYSTONE_GROUP_STARTUP_TRACE)
    sbi_printf("[SM][sched] enqueue: hart=%lu group=%lu eid=%u len=%lu epoch=%lu\n",
               hartid,
               (unsigned long)group->group_id,
               eid,
               (unsigned long)sched->runqueue_len,
               (unsigned long)sched->sched_epoch);
  return 0;
}

static int group_scheduler_bind_locked(struct enabled_group_slot* group,
                                       enclave_id eid,
                                       unsigned long hartid)
{
  struct group_member_descriptor* member;
#if KEYSTONE_GROUP_STARTUP_TRACE
  int already_bound;
#endif

  if (!group || eid >= ENCL_MAX || hartid >= MAX_HARTS)
    return -1;
  if (!ENCLAVE_EXISTS(eid) || enclaves[eid].group_id != group->group_id)
    return -1;
  member = group_member_find_locked(group, eid);
  if (!member)
    return -1;
  if (group->execution_mode == GROUP_MODE_3W_1HM &&
      member->role == GROUP_ROLE_WORKER &&
      (!member->pmp_cache_valid || !member->pmp_utm_cache_valid ||
      member->pmp_cache_group_generation != group->generation ||
      !member->pmp_utm_allow.valid || !member->pmp_utm_deny.valid ||
       member->pmp_yxstm_deny_count != 2 ||
       !member->pmp_yxstm_deny[0].valid ||
       !member->pmp_yxstm_deny[1].valid ||
       member->pmp_utm_allow.slot != KEYSTONE_PMP_SLOT_OS_UTM ||
       member->pmp_utm_deny.slot != KEYSTONE_PMP_SLOT_OS_UTM ||
       member->pmp_yxstm_deny[0].slot != KEYSTONE_PMP_SLOT_YXSTM_LO ||
       member->pmp_yxstm_deny[1].slot != KEYSTONE_PMP_SLOT_YXSTM_HI ||
       enclaves[eid].params.shared_utm_size)) {
    sbi_printf("[SM][sched] bind rejected: worker fast-PMP preflight failed group=%lu eid=%u hart=%lu\n",
               (unsigned long)group->group_id, eid, hartid);
    return -1;
  }
  if (!group_hart_allowed_locked(group, hartid))
    return -1;
  if (enclaves[eid].hart_bound && enclaves[eid].assigned_hart != hartid)
    return -1;
#if KEYSTONE_GROUP_STARTUP_TRACE
  already_bound = enclaves[eid].hart_bound &&
                  enclaves[eid].assigned_hart == hartid;
#endif
  if (group_member_update_binding_locked(group, eid, hartid))
    return -1;
  if (group_scheduler_enqueue_locked(group, hartid, eid))
    return -1;

  enclaves[eid].assigned_hart = hartid;
  enclaves[eid].hart_bound = 1;
  if (enclaves[eid].sched_state == GROUP_SCHED_NONE &&
      group_scheduler_transition_locked(eid, GROUP_SCHED_RUNNABLE, "bind"))
    return -1;

#if KEYSTONE_GROUP_STARTUP_TRACE
  if (!already_bound) {
    sbi_printf("[SM][sched] bind: group=%lu eid=%u hart=%lu role=%lu slice_mask=0x%lx state=%u\n",
               (unsigned long)group->group_id,
               eid,
               hartid,
               member ? (unsigned long)member->role : 0,
               member ? (unsigned long)member->allowed_slice_mask : 0,
               (unsigned int)enclaves[eid].sched_state);
  }
#endif
  if (!group_scheduler_validate_locked(&group_hart_schedulers[hartid],
                                       "bind"))
    return -1;
  return 0;
}

static int group_scheduler_choose_hart_locked(struct enabled_group_slot* group,
                                             unsigned long* hartid_out)
{
  unsigned long hartid;
  unsigned long best_hart = MAX_HARTS;
  size_t best_len = KEYSTONE_GROUP_SCHED_MAX_RUNQUEUE + 1;

  if (!group || !hartid_out)
    return -1;

  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct sm_hart_sched* sched;

    if (!group_hart_allowed_locked(group, hartid))
      continue;

    sched = &group_hart_schedulers[hartid];
    if (sched->valid &&
        sched->active_group_id &&
        sched->active_group_id != group->group_id)
      continue;

    if (sched->runqueue_len < best_len) {
      best_len = sched->runqueue_len;
      best_hart = hartid;
    }
  }

  if (best_hart >= MAX_HARTS)
    return -1;

  *hartid_out = best_hart;
  return 0;
}

static int group_scheduler_set_active_locked(
    struct enabled_group_slot* group,
    unsigned long hartid,
    enclave_id eid)
{
  struct sm_hart_sched* sched;
  struct group_member_descriptor* member;
  struct group_worker_lane* lane = 0;
  int index;

  if (group_scheduler_enqueue_locked(group, hartid, eid))
    return -1;

  sched = &group_hart_schedulers[hartid];
  member = group_member_find_locked(group, eid);
  if (!member)
    return -1;
  if (sched->active_eid != ENCL_MAX ||
      !group_scheduler_validate_locked(sched, "set_active_pre"))
    return -1;
  if (member->role == GROUP_ROLE_WORKER) {
    struct group_member_descriptor* last_owner = 0;
    int bank_wait_handoff = 0;
    int shared_handoff = 0;
    int slot_handoff = 0;
    int suspended_resume = 0;

    lane = group_lane_for_id_locked(group, member->lane_id);
    if (!lane || lane->hart_id != hartid ||
        (lane->active_eid != ENCL_MAX && lane->active_eid != eid))
      return -1;
    if (member->yxstm_suspended_acquired) {
      suspended_resume = group_member_suspended_grant_valid_locked(
          group, hartid, member);
      if (!suspended_resume)
        return -1;
    }
    if (lane->active_eid == ENCL_MAX &&
        lane->last_owner_eid != ENCL_MAX &&
        (lane->last_owner_eid != eid ||
         lane->last_owner_generation != enclaves[eid].generation)) {
      if (lane->last_owner_eid < ENCL_MAX &&
          ENCLAVE_EXISTS(lane->last_owner_eid) &&
          enclaves[lane->last_owner_eid].generation ==
              lane->last_owner_generation)
        last_owner = group_member_find_locked(group, lane->last_owner_eid);
      uint64_t bank_id;

      /*
       * Frozen per-member slots are independent channel authorities.  The
       * legacy group/task-bank phase gate below predates that model and can
       * reject a valid owner rotation merely because another slot is active.
       * At this boundary the old hardware grant is already revoked; retain
       * only validated suspended metadata for the exact old/new slot.
       */
      slot_handoff = group->yxstm_slots_frozen && lane->slots_frozen &&
          member->yxstm_slot.valid &&
          member->yxstm_slot.lane_id == lane->lane_id &&
          (!last_owner ||
           (last_owner->yxstm_slot.valid &&
            last_owner->yxstm_slot.lane_id == lane->lane_id));

      /*
       * A timer-preempted member owns an SM-saved continuation, not an
       * installed PMP grant.  Resume it even when another member ran last,
       * after the full slot/epoch/permission validation above.
       */
      if (suspended_resume) {
        lane->owner_switch_count++;
      } else if (slot_handoff) {
        if (group->hart_slots[hartid].yxstm_acquired ||
            (last_owner && last_owner->yxstm_suspended_acquired &&
             !group_member_suspended_grant_valid_locked(
                 group, hartid, last_owner)))
          return -1;
        lane->owner_switch_count++;
      } else {
        bank_wait_handoff = last_owner &&
            group_worker_lane_bank_wait_handoff_locked(
                group, hartid, last_owner, member, 0);

        if (bank_wait_handoff) {
          lane->owner_switch_count++;
        } else if (group->yxstm_phase != YXSTM_PHASE_IDLE ||
            (last_owner && last_owner->yxstm_suspended_acquired &&
             last_owner->yxstm_suspended_bank_id !=
                 KEYSTONE_YXSTM_INVALID_BANK)) {
          if (!last_owner ||
              !group_worker_lane_shared_handoff_locked(
                  group, hartid, last_owner, 0))
            return -1;
          shared_handoff = 1;
          member->task_epoch = lane->task_epoch;
        } else {
          if (group->hart_slots[hartid].yxstm_acquired ||
              (last_owner && last_owner->yxstm_suspended_acquired))
            return -1;
        }
      }
      if (!suspended_resume && !slot_handoff &&
          !bank_wait_handoff && !shared_handoff)
        for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++) {
          if (group->task_banks[bank_id].phase != YXSTM_PHASE_IDLE)
            return -1;
        }
      if (!suspended_resume && !slot_handoff &&
          !bank_wait_handoff && !shared_handoff &&
          group->yxstm_phase == YXSTM_PHASE_IDLE) {
        /*
         * IDLE exposes no YXSTM grant. Do not synchronously zero every bank
         * while holding encl_lock on each scheduler rotation: task_begin
         * revokes old permissions and scrubs the complete active slice mask
         * before DISPATCH can grant access. This keeps the security boundary
         * while avoiding O(bank_size * runnable_members) bootstrap work under
         * the global scheduler lock.
         */
        lane->owner_switch_count++;
        lane->task_epoch = group->yxstm_task_epoch;
        member->task_epoch = lane->task_epoch;
      }
    }
  }
  index = group_scheduler_find_locked(sched, eid);
  if (index < 0)
    return -1;

  sched->active_group_id = group->group_id;
  sched->active_group_generation = group->generation;
  sched->active_eid = eid;
  sched->active_eid_generation = enclaves[eid].generation;
  sched->current_index = (size_t)index;
  group_scheduler_progress_locked(sched);
  group_scheduler_set_state_locked(eid, GROUP_SCHED_RUNNING);
  member->sched_last_run_epoch = sched->sched_epoch;
  group_scheduler_cfs_prepare_active_locked(
      group, sched, member, sbi_timer_value());
  if (member->role == GROUP_ROLE_MASTER) {
    int boundary = group->yxstm_phase != YXSTM_PHASE_COMPUTE;
    uint64_t bank_id;

    if (group->yxstm_bank_count) {
      boundary = 0;
      for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++)
        if (group->task_banks[bank_id].phase != YXSTM_PHASE_COMPUTE) {
          boundary = 1;
          break;
        }
    }
    if (!boundary)
      group->master_non_boundary_entries++;
  }
  if (lane) {
    size_t lane_index;
    uint64_t running_workers = 0;
    lane->active_eid = eid;
    lane->active_eid_generation = enclaves[eid].generation;
    lane->state = GROUP_WORKER_LANE_RUNNING;
    for (lane_index = 0; lane_index < lane->runqueue_len; lane_index++)
      if (lane->runqueue[lane_index].eid == eid &&
          lane->runqueue[lane_index].eid_generation ==
              enclaves[eid].generation) {
        lane->current_index = lane_index;
        break;
      }
    lane->lane_epoch++;
    if (!lane->lane_epoch)
      lane->lane_epoch = 1;
    for (lane_index = 0;
         lane_index < KEYSTONE_GROUP_MAX_WORKER_LANES;
         lane_index++)
      if (group->worker_lanes[lane_index].valid &&
          group->worker_lanes[lane_index].state ==
              GROUP_WORKER_LANE_RUNNING)
        running_workers++;
    if (running_workers > group->max_running_workers)
      group->max_running_workers = running_workers;
  }
  if (!group_scheduler_validate_locked(sched, "set_active")) {
    /*
     * Do not leave a half-committed active eid/lane behind. A later peer
     * would otherwise be rejected forever by the lane owner check.
     */
    group_scheduler_set_state_locked(eid, GROUP_SCHED_RUNNABLE);
    group_scheduler_clear_active_locked(hartid, eid);
    return -1;
  }
  return 0;
}

static void group_scheduler_clear_active_locked(unsigned long hartid,
                                                enclave_id eid)
{
  struct sm_hart_sched* sched;
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  struct group_worker_lane* lane;
  uint64_t now;

  if (hartid >= MAX_HARTS)
    return;

  sched = &group_hart_schedulers[hartid];
  if (!sched->valid || sched->active_eid != eid ||
      !ENCLAVE_EXISTS(eid) ||
      sched->active_eid_generation != enclaves[eid].generation)
    return;

  group = find_group_locked(enclaves[eid].group_id);
  member = group ? group_member_find_locked(group, eid) : 0;
  now = sbi_timer_value();
  if (group && member)
    group_scheduler_cfs_account_current_locked(
        group, sched, eid, now);
  if (member) {
    group_member_publish_exec_clock_locked(member, now, 0);
    member->sched_exec_start_time = 0;
  }
  /*
   * Clearing active_eid is a scheduler boundary.  Some asynchronous paths
   * (notably a forced phase-edge HOST handoff after a direct peer switch)
   * can reach it before their caller has published RUNNABLE.  Never leave a
   * runqueue member marked RUNNING without a matching active_eid.
   */
  if (enclaves[eid].sched_state == GROUP_SCHED_RUNNING)
    group_scheduler_set_state_locked(eid, GROUP_SCHED_RUNNABLE);
  sched->active_eid = ENCL_MAX;
  sched->active_eid_generation = 0;
  sched->cfs_timer_enabled = 0;
  sched->cfs_resched_pending = 0;
  sched->cfs_slice_deadline = 0;
  sched->cfs_current_slice_ticks = 0;
  lane = member && member->role == GROUP_ROLE_WORKER ?
      group_lane_for_id_locked(group, member->lane_id) : 0;
  if (lane && lane->active_eid == eid) {
    lane->active_eid = ENCL_MAX;
    lane->active_eid_generation = 0;
    lane->state = GROUP_WORKER_LANE_IDLE;
    lane->last_owner_eid = eid;
    lane->last_owner_generation = enclaves[eid].generation;
    lane->lane_epoch++;
    if (!lane->lane_epoch)
      lane->lane_epoch = 1;
  }
  group_scheduler_progress_locked(sched);
  (void)group_scheduler_validate_locked(sched, "clear_active");
}

static void group_scheduler_remove_eid_locked(enclave_id eid)
{
  unsigned long hartid;

  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct sm_hart_sched* sched = &group_hart_schedulers[hartid];
    size_t src;
    size_t dst = 0;
    int removed = 0;

    if (!sched->valid)
      continue;

    for (src = 0; src < sched->runqueue_len; src++) {
      if (sched->runqueue[src].eid == eid) {
        removed = 1;
        continue;
      }
      sched->runqueue[dst] = sched->runqueue[src];
      dst++;
    }

    if (!removed)
      continue;

    for (src = dst; src < sched->runqueue_capacity; src++) {
      sched->runqueue[src].eid = ENCL_MAX;
      sched->runqueue[src].eid_generation = 0;
    }

    sched->runqueue_len = dst;
    if (sched->current_index >= sched->runqueue_len)
      sched->current_index = 0;
    if (sched->active_eid == eid)
      group_scheduler_clear_active_locked(hartid, eid);
    if (sched->host_service_pending &&
        sched->host_service_eid == eid)
      group_scheduler_clear_host_service_locked(sched);
    if (sched->runqueue_len == 0) {
      sched->active_group_id = 0;
      sched->active_group_generation = 0;
      sched->timer_tick_count = 0;
      sched->cfs_min_vruntime = 0;
      sched->cfs_slice_start = 0;
      sched->cfs_slice_deadline = 0;
      sched->cfs_current_slice_ticks = 0;
      sched->cfs_runnable_weight = 0;
      sched->cfs_nr_running = 0;
      sched->cfs_timer_enabled = 0;
      sched->cfs_resched_pending = 0;
      sched->host_service_deadline = 0;
      group_scheduler_clear_host_service_locked(sched);
    }
    group_scheduler_progress_locked(sched);
    (void)group_scheduler_validate_locked(sched, "remove_eid");
    sbi_printf("[SM][sched] dequeue: hart=%lu eid=%u len=%lu epoch=%lu\n",
               hartid,
               eid,
               (unsigned long)sched->runqueue_len,
               (unsigned long)sched->sched_epoch);
  }
}

static int group_scheduler_member_has_work_locked(
    const struct group_member_descriptor* member, enclave_id eid)
{
  if (!member || member->role != GROUP_ROLE_WORKER ||
      !member->yxstm_slot.valid)
    return 1;

  /* A fresh worker must run once so it can initialize and block on its slot. */
  if (eid < ENCL_MAX && ENCLAVE_EXISTS(eid) && enclaves[eid].state == FRESH)
    return 1;

  /*
   * Slot state alone cannot suppress a runnable worker. After COMPUTE_DONE,
   * the worker still has a short continuation that accounts the batch and
   * either exits or enters WAIT_READY. The master may advance DONE through
   * AGGREGATING to FREE before that continuation is scheduled. Explicit
   * lane_wait_pending is the authoritative indication that this worker has
   * no work to execute.
   */
  return 1;
}

static int group_scheduler_eid_runnable_locked(enclave_id eid)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;

  if (!ENCLAVE_EXISTS(eid))
    return 0;
  if (enclaves[eid].group_id == 0)
    return 0;
  if (enclaves[eid].sched_state != GROUP_SCHED_RUNNABLE ||
      group_ocalls[eid].valid)
    return 0;
  group = find_group_locked(enclaves[eid].group_id);
  member = group ? group_member_find_locked(group, eid) : 0;
  return member && !member->lane_wait_pending &&
         group_scheduler_member_has_work_locked(member, eid);
}

static int group_scheduler_eid_direct_switchable_locked(enclave_id eid,
                                                         uint64_t group_id)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;

  if (!thread_extended_context_supported() || !ENCLAVE_EXISTS(eid))
    return 0;
  if (enclaves[eid].group_id != group_id)
    return 0;
  group = find_group_locked(group_id);
  member = group ? group_member_find_locked(group, eid) : 0;
  if (!group || group->lifecycle_state != KEYSTONE_GROUP_STATE_ACTIVE ||
      !member || member->lane_wait_pending)
    return 0;
  if (enclaves[eid].sched_state != GROUP_SCHED_RUNNABLE)
    return 0;
  if (enclaves[eid].state == FRESH)
    return 1;

  if (enclaves[eid].state != STOPPED && enclaves[eid].state != RUNNING)
    return 0;

  return enclaves[eid].threads[0].prev_mepc != 0;
}

static uint64_t group_scheduler_timer_delta_for_us_local(uint64_t interval_us)
{
  const struct sbi_timer_device* timer = sbi_timer_get_device();
  uint64_t frequency = timer ? timer->timer_freq : 0;
  uint64_t delta;

  if (!interval_us)
    return 1;
  if (!frequency) {
    if (!KEYSTONE_GROUP_SCHED_QUANTUM_US)
      return KEYSTONE_GROUP_SCHED_TIMER_DELTA;
    delta = KEYSTONE_GROUP_SCHED_TIMER_DELTA /
            KEYSTONE_GROUP_SCHED_QUANTUM_US;
    delta *= interval_us;
    return delta ? delta : 1;
  }

  delta =
      (frequency / 1000000UL) * interval_us;
  delta +=
      ((frequency % 1000000UL) * interval_us) /
      1000000UL;
  return delta ? delta : 1;
}

/* Linux CFS prio_to_weight values for nice +16 through nice -15. */
static const uint64_t group_scheduler_cfs_weights[32] = {
  29, 36, 45, 56, 70, 87, 110, 137,
  172, 215, 272, 335, 423, 526, 655, 820,
  1024, 1277, 1586, 1991, 2501, 3121, 3906, 4904,
  6100, 7620, 9548, 11916, 14949, 18705, 23254, 29154
};

static uint64_t group_scheduler_cfs_weight(uint64_t priority)
{
  if (priority > KEYSTONE_GROUP_SCHED_PRIORITY_MAX)
    priority = KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT;
  return group_scheduler_cfs_weights[priority];
}

static uint64_t group_scheduler_cfs_scale_delta(uint64_t delta,
                                                uint64_t weight)
{
  uint64_t quotient;
  uint64_t result;

  if (!weight)
    weight = KEYSTONE_GROUP_SCHED_CFS_NICE_0_LOAD;
  quotient = delta / weight;
  if (quotient > ~(uint64_t)0 / KEYSTONE_GROUP_SCHED_CFS_NICE_0_LOAD)
    return ~(uint64_t)0;
  result = quotient * KEYSTONE_GROUP_SCHED_CFS_NICE_0_LOAD;
  result += ((delta % weight) * KEYSTONE_GROUP_SCHED_CFS_NICE_0_LOAD) /
            weight;
  return result;
}

static uint64_t group_scheduler_cfs_saturating_add(uint64_t value,
                                                   uint64_t delta)
{
  return delta > ~(uint64_t)0 - value ? ~(uint64_t)0 : value + delta;
}

static uint64_t group_scheduler_cfs_dynamic_min_locked(
    const struct sm_hart_sched* sched)
{
  uint64_t minimum = group_scheduler_timer_delta_for_us_local(
      KEYSTONE_GROUP_SCHED_CFS_MIN_GRAN_US);
  const struct group_perf_hart_local* perf;
  uint64_t average;
  uint64_t dynamic;

  if (!sched || sched->hart_id >= MAX_HARTS)
    return minimum;
  perf = &group_perf_harts[sched->hart_id];
  average = sched->cfs_avg_switch_ticks;
  if (!average) {
    if (!perf->context_switch_count || !perf->context_switch_ticks)
      return minimum;
    average = perf->context_switch_ticks / perf->context_switch_count;
    if (perf->context_switch_ticks % perf->context_switch_count)
      average++;
  }
  dynamic = average > ~(uint64_t)0 /
                        KEYSTONE_GROUP_SCHED_SWITCH_COST_MULTIPLIER ?
      ~(uint64_t)0 :
      average * KEYSTONE_GROUP_SCHED_SWITCH_COST_MULTIPLIER;
  return dynamic > minimum ? dynamic : minimum;
}

static uint64_t group_scheduler_cfs_member_min_locked(
    const struct sm_hart_sched* sched,
    const struct group_member_descriptor* member)
{
  uint64_t minimum = group_scheduler_cfs_dynamic_min_locked(sched);
  uint64_t multiplier = member && member->sched_quantum_ticks ?
      member->sched_quantum_ticks : KEYSTONE_GROUP_SCHED_QUANTUM_DEFAULT;
  uint64_t load_bonus = 0;

  /* Blocked entities are excluded from cfs_nr_running. Increase the minimum
   * slice only when a lane is genuinely oversubscribed, amortizing PMP,
   * address-space and cache costs without delaying I/O wakeups. */
  if (sched && sched->cfs_nr_running > 1) {
    load_bonus = (sched->cfs_nr_running + 1) / 2;
    if (load_bonus > 8)
      load_bonus = 8;
    multiplier = multiplier > KEYSTONE_GROUP_SCHED_QUANTUM_MAX - load_bonus ?
        KEYSTONE_GROUP_SCHED_QUANTUM_MAX : multiplier + load_bonus;
  }

  return minimum > ~(uint64_t)0 / multiplier ?
      ~(uint64_t)0 : minimum * multiplier;
}

static int group_scheduler_cfs_entity_on_rq_locked(
    const struct sm_hart_sched* sched, enclave_id eid)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;

  if (!sched || eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
      !enclaves[eid].hart_bound ||
      enclaves[eid].assigned_hart != sched->hart_id)
    return 0;
  if (enclaves[eid].sched_state == GROUP_SCHED_RUNNABLE)
    return group_scheduler_eid_runnable_locked(eid);
  if (enclaves[eid].sched_state != GROUP_SCHED_RUNNING ||
      group_ocalls[eid].valid)
    return 0;
  group = find_group_locked(enclaves[eid].group_id);
  member = group ? group_member_find_locked(group, eid) : 0;
  return member && !member->lane_wait_pending &&
         group_scheduler_member_has_work_locked(member, eid);
}

static void group_scheduler_cfs_recompute_locked(
    struct enabled_group_slot* group, struct sm_hart_sched* sched)
{
  uint64_t total_weight = 0;
  uint64_t minimum = ~(uint64_t)0;
  size_t nr_running = 0;
  size_t index;

  if (!group || !sched)
    return;
  for (index = 0; index < sched->runqueue_len; index++) {
    enclave_id eid = sched->runqueue[index].eid;
    struct group_member_descriptor* member;

    if (eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
        sched->runqueue[index].eid_generation != enclaves[eid].generation ||
        !group_scheduler_cfs_entity_on_rq_locked(sched, eid))
      continue;
    member = group_member_find_locked(group, eid);
    if (!member)
      continue;
    nr_running++;
    if (~(uint64_t)0 - total_weight < member->sched_weight)
      total_weight = ~(uint64_t)0;
    else
      total_weight += member->sched_weight;
    if (member->sched_vruntime < minimum)
      minimum = member->sched_vruntime;
  }
  sched->cfs_nr_running = nr_running;
  sched->cfs_runnable_weight = total_weight;
  if (minimum != ~(uint64_t)0 && minimum > sched->cfs_min_vruntime)
    sched->cfs_min_vruntime = minimum;
}

static void group_scheduler_cfs_place_entity_locked(
    struct sm_hart_sched* sched,
    struct group_member_descriptor* member,
    int waking)
{
  uint64_t floor;

  if (!sched || !member)
    return;
  floor = sched->cfs_min_vruntime;
  if (waking) {
    uint64_t granularity = group_scheduler_cfs_scale_delta(
        group_scheduler_timer_delta_for_us_local(
            KEYSTONE_GROUP_SCHED_CFS_WAKEUP_GRAN_US),
        member->sched_weight);
    floor = floor > granularity ? floor - granularity : 0;
  }
  if (member->sched_vruntime < floor)
    member->sched_vruntime = floor;
}

static uint64_t group_scheduler_cfs_slice_locked(
    struct sm_hart_sched* sched,
    struct group_member_descriptor* member)
{
  uint64_t latency = group_scheduler_timer_delta_for_us_local(
      KEYSTONE_GROUP_SCHED_CFS_LATENCY_US);
  uint64_t minimum = group_scheduler_cfs_member_min_locked(sched, member);
  uint64_t period;
  uint64_t slice;

  if (!sched || !member || !sched->cfs_nr_running ||
      !sched->cfs_runnable_weight)
    return minimum;
  if (sched->cfs_nr_running > ~(uint64_t)0 / minimum)
    period = ~(uint64_t)0;
  else
    period = sched->cfs_nr_running * minimum;
  if (period < latency)
    period = latency;
  slice = (period / sched->cfs_runnable_weight) * member->sched_weight;
  slice += ((period % sched->cfs_runnable_weight) * member->sched_weight) /
           sched->cfs_runnable_weight;
  return slice < minimum ? minimum : slice;
}

static void group_scheduler_cfs_prepare_active_locked(
    struct enabled_group_slot* group,
    struct sm_hart_sched* sched,
    struct group_member_descriptor* member,
    uint64_t now)
{
  uint64_t minimum;
  uint64_t slice;
  struct group_perf_hart_local* perf;

  if (!group || !sched || !member)
    return;
  /* A refresh of the active slice is not a context switch. Account its old
   * interval before replacing exec_start, otherwise on-CPU time is lost. */
  if (member->sched_exec_start_time && sched->active_eid == member->eid)
    group_scheduler_cfs_account_current_locked(group, sched, member->eid, now);
  group_scheduler_cfs_recompute_locked(group, sched);
  minimum = group_scheduler_cfs_member_min_locked(sched, member);
  slice = group_scheduler_cfs_slice_locked(sched, member);
  member->sched_exec_start_time = now;
  group_member_publish_exec_clock_locked(member, now, 1);
  member->sched_slice_ticks = slice;
  sched->cfs_slice_start = now;
  sched->cfs_current_slice_ticks = slice;
  sched->cfs_slice_deadline = now + slice;
  if (sched->cfs_slice_deadline < now)
    sched->cfs_slice_deadline = ~(uint64_t)0;
  sched->cfs_timer_enabled = sched->cfs_nr_running > 1;
  if (sched->hart_id < MAX_HARTS) {
    perf = &group_perf_harts[sched->hart_id];
    perf->cfs_slice_ticks = group_scheduler_cfs_saturating_add(
        perf->cfs_slice_ticks, slice);
    if (minimum > perf->cfs_dynamic_min_slice_ticks)
      perf->cfs_dynamic_min_slice_ticks = minimum;
    if (slice == minimum)
      perf->cfs_min_granularity_count++;
  }
}

static void group_scheduler_cfs_account_current_locked(
    struct enabled_group_slot* group,
    struct sm_hart_sched* sched,
    enclave_id eid,
    uint64_t now)
{
  struct group_member_descriptor* member;
  uint64_t delta;
  uint64_t vruntime_delta;

  if (!group || !sched || eid >= ENCL_MAX ||
      sched->active_eid != eid || !ENCLAVE_EXISTS(eid))
    return;
  member = group_member_find_locked(group, eid);
  if (!member || !member->sched_exec_start_time ||
      now < member->sched_exec_start_time)
    return;
  delta = now - member->sched_exec_start_time;
  vruntime_delta = group_scheduler_cfs_scale_delta(delta,
                                                    member->sched_weight);
  member->sched_sum_exec_time = group_scheduler_cfs_saturating_add(
      member->sched_sum_exec_time, delta);
  member->sched_vruntime = group_scheduler_cfs_saturating_add(
      member->sched_vruntime, vruntime_delta);
  member->sched_exec_start_time = now;
  if (sched->hart_id < MAX_HARTS) {
    struct group_perf_hart_local* perf = &group_perf_harts[sched->hart_id];
    perf->cfs_runtime_ticks = group_scheduler_cfs_saturating_add(
        perf->cfs_runtime_ticks, delta);
    perf->cfs_vruntime_delta = group_scheduler_cfs_saturating_add(
        perf->cfs_vruntime_delta, vruntime_delta);
  }
  group_scheduler_cfs_recompute_locked(group, sched);
}

/*
 * sched_sum_exec_time is maintained in shared mtime ticks at every scheduler
 * boundary. Include the currently running interval without mutating CFS state
 * so performance snapshots never charge time spent descheduled on the hart.
 */
static uint64_t group_member_exec_runtime_now_locked(
    const struct group_member_descriptor* member, uint64_t now)
{
  const struct sm_hart_sched* sched;
  uint64_t runtime;

  if (!member || !member->valid)
    return 0;
  runtime = member->sched_sum_exec_time;
  if (member->bound_hart >= MAX_HARTS ||
      member->eid >= ENCL_MAX || !ENCLAVE_EXISTS(member->eid))
    return runtime;
  sched = &group_hart_schedulers[member->bound_hart];
  if (sched->valid && sched->active_eid == member->eid &&
      sched->active_eid_generation == member->eid_generation &&
      enclaves[member->eid].sched_state == GROUP_SCHED_RUNNING &&
      member->sched_exec_start_time && now >= member->sched_exec_start_time)
    runtime = group_scheduler_cfs_saturating_add(
        runtime, now - member->sched_exec_start_time);
  return runtime;
}

static void group_member_publish_exec_clock_locked(
    struct group_member_descriptor* member, uint64_t now, int running)
{
  volatile struct keystone_member_exec_clock* clock;
  uintptr_t sequence;
  if (!member || !member->valid || !member->protocol_mailbox_registered ||
      !(member->protocol_mailbox_flags & KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK))
    return;
  clock = (struct keystone_member_exec_clock*)(member->protocol_mailbox_paddr +
                                               KEYSTONE_EXEC_CLOCK_OFFSET);
  sequence = clock->sequence;
  if (sequence & 1)
    sequence++;
  if (sequence > ~(uintptr_t)0 - 2)
    sequence = 0;
  clock->sequence = sequence + 1;
  __atomic_thread_fence(__ATOMIC_RELEASE);
  clock->version = KEYSTONE_EXEC_CLOCK_VERSION;
  clock->generation = member->eid_generation;
  clock->runtime_ticks = group_member_exec_runtime_now_locked(member, now);
  clock->resume_ticks = now;
  clock->running = running != 0;
  __atomic_thread_fence(__ATOMIC_RELEASE);
  clock->sequence = sequence + 2;
}

/*
 * Measure worker AES with scheduler-owned on-CPU time. Unlike wall-clock
 * timing, sched_sum_exec_time excludes intervals in which this member is
 * preempted, blocked, or waiting for its lane slot.
 */
static unsigned long group_member_perf_aes_transition_locked(
    struct group_member_descriptor* member, uint64_t work_epoch, int begin)
{
  uint64_t runtime;

  if (!member || !member->valid || member->role != GROUP_ROLE_WORKER ||
      !work_epoch)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  runtime = group_member_exec_runtime_now_locked(member, sbi_timer_value());
  if (begin) {
    if (member->perf_aes_exec_active)
      return SBI_ERR_SM_YXSTM_ALREADY_ACQUIRED;
    member->perf_aes_exec_start = runtime;
    member->perf_aes_phase_epoch = work_epoch;
    member->perf_aes_exec_active = 1;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }

  if (!member->perf_aes_exec_active ||
      member->perf_aes_phase_epoch != work_epoch ||
      runtime < member->perf_aes_exec_start)
    return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;

  member->perf_aes_exec_runtime = group_scheduler_cfs_saturating_add(
      member->perf_aes_exec_runtime,
      runtime - member->perf_aes_exec_start);
  member->perf_aes_exec_start = 0;
  member->perf_aes_phase_epoch = 0;
  member->perf_aes_exec_active = 0;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static void group_perf_window_reset_members_locked(
    struct enabled_group_slot* group, uint64_t now)
{
  size_t i;

  if (!group || !group->members)
    return;
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];

    if (!member->valid)
      continue;
    member->perf_window_exec_baseline =
        group_member_exec_runtime_now_locked(member, now);
    member->perf_window_exec_runtime = 0;
    member->perf_aes_exec_start = 0;
    member->perf_aes_exec_runtime = 0;
    member->perf_aes_phase_epoch = 0;
    member->perf_aes_exec_active = 0;
  }
}

static int group_perf_window_freeze_members_locked(
    struct enabled_group_slot* group, uint64_t now)
{
  size_t i;

  if (!group || !group->members)
    return 0;
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];
    uint64_t current;

    if (!member->valid)
      continue;
    if (member->perf_aes_exec_active)
      return 0;
    current = group_member_exec_runtime_now_locked(member, now);
    member->perf_window_exec_runtime =
        current >= member->perf_window_exec_baseline ?
            current - member->perf_window_exec_baseline : 0;
  }
  return 1;
}

static uint64_t group_scheduler_timer_delta_local(void)
{
  return group_scheduler_timer_delta_for_us_local(
      KEYSTONE_GROUP_SCHED_CFS_MIN_GRAN_US);
}

static uint64_t group_scheduler_host_service_delta_local(void)
{
  return group_scheduler_timer_delta_for_us_local(
      KEYSTONE_GROUP_HOST_SERVICE_INTERVAL_US);
}

static void group_scheduler_rearm_timer_local(const char* where)
{
  unsigned long hartid = csr_read(mhartid);
  uint64_t now = sbi_timer_value();
  uint64_t cfs_delta = group_scheduler_timer_delta_local();
  uint64_t host_delta = group_scheduler_host_service_delta_local();
  uint64_t delta = cfs_delta;
  uint64_t next = now + delta;
  int cfs_enabled = 0;
  int heartbeat_enabled = 0;
  int host_service_enabled = 0;

#if KEYSTONE_GROUP_TIMER_PREEMPT
  if (hartid < MAX_HARTS) {
    struct sm_hart_sched* sched = &group_hart_schedulers[hartid];

    cfs_enabled = sched->valid && sched->active_eid != ENCL_MAX &&
                  sched->cfs_timer_enabled;
    if (cfs_enabled) {
      if (sched->cfs_slice_deadline <= now) {
        /*
         * A denied host handoff or a rolled-back peer switch can reach this
         * path after the old comparator has expired.  Re-arming at now + 1
         * keeps MTIP effectively level-pending and starves the interrupted
         * enclave in an M-mode trap loop.  Start a complete replacement slice
         * so the enclave can reach its next protocol/scheduler boundary.
         */
        cfs_delta = sched->cfs_current_slice_ticks;
        if (cfs_delta < group_scheduler_timer_delta_local())
          cfs_delta = group_scheduler_timer_delta_local();
        sched->cfs_slice_start = now;
        sched->cfs_current_slice_ticks = cfs_delta;
        sched->cfs_slice_deadline = now + cfs_delta;
        if (sched->cfs_slice_deadline < now)
          sched->cfs_slice_deadline = ~(uint64_t)0;
      } else {
        cfs_delta = sched->cfs_slice_deadline - now;
      }
    }
    heartbeat_enabled = sched->heartbeat_enabled;
    host_service_enabled = heartbeat_enabled || sched->host_service_forced;
    if (host_service_enabled) {
      uint64_t deadline = sched->host_service_deadline;

      if (!deadline || deadline <= now) {
        /*
         * A forced phase-edge handoff can be rejected while the previous host
         * frame is still pending.  Retrying an expired deadline at now + 1
         * turns the level-sensitive MTIP into a tight M-mode loop.  Forced
         * service remains prompt but is rate-limited by one scheduler interval;
         * periodic heartbeat starts a fresh full interval.
         */
        host_delta = sched->host_service_forced ?
            group_scheduler_timer_delta_local() : host_delta;
        deadline = now + host_delta;
        if (deadline < now)
          deadline = ~(uint64_t)0;
        sched->host_service_deadline = deadline;
      }
      host_delta = deadline - now;
    }
  }
  if (!cfs_enabled && !host_service_enabled) {
    csr_clear(mie, MIP_MTIP);
    return;
  }
  delta = cfs_enabled ? cfs_delta : host_delta;
  if (host_service_enabled && cfs_enabled && host_delta < delta)
    delta = host_delta;
  next = now + delta;
  if (next < now)
    next = ~(uint64_t)0;
#if KEYSTONE_GROUP_STARTUP_TRACE
  if (hartid < MAX_HARTS && !group_timer_config_log_seen[hartid]) {
    const struct sbi_timer_device* timer = sbi_timer_get_device();
    group_timer_config_log_seen[hartid] = 1;
    sbi_printf("[SM][sched] timer config: hart=%lu device=%s frequency=%luHz policy=cfs-lite latency=%luus min_gran=%luus switch_cost_x=%lu slice_delta=%lu host_service_us=%lu host_delta=%lu adaptive=%s where=%s\n",
               hartid,
               timer ? timer->name : "fallback",
               timer ? timer->timer_freq : 0,
               (unsigned long)KEYSTONE_GROUP_SCHED_CFS_LATENCY_US,
               (unsigned long)KEYSTONE_GROUP_SCHED_CFS_MIN_GRAN_US,
               (unsigned long)KEYSTONE_GROUP_SCHED_SWITCH_COST_MULTIPLIER,
               (unsigned long)cfs_delta,
               (unsigned long)KEYSTONE_GROUP_HOST_SERVICE_INTERVAL_US,
               (unsigned long)group_scheduler_host_service_delta_local(),
               cfs_enabled ? "cfs-slice" : "heartbeat",
               where);
  }
#else
  (void)hartid;
  (void)where;
#endif
  sbi_timer_event_start(next);
#else
  (void)hartid;
  (void)now;
  (void)cfs_delta;
  (void)host_delta;
  (void)delta;
  (void)next;
  (void)cfs_enabled;
  (void)heartbeat_enabled;
  (void)host_service_enabled;
  (void)where;
#endif
}

void group_scheduler_runtime_timer_init(enclave_id eid)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  int ready = 0;

  spin_lock(&encl_lock);
  group = ENCLAVE_EXISTS(eid) ? find_group_locked(enclaves[eid].group_id) : 0;
  member = group ? group_member_find_locked(group, eid) : 0;
  if (hartid < MAX_HARTS && group && member &&
      (member->role == GROUP_ROLE_WORKER ||
       group->execution_mode == GROUP_MODE_SATURATION_TEST) &&
      enclaves[eid].hart_bound && enclaves[eid].assigned_hart == hartid &&
      thread_extended_context_supported() &&
      group_scheduler_active_matches_locked(&group_hart_schedulers[hartid],
                                            eid)) {
    group_member_timer_ready[eid] = 1;
    ready = 1;
  }
  spin_unlock(&encl_lock);

  if (ready) {
    /*
     * MTIP is the only production host-service trigger. Supervisor interrupt
     * delivery remains disabled while the enclave runs; pending Linux work is
     * exposed when the scheduler-owned timer restores the group_run_hart host
     * frame.
     */
#if KEYSTONE_GROUP_TIMER_PREEMPT
    if (hartid < MAX_HARTS && group_hart_run_status_ptr[hartid] &&
        group_hart_host_context_valid[hartid]) {
      group_scheduler_rearm_timer_local("runtime_timer_init");
    } else {
      csr_clear(mie, MIP_MTIP);
    }
#else
    csr_clear(mie, MIP_MTIP);
#endif
    csr_clear(mie, MIP_SSIP | MIP_STIP | MIP_SEIP);
  }
}

static void group_scheduler_defer_timer_local(const char* where)
{
  uint64_t delta = group_scheduler_timer_delta_local();
  uint64_t now = sbi_timer_value();
  uint64_t boot_delta;
  uint64_t next;

  (void)where;
#if KEYSTONE_GROUP_TIMER_PREEMPT
  if (delta > ~(uint64_t)0 / 1024UL)
    boot_delta = ~(uint64_t)0;
  else
    boot_delta = delta * 1024UL;
  next = now + boot_delta;
  if (next < now)
    next = ~(uint64_t)0;
  sbi_timer_event_start(next);
#else
  (void)delta;
  (void)now;
  (void)boot_delta;
  (void)next;
#endif
}

static enclave_id group_scheduler_pick_next_locked(unsigned long hartid,
                                                   enclave_id current_eid)
{
  struct sm_hart_sched* sched;
  size_t offset;
  enclave_id best = ENCL_MAX;
  uint64_t best_vruntime = ~(uint64_t)0;
  int best_is_fresh = 0;
  int best_class = 4;
  int best_cache_hot = 0;

  if (hartid >= MAX_HARTS)
    return ENCL_MAX;

  sched = &group_hart_schedulers[hartid];
  if (!sched->valid || sched->runqueue_len == 0)
    return ENCL_MAX;

  for (offset = 1; offset <= sched->runqueue_len; offset++) {
    size_t index = (sched->current_index + offset) % sched->runqueue_len;
    enclave_id candidate = sched->runqueue[index].eid;

    if (candidate == current_eid)
      continue;
    if (candidate >= ENCL_MAX || !ENCLAVE_EXISTS(candidate) ||
        sched->runqueue[index].eid_generation !=
            enclaves[candidate].generation)
      continue;
    if (group_scheduler_eid_runnable_locked(candidate)) {
      struct enabled_group_slot* group =
          find_group_locked(enclaves[candidate].group_id);
      struct group_member_descriptor* member =
          group ? group_member_find_locked(group, candidate) : 0;
      int candidate_is_fresh = enclaves[candidate].state == FRESH;
      int data_ready = member && member->yxstm_slot.valid &&
          (member->yxstm_slot.state == YXSTM_SLOT_READY ||
           member->yxstm_slot.state == YXSTM_SLOT_COMPUTING);
      int aged = member && sched->sched_epoch > member->sched_last_run_epoch &&
          sched->sched_epoch - member->sched_last_run_epoch >= 64;
      int candidate_class = data_ready ? (aged ? 0 : 1) : (aged ? 2 : 3);
      int cache_hot = member && member->yxstm_suspended_acquired;

      if (member &&
          (best == ENCL_MAX ||
           candidate_class < best_class ||
           (candidate_class == best_class &&
            (member->sched_vruntime < best_vruntime ||
             (member->sched_vruntime == best_vruntime &&
              (cache_hot > best_cache_hot ||
               (cache_hot == best_cache_hot &&
                candidate_is_fresh && !best_is_fresh))))))) {
        best = candidate;
        best_vruntime = member->sched_vruntime;
        best_is_fresh = candidate_is_fresh;
        best_class = candidate_class;
        best_cache_hot = cache_hot;
      }
    }
  }

  return best;
}

static int group_scheduler_account_tick_locked(
    struct enabled_group_slot* group,
    struct sm_hart_sched* sched,
    enclave_id current_eid)
{
  struct group_member_descriptor* current;
  uint64_t now;
  uint64_t wakeup_granularity;
  uint64_t minimum_peer_vruntime = ~(uint64_t)0;
  size_t i;

  if (!group || !sched)
    return 1;
  current = group_member_find_locked(group, current_eid);
  if (!current)
    return 1;
  now = sbi_timer_value();
  group_scheduler_cfs_account_current_locked(group, sched, current_eid, now);
  sched->cfs_resched_pending = 0;
  current->sched_last_run_epoch = sched->sched_epoch;
  if (sched->cfs_nr_running <= 1) {
    sched->cfs_timer_enabled = 0;
    sched->cfs_slice_deadline = 0;
    sched->cfs_current_slice_ticks = 0;
    return 0;
  }
  sched->cfs_timer_enabled = 1;
  if (!sched->cfs_slice_deadline)
    group_scheduler_cfs_prepare_active_locked(group, sched, current, now);

  wakeup_granularity = group_scheduler_cfs_scale_delta(
      group_scheduler_timer_delta_for_us_local(
          KEYSTONE_GROUP_SCHED_CFS_WAKEUP_GRAN_US),
      current->sched_weight);

  for (i = 0; i < sched->runqueue_len; i++) {
    enclave_id eid = sched->runqueue[i].eid;
    struct group_member_descriptor* member;

    if (eid == current_eid || eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
        sched->runqueue[i].eid_generation != enclaves[eid].generation ||
        !group_scheduler_eid_runnable_locked(eid))
      continue;
    member = group_member_find_locked(group, eid);
    if (!member)
      continue;
    if (member->sched_vruntime < minimum_peer_vruntime)
      minimum_peer_vruntime = member->sched_vruntime;
  }

  if (minimum_peer_vruntime == ~(uint64_t)0)
    return 0;
  if (sched->cfs_slice_deadline && now >= sched->cfs_slice_deadline) {
    if (minimum_peer_vruntime <= current->sched_vruntime)
      return 1;
    group_scheduler_cfs_prepare_active_locked(group, sched, current, now);
    return 0;
  }
  if (minimum_peer_vruntime < current->sched_vruntime &&
      current->sched_vruntime - minimum_peer_vruntime > wakeup_granularity)
    return 1;
  return 0;
}

static void group_scheduler_refresh_slice_locked(
    struct enabled_group_slot* group, enclave_id eid)
{
  struct group_member_descriptor* member;
  struct sm_hart_sched* sched;

  if (!group || eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
      !enclaves[eid].hart_bound || enclaves[eid].assigned_hart >= MAX_HARTS)
    return;
  member = group_member_find_locked(group, eid);
  sched = &group_hart_schedulers[enclaves[eid].assigned_hart];
  if (!member || !group_scheduler_active_matches_locked(sched, eid))
    return;
  group_scheduler_cfs_prepare_active_locked(
      group, sched, member, sbi_timer_value());
}

static void group_scheduler_refresh_current_slice_local(enclave_id eid)
{
  struct enabled_group_slot* group;

  spin_lock(&encl_lock);
  group = eid < ENCL_MAX && ENCLAVE_EXISTS(eid) ?
      find_group_locked(enclaves[eid].group_id) : 0;
  group_scheduler_refresh_slice_locked(group, eid);
  spin_unlock(&encl_lock);
}

static void group_scheduler_log_timer_retry_local(
    enclave_id current, enclave_id next, unsigned long error,
    const char* where)
{
  unsigned long hartid = csr_read(mhartid);
  uint64_t count;

  if (hartid >= MAX_HARTS)
    return;
  count = ++group_timer_retry_log_count[hartid];
  if (count <= 4 || !(count & (count - 1)))
    sbi_printf("[SM][sched] timer retry: hart=%lu current=%u next=%u error=%lu where=%s count=%lu\n",
               hartid, current, next, error,
               where ? where : "unknown", (unsigned long)count);
}

/*
 * Suspended YXSTM state is an SM-owned continuation, not a second hardware
 * grant.  It may coexist with another member's installed grant on the same
 * lane, but it is restorable only while every authority epoch still matches.
 */
static int group_member_suspended_grant_valid_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    struct group_member_descriptor* member)
{
  struct group_task_bank_protocol* bank = 0;
  struct group_worker_lane* lane;
  struct group_member_descriptor* slot_owner = 0;
  int task_bank_grant;
  int slot_grant;

  if (!group || !member || !member->valid ||
      !member->yxstm_suspended_acquired || hartid >= MAX_HARTS ||
      member->eid >= ENCL_MAX || !ENCLAVE_EXISTS(member->eid) ||
      member->eid_generation != enclaves[member->eid].generation ||
      member->group_id != group->group_id ||
      member->group_generation != group->generation ||
      member->bound_hart != hartid || group->coherence_inflight ||
      !member->yxstm_suspended_slice_mask ||
      (member->yxstm_suspended_slice_mask & ~member->allowed_slice_mask) ||
      !yxstm_flags_valid(member->yxstm_suspended_permissions) ||
      group->hart_slots[hartid].yxstm_acquired)
    return 0;

  slot_grant = member->yxstm_suspended_bank_id ==
      GROUP_YXSTM_SLOT_GRANT_BANK;
  task_bank_grant = !slot_grant &&
      member->yxstm_suspended_bank_id != KEYSTONE_YXSTM_INVALID_BANK;
  if (slot_grant) {
    slot_owner = group_yxstm_slot_member_locked(
        group, member->yxstm_suspended_slot_lane,
        member->yxstm_suspended_slot_id);
    if (!slot_owner || !slot_owner->yxstm_slot.valid ||
        slot_owner != member ||
        member->yxstm_suspended_slot_epoch !=
            slot_owner->yxstm_slot.epoch ||
        slot_owner->yxstm_slot.state != YXSTM_SLOT_COMPUTING ||
        member->yxstm_suspended_phase != YXSTM_SLOT_COMPUTING ||
        member->yxstm_suspended_permissions !=
            (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W))
      return 0;
  } else if (task_bank_grant) {
    if (member->yxstm_suspended_bank_id >= group->yxstm_bank_count)
      return 0;
    bank = &group->task_banks[member->yxstm_suspended_bank_id];
    if (member->yxstm_suspended_phase != bank->phase ||
        member->yxstm_suspended_phase_epoch != bank->phase_epoch ||
        member->yxstm_suspended_task_epoch != bank->task_epoch)
      return 0;
  } else if (member->yxstm_suspended_phase != group->yxstm_phase ||
             member->yxstm_suspended_phase_epoch !=
                 group->yxstm_phase_epoch ||
             member->yxstm_suspended_task_epoch !=
                 group->yxstm_task_epoch ||
             member->task_epoch != group->yxstm_task_epoch) {
    return 0;
  }
  if (member->yxstm_suspended_permission_epoch != group->permission_epoch)
    return 0;
  if (!slot_grant &&
      yxstm_validate_member_access_locked(
          group, member, member->yxstm_suspended_slice_mask,
          member->yxstm_suspended_permissions,
          member->yxstm_suspended_phase) !=
          SBI_ERR_SM_ENCLAVE_SUCCESS)
    return 0;

  if (member->role != GROUP_ROLE_WORKER)
    return member->role == GROUP_ROLE_MASTER;
  lane = group_lane_for_id_locked(group, member->lane_id);
  return lane && lane->hart_id == hartid &&
         lane->task_epoch == member->task_epoch;
}

static int group_worker_lane_preemptible_grant_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    struct group_member_descriptor* member)
{
  struct group_hart_slot* slot;
  struct group_worker_lane* lane;
  struct group_task_bank_protocol* bank = 0;
  int task_bank_grant;
  int slot_grant;

  if (!group || !member || member->role != GROUP_ROLE_WORKER ||
      hartid >= MAX_HARTS || group->coherence_inflight ||
      member->yxstm_suspended_acquired ||
      member->eid >= ENCL_MAX || !ENCLAVE_EXISTS(member->eid))
    return 0;
  slot = &group->hart_slots[hartid];
  lane = group_lane_for_id_locked(group, member->lane_id);
  if (!slot->valid || !slot->yxstm_acquired ||
      slot->yxstm_owner_eid != member->eid ||
      !slot->yxstm_acquired_slice_mask ||
      (slot->yxstm_acquired_slice_mask & ~member->allowed_slice_mask) ||
      slot->pmp_epoch != group->permission_epoch || !lane ||
      lane->hart_id != hartid || lane->active_eid != member->eid ||
      lane->active_eid_generation != member->eid_generation)
    return 0;

  slot_grant = slot->yxstm_bank_id == GROUP_YXSTM_SLOT_GRANT_BANK;
  task_bank_grant = !slot_grant &&
      slot->yxstm_bank_id != KEYSTONE_YXSTM_INVALID_BANK;
  if (slot_grant) {
    if (!member->yxstm_slot.valid ||
        slot->yxstm_slot_lane != member->yxstm_slot.lane_id ||
        slot->yxstm_slot_id != member->yxstm_slot.slot_id ||
        slot->yxstm_slot_epoch != member->yxstm_slot.epoch ||
        slot->yxstm_phase != YXSTM_SLOT_COMPUTING ||
        member->yxstm_slot.state != YXSTM_SLOT_COMPUTING ||
        slot->yxstm_permissions !=
            (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W))
      return 0;
  } else if (task_bank_grant) {
    if (slot->yxstm_bank_id >= group->yxstm_bank_count)
      return 0;
    bank = &group->task_banks[slot->yxstm_bank_id];
    if (slot->yxstm_phase != bank->phase ||
        slot->phase_epoch != bank->phase_epoch)
      return 0;
  } else if (slot->yxstm_phase != group->yxstm_phase ||
             slot->phase_epoch != group->yxstm_phase_epoch ||
             member->task_epoch != group->yxstm_task_epoch ||
             lane->task_epoch != group->yxstm_task_epoch) {
    return 0;
  }

  if (slot_grant)
    return 1;
  return yxstm_validate_member_access_locked(
             group, member, slot->yxstm_acquired_slice_mask,
             slot->yxstm_permissions, slot->yxstm_phase) ==
         SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/*
 * A lane is shared by its worker members. During an active group phase an
 * explicit yield, a BLOCKED OCALL, or timer preemption is a safe scheduling
 * boundary after SM has converted any hardware grant into a validated
 * suspended continuation. Inactive members retain metadata, never hardware
 * access.
 * Once the aggregate lane barrier is committed, an EXITED last owner is also
 * safe because every live lane member has acknowledged the same result. The
 * task epoch and slice stay unchanged, so this is scheduler handoff, not lane
 * reassignment and must not scrub the in-flight channel contents.
 */
static int group_worker_lane_shared_handoff_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    struct group_member_descriptor* member, int active_owner)
{
  struct group_worker_lane* lane;
  struct group_hart_slot* slot;
  struct group_task_bank_protocol* suspended_bank = 0;
  uint64_t bank_id;
  enum group_sched_state state;
  int aggregate_committed;
  int suspended_bank_active = 0;
  int suspended_slot_active = 0;

  if (!group || !member || member->role != GROUP_ROLE_WORKER ||
      member->eid >= ENCL_MAX || !ENCLAVE_EXISTS(member->eid) ||
      hartid >= MAX_HARTS || group->coherence_inflight)
    return 0;
  if (member->yxstm_suspended_acquired &&
      member->yxstm_suspended_bank_id != KEYSTONE_YXSTM_INVALID_BANK &&
      member->yxstm_suspended_bank_id < group->yxstm_bank_count) {
    suspended_bank =
        &group->task_banks[member->yxstm_suspended_bank_id];
    suspended_bank_active = suspended_bank->phase != YXSTM_PHASE_IDLE;
  }
  suspended_slot_active = member->yxstm_suspended_acquired &&
      member->yxstm_suspended_bank_id == GROUP_YXSTM_SLOT_GRANT_BANK &&
      member->yxstm_slot.valid &&
      member->yxstm_slot.state == YXSTM_SLOT_COMPUTING &&
      member->yxstm_suspended_slot_epoch == member->yxstm_slot.epoch;
  if (group->yxstm_phase == YXSTM_PHASE_IDLE && !suspended_bank_active &&
      !suspended_slot_active)
    return 0;
  if (!suspended_bank_active && !suspended_slot_active &&
      member->task_epoch != group->yxstm_task_epoch)
    return 0;
  state = enclaves[member->eid].sched_state;
  aggregate_committed = suspended_bank_active ?
      (suspended_bank->phase == YXSTM_PHASE_AGGREGATE &&
       (suspended_bank->ready_bitmap & member->allowed_slice_mask) ==
           member->allowed_slice_mask) :
      (group->yxstm_phase == YXSTM_PHASE_AGGREGATE &&
       (group->yxstm_ready_bitmap & member->allowed_slice_mask) ==
           member->allowed_slice_mask);
  if (active_owner) {
    if (state != GROUP_SCHED_RUNNING &&
        state != GROUP_SCHED_RUNNABLE &&
        state != GROUP_SCHED_BLOCKED)
      return 0;
  } else if (state != GROUP_SCHED_RUNNABLE &&
             state != GROUP_SCHED_BLOCKED &&
             !(state == GROUP_SCHED_EXITED && aggregate_committed)) {
    return 0;
  }
  slot = &group->hart_slots[hartid];
  if (slot->yxstm_acquired)
    return 0;
  if (member->yxstm_suspended_acquired &&
      !group_member_suspended_grant_valid_locked(group, hartid, member))
    return 0;
  lane = group_lane_for_id_locked(group, member->lane_id);
  if (!lane || lane->hart_id != hartid ||
      (!suspended_bank_active && !suspended_slot_active &&
       lane->task_epoch != group->yxstm_task_epoch))
    return 0;
  if (active_owner) {
    if (lane->active_eid != member->eid ||
        lane->active_eid_generation != member->eid_generation)
      return 0;
  } else if (lane->active_eid != ENCL_MAX ||
             lane->last_owner_eid != member->eid ||
             lane->last_owner_generation != member->eid_generation) {
    return 0;
  }
  if (!member->yxstm_suspended_acquired)
    for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++)
      if (group->task_banks[bank_id].phase != YXSTM_PHASE_IDLE ||
          yxstm_task_bank_any_acquired_locked(group, bank_id))
        return 0;
  return 1;
}

/*
 * Streaming task banks can wake a different member than the lane's last
 * owner.  The legacy owner gate only understood the group-wide phase and
 * rejected that handoff whenever a per-bank phase was active.  Permit the
 * handoff only after the old owner has saved a BLOCKED bank-wait context and
 * the new owner is the stopped, runnable rank selected by an active bank.
 * No YXSTM authority may survive the boundary; the resumed member must still
 * pass the normal bank/rank/epoch checks before installing a PMP grant.
 */
static int group_worker_lane_bank_wait_handoff_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    struct group_member_descriptor* previous,
    struct group_member_descriptor* next, int active_owner)
{
  struct group_worker_lane* lane;
  uint64_t lane_slice_mask;
  uint64_t bank_id;
  unsigned long slot_hart;
  size_t member_index;
  enum group_sched_state previous_state;
  int previous_wait_boundary;
  int previous_exit_boundary;

  if (!group || !previous || !next || previous == next ||
      hartid >= MAX_HARTS || group->coherence_inflight ||
      previous->role != GROUP_ROLE_WORKER ||
      next->role != GROUP_ROLE_WORKER ||
      previous->lane_id != next->lane_id ||
      previous->bound_hart != hartid || next->bound_hart != hartid ||
      previous->eid >= ENCL_MAX || next->eid >= ENCL_MAX ||
      !ENCLAVE_EXISTS(previous->eid) || !ENCLAVE_EXISTS(next->eid) ||
      previous->eid_generation != enclaves[previous->eid].generation ||
      next->eid_generation != enclaves[next->eid].generation ||
      previous->yxstm_suspended_acquired ||
      next->yxstm_suspended_acquired ||
      group->hart_slots[hartid].yxstm_acquired ||
      enclaves[next->eid].sched_state != GROUP_SCHED_RUNNABLE ||
      next->lane_wait_pending ||
      (enclaves[next->eid].state != STOPPED &&
       enclaves[next->eid].state != RUNNING) ||
      enclaves[next->eid].threads[0].prev_mepc == 0)
    return 0;

  previous_state = enclaves[previous->eid].sched_state;
  previous_wait_boundary =
      previous_state == GROUP_SCHED_BLOCKED &&
      previous->lane_wait_pending &&
      previous->lane_wait_task_bank != GROUP_LANE_WAIT_KIND_TURN &&
      (active_owner || previous->lane_wait_context_saved);
  previous_exit_boundary =
      previous_state == GROUP_SCHED_EXITED &&
      !previous->lane_wait_pending;
  if (!previous_wait_boundary && !previous_exit_boundary)
    return 0;

  lane = group_lane_for_id_locked(group, previous->lane_id);
  if (!lane || lane->hart_id != hartid)
    return 0;
  if (active_owner) {
    if (lane->active_eid != previous->eid ||
        lane->active_eid_generation != previous->eid_generation)
      return 0;
  } else if (lane->active_eid != ENCL_MAX ||
             lane->last_owner_eid != previous->eid ||
             lane->last_owner_generation != previous->eid_generation) {
    return 0;
  }

  lane_slice_mask = previous->allowed_slice_mask;
  if (!lane_slice_mask || lane_slice_mask != next->allowed_slice_mask)
    return 0;
  for (slot_hart = 0; slot_hart < MAX_HARTS; slot_hart++)
    if (group->hart_slots[slot_hart].valid &&
        group->hart_slots[slot_hart].yxstm_acquired &&
        (group->hart_slots[slot_hart].yxstm_acquired_slice_mask &
         lane_slice_mask))
      return 0;
  for (member_index = 0;
       member_index < group->member_metadata_capacity;
       member_index++) {
    const struct group_member_descriptor* lane_member =
        &group->members[member_index];

    if (lane_member->valid && lane_member->yxstm_suspended_acquired &&
        (lane_member->yxstm_suspended_slice_mask & lane_slice_mask))
      return 0;
  }

  /*
   * Frozen slots are independent scheduling objects. Once the previous
   * member has no hardware or suspended grant, another runnable member on
   * the same lane can restore its private continuation with YXSTM denied.
   * Its own slot command will validate ownership/epoch and install the only
   * dynamic PMP grant it may use.
   *
   * Do not retain the legacy group-wide task-bank-idle gate here. A different
   * lane may legitimately be computing while this lane changes owner, and
   * waiting for every bank to become IDLE can strand a READY slot forever.
   */
  if (group->yxstm_slots_frozen && lane->slots_frozen &&
      previous->yxstm_slot.valid && next->yxstm_slot.valid &&
      previous->yxstm_slot.lane_id == lane->lane_id &&
      next->yxstm_slot.lane_id == lane->lane_id &&
      (previous_state == GROUP_SCHED_RUNNABLE ||
       previous_state == GROUP_SCHED_BLOCKED ||
       previous_state == GROUP_SCHED_EXITED))
    return 1;

  if ((previous_wait_boundary &&
       previous->lane_wait_task_bank == GROUP_LANE_WAIT_KIND_SLOT_READY) ||
      (next->yxstm_slot.valid &&
       (next->yxstm_slot.state == YXSTM_SLOT_READY ||
        next->yxstm_slot.state == YXSTM_SLOT_COMPUTING)))
    return next->yxstm_slot.valid &&
           (next->yxstm_slot.state == YXSTM_SLOT_READY ||
            next->yxstm_slot.state == YXSTM_SLOT_COMPUTING);

  for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++) {
    struct group_task_bank_protocol* bank = &group->task_banks[bank_id];

    if (previous_exit_boundary && bank->phase != YXSTM_PHASE_IDLE &&
        bank->lane_rank == previous->lane_rank &&
        (bank->active_worker_mask & lane_slice_mask) &&
        (bank->phase != YXSTM_PHASE_AGGREGATE ||
         (bank->ready_bitmap & lane_slice_mask) != lane_slice_mask))
      return 0;
  }
  for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++) {
    struct group_task_bank_protocol* bank = &group->task_banks[bank_id];

    if (bank->phase != YXSTM_PHASE_IDLE &&
        bank->lane_rank == next->lane_rank &&
        (bank->active_worker_mask & lane_slice_mask))
      return 1;
  }
  return 0;
}

static int group_scheduler_host_entry_admissible_locked(
    struct enabled_group_slot* group, unsigned long hartid, enclave_id eid)
{
  struct group_member_descriptor* member;
  struct group_member_descriptor* last_owner = 0;
  struct group_worker_lane* lane;
  uint64_t bank_id;
  int shared_handoff = 0;

  if (!group || hartid >= MAX_HARTS || eid >= ENCL_MAX ||
      !ENCLAVE_EXISTS(eid))
    return 0;
  member = group_member_find_locked(group, eid);
  if (!member || member->role != GROUP_ROLE_WORKER)
    return member != 0;

  lane = group_lane_for_id_locked(group, member->lane_id);
  if (!lane || lane->hart_id != hartid || lane->active_eid != ENCL_MAX)
    return 0;
  /*
   * Frozen per-member slots remove the legacy requirement that every worker
   * on a lane must finish its first launch before any slot on that lane can be
   * active.  A late FRESH worker may start with YXSTM denied, initialize its
   * runtime, and then acquire only its own FREE/READY slot through the normal
   * epoch and ownership checks.  Without this bootstrap exception, a fourth
   * lane member can be starved behind already-active task banks forever.
   */
  if (enclaves[eid].state == FRESH && group->yxstm_slots_frozen &&
      lane->slots_frozen && member->yxstm_slot.valid &&
      !group->hart_slots[hartid].yxstm_acquired &&
      !member->yxstm_suspended_acquired &&
      (member->yxstm_slot.state == YXSTM_SLOT_FREE ||
       member->yxstm_slot.state == YXSTM_SLOT_READY))
    return 1;
  /*
   * A suspended grant is already bound to this exact member and has no live
   * hardware PMP authority.  Validate and resume that continuation before
   * applying the legacy last-owner handoff rules.
   */
  if (member->yxstm_suspended_acquired)
    return group_member_suspended_grant_valid_locked(
        group, hartid, member);
  if (lane->last_owner_eid == ENCL_MAX ||
      (lane->last_owner_eid == eid &&
       lane->last_owner_generation == enclaves[eid].generation))
    return 1;

  if (lane->last_owner_eid < ENCL_MAX &&
      ENCLAVE_EXISTS(lane->last_owner_eid) &&
      enclaves[lane->last_owner_eid].generation ==
          lane->last_owner_generation)
    last_owner = group_member_find_locked(group, lane->last_owner_eid);

  if (last_owner && group_worker_lane_bank_wait_handoff_locked(
                        group, hartid, last_owner, member, 0))
    return 1;

  if (group->yxstm_phase != YXSTM_PHASE_IDLE ||
      (last_owner && last_owner->yxstm_suspended_acquired)) {
    if (!last_owner ||
        !group_worker_lane_shared_handoff_locked(
            group, hartid, last_owner, 0))
      return 0;
    shared_handoff = 1;
  } else if (group->hart_slots[hartid].yxstm_acquired ||
             member->yxstm_suspended_acquired ||
             (last_owner && last_owner->yxstm_suspended_acquired)) {
    return 0;
  }

  if (!shared_handoff)
    for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++)
      if (group->task_banks[bank_id].phase != YXSTM_PHASE_IDLE)
        return 0;
  return 1;
}

static int group_scheduler_phase_edge_reentry_admissible_locked(
    struct enabled_group_slot* group, struct sm_hart_sched* sched,
    unsigned long hartid, enclave_id eid)
{
  struct group_member_descriptor* member;
  struct group_worker_lane* lane;

  if (!group || !sched || hartid >= MAX_HARTS || eid >= ENCL_MAX ||
      !ENCLAVE_EXISTS(eid) || !sched->host_service_pending ||
      !sched->host_service_drop_grant || sched->host_service_eid != eid ||
      sched->host_service_eid_generation != enclaves[eid].generation ||
      group->coherence_inflight)
    return 0;
  member = group_member_find_locked(group, eid);
  if (!member || member->role != GROUP_ROLE_WORKER ||
      member->bound_hart != hartid || member->yxstm_suspended_acquired)
    return 0;
  if (group->hart_slots[hartid].yxstm_acquired)
    return 0;
  lane = group_lane_for_id_locked(group, member->lane_id);
  if (!lane || lane->hart_id != hartid || lane->active_eid != ENCL_MAX ||
      lane->last_owner_eid != eid ||
      lane->last_owner_generation != enclaves[eid].generation)
    return 0;

  /*
   * This is an exact resume of the worker interrupted solely to publish a
   * phase-edge event.  YXSTM remains PMP-denied, and every later bank acquire
   * still validates lane rank, phase and task epoch.  Active task banks are
   * therefore expected here and must not force the leased hart to sleep.
   */
  return 1;
}

static int group_scheduler_release_unbound_host_service_locked(
    struct enabled_group_slot* group, struct sm_hart_sched* sched,
    unsigned long hartid)
{
  struct group_member_descriptor* member;
  enclave_id eid;
  uint64_t started;

  if (!group || !sched || !sched->host_service_pending ||
      sched->host_service_drop_grant ||
      sched->host_service_grant_suspended || sched->heartbeat_enabled ||
      hartid >= MAX_HARTS || !group->hart_slots[hartid].valid ||
      group->hart_slots[hartid].yxstm_acquired)
    return 0;

  eid = sched->host_service_eid;
  if (eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
      sched->host_service_eid_generation != enclaves[eid].generation ||
      sched->host_service_group_generation != group->generation ||
      enclaves[eid].group_id != group->group_id)
    return 0;
  member = group_member_find_locked(group, eid);
  if (!member || member->yxstm_suspended_acquired)
    return 0;

  /*
   * This host-service return carries no YXSTM authority and has no phase-edge
   * ACK to serialize. Keeping an exact-eid reservation in that state is only
   * a scheduling constraint: if another member became READY while HOST was
   * running, the reservation can put the whole lane to sleep. Account the
   * completed service and return the saved member to normal CFS competition.
   */
  started = sched->host_service_start_cycle;
  atomic_add_return(&group_perf_host_service_count, 1);
  if (started)
    atomic_add_return(&group_perf_host_service_cycles,
                      (long)(csr_read(CSR_MCYCLE) - started));
  group_scheduler_clear_host_service_locked(sched);
  group_scheduler_progress_locked(sched);
  return 1;
}

static int group_worker_lane_clean_task_boundary_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    struct group_member_descriptor* member)
{
  struct group_worker_lane* lane;
  uint64_t bank_id;

  if (!group || !member || member->role != GROUP_ROLE_WORKER ||
      hartid >= MAX_HARTS || group->coherence_inflight ||
      group->yxstm_phase != YXSTM_PHASE_IDLE ||
      group->hart_slots[hartid].yxstm_acquired ||
      member->yxstm_suspended_acquired)
    return 0;
  lane = group_lane_for_id_locked(group, member->lane_id);
  if (!lane || lane->hart_id != hartid ||
      lane->active_eid != member->eid ||
      lane->active_eid_generation != member->eid_generation ||
      lane->task_epoch != member->task_epoch)
    return 0;
  for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++)
    if (group->task_banks[bank_id].phase != YXSTM_PHASE_IDLE ||
        group->task_banks[bank_id].active_worker_mask ||
        group->task_banks[bank_id].ready_bitmap ||
        group->task_banks[bank_id].done_bitmap ||
        yxstm_task_bank_any_acquired_locked(group, bank_id))
      return 0;
  return 1;
}

static enclave_id group_scheduler_pick_next_direct_locked(
    unsigned long hartid,
    enclave_id current_eid,
    uint64_t group_id,
    int allow_fresh)
{
  struct sm_hart_sched* sched;
  struct enabled_group_slot* group;
  struct group_member_descriptor* current_member;
  size_t offset;
  enclave_id best = ENCL_MAX;
  uint64_t best_vruntime = ~(uint64_t)0;
  int best_is_fresh = 0;
  int best_class = 4;
  int best_cache_hot = 0;

  if (hartid >= MAX_HARTS)
    return ENCL_MAX;

  sched = &group_hart_schedulers[hartid];
  if (!sched->valid || sched->runqueue_len == 0)
    return ENCL_MAX;
  group = find_group_locked(group_id);
  current_member = group ? group_member_find_locked(group, current_eid) : 0;
  if (!group || !current_member)
    return ENCL_MAX;
  group_lane_wait_reconcile_slot_ready_locked(
      group, hartid, "direct_pick_slot_ready");
  if (current_member->role == GROUP_ROLE_WORKER &&
      !group_worker_lane_clean_task_boundary_locked(
          group, hartid, current_member) &&
      !group_worker_lane_shared_handoff_locked(
          group, hartid, current_member, 1) &&
      !group_worker_lane_preemptible_grant_locked(
          group, hartid, current_member))
    return ENCL_MAX;
  if (current_member->role != GROUP_ROLE_WORKER &&
      group->hart_slots[hartid].yxstm_acquired)
    return ENCL_MAX;

  for (offset = 1; offset <= sched->runqueue_len; offset++) {
    size_t index = (sched->current_index + offset) % sched->runqueue_len;
    enclave_id candidate = sched->runqueue[index].eid;

    if (candidate == current_eid)
      continue;
    if (candidate >= ENCL_MAX || !ENCLAVE_EXISTS(candidate) ||
        sched->runqueue[index].eid_generation !=
            enclaves[candidate].generation)
      continue;
    if (group_scheduler_eid_direct_switchable_locked(candidate, group_id)) {
      struct group_member_descriptor* member =
          group_member_find_locked(group, candidate);
      int candidate_is_fresh = enclaves[candidate].state == FRESH;
      int data_ready = member && member->yxstm_slot.valid &&
          (member->yxstm_slot.state == YXSTM_SLOT_READY ||
           member->yxstm_slot.state == YXSTM_SLOT_COMPUTING);
      int aged = member && sched->sched_epoch > member->sched_last_run_epoch &&
          sched->sched_epoch - member->sched_last_run_epoch >= 64;
      int candidate_class = data_ready ? (aged ? 0 : 1) : (aged ? 2 : 3);
      int cache_hot = member && member->yxstm_suspended_acquired;

      if (candidate_is_fresh && !allow_fresh)
        continue;
      if (member && group_scheduler_member_has_work_locked(member, candidate) &&
          (best == ENCL_MAX ||
           candidate_class < best_class ||
           (candidate_class == best_class &&
            (member->sched_vruntime < best_vruntime ||
             (member->sched_vruntime == best_vruntime &&
              (cache_hot > best_cache_hot ||
               (cache_hot == best_cache_hot &&
                candidate_is_fresh && !best_is_fresh))))))) {
        best = candidate;
        best_vruntime = member->sched_vruntime;
        best_is_fresh = candidate_is_fresh;
        best_class = candidate_class;
        best_cache_hot = cache_hot;
      }
    }
  }

  if (best != ENCL_MAX && hartid < MAX_HARTS)
    group_perf_harts[hartid].cfs_pick_count++;
  return best;
}

static enclave_id group_scheduler_pick_host_entry_locked(
    unsigned long hartid,
    uint64_t group_id)
{
  struct sm_hart_sched* sched;
  struct enabled_group_slot* group;
  size_t offset;
  enclave_id best = ENCL_MAX;
  uint64_t best_vruntime = ~(uint64_t)0;
  int best_is_fresh = 0;
  int best_class = 4;
  int best_cache_hot = 0;

  if (hartid >= MAX_HARTS)
    return ENCL_MAX;

  sched = &group_hart_schedulers[hartid];
  group = find_group_locked(group_id);
  if (!group || !sched->valid || sched->runqueue_len == 0)
    return ENCL_MAX;
  if (sched->active_group_id && sched->active_group_id != group_id)
    return ENCL_MAX;

  group_lane_wait_reconcile_slot_ready_locked(
      group, hartid, "host_pick_slot_ready");
  (void)group_scheduler_release_unbound_host_service_locked(
      group, sched, hartid);

  if (sched->host_service_pending) {
    enclave_id candidate = sched->host_service_eid;
    int admissible = 0;

    if (sched->heartbeat_enabled &&
        sched->heartbeat_state != KEYSTONE_GROUP_HEARTBEAT_STATE_VERIFIED)
      return ENCL_MAX;
    if (candidate < ENCL_MAX && ENCLAVE_EXISTS(candidate)) {
      admissible = group_scheduler_host_entry_admissible_locked(
          group, hartid, candidate);
      if (!admissible)
        admissible = group_scheduler_phase_edge_reentry_admissible_locked(
            group, sched, hartid, candidate);
    }
    if (candidate < ENCL_MAX && ENCLAVE_EXISTS(candidate) &&
        sched->host_service_eid_generation ==
            enclaves[candidate].generation &&
        sched->active_group_id == group_id &&
        enclaves[candidate].group_id == group_id &&
        group_scheduler_eid_direct_switchable_locked(candidate, group_id) &&
        admissible)
      return candidate;

    /*
     * A suspended grant is bound to this exact eid/generation. Never fall
     * through to another member on the same hart; cleanup, destroy or an
     * explicit stale-resume error must resolve the pending service first.
     */
    return ENCL_MAX;
  }

  for (offset = 0; offset < sched->runqueue_len; offset++) {
    size_t index = (sched->current_index + offset) % sched->runqueue_len;
    enclave_id candidate = sched->runqueue[index].eid;
    struct group_member_descriptor* member;
    int candidate_is_fresh;
    int data_ready;
    int aged;
    int candidate_class;
    int cache_hot;

    if (candidate >= ENCL_MAX || !ENCLAVE_EXISTS(candidate) ||
        sched->runqueue[index].eid_generation !=
            enclaves[candidate].generation ||
        !group_scheduler_eid_direct_switchable_locked(candidate, group_id) ||
        !group_scheduler_host_entry_admissible_locked(
            group, hartid, candidate))
      continue;
    member = group_member_find_locked(group, candidate);
    if (!member ||
        !group_scheduler_member_has_work_locked(member, candidate))
      continue;
    candidate_is_fresh = enclaves[candidate].state == FRESH;
    data_ready = member->yxstm_slot.valid &&
        (member->yxstm_slot.state == YXSTM_SLOT_READY ||
         member->yxstm_slot.state == YXSTM_SLOT_COMPUTING);
    aged = sched->sched_epoch > member->sched_last_run_epoch &&
        sched->sched_epoch - member->sched_last_run_epoch >= 64;
    candidate_class = data_ready ? (aged ? 0 : 1) : (aged ? 2 : 3);
    cache_hot = member->yxstm_suspended_acquired;
    if (best == ENCL_MAX || candidate_class < best_class ||
        (candidate_class == best_class &&
         (member->sched_vruntime < best_vruntime ||
          (member->sched_vruntime == best_vruntime &&
           (cache_hot > best_cache_hot ||
            (cache_hot == best_cache_hot &&
             candidate_is_fresh && !best_is_fresh)))))) {
      best = candidate;
      best_vruntime = member->sched_vruntime;
      best_is_fresh = candidate_is_fresh;
      best_class = candidate_class;
      best_cache_hot = cache_hot;
    }
  }
  if (best != ENCL_MAX && hartid < MAX_HARTS)
    group_perf_harts[hartid].cfs_pick_count++;
  return best;
}

static int group_scheduler_host_service_due_locked(
    struct enabled_group_slot* group,
    struct sm_hart_sched* sched,
    enclave_id current,
    enclave_id next)
{
  unsigned long hartid;
  uint64_t now;
  uint64_t interval;
  uint64_t deadline;

  if (!group || !sched || current >= ENCL_MAX)
    return 0;
  hartid = sched->hart_id;
  if (hartid >= MAX_HARTS || group->coherence_inflight ||
      !group_hart_run_status_ptr[hartid] ||
      !group_hart_host_context_valid[hartid])
    return 0;
  if (sched->host_service_forced)
    return 1;
  if (!sched->heartbeat_enabled ||
      !(group->lease_flags & KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT))
    return 0;

  sched->timer_tick_count++;
  if (!sched->timer_tick_count)
    sched->timer_tick_count++;

  /*
   * SSIP/STIP/SEIP are not ownership-tagged. While a group enclave is active,
   * they may describe saved runtime state, Linux work waiting for the next
   * host boundary, or a level-triggered device. Treating any pending bit as an
   * immediate request collapses the configured cadence into a timer-driven
   * return/re-enter loop and can starve both protocol progress and Linux
   * workqueues.
   *
   * MTIP remains the scheduler trigger. Expose Linux work only at the
   * deterministic host-service cadence, where context_switch_to_host()
   * publishes a fresh STIP after restoring the host frame.
   */
  if (!KEYSTONE_GROUP_HOST_SERVICE_INTERVAL_US)
    return 0;
  now = sbi_timer_value();
  interval = group_scheduler_host_service_delta_local();
  deadline = sched->host_service_deadline;
  if (!deadline) {
    deadline = now + interval;
    if (deadline < now)
      deadline = ~(uint64_t)0;
    sched->host_service_deadline = deadline;
    return 0;
  }
  if (now < deadline)
    return 0;
  deadline = now + interval;
  if (deadline < now)
    deadline = ~(uint64_t)0;
  sched->host_service_deadline = deadline;
  (void)next;
  return 1;
}

unsigned long group_scheduler_timer_tick(enclave_id eid)
{
  unsigned long hartid = csr_read(mhartid);
  struct sm_hart_sched* sched;
  enclave_id next;

  if (eid >= ENCL_MAX || enclaves[eid].group_id == 0)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

  spin_lock(&encl_lock);
  if (hartid >= MAX_HARTS) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  sched = &group_hart_schedulers[hartid];
  if (!group_scheduler_active_matches_locked(sched, eid)) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }

  next = group_scheduler_pick_next_locked(hartid, eid);
  if (next == ENCL_MAX) {
    (void)group_scheduler_validate_locked(sched, "timer_single_runnable");
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }

  if ((uint64_t)(sbi_timer_value() - sched->last_progress_time) >=
      KEYSTONE_GROUP_WATCHDOG_CYCLES) {
    struct enabled_group_slot* group = find_group_locked(enclaves[eid].group_id);
    sched->watchdog_count++;
    sched->last_progress_time = sbi_timer_value();
    (void)group_scheduler_event_enqueue(
        hartid, enclaves[eid].group_id, group ? group->generation : 0,
        eid, enclaves[eid].generation, KEYSTONE_GROUP_EVENT_WATCHDOG,
        SBI_ERR_SM_GROUP_WATCHDOG, sched->watchdog_count);
    sbi_printf("[SM][sched] watchdog: hart=%lu group=%lu eid=%u next=%u epoch=%lu count=%lu\n",
               hartid, (unsigned long)enclaves[eid].group_id, eid, next,
               (unsigned long)sched->sched_epoch,
               (unsigned long)sched->watchdog_count);
  }

  /*
   * Diagnostic fallback: F2 direct switching uses the stricter
   * group_scheduler_pick_next_direct_locked() path. This tick-only path still
   * records that a runnable peer exists even when it is not yet direct
   * switchable, for example because it has no restorable thread context.
   */
#if KEYSTONE_GROUP_TIMER_TRACE
  if (hartid < MAX_HARTS) {
    uint64_t count = ++group_timer_candidate_log_count[hartid];
    if (count <= 4 || (count & 0xff) == 0) {
      sbi_printf("[SM][sched] timer candidate: hart=%lu current=%u next=%u epoch=%lu count=%lu\n",
                 hartid,
                 eid,
                 next,
                 (unsigned long)sched->sched_epoch,
                 (unsigned long)count);
    }
  }
#endif
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long group_scheduler_switch_active_local(
    enclave_id current,
    enclave_id* next_inout,
    enum group_sched_state current_state,
    int allow_reselect,
    int* next_first_run_out)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group;
  struct group_active_hart_state* state;
  struct group_member_descriptor* current_member;
  struct group_member_descriptor* next_member;
  struct group_worker_lane* lane = 0;
  uint64_t bank_id;
  int shared_handoff = 0;
  int slot_handoff = 0;
  const char* reject_where = "unknown";
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
  enclave_id next;

  if (!next_inout || current >= ENCL_MAX || *next_inout >= ENCL_MAX)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (next_first_run_out)
    *next_first_run_out = 0;
  next = *next_inout;
  if (hartid >= MAX_HARTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);

  if (enclaves[current].group_id == 0) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    reject_where = "current_group";
    goto out;
  }

  group = find_group_locked(enclaves[current].group_id);
  state = &group_active_harts[hartid];
  current_member = group ? group_member_find_locked(group, current) : 0;
  if (!group || !state->active || state->eid != current ||
      state->eid_generation != enclaves[current].generation ||
      state->active_group_id != group->group_id ||
      state->group_generation != group->generation ||
      !current_member) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    reject_where = "current_not_active";
    goto out;
  }

  /*
   * OCALL completion and slot wakeups run on the housekeeping hart.  They may
   * change the selected peer between the timer's initial pick and this commit
   * point.  Re-pick while holding encl_lock so validation and active-owner
   * publication form one scheduler transaction.
   */
  if (!ENCLAVE_EXISTS(next) ||
      enclaves[next].group_id != group->group_id ||
      !group_scheduler_eid_direct_switchable_locked(next, group->group_id)) {
    if (allow_reselect)
      next = group_scheduler_pick_next_direct_locked(
          hartid, current, group->group_id, 0);
    if (next == ENCL_MAX || !ENCLAVE_EXISTS(next) ||
        enclaves[next].group_id != group->group_id ||
        !group_scheduler_eid_direct_switchable_locked(
            next, group->group_id)) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
      reject_where = "peer_state_changed";
      goto out;
    }
  }
  next_member = group_member_find_locked(group, next);
  if (!next_member) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    reject_where = "peer_member_missing";
    goto out;
  }
  *next_inout = next;
  if (next_first_run_out)
    *next_first_run_out = enclaves[next].state == FRESH;

  if (current_member->role == GROUP_ROLE_WORKER ||
      next_member->role == GROUP_ROLE_WORKER) {
    if (current_member->role != GROUP_ROLE_WORKER ||
        next_member->role != GROUP_ROLE_WORKER ||
        current_member->lane_id != next_member->lane_id) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
      reject_where = "cross_lane";
      goto out;
    }
    lane = group_lane_for_id_locked(group, current_member->lane_id);
    slot_handoff = lane && lane->hart_id == hartid &&
        group->yxstm_slots_frozen && lane->slots_frozen &&
        current_member->yxstm_slot.valid && next_member->yxstm_slot.valid &&
        current_member->yxstm_slot.lane_id == lane->lane_id &&
        next_member->yxstm_slot.lane_id == lane->lane_id &&
        !group->coherence_inflight &&
        (current_state == GROUP_SCHED_RUNNABLE ||
         current_state == GROUP_SCHED_BLOCKED) &&
        !group->hart_slots[hartid].yxstm_acquired;
    if (slot_handoff && current_member->yxstm_suspended_acquired)
      slot_handoff = group_member_suspended_grant_valid_locked(
          group, hartid, current_member);
    if (slot_handoff && next_member->yxstm_suspended_acquired)
      slot_handoff = group_member_suspended_grant_valid_locked(
          group, hartid, next_member);
    if (lane && lane->hart_id == hartid && !group->coherence_inflight &&
        (current_state == GROUP_SCHED_RUNNABLE ||
         current_state == GROUP_SCHED_BLOCKED) &&
        !group->hart_slots[hartid].yxstm_acquired) {
      if (current_member->yxstm_suspended_acquired) {
        shared_handoff = group_member_suspended_grant_valid_locked(
            group, hartid, current_member);
      } else if (group->yxstm_phase != YXSTM_PHASE_IDLE &&
                 current_member->task_epoch == group->yxstm_task_epoch &&
                 next_member->task_epoch == group->yxstm_task_epoch &&
                 lane->task_epoch == group->yxstm_task_epoch) {
        shared_handoff = 1;
        for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++)
          if (group->task_banks[bank_id].phase != YXSTM_PHASE_IDLE ||
              yxstm_task_bank_any_acquired_locked(group, bank_id)) {
            shared_handoff = 0;
            break;
          }
      }
      if (shared_handoff && next_member->yxstm_suspended_acquired)
        shared_handoff = group_member_suspended_grant_valid_locked(
            group, hartid, next_member);
    }
    if (!lane || lane->hart_id != hartid ||
        ((group->yxstm_phase != YXSTM_PHASE_IDLE ||
          current_member->yxstm_suspended_acquired ||
          next_member->yxstm_suspended_acquired) &&
         !slot_handoff && !shared_handoff) ||
        group->hart_slots[hartid].yxstm_acquired) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
      reject_where = slot_handoff ? "slot_handoff_live_grant" :
                                    "legacy_handoff_gate";
      goto out;
    }
  }

  /*
   * Publish the outgoing scheduler state before clearing active_eid.  The
   * invariant requires RUNNING and active_eid to change as one transaction;
   * clearing active_eid while current is still RUNNING creates a transient
   * state that the following set_active() quite correctly rejects.
   */
  group_scheduler_set_state_locked(current, current_state);
  group_scheduler_clear_active_locked(hartid, current);

  if (group_scheduler_set_active_locked(group, hartid, next)) {
    (void)group_scheduler_set_active_locked(group, hartid, current);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    reject_where = "set_active";
    goto out;
  }

  /*
   * keystone-group-thread-count-canonical-v1
   *
   * The outgoing trap frame is now saved and no longer executes on this
   * hart. Keep the legacy enclave lifecycle state consistent with the
   * scheduler state; otherwise every later group_run_hart entry increments
   * n_thread again and OCALL resume eventually observes threads=2,3,... .
   */
  if (enclaves[current].state == RUNNING ||
      enclaves[current].state == STOPPED) {
    enclaves[current].state = STOPPED;
    enclaves[current].n_thread = 0;
  }

  group_scheduler_set_state_locked(next, GROUP_SCHED_RUNNING);

  if (enclaves[next].state == FRESH || enclaves[next].state == STOPPED) {
    enclaves[next].state = RUNNING;
    if (enclaves[next].n_thread == 0)
      enclaves[next].n_thread = 1;
  }

  state->eid = next;
  state->eid_generation = enclaves[next].generation;
  state->active_group_id = group->group_id;
  state->group_generation = group->generation;
  state->active_epoch = group->permission_epoch;
  state->active_phase_epoch = group->yxstm_phase_epoch;
  state->pmp_installed = 0;
  if (group->hart_slots[hartid].valid) {
    group->hart_slots[hartid].active_eid = next;
    group->hart_slots[hartid].active_epoch = group->permission_epoch;
    group->hart_slots[hartid].pmp_epoch = group->permission_epoch;
    group->hart_slots[hartid].phase_epoch = group->yxstm_phase_epoch;
  }

  if (!group_context_validate_locked(group, "timer_switch_active"))
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

out:
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
    sbi_printf("[SM][sched] switch commit rejected: hart=%lu current=%u next=%u reason=%s current_sched=%u next_sched=%u current_state=%d next_state=%d\n",
               hartid, current, next, reject_where,
               current < ENCL_MAX && ENCLAVE_EXISTS(current) ?
                   (unsigned int)enclaves[current].sched_state : 0U,
               next < ENCL_MAX && ENCLAVE_EXISTS(next) ?
                   (unsigned int)enclaves[next].sched_state : 0U,
               current < ENCL_MAX && ENCLAVE_EXISTS(current) ?
                   (int)enclaves[current].state : -1,
               next < ENCL_MAX && ENCLAVE_EXISTS(next) ?
                   (int)enclaves[next].state : -1);
  spin_unlock(&encl_lock);
  return ret;
}

static void group_scheduler_save_thread_context(
    struct thread_state* thread,
    struct sbi_trap_regs* regs,
    int return_on_resume)
{
  /*
   * G-stage context boundary:
   * - save every GPR captured by trap.S plus the audited S-mode CSR image.
   * - save the trap return point and enclave-visible mstatus bits.
   * - PMP/YXSTM permissions are deliberately outside thread_state and are
   *   rebuilt by group_scheduler_schedule_in_local().
   * - M-mode delegation/counter policy is SM-owned in Keystone. Unlike Coffer's
   *   standalone Context, we do not treat mideleg/medeleg/mcounteren as
   *   per-enclave scheduler state.
   */
  thread_state_save_exact(thread, regs);
  /* Preserve Keystone's historical synchronous stop/resume marker. */
  thread->prev_state.slot = !return_on_resume;
}

static void group_scheduler_save_thread_context_profiled(
    struct thread_state* thread,
    struct sbi_trap_regs* regs,
    int return_on_resume,
    struct thread_state_profile* profile)
{
  thread_state_save_exact_profiled(thread, regs, profile);
  thread->prev_state.slot = !return_on_resume;
}

static void group_scheduler_save_thread_context_exact(
    struct thread_state* thread,
    struct sbi_trap_regs* regs)
{
  /* Asynchronous timer/IPI/host-service interrupts preserve every GPR. */
  thread_state_save_exact(thread, regs);
}

static void group_scheduler_restore_thread_context_exact(
    const struct thread_state* thread,
    struct sbi_trap_regs* regs)
{
  thread_state_restore_exact(thread, regs);
}

static void group_scheduler_restore_thread_context_profiled(
    const struct thread_state* thread,
    struct sbi_trap_regs* regs,
    struct thread_state_profile* profile)
{
  thread_state_restore_exact_profiled(thread, regs, profile);
}

static void group_scheduler_prepare_first_run_regs(enclave_id eid,
                                                   struct sbi_trap_regs* regs)
{
  uintptr_t yxstm_param_base = enclaves[eid].params.YXSTrusted_base;
  size_t yxstm_param_size = enclaves[eid].params.YXSTrusted_size;

  /*
   * A successful peer switch makes sbi_sm_stop_enclave() call
   * sbi_trap_exit() directly, before its ordinary mepc += 4 path. Timer
   * switches likewise return directly from the interrupt trap. Both direct
   * FRESH launch paths must therefore seed the exact loader entry address.
   */
  regs->mepc = (uintptr_t)enclaves[eid].params.dram_base;
  regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
  regs->a0 = SBI_ERR_SM_ENCLAVE_SUCCESS;
  regs->a1 = (uintptr_t)enclaves[eid].params.dram_base;
  regs->a2 = (uintptr_t)enclaves[eid].params.dram_size;
  regs->a3 = (uintptr_t)enclaves[eid].params.runtime_base;
  regs->a4 = (uintptr_t)enclaves[eid].params.user_base;
  regs->a5 = (uintptr_t)enclaves[eid].params.free_base;
  regs->a6 = (uintptr_t)enclaves[eid].params.untrusted_base;
  regs->a7 = (uintptr_t)enclaves[eid].params.untrusted_size;
  regs->t0 = (uintptr_t)yxstm_param_base;
  regs->t1 = (uintptr_t)yxstm_param_size;
  regs->t2 = (uintptr_t)enclaves[eid].params.shared_utm_base;
  regs->t3 = (uintptr_t)enclaves[eid].params.shared_utm_size;
  regs->t4 = (uintptr_t)enclaves[eid].params.sec_base;
  regs->t5 = (uintptr_t)enclaves[eid].params.sec_size;

  csr_write(sstatus, 0);
  csr_write(sie, 0);
  csr_write(stvec, 0);
  csr_write(sscratch, 0);
  csr_write(sepc, 0);
  csr_write(scause, 0);
  csr_write(sbadaddr, 0);
  csr_write(sip, 0);
  csr_write(satp, 0);
  asm volatile("sfence.vma" ::: "memory");
}

static void group_scheduler_restore_fresh_state(enclave_id eid)
{
  if (eid >= ENCL_MAX)
    return;

  spin_lock(&encl_lock);
  if (ENCLAVE_EXISTS(eid) && enclaves[eid].group_id != 0) {
    enclaves[eid].state = FRESH;
    enclaves[eid].n_thread = 0;
    (void)group_scheduler_transition_locked(
        eid, GROUP_SCHED_RUNNABLE, "restore_fresh");
    group_member_timer_ready[eid] = 0;
  }
  spin_unlock(&encl_lock);
}

static void group_scheduler_adjust_resume_pc(
    struct sbi_trap_regs* regs, enclave_id eid, int via_sbi_return)
{
  /*
   * Synchronous HOST returns save the STOP ecall PC. Timer/IPI saves and
   * direct yields save an exact continuation instead. A peer trap exit has
   * no outer SBI +4; consuming a HOST-completed OCALL there must skip STOP,
   * or its saved a0=SUCCESS re-executes it as STOP_TIMER_INTERRUPT.
   */
  if (via_sbi_return) {
    if (group_member_saved_mepc_advanced[eid] && regs->mepc >= 4)
      regs->mepc -= 4;
  } else if (!group_member_saved_mepc_advanced[eid]) {
    regs->mepc += 4;
  }
  group_member_saved_mepc_advanced[eid] = 0;
}

static int group_scheduler_direct_switch_from_ecall(
    struct sbi_trap_regs* regs,
    enclave_id current,
    enum group_sched_state current_state,
    const char* where,
    int advance_current_mepc)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group;
  struct sm_hart_sched* sched;
  enclave_id next = ENCL_MAX;
  int next_first_run = 0;
  unsigned long ret;
  uintptr_t saved_mepc;
  uintptr_t resume_mepc;
  int next_pc_exact;
  uint64_t switch_count = 0;
  uint64_t perf_cycle_start;
  uint64_t perf_time_start;
  uint64_t component_start;
  uint64_t pmp_cycles = 0;
  uint64_t platform_cycles = 0;
  uint64_t scheduler_lock_cycles = 0;
  struct thread_state_profile save_profile = {0};
  struct thread_state_profile restore_profile = {0};
  int same_lane_fast_path = 0;

  if (!regs || current >= ENCL_MAX || enclaves[current].group_id == 0)
    return 0;
  if (hartid >= MAX_HARTS)
    return 0;
  /*
   * Direct enclave-to-enclave switching is owned by group_run_hart. A normal
   * run_enclave call only has the launched enclave's thread_state available as
   * the host return context; switching to a different eid from that path can
   * make a later fault/exit restore the wrong host frame.
   */
  if (!group_hart_run_status_ptr[hartid])
    return 0;

  spin_lock(&encl_lock);
  group_ocall_expire_locked();
  group = find_group_locked(enclaves[current].group_id);
  sched = &group_hart_schedulers[hartid];
  if (group && current_state != GROUP_SCHED_BLOCKED)
    group_member_timer_ready[current] = 1;
  if (group && group_scheduler_active_matches_locked(sched, current)) {
    group_scheduler_cfs_account_current_locked(
        group, sched, current, sbi_timer_value());
    next = group_scheduler_pick_next_direct_locked(hartid, current,
                                                   group->group_id, 1);
  }
  if (next != ENCL_MAX && enclaves[next].state == FRESH)
    next_first_run = 1;
  if (next != ENCL_MAX && group) {
    same_lane_fast_path = group_scheduler_same_lane_fast_eligible_locked(
        group, hartid, current, next);
    if (group->execution_mode == GROUP_MODE_3W_1HM &&
        !same_lane_fast_path) {
      sbi_printf("[SM][sched] peer switch rejected: fast-PMP invariant failed hart=%lu group=%lu current=%u next=%u where=%s\n",
                 hartid, (unsigned long)group->group_id,
                 current, next, where);
      next = ENCL_MAX;
    }
  }
  spin_unlock(&encl_lock);

  if (next == ENCL_MAX)
    return 0;

  perf_cycle_start = csr_read(CSR_MCYCLE);
  perf_time_start = sbi_timer_value();

  switch_count = ++group_ecall_switch_log_count[hartid];

  /*
   * keystone-yxstm-resumable-grant-v1
   * A worker may yield while an asynchronous OCALL is still pending and while
   * it owns its COMPUTING slot.  Preserve that authority as SM-only suspended
   * metadata before the same-lane PMP handoff.  schedule-in revalidates the
   * group/member/permission/slot epochs before restoring the aperture.
   */
  component_start = csr_read(CSR_MCYCLE);
  ret = group_scheduler_suspend_yxstm_grant_local(
      current, where, same_lane_fast_path);
  pmp_cycles += csr_read(CSR_MCYCLE) - component_start;
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    group_scheduler_log_timer_retry_local(
        current, next, ret, "ecall_grant_suspend");
    group_scheduler_refresh_current_slice_local(current);
    return 0;
  }

  if (advance_current_mepc) {
    regs->mepc += 4;
    regs->a0 = SBI_ERR_SM_ENCLAVE_SUCCESS;
  }

  saved_mepc = regs->mepc;
  group_scheduler_save_thread_context_profiled(
      &enclaves[current].threads[0], regs, 1, &save_profile);
  /* Record that this saved PC is already past the initiating ecall. */
  if (advance_current_mepc) {
    enclaves[current].threads[0].prev_mepc = saved_mepc;
    enclaves[current].threads[0].prev_state.a0 =
        SBI_ERR_SM_ENCLAVE_SUCCESS;
    group_member_saved_mepc_advanced[current] = 1;
  }
  component_start = csr_read(CSR_MCYCLE);
  group_scheduler_schedule_out_local(
      current, where, same_lane_fast_path ? 2 : 0);
  pmp_cycles += csr_read(CSR_MCYCLE) - component_start;
  component_start = csr_read(CSR_MCYCLE);
  platform_switch_from_enclave(&enclaves[current]);
  platform_cycles += csr_read(CSR_MCYCLE) - component_start;

  component_start = csr_read(CSR_MCYCLE);
  ret = group_scheduler_switch_active_local(
      current, &next, current_state, 1, &next_first_run);
  scheduler_lock_cycles += csr_read(CSR_MCYCLE) - component_start;
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    group_scheduler_schedule_in_local(current, same_lane_fast_path ? 2 : 0);
    platform_switch_to_enclave(&enclaves[current]);
    group_scheduler_restore_thread_context_exact(
        &enclaves[current].threads[0], regs);
    /* No peer trap exit: the caller still owns the SBI return adjustment. */
    if (advance_current_mepc)
      regs->mepc -= 4;
    group_member_saved_mepc_advanced[current] = 0;
    return 0;
  }
  if (current_state == GROUP_SCHED_BLOCKED)
    group_lane_wait_mark_context_saved(current);

  component_start = csr_read(CSR_MCYCLE);
  ret = group_scheduler_schedule_in_local(
      next, same_lane_fast_path ? 2 : 0);
  pmp_cycles += csr_read(CSR_MCYCLE) - component_start;
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    enclave_id rollback = current;
    (void)group_scheduler_switch_active_local(
        next, &rollback, GROUP_SCHED_RUNNABLE, 0, 0);
    if (next_first_run)
      group_scheduler_restore_fresh_state(next);
    group_scheduler_schedule_in_local(current, same_lane_fast_path ? 2 : 0);
    platform_switch_to_enclave(&enclaves[current]);
    group_scheduler_restore_thread_context_exact(
        &enclaves[current].threads[0], regs);
    if (advance_current_mepc)
      regs->mepc -= 4;
    group_member_saved_mepc_advanced[current] = 0;
    return 0;
  }

  component_start = csr_read(CSR_MCYCLE);
  platform_switch_to_enclave(&enclaves[next]);
  platform_cycles += csr_read(CSR_MCYCLE) - component_start;
  next_pc_exact = group_member_saved_mepc_advanced[next];
  if (next_first_run) {
    group_scheduler_restore_thread_context_profiled(
        &enclaves[next].threads[0], regs, &restore_profile);
    component_start = csr_read(CSR_MCYCLE);
    group_scheduler_prepare_first_run_regs(next, regs);
    restore_profile.smode_csr_cycles +=
        csr_read(CSR_MCYCLE) - component_start;
    group_member_saved_mepc_advanced[next] = 0;
  } else {
    group_scheduler_restore_thread_context_profiled(
        &enclaves[next].threads[0], regs, &restore_profile);
    group_scheduler_adjust_resume_pc(regs, next, 0);
  }
  resume_mepc = regs->mepc;
  cpu_enter_enclave_context(next);
  group_perf_add_context_components(
      &save_profile, &restore_profile, pmp_cycles,
      platform_cycles, scheduler_lock_cycles);
  group_perf_record_context_switch(perf_cycle_start, perf_time_start);

  if (switch_count <= 4 || (switch_count & 0x3f) == 0) {
    sbi_printf("[SM][sched] ecall switch: hart=%lu group=%lu current=%u next=%u state=%u first=%d where=%s count=%lu saved_mepc=0x%lx resume_mepc=0x%lx resume_pc_fix=1 resume_kind=%s\n",
               hartid,
               (unsigned long)enclaves[next].group_id,
               current,
               next,
               (unsigned int)current_state,
               next_first_run,
               where,
               (unsigned long)switch_count,
               (unsigned long)saved_mepc,
               (unsigned long)resume_mepc,
               next_first_run ? "fresh" : (next_pc_exact ? "exact" : "stop"));
  }
  return 1;
}

static int group_scheduler_same_lane_fast_eligible_locked(
    struct enabled_group_slot* group, unsigned long hartid,
    enclave_id current, enclave_id next)
{
  struct group_member_descriptor* current_member;
  struct group_member_descriptor* next_member;

  if (!group || hartid >= MAX_HARTS || current >= ENCL_MAX ||
      next >= ENCL_MAX || !ENCLAVE_EXISTS(current) || !ENCLAVE_EXISTS(next))
    return 0;
  current_member = group_member_find_locked(group, current);
  next_member = group_member_find_locked(group, next);
  /*
   * The group EPM entry is the unchanged outer boundary. Each member's SATP
   * selects its private virtual view, while the cached OS/UTM PMP entry is
   * replaced at handoff. shared_utm still needs the legacy OS aperture, so it
   * deliberately falls back to the full path.
   */
  if (!current_member || !next_member ||
      current_member->role != GROUP_ROLE_WORKER ||
      next_member->role != GROUP_ROLE_WORKER ||
      current_member->bound_hart != hartid ||
      next_member->bound_hart != hartid ||
      current_member->lane_id != next_member->lane_id ||
      !current_member->pmp_cache_valid || !next_member->pmp_cache_valid ||
      current_member->pmp_cache_group_generation != group->generation ||
      next_member->pmp_cache_group_generation != group->generation ||
      !current_member->pmp_utm_cache_valid ||
      !next_member->pmp_utm_cache_valid ||
      !current_member->pmp_utm_allow.valid ||
      !current_member->pmp_utm_deny.valid ||
      !next_member->pmp_utm_allow.valid ||
      !next_member->pmp_utm_deny.valid ||
      current_member->pmp_utm_allow.slot != KEYSTONE_PMP_SLOT_OS_UTM ||
      current_member->pmp_utm_deny.slot != KEYSTONE_PMP_SLOT_OS_UTM ||
      next_member->pmp_utm_allow.slot != KEYSTONE_PMP_SLOT_OS_UTM ||
      next_member->pmp_utm_deny.slot != KEYSTONE_PMP_SLOT_OS_UTM ||
      current_member->pmp_yxstm_deny_count != 2 ||
      next_member->pmp_yxstm_deny_count != 2 ||
      current_member->pmp_yxstm_deny[0].slot !=
          KEYSTONE_PMP_SLOT_YXSTM_LO ||
      current_member->pmp_yxstm_deny[1].slot !=
          KEYSTONE_PMP_SLOT_YXSTM_HI ||
      next_member->pmp_yxstm_deny[0].slot !=
          KEYSTONE_PMP_SLOT_YXSTM_LO ||
      next_member->pmp_yxstm_deny[1].slot !=
          KEYSTONE_PMP_SLOT_YXSTM_HI ||
      enclaves[current].regions[0].pmp_rid !=
          enclaves[next].regions[0].pmp_rid ||
      enclaves[current].params.shared_utm_size ||
      enclaves[next].params.shared_utm_size ||
      enclaves[current].ped.sec_mmio_base !=
          enclaves[next].ped.sec_mmio_base ||
      enclaves[current].ped.sec_mmio_size !=
          enclaves[next].ped.sec_mmio_size)
    return 0;
  return 1;
}

static const struct keystone_pmp_cached_entry*
group_member_cached_yxstm_entries_locked(
    const struct group_member_descriptor* member, size_t* entry_count)
{
  unsigned int writable;

  if (entry_count)
    *entry_count = 0;
  if (!member || !member->pmp_cache_valid)
    return 0;
  if (!member->yxstm_suspended_acquired) {
    if (entry_count)
      *entry_count = member->pmp_yxstm_deny_count;
    return member->pmp_yxstm_deny;
  }
  if (!member->yxstm_slot.valid || !member->yxstm_slot.pmp_cache_valid ||
      member->yxstm_slot.pmp_entry_count != 2 ||
      member->yxstm_suspended_permissions == 0 ||
      (member->yxstm_suspended_permissions &
       ~(KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W)))
    return 0;
  writable = (member->yxstm_suspended_permissions &
              KEYSTONE_YXSTM_PERM_W) ? 1U : 0U;
  if (entry_count)
    *entry_count = member->yxstm_slot.pmp_entry_count;
  return member->yxstm_slot.pmp_grant[writable];
}

static int group_member_apply_same_lane_pmp_locked(
    const struct group_member_descriptor* member,
    const struct keystone_pmp_cached_entry* yxstm_entries,
    size_t yxstm_entry_count,
    int allow_utm)
{
  struct keystone_pmp_cached_entry entries[3];

  if (!member || !member->pmp_cache_valid || !member->pmp_utm_cache_valid ||
      !yxstm_entries || yxstm_entry_count != 2 ||
      !yxstm_entries[0].valid || !yxstm_entries[1].valid ||
      yxstm_entries[0].slot != KEYSTONE_PMP_SLOT_YXSTM_LO ||
      yxstm_entries[1].slot != KEYSTONE_PMP_SLOT_YXSTM_HI ||
      member->pmp_utm_allow.slot != KEYSTONE_PMP_SLOT_OS_UTM ||
      member->pmp_utm_deny.slot != KEYSTONE_PMP_SLOT_OS_UTM)
    return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  entries[0] = allow_utm ? member->pmp_utm_allow : member->pmp_utm_deny;
  entries[1] = yxstm_entries[0];
  entries[2] = yxstm_entries[1];
  return pmp_apply_cached_entries_deferred_fence(entries, 3) ?
      SBI_ERR_SM_ENCLAVE_PMP_FAILURE : SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/*
 * Convert the current hart's installed YXSTM aperture into an SM-owned
 * continuation. The interrupted S/U-mode context cannot execute while this
 * function runs, so snapshot + PMP revoke is atomic with respect to enclave
 * memory accesses. A later schedule-in must revalidate every authority epoch
 * before rebuilding the aperture.
 */
static unsigned long group_scheduler_suspend_yxstm_grant_local(
    enclave_id eid, const char* where, int defer_hardware_revoke)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  struct group_hart_slot* slot;
  struct group_active_hart_state* active;
  uint64_t started;
  uint64_t component_start;
  uint64_t component_cycles;
  uint64_t suspend_fence_cycles = 0;
  uint64_t suspend_core_cycles = 0;
  int grant_suspended = 0;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (eid >= ENCL_MAX || hartid >= MAX_HARTS || !ENCLAVE_EXISTS(eid))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  component_start = csr_read(CSR_MCYCLE);
  spin_lock(&encl_lock);
  group_perf_add_pmp_component(
      GROUP_PERF_PMP_LOCK_WAIT, csr_read(CSR_MCYCLE) - component_start);
  group = find_group_locked(enclaves[eid].group_id);
  member = group ? group_member_find_locked(group, eid) : 0;
  slot = group ? &group->hart_slots[hartid] : 0;
  active = &group_active_harts[hartid];
  if (!group || !member || !slot || !slot->valid || !active->active ||
      active->eid != eid ||
      active->eid_generation != enclaves[eid].generation ||
      active->active_group_id != group->group_id ||
      active->group_generation != group->generation) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out;
  }
  if (!slot->yxstm_acquired) {
    if (slot->yxstm_owner_eid != ENCL_MAX ||
        slot->yxstm_acquired_slice_mask || slot->yxstm_permissions ||
        slot->yxstm_phase != YXSTM_PHASE_IDLE)
      ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
    goto out;
  }
  if (!group_worker_lane_preemptible_grant_locked(
          group, hartid, member)) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out;
  }
  if (group->yxstm_region < 0) {
    ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
    goto out;
  }

  started = csr_read(CSR_MCYCLE);
  member->yxstm_suspended_acquired = 1;
  member->yxstm_suspended_slice_mask = slot->yxstm_acquired_slice_mask;
  member->yxstm_suspended_permissions = slot->yxstm_permissions;
  member->yxstm_suspended_phase = slot->yxstm_phase;
  member->yxstm_suspended_bank_id = slot->yxstm_bank_id;
  member->yxstm_suspended_phase_epoch = slot->phase_epoch;
  member->yxstm_suspended_permission_epoch = slot->pmp_epoch;
  member->yxstm_suspended_task_epoch =
      slot->yxstm_bank_id == GROUP_YXSTM_SLOT_GRANT_BANK ?
          slot->yxstm_slot_epoch :
      slot->yxstm_bank_id != KEYSTONE_YXSTM_INVALID_BANK &&
              slot->yxstm_bank_id < group->yxstm_bank_count ?
          group->task_banks[slot->yxstm_bank_id].task_epoch :
          group->yxstm_task_epoch;
  member->yxstm_suspended_slot_lane = slot->yxstm_slot_lane;
  member->yxstm_suspended_slot_id = slot->yxstm_slot_id;
  member->yxstm_suspended_slot_epoch = slot->yxstm_slot_epoch;

  /*
   * A same-lane handoff keeps the group EPM boundary installed. Its one
   * batched PMP commit below will revoke this grant and install the next one,
   * so publishing the continuation here needs no intermediate CSR write.
   */
  if (!defer_hardware_revoke) {
    component_start = csr_read(CSR_MCYCLE);
    asm volatile("fence rw,rw" ::: "memory");
    component_cycles = csr_read(CSR_MCYCLE) - component_start;
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_FENCE, component_cycles);
    suspend_fence_cycles += component_cycles;
    pmp_set_keystone(group->yxstm_region, PMP_NO_PERM);
    component_start = csr_read(CSR_MCYCLE);
    asm volatile("sfence.vma" ::: "memory");
    component_cycles = csr_read(CSR_MCYCLE) - component_start;
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_FENCE, component_cycles);
    suspend_fence_cycles += component_cycles;
  }

  slot->yxstm_owner_eid = ENCL_MAX;
  slot->yxstm_acquired = 0;
  slot->yxstm_acquired_slice_mask = 0;
  slot->yxstm_permissions = 0;
  slot->yxstm_phase = YXSTM_PHASE_IDLE;
  slot->yxstm_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
  slot->yxstm_slot_lane = KEYSTONE_GROUP_UNBOUND_LANE;
  slot->yxstm_slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
  slot->yxstm_slot_epoch = 0;
  member->yxstm_suspended_save_cycles =
      csr_read(CSR_MCYCLE) - started;
  suspend_core_cycles =
      member->yxstm_suspended_save_cycles > suspend_fence_cycles ?
          member->yxstm_suspended_save_cycles - suspend_fence_cycles : 0;
  grant_suspended = 1;
#if KEYSTONE_GROUP_TIMER_TRACE
  sbi_printf("[SM][sched] grant suspended: hart=%lu group=%lu eid=%u where=%s mask=0x%lx phase=%lu epoch=%lu\n",
             hartid, (unsigned long)group->group_id, eid,
             where ? where : "unknown",
             (unsigned long)member->yxstm_suspended_slice_mask,
             (unsigned long)member->yxstm_suspended_phase,
             (unsigned long)member->yxstm_suspended_phase_epoch);
#else
  (void)where;
#endif

out:
  spin_unlock(&encl_lock);
  if (grant_suspended)
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_GRANT_SUSPEND, suspend_core_cycles);
  return ret;
}

unsigned long group_scheduler_timer_switch(struct sbi_trap_regs* regs,
                                            enclave_id current)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  struct sm_hart_sched* sched;
  enclave_id next = ENCL_MAX;
  int next_first_run = 0;
  unsigned long ret;
  uintptr_t control_action = 0;
  enum group_sched_state current_state = GROUP_SCHED_RUNNABLE;
  uint64_t perf_cycle_start;
  uint64_t perf_time_start;
  uint64_t component_start;
  uint64_t pmp_cycles = 0;
  uint64_t platform_cycles = 0;
  uint64_t scheduler_lock_cycles = 0;
  struct thread_state_profile save_profile = {0};
  struct thread_state_profile restore_profile = {0};
  int service_host = 0;
  int cfs_preempt = 1;
  int same_lane_fast_path = 0;

  if (!regs || current >= ENCL_MAX || enclaves[current].group_id == 0)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (hartid >= MAX_HARTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  group_ocall_expire_locked();
  group = find_group_locked(enclaves[current].group_id);
  member = group ? group_member_find_locked(group, current) : 0;
  sched = &group_hart_schedulers[hartid];
  if (!group || !member ||
      (group->execution_mode == GROUP_MODE_3W_1HM &&
       member->role != GROUP_ROLE_WORKER)) {
    /* The housekeeping/master lane is cooperative and HOST-owned. */
    csr_clear(mie, MIP_MTIP);
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  if (!group_member_timer_ready[current] &&
      !sched->host_service_forced) {
    spin_unlock(&encl_lock);
    group_scheduler_defer_timer_local("timer_not_ready");
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  control_action = group_control_requests[current];
  if (control_action == KEYSTONE_GROUP_CONTROL_PAUSE)
    current_state = GROUP_SCHED_PAUSED;
  else if (control_action == KEYSTONE_GROUP_CONTROL_CANCEL)
    current_state = GROUP_SCHED_EXITED;
  if (group && group_scheduler_active_matches_locked(sched, current)) {
    cfs_preempt = group_scheduler_account_tick_locked(group, sched, current);
    if (control_action || cfs_preempt)
      next = group_scheduler_pick_next_direct_locked(hartid, current,
                                                     group->group_id, 0);
  }
  if (next != ENCL_MAX && !control_action) {
    same_lane_fast_path = group_scheduler_same_lane_fast_eligible_locked(
        group, hartid, current, next);
    if (group->execution_mode == GROUP_MODE_3W_1HM &&
        !same_lane_fast_path) {
      sbi_printf("[SM][sched] timer peer switch rejected: fast-PMP invariant failed hart=%lu group=%lu current=%u next=%u\n",
                 hartid, (unsigned long)group->group_id, current, next);
      next = ENCL_MAX;
    }
  }
  /* Pause/cancel are host-visible control boundaries, never peer handoffs. */
  if (control_action)
    next = ENCL_MAX;
  if (!control_action && group) {
    service_host = group_scheduler_host_service_due_locked(
        group, sched, current, next);
  }
  spin_unlock(&encl_lock);

  if (service_host) {
    ret = group_service_host_interrupt(regs, current, IRQ_M_TIMER);
    if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS)
      return ret;
    group_scheduler_log_timer_retry_local(
        current, next, ret, "host_service");
    group_scheduler_refresh_current_slice_local(current);
    group_scheduler_rearm_timer_local("timer_host_service_denied");
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }

  if (next == ENCL_MAX) {
    if (control_action) {
      uintptr_t event = control_action == KEYSTONE_GROUP_CONTROL_CANCEL ?
          KEYSTONE_GROUP_EVENT_CANCELLED : KEYSTONE_GROUP_EVENT_PAUSED;
      uintptr_t error = control_action == KEYSTONE_GROUP_CONTROL_CANCEL ?
          SBI_ERR_SM_GROUP_OCALL_CANCELLED : SBI_ERR_SM_GROUP_PAUSED;

      spin_lock(&encl_lock);
      if (ENCLAVE_EXISTS(current) &&
          group_control_requests[current] == control_action &&
          !group_scheduler_transition_locked(current, current_state,
                                             "timer_host_control")) {
        struct enabled_group_slot* current_group =
            find_group_locked(enclaves[current].group_id);
        group_control_requests[current] = 0;
        enclaves[current].n_thread = 0;
        if (control_action == KEYSTONE_GROUP_CONTROL_CANCEL) {
          group_ocall_clear_locked(current, 0);
          yxstm_protocol_member_gone_locked(current_group, current,
                                            YXSTM_ROLLBACK_WORKER_GONE);
          group_release_yxstm_owner_metadata_locked(current);
          enclaves[current].state = FAULTED;
        } else {
          enclaves[current].state = STOPPED;
        }
      }
      spin_unlock(&encl_lock);
      context_switch_to_host(regs, current, 1, 1);
      group_record_host_event(current, event, error, 0);
      /* Host-facing SBI error must remain in the standard negative range. */
      regs->a0 = SBI_EALREADY;
      regs->a1 = error;
      return SBI_ERR_SM_ENCLAVE_SUCCESS;
    }
    ret = group_scheduler_timer_tick(current);
    if (cfs_preempt) {
      spin_lock(&encl_lock);
      group = ENCLAVE_EXISTS(current) ?
          find_group_locked(enclaves[current].group_id) : 0;
      group_scheduler_refresh_slice_locked(group, current);
      spin_unlock(&encl_lock);
    }
    group_scheduler_rearm_timer_local("timer_no_peer");
    return ret;
  }

  perf_cycle_start = csr_read(CSR_MCYCLE);
  perf_time_start = sbi_timer_value();

  component_start = csr_read(CSR_MCYCLE);
  ret = group_scheduler_suspend_yxstm_grant_local(
      current, "timer_switch", same_lane_fast_path);
  pmp_cycles += csr_read(CSR_MCYCLE) - component_start;
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    group_scheduler_log_timer_retry_local(
        current, next, ret, "grant_suspend");
    group_scheduler_refresh_current_slice_local(current);
    group_scheduler_rearm_timer_local("timer_grant_suspend_denied");
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  thread_state_save_exact_profiled(
      &enclaves[current].threads[0], regs, &save_profile);
  /*
   * An asynchronous timer saves the exact interrupted PC. If a later
   * host-service return selects this member, context_switch_to_enclave() must
   * neutralize group_run_hart's unconditional SBI +4 exactly once.
   */
  group_member_saved_mepc_advanced[current] = 1;
  component_start = csr_read(CSR_MCYCLE);
  group_scheduler_schedule_out_local(
      current, "timer_switch", same_lane_fast_path ? 2 : 1);
  pmp_cycles += csr_read(CSR_MCYCLE) - component_start;
  component_start = csr_read(CSR_MCYCLE);
  platform_switch_from_enclave(&enclaves[current]);
  platform_cycles += csr_read(CSR_MCYCLE) - component_start;

  component_start = csr_read(CSR_MCYCLE);
  ret = group_scheduler_switch_active_local(
      current, &next, current_state, 1, &next_first_run);
  scheduler_lock_cycles += csr_read(CSR_MCYCLE) - component_start;
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    group_scheduler_schedule_in_local(current, same_lane_fast_path ? 2 : 1);
    platform_switch_to_enclave(&enclaves[current]);
    group_scheduler_restore_thread_context_exact(
        &enclaves[current].threads[0], regs);
    group_member_saved_mepc_advanced[current] = 0;
    group_scheduler_log_timer_retry_local(
        current, next, ret, "switch_active");
    group_scheduler_refresh_current_slice_local(current);
    group_scheduler_rearm_timer_local("timer_switch_active_rollback");
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  component_start = csr_read(CSR_MCYCLE);
  ret = group_scheduler_schedule_in_local(
      next, same_lane_fast_path ? 2 : 1);
  pmp_cycles += csr_read(CSR_MCYCLE) - component_start;
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    enclave_id rollback = current;
    (void)group_scheduler_switch_active_local(
        next, &rollback, GROUP_SCHED_RUNNABLE, 0, 0);
    if (next_first_run)
      group_scheduler_restore_fresh_state(next);
    group_scheduler_schedule_in_local(current, same_lane_fast_path ? 2 : 1);
    platform_switch_to_enclave(&enclaves[current]);
    group_scheduler_restore_thread_context_exact(
        &enclaves[current].threads[0], regs);
    group_member_saved_mepc_advanced[current] = 0;
    group_scheduler_log_timer_retry_local(
        current, next, ret, "schedule_in");
    group_scheduler_refresh_current_slice_local(current);
    group_scheduler_rearm_timer_local("timer_schedule_in_rollback");
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }

  if (control_action) {
    spin_lock(&encl_lock);
    if (ENCLAVE_EXISTS(current) &&
        group_control_requests[current] == control_action) {
      struct enabled_group_slot* current_group =
          find_group_locked(enclaves[current].group_id);
      group_control_requests[current] = 0;
      enclaves[current].n_thread = 0;
      if (control_action == KEYSTONE_GROUP_CONTROL_CANCEL) {
        group_ocall_clear_locked(current, 0);
        yxstm_protocol_member_gone_locked(current_group, current,
                                          YXSTM_ROLLBACK_WORKER_GONE);
        group_release_yxstm_owner_metadata_locked(current);
        enclaves[current].state = FAULTED;
      } else {
        enclaves[current].state = STOPPED;
      }
    }
    spin_unlock(&encl_lock);
    group_queue_host_event(
        current,
        control_action == KEYSTONE_GROUP_CONTROL_CANCEL ?
            KEYSTONE_GROUP_EVENT_CANCELLED : KEYSTONE_GROUP_EVENT_PAUSED,
        control_action == KEYSTONE_GROUP_CONTROL_CANCEL ?
            SBI_ERR_SM_GROUP_OCALL_CANCELLED : SBI_ERR_SM_GROUP_PAUSED,
        0);
  }

  component_start = csr_read(CSR_MCYCLE);
  platform_switch_to_enclave(&enclaves[next]);
  platform_cycles += csr_read(CSR_MCYCLE) - component_start;
  if (next_first_run) {
    group_scheduler_restore_thread_context_profiled(
        &enclaves[next].threads[0], regs, &restore_profile);
    component_start = csr_read(CSR_MCYCLE);
    group_scheduler_prepare_first_run_regs(next, regs);
    restore_profile.smode_csr_cycles +=
        csr_read(CSR_MCYCLE) - component_start;
    group_member_saved_mepc_advanced[next] = 0;
  } else {
    group_scheduler_restore_thread_context_profiled(
        &enclaves[next].threads[0], regs, &restore_profile);
    group_scheduler_adjust_resume_pc(regs, next, 0);
  }
  cpu_enter_enclave_context(next);
  group_perf_add_context_components(
      &save_profile, &restore_profile, pmp_cycles,
      platform_cycles, scheduler_lock_cycles);
  group_perf_record_context_switch(perf_cycle_start, perf_time_start);
  if (hartid < MAX_HARTS)
    group_perf_harts[hartid].cfs_preempt_count++;
#if KEYSTONE_GROUP_TIMER_TRACE
  if (hartid < MAX_HARTS) {
    uint64_t count = ++group_timer_switch_log_count[hartid];
    if (count <= 8 || (count & 0xff) == 0) {
      sbi_printf("[SM][sched] timer switch: hart=%lu group=%lu current=%u next=%u first=%d mepc=0x%lx count=%lu\n",
                 hartid,
                 (unsigned long)enclaves[next].group_id,
                 current,
                 next,
                 next_first_run,
                 (unsigned long)regs->mepc,
                 (unsigned long)count);
    }
  }
#endif

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long group_scheduler_ipi_switch(struct sbi_trap_regs* regs,
                                         enclave_id current)
{
  /*
   * Group software interrupts are scheduler-owned. Treat them as an immediate
   * reschedule request, not as a host-visible EnclaveInterrupted event.
   */
  return group_scheduler_timer_switch(regs, current);
}

int group_scheduler_ipi_reschedule_pending(enclave_id eid)
{
  struct sm_hart_sched* sched = 0;
  int pending = 0;

  spin_lock(&encl_lock);
  if (ENCLAVE_EXISTS(eid) && enclaves[eid].group_id &&
      enclaves[eid].hart_bound && enclaves[eid].assigned_hart < MAX_HARTS) {
    sched = &group_hart_schedulers[enclaves[eid].assigned_hart];
    pending = group_control_requests[eid] != 0 ||
              sched->host_service_forced ||
              sched->cfs_resched_pending;
  }
  spin_unlock(&encl_lock);
  return pending;
}

static int group_any_active_locked(void)
{
  int i;

  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    if (enabled_groups[i].valid && enabled_groups[i].active_hart_bitmap)
      return 1;
  }

  return 0;
}

static uint64_t group_configured_hart_total_locked(void)
{
  uint64_t total = 0;
  int i;

  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    if (enabled_groups[i].valid)
      total += enabled_groups[i].hart_count;
  }

  return total;
}

static int group_recompute_hart_masks_locked(void)
{
  uint64_t group_id;
  uint64_t offset = 0;

  if (group_configured_hart_total_locked() >
      KEYSTONE_GROUP_MAX_CONFIGURED_HARTS)
    return 0;

  for (group_id = 1; group_id <= configured_group_count; group_id++) {
    struct enabled_group_slot* group = find_group_locked(group_id);
    uint64_t hart_count;
    uint64_t hart_mask;

    if (!group || !group->hart_count)
      continue;

    hart_count = group->hart_count;
    hart_mask = group_hart_mask_from_offset(offset, hart_count);
    if (group_hart_mask_popcount(hart_mask) != (int)hart_count)
      return 0;
    group_configure_hart_slots_locked(group, hart_mask);
    if (group_topology_apply_default_locked(group))
      return 0;
    group_update_yxstm_slices_locked(group);
    offset += hart_count;
  }

  return 1;
}

static struct enabled_group_slot*
find_or_alloc_config_group_locked(uint64_t group_id)
{
  int i;
  struct enabled_group_slot* group;

  if (!group_id || group_id > configured_group_count ||
      group_id > KEYSTONE_MAX_ENABLED_GROUPS)
    return 0;

  group = find_group_locked(group_id);
  if (group)
    return group;

  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    if (!enabled_groups[i].valid) {
      group = &enabled_groups[i];
      sbi_memset(group, 0, sizeof(*group));
      group->valid = 1;
      group->group_id = group_id;
      group->generation = next_nonzero_generation(&group_generation_counter);
      group->lifecycle_state = KEYSTONE_GROUP_STATE_CONFIGURING;
      group->execution_mode = GROUP_MODE_INVALID;
      group->lease_state = KEYSTONE_GROUP_LEASE_FREE;
      group->topology_epoch = 1;
      group->lease_epoch = 1;
      group->yxstm_task_epoch = 1;
      group->yxstm_bank_count = KEYSTONE_YXSTM_DEFAULT_BANK_COUNT;
      group->epm_region = -1;
      group->yxstm_region = -1;
      group->next_region_id = 1;
      group->security_policy_version =
          KEYSTONE_GROUP_SECURITY_POLICY_VERSION;
      group->membership_epoch = 1;
      group_task_banks_init_locked(group);
      group_security_rekey_locked(group, YXSTM_ROLLBACK_NONE);
      (void)group_topology_apply_default_locked(group);
      sbi_printf("[SM][group] created: group=%lu generation=%lu state=%s\n",
                 (unsigned long)group_id,
                 (unsigned long)group->generation,
                 group_lifecycle_name(group->lifecycle_state));
      return group;
    }
  }

  return 0;
}

static void group_update_yxstm_slices_locked(struct enabled_group_slot* group)
{
  uint64_t hartid;
  size_t slice_size;

  if (!group || !group->yxstm_base || !group->yxstm_size ||
      !group->hart_count)
    return;

  slice_size = group->yxstm_bank_slice_size;
  if (!slice_size)
    return;

  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct group_hart_slot* slot = &group->hart_slots[hartid];
    struct group_worker_lane* lane;
    uint64_t slice_id;

    if (!slot->valid)
      continue;
    if (hartid == group->master_hart) {
      /* Master maps three 16 MiB lane backings; only 12 MB/lane is payload. */
      slot->yxstm_slice_base = group->yxstm_base;
      slot->yxstm_slice_size = group->yxstm_size;
      continue;
    } else {
      lane = group_lane_for_hart_locked(group, hartid);
      if (!lane)
        continue;
      slice_id = lane->slice_id;
    }
    slot->yxstm_slice_base = group_yxstm_worker_lane_base(group, slice_id - 1);
    slot->yxstm_slice_size = KEYSTONE_YXSTM_WORKER_LANE_SIZE;
  }
}

static unsigned long group_coherence_begin_locked(
    struct enabled_group_slot* group,
    uint64_t target_permission_epoch,
    uint64_t target_phase_epoch,
    unsigned long operation,
    struct group_coherence_snapshot* snapshot)
{
  if (!group || !snapshot)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (group->coherence_inflight)
    return SBI_ERR_SM_GROUP_COHERENCE_BUSY;
  if (target_permission_epoch < group->permission_epoch ||
      target_phase_epoch < group->yxstm_phase_epoch)
    return SBI_ERR_SM_YXSTM_STALE_EPOCH;

  sbi_memset(snapshot, 0, sizeof(*snapshot));
  snapshot->group_id = group->group_id;
  snapshot->group_generation = group->generation;
  snapshot->old_permission_epoch = group->permission_epoch;
  snapshot->old_phase_epoch = group->yxstm_phase_epoch;
  snapshot->target_permission_epoch = target_permission_epoch;
  snapshot->target_phase_epoch = target_phase_epoch;
  snapshot->target_hart_mask = group->active_hart_bitmap;
  snapshot->request.operation = operation;
  snapshot->request.group_id = group->group_id;
  snapshot->request.group_generation = group->generation;
  snapshot->request.permission_epoch = target_permission_epoch;
  snapshot->request.phase_epoch = target_phase_epoch;
  snapshot->request.epm_rid = group->epm_region;
  snapshot->request.yxstm_rid = group->yxstm_region;

  group->coherence_inflight = 1;
  group->coherence_target_permission_epoch = target_permission_epoch;
  group->coherence_target_phase_epoch = target_phase_epoch;
  group->coherence_target_hart_mask = snapshot->target_hart_mask;
  group->coherence_acked_hart_mask = 0;
  asm volatile("fence rw,rw" ::: "memory");
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long group_coherence_execute_unlocked(
    struct group_coherence_snapshot* snapshot,
    uint64_t* acked_mask,
    uint64_t* offline_mask)
{
  int ret;
  ulong acked = 0;
  ulong offline = 0;
  unsigned long perf_start = csr_read(CSR_MCYCLE);

  ret = group_coherence_ipi_sync((ulong)snapshot->target_hart_mask,
                                 &snapshot->request,
                                 KEYSTONE_GROUP_COHERENCE_TIMEOUT_CYCLES,
                                 &acked, &offline);
  atomic_add_return(&group_perf_ipi_count, 1);
  atomic_add_return(&group_perf_ipi_cycles,
                    (long)(csr_read(CSR_MCYCLE) - perf_start));
  if (acked_mask)
    *acked_mask = acked;
  if (offline_mask)
    *offline_mask = offline;
  if (ret == SBI_ETIMEDOUT)
    return SBI_ERR_SM_GROUP_COHERENCE_TIMEOUT;
  if (ret)
    return SBI_ERR_SM_GROUP_COHERENCE_BUSY;
  if (offline)
    return SBI_ERR_SM_GROUP_COHERENCE_OFFLINE;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long group_coherence_finish_locked(
    struct enabled_group_slot* group,
    const struct group_coherence_snapshot* snapshot,
    uint64_t acked_mask,
    uint64_t offline_mask,
    unsigned long sync_ret,
    const char* reason)
{
  unsigned long hartid;

  if (!group || !snapshot || !group->coherence_inflight ||
      group->group_id != snapshot->group_id ||
      group->generation != snapshot->group_generation ||
      group->permission_epoch != snapshot->old_permission_epoch ||
      group->yxstm_phase_epoch != snapshot->old_phase_epoch) {
    if (group)
      group->coherence_inflight = 0;
    return SBI_ERR_SM_GROUP_STALE_GENERATION;
  }

  group->coherence_sequence = snapshot->request.sequence;
  group->coherence_acked_hart_mask = acked_mask;
  if (sync_ret || offline_mask ||
      (acked_mask & snapshot->target_hart_mask) !=
          snapshot->target_hart_mask) {
    group->coherence_inflight = 0;
    sbi_printf("[SM][group] coherence failed: reason=%s group=%lu seq=%lu target=0x%lx acked=0x%lx offline=0x%lx ret=%lu\n",
               reason, (unsigned long)group->group_id,
               (unsigned long)snapshot->request.sequence,
               (unsigned long)snapshot->target_hart_mask,
               (unsigned long)acked_mask,
               (unsigned long)offline_mask, sync_ret);
    return sync_ret ? sync_ret : SBI_ERR_SM_GROUP_COHERENCE_OFFLINE;
  }

  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    uint64_t bit = group_hart_bit(hartid);
    struct group_active_hart_state* state = &group_active_harts[hartid];
    struct group_hart_slot* slot = &group->hart_slots[hartid];

    if (!(snapshot->target_hart_mask & bit))
      continue;
    if (state->active && state->active_group_id == group->group_id &&
        state->group_generation == group->generation) {
      state->active_epoch = snapshot->target_permission_epoch;
      state->active_phase_epoch = snapshot->target_phase_epoch;
      state->pmp_installed = 1;
    }
    if (slot->valid) {
      slot->yxstm_owner_eid = ENCL_MAX;
      slot->yxstm_acquired = 0;
      slot->yxstm_acquired_slice_mask = 0;
      slot->yxstm_permissions = 0;
      slot->yxstm_phase = YXSTM_PHASE_IDLE;
      slot->yxstm_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
      slot->yxstm_slot_lane = KEYSTONE_GROUP_UNBOUND_LANE;
      slot->yxstm_slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
      slot->yxstm_slot_epoch = 0;
      slot->active_epoch = snapshot->target_permission_epoch;
      slot->pmp_epoch = snapshot->target_permission_epoch;
      slot->phase_epoch = snapshot->target_phase_epoch;
    }
  }
  group->coherence_sync_count++;
  group->coherence_inflight = 0;
  asm volatile("fence rw,rw" ::: "memory");
  if (!group->yxstm_perf_quiet)
    sbi_printf("[SM][group] coherence complete: reason=%s group=%lu seq=%lu target=0x%lx acked=0x%lx perm_epoch=%lu phase_epoch=%lu sync=%lu\n",
               reason, (unsigned long)group->group_id,
               (unsigned long)snapshot->request.sequence,
               (unsigned long)snapshot->target_hart_mask,
               (unsigned long)acked_mask,
               (unsigned long)snapshot->target_permission_epoch,
               (unsigned long)snapshot->target_phase_epoch,
               (unsigned long)group->coherence_sync_count);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static void group_permission_epoch_advance_locked(
    struct enabled_group_slot* group,
    const char* reason)
{
  int i;

  if (!group)
    return;

  group->permission_epoch++;
  for (i = 0; i < MAX_HARTS; i++) {
    if (group_active_harts[i].active &&
        group_active_harts[i].active_group_id == group->group_id)
      group_active_harts[i].active_epoch = group->permission_epoch;
  }
  (void)reason;
}

static int group_active_hart_state_matches_locked(
    struct enabled_group_slot* group,
    unsigned long hartid)
{
  struct group_active_hart_state* state;

  if (hartid >= MAX_HARTS)
    return 0;

  state = &group_active_harts[hartid];
  return state->active &&
         state->active_group_id == group->group_id &&
         state->group_generation == group->generation &&
         state->eid < ENCL_MAX &&
         ENCLAVE_EXISTS(state->eid) &&
         state->eid_generation == enclaves[state->eid].generation &&
         enclaves[state->eid].group_id == group->group_id &&
         state->active_epoch == group->permission_epoch &&
         state->active_phase_epoch == group->yxstm_phase_epoch;
}

static int group_epoch_can_change_locked(struct enabled_group_slot* group,
                                         const char* where)
{
  if (!group)
    return 0;

  if (group->active_hart_bitmap) {
    struct group_coherence_snapshot snapshot;
    uint64_t acked = 0;
    uint64_t offline = 0;
    unsigned long ret;

    ret = group_coherence_begin_locked(group, group->permission_epoch + 1,
                                       group->yxstm_phase_epoch,
                                       SBI_GROUP_IPI_REFRESH_PMP, &snapshot);
    if (ret)
      return 0;
    ret = group_coherence_execute_unlocked(&snapshot, &acked, &offline);
    ret = group_coherence_finish_locked(group, &snapshot, acked, offline,
                                        ret, where);
    if (ret)
      return 0;
  }

  return 1;
}

static void group_scheduler_install_enclave_pmp_local(enclave_id eid)
{
  int memid;

  pmp_clear_dynamic_slots();
  osm_pmp_set(PMP_NO_PERM);
  for (memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if (enclaves[eid].regions[memid].type == REGION_INVALID)
      continue;
    if (enclaves[eid].regions[memid].pmp_rid < 0)
      continue;

    if (enclaves[eid].regions[memid].type == REGION_GROUP_SHARED) {
      /*
       * OFF is not a deny: the later OS catch-all PMP entry would match.
       * Keep an address-matching, permission-free entry for YXSTM until an
       * explicit acquire installs R/W permissions.
       */
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
      continue;
    }

    pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
  }

  /*
   * shared_utm still shares the OS PMP aperture in the current prototype.
   * Keep this behavior here so all group schedule-in paths use one PMP model.
   */
  if (enclaves[eid].params.shared_utm_size > 0)
    osm_pmp_set(PMP_ALL_PERM);
}

static int group_scheduler_verify_enclave_pmp_local(enclave_id eid)
{
  int memid;

  for (memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    struct enclave_region* region = &enclaves[eid].regions[memid];
    uint8_t expected;

    if (region->type == REGION_INVALID || region->type == REGION_UTM ||
        region->pmp_rid < 0)
      continue;
    expected = region->type == REGION_GROUP_SHARED ?
        PMP_NO_PERM : PMP_ALL_PERM;
    if (!pmp_region_readback_matches(region->pmp_rid, expected)) {
      sbi_printf("[SM][pmp] schedule-in readback mismatch: hart=%lu eid=%u memid=%d type=%d rid=%d reg=%d expected=0x%x\n",
                 (unsigned long)csr_read(mhartid), eid, memid,
                 region->type, region->pmp_rid,
                 pmp_region_get_reg_idx(region->pmp_rid),
                 (unsigned int)expected);
      pmp_debug_dump_hart("schedule_in_mismatch");
      return 0;
    }
  }
  return 1;
}

static void group_scheduler_clear_enclave_pmp_local(enclave_id eid)
{
  int memid;

  /*
   * First remove the active enclave apertures, then reinstall explicit deny
   * entries ahead of the OS catch-all PMP slot. Leaving a slot OFF would let
   * the later OS entry grant S-mode access to EPM/YXSTM.
   */
  asm volatile("fence rw,rw" ::: "memory");
  pmp_clear_dynamic_slots();
  for (memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    struct enclave_region* region = &enclaves[eid].regions[memid];

    if (region->type == REGION_INVALID || region->type == REGION_UTM ||
        region->pmp_rid < 0)
      continue;
    pmp_set_keystone(region->pmp_rid, PMP_NO_PERM);
  }
}

static int group_scheduler_verify_host_denies_local(enclave_id eid,
                                                     const char* where)
{
  int memid;

  for (memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    struct enclave_region* region = &enclaves[eid].regions[memid];

    if (region->type == REGION_INVALID || region->type == REGION_UTM ||
        region->pmp_rid < 0)
      continue;
    if (!pmp_region_readback_matches(region->pmp_rid, PMP_NO_PERM)) {
      sbi_printf("[SM][pmp] host-deny readback mismatch: hart=%lu eid=%u where=%s memid=%d type=%d rid=%d reg=%d\n",
                 (unsigned long)csr_read(mhartid), eid, where, memid,
                 region->type, region->pmp_rid,
                 pmp_region_get_reg_idx(region->pmp_rid));
      pmp_debug_dump_hart("host_deny_mismatch");
      return 0;
    }
  }
  return 1;
}

static void group_scheduler_revoke_yxstm_locked(
    struct enabled_group_slot* group,
    unsigned long hartid,
    enclave_id eid,
    const char* where,
    int hardware_already_revoked)
{
  struct group_hart_slot* slot;
  struct group_member_descriptor* member;
  int suspended;

  if (!group || hartid >= MAX_HARTS)
    return;

  slot = &group->hart_slots[hartid];
  if (!slot->valid)
    return;
  member = group_member_find_locked(group, eid);
  suspended = member && member->yxstm_suspended_acquired;

  if (slot->yxstm_acquired &&
      slot->yxstm_owner_eid == eid &&
      group->yxstm_region >= 0) {
    if (!hardware_already_revoked) {
      asm volatile("fence rw,rw" ::: "memory");
      pmp_set_keystone(group->yxstm_region, PMP_NO_PERM);
      asm volatile("sfence.vma" ::: "memory");
    }
    if (!suspended)
      sbi_printf("[SM][yxstm] auto-release: hart=%lu group=%lu eid=%u where=%s epoch=%lu\n",
                 hartid,
                 (unsigned long)group->group_id,
                 eid,
                 where,
                 (unsigned long)group->permission_epoch);
  }

  slot->yxstm_owner_eid = ENCL_MAX;
  slot->yxstm_acquired = 0;
  slot->yxstm_acquired_slice_mask = 0;
  slot->yxstm_permissions = 0;
  slot->yxstm_phase = YXSTM_PHASE_IDLE;
  slot->yxstm_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
  slot->yxstm_slot_lane = KEYSTONE_GROUP_UNBOUND_LANE;
  slot->yxstm_slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
  slot->yxstm_slot_epoch = 0;
}

static void group_release_yxstm_owner_metadata_locked(enclave_id eid)
{
  int i;
  unsigned long hartid;

  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    struct enabled_group_slot* group = &enabled_groups[i];
    struct group_member_descriptor* member;

    if (!group->valid)
      continue;

    member = group_member_find_locked(group, eid);
    if (member) {
      member->yxstm_suspended_acquired = 0;
      member->yxstm_suspended_slice_mask = 0;
      member->yxstm_suspended_permissions = 0;
      member->yxstm_suspended_phase = YXSTM_PHASE_IDLE;
      member->yxstm_suspended_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
      member->yxstm_suspended_phase_epoch = 0;
      member->yxstm_suspended_permission_epoch = 0;
      member->yxstm_suspended_task_epoch = 0;
      member->yxstm_suspended_slot_lane = KEYSTONE_GROUP_UNBOUND_LANE;
      member->yxstm_suspended_slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
      member->yxstm_suspended_slot_epoch = 0;
      member->yxstm_suspended_save_cycles = 0;
    }

    for (hartid = 0; hartid < MAX_HARTS; hartid++) {
      struct group_hart_slot* slot = &group->hart_slots[hartid];

      if (!slot->valid || !slot->yxstm_acquired ||
          slot->yxstm_owner_eid != eid)
        continue;

      if (group_active_harts[hartid].active &&
          group_active_harts[hartid].eid == eid) {
        group_scheduler_revoke_yxstm_locked(group, hartid, eid,
                                            "owner_metadata_release", 0);
        continue;
      }

      slot->yxstm_owner_eid = ENCL_MAX;
      slot->yxstm_acquired = 0;
      slot->yxstm_acquired_slice_mask = 0;
      slot->yxstm_permissions = 0;
      slot->yxstm_phase = YXSTM_PHASE_IDLE;
      slot->yxstm_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
      slot->yxstm_slot_lane = KEYSTONE_GROUP_UNBOUND_LANE;
      slot->yxstm_slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
      slot->yxstm_slot_epoch = 0;
      slot->pmp_epoch = group->permission_epoch;
      slot->phase_epoch = group->yxstm_phase_epoch;
    }
  }

  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct sm_hart_sched* sched = &group_hart_schedulers[hartid];
    if (sched->host_service_pending &&
        sched->host_service_eid == eid)
      group_scheduler_clear_host_service_locked(sched);
  }
}

static void group_active_hart_clear_locked(unsigned long hartid,
                                           const char* where)
{
  struct group_active_hart_state* state;
  struct enabled_group_slot* group;
  uint64_t bit;

  if (hartid >= MAX_HARTS)
    return;

  state = &group_active_harts[hartid];
  if (!state->active)
    return;

  if (csr_read(mhartid) == hartid) {
    group_scheduler_clear_enclave_pmp_local(state->eid);
    asm volatile("sfence.vma" ::: "memory");
    if (!group_scheduler_verify_host_denies_local(
            state->eid, "active_hart_clear"))
      sbi_printf("[SM][pmp] active-hart clear failed to restore host denies: hart=%lu eid=%u\n",
                 hartid, state->eid);
  }

  bit = group_hart_bit(hartid);
  group = find_group_locked(state->active_group_id);
  if (group && bit) {
    group->active_hart_bitmap &= ~bit;
    group_scheduler_clear_active_locked(hartid, state->eid);
    if (hartid < MAX_HARTS && group->hart_slots[hartid].valid) {
      group_scheduler_revoke_yxstm_locked(group, hartid, state->eid,
                                          where, 0);
      group->hart_slots[hartid].active_eid = ENCL_MAX;
      group->hart_slots[hartid].active_epoch = group->permission_epoch;
      group->hart_slots[hartid].pmp_epoch = group->permission_epoch;
      group->hart_slots[hartid].phase_epoch = group->yxstm_phase_epoch;
      asm volatile("sfence.vma" ::: "memory");
    }
  }

  sbi_memset(state, 0, sizeof(*state));

  if (group && !group_context_validate_locked(group, where))
    sbi_printf("[SM][group] active hart clear left invalid group context: group=%lu hart=%lu\n",
               (unsigned long)group->group_id,
               hartid);
}

static void group_active_hart_clear_eid_locked(enclave_id eid)
{
  unsigned long hartid;

  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    if (group_active_harts[hartid].active &&
        group_active_harts[hartid].eid == eid)
      group_active_hart_clear_locked(hartid, "clear_eid");
  }
}

/* encl_lock must be held for the complete select-and-commit transaction. */
static unsigned long group_active_hart_enter_locked(enclave_id eid,
                                                    unsigned long hartid)
{
  struct group_active_hart_state* state;
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  uint64_t bit;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (eid >= ENCL_MAX || enclaves[eid].group_id == 0)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (hartid >= MAX_HARTS || !group_hart_bit(hartid)) {
    sbi_printf("[SM][group] reject active hart enter: hart=%lu out of range, eid=%u group=%lu\n",
               hartid, eid, (unsigned long)enclaves[eid].group_id);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  state = &group_active_harts[hartid];
  if (state->active) {
    sbi_printf("[SM][group] reject active hart enter: hart=%lu already active eid=%u group=%lu epoch=%lu, new_eid=%u group=%lu\n",
               hartid,
               state->eid,
               (unsigned long)state->active_group_id,
               (unsigned long)state->active_epoch,
               eid,
               (unsigned long)enclaves[eid].group_id);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    return ret;
  }

  for (unsigned long i = 0; i < MAX_HARTS; i++) {
    if (group_active_harts[i].active &&
        group_active_harts[i].eid == eid) {
      sbi_printf("[SM][group] reject active hart enter: eid=%u already active on hart=%lu, new_hart=%lu group=%lu\n",
                 eid,
                 i,
                 hartid,
                 (unsigned long)enclaves[eid].group_id);
      ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
      return ret;
    }
  }

  group = find_group_locked(enclaves[eid].group_id);
  if (!group || !group_context_validate_locked(group, "active_enter")) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    return ret;
  }
  if (group->lifecycle_state != KEYSTONE_GROUP_STATE_ACTIVE) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    return ret;
  }
  if (group->coherence_inflight) {
    ret = SBI_ERR_SM_GROUP_COHERENCE_BUSY;
    return ret;
  }

  if (!group_hart_allowed_locked(group, hartid)) {
    sbi_printf("[SM][group] reject active hart enter: hart=%lu not in group=%lu mask=0x%lx eid=%u\n",
               hartid,
               (unsigned long)group->group_id,
               (unsigned long)group->configured_hart_mask,
               eid);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    return ret;
  }

  if (enclaves[eid].hart_bound && enclaves[eid].assigned_hart != hartid) {
    sbi_printf("[SM][group] reject active hart enter: eid=%u bound_hart=%lu new_hart=%lu group=%lu\n",
               eid,
               (unsigned long)enclaves[eid].assigned_hart,
               hartid,
               (unsigned long)group->group_id);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    return ret;
  }

  member = group_member_find_locked(group, eid);
  if (!member || !member->valid) {
    sbi_printf("[SM][group] reject active hart enter: eid=%u is not a member of group=%lu\n",
               eid, (unsigned long)enclaves[eid].group_id);
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    return ret;
  }

  /*
   * Commit the member descriptor, enclave hart binding and runqueue entry as
   * one scheduler operation before marking the enclave active.  Calling only
   * group_member_update_binding_locked() leaves enclave.hart_bound clear, so
   * set_active's invariant check rejects the first ordinary run() of an
   * enclave that was not explicitly bound by the host.
   */
  if (group_scheduler_bind_locked(group, eid, hartid)) {
    sbi_printf("[SM][group] reject active hart enter: scheduler bind failed eid=%u hart=%lu group=%lu\n",
               eid, hartid, (unsigned long)group->group_id);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    return ret;
  }

  bit = group_hart_bit(hartid);
  if (group_scheduler_set_active_locked(group, hartid, eid)) {
    sbi_printf("[SM][sched] reject active hart enter: scheduler bind failed hart=%lu group=%lu eid=%u\n",
               hartid,
               (unsigned long)group->group_id,
               eid);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    return ret;
  }

  state->active = 1;
  state->eid = eid;
  state->eid_generation = enclaves[eid].generation;
  state->active_group_id = group->group_id;
  state->group_generation = group->generation;
  state->active_epoch = group->permission_epoch;
  state->active_phase_epoch = group->yxstm_phase_epoch;
  group->active_hart_bitmap |= bit;
  if (group->hart_slots[hartid].valid) {
    group->hart_slots[hartid].active_eid = eid;
    group->hart_slots[hartid].active_epoch = group->permission_epoch;
    group->hart_slots[hartid].pmp_epoch = group->permission_epoch;
    group->hart_slots[hartid].phase_epoch = group->yxstm_phase_epoch;
  }

  if (!group_context_validate_locked(group, "active_enter_commit")) {
    group->active_hart_bitmap &= ~bit;
    if (group->hart_slots[hartid].valid)
      group->hart_slots[hartid].active_eid = ENCL_MAX;
    group_scheduler_clear_active_locked(hartid, eid);
    sbi_memset(state, 0, sizeof(*state));
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  return ret;
}

static unsigned long group_active_hart_enter(enclave_id eid)
{
  unsigned long hartid = csr_read(mhartid);
  unsigned long ret;

  if (eid >= ENCL_MAX || enclaves[eid].group_id == 0)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  if (hartid >= MAX_HARTS || !group_hart_bit(hartid)) {
    sbi_printf("[SM][group] reject active hart enter: hart=%lu out of range, eid=%u group=%lu\n",
               hartid, eid, (unsigned long)enclaves[eid].group_id);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  spin_lock(&encl_lock);
  ret = group_active_hart_enter_locked(eid, hartid);
  spin_unlock(&encl_lock);
  return ret;
}

static void group_active_hart_exit(enclave_id eid)
{
  unsigned long hartid = csr_read(mhartid);

  if (eid >= ENCL_MAX || enclaves[eid].group_id == 0)
    return;

  spin_lock(&encl_lock);

  if (hartid < MAX_HARTS &&
      group_active_harts[hartid].active &&
      group_active_harts[hartid].eid == eid) {
    group_active_hart_clear_locked(hartid, "active_exit");
  } else {
    sbi_printf("[SM][group] active hart exit mismatch: hart=%lu eid=%u group=%lu\n",
               hartid, eid, (unsigned long)enclaves[eid].group_id);
  }

  spin_unlock(&encl_lock);
}

static void group_context_switch_fail_rollback(enclave_id eid,
                                               int load_parameters)
{
  if (eid >= ENCL_MAX)
    return;

  group_active_hart_exit(eid);

  spin_lock(&encl_lock);
  if (ENCLAVE_EXISTS(eid) && enclaves[eid].state == RUNNING) {
    if (enclaves[eid].n_thread > 0)
      enclaves[eid].n_thread--;
    if (enclaves[eid].n_thread == 0) {
      enclaves[eid].state = load_parameters ? FRESH : STOPPED;
      if (enclaves[eid].group_id != 0)
        (void)group_scheduler_transition_locked(
            eid, GROUP_SCHED_RUNNABLE, "context_switch_rollback");
    }
  }
  spin_unlock(&encl_lock);
}

#if KEYSTONE_GROUP_STARTUP_TRACE
static void group_active_hart_snapshot(uint64_t group_id,
                                       uint64_t* active_hart_bitmap,
                                       uint64_t* active_epoch)
{
  struct enabled_group_slot* group;

  if (active_hart_bitmap)
    *active_hart_bitmap = 0;
  if (active_epoch)
    *active_epoch = 0;
  if (!group_id)
    return;

  spin_lock(&encl_lock);
  group = find_group_locked(group_id);
  if (group) {
    if (active_hart_bitmap)
      *active_hart_bitmap = group->active_hart_bitmap;
    if (active_epoch)
      *active_epoch = group->permission_epoch;
  }
  spin_unlock(&encl_lock);
}
#endif

static int group_member_initial_view_cached(enclave_id eid)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  int cached = 0;

  if (eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
      enclaves[eid].group_id == 0)
    return 0;

  spin_lock(&encl_lock);
  group = find_group_locked(enclaves[eid].group_id);
  member = group ? group_member_find_locked(group, eid) : 0;
  if (member &&
      member->group_generation == group->generation &&
      member->eid_generation == enclaves[eid].generation &&
      member->page_table_trust_model ==
          KEYSTONE_GROUP_PT_TRUST_MEASURED_RUNTIME &&
      member->allowed_region_epoch == group->permission_epoch &&
      (!member->page_table_root ||
       (member->page_table_audit_epoch == member->allowed_region_epoch &&
        member->audited_page_table_pages)))
    cached = 1;
  spin_unlock(&encl_lock);
  return cached;
}

static unsigned long group_scheduler_schedule_in_local(enclave_id eid,
                                                         int timer_fast_path)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group = 0;
  struct group_member_descriptor* member = 0;
  struct group_active_hart_state* state = 0;
  struct group_hart_slot* slot = 0;
  struct sm_hart_sched* sched = 0;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
  uint64_t grant_restore_start = 0;
  uint64_t component_start;
  int pmp_installed = 0;
  int same_lane_fast_path = timer_fast_path == 2;
  int fast_pmp_committed = 0;

  if (eid >= ENCL_MAX)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (enclaves[eid].group_id != 0) {
    if (hartid >= MAX_HARTS)
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    component_start = csr_read(CSR_MCYCLE);
    spin_lock(&encl_lock);
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_LOCK_WAIT,
        csr_read(CSR_MCYCLE) - component_start);
    group = find_group_locked(enclaves[eid].group_id);
    sched = &group_hart_schedulers[hartid];
    if (group && sched->host_service_pending && sched->heartbeat_enabled &&
        sched->host_service_eid == eid &&
        sched->host_service_eid_generation == enclaves[eid].generation &&
        sched->host_service_group_generation == group->generation &&
        sched->heartbeat_state != KEYSTONE_GROUP_HEARTBEAT_STATE_VERIFIED) {
      spin_unlock(&encl_lock);
      return SBI_ERR_SM_GROUP_HEARTBEAT_SEQUENCE;
    }
    spin_unlock(&encl_lock);
  }

  if (enclaves[eid].group_id != 0 &&
      !group_member_initial_view_cached(eid)) {
    component_start = csr_read(CSR_MCYCLE);
    ret = group_member_validate_initial_view(eid);
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_VALIDATION,
        csr_read(CSR_MCYCLE) - component_start);
    if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
      sbi_printf("[SM][group] schedule-in page-table policy rejected: hart=%lu eid=%u group=%lu ret=%lu\n",
                 hartid,
                 eid,
                 (unsigned long)enclaves[eid].group_id,
                 ret);
      return ret;
    }
  }

  component_start = csr_read(CSR_MCYCLE);
  if (!same_lane_fast_path)
    group_scheduler_install_enclave_pmp_local(eid);
  group_perf_add_pmp_component(
      GROUP_PERF_PMP_EPM_INSTALL,
      csr_read(CSR_MCYCLE) - component_start);
  pmp_installed = 1;

  if (!timer_fast_path && enclaves[eid].group_id != 0) {
    int pmp_valid;

    component_start = csr_read(CSR_MCYCLE);
    pmp_valid = group_scheduler_verify_enclave_pmp_local(eid);
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_VALIDATION,
        csr_read(CSR_MCYCLE) - component_start);
    if (!pmp_valid) {
      group_scheduler_clear_enclave_pmp_local(eid);
      component_start = csr_read(CSR_MCYCLE);
      asm volatile("sfence.vma" ::: "memory");
      group_perf_add_pmp_component(
          GROUP_PERF_PMP_FENCE,
          csr_read(CSR_MCYCLE) - component_start);
      (void)group_scheduler_verify_host_denies_local(
          eid, "schedule_in_rollback");
      return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
    }
  }

  if (enclaves[eid].group_id == 0)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (hartid >= MAX_HARTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  component_start = csr_read(CSR_MCYCLE);
  spin_lock(&encl_lock);
  group_perf_add_pmp_component(
      GROUP_PERF_PMP_LOCK_WAIT,
      csr_read(CSR_MCYCLE) - component_start);

  group = find_group_locked(enclaves[eid].group_id);
  state = &group_active_harts[hartid];
  if (!group || !state->active || state->eid != eid ||
      state->eid_generation != enclaves[eid].generation ||
      state->active_group_id != enclaves[eid].group_id ||
      state->group_generation != group->generation) {
    sbi_printf("[SM][group] schedule-in coherence mismatch: hart=%lu eid=%u group=%lu\n",
               hartid, eid, (unsigned long)enclaves[eid].group_id);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out;
  }
  member = group_member_find_locked(group, eid);
  slot = &group->hart_slots[hartid];
  sched = &group_hart_schedulers[hartid];
  if (!member || !slot->valid) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out;
  }
  if (sched->host_service_pending &&
      (sched->host_service_eid != eid ||
       sched->host_service_eid_generation != enclaves[eid].generation ||
       sched->host_service_group_generation != group->generation)) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out;
  }

  state->pmp_installed = 1;
  state->active_epoch = group->permission_epoch;
  state->active_phase_epoch = group->yxstm_phase_epoch;
  if (slot->valid) {
    slot->active_eid = eid;
    slot->active_epoch = group->permission_epoch;
    slot->pmp_epoch = group->permission_epoch;
    slot->phase_epoch = group->yxstm_phase_epoch;
    if (!timer_fast_path && group->yxstm_region >= 0)
      pmp_set_keystone(group->yxstm_region, PMP_NO_PERM);
  }
  if (member->yxstm_suspended_acquired) {
    uint64_t grant_restore_cycles;
    uint64_t grant_suspend_cycles = member->yxstm_suspended_save_cycles;
    uint64_t grant_validation_cycles;
    uint64_t grant_fence_cycles;
    uint64_t grant_restore_core_cycles;
    int slot_grant = member->yxstm_suspended_bank_id ==
        GROUP_YXSTM_SLOT_GRANT_BANK;
    int task_bank_grant = !slot_grant &&
        member->yxstm_suspended_bank_id != KEYSTONE_YXSTM_INVALID_BANK;
    struct group_task_bank_protocol* suspended_bank = 0;
    struct group_member_descriptor* suspended_slot_owner = 0;
    struct group_worker_lane* suspended_lane =
        member->role == GROUP_ROLE_WORKER ?
        group_lane_for_id_locked(group, member->lane_id) : 0;

    grant_restore_start = csr_read(CSR_MCYCLE);
    if (task_bank_grant &&
        member->yxstm_suspended_bank_id < group->yxstm_bank_count)
      suspended_bank =
          &group->task_banks[member->yxstm_suspended_bank_id];
    if (slot_grant)
      suspended_slot_owner = group_yxstm_slot_member_locked(
          group, member->yxstm_suspended_slot_lane,
          member->yxstm_suspended_slot_id);
    if (member->group_generation != group->generation ||
        member->group_id != group->group_id ||
        member->eid != eid ||
        member->eid_generation != enclaves[eid].generation ||
        member->bound_hart != hartid ||
        (task_bank_grant && !suspended_bank) ||
        (slot_grant &&
         (!suspended_slot_owner || suspended_slot_owner != member ||
          !member->yxstm_slot.valid ||
          member->yxstm_slot.state != YXSTM_SLOT_COMPUTING ||
          member->yxstm_suspended_slot_epoch != member->yxstm_slot.epoch)) ||
        member->yxstm_suspended_phase !=
            (slot_grant ? YXSTM_SLOT_COMPUTING :
             (task_bank_grant ? suspended_bank->phase : group->yxstm_phase)) ||
        member->yxstm_suspended_phase_epoch !=
            (slot_grant ? member->yxstm_slot.epoch :
             (task_bank_grant ? suspended_bank->phase_epoch :
                                group->yxstm_phase_epoch)) ||
        member->yxstm_suspended_permission_epoch != group->permission_epoch ||
        member->yxstm_suspended_task_epoch !=
            (slot_grant ? member->yxstm_slot.epoch :
             (task_bank_grant ? suspended_bank->task_epoch :
                                group->yxstm_task_epoch)) ||
        (!slot_grant && !task_bank_grant &&
         member->task_epoch != group->yxstm_task_epoch) ||
        (!slot_grant && !task_bank_grant &&
         member->role == GROUP_ROLE_WORKER &&
         (!suspended_lane || suspended_lane->active_eid != eid ||
          suspended_lane->active_eid_generation != enclaves[eid].generation ||
          suspended_lane->task_epoch != group->yxstm_task_epoch)) ||
        ((slot_grant || task_bank_grant) &&
         member->role == GROUP_ROLE_WORKER &&
         (!suspended_lane || suspended_lane->active_eid != eid ||
          suspended_lane->active_eid_generation != enclaves[eid].generation)) ||
        !member->yxstm_suspended_slice_mask ||
        (member->yxstm_suspended_slice_mask &
         ~member->allowed_slice_mask) ||
        slot->yxstm_acquired || slot->yxstm_owner_eid != ENCL_MAX) {
      ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
      goto out;
    }
    component_start = csr_read(CSR_MCYCLE);
    ret = slot_grant ? SBI_ERR_SM_ENCLAVE_SUCCESS :
        yxstm_validate_member_access_locked(
            group, member, member->yxstm_suspended_slice_mask,
            member->yxstm_suspended_permissions,
            member->yxstm_suspended_phase);
    grant_validation_cycles = csr_read(CSR_MCYCLE) - component_start;
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_VALIDATION, grant_validation_cycles);
    if (ret)
      goto out;
    component_start = csr_read(CSR_MCYCLE);
    if (slot_grant) {
      unsigned int writable =
          (member->yxstm_suspended_permissions & KEYSTONE_YXSTM_PERM_W) ?
              1U : 0U;
      ret = same_lane_fast_path ?
          group_member_apply_same_lane_pmp_locked(
              member, member->yxstm_slot.pmp_grant[writable],
              member->yxstm_slot.pmp_entry_count, 1) :
          (pmp_apply_cached_entries(
               member->yxstm_slot.pmp_grant[writable],
               member->yxstm_slot.pmp_entry_count) ?
               SBI_ERR_SM_ENCLAVE_PMP_FAILURE :
               SBI_ERR_SM_ENCLAVE_SUCCESS);
      fast_pmp_committed = same_lane_fast_path &&
          ret == SBI_ERR_SM_ENCLAVE_SUCCESS;
    } else if (same_lane_fast_path) {
      size_t cached_count = 0;
      const struct keystone_pmp_cached_entry* cached =
          group_member_cached_yxstm_entries_locked(member, &cached_count);

      ret = group_member_apply_same_lane_pmp_locked(
          member, cached, cached_count, 1);
      fast_pmp_committed = ret == SBI_ERR_SM_ENCLAVE_SUCCESS;
    } else {
      ret = task_bank_grant ?
          yxstm_install_task_bank_pmp_locked(
              group, member, member->yxstm_suspended_bank_id,
              member->yxstm_suspended_slice_mask,
              member->yxstm_suspended_permissions) :
          yxstm_install_pmp_for_mask_locked(
              group, member, member->yxstm_suspended_slice_mask,
              member->yxstm_suspended_permissions);
    }
    if (ret)
      goto out;
    slot->yxstm_owner_eid = eid;
    slot->yxstm_acquired = 1;
    slot->yxstm_acquired_slice_mask =
        member->yxstm_suspended_slice_mask;
    slot->yxstm_permissions = member->yxstm_suspended_permissions;
    slot->yxstm_phase = member->yxstm_suspended_phase;
    slot->yxstm_bank_id = member->yxstm_suspended_bank_id;
    slot->yxstm_slot_lane = member->yxstm_suspended_slot_lane;
    slot->yxstm_slot_id = member->yxstm_suspended_slot_id;
    slot->yxstm_slot_epoch = member->yxstm_suspended_slot_epoch;
    slot->pmp_epoch = group->permission_epoch;
    slot->phase_epoch = slot_grant ? member->yxstm_slot.epoch :
        (task_bank_grant ? suspended_bank->phase_epoch :
                           group->yxstm_phase_epoch);
    member->yxstm_suspended_acquired = 0;
    member->yxstm_suspended_slice_mask = 0;
    member->yxstm_suspended_permissions = 0;
    member->yxstm_suspended_phase = YXSTM_PHASE_IDLE;
    member->yxstm_suspended_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
    member->yxstm_suspended_phase_epoch = 0;
    member->yxstm_suspended_permission_epoch = 0;
    member->yxstm_suspended_task_epoch = 0;
    member->yxstm_suspended_slot_lane = KEYSTONE_GROUP_UNBOUND_LANE;
    member->yxstm_suspended_slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
    member->yxstm_suspended_slot_epoch = 0;
    member->yxstm_suspended_save_cycles = 0;
    component_start = csr_read(CSR_MCYCLE);
    if (!same_lane_fast_path)
      asm volatile("fence rw,rw" ::: "memory");
    grant_fence_cycles = csr_read(CSR_MCYCLE) - component_start;
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_FENCE, grant_fence_cycles);
    grant_restore_cycles = csr_read(CSR_MCYCLE) - grant_restore_start;
    grant_restore_core_cycles =
        grant_restore_cycles >
            grant_validation_cycles + grant_fence_cycles ?
        grant_restore_cycles - grant_validation_cycles - grant_fence_cycles :
        0;
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_YXSTM_RESTORE, grant_restore_core_cycles);
    atomic_add_return(&group_perf_grant_suspend_restore_count, 1);
    atomic_add_return(
        &group_perf_grant_suspend_restore_cycles,
        (long)(grant_suspend_cycles + grant_restore_cycles));
    if (sched->host_service_pending &&
        sched->host_service_eid == eid &&
        sched->host_service_grant_suspended) {
      sched->host_service_grant_suspended = 0;
      sched->host_service_grant_cycles = 0;
    }
  }
  if (same_lane_fast_path && !fast_pmp_committed) {
    size_t cached_count = 0;
    const struct keystone_pmp_cached_entry* cached =
        group_member_cached_yxstm_entries_locked(member, &cached_count);

    component_start = csr_read(CSR_MCYCLE);
    if (group_member_apply_same_lane_pmp_locked(
            member, cached, cached_count, 1) !=
        SBI_ERR_SM_ENCLAVE_SUCCESS) {
      ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
      goto out;
    }
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_YXSTM_RESTORE,
        csr_read(CSR_MCYCLE) - component_start);
    fast_pmp_committed = 1;
  }
  group_scheduler_set_state_locked(eid, GROUP_SCHED_RUNNING);
  group_scheduler_enable_smode_counters();
#if KEYSTONE_GROUP_TIMER_PREEMPT
  if ((member->role == GROUP_ROLE_WORKER ||
       group->execution_mode == GROUP_MODE_SATURATION_TEST) &&
      group_member_timer_ready[eid] &&
      group_hart_run_status_ptr[hartid] &&
      group_hart_host_context_valid[hartid]) {
    /*
     * sbi_timer_process() leaves the old comparator expired with MTIE
     * disabled. event_start() must install the future deadline before it
     * enables MTIP, otherwise resume has an immediate re-entry window.
     */
    group_scheduler_rearm_timer_local("schedule_in");
  } else {
    csr_clear(mie, MIP_MTIP);
  }
#else
  csr_clear(mie, MIP_MTIP);
#endif
  /* Coherence IPIs are required even when timer preemption is disabled. */
  csr_set(mie, MIP_MSIP);
  component_start = csr_read(CSR_MCYCLE);
  asm volatile("sfence.vma" ::: "memory");
  group_perf_add_pmp_component(
      GROUP_PERF_PMP_FENCE,
      csr_read(CSR_MCYCLE) - component_start);
#if KEYSTONE_GROUP_STARTUP_TRACE
  if (!group_pmp_layout_dump_seen[hartid]) {
    group_pmp_layout_dump_seen[hartid] = 1;
    pmp_debug_dump_hart("first_group_schedule_in");
  }
#endif
#if KEYSTONE_PMP_DEBUG_DUMP
  pmp_debug_dump_hart("group_schedule_in");
#endif

  if (!timer_fast_path &&
      !group_context_validate_locked(group, "schedule_in"))
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS &&
      group_ocall_resume_start_cycle[eid]) {
    if (group_ocall_resume_generation[eid] == enclaves[eid].generation) {
      atomic_add_return(&group_perf_ocall_count, 1);
      atomic_add_return(
          &group_perf_ocall_cycles,
          (long)(csr_read(CSR_MCYCLE) -
                 group_ocall_resume_start_cycle[eid]));
    }
    group_ocall_resume_start_cycle[eid] = 0;
    group_ocall_resume_generation[eid] = 0;
  }
  if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS &&
      sched->host_service_pending &&
      sched->host_service_eid == eid) {
    uint64_t started = sched->host_service_start_cycle;
    atomic_add_return(&group_perf_host_service_count, 1);
    if (started)
      atomic_add_return(&group_perf_host_service_cycles,
                        (long)(csr_read(CSR_MCYCLE) - started));
    group_scheduler_clear_host_service_locked(sched);
  }

out:
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    if (group && slot && slot->valid && slot->yxstm_acquired &&
        slot->yxstm_owner_eid == eid)
      group_scheduler_revoke_yxstm_locked(
          group, hartid, eid, "schedule_in_error", 0);
    if (state)
      state->pmp_installed = 0;
    if (member) {
      member->yxstm_suspended_acquired = 0;
      member->yxstm_suspended_slice_mask = 0;
      member->yxstm_suspended_permissions = 0;
      member->yxstm_suspended_phase = YXSTM_PHASE_IDLE;
      member->yxstm_suspended_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
      member->yxstm_suspended_phase_epoch = 0;
      member->yxstm_suspended_permission_epoch = 0;
      member->yxstm_suspended_task_epoch = 0;
      member->yxstm_suspended_save_cycles = 0;
    }
    if (sched && sched->host_service_pending &&
        sched->host_service_eid == eid)
      group_scheduler_clear_host_service_locked(sched);
  }
  spin_unlock(&encl_lock);
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS && pmp_installed) {
    component_start = csr_read(CSR_MCYCLE);
    if (same_lane_fast_path && member && member->pmp_cache_valid)
      (void)group_member_apply_same_lane_pmp_locked(
          member, member->pmp_yxstm_deny,
          member->pmp_yxstm_deny_count, 0);
    else
      group_scheduler_clear_enclave_pmp_local(eid);
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_EPM_REVOKE,
        csr_read(CSR_MCYCLE) - component_start);
    component_start = csr_read(CSR_MCYCLE);
    asm volatile("sfence.vma" ::: "memory");
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_FENCE,
        csr_read(CSR_MCYCLE) - component_start);
    if (!same_lane_fast_path)
      (void)group_scheduler_verify_host_denies_local(
          eid, "schedule_in_error");
  }
  return ret;
}

static void group_scheduler_schedule_out_local(enclave_id eid,
                                                const char* where,
                                                int timer_fast_path)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group;
  struct group_active_hart_state* state;
  uint64_t component_start;
  int same_lane_fast_path = timer_fast_path == 2;

  if (eid >= ENCL_MAX)
    return;

  component_start = csr_read(CSR_MCYCLE);
  if (!same_lane_fast_path)
    group_scheduler_clear_enclave_pmp_local(eid);
  group_perf_add_pmp_component(
      GROUP_PERF_PMP_EPM_REVOKE,
      csr_read(CSR_MCYCLE) - component_start);
  if (!timer_fast_path) {
    component_start = csr_read(CSR_MCYCLE);
    asm volatile("sfence.vma" ::: "memory");
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_FENCE,
        csr_read(CSR_MCYCLE) - component_start);
  }
  if (!timer_fast_path) {
    int host_denies_valid;

    component_start = csr_read(CSR_MCYCLE);
    host_denies_valid = group_scheduler_verify_host_denies_local(eid, where);
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_VALIDATION,
        csr_read(CSR_MCYCLE) - component_start);
    if (!host_denies_valid) {
      sbi_printf("[SM][pmp] schedule-out failed to restore host denies: hart=%lu eid=%u where=%s\n",
                 hartid, eid, where);
      pmp_debug_dump_hart("schedule_out_mismatch");
    }
  }
#if KEYSTONE_PMP_DEBUG_DUMP
  pmp_debug_dump_hart("group_schedule_out");
#endif

  if (enclaves[eid].group_id == 0)
    return;
  if (hartid >= MAX_HARTS)
    return;

  component_start = csr_read(CSR_MCYCLE);
  spin_lock(&encl_lock);
  group_perf_add_pmp_component(
      GROUP_PERF_PMP_LOCK_WAIT,
      csr_read(CSR_MCYCLE) - component_start);

  group = find_group_locked(enclaves[eid].group_id);
  state = &group_active_harts[hartid];
  if (group && state->active && state->eid == eid &&
      state->eid_generation == enclaves[eid].generation &&
      state->active_group_id == enclaves[eid].group_id &&
      state->group_generation == group->generation) {
    group_scheduler_revoke_yxstm_locked(group, hartid, eid, where, 1);
    if (group->hart_slots[hartid].valid) {
      group->hart_slots[hartid].pmp_epoch = group->permission_epoch;
      group->hart_slots[hartid].active_epoch = group->permission_epoch;
      group->hart_slots[hartid].phase_epoch = group->yxstm_phase_epoch;
    }
    state->pmp_installed = 0;
    state->active_epoch = group->permission_epoch;
    state->active_phase_epoch = group->yxstm_phase_epoch;

    if (!timer_fast_path &&
        !group_context_validate_locked(group, "schedule_out"))
      sbi_printf("[SM][sched] schedule-out left invalid group context: hart=%lu eid=%u group=%lu where=%s\n",
                 hartid,
                 eid,
                 (unsigned long)group->group_id,
                 where);
  }

  spin_unlock(&encl_lock);
  if (!same_lane_fast_path) {
    component_start = csr_read(CSR_MCYCLE);
    asm volatile("sfence.vma" ::: "memory");
    group_perf_add_pmp_component(
        GROUP_PERF_PMP_FENCE,
        csr_read(CSR_MCYCLE) - component_start);
  }
}

static int group_context_validate_locked(struct enabled_group_slot* group,
                                         const char* where)
{
  int i;
  uint64_t expected_bitmap = 0;

  if (!group || !group->valid || !group->group_id) {
    sbi_printf("[SM][group] invalid group context at %s\n", where);
    return 0;
  }
  if (!group->generation ||
      group->lifecycle_state < KEYSTONE_GROUP_STATE_CONFIGURING ||
      group->lifecycle_state > KEYSTONE_GROUP_STATE_DRAINING) {
    sbi_printf("[SM][group] invalid lifecycle at %s: group=%lu generation=%lu state=%lu\n",
               where, (unsigned long)group->group_id,
               (unsigned long)group->generation,
               (unsigned long)group->lifecycle_state);
    return 0;
  }

  if (group->member_capacity == 0 ||
      group->member_capacity > KEYSTONE_GROUP_MAX_MEMBERS ||
      !group->members ||
      group->member_metadata_capacity != group->member_capacity ||
      !group->metadata_bytes ||
      group->member_count > group->member_capacity) {
    sbi_printf("[SM][group] invalid membership at %s: group=%lu count=%lu capacity=%lu\n",
               where,
               (unsigned long)group->group_id,
               (unsigned long)group->member_count,
               (unsigned long)group->member_capacity);
    return 0;
  }
  if (group->registered_member_count > group->member_count ||
      group->pending_create_count > group->member_count) {
    sbi_printf("[SM][group] invalid create counters at %s: group=%lu members=%lu registered=%lu pending=%lu\n",
               where, (unsigned long)group->group_id,
               (unsigned long)group->member_count,
               (unsigned long)group->registered_member_count,
               (unsigned long)group->pending_create_count);
    return 0;
  }
  {
    size_t valid_members = 0;
    size_t member_index;
    for (member_index = 0;
         member_index < group->member_metadata_capacity;
         member_index++)
      if (group->members[member_index].valid)
        valid_members++;
    if (valid_members != group->registered_member_count) {
      sbi_printf("[SM][group] member metadata mismatch at %s: group=%lu valid=%lu registered=%lu\n",
                 where, (unsigned long)group->group_id,
                 (unsigned long)valid_members,
                 (unsigned long)group->registered_member_count);
      return 0;
    }
  }

  if (group->hart_count == 0 ||
      group->hart_count > KEYSTONE_GROUP_MAX_CONFIGURED_HARTS ||
      group_hart_mask_popcount(group->configured_hart_mask) !=
        (int)group->hart_count ||
      (group->active_hart_bitmap & ~group->configured_hart_mask)) {
    sbi_printf("[SM][group] invalid hart config at %s: group=%lu hart_count=%lu mask=0x%lx active=0x%lx\n",
               where,
               (unsigned long)group->group_id,
               (unsigned long)group->hart_count,
               (unsigned long)group->configured_hart_mask,
               (unsigned long)group->active_hart_bitmap);
    return 0;
  }
  if (!group_topology_validate_locked(group) ||
      !group->topology_epoch ||
      group->lease_state > KEYSTONE_GROUP_LEASE_FAILED ||
      !group->lease_epoch) {
    sbi_printf("[SM][group] invalid topology at %s: group=%lu mode=%lu housekeeping=cpu%lu/hart%lu master=%lu workers=0x%lx count=%lu lease=%lu\n",
               where,
               (unsigned long)group->group_id,
               (unsigned long)group->execution_mode,
               (unsigned long)group->housekeeping_cpu,
               (unsigned long)group->housekeeping_hart,
               (unsigned long)group->master_hart,
               (unsigned long)group->worker_hart_mask,
               (unsigned long)group->worker_count,
               (unsigned long)group->lease_state);
    return 0;
  }
  {
    uint64_t lane_mask = 0;
    uint64_t lane_count = 0;

    for (i = 0; i < KEYSTONE_GROUP_MAX_WORKER_LANES; i++) {
      struct group_worker_lane* lane = &group->worker_lanes[i];
      size_t member_index;

      if (!lane->valid)
        continue;
      if (lane->lane_id != (uint64_t)i || lane->hart_id >= MAX_HARTS ||
          lane->slice_id != (uint64_t)i + 1 ||
          lane->slice_mask != (1UL << lane->slice_id) ||
          !(group->worker_hart_mask & group_hart_bit(lane->hart_id)) ||
          lane->runqueue_capacity != group->member_capacity ||
          lane->runqueue_len > lane->runqueue_capacity ||
          (lane->runqueue_len && !lane->runqueue) ||
          (lane->runqueue_len &&
           lane->current_index >= lane->runqueue_len) ||
          lane->state > GROUP_WORKER_LANE_DRAINING ||
          (group->lifecycle_state == KEYSTONE_GROUP_STATE_ACTIVE &&
           (!group->yxstm_slots_frozen || !lane->slots_frozen ||
            lane->yxstm_size != KEYSTONE_YXSTM_WORKER_LANE_SIZE ||
            lane->slot_count != lane->runqueue_len ||
            (lane->runqueue_len && !lane->slot_size) ||
            (!lane->runqueue_len && lane->slot_size) ||
            lane->slot_size * lane->slot_count + lane->reserved_size !=
                KEYSTONE_YXSTM_WORKER_LANE_SIZE))) {
        sbi_printf("[SM][group] invalid worker lane at %s: group=%lu lane=%d hart=%lu slice=%lu mask=0x%lx members=%lu state=%u\n",
                   where, (unsigned long)group->group_id, i,
                   (unsigned long)lane->hart_id,
                   (unsigned long)lane->slice_id,
                   (unsigned long)lane->slice_mask,
                   (unsigned long)lane->runqueue_len,
                   (unsigned int)lane->state);
        return 0;
      }
      for (member_index = 0;
           member_index < lane->runqueue_len;
           member_index++) {
        struct group_member_descriptor* lane_member =
            group_member_find_locked(
                group, lane->runqueue[member_index].eid);
        if (!lane_member || lane_member->role != GROUP_ROLE_WORKER ||
            lane_member->eid_generation !=
                lane->runqueue[member_index].eid_generation ||
            lane_member->lane_id != lane->lane_id ||
            lane_member->bound_hart != lane->hart_id ||
            lane_member->allowed_slice_mask != lane->slice_mask ||
            (group->lifecycle_state == KEYSTONE_GROUP_STATE_ACTIVE &&
             !group_yxstm_slot_metadata_valid(lane, lane_member)))
          return 0;
      }
      if (lane->active_eid != ENCL_MAX) {
        struct group_member_descriptor* active =
            group_member_find_locked(group, lane->active_eid);
        if (!active || active->role != GROUP_ROLE_WORKER ||
            active->eid_generation != lane->active_eid_generation ||
            active->lane_id != lane->lane_id ||
            lane->state != GROUP_WORKER_LANE_RUNNING)
          return 0;
      } else if (lane->state == GROUP_WORKER_LANE_RUNNING) {
        return 0;
      }
      lane_mask |= group_hart_bit(lane->hart_id);
      lane_count++;
    }
    if (lane_mask != group->worker_hart_mask ||
        lane_count != group->worker_count)
      return 0;
  }
  if (group->coherence_inflight &&
      ((group->coherence_target_hart_mask &
        ~group->configured_hart_mask) ||
       group->coherence_target_permission_epoch < group->permission_epoch ||
       group->coherence_target_phase_epoch < group->yxstm_phase_epoch)) {
    sbi_printf("[SM][group] invalid coherence transaction at %s: group=%lu target=0x%lx permission=%lu/%lu phase=%lu/%lu\n",
               where, (unsigned long)group->group_id,
               (unsigned long)group->coherence_target_hart_mask,
               (unsigned long)group->permission_epoch,
               (unsigned long)group->coherence_target_permission_epoch,
               (unsigned long)group->yxstm_phase_epoch,
               (unsigned long)group->coherence_target_phase_epoch);
    return 0;
  }

  if ((group->epm_region >= 0 || group->yxstm_region >= 0) &&
      (!group->pmp_budget_valid ||
       group->pmp_budget.hardware_entries != PMP_N_REG ||
       group->pmp_budget.total_entries > PMP_N_REG)) {
    sbi_printf("[SM][pmp] invalid group budget at %s: group=%lu valid=%d total=%u hardware=%u\n",
               where, (unsigned long)group->group_id,
               group->pmp_budget_valid,
               (unsigned int)group->pmp_budget.total_entries,
               (unsigned int)group->pmp_budget.hardware_entries);
    return 0;
  }

  if (group->epm_region >= 0) {
    if (!group->epm_base || !group->epm_size || !group->epm_refcount) {
      sbi_printf("[SM][group] invalid EPM context at %s: group=%lu rid=%d base=0x%lx size=0x%lx refs=%lu\n",
                 where,
                 (unsigned long)group->group_id,
                 group->epm_region,
                 (unsigned long)group->epm_base,
                 (unsigned long)group->epm_size,
                 (unsigned long)group->epm_refcount);
      return 0;
    }
    if (pmp_region_get_entry_count(group->epm_region) !=
          group->pmp_budget.epm_entries ||
        (pmp_region_get_reg_idx(group->epm_region) !=
           KEYSTONE_PMP_SLOT_GROUP_EPM_LO &&
         pmp_region_get_reg_idx(group->epm_region) !=
           KEYSTONE_PMP_SLOT_GROUP_EPM_HI)) {
      sbi_printf("[SM][pmp] invalid group EPM slot at %s: group=%lu rid=%d reg=%d entries=%d\n",
                 where, (unsigned long)group->group_id,
                 group->epm_region,
                 pmp_region_get_reg_idx(group->epm_region),
                 pmp_region_get_entry_count(group->epm_region));
      return 0;
    }
  } else if (group->epm_base || group->epm_size || group->epm_refcount) {
    sbi_printf("[SM][group] stale EPM context at %s: group=%lu\n",
               where, (unsigned long)group->group_id);
    return 0;
  }

  if (group->yxstm_region >= 0) {
    struct group_region_descriptor* region;

    if (!group->yxstm_base || !group->yxstm_size || !group->yxstm_refcount) {
      sbi_printf("[SM][group] invalid YXSTM context at %s: group=%lu rid=%d base=0x%lx size=0x%lx refs=%lu\n",
                 where,
                 (unsigned long)group->group_id,
                 group->yxstm_region,
                 (unsigned long)group->yxstm_base,
                 (unsigned long)group->yxstm_size,
                 (unsigned long)group->yxstm_refcount);
      return 0;
    }
    if (pmp_region_get_entry_count(group->yxstm_region) != 2 ||
        pmp_region_get_reg_idx(group->yxstm_region) !=
          KEYSTONE_PMP_SLOT_YXSTM) {
      sbi_printf("[SM][pmp] invalid YXSTM slot at %s: group=%lu rid=%d reg=%d entries=%d\n",
                 where, (unsigned long)group->group_id,
                 group->yxstm_region,
                 pmp_region_get_reg_idx(group->yxstm_region),
                 pmp_region_get_entry_count(group->yxstm_region));
      return 0;
    }

    region = 0;
    for (i = 0; i < KEYSTONE_GROUP_MAX_REGIONS; i++) {
      if (group->region_table[i].valid &&
          group->region_table[i].type == GROUP_REGION_SHARED &&
          group->region_table[i].paddr == group->yxstm_base &&
          group->region_table[i].size == group->yxstm_size) {
        region = &group->region_table[i];
        break;
      }
    }
    if (!region || region->owner_group != group->group_id) {
      sbi_printf("[SM][group] YXSTM missing shared-region descriptor at %s: group=%lu base=0x%lx size=0x%lx\n",
                 where,
                 (unsigned long)group->group_id,
                 (unsigned long)group->yxstm_base,
                 (unsigned long)group->yxstm_size);
      return 0;
    }
  } else if (group->yxstm_base || group->yxstm_size || group->yxstm_refcount) {
    sbi_printf("[SM][group] stale YXSTM context at %s: group=%lu\n",
               where, (unsigned long)group->group_id);
    return 0;
  }

  for (i = 0; i < KEYSTONE_GROUP_MAX_REGIONS; i++) {
    struct group_region_descriptor* region = &group->region_table[i];
    uintptr_t end;

    if (!region->valid)
      continue;

    if (!group_region_is_table_region(region->type) ||
        !region->region_id ||
        region->generation != group->generation ||
        !region->paddr ||
        !region->size ||
        region->owner_group != group->group_id ||
        !region->permissions ||
        CHECKED_ADD(region->paddr, region->size, &end)) {
      sbi_printf("[SM][group] invalid region descriptor at %s: group=%lu slot=%d type=%s id=%lu pa=0x%lx size=0x%lx owner=%lu perms=0x%lx\n",
                 where,
                 (unsigned long)group->group_id,
                 i,
                 group_region_type_name(region->type),
                 (unsigned long)region->region_id,
                 (unsigned long)region->paddr,
                 (unsigned long)region->size,
                 (unsigned long)region->owner_group,
                 (unsigned long)region->permissions);
      return 0;
    }
  }

  for (i = 0; i < MAX_HARTS; i++) {
    struct group_active_hart_state* state = &group_active_harts[i];
    uint64_t bit = group_hart_bit((unsigned long)i);

    if (!state->active) {
      if (group->active_hart_bitmap & bit) {
        sbi_printf("[SM][group] stale active hart bitmap at %s: group=%lu hart=%d bitmap=0x%lx\n",
                   where,
                   (unsigned long)group->group_id,
                   i,
                   (unsigned long)group->active_hart_bitmap);
        return 0;
      }
      continue;
    }

    if (state->active_group_id != group->group_id)
      continue;

    expected_bitmap |= bit;
    if (!group_active_hart_state_matches_locked(group, (unsigned long)i)) {
      sbi_printf("[SM][group] invalid active hart state at %s: group=%lu hart=%d eid=%u state_group=%lu state_epoch=%lu/%lu group_epoch=%lu/%lu\n",
                 where,
                 (unsigned long)group->group_id,
                 i,
                 state->eid,
                 (unsigned long)state->active_group_id,
                 (unsigned long)state->active_epoch,
                 (unsigned long)state->active_phase_epoch,
                 (unsigned long)group->permission_epoch,
                 (unsigned long)group->yxstm_phase_epoch);
      return 0;
    }
  }

  if (group->active_hart_bitmap != expected_bitmap) {
    sbi_printf("[SM][group] active hart bitmap mismatch at %s: group=%lu bitmap=0x%lx expected=0x%lx\n",
               where,
               (unsigned long)group->group_id,
               (unsigned long)group->active_hart_bitmap,
               (unsigned long)expected_bitmap);
    return 0;
  }

  return 1;
}

static struct enabled_group_slot* find_or_alloc_group_locked(uint64_t group_id,
                                                             uint64_t capacity)
{
  struct enabled_group_slot* group;

  if (!group_id || group_id > configured_group_count ||
      group_id > KEYSTONE_MAX_ENABLED_GROUPS)
    return 0;

  group = find_group_locked(group_id);

  if (group) {
    if (group->lifecycle_state != KEYSTONE_GROUP_STATE_CONFIGURING &&
        group->lifecycle_state != KEYSTONE_GROUP_STATE_READY) {
      sbi_printf("[SM][group] reject member reservation: group=%lu state=%s active_harts=0x%lx\n",
                 (unsigned long)group_id,
                 group_lifecycle_name(group->lifecycle_state),
                 (unsigned long)group->active_hart_bitmap);
      return 0;
    }
    if (group->member_capacity != 0 && group->member_capacity != capacity)
      return 0;
    if (group->member_capacity > KEYSTONE_GROUP_MAX_MEMBERS)
      return 0;
    if (capacity > KEYSTONE_GROUP_MAX_MEMBERS)
      return 0;
    if (!group->hart_count || !group->configured_hart_mask)
      return 0;
    if (!group->members && group_metadata_prepare_locked(group, capacity)) {
      sbi_printf("[SM][group] metadata preflight failed: group=%lu generation=%lu capacity=%lu free=%lu\n",
                 (unsigned long)group->group_id,
                 (unsigned long)group->generation,
                 (unsigned long)capacity,
                 (unsigned long)group_metadata_free_bytes_locked());
      return 0;
    }
    if (group->member_metadata_capacity != capacity)
      return 0;
    if (group->member_count >= group->member_capacity)
      return 0;
    group->member_count++;
    group->pending_create_count++;
    return group;
  }
  return 0;
}

static void maybe_clear_group_locked(struct enabled_group_slot* group)
{
  if (!group)
    return;
  if (group->member_count == 0 &&
      group->epm_refcount == 0 &&
      group->yxstm_refcount == 0 &&
      group->epm_region < 0 &&
      group->yxstm_region < 0 &&
      group->region_count == 0 &&
      group->active_hart_bitmap == 0 &&
      !group->coherence_inflight) {
    if (group->lifecycle_state == KEYSTONE_GROUP_STATE_DRAINING) {
      uint64_t group_id = group->group_id;
      uint64_t generation = group->generation;
      if (group_perf_window_group_id == group_id &&
          group_perf_window_group_generation == generation) {
        group_perf_window_state = KEYSTONE_GROUP_PERF_WINDOW_IDLE;
        group_perf_window_group_id = 0;
        group_perf_window_group_generation = 0;
        group_perf_window_start_ticks = 0;
        group_perf_window_stop_ticks = 0;
      }
      group_metadata_release_locked(group);
      sbi_memset(group, 0, sizeof(*group));
      sbi_printf("[SM][group] destroyed: group=%lu generation=%lu state=free\n",
                 (unsigned long)group_id, (unsigned long)generation);
      return;
    }
    group->member_capacity = 0;
    group->next_region_id = 1;
    group->permission_epoch++;
    group->coherence_sync_count = 0;
    group->coherence_sequence = 0;
    group->coherence_target_permission_epoch = 0;
    group->coherence_target_phase_epoch = 0;
    group->coherence_target_hart_mask = 0;
    group->coherence_acked_hart_mask = 0;
    group->pmp_budget_valid = 0;
    sbi_memset(&group->pmp_budget, 0, sizeof(group->pmp_budget));
    sbi_memset(group->region_table, 0, sizeof(group->region_table));
    if (group->members)
      sbi_memset(group->members, 0,
                 group->member_metadata_capacity *
                     sizeof(struct group_member_descriptor));
  }
}

static int group_epm_release(region_id rid)
{
  int i;
  int should_free = 0;

  spin_lock(&encl_lock);
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    struct enabled_group_slot* group = &enabled_groups[i];
    if (!group->valid || group->epm_region != rid)
      continue;

    if (group->epm_refcount > 0)
      group->epm_refcount--;

    if (group->epm_refcount == 0) {
      group->epm_region = -1;
      group->epm_base = 0;
      group->epm_size = 0;
      should_free = 1;
    }
    maybe_clear_group_locked(group);
    spin_unlock(&encl_lock);

    if (should_free) {
      void* base = (void*) pmp_region_get_addr(rid);
      size_t size = (size_t) pmp_region_get_size(rid);
      if (base && size)
        sbi_memset(base, 0, size);
      pmp_unset_global(rid);
      pmp_region_free_atomic(rid);
    }
    return 1;
  }
  spin_unlock(&encl_lock);
  return 0;
}

static void group_member_release(uint64_t group_id)
{
  struct enabled_group_slot* group;

  if (!group_id)
    return;

  spin_lock(&encl_lock);
  group = find_group_locked(group_id);
  if (group) {
    if (group->pending_create_count > 0)
      group->pending_create_count--;
    if (group->member_count > 0)
      group->member_count--;
    maybe_clear_group_locked(group);
  }
  spin_unlock(&encl_lock);
}

static struct group_member_descriptor*
group_member_find_locked(struct enabled_group_slot* group, enclave_id eid)
{
  int i;

  if (!group)
    return 0;

  for (i = 0; i < (int)group->member_metadata_capacity; i++) {
    if (group->members[i].valid && group->members[i].eid == eid &&
        group->members[i].group_generation == group->generation &&
        eid < ENCL_MAX &&
        group->members[i].eid_generation == enclaves[eid].generation)
      return &group->members[i];
  }

  return 0;
}

static int group_member_add_allowed_region(struct enabled_group_slot* group,
                                           struct group_member_descriptor* member,
                                           enum group_region_type type,
                                           uintptr_t paddr,
                                           size_t size,
                                           uint64_t permissions)
{
  struct group_region_descriptor* region;

  if (!size)
    return 0;

  if (member->allowed_shared_region_count >=
      KEYSTONE_GROUP_MAX_ALLOWED_SHARED_REGIONS)
    return -1;

  region = &member->allowed_shared_regions[member->allowed_shared_region_count++];
  region->valid = 1;
  region->region_id = group_next_region_id_locked(group);
  region->generation = group->generation;
  region->type = type;
  region->paddr = paddr;
  region->size = size;
  region->owner_group = group->group_id;
  region->permissions = permissions;

  return 0;
}

static int group_member_add_allowed_region_desc(
    struct group_member_descriptor* member,
    const struct group_region_descriptor* src)
{
  struct group_region_descriptor* region;

  if (!src || !src->valid || !src->size)
    return 0;

  if (member->allowed_shared_region_count >=
      KEYSTONE_GROUP_MAX_ALLOWED_SHARED_REGIONS)
    return -1;

  region = &member->allowed_shared_regions[member->allowed_shared_region_count++];
  *region = *src;

  return 0;
}

static int group_member_add_yxstm_slice_regions_locked(
    struct enabled_group_slot* group,
    struct group_member_descriptor* member)
{
  uint64_t lane_id;

  if (!group || !member)
    return -1;

  /* Worker slot ranges are unknown until every member has registered. */
  if (member->role == GROUP_ROLE_WORKER) {
    if (member->yxstm_slot.valid &&
        group_member_add_allowed_region(
            group, member, GROUP_REGION_SHARED,
            member->yxstm_slot.base, member->yxstm_slot.size,
            GROUP_REGION_PERM_R | GROUP_REGION_PERM_W))
      return -1;
    return 0;
  }
  if (member->role != GROUP_ROLE_MASTER)
    return 0;
  if (!group->yxstm_slots_frozen)
    return 0;

  for (lane_id = 0; lane_id < KEYSTONE_YXSTM_WORKER_LANE_COUNT; lane_id++) {
    struct group_worker_lane* lane = group_lane_for_id_locked(group, lane_id);
    uintptr_t base;

    if (!lane || !lane->slots_frozen)
      return -1;
    base = lane->yxstm_base;
    if (!base || group_member_add_allowed_region(
                     group, member, GROUP_REGION_SHARED, base,
                     KEYSTONE_YXSTM_WORKER_LANE_SIZE,
                     GROUP_REGION_PERM_R | GROUP_REGION_PERM_W))
        return -1;
  }

  return 0;
}

static int group_yxstm_slots_freeze_locked(struct enabled_group_slot* group)
{
  uint64_t lane_id;
  size_t i;

  if (!group || group->yxstm_slots_frozen ||
      group->worker_count != KEYSTONE_YXSTM_WORKER_LANE_COUNT ||
      !group_yxstm_layout_valid(group) ||
      group->yxstm_bank_count != 1 ||
      group->yxstm_bank_slice_size < KEYSTONE_YXSTM_WORKER_LANE_SIZE)
    return group && group->yxstm_slots_frozen ? 0 : -1;

  /* Validation pass: no metadata is changed until every lane is feasible. */
  for (lane_id = 0; lane_id < KEYSTONE_YXSTM_WORKER_LANE_COUNT; lane_id++) {
    struct group_worker_lane* lane = group_lane_for_id_locked(group, lane_id);
    uintptr_t lane_base = group_yxstm_worker_lane_base(group, lane_id);
    size_t slot_size;
    size_t seen = 0;

    if (!lane || !lane_base || (lane_base & (RISCV_PGSIZE - 1)) ||
        !range_contains(group->yxstm_base, group->yxstm_size, lane_base,
                        KEYSTONE_YXSTM_WORKER_LANE_SIZE))
      return -1;
    if (!lane->runqueue_len)
      continue;
    slot_size = keystone_yxstm_slot_mapping_size(lane->runqueue_len);
    if (!slot_size || slot_size * lane->runqueue_len >
                          KEYSTONE_YXSTM_WORKER_LANE_SIZE)
      return -1;
    for (i = 0; i < group->member_metadata_capacity; i++) {
      struct group_member_descriptor* member = &group->members[i];

      if (!member->valid || member->role != GROUP_ROLE_WORKER ||
          member->lane_id != lane_id)
        continue;
      if (member->lane_rank >= lane->runqueue_len ||
          member->allowed_shared_region_count >=
              KEYSTONE_GROUP_MAX_ALLOWED_SHARED_REGIONS)
        return -1;
      seen++;
    }
    if (seen != lane->runqueue_len)
      return -1;
  }
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];

    if (member->valid && member->role == GROUP_ROLE_MASTER &&
        member->allowed_shared_region_count +
                KEYSTONE_YXSTM_WORKER_LANE_COUNT >
            KEYSTONE_GROUP_MAX_ALLOWED_SHARED_REGIONS)
      return -1;
  }

  for (lane_id = 0; lane_id < KEYSTONE_YXSTM_WORKER_LANE_COUNT; lane_id++) {
    struct group_worker_lane* lane = group_lane_for_id_locked(group, lane_id);
    uintptr_t lane_base = group_yxstm_worker_lane_base(group, lane_id);
    size_t slot_size = keystone_yxstm_slot_mapping_size(
        lane->runqueue_len);
    size_t slot_payload_size = keystone_yxstm_slot_payload_capacity(
        lane->runqueue_len);

    lane->yxstm_base = lane_base;
    lane->yxstm_size = KEYSTONE_YXSTM_WORKER_LANE_SIZE;
    lane->slot_count = lane->runqueue_len;
    lane->slot_size = slot_size;
    lane->slot_payload_size = slot_payload_size;
    lane->reserved_size = KEYSTONE_YXSTM_WORKER_LANE_SIZE -
                          slot_size * lane->slot_count;
    lane->slots_frozen = 1;

    for (i = 0; i < group->member_metadata_capacity; i++) {
      struct group_member_descriptor* member = &group->members[i];
      struct yxstm_slot* slot;

      if (!member->valid || member->role != GROUP_ROLE_WORKER ||
          member->lane_id != lane_id)
        continue;
      slot = &member->yxstm_slot;
      sbi_memset(slot, 0, sizeof(*slot));
      slot->valid = 1;
      slot->slot_id = member->lane_rank;
      slot->owner_eid = member->eid;
      slot->owner_generation = member->eid_generation;
      slot->lane_id = lane_id;
      slot->base = lane_base + slot->slot_id * slot_size;
      slot->size = slot_size;
      slot->payload_capacity = lane->slot_payload_size;
      slot->payload_size = 0;
      slot->state = YXSTM_SLOT_FREE;
      slot->epoch = 1;
      if (group_yxstm_slot_prepare_pmp_cache_locked(group, slot))
        return -1;
      if (group_member_add_allowed_region(
              group, member, GROUP_REGION_SHARED, slot->base, slot->size,
              GROUP_REGION_PERM_R | GROUP_REGION_PERM_W))
        return -1;
    }
    sbi_printf("[SM][yxstm-slot] frozen: group=%lu lane=%lu base=0x%lx size=0x%lx slots=%lu slot_size=0x%lx reserved=0x%lx\n",
               (unsigned long)group->group_id, (unsigned long)lane_id,
               (unsigned long)lane->yxstm_base,
               (unsigned long)lane->yxstm_size,
               (unsigned long)lane->slot_count,
               (unsigned long)lane->slot_size,
               (unsigned long)lane->reserved_size);
  }
  group->yxstm_slots_frozen = 1;
  group->yxstm_slot_layout_epoch++;
  if (!group->yxstm_slot_layout_epoch)
    group->yxstm_slot_layout_epoch = 1;
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];

    if (member->valid && member->role == GROUP_ROLE_MASTER &&
        group_member_add_yxstm_slice_regions_locked(group, member))
      return -1;
  }
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];

    if (member->valid && group_member_prepare_pmp_cache_locked(group, member))
      return -1;
  }
  group_update_yxstm_slices_locked(group);
  return 0;
}

static int group_member_refresh_group_regions_locked(
    struct enabled_group_slot* group,
    struct group_member_descriptor* member)
{
  int i;
  size_t new_count = 0;
  struct group_region_descriptor refreshed[KEYSTONE_GROUP_MAX_ALLOWED_SHARED_REGIONS];

  if (!group || !member)
    return -1;

  sbi_memset(refreshed, 0, sizeof(refreshed));

  for (i = 0; i < KEYSTONE_GROUP_MAX_REGIONS; i++) {
    struct group_region_descriptor* region = &group->region_table[i];

    if (!region->valid)
      continue;

    if (!group_region_is_table_region(region->type) ||
        region->owner_group != group->group_id)
      return -1;

    if (region->type == GROUP_REGION_SHARED &&
        region->paddr == group->yxstm_base &&
        region->size == group->yxstm_size)
      continue;

    if (new_count >= KEYSTONE_GROUP_MAX_ALLOWED_SHARED_REGIONS)
      return -1;

    refreshed[new_count++] = *region;
  }

  for (i = 0; i < (int)member->allowed_shared_region_count; i++) {
    struct group_region_descriptor* region =
      &member->allowed_shared_regions[i];

    if (!region->valid)
      continue;

    if (group_region_is_table_region(region->type))
      continue;

    if (new_count >= KEYSTONE_GROUP_MAX_ALLOWED_SHARED_REGIONS)
      return -1;

    refreshed[new_count++] = *region;
  }

  sbi_memset(member->allowed_shared_regions,
             0,
             sizeof(member->allowed_shared_regions));
  for (i = 0; i < (int)new_count; i++)
    member->allowed_shared_regions[i] = refreshed[i];

  member->allowed_shared_region_count = new_count;
  if (group_member_add_yxstm_slice_regions_locked(group, member))
    return -1;

  /*
   * A changed region policy invalidates the full page-table walk. The next
   * schedule-in must audit the same root against the new allowed layout.
   */
  member->page_table_audit_epoch = 0;
  member->audited_page_table_pages = 0;
  member->audited_leaf_mappings = 0;
  member->audited_yxstm_pte_flags = 0;
  member->audited_yxstm_leaf_count = 0;
  member->audited_yxstm_min_leaf_size = 0;
  member->audited_yxstm_max_leaf_size = 0;
  member->audited_yxstm_alignment = 0;
  member->allowed_region_epoch = group->permission_epoch;
  return 0;
}

static int group_member_add_regions_by_type_locked(
    struct enabled_group_slot* group,
    struct group_member_descriptor* member,
    enum group_region_type type)
{
  int i;
  int added = 0;

  if (!group || !member)
    return -1;

  if (!group_region_is_table_region(type))
    return -1;

  for (i = 0; i < KEYSTONE_GROUP_MAX_REGIONS; i++) {
    if (!group->region_table[i].valid ||
        group->region_table[i].type != type)
      continue;

    if (group->region_table[i].owner_group != group->group_id)
      return -1;

    if (group_member_add_allowed_region_desc(member,
                                             &group->region_table[i]))
      return -1;
    added++;
  }

  return added;
}

static struct group_region_descriptor*
group_region_find_locked(struct enabled_group_slot* group,
                         enum group_region_type type,
                         uintptr_t paddr,
                         size_t size)
{
  int i;

  if (!group)
    return 0;

  for (i = 0; i < KEYSTONE_GROUP_MAX_REGIONS; i++) {
    if (group->region_table[i].valid &&
        group->region_table[i].type == type &&
        group->region_table[i].paddr == paddr &&
        group->region_table[i].size == size)
      return &group->region_table[i];
  }

  return 0;
}

static int group_region_add_or_get_locked(struct enabled_group_slot* group,
                                          enum group_region_type type,
                                          uintptr_t paddr,
                                          size_t size,
                                          uint64_t permissions,
                                          struct group_region_descriptor* out)
{
  int i;
  int free_slot = -1;
  struct group_region_descriptor* region;

  if (!group || !size)
    return -1;
  if (!group_region_is_table_region(type))
    return -1;

  region = group_region_find_locked(group, type, paddr, size);
  if (region) {
    if (region->owner_group != group->group_id)
      return -1;
    if (region->permissions != permissions) {
      if (!group_epoch_can_change_locked(group, "region_permission_update"))
        return -1;
      region->permissions = permissions;
      group_permission_epoch_advance_locked(group, "region_permission_update");
    }
    if (out)
      *out = *region;
    return 0;
  }

  for (i = 0; i < KEYSTONE_GROUP_MAX_REGIONS; i++) {
    if (!group->region_table[i].valid) {
      free_slot = i;
      break;
    }
  }

  if (free_slot < 0)
    return -1;

  if (!group_epoch_can_change_locked(group, "region_add"))
    return -1;

  region = &group->region_table[free_slot];
  if (!group->next_region_id)
    group->next_region_id = 1;

  sbi_memset(region, 0, sizeof(*region));
  region->valid = 1;
  region->region_id = group_next_region_id_locked(group);
  region->generation = group->generation;
  region->type = type;
  region->paddr = paddr;
  region->size = size;
  region->owner_group = group->group_id;
  region->permissions = permissions;
  group->region_count++;
  group_permission_epoch_advance_locked(group, "region_add");

  sbi_printf("[SM][group] region registered: group=%lu region=%lu type=%s pa=0x%lx size=0x%lx perms=0x%lx epoch=%lu count=%lu\n",
             (unsigned long)group->group_id,
             (unsigned long)region->region_id,
             group_region_type_name(type),
             (unsigned long)paddr,
             (unsigned long)size,
             (unsigned long)permissions,
             (unsigned long)group->permission_epoch,
             (unsigned long)group->region_count);

  if (out)
    *out = *region;

  return 0;
}

static void group_region_remove_locked(struct enabled_group_slot* group,
                                       enum group_region_type type,
                                       uintptr_t paddr,
                                       size_t size)
{
  struct group_region_descriptor* region;

  region = group_region_find_locked(group, type, paddr, size);
  if (!region)
    return;

  if (!group_epoch_can_change_locked(group, "region_remove"))
    return;

  sbi_memset(region, 0, sizeof(*region));
  if (group->region_count > 0)
    group->region_count--;
  group_permission_epoch_advance_locked(group, "region_remove");
  sbi_printf("[SM][group] region removed: group=%lu type=%s pa=0x%lx size=0x%lx epoch=%lu count=%lu\n",
             (unsigned long)group->group_id,
             group_region_type_name(type),
             (unsigned long)paddr,
             (unsigned long)size,
             (unsigned long)group->permission_epoch,
             (unsigned long)group->region_count);
}

static int group_member_register(uint64_t group_id,
                                 enclave_id eid,
                                 uintptr_t private_epm_base,
                                 size_t private_epm_size,
                                 uintptr_t page_table_root,
                                 uintptr_t yxstm_base,
                                 size_t yxstm_size,
                                 uintptr_t utm_base,
                                 size_t utm_size,
                                 uintptr_t shared_utm_base,
                                 size_t shared_utm_size,
                                 uintptr_t sec_base,
                                 size_t sec_size)
{
  int i;
  int ret = -1;
  struct enabled_group_slot* group;
  struct group_member_descriptor* member = 0;
  int member_index = -1;
  unsigned long default_hart;

  if (!group_id)
    return 0;

  spin_lock(&encl_lock);
  group = find_group_locked(group_id);
  if (!group || group_member_find_locked(group, eid))
    goto out;

  if (group->lifecycle_state != KEYSTONE_GROUP_STATE_CONFIGURING &&
      group->lifecycle_state != KEYSTONE_GROUP_STATE_READY)
    goto out;

  if (group->active_hart_bitmap) {
    sbi_printf("[SM][group] reject member register while active: group=%lu eid=%u active_harts=0x%lx\n",
               (unsigned long)group_id,
               eid,
               (unsigned long)group->active_hart_bitmap);
    goto out;
  }

  if (!group_context_validate_locked(group, "member_register"))
    goto out;

  if (!range_contains(group->epm_base, group->epm_size,
                      private_epm_base, private_epm_size)) {
    sbi_printf("[SM][group] member private EPM outside group pool: group=%lu eid=%u private=0x%lx/0x%lx pool=0x%lx/0x%lx\n",
               (unsigned long)group_id,
               eid,
               (unsigned long)private_epm_base,
               (unsigned long)private_epm_size,
               (unsigned long)group->epm_base,
               (unsigned long)group->epm_size);
    goto out;
  }

  if (yxstm_size &&
      !group_region_find_locked(group,
                                GROUP_REGION_SHARED,
                                yxstm_base,
                                yxstm_size)) {
    sbi_printf("[SM][group] member references unregistered YXSTM shared region: group=%lu eid=%u yxstm=0x%lx/0x%lx\n",
               (unsigned long)group_id,
               eid,
               (unsigned long)yxstm_base,
               (unsigned long)yxstm_size);
    goto out;
  }

  for (i = 0; i < (int)group->member_metadata_capacity; i++) {
    if (!group->members[i].valid) {
      member = &group->members[i];
      member_index = i;
      break;
    }
  }

  if (!member)
    goto out;

  sbi_memset(member, 0, sizeof(*member));
  member->valid = 1;
  member->eid = eid;
  member->eid_generation = enclaves[eid].generation;
  member->group_id = group_id;
  member->group_generation = group->generation;
  member->role = GROUP_ROLE_NONE;
  member->bound_hart = KEYSTONE_GROUP_UNBOUND_HART;
  member->lane_id = KEYSTONE_GROUP_UNBOUND_LANE;
  member->lane_rank = KEYSTONE_GROUP_UNBOUND_LANE;
  member->task_epoch = group->yxstm_task_epoch;
  member->allowed_slice_mask = 0;
  member->private_epm_base = private_epm_base;
  member->private_epm_size = private_epm_size;
  member->page_table_root = page_table_root;
  member->yxstm_base = yxstm_base;
  member->yxstm_size = yxstm_size;
  member->yxstm_bank_slice_size = group->yxstm_bank_slice_size;
  member->yxstm_bank_count = group->yxstm_bank_count;
  member->sched_base_priority = KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT;
  member->sched_weight = group_scheduler_cfs_weight(
      KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT);
  member->sched_quantum_ticks = KEYSTONE_GROUP_SCHED_QUANTUM_DEFAULT;
  member->sched_vruntime = 0;
  member->sched_sum_exec_time = 0;
  member->sched_exec_start_time = 0;
  member->sched_slice_ticks = 0;
  member->sched_last_run_epoch = 0;
  member->page_table_trust_model = KEYSTONE_GROUP_PT_TRUST_MEASURED_RUNTIME;
  member->private_region.valid = 1;
  member->private_region.region_id = group_next_region_id_locked(group);
  member->private_region.generation = group->generation;
  member->private_region.type = GROUP_REGION_PRIVATE_EPM;
  member->private_region.paddr = private_epm_base;
  member->private_region.size = private_epm_size;
  member->private_region.owner_group = group_id;
  member->private_region.permissions =
    GROUP_REGION_PERM_R | GROUP_REGION_PERM_W | GROUP_REGION_PERM_X;

  default_hart = group_default_hart_for_member_index_locked(group,
                                                           (size_t)member_index);
  if (default_hart >= MAX_HARTS ||
      group_member_update_binding_locked(group, eid, default_hart))
    goto clear_member;

  if (group_member_add_yxstm_slice_regions_locked(group, member))
    goto clear_member;

  if (group_member_add_regions_by_type_locked(group, member,
                                              GROUP_REGION_METADATA) < 0)
    goto clear_member;

  if (group_member_add_regions_by_type_locked(group, member,
                                              GROUP_REGION_CHANNEL) < 0)
    goto clear_member;

  if (group_member_add_allowed_region(group, member, GROUP_REGION_UTM,
                                      utm_base, utm_size,
                                      GROUP_REGION_PERM_R | GROUP_REGION_PERM_W))
    goto clear_member;

  if (group_member_add_allowed_region(group, member, GROUP_REGION_SHARED_UTM,
                                      shared_utm_base, shared_utm_size,
                                      GROUP_REGION_PERM_R | GROUP_REGION_PERM_W))
    goto clear_member;

  if (group_member_add_allowed_region(group, member, GROUP_REGION_SEC,
                                       sec_base, sec_size,
                                       GROUP_REGION_PERM_R | GROUP_REGION_PERM_W))
    goto clear_member;

  if (group_member_prepare_pmp_cache_locked(group, member))
    goto clear_member;

  member->allowed_region_epoch = group->permission_epoch;
  group->membership_epoch++;
  if (!group->membership_epoch)
    group->membership_epoch = 1;
  member->membership_epoch = group->membership_epoch;
  member->revoked_epoch = 0;
  group_security_rekey_locked(group, YXSTM_ROLLBACK_NONE);

  sbi_printf("[SM][group] member registered: group=%lu eid=%u role=%lu bound_hart=%lu slice_mask=0x%lx private=0x%lx/0x%lx root=0x%lx allowed=%lu epoch=%lu\n",
             (unsigned long)group_id,
             eid,
             (unsigned long)member->role,
             (unsigned long)member->bound_hart,
             (unsigned long)member->allowed_slice_mask,
             (unsigned long)private_epm_base,
             (unsigned long)private_epm_size,
             (unsigned long)page_table_root,
             (unsigned long)member->allowed_shared_region_count,
             (unsigned long)member->allowed_region_epoch);

  group->registered_member_count++;
  ret = 0;
  goto out;

clear_member:
  group_lane_remove_member_locked(group, eid);
  sbi_memset(member, 0, sizeof(*member));
out:
  spin_unlock(&encl_lock);
  return ret;
}

static void group_member_unregister(uint64_t group_id, enclave_id eid)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;

  if (!group_id)
    return;

  spin_lock(&encl_lock);
  group_active_hart_clear_eid_locked(eid);
  group_release_yxstm_owner_metadata_locked(eid);
  group_scheduler_remove_eid_locked(eid);
  group = find_group_locked(group_id);
  member = group_member_find_locked(group, eid);
  if (member) {
    yxstm_protocol_member_gone_locked(group, eid,
                                      YXSTM_ROLLBACK_WORKER_GONE);
    group_scrub_member_yxstm_locked(group, member, "member_unregister");
    group->membership_epoch++;
    if (!group->membership_epoch)
      group->membership_epoch = 1;
    member->revoked_epoch = group->membership_epoch;
    group_security_rekey_locked(group, YXSTM_ROLLBACK_WORKER_GONE);
    group_lane_remove_member_locked(group, eid);
    sbi_printf("[SM][group] member unregistered: group=%lu eid=%u epoch=%lu\n",
               (unsigned long)group_id,
               eid,
               group ? (unsigned long)group->permission_epoch : 0);
    sbi_memset(member, 0, sizeof(*member));
    if (group->registered_member_count > 0)
      group->registered_member_count--;
  }
  spin_unlock(&encl_lock);
}

static int group_region_permissions_allow_pte(
    const struct group_region_descriptor* region,
    uintptr_t pte)
{
  if ((pte & PTE_R) && !(region->permissions & GROUP_REGION_PERM_R))
    return 0;
  if ((pte & PTE_W) && !(region->permissions & GROUP_REGION_PERM_W))
    return 0;
  if ((pte & PTE_X) && !(region->permissions & GROUP_REGION_PERM_X))
    return 0;
  return 1;
}

static int group_member_allowed_region_accepts_pte(
    const struct group_member_descriptor* member,
    const struct group_region_descriptor* region,
    uintptr_t paddr,
    size_t size,
    uintptr_t pte)
{
  if (!member || !region || !region->valid)
    return 0;

  if (region->owner_group != member->group_id) {
    sbi_printf("[SM][group] reject cross-group page-table region: group=%lu eid=%u region_group=%lu type=%s pa=0x%lx size=0x%lx\n",
               (unsigned long)member->group_id,
               member->eid,
               (unsigned long)region->owner_group,
               group_region_type_name(region->type),
               (unsigned long)paddr,
               (unsigned long)size);
    return 0;
  }

  if (!range_contains(region->paddr, region->size, paddr, size))
    return 0;

  if (region->type != GROUP_REGION_PRIVATE_EPM && (pte & PTE_X)) {
    sbi_printf("[SM][group] reject executable non-private mapping: group=%lu eid=%u type=%s pa=0x%lx size=0x%lx region=0x%lx/0x%lx\n",
               (unsigned long)member->group_id,
               member->eid,
               group_region_type_name(region->type),
               (unsigned long)paddr,
               (unsigned long)size,
               (unsigned long)region->paddr,
               (unsigned long)region->size);
    return 0;
  }

  if (!group_region_permissions_allow_pte(region, pte))
    return 0;

  return 1;
}

static const struct group_region_descriptor*
group_member_find_allowed_region(const struct group_member_descriptor* member,
                                 uintptr_t paddr,
                                 size_t size,
                                 uintptr_t pte)
{
  size_t i;
  const struct group_region_descriptor* match = 0;

  if (member->private_region.valid &&
      group_member_allowed_region_accepts_pte(member,
                                              &member->private_region,
                                              paddr,
                                              size,
                                              pte))
    match = &member->private_region;

  for (i = 0; i < member->allowed_shared_region_count; i++) {
    const struct group_region_descriptor* region =
      &member->allowed_shared_regions[i];
    if (group_member_allowed_region_accepts_pte(member,
                                                region,
                                                paddr,
                                                size,
                                                pte)) {
      if (match && match->region_id != region->region_id) {
        sbi_printf("[SM][group] reject ambiguous overlapping regions: group=%lu eid=%u first=%lu second=%lu pa=0x%lx size=0x%lx\n",
                   (unsigned long)member->group_id, member->eid,
                   (unsigned long)match->region_id,
                   (unsigned long)region->region_id,
                   (unsigned long)paddr, (unsigned long)size);
        return 0;
      }
      match = region;
    }
  }

  return match;
}

static int group_pt_ranges_overlap(uintptr_t a, size_t a_size,
                                   uintptr_t b, size_t b_size)
{
  uintptr_t a_end;
  uintptr_t b_end;

  if (!a_size || !b_size || CHECKED_ADD(a, a_size, &a_end) ||
      CHECKED_ADD(b, b_size, &b_end))
    return 1;
  return a < b_end && b < a_end;
}

static int group_pt_canonicalize_va(uintptr_t raw, uintptr_t* canonical)
{
#if __riscv_xlen == 64
  const uintptr_t va_mask = (((uintptr_t)1 << VA_BITS) - 1);
  const uintptr_t sign_bit = (uintptr_t)1 << (VA_BITS - 1);
  uintptr_t value = raw & va_mask;

  if (value & sign_bit)
    value |= ~va_mask;
  *canonical = value;
  return ((*canonical & va_mask) == (raw & va_mask));
#else
  *canonical = raw;
  return 1;
#endif
}

static int group_pt_record_table_page(struct group_pt_audit* audit,
                                      uintptr_t page_table_pa)
{
  size_t i;

  if ((page_table_pa & (RISCV_PGSIZE - 1)) ||
      audit->table_page_count >= GROUP_PT_AUDIT_MAX_TABLE_PAGES)
    return 0;
  for (i = 0; i < audit->table_page_count; i++)
    if (audit->table_pages[i] == page_table_pa)
      return 0;
  audit->table_pages[audit->table_page_count++] = page_table_pa;
  return 1;
}

static int group_pt_yxstm_leaf_allowed(
    const struct group_member_descriptor* member,
    const struct group_region_descriptor* region,
    uintptr_t paddr, size_t size)
{
  size_t slice_size;
  size_t bank_size;
  uintptr_t offset;
  uintptr_t bank_id;
  uintptr_t slice_id;

  if (!member->yxstm_size ||
      !range_contains(member->yxstm_base, member->yxstm_size, paddr, size))
    return 1;
  if (region->type != GROUP_REGION_SHARED ||
      !member->yxstm_bank_count ||
      member->yxstm_bank_count > KEYSTONE_YXSTM_MAX_BANKS ||
      !member->yxstm_bank_slice_size)
    return 0;
  slice_size = member->yxstm_bank_slice_size;
  bank_size = slice_size * KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
  if (!bank_size || bank_size * member->yxstm_bank_count !=
                        member->yxstm_size)
    return 0;
  offset = paddr - member->yxstm_base;
  bank_id = offset / bank_size;
  slice_id = (offset % bank_size) / slice_size;
  if (bank_id >= member->yxstm_bank_count ||
      slice_id >= KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT ||
      !range_contains(member->yxstm_base + bank_id * bank_size +
                          slice_id * slice_size,
                      slice_size, paddr, size) ||
      !(member->allowed_slice_mask & ((uintptr_t)1 << slice_id)))
    return 0;
  if (member->role == GROUP_ROLE_MASTER)
    return member->allowed_slice_mask == KEYSTONE_YXSTM_MASTER_SLICE_MASK;
  if (member->role == GROUP_ROLE_WORKER)
    return member->allowed_slice_mask == ((uintptr_t)1 << slice_id);
  return 0;
}

static int group_pt_record_leaf(
    const struct group_member_descriptor* member,
    struct group_pt_audit* audit,
    uintptr_t vaddr, uintptr_t paddr, size_t size, uintptr_t pte,
    const struct group_region_descriptor* region)
{
  size_t i;
  uintptr_t vaddr_end;
  uintptr_t paddr_end;
  uintptr_t expected_yxstm_va;

  if (audit->leaf_count >= GROUP_PT_AUDIT_MAX_LEAVES) {
    audit->leaf_limit_exhausted = 1;
    return 0;
  }
  if (!size || CHECKED_ADD(vaddr, size, &vaddr_end) ||
      CHECKED_ADD(paddr, size, &paddr_end) ||
      !group_pt_yxstm_leaf_allowed(member, region, paddr, size))
    return 0;
  if (member->yxstm_size &&
      range_contains(member->yxstm_base, member->yxstm_size, paddr, size)) {
    if ((pte & PTE_X) ||
        CHECKED_ADD(KEYSTONE_YXSTM_ENCLAVE_VA_BASE,
                    paddr - member->yxstm_base, &expected_yxstm_va) ||
        vaddr != expected_yxstm_va)
      return 0;
    audit->yxstm_pte_flags |= pte & ((uintptr_t)0x3ff);
    audit->yxstm_leaf_count++;
    if (!audit->yxstm_min_leaf_size ||
        size < audit->yxstm_min_leaf_size)
      audit->yxstm_min_leaf_size = size;
    if (size > audit->yxstm_max_leaf_size)
      audit->yxstm_max_leaf_size = size;
    if (!audit->yxstm_alignment || size < audit->yxstm_alignment)
      audit->yxstm_alignment = size;
  }
  (void)vaddr_end;
  (void)paddr_end;

  for (i = 0; i < audit->leaf_count; i++) {
    const struct group_pt_leaf_record* old = &audit->leaves[i];

    /* A valid page-table tree assigns disjoint VA prefixes to its leaves.
     * Reusing a child table would be the only way to visit a VA leaf twice,
     * and group_pt_record_table_page() rejects that reuse/cycle earlier. */
    if (!group_pt_ranges_overlap(paddr, size, old->paddr, old->size))
      continue;
    if (old->region_id != region->region_id)
      return 0;
    if (region->type == GROUP_REGION_SHARED ||
        region->type == GROUP_REGION_METADATA ||
        region->type == GROUP_REGION_CHANNEL ||
        region->type == GROUP_REGION_SHARED_UTM ||
        region->type == GROUP_REGION_SEC)
      return 0;
  }

  audit->leaves[audit->leaf_count].paddr = paddr;
  audit->leaves[audit->leaf_count].size = size;
  audit->leaves[audit->leaf_count].region_id = region->region_id;
  audit->leaves[audit->leaf_count].user_accessible = !!(pte & PTE_U);
  audit->leaf_count++;
  return 1;
}

static int group_pt_yxstm_layout_complete(
    const struct group_member_descriptor* member,
    const struct group_pt_audit* audit)
{
  size_t region_index;
  size_t expected_region_count = 0;

  if (!member || !audit || !member->yxstm_size ||
      !member->yxstm_bank_slice_size)
    return 0;

  for (region_index = 0;
       region_index < member->allowed_shared_region_count; region_index++) {
    const struct group_region_descriptor* region =
        &member->allowed_shared_regions[region_index];
    size_t leaf_index;
    size_t mapped = 0;

    if (!region->valid || region->type != GROUP_REGION_SHARED ||
        !range_contains(member->yxstm_base, member->yxstm_size,
                        region->paddr, region->size))
      continue;
    expected_region_count++;
    if (member->role == GROUP_ROLE_MASTER) {
      uintptr_t offset = region->paddr - member->yxstm_base;
      uintptr_t physical_slice = offset / member->yxstm_bank_slice_size;

      if (region->size != KEYSTONE_YXSTM_WORKER_LANE_SIZE ||
          offset % member->yxstm_bank_slice_size || physical_slice == 0 ||
          physical_slice > KEYSTONE_YXSTM_WORKER_LANE_COUNT)
        return 0;
    } else if (member->role == GROUP_ROLE_WORKER) {
      if (!member->yxstm_slot.valid ||
          region->paddr != member->yxstm_slot.base ||
          region->size != member->yxstm_slot.size ||
          member->yxstm_slot.owner_eid != member->eid ||
          member->yxstm_slot.owner_generation != member->eid_generation)
        return 0;
    } else {
      return 0;
    }

    for (leaf_index = 0; leaf_index < audit->leaf_count; leaf_index++) {
      const struct group_pt_leaf_record* leaf = &audit->leaves[leaf_index];

      if (leaf->region_id != region->region_id)
        continue;
      if (mapped > region->size || leaf->size > region->size - mapped)
        return 0;
      mapped += leaf->size;
    }
    if (mapped != region->size)
      return 0;
  }

  if (member->role == GROUP_ROLE_MASTER)
    return expected_region_count == KEYSTONE_YXSTM_WORKER_LANE_COUNT;
  if (member->role == GROUP_ROLE_WORKER)
    return expected_region_count == 1;
  return expected_region_count == 0;
}

static int group_pt_table_pages_hidden_from_user(
    const struct group_pt_audit* audit)
{
  size_t table_index;
  size_t leaf_index;

  for (table_index = 0; table_index < audit->table_page_count;
       table_index++) {
    for (leaf_index = 0; leaf_index < audit->leaf_count; leaf_index++) {
      const struct group_pt_leaf_record* leaf = &audit->leaves[leaf_index];

      if (leaf->user_accessible &&
          group_pt_ranges_overlap(audit->table_pages[table_index],
                                  RISCV_PGSIZE,
                                  leaf->paddr,
                                  leaf->size))
        return 0;
    }
  }
  return 1;
}

static int group_member_validate_page_table_level(
    const struct group_member_descriptor* member,
    struct group_pt_audit* audit,
    uintptr_t page_table_pa,
    uintptr_t va_prefix,
    int level)
{
  uintptr_t* page_table;
  size_t i;
  size_t entry_span;

  if (level < 0 || level >= RISCV_PGLEVEL_TOP ||
      !range_contains(member->private_epm_base, member->private_epm_size,
                      page_table_pa, RISCV_PGSIZE) ||
      !group_pt_record_table_page(audit, page_table_pa)) {
    sbi_printf("[SM][group] reject invalid/cyclic page-table page: group=%lu eid=%u pt=0x%lx level=%d\n",
               (unsigned long)member->group_id, member->eid,
               (unsigned long)page_table_pa, level);
    return 0;
  }

  entry_span = (size_t)1 << (RISCV_PGSHIFT +
                             level * RISCV_PGLEVEL_BITS);
  page_table = (uintptr_t*)page_table_pa;
  for (i = 0; i < RISCV_PGSIZE / sizeof(uintptr_t); i++) {
    uintptr_t pte = page_table[i];
    uintptr_t pte_pa;
    uintptr_t raw_va = va_prefix | ((uintptr_t)i * entry_span);

    if (!(pte & PTE_V))
      continue;
#if __riscv_xlen == 64
    if (pte >> 54) {
      sbi_printf("[SM][group] reject reserved PTE bits: group=%lu eid=%u pte=0x%lx\n",
                 (unsigned long)member->group_id, member->eid,
                 (unsigned long)pte);
      return 0;
    }
#endif
    if ((pte & PTE_W) && !(pte & PTE_R))
      return 0;
    if (pte & PTE_G)
      return 0;

    pte_pa = (pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;
    if (pte & (PTE_R | PTE_W | PTE_X)) {
      uintptr_t canonical_va;
      const struct group_region_descriptor* region;

      if ((pte_pa & (entry_span - 1)) || (raw_va & (entry_span - 1)) ||
          !group_pt_canonicalize_va(raw_va, &canonical_va))
        return 0;
      region = group_member_find_allowed_region(member, pte_pa,
                                                entry_span, pte);
      if (!region) {
        sbi_printf("[SM][group] reject leaf outside member policy: group=%lu eid=%u va=0x%lx pa=0x%lx size=0x%lx\n",
                   (unsigned long)member->group_id, member->eid,
                   (unsigned long)canonical_va, (unsigned long)pte_pa,
                   (unsigned long)entry_span);
        return 0;
      }
      if (!group_pt_record_leaf(member, audit, canonical_va, pte_pa,
                                entry_span, pte, region)) {
        if (audit->leaf_limit_exhausted)
          sbi_printf("[SM][group] reject page-table audit capacity: group=%lu eid=%u leaves=%lu limit=%u va=0x%lx pa=0x%lx\n",
                     (unsigned long)member->group_id, member->eid,
                     (unsigned long)audit->leaf_count,
                     (unsigned int)GROUP_PT_AUDIT_MAX_LEAVES,
                     (unsigned long)canonical_va, (unsigned long)pte_pa);
        else
          sbi_printf("[SM][group] reject overlapping/aliased leaf: group=%lu eid=%u va=0x%lx pa=0x%lx size=0x%lx type=%s\n",
                     (unsigned long)member->group_id, member->eid,
                     (unsigned long)canonical_va, (unsigned long)pte_pa,
                     (unsigned long)entry_span,
                     group_region_type_name(region->type));
        return 0;
      }
      continue;
    }

    if (level == 0 || (pte & (PTE_U | PTE_A | PTE_D | PTE_SOFT)))
      return 0;
    if (!group_member_validate_page_table_level(member, audit, pte_pa,
                                                raw_va, level - 1))
      return 0;
  }

  return 1;
}

static int group_member_audit_page_table(
    const struct group_member_descriptor* member,
    size_t* table_pages,
    size_t* leaf_mappings,
    struct group_pt_mapping_summary* yxstm_summary)
{
  int valid;

  if (!member || !member->page_table_root ||
      member->page_table_trust_model !=
          KEYSTONE_GROUP_PT_TRUST_MEASURED_RUNTIME)
    return 0;

  spin_lock(&group_pt_audit_lock);
  sbi_memset(&group_pt_audit_scratch, 0, sizeof(group_pt_audit_scratch));
  valid = group_member_validate_page_table_level(
      member, &group_pt_audit_scratch, member->page_table_root, 0,
      RISCV_PGLEVEL_TOP - 1);
  if (valid &&
      !group_pt_table_pages_hidden_from_user(&group_pt_audit_scratch)) {
    sbi_printf("[SM][group] reject user alias of page-table page: group=%lu eid=%u\n",
               (unsigned long)member->group_id, member->eid);
    valid = 0;
  }
  if (valid &&
      !group_pt_yxstm_layout_complete(member, &group_pt_audit_scratch)) {
    sbi_printf("[SM][group] reject incomplete YXSTM slot view: group=%lu eid=%u role=%lu\n",
               (unsigned long)member->group_id, member->eid,
               (unsigned long)member->role);
    valid = 0;
  }
  if (table_pages)
    *table_pages = group_pt_audit_scratch.table_page_count;
  if (leaf_mappings)
    *leaf_mappings = group_pt_audit_scratch.leaf_count;
  if (yxstm_summary) {
    yxstm_summary->pte_flags = group_pt_audit_scratch.yxstm_pte_flags;
    yxstm_summary->leaf_count = group_pt_audit_scratch.yxstm_leaf_count;
    yxstm_summary->min_leaf_size =
        group_pt_audit_scratch.yxstm_min_leaf_size;
    yxstm_summary->max_leaf_size =
        group_pt_audit_scratch.yxstm_max_leaf_size;
    yxstm_summary->alignment = group_pt_audit_scratch.yxstm_alignment;
  }
  spin_unlock(&group_pt_audit_lock);
  return valid;
}

static unsigned long group_member_validate_initial_view(enclave_id eid)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  struct group_member_descriptor member_copy;
  uint64_t group_id;
  size_t table_pages = 0;
  size_t leaf_mappings = 0;
  struct group_pt_mapping_summary yxstm_summary = {0};

  if (eid >= ENCL_MAX || enclaves[eid].group_id == 0)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

  group_id = enclaves[eid].group_id;

  spin_lock(&encl_lock);
  group = find_group_locked(group_id);
  if (!group_context_validate_locked(group, "validate_view")) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  member = group_member_find_locked(group, eid);
  if (!member) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  if (member->group_id != group_id) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  if (member->group_generation != group->generation ||
      member->eid_generation != enclaves[eid].generation) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  if (member->allowed_region_epoch != group->permission_epoch &&
      group_member_refresh_group_regions_locked(group, member)) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;
  }
  if (member->page_table_trust_model ==
          KEYSTONE_GROUP_PT_TRUST_MEASURED_RUNTIME &&
      (!member->page_table_root ||
       (member->page_table_audit_epoch == member->allowed_region_epoch &&
        member->audited_page_table_pages))) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  member_copy = *member;
  spin_unlock(&encl_lock);

  /* The measured loader builds the initial tree before registering its root. */
  if (!member_copy.page_table_root)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (!group_member_audit_page_table(&member_copy, &table_pages,
                                     &leaf_mappings, &yxstm_summary))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;

  spin_lock(&encl_lock);
  group = find_group_locked(group_id);
  member = group_member_find_locked(group, eid);
  if (member && member->page_table_root == member_copy.page_table_root &&
      member->group_generation == member_copy.group_generation &&
      member->eid_generation == member_copy.eid_generation &&
      member->allowed_region_epoch == member_copy.allowed_region_epoch) {
    member->page_table_audit_epoch = member_copy.allowed_region_epoch;
    member->audited_page_table_pages = table_pages;
    member->audited_leaf_mappings = leaf_mappings;
    member->audited_yxstm_pte_flags = yxstm_summary.pte_flags;
    member->audited_yxstm_leaf_count = yxstm_summary.leaf_count;
    member->audited_yxstm_min_leaf_size = yxstm_summary.min_leaf_size;
    member->audited_yxstm_max_leaf_size = yxstm_summary.max_leaf_size;
    member->audited_yxstm_alignment = yxstm_summary.alignment;
  }
  spin_unlock(&encl_lock);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long group_member_register_page_table_root(enclave_id eid,
                                                    uintptr_t page_table_root)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  struct group_member_descriptor member_copy;
  uint64_t group_id;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
  size_t table_pages = 0;
  size_t leaf_mappings = 0;
  struct group_pt_mapping_summary yxstm_summary = {0};
  int had_registered_root = 0;

  if (eid >= ENCL_MAX || enclaves[eid].state < 0)
    return SBI_ERR_SM_ENCLAVE_INVALID_ID;

  group_id = enclaves[eid].group_id;
  if (!group_id)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (!range_contains(enclaves[eid].params.dram_base,
                      enclaves[eid].params.dram_size,
                      page_table_root,
                      RISCV_PGSIZE) ||
      (page_table_root & (RISCV_PGSIZE - 1)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;

  spin_lock(&encl_lock);
  group = find_group_locked(group_id);
  if (!group_context_validate_locked(group, "register_page_table_root")) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  member = group_member_find_locked(group, eid);
  if (!member) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  if (member->group_id != group_id) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  if (member->group_generation != group->generation ||
      member->eid_generation != enclaves[eid].generation) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  if (member->page_table_root && member->page_table_root != page_table_root) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;
  }
  had_registered_root = member->page_table_root != 0;
  if (member->allowed_region_epoch != group->permission_epoch &&
      group_member_refresh_group_regions_locked(group, member)) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;
  }

  member->page_table_root = page_table_root;
  member_copy = *member;
  spin_unlock(&encl_lock);

  if (!group_member_audit_page_table(&member_copy, &table_pages,
                                     &leaf_mappings, &yxstm_summary))
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;

  if (ret) {
    spin_lock(&encl_lock);
    group = find_group_locked(group_id);
    member = group_member_find_locked(group, eid);
    if (!had_registered_root && member &&
        member->page_table_root == page_table_root) {
      member->page_table_root = 0;
      member->page_table_audit_epoch = 0;
      member->audited_page_table_pages = 0;
      member->audited_leaf_mappings = 0;
      member->audited_yxstm_pte_flags = 0;
      member->audited_yxstm_leaf_count = 0;
      member->audited_yxstm_min_leaf_size = 0;
      member->audited_yxstm_max_leaf_size = 0;
      member->audited_yxstm_alignment = 0;
    }
    spin_unlock(&encl_lock);
  } else {
    spin_lock(&encl_lock);
    group = find_group_locked(group_id);
    member = group_member_find_locked(group, eid);
    if (member && member->page_table_root == page_table_root &&
        member->group_generation == member_copy.group_generation &&
        member->eid_generation == member_copy.eid_generation &&
        member->allowed_region_epoch == member_copy.allowed_region_epoch) {
      member->page_table_audit_epoch = member_copy.allowed_region_epoch;
      member->audited_page_table_pages = table_pages;
      member->audited_leaf_mappings = leaf_mappings;
      member->audited_yxstm_pte_flags = yxstm_summary.pte_flags;
      member->audited_yxstm_leaf_count = yxstm_summary.leaf_count;
      member->audited_yxstm_min_leaf_size = yxstm_summary.min_leaf_size;
      member->audited_yxstm_max_leaf_size = yxstm_summary.max_leaf_size;
      member->audited_yxstm_alignment = yxstm_summary.alignment;
    }
    spin_unlock(&encl_lock);
  }

  return ret;
}

static uint8_t yxstm_pmp_perm_from_flags(uintptr_t flags)
{
  uint8_t perm = 0;

  if (flags & KEYSTONE_YXSTM_PERM_R)
    perm |= PMP_R;
  if (flags & KEYSTONE_YXSTM_PERM_W)
    perm |= PMP_W;
  if (flags & KEYSTONE_YXSTM_PERM_X)
    perm |= PMP_X;

  return perm;
}

static unsigned long yxstm_current_context_locked(
    enclave_id eid,
    struct enabled_group_slot** out_group,
    struct group_hart_slot** out_slot,
    unsigned long* out_hartid)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group;
  struct group_active_hart_state* state;
  struct group_member_descriptor* member;

  if (out_group)
    *out_group = 0;
  if (out_slot)
    *out_slot = 0;
  if (out_hartid)
    *out_hartid = hartid;

  if (eid >= ENCL_MAX || enclaves[eid].state < 0)
    return SBI_ERR_SM_ENCLAVE_INVALID_ID;
  if (!enclaves[eid].group_id || hartid >= MAX_HARTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  group = find_group_locked(enclaves[eid].group_id);
  if (!group || !group_context_validate_locked(group, "yxstm_context"))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (group->coherence_inflight)
    return SBI_ERR_SM_GROUP_COHERENCE_BUSY;

  state = &group_active_harts[hartid];
  if (!state->active ||
      state->eid != eid ||
      state->eid_generation != enclaves[eid].generation ||
      state->active_group_id != group->group_id ||
      state->group_generation != group->generation ||
      state->active_epoch != group->permission_epoch ||
      state->active_phase_epoch != group->yxstm_phase_epoch)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  if (!group_hart_allowed_locked(group, hartid) ||
      !group->hart_slots[hartid].valid)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;

  member = group_member_find_locked(group, eid);
  if (!member || !member->valid)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (member->role == GROUP_ROLE_MASTER) {
    if (hartid != group->master_hart)
      return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;
  } else if (member->role == GROUP_ROLE_WORKER) {
    struct group_worker_lane* lane =
        group_lane_for_id_locked(group, member->lane_id);
    if (!lane || lane->hart_id != hartid ||
        lane->active_eid != eid ||
        lane->active_eid_generation != enclaves[eid].generation ||
        lane->state != GROUP_WORKER_LANE_RUNNING ||
        member->task_epoch != lane->task_epoch ||
        lane->task_epoch != group->yxstm_task_epoch)
      return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;
  } else {
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  group_update_yxstm_slices_locked(group);
  if (!group->yxstm_base || !group->yxstm_size ||
      group->yxstm_region < 0 ||
      !group->hart_slots[hartid].yxstm_slice_base ||
      !group->hart_slots[hartid].yxstm_slice_size)
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

  if (out_group)
    *out_group = group;
  if (out_slot)
    *out_slot = &group->hart_slots[hartid];
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static inline void yxstm_protocol_barrier(void)
{
  asm volatile("fence rw,rw" ::: "memory");
}

static void yxstm_task_epoch_advance_locked(
    struct enabled_group_slot* group)
{
  int i;

  if (!group)
    return;
  group->yxstm_task_epoch++;
  if (!group->yxstm_task_epoch)
    group->yxstm_task_epoch = 1;
  for (i = 0; i < KEYSTONE_GROUP_MAX_WORKER_LANES; i++) {
    if (!group->worker_lanes[i].valid)
      continue;
    group->worker_lanes[i].task_epoch = group->yxstm_task_epoch;
    group->worker_lanes[i].stream_sequence = 0;
    group->worker_lanes[i].stream_turn = 0;
    group->worker_lanes[i].lane_epoch++;
    if (!group->worker_lanes[i].lane_epoch)
      group->worker_lanes[i].lane_epoch = 1;
  }
  for (i = 0; i < (int)group->member_metadata_capacity; i++)
    if (group->members[i].valid) {
      group->members[i].task_epoch = group->yxstm_task_epoch;
      group->members[i].yxstm_ack_phase_epoch = 0;
      group->members[i].yxstm_ack_event_mask = 0;
      /* A RUNNING waiter may not have entered STOP_LANE_WAIT yet. */
      if (!group->members[i].lane_wait_pending)
        group_lane_wait_clear_locked(&group->members[i]);
    }
}

static void group_lane_cancel_waiters_locked(struct enabled_group_slot* group,
                                             const char* where)
{
  size_t i;

  if (!group)
    return;
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];
    if (!member->valid || !member->lane_wait_pending)
      continue;
    group_lane_wait_signal_locked(member, SBI_ERR_SM_YXSTM_PHASE, where);
  }
}

static void yxstm_protocol_reset_member_acks_locked(
    struct enabled_group_slot* group)
{
  size_t i;

  if (!group)
    return;
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];

    if (!member->valid)
      continue;
    member->yxstm_ack_phase_epoch = group->yxstm_phase_epoch;
    member->yxstm_ack_event_mask = 0;
  }
}

/*
 * ready_bitmap/done_bitmap are lane bitmaps, while an oversubscribed lane can
 * contain several worker enclaves. A lane reaches its phase barrier only after
 * every live member assigned to that active slice has acknowledged the same
 * phase epoch and event.
 */
static int yxstm_protocol_lane_members_acked_locked(
    struct enabled_group_slot* group, uintptr_t lane_bit,
    uintptr_t expected_epoch, uintptr_t event)
{
  uint64_t event_bit;
  size_t i;
  int found = 0;

  if (!group || !lane_bit || event >= 64)
    return 0;
  event_bit = UINT64_C(1) << event;
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];

    if (!member->valid || member->role != GROUP_ROLE_WORKER ||
        member->allowed_slice_mask != lane_bit)
      continue;
    found = 1;
    if (member->task_epoch != group->yxstm_task_epoch ||
        member->yxstm_ack_phase_epoch != expected_epoch ||
        !(member->yxstm_ack_event_mask & event_bit))
      return 0;
  }
  return found;
}

static uintptr_t yxstm_protocol_worker_mask(void)
{
  return KEYSTONE_YXSTM_MASTER_SLICE_MASK &
         ~(1UL << KEYSTONE_YXSTM_MASTER_SLICE_ID);
}

static int yxstm_protocol_revoke_all_locked(
    struct enabled_group_slot* group, const char* where)
{
  struct group_coherence_snapshot snapshot;
  struct enabled_group_slot* current_group;
  uint64_t acked = 0;
  uint64_t offline = 0;
  uint64_t group_id;
  uint64_t group_generation;
  unsigned long ret;

  if (!group)
    return -1;

  group_id = group->group_id;
  group_generation = group->generation;

  ret = group_coherence_begin_locked(group, group->permission_epoch,
                                     group->yxstm_phase_epoch + 1,
                                     SBI_GROUP_IPI_REVOKE_YXSTM, &snapshot);
  if (ret)
    return -1;

  /* A remote schedule-out may need encl_lock before it can become quiescent. */
  spin_unlock(&encl_lock);
  ret = group_coherence_execute_unlocked(&snapshot, &acked, &offline);
  spin_lock(&encl_lock);

  current_group = find_group_locked(group_id);
  if (!current_group || current_group != group ||
      current_group->generation != group_generation) {
    if (group->generation == group_generation)
      group->coherence_inflight = 0;
    return -1;
  }

  ret = group_coherence_finish_locked(current_group, &snapshot, acked, offline,
                                      ret, where);
  if (ret)
    return -1;
  yxstm_protocol_barrier();
  if (!current_group->yxstm_perf_quiet)
    sbi_printf("[SM][yxstm] protocol revoke-all: group=%lu where=%s phase_epoch=%lu\n",
               (unsigned long)current_group->group_id, where,
               (unsigned long)current_group->yxstm_phase_epoch);
  return 0;
}

static void yxstm_protocol_clear_suspended_locked(
    struct enabled_group_slot* group)
{
  size_t i;

  for (i = 0; group && i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];
    member->yxstm_suspended_acquired = 0;
    member->yxstm_suspended_slice_mask = 0;
    member->yxstm_suspended_permissions = 0;
    member->yxstm_suspended_phase = YXSTM_PHASE_IDLE;
    member->yxstm_suspended_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
    member->yxstm_suspended_phase_epoch = 0;
    member->yxstm_suspended_permission_epoch = 0;
    member->yxstm_suspended_task_epoch = 0;
  }
}

static void yxstm_protocol_rollback_locked(
    struct enabled_group_slot* group, uint64_t reason, const char* where)
{
  if (!group || group->yxstm_phase == YXSTM_PHASE_IDLE)
    return;

  if (yxstm_protocol_revoke_all_locked(group, where)) {
    group_lane_cancel_waiters_locked(group, "lane_wait_rollback");
    yxstm_protocol_clear_suspended_locked(group);
    group->yxstm_rollback_reason = reason;
    yxstm_protocol_publish_mailboxes_locked(group);
    return;
  }
  group_lane_cancel_waiters_locked(group, "lane_wait_rollback");
  yxstm_protocol_clear_suspended_locked(group);
  group->yxstm_phase = YXSTM_PHASE_IDLE;
  group->yxstm_phase_epoch++;
  yxstm_task_epoch_advance_locked(group);
  group->yxstm_active_worker_mask = 0;
  group->yxstm_published_sequence = 0;
  group->yxstm_ready_bitmap = 0;
  group->yxstm_done_bitmap = 0;
  group->yxstm_payload_length = 0;
  group->yxstm_deadline = 0;
  group->yxstm_rollback_reason = reason;
  group_scrub_yxstm_mask_locked(group, KEYSTONE_YXSTM_MASTER_SLICE_MASK,
                                where);
  group_security_rekey_locked(group, reason);
  yxstm_protocol_barrier();
  yxstm_protocol_publish_mailboxes_locked(group);
}

static int yxstm_protocol_timeout_locked(struct enabled_group_slot* group)
{
  if (!group || group->yxstm_phase == YXSTM_PHASE_IDLE ||
      !group->yxstm_deadline)
    return 0;
  if (group->coherence_inflight)
    return 0;

  if ((int64_t)(sbi_timer_value() - group->yxstm_deadline) < 0)
    return 0;

  yxstm_protocol_rollback_locked(group, YXSTM_ROLLBACK_TIMEOUT, "timeout");
  return 1;
}

static int yxstm_protocol_has_worker_locked(
    struct enabled_group_slot* group, uintptr_t slice_bit)
{
  size_t i;

  for (i = 0; group && i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];
    if (!member->valid || member->role != GROUP_ROLE_WORKER ||
        member->allowed_slice_mask != slice_bit)
      continue;
    if (!ENCLAVE_EXISTS(member->eid) ||
        enclaves[member->eid].sched_state == GROUP_SCHED_EXITED)
      continue;
    return 1;
  }
  return 0;
}

static int yxstm_protocol_workers_present_locked(
    struct enabled_group_slot* group, uintptr_t worker_mask)
{
  uintptr_t bit;

  for (bit = 1UL << 1;
       bit <= (1UL << (KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT - 1));
       bit <<= 1) {
    if ((worker_mask & bit) &&
        !yxstm_protocol_has_worker_locked(group, bit))
      return 0;
  }
  return 1;
}

static int yxstm_protocol_any_acquired_locked(
    struct enabled_group_slot* group)
{
  unsigned long hartid;
  size_t member_index;

  for (hartid = 0; group && hartid < MAX_HARTS; hartid++) {
    struct group_hart_slot* slot = &group->hart_slots[hartid];

    if (slot->valid &&
        (slot->yxstm_acquired || slot->yxstm_owner_eid != ENCL_MAX ||
         slot->yxstm_acquired_slice_mask || slot->yxstm_permissions ||
         slot->yxstm_phase != YXSTM_PHASE_IDLE))
      return 1;
  }
  for (member_index = 0;
       group && member_index < group->member_metadata_capacity;
       member_index++) {
    struct group_member_descriptor* member = &group->members[member_index];

    if (member->valid &&
        (member->yxstm_suspended_acquired ||
         member->yxstm_suspended_slice_mask ||
         member->yxstm_suspended_permissions ||
         member->yxstm_suspended_phase != YXSTM_PHASE_IDLE))
      return 1;
  }
  return 0;
}

static int yxstm_task_bank_any_acquired_locked(
    struct enabled_group_slot* group, uintptr_t bank_id)
{
  unsigned long hartid;
  size_t member_index;

  for (hartid = 0; group && hartid < MAX_HARTS; hartid++) {
    struct group_hart_slot* slot = &group->hart_slots[hartid];

    if (slot->valid && slot->yxstm_acquired &&
        slot->yxstm_bank_id == bank_id)
      return 1;
  }
  for (member_index = 0;
       group && member_index < group->member_metadata_capacity;
       member_index++) {
    struct group_member_descriptor* member = &group->members[member_index];

    if (member->valid && member->yxstm_suspended_acquired &&
        member->yxstm_suspended_bank_id == bank_id)
      return 1;
  }
  return 0;
}

static int yxstm_task_bank_any_active_locked(
    struct enabled_group_slot* group)
{
  uintptr_t bank_id;

  for (bank_id = 0; group && bank_id < group->yxstm_bank_count; bank_id++)
    if (group->task_banks[bank_id].phase != YXSTM_PHASE_IDLE ||
        group->task_banks[bank_id].rollback_reason != YXSTM_ROLLBACK_NONE ||
        yxstm_task_bank_any_acquired_locked(group, bank_id))
      return 1;
  return 0;
}

static int yxstm_legacy_any_acquired_locked(
    struct enabled_group_slot* group)
{
  unsigned long hartid;
  size_t member_index;

  for (hartid = 0; group && hartid < MAX_HARTS; hartid++) {
    struct group_hart_slot* slot = &group->hart_slots[hartid];

    if (slot->valid && slot->yxstm_acquired &&
        slot->yxstm_bank_id == KEYSTONE_YXSTM_INVALID_BANK)
      return 1;
  }
  for (member_index = 0;
       group && member_index < group->member_metadata_capacity;
       member_index++) {
    struct group_member_descriptor* member = &group->members[member_index];

    if (member->valid && member->yxstm_suspended_acquired &&
        member->yxstm_suspended_bank_id == KEYSTONE_YXSTM_INVALID_BANK)
      return 1;
  }
  return 0;
}

static void yxstm_task_bank_write_headers_locked(
    struct enabled_group_slot* group, uintptr_t bank_id)
{
  struct group_task_bank_protocol* bank;
  uintptr_t slice_id;

  if (!group || bank_id >= group->yxstm_bank_count)
    return;
  bank = &group->task_banks[bank_id];
  group_mark_yxstm_bank_dirty_locked(
      group, bank_id, bank->active_worker_mask);
  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    struct keystone_yxstm_channel_header header;
    struct group_member_descriptor* owner;
    uintptr_t bit = 1UL << slice_id;
    uintptr_t base;

    if (!(bank->active_worker_mask & bit))
      continue;
    owner = group_yxstm_slot_member_for_slice_locked(
        group, slice_id, bank->lane_rank);
    if (!owner || !owner->yxstm_slot.valid)
      continue;
    base = owner->yxstm_slot.base;
    sbi_memset(&header, 0, sizeof(header));
    header.magic = KEYSTONE_YXSTM_CHANNEL_MAGIC;
    header.version = KEYSTONE_YXSTM_CHANNEL_VERSION;
    header.header_size = sizeof(header);
    header.group_id = group->group_id;
    header.group_generation = group->generation;
    header.security_policy_version = group->security_policy_version;
    header.phase_epoch = bank->phase_epoch;
    header.task_epoch = bank->task_epoch;
    header.session_epoch = group->session_epoch;
    header.sequence = bank->sequence;
    header.payload_length = bank->payload_length;
    header.slice_id = slice_id;
    header.bank_id = bank_id;
    header.flags = bank->phase;
    sbi_memcpy((void*)base, &header, sizeof(header));
  }
  yxstm_protocol_barrier();
}

static int yxstm_task_bank_header_valid_locked(
    struct enabled_group_slot* group, uintptr_t bank_id,
    uintptr_t slice_id)
{
  struct group_task_bank_protocol* bank;
  struct group_member_descriptor* owner;
  struct keystone_yxstm_channel_header* header;
  uintptr_t base;

  if (!group || bank_id >= group->yxstm_bank_count ||
      slice_id >= KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
    return 0;
  bank = &group->task_banks[bank_id];
  owner = group_yxstm_slot_member_for_slice_locked(
      group, slice_id, bank->lane_rank);
  if (!owner || !owner->yxstm_slot.valid ||
      owner->yxstm_slot.size < sizeof(*header) ||
      bank->payload_length > owner->yxstm_slot.payload_capacity)
    return 0;
  base = owner->yxstm_slot.base;
  header = (struct keystone_yxstm_channel_header*)base;
  yxstm_protocol_barrier();
  return header->magic == KEYSTONE_YXSTM_CHANNEL_MAGIC &&
         header->version == KEYSTONE_YXSTM_CHANNEL_VERSION &&
         header->header_size == sizeof(*header) &&
         header->group_id == group->group_id &&
         header->group_generation == group->generation &&
         header->security_policy_version == group->security_policy_version &&
         header->phase_epoch == bank->phase_epoch &&
         header->task_epoch == bank->task_epoch &&
         header->session_epoch == group->session_epoch &&
         header->sequence == bank->sequence &&
         header->payload_length == bank->payload_length &&
         owner->yxstm_slot.payload_size == bank->payload_length &&
         header->slice_id == slice_id &&
         header->bank_id == bank_id &&
         header->flags == bank->phase;
}

static unsigned long yxstm_task_bank_wait_status_locked(
    struct enabled_group_slot* group,
    struct group_member_descriptor* member,
    uintptr_t bank_id,
    uintptr_t phase,
    uintptr_t sequence,
    uintptr_t task_epoch,
    int* ready)
{
  struct group_task_bank_protocol* bank;

  if (ready)
    *ready = 0;
  if (!group || !member || !ready || bank_id >= group->yxstm_bank_count ||
      (phase != YXSTM_PHASE_DISPATCH && phase != YXSTM_PHASE_COMPUTE &&
       phase != YXSTM_PHASE_AGGREGATE))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  bank = &group->task_banks[bank_id];
  if (bank->rollback_reason != YXSTM_ROLLBACK_NONE)
    return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
  if (task_epoch < bank->task_epoch)
    return SBI_ERR_SM_YXSTM_STALE_EPOCH;
  if (task_epoch > bank->task_epoch)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  if (sequence != bank->sequence || member->lane_rank != bank->lane_rank)
    return SBI_ERR_SM_YXSTM_STALE_EPOCH;
  if (!(bank->active_worker_mask & member->allowed_slice_mask))
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  if (bank->phase == YXSTM_PHASE_IDLE || bank->phase > phase)
    return SBI_ERR_SM_YXSTM_STALE_EPOCH;
  if (bank->phase < phase)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  if (phase == YXSTM_PHASE_DISPATCH &&
      bank->published_sequence != sequence)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  *ready = 1;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static void yxstm_task_bank_wake_waiters_locked(
    struct enabled_group_slot* group, uintptr_t bank_id,
    const char* where)
{
  size_t i;

  if (!group || bank_id >= group->yxstm_bank_count)
    return;
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];
    unsigned long result;
    int ready = 0;

    if (!member->valid || !member->lane_wait_pending ||
        member->lane_wait_task_bank != GROUP_LANE_WAIT_KIND_TASK_BANK ||
        member->lane_wait_turn != bank_id)
      continue;
    result = yxstm_task_bank_wait_status_locked(
        group, member, bank_id, member->lane_wait_phase,
        member->lane_wait_sequence, member->lane_wait_task_epoch, &ready);
    if (result != SBI_ERR_SM_ENCLAVE_SUCCESS)
      group_lane_wait_signal_locked(member, result, where);
    else if (ready)
      group_lane_wait_signal_locked(member, SBI_ERR_SM_ENCLAVE_SUCCESS,
                                    where);
  }
}

static void yxstm_task_bank_reset_slots_locked(
    struct enabled_group_slot* group,
    const struct group_task_bank_protocol* bank,
    int scrub)
{
  uintptr_t slice_id;

  if (!group || !bank)
    return;
  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    struct group_member_descriptor* owner;
    struct yxstm_slot* slot;

    if (!(bank->active_worker_mask & (1UL << slice_id)))
      continue;
    owner = group_yxstm_slot_member_for_slice_locked(
        group, slice_id, bank->lane_rank);
    if (!owner)
      continue;
    slot = &owner->yxstm_slot;
    if (scrub && slot->base && slot->size)
      sbi_memset((void*)slot->base, 0, slot->size);
    slot->state = YXSTM_SLOT_FREE;
    slot->batch_id = 0;
    slot->task_id = 0;
    slot->sequence = 0;
    slot->payload_size = 0;
    slot->permissions = 0;
    slot->digest = 0;
    slot->epoch++;
    if (!slot->epoch)
      slot->epoch = 1;
  }
  yxstm_protocol_barrier();
}

static void yxstm_task_bank_rollback_locked(
    struct enabled_group_slot* group, uintptr_t bank_id,
    uint64_t reason, const char* where)
{
  struct group_task_bank_protocol* bank;

  if (!group || bank_id >= group->yxstm_bank_count)
    return;
  (void)where;
  bank = &group->task_banks[bank_id];
  if (bank->phase == YXSTM_PHASE_IDLE)
    return;
  if (yxstm_task_bank_any_acquired_locked(group, bank_id)) {
    bank->rollback_reason = reason;
    yxstm_protocol_publish_mailboxes_locked(group);
    yxstm_task_bank_wake_waiters_locked(group, bank_id,
                                        "task_bank_rollback_pending");
    return;
  }
  yxstm_task_bank_reset_slots_locked(group, bank, 1);
  bank->phase = YXSTM_PHASE_IDLE;
  bank->phase_epoch++;
  bank->task_epoch++;
  if (!bank->task_epoch)
    bank->task_epoch = 1;
  bank->published_sequence = 0;
  bank->active_worker_mask = 0;
  bank->ready_bitmap = 0;
  bank->done_bitmap = 0;
  bank->payload_length = 0;
  bank->deadline = 0;
  bank->task_digest = 0;
  bank->owner_valid = 0;
  bank->owner_lane_rank = 0;
  bank->owner_worker_mask = 0;
  bank->owner_generation_token = 0;
  bank->rollback_reason = reason;
  yxstm_protocol_barrier();
  yxstm_protocol_publish_mailboxes_locked(group);
  yxstm_task_bank_wake_waiters_locked(group, bank_id,
                                      "task_bank_rollback");
}

static int yxstm_task_bank_timeout_locked(
    struct enabled_group_slot* group, uintptr_t bank_id)
{
  struct group_task_bank_protocol* bank;

  if (!group || bank_id >= group->yxstm_bank_count)
    return 0;
  bank = &group->task_banks[bank_id];
  if (bank->phase == YXSTM_PHASE_IDLE || !bank->deadline ||
      (int64_t)(sbi_timer_value() - bank->deadline) < 0)
    return 0;
  yxstm_task_bank_rollback_locked(group, bank_id,
                                  YXSTM_ROLLBACK_TIMEOUT,
                                  "task_bank_timeout");
  return 1;
}

static void yxstm_protocol_write_headers_locked(
    struct enabled_group_slot* group)
{
  uintptr_t slice_id;
  size_t slice_size;

  if (!group || !group->yxstm_base ||
      group->yxstm_size < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
    return;

  slice_size = group->yxstm_bank_slice_size;
  if (slice_size < sizeof(struct keystone_yxstm_channel_header) ||
      group->yxstm_payload_length >
          slice_size - sizeof(struct keystone_yxstm_channel_header))
    return;
  group_mark_yxstm_bank_dirty_locked(
      group, 0, group->yxstm_active_worker_mask);
  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    struct keystone_yxstm_channel_header header;
    uintptr_t bit = 1UL << slice_id;
    if (!(group->yxstm_active_worker_mask & bit))
      continue;
    sbi_memset(&header, 0, sizeof(header));
    header.magic = KEYSTONE_YXSTM_CHANNEL_MAGIC;
    header.version = KEYSTONE_YXSTM_CHANNEL_VERSION;
    header.header_size = sizeof(header);
    header.group_id = group->group_id;
    header.group_generation = group->generation;
    header.security_policy_version = group->security_policy_version;
    header.phase_epoch = group->yxstm_phase_epoch;
    header.task_epoch = group->yxstm_task_epoch;
    header.session_epoch = group->session_epoch;
    header.sequence = group->yxstm_sequence;
    header.payload_length = group->yxstm_payload_length;
    header.slice_id = slice_id;
    header.bank_id = 0;
    header.flags = group->yxstm_phase;
    sbi_memcpy((void*)group_yxstm_bank_slice_base(group, 0, slice_id),
               &header, sizeof(header));
  }
  yxstm_protocol_barrier();
}

static int yxstm_protocol_header_valid_locked(
    struct enabled_group_slot* group, uintptr_t slice_id)
{
  struct keystone_yxstm_channel_header* header;
  size_t slice_size;

  if (!group || slice_id >= KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
    return 0;
  slice_size = group->yxstm_bank_slice_size;
  if (slice_size < sizeof(*header) ||
      group->yxstm_payload_length > slice_size - sizeof(*header))
    return 0;
  header = (struct keystone_yxstm_channel_header*)(
      group_yxstm_bank_slice_base(group, 0, slice_id));
  yxstm_protocol_barrier();
  return header->magic == KEYSTONE_YXSTM_CHANNEL_MAGIC &&
         header->version == KEYSTONE_YXSTM_CHANNEL_VERSION &&
         header->header_size == sizeof(*header) &&
         header->group_id == group->group_id &&
         header->group_generation == group->generation &&
         header->security_policy_version == group->security_policy_version &&
         header->phase_epoch == group->yxstm_phase_epoch &&
         header->task_epoch == group->yxstm_task_epoch &&
         header->session_epoch == group->session_epoch &&
         header->sequence == group->yxstm_sequence &&
         header->payload_length == group->yxstm_payload_length &&
         header->slice_id == slice_id &&
         header->bank_id == 0 &&
         header->flags == group->yxstm_phase;
}

static void yxstm_protocol_member_gone_locked(
    struct enabled_group_slot* group, enclave_id eid, uint64_t reason)
{
  struct group_member_descriptor* member;
  uintptr_t bank_id;

  if (!group)
    return;
  member = group_member_find_locked(group, eid);
  if (!member)
    return;
  for (bank_id = 0; bank_id < group->yxstm_bank_count; bank_id++) {
    struct group_task_bank_protocol* bank = &group->task_banks[bank_id];

    if (bank->phase == YXSTM_PHASE_IDLE)
      continue;
    if (member->role == GROUP_ROLE_MASTER ||
        (member->role == GROUP_ROLE_WORKER &&
         member->lane_rank == bank->lane_rank &&
         (member->allowed_slice_mask & bank->active_worker_mask)))
      yxstm_task_bank_rollback_locked(
          group, bank_id,
          member->role == GROUP_ROLE_MASTER ?
              YXSTM_ROLLBACK_MASTER_GONE : reason,
          member->role == GROUP_ROLE_MASTER ?
              "task_bank_master_gone" : "task_bank_worker_gone");
  }
  if (group->yxstm_phase == YXSTM_PHASE_IDLE)
    return;
  if (member->role == GROUP_ROLE_MASTER) {
    yxstm_protocol_rollback_locked(group, YXSTM_ROLLBACK_MASTER_GONE,
                                   "master_gone");
  } else if (member->role == GROUP_ROLE_WORKER &&
             (member->allowed_slice_mask &
              group->yxstm_active_worker_mask)) {
    if (reason != YXSTM_ROLLBACK_FAULT &&
        group->yxstm_phase == YXSTM_PHASE_AGGREGATE &&
        (group->yxstm_ready_bitmap & member->allowed_slice_mask))
      return;
    yxstm_protocol_rollback_locked(group, reason, "worker_gone");
  }
}

static int yxstm_flags_valid(uintptr_t flags)
{
  if (!flags)
    return 0;
  if (flags & ~(KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W))
    return 0;
  if (!(flags & KEYSTONE_YXSTM_PERM_R))
    return 0;
  return 1;
}

static int yxstm_phase_valid(uintptr_t phase)
{
  return phase == YXSTM_PHASE_DISPATCH ||
         phase == YXSTM_PHASE_COMPUTE ||
         phase == YXSTM_PHASE_AGGREGATE;
}

static unsigned long yxstm_validate_member_access_locked(
    struct enabled_group_slot* group,
    const struct group_member_descriptor* member,
    uintptr_t slice_mask,
    uintptr_t flags,
    uintptr_t phase)
{
  uintptr_t worker_slice_mask;
  uintptr_t master_slice_mask;

  if (!group || !member || !member->valid)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (!yxstm_flags_valid(flags) || !yxstm_phase_valid(phase))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  master_slice_mask = KEYSTONE_YXSTM_MASTER_SLICE_MASK;
  if (!slice_mask || (slice_mask & ~master_slice_mask))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (member->role == GROUP_ROLE_WORKER) {
    if (slice_mask != member->allowed_slice_mask)
      return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

    if (phase == YXSTM_PHASE_DISPATCH &&
        flags == KEYSTONE_YXSTM_PERM_R)
      return SBI_ERR_SM_ENCLAVE_SUCCESS;

    if (phase == YXSTM_PHASE_COMPUTE &&
        flags == (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W))
      return SBI_ERR_SM_ENCLAVE_SUCCESS;

    /* Retained for the non-mixed compatibility tests; new work executes in
     * COMPUTE and only the master reads in AGGREGATE. */
    if (phase == YXSTM_PHASE_AGGREGATE &&
        flags == (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W))
      return SBI_ERR_SM_ENCLAVE_SUCCESS;

    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  if (member->role != GROUP_ROLE_MASTER)
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

  if (slice_mask & ~member->allowed_slice_mask)
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

  worker_slice_mask =
    master_slice_mask & ~(1UL << KEYSTONE_YXSTM_MASTER_SLICE_ID);

  if (slice_mask & (1UL << KEYSTONE_YXSTM_MASTER_SLICE_ID)) {
    /*
     * slice0 is master's private YXSTM scratch. Keep it separate from
     * worker-channel acquire requests so dispatch/aggregation policy remains
     * unambiguous.
     */
    if (slice_mask != (1UL << KEYSTONE_YXSTM_MASTER_SLICE_ID))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }

  if (!(slice_mask & worker_slice_mask))
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

  if (phase == YXSTM_PHASE_DISPATCH &&
      flags == (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W))
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (phase == YXSTM_PHASE_AGGREGATE &&
      flags == KEYSTONE_YXSTM_PERM_R)
    return SBI_ERR_SM_ENCLAVE_SUCCESS;

  return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
}

static unsigned long yxstm_current_member_context_locked(
    enclave_id eid,
    struct enabled_group_slot** out_group,
    struct group_hart_slot** out_slot,
    struct group_member_descriptor** out_member,
    unsigned long* out_hartid)
{
  struct enabled_group_slot* group;
  struct group_hart_slot* slot;
  struct group_member_descriptor* member;
  unsigned long hartid;
  unsigned long ret;

  if (out_member)
    *out_member = 0;

  ret = yxstm_current_context_locked(eid, &group, &slot, &hartid);
  if (ret)
    return ret;

  member = group_member_find_locked(group, eid);
  if (!member || !member->valid)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (member->bound_hart == KEYSTONE_GROUP_UNBOUND_HART) {
    if (group_member_update_binding_locked(group, eid, hartid))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  if (member->role == GROUP_ROLE_MASTER ||
             member->role == GROUP_ROLE_WORKER) {
    if (!member->allowed_slice_mask)
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  } else {
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  if (out_group)
    *out_group = group;
  if (out_slot)
    *out_slot = slot;
  if (out_member)
    *out_member = member;
  if (out_hartid)
    *out_hartid = hartid;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long yxstm_layout_member_context_locked(
    enclave_id eid,
    struct enabled_group_slot** out_group,
    struct group_member_descriptor** out_member)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;

  if (out_group)
    *out_group = 0;
  if (out_member)
    *out_member = 0;

  if (eid >= ENCL_MAX || enclaves[eid].state < 0)
    return SBI_ERR_SM_ENCLAVE_INVALID_ID;
  if (!enclaves[eid].group_id)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  group = find_group_locked(enclaves[eid].group_id);
  if (!group || !group_context_validate_locked(group, "yxstm_layout"))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  member = group_member_find_locked(group, eid);
  if (!member || !member->valid)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (member->bound_hart == KEYSTONE_GROUP_UNBOUND_HART)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (member->role == GROUP_ROLE_MASTER ||
             member->role == GROUP_ROLE_WORKER) {
    if (!member->allowed_slice_mask)
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  } else {
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  group_update_yxstm_slices_locked(group);
  if (!group->yxstm_base || !group->yxstm_size || group->yxstm_region < 0)
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

  if (out_group)
    *out_group = group;
  if (out_member)
    *out_member = member;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int yxstm_slice_mask_single(uintptr_t slice_mask, uintptr_t* slice_id)
{
  uintptr_t i;

  if (!slice_mask || (slice_mask & (slice_mask - 1)))
    return 0;

  for (i = 0; i < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT; i++) {
    if (slice_mask & (1UL << i)) {
      if (slice_id)
        *slice_id = i;
      return 1;
    }
  }

  return 0;
}

static unsigned long yxstm_install_pmp_for_mask_locked(
    struct enabled_group_slot* group,
    const struct group_member_descriptor* member,
    uintptr_t slice_mask,
    uintptr_t flags)
{
  unsigned int writable;

  if (group && member && member->role == GROUP_ROLE_WORKER &&
      member->yxstm_slot.valid && member->yxstm_slot.pmp_cache_valid &&
      member->yxstm_slot.pmp_entry_count == 2 &&
      slice_mask == member->allowed_slice_mask &&
      yxstm_pmp_perm_from_flags(flags) &&
      !(flags & ~(KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W))) {
    writable = (flags & KEYSTONE_YXSTM_PERM_W) ? 1U : 0U;
    return pmp_apply_cached_entries(
               member->yxstm_slot.pmp_grant[writable],
               member->yxstm_slot.pmp_entry_count) ?
        SBI_ERR_SM_ENCLAVE_PMP_FAILURE : SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  return yxstm_install_task_bank_pmp_locked(group, member, 0,
                                             slice_mask, flags);
}

static unsigned long yxstm_install_task_bank_pmp_locked(
    struct enabled_group_slot* group,
    const struct group_member_descriptor* member,
    uintptr_t bank_id,
    uintptr_t slice_mask,
    uintptr_t flags)
{
  uintptr_t slice_id = 0;
  uint64_t slot_id;
  unsigned int writable;
  struct group_member_descriptor* owner;
  struct yxstm_slot* task_slot;

  if (!group || !member || group->yxstm_region < 0 ||
      !group->yxstm_base || !group->yxstm_size ||
      bank_id >= group->yxstm_bank_count)
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

  if (!yxstm_slice_mask_single(slice_mask, &slice_id) || !slice_id ||
      slice_id > KEYSTONE_YXSTM_WORKER_LANE_COUNT)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (!group_yxstm_layout_valid(group))
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;

  if (!yxstm_pmp_perm_from_flags(flags) ||
      (flags & ~(KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  slot_id = group->task_banks[bank_id].lane_rank;
  owner = group_yxstm_slot_member_for_slice_locked(group, slice_id, slot_id);
  if (!owner || !owner->yxstm_slot.valid ||
      (member->role == GROUP_ROLE_WORKER && owner != member))
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  task_slot = &owner->yxstm_slot;
  if (!task_slot->pmp_cache_valid || task_slot->pmp_entry_count != 2 ||
      !range_contains(group->yxstm_base, group->yxstm_size,
                      task_slot->base, task_slot->size))
    return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  writable = (flags & KEYSTONE_YXSTM_PERM_W) ? 1U : 0U;
  if (pmp_apply_cached_entries(task_slot->pmp_grant[writable],
                               task_slot->pmp_entry_count))
    return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
#if KEYSTONE_PMP_DEBUG_DUMP
  pmp_debug_dump_hart("yxstm_acquire");
#endif
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long yxstm_query_layout(enclave_id eid, uintptr_t out_buf,
                                 uintptr_t out_len)
{
  struct keystone_yxstm_layout_info info;
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  unsigned long ret;

  if (out_len != sizeof(info))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  sbi_memset(&info, 0, sizeof(info));
  sm_abi_fill(&info.abi, sizeof(info), KEYSTONE_YXSTM_ABI_FEATURES);

  spin_lock(&encl_lock);
  ret = yxstm_layout_member_context_locked(eid, &group, &member);
  if (ret) {
    spin_unlock(&encl_lock);
    return ret;
  }

  if (!range_contains(member->private_epm_base,
                      member->private_epm_size,
                      out_buf,
                      sizeof(info))) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  info.group_id = group->group_id;
  info.role = member->role;
  info.bound_hart = member->bound_hart;
  info.slice_count = KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
  info.slice_size = group->yxstm_bank_slice_size;
  info.allowed_slice_mask = member->allowed_slice_mask;
  info.master_slice_id = KEYSTONE_YXSTM_MASTER_SLICE_ID;
  if (member->role == GROUP_ROLE_WORKER) {
    uint64_t slice_id;
    info.worker_slice_id = KEYSTONE_GROUP_UNBOUND_HART;
    for (slice_id = 0; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT; slice_id++) {
      if (member->allowed_slice_mask & (1UL << slice_id)) {
        info.worker_slice_id = slice_id;
        break;
      }
    }
  } else {
    info.worker_slice_id = KEYSTONE_GROUP_UNBOUND_HART;
  }
  info.yxstm_va_base = KEYSTONE_YXSTM_ENCLAVE_VA_BASE;
  info.lane_id = member->lane_id;
  info.task_epoch = member->task_epoch;
  info.bank_count = group->yxstm_bank_count;
  info.bank_size = group_yxstm_bank_size(group);
  info.bank_slice_size = group->yxstm_bank_slice_size;
  info.bank_stride = group_yxstm_bank_size(group);
  info.task_queue_capacity = 64;
  info.worker_lane_count = KEYSTONE_YXSTM_WORKER_LANE_COUNT;
  info.worker_lane_size = KEYSTONE_YXSTM_WORKER_LANE_SIZE;
  info.mapping_pte_flags = member->audited_yxstm_pte_flags;
  info.mapping_leaf_count = member->audited_yxstm_leaf_count;
  info.mapping_min_leaf_size = member->audited_yxstm_min_leaf_size;
  info.mapping_max_leaf_size = member->audited_yxstm_max_leaf_size;
  /*
   * The walker rejects Sv39 reserved/PBMT bits and YXSTM is allocated from
   * Linux CMA or buddy RAM. Therefore the leaf inherits the JH7110 normal-DDR
   * PMA instead of selecting an MMIO/non-cacheable page type in the PTE.
   */
  info.mapping_cache_mode = KEYSTONE_YXSTM_CACHE_PLATFORM_DEFAULT;
  info.mapping_nx =
      member->audited_yxstm_leaf_count &&
      !(member->audited_yxstm_pte_flags & PTE_X);
  /*
   * The full page-table audit rejects aliases and requires
   * VA = canonical_base + (PA - group_yxstm_base) for every YXSTM leaf.
   */
  info.mapping_linear = member->audited_yxstm_leaf_count != 0;
  info.mapping_alias_count = 0;
  info.mapping_page_table_pages = member->audited_page_table_pages;
  info.mapping_tlb_counter_supported =
      KEYSTONE_YXSTM_TLB_COUNTER_UNAVAILABLE;
  info.mapping_alignment = member->audited_yxstm_alignment;
  info.mapping_hidden_copy_bytes = 0;
  info.slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
  if (member->role == GROUP_ROLE_WORKER && member->yxstm_slot.valid) {
    struct group_worker_lane* lane =
        group_lane_for_id_locked(group, member->lane_id);

    if (!lane || !lane->slots_frozen) {
      spin_unlock(&encl_lock);
      return SBI_ERR_SM_GROUP_BAD_STATE;
    }
    info.slot_id = member->yxstm_slot.slot_id;
    info.slot_count = lane->slot_count;
    info.slot_offset = member->yxstm_slot.base - lane->yxstm_base;
    info.slot_size = member->yxstm_slot.size;
    info.slot_payload_size = member->yxstm_slot.payload_capacity;
    info.slot_epoch = member->yxstm_slot.epoch;
    info.slot_state = member->yxstm_slot.state;
    info.lane_reserved_size = lane->reserved_size;
  }
  spin_unlock(&encl_lock);

  sbi_memcpy((void*)out_buf, &info, sizeof(info));
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long yxstm_query_slot(enclave_id eid, uintptr_t inout_buf,
                               uintptr_t inout_len)
{
  struct keystone_yxstm_slot_info info;
  struct enabled_group_slot* group;
  struct group_member_descriptor* caller;
  struct group_member_descriptor* owner;
  struct group_worker_lane* lane;
  unsigned long ret;

  if (inout_len != sizeof(info))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  spin_lock(&encl_lock);
  ret = yxstm_layout_member_context_locked(eid, &group, &caller);
  if (ret)
    goto out;
  if (!range_contains(caller->private_epm_base, caller->private_epm_size,
                      inout_buf, sizeof(info))) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  sbi_memcpy(&info, (void*)inout_buf, sizeof(info));
  ret = sm_abi_validate(&info.abi, sizeof(info),
                        KEYSTONE_YXSTM_ABI_FEATURES);
  if (ret)
    goto out;
  if (!group->yxstm_slots_frozen ||
      info.lane_id >= KEYSTONE_YXSTM_WORKER_LANE_COUNT) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }
  lane = group_lane_for_id_locked(group, info.lane_id);
  if (!lane || !lane->slots_frozen) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }
  if (caller->role == GROUP_ROLE_MASTER &&
      info.slot_id == KEYSTONE_YXSTM_INVALID_SLOT) {
    sbi_memset(&info, 0, sizeof(info));
    sm_abi_fill(&info.abi, sizeof(info), KEYSTONE_YXSTM_ABI_FEATURES);
    info.group_id = group->group_id;
    info.lane_id = lane->lane_id;
    info.slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
    info.owner_eid = ENCL_MAX;
    info.slot_count = lane->slot_count;
    info.slot_size = lane->slot_size;
    info.payload_size = lane->slot_payload_size;
    info.epoch = group->yxstm_slot_layout_epoch;
    sbi_memcpy((void*)inout_buf, &info, sizeof(info));
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    goto out;
  }
  owner = group_yxstm_slot_member_locked(group, info.lane_id, info.slot_id);
  if (!owner || (caller->role != GROUP_ROLE_MASTER && owner != caller)) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  sbi_memset(&info, 0, sizeof(info));
  sm_abi_fill(&info.abi, sizeof(info), KEYSTONE_YXSTM_ABI_FEATURES);
  info.group_id = group->group_id;
  info.lane_id = owner->yxstm_slot.lane_id;
  info.slot_id = owner->yxstm_slot.slot_id;
  info.owner_eid = owner->eid;
  info.slot_count = lane->slot_count;
  info.slot_offset = owner->yxstm_slot.base - lane->yxstm_base;
  info.slot_size = owner->yxstm_slot.size;
  info.payload_size = owner->yxstm_slot.payload_size;
  info.state = owner->yxstm_slot.state;
  info.batch_id = owner->yxstm_slot.batch_id;
  info.task_id = owner->yxstm_slot.task_id;
  info.sequence = owner->yxstm_slot.sequence;
  info.epoch = owner->yxstm_slot.epoch;
  info.permissions = owner->yxstm_slot.permissions;
  info.digest = owner->yxstm_slot.digest;
  sbi_memcpy((void*)inout_buf, &info, sizeof(info));
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
out:
  spin_unlock(&encl_lock);
  return ret;
}

static void yxstm_slot_clear_hart_grant_locked(struct group_hart_slot* hart)
{
  if (!hart)
    return;
  hart->yxstm_owner_eid = ENCL_MAX;
  hart->yxstm_acquired = 0;
  hart->yxstm_acquired_slice_mask = 0;
  hart->yxstm_permissions = 0;
  hart->yxstm_phase = YXSTM_PHASE_IDLE;
  hart->yxstm_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
  hart->yxstm_slot_lane = KEYSTONE_GROUP_UNBOUND_LANE;
  hart->yxstm_slot_id = KEYSTONE_YXSTM_INVALID_SLOT;
  hart->yxstm_slot_epoch = 0;
}

static unsigned long yxstm_slot_install_grant_locked(
    struct enabled_group_slot* group, struct group_hart_slot* hart,
    const struct group_member_descriptor* caller,
    const struct yxstm_slot* target, uintptr_t permissions)
{
  unsigned int writable;

  if (!group || !hart || !caller || !target || !target->valid ||
      !target->pmp_cache_valid || target->pmp_entry_count != 2 ||
      hart->yxstm_acquired || caller->yxstm_suspended_acquired ||
      (permissions != KEYSTONE_YXSTM_PERM_R &&
       permissions != (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W)))
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  writable = (permissions & KEYSTONE_YXSTM_PERM_W) ? 1U : 0U;
  asm volatile("fence rw,rw" ::: "memory");
  if (pmp_apply_cached_entries(target->pmp_grant[writable],
                               target->pmp_entry_count))
    return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  asm volatile("sfence.vma" ::: "memory");
  hart->yxstm_owner_eid = caller->eid;
  hart->yxstm_acquired = 1;
  hart->yxstm_acquired_slice_mask = 1UL << (target->lane_id + 1);
  hart->yxstm_permissions = permissions;
  hart->yxstm_phase = target->state;
  hart->yxstm_bank_id = GROUP_YXSTM_SLOT_GRANT_BANK;
  hart->yxstm_slot_lane = target->lane_id;
  hart->yxstm_slot_id = target->slot_id;
  hart->yxstm_slot_epoch = target->epoch;
  hart->pmp_epoch = group->permission_epoch;
  hart->phase_epoch = target->epoch;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long yxstm_slot_release_grant_locked(
    struct enabled_group_slot* group, struct group_hart_slot* hart,
    const struct group_member_descriptor* caller,
    const struct yxstm_slot* target)
{
  if (!group || !hart || !caller || !target || !hart->yxstm_acquired ||
      hart->yxstm_owner_eid != caller->eid ||
      hart->yxstm_bank_id != GROUP_YXSTM_SLOT_GRANT_BANK ||
      hart->yxstm_slot_lane != target->lane_id ||
      hart->yxstm_slot_id != target->slot_id ||
      hart->yxstm_slot_epoch != target->epoch)
    return SBI_ERR_SM_YXSTM_NOT_ACQUIRED;
  asm volatile("fence rw,rw" ::: "memory");
  pmp_set_keystone(group->yxstm_region, PMP_NO_PERM);
  asm volatile("sfence.vma" ::: "memory");
  yxstm_slot_clear_hart_grant_locked(hart);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static void yxstm_slot_wake_owner_locked(
    struct group_member_descriptor* owner, const char* where)
{
  if (!owner)
    return;
  if (!owner->lane_wait_pending) {
    if (owner->yxstm_slot.state == YXSTM_SLOT_READY)
      group_scheduler_kick_ready_member_locked(owner);
    return;
  }
  if (owner->lane_wait_task_bank != GROUP_LANE_WAIT_KIND_SLOT_READY)
    return;
  if (owner->lane_wait_phase != owner->yxstm_slot.lane_id ||
      owner->lane_wait_turn != owner->yxstm_slot.slot_id)
    return;
  if (owner->lane_wait_task_epoch &&
      owner->lane_wait_task_epoch != owner->yxstm_slot.epoch) {
    group_lane_wait_signal_locked(owner, SBI_ERR_SM_YXSTM_STALE_EPOCH,
                                  where);
    return;
  }
  if (owner->yxstm_slot.state == YXSTM_SLOT_READY)
    group_lane_wait_signal_locked(owner, SBI_ERR_SM_ENCLAVE_SUCCESS, where);
}

static int yxstm_slot_identity_matches(
    const struct yxstm_slot* slot,
    const struct keystone_yxstm_slot_command* command)
{
  return slot && command && slot->epoch == command->expected_epoch &&
         slot->batch_id == command->batch_id &&
         slot->task_id == command->task_id &&
         slot->sequence == command->sequence &&
         slot->payload_size == command->payload_size;
}

unsigned long yxstm_slot_command(enclave_id eid, uintptr_t inout_buf,
                                 uintptr_t inout_len)
{
  struct keystone_yxstm_slot_command command;
  struct enabled_group_slot* group;
  struct group_hart_slot* hart;
  struct group_member_descriptor* caller;
  struct group_member_descriptor* owner;
  struct group_worker_lane* target_lane;
  struct yxstm_slot* target;
  unsigned long hartid;
  unsigned long ret;
  uintptr_t wait_request_epoch = 0;
  int wait_blocked = 0;

  if (inout_len != sizeof(command))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  spin_lock(&encl_lock);
  ret = yxstm_current_member_context_locked(
      eid, &group, &hart, &caller, &hartid);
  if (ret)
    goto out;
  if (!range_contains(caller->private_epm_base, caller->private_epm_size,
                      inout_buf, sizeof(command))) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  sbi_memcpy(&command, (void*)inout_buf, sizeof(command));
  ret = sm_abi_validate(&command.abi, sizeof(command),
                        KEYSTONE_YXSTM_ABI_FEATURES);
  if (ret)
    goto out;
  if (command.reserved[0] || command.reserved[1]) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  if (!group->yxstm_slots_frozen ||
      command.lane_id >= KEYSTONE_YXSTM_WORKER_LANE_COUNT) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }
  owner = group_yxstm_slot_member_locked(
      group, command.lane_id, command.slot_id);
  if (!owner || !owner->yxstm_slot.valid ||
      (caller->role == GROUP_ROLE_WORKER && owner != caller) ||
      (caller->role != GROUP_ROLE_WORKER &&
       caller->role != GROUP_ROLE_MASTER)) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  target = &owner->yxstm_slot;
  target_lane = group_lane_for_id_locked(group, target->lane_id);
  if (!target_lane ||
      !group_yxstm_slot_metadata_valid(target_lane, owner)) {
    ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
    goto out;
  }
  command.result = KEYSTONE_YXSTM_SLOT_RESULT_READY;

  switch (command.operation) {
    case KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_ACQUIRE:
      if (caller->role != GROUP_ROLE_MASTER ||
          target->state != YXSTM_SLOT_FREE || !command.expected_epoch ||
          target->epoch != command.expected_epoch || !command.batch_id ||
          !command.task_id || !command.sequence || !command.payload_size ||
          command.payload_size > target->payload_capacity ||
          command.permissions !=
              (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W)) {
        ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
        goto out;
      }
      target->state = YXSTM_SLOT_DISPATCHING;
      target->batch_id = command.batch_id;
      target->task_id = command.task_id;
      target->sequence = command.sequence;
      target->payload_size = command.payload_size;
      target->permissions = command.permissions;
      target->digest = 0;
      ret = yxstm_slot_install_grant_locked(
          group, hart, caller, target, command.permissions);
      if (ret) {
        target->state = YXSTM_SLOT_FREE;
        target->batch_id = 0;
        target->task_id = 0;
        target->sequence = 0;
        target->payload_size = 0;
        target->permissions = 0;
      }
      break;

    case KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_PUBLISH:
      if (caller->role != GROUP_ROLE_MASTER ||
          target->state != YXSTM_SLOT_DISPATCHING ||
          !yxstm_slot_identity_matches(target, &command)) {
        ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
        goto out;
      }
      ret = yxstm_slot_release_grant_locked(group, hart, caller, target);
      if (ret)
        goto out;
      target->state = YXSTM_SLOT_READY;
      target->permissions = KEYSTONE_YXSTM_PERM_R;
      yxstm_protocol_barrier();
      yxstm_slot_wake_owner_locked(owner, "slot_dispatch_publish");
      break;

    case KEYSTONE_YXSTM_SLOT_WORKER_WAIT_READY:
    case KEYSTONE_YXSTM_SLOT_WORKER_WAIT_ACQUIRE_BEGIN:
      {
      int acquire_and_begin =
          command.operation ==
              KEYSTONE_YXSTM_SLOT_WORKER_WAIT_ACQUIRE_BEGIN;
      if (caller->role != GROUP_ROLE_WORKER || owner != caller ||
          hart->yxstm_acquired || caller->yxstm_suspended_acquired ||
          (acquire_and_begin &&
           command.permissions !=
               (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W))) {
        ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
        goto out;
      }
      /* Reaching the next wait proves the prior COMPUTE_DONE continuation ran. */
      caller->yxstm_completion_pending = 0;
      caller->yxstm_completion_epoch = 0;
      wait_request_epoch = caller->lane_wait_pending ?
          caller->lane_wait_task_epoch : command.expected_epoch;
      if (!caller->lane_wait_pending && command.expected_epoch &&
          command.expected_epoch != target->epoch) {
        ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
        goto out;
      }
      /*
       * WAIT_READY spans an enclave -> HOST -> enclave context round trip
       * when a lane has no runnable peer.  The runtime deliberately reissues
       * the command after it resumes so that the slot table, rather than a
       * stale userspace buffer, remains authoritative.  Treat that reissue as
       * consumption of the existing wait instead of rejecting it as a nested
       * wait.  This also closes the narrow wake/resume race where the member
       * is runnable before the original wait metadata has been consumed.
       */
      if (caller->lane_wait_pending) {
        unsigned long wait_result = caller->lane_wait_result;

        if (caller->lane_wait_task_bank !=
                GROUP_LANE_WAIT_KIND_SLOT_READY ||
            caller->lane_wait_phase != target->lane_id ||
            caller->lane_wait_turn != target->slot_id ||
            (caller->lane_wait_task_epoch &&
             caller->lane_wait_task_epoch != target->epoch)) {
          ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
          goto out;
        }
        if (!caller->lane_wait_ready &&
            target->state != YXSTM_SLOT_READY) {
          command.result = KEYSTONE_YXSTM_SLOT_RESULT_BLOCK;
          wait_blocked = 1;
          ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
          break;
        }
        group_lane_wait_account_and_clear_locked(caller);
        group_member_timer_ready[eid] = 1;
        if (wait_result != SBI_ERR_SM_ENCLAVE_SUCCESS) {
          ret = wait_result;
          goto out;
        }
      }
      if (target->state != YXSTM_SLOT_READY) {
        caller->lane_wait_sequence = 0;
        caller->lane_wait_turn = target->slot_id;
        caller->lane_wait_phase = target->lane_id;
        caller->lane_wait_task_epoch = command.expected_epoch;
        caller->lane_wait_result = SBI_ERR_SM_ENCLAVE_SUCCESS;
        caller->lane_wait_started_at = sbi_timer_value();
        caller->lane_wait_pending = 1;
        caller->lane_wait_task_bank = GROUP_LANE_WAIT_KIND_SLOT_READY;
        caller->lane_wait_ready = 0;
        caller->lane_wait_context_saved = 0;
        group_member_timer_ready[eid] = 0;
        command.result = KEYSTONE_YXSTM_SLOT_RESULT_BLOCK;
        wait_blocked = 1;
        atomic_add_return(&group_perf_lane_wait_block_count, 1);
      } else if (acquire_and_begin) {
        ret = yxstm_slot_install_grant_locked(
            group, hart, caller, target, command.permissions);
        if (ret)
          goto out;
        target->state = YXSTM_SLOT_COMPUTING;
        target->permissions = command.permissions;
        hart->yxstm_phase = YXSTM_SLOT_COMPUTING;
        ret = group_member_perf_aes_transition_locked(
            caller, target->epoch, 1);
        if (ret) {
          yxstm_slot_release_grant_locked(group, hart, caller, target);
          target->state = YXSTM_SLOT_READY;
          target->permissions = KEYSTONE_YXSTM_PERM_R;
          goto out;
        }
      }
      ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
      }
      break;

    case KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_ACQUIRE:
      if (caller->role != GROUP_ROLE_WORKER || owner != caller ||
          target->state != YXSTM_SLOT_READY ||
          !yxstm_slot_identity_matches(target, &command) ||
          command.permissions !=
              (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W)) {
        ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
        goto out;
      }
      ret = yxstm_slot_install_grant_locked(
          group, hart, caller, target, command.permissions);
      if (ret)
        goto out;
      target->state = YXSTM_SLOT_COMPUTING;
      target->permissions = command.permissions;
      hart->yxstm_phase = YXSTM_SLOT_COMPUTING;
      break;

    case KEYSTONE_YXSTM_SLOT_WORKER_AES_EXEC_BEGIN:
    case KEYSTONE_YXSTM_SLOT_WORKER_AES_EXEC_END:
      if (caller->role != GROUP_ROLE_WORKER || owner != caller ||
          target->state != YXSTM_SLOT_COMPUTING ||
          !yxstm_slot_identity_matches(target, &command) ||
          !hart->yxstm_acquired ||
          hart->yxstm_owner_eid != caller->eid ||
          hart->yxstm_bank_id != GROUP_YXSTM_SLOT_GRANT_BANK ||
          hart->yxstm_slot_lane != target->lane_id ||
          hart->yxstm_slot_id != target->slot_id ||
          hart->yxstm_slot_epoch != target->epoch) {
        ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
        goto out;
      }
      ret = group_member_perf_aes_transition_locked(
          caller, target->epoch,
          command.operation == KEYSTONE_YXSTM_SLOT_WORKER_AES_EXEC_BEGIN);
      if (ret)
        goto out;
      break;

    case KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_DONE:
      if (caller->role != GROUP_ROLE_WORKER || owner != caller ||
          target->state != YXSTM_SLOT_COMPUTING ||
          !yxstm_slot_identity_matches(target, &command) ||
          !command.digest || caller->perf_aes_exec_active) {
        ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
        goto out;
      }
      ret = yxstm_slot_release_grant_locked(group, hart, caller, target);
      if (ret)
        goto out;
      target->digest = command.digest;
      target->state = YXSTM_SLOT_DONE;
      target->permissions = 0;
      caller->yxstm_completion_pending = 1;
      caller->yxstm_completion_epoch = target->epoch;
      yxstm_protocol_barrier();
      {
        enclave_id master_eid = ENCL_MAX;
        size_t member_index;

        for (member_index = 0;
             member_index < group->member_metadata_capacity; member_index++)
          if (group->members[member_index].valid &&
              group->members[member_index].role == GROUP_ROLE_MASTER) {
            master_eid = group->members[member_index].eid;
            break;
          }
        if (master_eid != ENCL_MAX && ENCLAVE_EXISTS(master_eid))
          (void)group_scheduler_event_enqueue(
              hartid, group->group_id, group->generation,
              master_eid, enclaves[master_eid].generation,
              KEYSTONE_GROUP_EVENT_WORKERS_READY,
              SBI_ERR_SM_ENCLAVE_SUCCESS,
              ((uint64_t)YXSTM_PHASE_COMPUTE << 56) |
                  (target->epoch & UINT64_C(0x0000ffffffffffff)));
      }
      break;

    case KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_ACQUIRE:
      if (caller->role != GROUP_ROLE_MASTER ||
          target->state != YXSTM_SLOT_DONE ||
          !yxstm_slot_identity_matches(target, &command) ||
          target->digest != command.digest ||
          command.permissions != KEYSTONE_YXSTM_PERM_R) {
        ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
        goto out;
      }
      ret = yxstm_slot_install_grant_locked(
          group, hart, caller, target, command.permissions);
      if (ret)
        goto out;
      target->state = YXSTM_SLOT_AGGREGATING;
      target->permissions = KEYSTONE_YXSTM_PERM_R;
      hart->yxstm_phase = YXSTM_SLOT_AGGREGATING;
      break;

    case KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_COMPLETE:
      if (caller->role != GROUP_ROLE_MASTER ||
          target->state != YXSTM_SLOT_AGGREGATING ||
          !yxstm_slot_identity_matches(target, &command) ||
          target->digest != command.digest) {
        ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
        goto out;
      }
      ret = yxstm_slot_release_grant_locked(group, hart, caller, target);
      if (ret)
        goto out;
      target->state = YXSTM_SLOT_FREE;
      target->batch_id = 0;
      target->task_id = 0;
      target->sequence = 0;
      target->payload_size = 0;
      target->permissions = 0;
      target->digest = 0;
      target->epoch++;
      if (!target->epoch)
        target->epoch = 1;
      yxstm_protocol_barrier();
      group_scheduler_kick_completion_locked(owner);
      break;

    case KEYSTONE_YXSTM_SLOT_MASTER_FINISH_AND_ACQUIRE:
      {
        struct group_member_descriptor* current_owner;
        struct group_worker_lane* current_lane;
        struct yxstm_slot* current;
        unsigned int writable;
        uint64_t current_state;
        uint64_t next_epoch;

        if (caller->role != GROUP_ROLE_MASTER ||
            !hart->yxstm_acquired ||
            hart->yxstm_owner_eid != caller->eid ||
            hart->yxstm_bank_id != GROUP_YXSTM_SLOT_GRANT_BANK) {
          ret = SBI_ERR_SM_YXSTM_NOT_ACQUIRED;
          goto out;
        }
        current_owner = group_yxstm_slot_member_locked(
            group, hart->yxstm_slot_lane, hart->yxstm_slot_id);
        if (!current_owner || !current_owner->yxstm_slot.valid) {
          ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
          goto out;
        }
        current = &current_owner->yxstm_slot;
        current_lane = group_lane_for_id_locked(group, current->lane_id);
        if (!current_lane ||
            !group_yxstm_slot_metadata_valid(current_lane, current_owner) ||
            hart->yxstm_slot_epoch != current->epoch ||
            (current->state != YXSTM_SLOT_DISPATCHING &&
             current->state != YXSTM_SLOT_AGGREGATING)) {
          ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
          goto out;
        }
        current_state = current->state;
        next_epoch = current == target &&
                     current_state == YXSTM_SLOT_AGGREGATING ?
                         current->epoch + 1 : target->epoch;
        if (!next_epoch)
          next_epoch = 1;
        if (command.permissions ==
                (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W)) {
          if ((target != current && target->state != YXSTM_SLOT_FREE) ||
              (target == current &&
               current_state != YXSTM_SLOT_AGGREGATING) ||
              command.expected_epoch != next_epoch ||
              !command.batch_id || !command.task_id ||
              !command.sequence || !command.payload_size ||
              command.payload_size > target->payload_capacity) {
            ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
            goto out;
          }
          writable = 1;
        } else if (command.permissions == KEYSTONE_YXSTM_PERM_R) {
          if (target == current || target->state != YXSTM_SLOT_DONE ||
              !yxstm_slot_identity_matches(target, &command) ||
              target->digest != command.digest) {
            ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
            goto out;
          }
          writable = 0;
        } else {
          ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
          goto out;
        }
        if (!target->pmp_cache_valid || target->pmp_entry_count != 2) {
          ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
          goto out;
        }

        /* Replace the old slot aperture directly; never expose both slots. */
        asm volatile("fence rw,rw" ::: "memory");
        if (pmp_apply_cached_entries(target->pmp_grant[writable],
                                     target->pmp_entry_count)) {
          ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
          goto out;
        }
        asm volatile("sfence.vma" ::: "memory");

        if (current_state == YXSTM_SLOT_DISPATCHING) {
          current->state = YXSTM_SLOT_READY;
          current->permissions = KEYSTONE_YXSTM_PERM_R;
          yxstm_slot_wake_owner_locked(
              current_owner, "slot_dispatch_switch_publish");
        } else {
          current->state = YXSTM_SLOT_FREE;
          current->batch_id = 0;
          current->task_id = 0;
          current->sequence = 0;
          current->payload_size = 0;
          current->permissions = 0;
          current->digest = 0;
          current->epoch++;
          if (!current->epoch)
            current->epoch = 1;
          group_scheduler_kick_completion_locked(current_owner);
        }

        if (writable) {
          target->state = YXSTM_SLOT_DISPATCHING;
          target->batch_id = command.batch_id;
          target->task_id = command.task_id;
          target->sequence = command.sequence;
          target->payload_size = command.payload_size;
          target->permissions = command.permissions;
          target->digest = 0;
        } else {
          target->state = YXSTM_SLOT_AGGREGATING;
          target->permissions = KEYSTONE_YXSTM_PERM_R;
        }
        hart->yxstm_acquired = 1;
        hart->yxstm_owner_eid = caller->eid;
        hart->yxstm_acquired_slice_mask =
            1UL << (target->lane_id + 1);
        hart->yxstm_permissions = command.permissions;
        hart->yxstm_phase = target->state;
        hart->yxstm_bank_id = GROUP_YXSTM_SLOT_GRANT_BANK;
        hart->yxstm_slot_lane = target->lane_id;
        hart->yxstm_slot_id = target->slot_id;
        hart->yxstm_slot_epoch = target->epoch;
        hart->pmp_epoch = group->permission_epoch;
        hart->phase_epoch = target->epoch;
        yxstm_protocol_barrier();
        if (current != target &&
            !group_yxstm_slot_metadata_valid(current_lane, current_owner)) {
          ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
          goto out;
        }
      }
      break;

    default:
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      goto out;
  }
  if (ret)
    goto out;
  if (!group_yxstm_slot_metadata_valid(target_lane, owner)) {
    ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
    goto out;
  }
  command.state = target->state;
  /*
   * WAIT_READY may sleep while the master aggregates the previous batch,
   * increments the slot epoch, and publishes the next batch.  Preserve the
   * request token while returning BLOCK; otherwise the runtime reissues WAIT
   * with the old observed epoch and spuriously receives STALE_EPOCH.  Once a
   * READY object is consumed, return its authoritative current epoch.
   */
  command.expected_epoch = wait_blocked ? wait_request_epoch : target->epoch;
  command.batch_id = target->batch_id;
  command.task_id = target->task_id;
  command.sequence = target->sequence;
  command.payload_size = target->payload_size;
  command.permissions =
      wait_blocked &&
      command.operation == KEYSTONE_YXSTM_SLOT_WORKER_WAIT_ACQUIRE_BEGIN ?
          (KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W) :
          target->permissions;
  command.digest = target->digest;
  sm_abi_fill(&command.abi, sizeof(command), KEYSTONE_YXSTM_ABI_FEATURES);
  sbi_memcpy((void*)inout_buf, &command, sizeof(command));
out:
  spin_unlock(&encl_lock);
  return ret;
}

static unsigned long yxstm_acquire_mask_checked(enclave_id eid,
                                                uintptr_t slice_mask,
                                                uintptr_t flags,
                                                uintptr_t phase,
                                                uintptr_t expected_epoch)
{
  struct enabled_group_slot* group = 0;
  struct group_hart_slot* slot = 0;
  struct group_member_descriptor* member = 0;
  unsigned long hartid = csr_read(mhartid);
  unsigned long ret;
  uintptr_t slice_id;
  unsigned long perf_start = csr_read(CSR_MCYCLE);

  spin_lock(&encl_lock);
  ret = yxstm_current_member_context_locked(eid, &group, &slot, &member, &hartid);
  if (ret)
    goto out;

  if (yxstm_protocol_timeout_locked(group)) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  if (yxstm_task_bank_any_active_locked(group)) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  if (group->yxstm_rollback_reason != YXSTM_ROLLBACK_NONE) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  if (expected_epoch != group->yxstm_phase_epoch) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  if (phase != group->yxstm_phase || phase == YXSTM_PHASE_IDLE) {
    ret = SBI_ERR_SM_YXSTM_PHASE;
    goto out;
  }

  if (member->task_epoch != group->yxstm_task_epoch) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }

  if (member->role == GROUP_ROLE_WORKER) {
    struct group_worker_lane* lane =
        group_lane_for_id_locked(group, member->lane_id);
    if (!lane || lane->active_eid != eid ||
        lane->active_eid_generation != enclaves[eid].generation ||
        lane->task_epoch != group->yxstm_task_epoch ||
        member->task_epoch != lane->task_epoch) {
      ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
      goto out;
    }
  }

  ret = yxstm_validate_member_access_locked(group, member, slice_mask,
                                            flags, phase);
  if (ret) {
    sbi_printf("[SM][yxstm] acquire denied: group=%lu eid=%u hart=%lu role=%lu allowed=0x%lx request_mask=0x%lx flags=0x%lx phase=%lu ret=%lu\n",
               (unsigned long)group->group_id,
               eid,
               hartid,
               (unsigned long)member->role,
               (unsigned long)member->allowed_slice_mask,
               (unsigned long)slice_mask,
               (unsigned long)flags,
               (unsigned long)phase,
               ret);
    goto out;
  }

  /* Repeated and nested acquire are both protocol errors. */
  if (slot->yxstm_acquired || member->yxstm_suspended_acquired) {
    ret = SBI_ERR_SM_YXSTM_ALREADY_ACQUIRED;
    goto out;
  }

  if (member->role == GROUP_ROLE_WORKER &&
      phase == YXSTM_PHASE_DISPATCH &&
      group->yxstm_published_sequence != group->yxstm_sequence) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }

  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    if ((slice_mask & (1UL << slice_id)) &&
        (!(group->yxstm_active_worker_mask & (1UL << slice_id)) ||
         !yxstm_protocol_header_valid_locked(group, slice_id))) {
      ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      goto out;
    }
  }

  /* Validation is complete before the single PMP write: all-or-nothing. */
  ret = yxstm_install_pmp_for_mask_locked(group, member, slice_mask, flags);
  if (ret)
    goto out;

  yxstm_protocol_barrier();
  slot->yxstm_acquired = 1;
  slot->yxstm_owner_eid = eid;
  slot->yxstm_acquired_slice_mask = slice_mask;
  slot->yxstm_permissions = flags;
  slot->yxstm_phase = phase;
  slot->yxstm_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
  slot->pmp_epoch = group->permission_epoch;
  slot->phase_epoch = group->yxstm_phase_epoch;
  if (flags & KEYSTONE_YXSTM_PERM_W)
    group_mark_yxstm_bank_dirty_locked(group, 0, slice_mask);
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

out:
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    sbi_printf("[SM][yxstm] acquire failed: eid=%u hart=%lu group=%lu role=%lu mask=0x%lx flags=0x%lx requested_phase=%lu current_phase=%lu expected_epoch=%lu current_epoch=%lu member_task=%lu group_task=%lu ret=%lu\n",
               eid, hartid,
               group ? (unsigned long)group->group_id : 0,
               member ? (unsigned long)member->role : 0,
               (unsigned long)slice_mask, (unsigned long)flags,
               (unsigned long)phase,
               group ? (unsigned long)group->yxstm_phase : 0,
               (unsigned long)expected_epoch,
               group ? (unsigned long)group->yxstm_phase_epoch : 0,
               member ? (unsigned long)member->task_epoch : 0,
               group ? (unsigned long)group->yxstm_task_epoch : 0,
               ret);
  }
  spin_unlock(&encl_lock);
  if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS) {
    atomic_add_return(&group_perf_acquire_count, 1);
    atomic_add_return(&group_perf_acquire_cycles,
                      (long)(csr_read(CSR_MCYCLE) - perf_start));
  }
  return ret;
}

unsigned long yxstm_acquire_slice(enclave_id eid, uintptr_t slice_id,
                                  uintptr_t flags, uintptr_t phase,
                                  uintptr_t expected_epoch)
{
  if (slice_id >= KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return yxstm_acquire_mask_checked(eid, 1UL << slice_id, flags, phase,
                                    expected_epoch);
}

unsigned long yxstm_acquire_mask(enclave_id eid, uintptr_t slice_mask,
                                 uintptr_t flags, uintptr_t phase,
                                 uintptr_t expected_epoch)
{
  return yxstm_acquire_mask_checked(eid, slice_mask, flags, phase,
                                    expected_epoch);
}

static unsigned long yxstm_release_mask_checked(enclave_id eid,
                                                uintptr_t slice_mask,
                                                uintptr_t expected_epoch)
{
  struct enabled_group_slot* group = 0;
  struct group_hart_slot* slot = 0;
  struct group_member_descriptor* member = 0;
  unsigned long hartid = csr_read(mhartid);
  unsigned long ret;
  unsigned long perf_start = csr_read(CSR_MCYCLE);

  if (!slice_mask ||
      (slice_mask & ~KEYSTONE_YXSTM_MASTER_SLICE_MASK))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  ret = yxstm_current_member_context_locked(eid, &group, &slot, &member, &hartid);
  if (ret)
    goto out;

  if (yxstm_protocol_timeout_locked(group) ||
      expected_epoch != group->yxstm_phase_epoch) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }

  if (!slot->yxstm_acquired) {
    ret = SBI_ERR_SM_YXSTM_NOT_ACQUIRED;
    goto out;
  }

  if (member->task_epoch != group->yxstm_task_epoch) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }

  if (slot->yxstm_owner_eid != eid ||
      slice_mask != slot->yxstm_acquired_slice_mask) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  if (slot->yxstm_phase != group->yxstm_phase) {
    ret = SBI_ERR_SM_YXSTM_PHASE;
    goto out;
  }

  if (group->yxstm_region >= 0) {
    yxstm_protocol_barrier();
    if (pmp_set_keystone(group->yxstm_region, PMP_NO_PERM)) {
      ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
      goto out;
    }
  }
  asm volatile("sfence.vma" ::: "memory");
  yxstm_protocol_barrier();

  slot->yxstm_acquired = 0;
  slot->yxstm_owner_eid = ENCL_MAX;
  slot->yxstm_acquired_slice_mask = 0;
  slot->yxstm_permissions = 0;
  slot->yxstm_phase = YXSTM_PHASE_IDLE;
  slot->yxstm_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
  slot->pmp_epoch = group->permission_epoch;
  slot->phase_epoch = group->yxstm_phase_epoch;
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

out:
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    sbi_printf("[SM][yxstm] release failed: eid=%u hart=%lu group=%lu role=%lu request_mask=0x%lx owner=%u acquired=%lu acquired_mask=0x%lx slot_phase=%lu current_phase=%lu expected_epoch=%lu current_epoch=%lu member_task=%lu group_task=%lu ret=%lu\n",
               eid, hartid,
               group ? (unsigned long)group->group_id : 0,
               member ? (unsigned long)member->role : 0,
               (unsigned long)slice_mask,
               slot ? slot->yxstm_owner_eid : ENCL_MAX,
               slot ? (unsigned long)slot->yxstm_acquired : 0,
               slot ? (unsigned long)slot->yxstm_acquired_slice_mask : 0,
               slot ? (unsigned long)slot->yxstm_phase : 0,
               group ? (unsigned long)group->yxstm_phase : 0,
               (unsigned long)expected_epoch,
               group ? (unsigned long)group->yxstm_phase_epoch : 0,
               member ? (unsigned long)member->task_epoch : 0,
               group ? (unsigned long)group->yxstm_task_epoch : 0,
               ret);
  }
  spin_unlock(&encl_lock);
  if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS) {
    atomic_add_return(&group_perf_release_count, 1);
    atomic_add_return(&group_perf_release_cycles,
                      (long)(csr_read(CSR_MCYCLE) - perf_start));
  }
  return ret;
}

unsigned long yxstm_release_slice(enclave_id eid, uintptr_t slice_id,
                                  uintptr_t expected_epoch)
{
  if (slice_id >= KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return yxstm_release_mask_checked(eid, 1UL << slice_id, expected_epoch);
}

unsigned long yxstm_release_mask(enclave_id eid, uintptr_t slice_mask,
                                 uintptr_t expected_epoch)
{
  return yxstm_release_mask_checked(eid, slice_mask, expected_epoch);
}

static void yxstm_protocol_fill_state_locked(
    struct enabled_group_slot* group,
    struct keystone_yxstm_protocol_state* state)
{
  sbi_memset(state, 0, sizeof(*state));
  sm_abi_fill(&state->abi, sizeof(*state), KEYSTONE_YXSTM_ABI_FEATURES);
  state->group_id = group->group_id;
  state->group_generation = group->generation;
  state->security_policy_version = group->security_policy_version;
  state->phase = group->yxstm_phase;
  state->phase_epoch = group->yxstm_phase_epoch;
  state->session_epoch = group->session_epoch;
  state->membership_epoch = group->membership_epoch;
  state->sequence = group->yxstm_sequence;
  state->published_sequence = group->yxstm_published_sequence;
  state->active_worker_mask = group->yxstm_active_worker_mask;
  state->ready_bitmap = group->yxstm_ready_bitmap;
  state->done_bitmap = group->yxstm_done_bitmap;
  state->payload_length = group->yxstm_payload_length;
  state->deadline = group->yxstm_deadline;
  state->rollback_reason = group->yxstm_rollback_reason;
  state->channel_version = KEYSTONE_YXSTM_CHANNEL_VERSION;
  state->task_epoch = group->yxstm_task_epoch;
}

static void yxstm_task_bank_fill_state_locked(
    uintptr_t bank_id, const struct group_task_bank_protocol* bank,
    struct keystone_yxstm_task_bank_state* state)
{
  sbi_memset(state, 0, sizeof(*state));
  state->bank_id = bank_id;
  state->phase = bank->phase;
  state->phase_epoch = bank->phase_epoch;
  state->task_epoch = bank->task_epoch;
  state->sequence = bank->sequence;
  state->published_sequence = bank->published_sequence;
  state->active_worker_mask = bank->active_worker_mask;
  state->ready_bitmap = bank->ready_bitmap;
  state->done_bitmap = bank->done_bitmap;
  state->payload_length = bank->payload_length;
  state->deadline = bank->deadline;
  state->rollback_reason = bank->rollback_reason;
  state->commit_epoch = bank->commit_epoch;
  state->task_digest = bank->task_digest;
  state->lane_rank = bank->lane_rank;
}

static int group_member_resolve_readonly_user_page(
    const struct group_member_descriptor* member, uintptr_t user_va,
    uintptr_t* page_paddr)
{
  uintptr_t table_pa;
  uintptr_t canonical_va;
  int level;

  if (!member || !page_paddr || !member->page_table_root ||
      (user_va & (RISCV_PGSIZE - 1)) ||
      !group_pt_canonicalize_va(user_va, &canonical_va) ||
      canonical_va != user_va)
    return 0;

  table_pa = member->page_table_root;
  for (level = RISCV_PGLEVEL_TOP - 1; level >= 0; level--) {
    uintptr_t* table;
    uintptr_t index;
    uintptr_t pte;
    uintptr_t pte_pa;

    if (!range_contains(member->private_epm_base, member->private_epm_size,
                        table_pa, RISCV_PGSIZE))
      return 0;
    table = (uintptr_t*)table_pa;
    index = (user_va >>
             (RISCV_PGSHIFT + level * RISCV_PGLEVEL_BITS)) &
            (((uintptr_t)1 << RISCV_PGLEVEL_BITS) - 1);
    pte = table[index];
    if (!(pte & PTE_V) || (pte & PTE_G) ||
        ((pte & PTE_W) && !(pte & PTE_R)))
      return 0;
    pte_pa = (pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;
    if (pte & (PTE_R | PTE_W | PTE_X)) {
      uintptr_t leaf_size = (uintptr_t)1 <<
          (RISCV_PGSHIFT + level * RISCV_PGLEVEL_BITS);
      uintptr_t leaf_offset = canonical_va & (leaf_size - 1);
      uintptr_t resolved_paddr;

      /*
       * The mailbox integrity property is read-only U-mode access. Static
       * linkers may place const data in an R-X PT_LOAD, and a measured runtime
       * may use a larger read-only leaf. Neither permits the enclave to alter
       * SM-published state, so accept both while resolving the exact 4 KiB
       * physical page. YXSTM itself remains NX under the separate region
       * policy.
       */
      if (!(pte & PTE_R) || !(pte & PTE_U) || (pte & PTE_W) ||
          (pte_pa & (leaf_size - 1)) ||
          leaf_offset > leaf_size - RISCV_PGSIZE ||
          pte_pa > ~(uintptr_t)0 - leaf_offset) {
        sbi_printf("[SM][yxstm] mailbox leaf rejected: group=%lu eid=%u "
                   "va=0x%lx level=%d pte=0x%lx leaf_pa=0x%lx\n",
                   (unsigned long)member->group_id, member->eid,
                   (unsigned long)user_va, level, (unsigned long)pte,
                   (unsigned long)pte_pa);
        return 0;
      }
      resolved_paddr = pte_pa + leaf_offset;
      if (!range_contains(member->private_epm_base,
                          member->private_epm_size,
                          resolved_paddr, RISCV_PGSIZE))
        return 0;
      *page_paddr = resolved_paddr;
      return 1;
    }
    if (level == 0 || (pte & (PTE_U | PTE_A | PTE_D | PTE_SOFT)))
      return 0;
    table_pa = pte_pa;
  }
  return 0;
}

static void yxstm_protocol_publish_mailboxes_locked(
    struct enabled_group_slot* group)
{
  struct keystone_yxstm_protocol_state state;
  size_t i;

  if (!group)
    return;
  yxstm_protocol_fill_state_locked(group, &state);
  for (i = 0; i < group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];
    struct keystone_yxstm_protocol_mailbox* mailbox;
    uintptr_t sequence;
    uintptr_t bank_id;

    if (!member->valid || !member->protocol_mailbox_registered ||
        (member->protocol_mailbox_flags & KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK_ONLY) ||
        member->protocol_mailbox_size != KEYSTONE_YXSTM_MAILBOX_PAGE_SIZE ||
        !range_contains(member->private_epm_base, member->private_epm_size,
                        member->protocol_mailbox_paddr,
                        KEYSTONE_YXSTM_MAILBOX_PAGE_SIZE))
      continue;

    mailbox = (struct keystone_yxstm_protocol_mailbox*)
        member->protocol_mailbox_paddr;
    sequence = mailbox->publish_sequence;
    if (sequence & 1)
      sequence++;
    if (sequence > ~(uintptr_t)0 - 2)
      sequence = 0;
    mailbox->publish_sequence = sequence + 1;
    yxstm_protocol_barrier();
    mailbox->magic = KEYSTONE_YXSTM_MAILBOX_MAGIC;
    mailbox->version = KEYSTONE_YXSTM_MAILBOX_VERSION;
    mailbox->flags = member->protocol_mailbox_flags;
    sbi_memcpy(&mailbox->state, &state, sizeof(state));
    mailbox->task_bank_count = group->yxstm_bank_count;
    for (bank_id = 0; bank_id < KEYSTONE_YXSTM_MAX_BANKS; bank_id++)
      yxstm_task_bank_fill_state_locked(
          bank_id, &group->task_banks[bank_id],
          &mailbox->task_banks[bank_id]);
    yxstm_protocol_barrier();
    mailbox->publish_sequence = sequence + 2;
    yxstm_protocol_barrier();
  }
}

unsigned long yxstm_register_mailbox(enclave_id eid, uintptr_t request_buf,
                                     uintptr_t request_len)
{
  struct keystone_yxstm_mailbox_registration request;
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  uintptr_t mailbox_paddr = 0;
  unsigned long ret;

  if (request_len != sizeof(request)) {
    sbi_printf("[SM][yxstm] mailbox request size rejected: eid=%u got=0x%lx "
               "expected=0x%lx\n",
               eid, (unsigned long)request_len,
               (unsigned long)sizeof(request));
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  spin_lock(&encl_lock);
  ret = yxstm_layout_member_context_locked(eid, &group, &member);
  if (ret)
    goto out;
  if (!range_contains(member->private_epm_base, member->private_epm_size,
                      request_buf, sizeof(request))) {
    sbi_printf("[SM][yxstm] mailbox request buffer rejected: hart=%lu eid=%u "
               "buffer=0x%lx private=0x%lx/0x%lx\n",
               (unsigned long)csr_read(mhartid), eid,
               (unsigned long)request_buf,
               (unsigned long)member->private_epm_base,
               (unsigned long)member->private_epm_size);
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  sbi_memcpy(&request, (void*)request_buf, sizeof(request));
  ret = sm_abi_validate(&request.abi, sizeof(request),
                        KEYSTONE_YXSTM_ABI_FEATURES);
  if (ret) {
    sbi_printf("[SM][yxstm] mailbox ABI rejected: hart=%lu eid=%u ret=%lu "
               "version=0x%lx size=0x%lx features=0x%lx reserved=0x%lx\n",
               (unsigned long)csr_read(mhartid), eid, ret,
               (unsigned long)request.abi.version,
               (unsigned long)request.abi.struct_size,
               (unsigned long)request.abi.features,
               (unsigned long)request.abi.reserved);
    goto out;
  }
  if (request.reserved ||
      request.mailbox_size != KEYSTONE_YXSTM_MAILBOX_PAGE_SIZE ||
      (request.flags & ~(KEYSTONE_YXSTM_MAILBOX_FLAG_PERF_QUIET |
                         KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK |
                         KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK_ONLY)) ||
      ((request.flags & KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK_ONLY) &&
       !(request.flags & KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK)) ||
      ((request.flags & KEYSTONE_YXSTM_MAILBOX_FLAG_PERF_QUIET) &&
       member->role != GROUP_ROLE_MASTER)) {
    sbi_printf("[SM][yxstm] mailbox registration rejected: hart=%lu eid=%u "
               "role=%lu va=0x%lx size=0x%lx flags=0x%lx reserved=0x%lx\n",
               (unsigned long)csr_read(mhartid), eid,
               (unsigned long)member->role,
               (unsigned long)request.mailbox_va,
               (unsigned long)request.mailbox_size,
               (unsigned long)request.flags,
               (unsigned long)request.reserved);
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  if (!group_member_resolve_readonly_user_page(
          member, request.mailbox_va, &mailbox_paddr)) {
    sbi_printf("[SM][yxstm] mailbox page rejected: hart=%lu group=%lu eid=%u "
               "va=0x%lx root=0x%lx private=0x%lx/0x%lx\n",
               (unsigned long)csr_read(mhartid),
               (unsigned long)member->group_id, eid,
               (unsigned long)request.mailbox_va,
               (unsigned long)member->page_table_root,
               (unsigned long)member->private_epm_base,
               (unsigned long)member->private_epm_size);
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  if (member->protocol_mailbox_registered &&
      (member->protocol_mailbox_va != request.mailbox_va ||
       member->protocol_mailbox_paddr != mailbox_paddr)) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }

  member->protocol_mailbox_va = request.mailbox_va;
  member->protocol_mailbox_paddr = mailbox_paddr;
  member->protocol_mailbox_size = request.mailbox_size;
  member->protocol_mailbox_flags = request.flags;
  member->protocol_mailbox_registered = 1;
  if (request.flags & KEYSTONE_YXSTM_MAILBOX_FLAG_PERF_QUIET)
    group->yxstm_perf_quiet = 1;
  yxstm_protocol_publish_mailboxes_locked(group);
  group_member_publish_exec_clock_locked(member, sbi_timer_value(), 1);
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
out:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long yxstm_query_protocol(enclave_id eid, uintptr_t out_buf,
                                   uintptr_t out_len)
{
  struct keystone_yxstm_protocol_state state;
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  unsigned long ret;

  if (out_len != sizeof(state))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  ret = yxstm_layout_member_context_locked(eid, &group, &member);
  if (ret)
    goto out;
  if (!range_contains(member->private_epm_base, member->private_epm_size,
                      out_buf, sizeof(state))) {
    sbi_printf("[SM][yxstm] query buffer rejected: hart=%lu eid=%u out=0x%lx size=0x%lx private=0x%lx/0x%lx\n",
               (unsigned long)csr_read(mhartid), eid,
               (unsigned long)out_buf, (unsigned long)sizeof(state),
               (unsigned long)member->private_epm_base,
               (unsigned long)member->private_epm_size);
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  (void)yxstm_protocol_timeout_locked(group);
  yxstm_protocol_fill_state_locked(group, &state);
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
out:
  spin_unlock(&encl_lock);
  if (!ret)
    sbi_memcpy((void*)out_buf, &state, sizeof(state));
  return ret;
}

static unsigned long yxstm_protocol_validate_transition_locked(
    struct enabled_group_slot* group,
    const struct keystone_yxstm_phase_transition* request)
{
  size_t slice_size;
  uintptr_t worker_mask = yxstm_protocol_worker_mask();

  if (group->yxstm_rollback_reason != YXSTM_ROLLBACK_NONE)
    return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
  if (request->expected_epoch != group->yxstm_phase_epoch)
    return SBI_ERR_SM_YXSTM_STALE_EPOCH;
  if (yxstm_protocol_any_acquired_locked(group))
    return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
  if (yxstm_task_bank_any_active_locked(group))
    return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;

  switch (group->yxstm_phase) {
    case YXSTM_PHASE_IDLE:
      if (request->next_phase != YXSTM_PHASE_DISPATCH ||
          !request->active_worker_mask ||
          (request->active_worker_mask & ~worker_mask) ||
          request->sequence <= group->yxstm_sequence ||
          !yxstm_protocol_workers_present_locked(
              group, request->active_worker_mask))
        return SBI_ERR_SM_YXSTM_PHASE;
      slice_size = group->yxstm_bank_slice_size;
      if (slice_size < sizeof(struct keystone_yxstm_channel_header) ||
          request->payload_length >
              slice_size - sizeof(struct keystone_yxstm_channel_header))
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      return SBI_ERR_SM_ENCLAVE_SUCCESS;
    case YXSTM_PHASE_DISPATCH:
      if (request->next_phase != YXSTM_PHASE_COMPUTE ||
          request->sequence != group->yxstm_sequence)
        return SBI_ERR_SM_YXSTM_PHASE;
      if (group->yxstm_published_sequence != group->yxstm_sequence)
        return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      if (group->yxstm_ready_bitmap != group->yxstm_active_worker_mask)
        return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      return SBI_ERR_SM_ENCLAVE_SUCCESS;
    case YXSTM_PHASE_COMPUTE:
      if (request->next_phase != YXSTM_PHASE_AGGREGATE ||
          request->sequence != group->yxstm_sequence)
        return SBI_ERR_SM_YXSTM_PHASE;
      if (group->yxstm_done_bitmap != group->yxstm_active_worker_mask)
        return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      return SBI_ERR_SM_ENCLAVE_SUCCESS;
    case YXSTM_PHASE_AGGREGATE:
      if (request->next_phase != YXSTM_PHASE_IDLE ||
          request->sequence != group->yxstm_sequence)
        return SBI_ERR_SM_YXSTM_PHASE;
      if (group->yxstm_ready_bitmap != group->yxstm_active_worker_mask)
        return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      return SBI_ERR_SM_ENCLAVE_SUCCESS;
    default:
      return SBI_ERR_SM_YXSTM_PHASE;
  }
}

unsigned long yxstm_phase_transition(enclave_id eid, uintptr_t request_buf,
                                     uintptr_t request_len)
{
  struct keystone_yxstm_phase_transition request;
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  unsigned long ret;
  uint64_t old_phase;
  uint64_t now;
  uint64_t deadline;
  uint64_t acked = 0;
  uint64_t offline = 0;
  struct group_coherence_snapshot coherence;

  if (request_len != sizeof(request))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  ret = yxstm_layout_member_context_locked(eid, &group, &member);
  if (ret)
    goto out;
  if (member->role != GROUP_ROLE_MASTER ||
      !range_contains(member->private_epm_base, member->private_epm_size,
                      request_buf, sizeof(request))) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  if (yxstm_protocol_timeout_locked(group)) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  sbi_memcpy(&request, (void*)request_buf, sizeof(request));
  ret = sm_abi_validate(&request.abi, sizeof(request),
                        KEYSTONE_YXSTM_ABI_FEATURES);
  if (ret)
    goto out;
  ret = yxstm_protocol_validate_transition_locked(group, &request);
  if (ret)
    goto out;

  now = sbi_timer_value();
  if (request.timeout_cycles &&
      ~(uint64_t)0 - now < request.timeout_cycles) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  deadline = 0;

  old_phase = group->yxstm_phase;
  ret = group_coherence_begin_locked(group, group->permission_epoch,
                                     group->yxstm_phase_epoch + 1,
                                     SBI_GROUP_IPI_REVOKE_YXSTM,
                                     &coherence);
  if (ret)
    goto out;

  /* Do not hold encl_lock while remote harts process and ACK the IPI. */
  spin_unlock(&encl_lock);
  ret = group_coherence_execute_unlocked(&coherence, &acked, &offline);
  spin_lock(&encl_lock);

  group = find_group_locked(coherence.group_id);
  if (!group || group->generation != coherence.group_generation ||
      group->yxstm_phase != old_phase) {
    if (group)
      group->coherence_inflight = 0;
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto out;
  }
  ret = group_coherence_finish_locked(group, &coherence, acked, offline,
                                      ret, "phase_transition");
  if (ret)
    goto out;

  now = sbi_timer_value();
  deadline = request.timeout_cycles ? now + request.timeout_cycles : 0;
  group->yxstm_phase = request.next_phase;
  group->yxstm_phase_epoch++;
  group->yxstm_deadline = deadline;

  if (old_phase == YXSTM_PHASE_IDLE) {
    yxstm_task_epoch_advance_locked(group);
    group_scrub_yxstm_mask_locked(group, request.active_worker_mask,
                                  "task_begin");
    group->yxstm_sequence = request.sequence;
    group->yxstm_published_sequence = 0;
    group->yxstm_active_worker_mask = request.active_worker_mask;
    group->yxstm_payload_length = request.payload_length;
    group->yxstm_ready_bitmap = 0;
    group->yxstm_done_bitmap = 0;
    group->yxstm_rollback_reason = YXSTM_ROLLBACK_NONE;
  } else if (request.next_phase == YXSTM_PHASE_COMPUTE) {
    group->yxstm_done_bitmap = 0;
  } else if (request.next_phase == YXSTM_PHASE_AGGREGATE) {
    group->yxstm_ready_bitmap = 0;
  } else if (request.next_phase == YXSTM_PHASE_IDLE) {
    group_scrub_yxstm_mask_locked(group,
                                  group->yxstm_active_worker_mask,
                                  "task_complete");
    group->yxstm_active_worker_mask = 0;
    group->yxstm_published_sequence = 0;
    group->yxstm_ready_bitmap = 0;
    group->yxstm_done_bitmap = 0;
    group->yxstm_payload_length = 0;
    group->yxstm_deadline = 0;
  }
  yxstm_protocol_reset_member_acks_locked(group);
  group_security_rekey_locked(group, YXSTM_ROLLBACK_NONE);

  if (group->yxstm_phase != YXSTM_PHASE_IDLE)
    yxstm_protocol_write_headers_locked(group);
  yxstm_protocol_barrier();
  yxstm_protocol_publish_mailboxes_locked(group);
  if (!group->yxstm_perf_quiet)
    sbi_printf("[SM][yxstm] phase: group=%lu eid=%u %lu->%lu epoch=%lu seq=%lu published=%lu workers=0x%lx ready=0x%lx done=0x%lx\n",
               (unsigned long)group->group_id, eid,
               (unsigned long)old_phase,
               (unsigned long)group->yxstm_phase,
               (unsigned long)group->yxstm_phase_epoch,
               (unsigned long)group->yxstm_sequence,
               (unsigned long)group->yxstm_published_sequence,
               (unsigned long)group->yxstm_active_worker_mask,
               (unsigned long)group->yxstm_ready_bitmap,
               (unsigned long)group->yxstm_done_bitmap);
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
out:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long yxstm_phase_ack(enclave_id eid, uintptr_t expected_epoch,
                              uintptr_t event)
{
  struct enabled_group_slot* group = 0;
  struct group_hart_slot* slot = 0;
  struct group_member_descriptor* member = 0;
  unsigned long hartid = csr_read(mhartid);
  unsigned long ret;
  uintptr_t bit;
  uint64_t event_bit;
  uint64_t* bitmap;
  int wake_master_host = 0;

  spin_lock(&encl_lock);
  ret = yxstm_current_member_context_locked(eid, &group, &slot, &member,
                                            &hartid);
  if (ret)
    goto out;
  if (yxstm_protocol_timeout_locked(group) ||
      expected_epoch != group->yxstm_phase_epoch) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  if (group->yxstm_rollback_reason != YXSTM_ROLLBACK_NONE) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  if (member->role == GROUP_ROLE_WORKER &&
      group->yxstm_phase == YXSTM_PHASE_COMPUTE &&
      (event == YXSTM_ACK_COMPUTE_EXEC_BEGIN ||
       event == YXSTM_ACK_COMPUTE_EXEC_END)) {
    uint64_t now = sbi_timer_value();
    uint64_t runtime = group_member_exec_runtime_now_locked(member, now);

    if (event == YXSTM_ACK_COMPUTE_EXEC_BEGIN) {
      if (member->perf_aes_exec_active) {
        ret = SBI_ERR_SM_YXSTM_ALREADY_ACQUIRED;
        goto out;
      }
      member->perf_aes_exec_start = runtime;
      member->perf_aes_phase_epoch = expected_epoch;
      member->perf_aes_exec_active = 1;
    } else {
      if (!member->perf_aes_exec_active ||
          member->perf_aes_phase_epoch != expected_epoch ||
          runtime < member->perf_aes_exec_start) {
        ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
        goto out;
      }
      member->perf_aes_exec_runtime =
          group_scheduler_cfs_saturating_add(
              member->perf_aes_exec_runtime,
              runtime - member->perf_aes_exec_start);
      member->perf_aes_exec_start = 0;
      member->perf_aes_phase_epoch = 0;
      member->perf_aes_exec_active = 0;
    }
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    goto out;
  }
  if (slot->yxstm_acquired) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }

  if (member->role == GROUP_ROLE_MASTER) {
    uintptr_t slice_id;

    if (group->yxstm_phase != YXSTM_PHASE_DISPATCH ||
        event != YXSTM_ACK_DISPATCH_PUBLISHED) {
      ret = SBI_ERR_SM_YXSTM_PHASE;
      goto out;
    }
    if (group->yxstm_published_sequence == group->yxstm_sequence) {
      ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      goto out;
    }
    for (slice_id = 1;
         slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
         slice_id++) {
      if ((group->yxstm_active_worker_mask & (1UL << slice_id)) &&
          !yxstm_protocol_header_valid_locked(group, slice_id)) {
        ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
        goto out;
      }
    }
    yxstm_protocol_barrier();
    group->yxstm_published_sequence = group->yxstm_sequence;
    yxstm_protocol_barrier();
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    goto out;
  }

  if (member->role != GROUP_ROLE_WORKER) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  bit = member->allowed_slice_mask;
  if (!bit || !(group->yxstm_active_worker_mask & bit)) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }

  bitmap = 0;
  if (group->yxstm_phase == YXSTM_PHASE_DISPATCH &&
      event == YXSTM_ACK_DISPATCH_READY &&
      group->yxstm_published_sequence == group->yxstm_sequence)
    bitmap = &group->yxstm_ready_bitmap;
  else if (group->yxstm_phase == YXSTM_PHASE_COMPUTE &&
           event == YXSTM_ACK_COMPUTE_DONE)
    bitmap = &group->yxstm_done_bitmap;
  else if (group->yxstm_phase == YXSTM_PHASE_AGGREGATE &&
           event == YXSTM_ACK_AGGREGATE_READY)
    bitmap = &group->yxstm_ready_bitmap;
  else {
    ret = SBI_ERR_SM_YXSTM_PHASE;
    goto out;
  }
  if (event >= 64) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  event_bit = UINT64_C(1) << event;
  if (member->yxstm_ack_phase_epoch != expected_epoch) {
    member->yxstm_ack_phase_epoch = expected_epoch;
    member->yxstm_ack_event_mask = 0;
  }
  if (member->yxstm_ack_event_mask & event_bit) {
    /* A retried ACK is idempotent for the same member and phase epoch. */
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    goto out;
  }
  yxstm_protocol_barrier();
  member->yxstm_ack_event_mask |= event_bit;
  yxstm_protocol_barrier();
  if (yxstm_protocol_lane_members_acked_locked(
          group, bit, expected_epoch, event))
    *bitmap |= bit;
  yxstm_protocol_barrier();
  if (((group->yxstm_phase == YXSTM_PHASE_DISPATCH ||
        group->yxstm_phase == YXSTM_PHASE_AGGREGATE) &&
       group->yxstm_ready_bitmap == group->yxstm_active_worker_mask) ||
      (group->yxstm_phase == YXSTM_PHASE_COMPUTE &&
       group->yxstm_done_bitmap == group->yxstm_active_worker_mask)) {
    enclave_id master_eid = ENCL_MAX;
    int i;

    for (i = 0; i < (int)group->member_metadata_capacity; i++)
      if (group->members[i].valid &&
          group->members[i].role == GROUP_ROLE_MASTER) {
        master_eid = group->members[i].eid;
        break;
      }
    if (master_eid != ENCL_MAX &&
        !group_scheduler_event_enqueue(
            hartid, group->group_id, group->generation,
            master_eid, enclaves[master_eid].generation,
            KEYSTONE_GROUP_EVENT_WORKERS_READY,
            SBI_ERR_SM_ENCLAVE_SUCCESS,
            (group->yxstm_phase << 56) |
                (group->yxstm_task_epoch & UINT64_C(0x00ffffffffffffff)))) {
      struct sm_hart_sched* sched = &group_hart_schedulers[hartid];
      sched->host_service_deadline = sbi_timer_value();
      wake_master_host = 1;
    }
  }
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
out:
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    sbi_printf("[SM][yxstm] phase ack failed: eid=%u hart=%lu group=%lu role=%lu event=%lu expected_epoch=%lu current_epoch=%lu phase=%lu sequence=%lu published=%lu active=0x%lx ready=0x%lx done=0x%lx acquired=%lu ret=%lu\n",
               eid, hartid,
               group ? (unsigned long)group->group_id : 0,
               member ? (unsigned long)member->role : 0,
               (unsigned long)event,
               (unsigned long)expected_epoch,
               group ? (unsigned long)group->yxstm_phase_epoch : 0,
               group ? (unsigned long)group->yxstm_phase : 0,
               group ? (unsigned long)group->yxstm_sequence : 0,
               group ? (unsigned long)group->yxstm_published_sequence : 0,
               group ? (unsigned long)group->yxstm_active_worker_mask : 0,
               group ? (unsigned long)group->yxstm_ready_bitmap : 0,
               group ? (unsigned long)group->yxstm_done_bitmap : 0,
               slot ? (unsigned long)slot->yxstm_acquired : 0,
               ret);
  }
  if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS && group)
    yxstm_protocol_publish_mailboxes_locked(group);
  spin_unlock(&encl_lock);
  if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS && wake_master_host) {
#if KEYSTONE_GROUP_TIMER_PREEMPT
    sbi_timer_event_start(sbi_timer_value() + 1);
    csr_set(mie, MIP_MTIP);
#endif
  }
  return ret;
}

static int yxstm_task_bank_lane_rank_present_locked(
    struct enabled_group_slot* group, uintptr_t active_worker_mask,
    uintptr_t lane_rank)
{
  uintptr_t slice_id;

  if (!group || lane_rank >= group->member_capacity)
    return 0;
  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    size_t member_index;
    int found = 0;

    if (!(active_worker_mask & (1UL << slice_id)))
      continue;
    for (member_index = 0;
         member_index < group->member_metadata_capacity; member_index++) {
      const struct group_member_descriptor* member =
          &group->members[member_index];

      if (member->valid && member->role == GROUP_ROLE_WORKER &&
          member->lane_id == slice_id - 1 &&
          member->lane_rank == lane_rank) {
        found = 1;
        break;
      }
    }
    if (!found)
      return 0;
  }
  return 1;
}

static int yxstm_task_bank_lane_owner_token_locked(
    struct enabled_group_slot* group, uintptr_t active_worker_mask,
    uintptr_t lane_rank, uint64_t* owner_token)
{
  uintptr_t slice_id;
  uint64_t token;

  if (!group || !owner_token ||
      !yxstm_task_bank_lane_rank_present_locked(
          group, active_worker_mask, lane_rank))
    return 0;
  token = UINT64_C(0x594853544d42414e) ^ group->generation ^
          (lane_rank << 32) ^ active_worker_mask;
  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    size_t member_index;

    if (!(active_worker_mask & (1UL << slice_id)))
      continue;
    for (member_index = 0;
         member_index < group->member_metadata_capacity; member_index++) {
      const struct group_member_descriptor* member =
          &group->members[member_index];

      if (member->valid && member->role == GROUP_ROLE_WORKER &&
          member->lane_id == slice_id - 1 &&
          member->lane_rank == lane_rank) {
        if (!member->yxstm_slot.valid ||
            member->yxstm_slot.owner_eid != member->eid ||
            member->yxstm_slot.owner_generation != member->eid_generation ||
            !member->yxstm_slot.epoch)
          return 0;
        token ^= ((uint64_t)member->eid_generation << 32) |
                 (uint64_t)member->eid;
        token ^= member->yxstm_slot.epoch *
                 UINT64_C(0xd6e8feb86659fd93);
        token = (token << 13) | (token >> (64 - 13));
        token *= UINT64_C(0x9e3779b97f4a7c15);
        break;
      }
    }
  }
  *owner_token = token ? token : UINT64_C(1);
  return 1;
}

static int yxstm_task_bank_owner_binding_valid_locked(
    struct enabled_group_slot* group,
    const struct group_task_bank_protocol* bank)
{
  uint64_t token = 0;

  if (!group || !bank || !bank->owner_valid ||
      !bank->owner_worker_mask)
    return 0;
  return yxstm_task_bank_lane_owner_token_locked(
             group, bank->owner_worker_mask, bank->owner_lane_rank,
             &token) &&
         token == bank->owner_generation_token;
}

static int yxstm_slot_matches_task(
    const struct yxstm_slot* slot,
    const struct group_task_bank_protocol* bank,
    const struct keystone_yxstm_task_bank_transition* request)
{
  return slot && slot->valid && bank &&
         bank->commit_epoch != ~(uint64_t)0 &&
         slot->batch_id == bank->commit_epoch + 1 &&
         slot->task_id == request->task_epoch &&
         slot->sequence == request->sequence &&
         slot->digest == request->task_digest;
}

static unsigned long yxstm_task_bank_slots_validate_locked(
    struct enabled_group_slot* group,
    const struct keystone_yxstm_task_bank_transition* request,
    uint64_t old_phase)
{
  const struct group_task_bank_protocol* bank;
  uintptr_t slice_id;
  uint64_t expected_state;

  if (!group || !group->yxstm_slots_frozen)
    return SBI_ERR_SM_GROUP_BAD_STATE;
  if (request->bank_id >= group->yxstm_bank_count)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  bank = &group->task_banks[request->bank_id];
  if (old_phase == YXSTM_PHASE_IDLE)
    expected_state = YXSTM_SLOT_FREE;
  else if (old_phase == YXSTM_PHASE_DISPATCH)
    expected_state = YXSTM_SLOT_READY;
  else if (old_phase == YXSTM_PHASE_COMPUTE)
    expected_state = YXSTM_SLOT_DONE;
  else if (old_phase == YXSTM_PHASE_AGGREGATE)
    expected_state = YXSTM_SLOT_AGGREGATING;
  else
    return SBI_ERR_SM_YXSTM_PHASE;

  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    struct group_member_descriptor* owner;
    struct yxstm_slot* slot;

    if (!(request->active_worker_mask & (1UL << slice_id)))
      continue;
    owner = group_yxstm_slot_member_for_slice_locked(
        group, slice_id, request->lane_rank);
    if (!owner)
      return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    slot = &owner->yxstm_slot;
    if (!slot->valid || slot->state != expected_state ||
        (old_phase != YXSTM_PHASE_IDLE &&
          (!yxstm_slot_matches_task(slot, bank, request) ||
          slot->payload_size != bank->payload_length)))
      return SBI_ERR_SM_YXSTM_STALE_EPOCH;
    if (old_phase == YXSTM_PHASE_IDLE &&
        request->payload_length > slot->payload_capacity)
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static void yxstm_task_bank_slots_transition_locked(
    struct enabled_group_slot* group,
    const struct keystone_yxstm_task_bank_transition* request,
    uint64_t old_phase)
{
  uintptr_t slice_id;

  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    struct group_member_descriptor* owner;
    struct yxstm_slot* slot;

    if (!(request->active_worker_mask & (1UL << slice_id)))
      continue;
    owner = group_yxstm_slot_member_for_slice_locked(
        group, slice_id, request->lane_rank);
    if (!owner)
      continue;
    slot = &owner->yxstm_slot;
    if (old_phase == YXSTM_PHASE_IDLE) {
      slot->state = YXSTM_SLOT_DISPATCHING;
      slot->batch_id =
          group->task_banks[request->bank_id].commit_epoch + 1;
      slot->task_id = request->task_epoch;
      slot->sequence = request->sequence;
      slot->payload_size = request->payload_length;
      slot->permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
      slot->digest = request->task_digest;
    } else if (old_phase == YXSTM_PHASE_DISPATCH) {
      slot->state = YXSTM_SLOT_COMPUTING;
      slot->permissions = KEYSTONE_YXSTM_PERM_R | KEYSTONE_YXSTM_PERM_W;
    } else if (old_phase == YXSTM_PHASE_COMPUTE) {
      slot->state = YXSTM_SLOT_AGGREGATING;
      slot->permissions = KEYSTONE_YXSTM_PERM_R;
    } else if (old_phase == YXSTM_PHASE_AGGREGATE) {
      slot->state = YXSTM_SLOT_FREE;
      slot->batch_id = 0;
      slot->task_id = 0;
      slot->sequence = 0;
      slot->payload_size = 0;
      slot->permissions = 0;
      slot->digest = 0;
      slot->epoch++;
      if (!slot->epoch)
        slot->epoch = 1;
    }
  }
  yxstm_protocol_barrier();
}

static unsigned long yxstm_task_bank_validate_transition_locked(
    struct enabled_group_slot* group,
    const struct keystone_yxstm_task_bank_transition* request)
{
  struct group_task_bank_protocol* bank;
  uintptr_t worker_mask = yxstm_protocol_worker_mask();

  if (!group || request->bank_id >= group->yxstm_bank_count ||
      request->expected_phase_epoch !=
          group->task_banks[request->bank_id].phase_epoch)
    return SBI_ERR_SM_YXSTM_STALE_EPOCH;
  if (request->flags)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  if (yxstm_task_bank_any_acquired_locked(group, request->bank_id))
    return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
  bank = &group->task_banks[request->bank_id];
  if (bank->phase == YXSTM_PHASE_IDLE &&
      (group->yxstm_phase != YXSTM_PHASE_IDLE ||
       group->yxstm_rollback_reason != YXSTM_ROLLBACK_NONE ||
       yxstm_legacy_any_acquired_locked(group)))
    return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
  if (bank->phase != YXSTM_PHASE_IDLE &&
      (bank->rollback_reason != YXSTM_ROLLBACK_NONE ||
       !yxstm_task_bank_owner_binding_valid_locked(group, bank)))
    return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;

  switch (bank->phase) {
    case YXSTM_PHASE_IDLE:
      if (request->next_phase != YXSTM_PHASE_DISPATCH ||
          bank->commit_epoch == ~(uint64_t)0 ||
          !request->active_worker_mask ||
          (request->active_worker_mask & ~worker_mask) ||
          request->sequence <= bank->sequence ||
          request->task_epoch <= bank->task_epoch ||
          !request->task_digest ||
          !yxstm_protocol_workers_present_locked(
              group, request->active_worker_mask) ||
          !yxstm_task_bank_lane_rank_present_locked(
              group, request->active_worker_mask, request->lane_rank))
        return SBI_ERR_SM_YXSTM_PHASE;
      break;
    case YXSTM_PHASE_DISPATCH:
      if (request->next_phase != YXSTM_PHASE_COMPUTE ||
          request->sequence != bank->sequence ||
          request->task_epoch != bank->task_epoch ||
          request->task_digest != bank->task_digest)
        return SBI_ERR_SM_YXSTM_PHASE;
      if (bank->published_sequence != bank->sequence ||
          bank->ready_bitmap != bank->active_worker_mask)
        return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      break;
    case YXSTM_PHASE_COMPUTE:
      if (request->next_phase != YXSTM_PHASE_AGGREGATE ||
          request->sequence != bank->sequence ||
          request->task_epoch != bank->task_epoch ||
          request->task_digest != bank->task_digest)
        return SBI_ERR_SM_YXSTM_PHASE;
      if (bank->done_bitmap != bank->active_worker_mask)
        return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      break;
    case YXSTM_PHASE_AGGREGATE:
      if (request->next_phase != YXSTM_PHASE_IDLE ||
          request->sequence != bank->sequence ||
          request->task_epoch != bank->task_epoch ||
          request->task_digest != bank->task_digest)
        return SBI_ERR_SM_YXSTM_PHASE;
      if (bank->ready_bitmap != bank->active_worker_mask)
        return SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      break;
    default:
      return SBI_ERR_SM_YXSTM_PHASE;
  }
  return yxstm_task_bank_slots_validate_locked(
      group, request, bank->phase);
}

unsigned long yxstm_task_bank_transition(enclave_id eid,
                                         uintptr_t request_buf,
                                         uintptr_t request_len)
{
  struct keystone_yxstm_task_bank_transition request;
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  struct group_task_bank_protocol* bank;
  unsigned long ret;
  uint64_t old_phase;
  uint64_t now;
  uint64_t owner_token = 0;

  if (request_len != sizeof(request))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  ret = yxstm_layout_member_context_locked(eid, &group, &member);
  if (ret)
    goto out;
  if (member->role != GROUP_ROLE_MASTER ||
      !range_contains(member->private_epm_base, member->private_epm_size,
                      request_buf, sizeof(request))) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  sbi_memcpy(&request, (void*)request_buf, sizeof(request));
  ret = sm_abi_validate(&request.abi, sizeof(request),
                        KEYSTONE_YXSTM_ABI_FEATURES);
  if (ret)
    goto out;
  if (request.bank_id >= group->yxstm_bank_count) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  if (yxstm_task_bank_timeout_locked(group, request.bank_id)) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  ret = yxstm_task_bank_validate_transition_locked(group, &request);
  if (ret)
    goto out;
  now = sbi_timer_value();
  if (request.timeout_cycles &&
      ~(uint64_t)0 - now < request.timeout_cycles) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  bank = &group->task_banks[request.bank_id];
  if (bank->phase != YXSTM_PHASE_IDLE &&
      bank->rollback_reason != YXSTM_ROLLBACK_NONE) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  old_phase = bank->phase;
  if (old_phase != YXSTM_PHASE_IDLE &&
      (request.active_worker_mask != bank->active_worker_mask ||
       request.lane_rank != bank->lane_rank)) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  if (old_phase == YXSTM_PHASE_IDLE &&
      !yxstm_task_bank_lane_owner_token_locked(
          group, request.active_worker_mask, request.lane_rank,
          &owner_token)) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  yxstm_task_bank_slots_transition_locked(group, &request, old_phase);
  bank->phase = request.next_phase;
  bank->phase_epoch++;
  bank->deadline = request.timeout_cycles ? now + request.timeout_cycles : 0;

  if (old_phase == YXSTM_PHASE_IDLE) {
    bank->owner_valid = 1;
    bank->owner_lane_rank = request.lane_rank;
    bank->owner_worker_mask = request.active_worker_mask;
    bank->owner_generation_token = owner_token;
    bank->task_epoch = request.task_epoch;
    bank->sequence = request.sequence;
    bank->published_sequence = 0;
    bank->active_worker_mask = request.active_worker_mask;
    bank->ready_bitmap = 0;
    bank->done_bitmap = 0;
    bank->payload_length = request.payload_length;
    bank->rollback_reason = YXSTM_ROLLBACK_NONE;
    bank->task_digest = request.task_digest;
    bank->lane_rank = request.lane_rank;
  } else if (request.next_phase == YXSTM_PHASE_COMPUTE) {
    bank->done_bitmap = 0;
  } else if (request.next_phase == YXSTM_PHASE_AGGREGATE) {
    bank->ready_bitmap = 0;
  } else if (request.next_phase == YXSTM_PHASE_IDLE) {
    bank->commit_epoch++;
    bank->published_sequence = 0;
    bank->active_worker_mask = 0;
    bank->ready_bitmap = 0;
    bank->done_bitmap = 0;
    bank->payload_length = 0;
    bank->deadline = 0;
    bank->task_digest = 0;
    bank->lane_rank = 0;
    bank->owner_valid = 0;
    bank->owner_lane_rank = 0;
    bank->owner_worker_mask = 0;
    bank->owner_generation_token = 0;
  }
  if (bank->phase != YXSTM_PHASE_IDLE)
    yxstm_task_bank_write_headers_locked(group, request.bank_id);
  yxstm_protocol_barrier();
  yxstm_protocol_publish_mailboxes_locked(group);
  yxstm_task_bank_wake_waiters_locked(
      group, request.bank_id, "task_bank_transition");
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
out:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long yxstm_task_bank_acquire(enclave_id eid,
                                      uintptr_t request_buf,
                                      uintptr_t request_len)
{
  struct keystone_yxstm_task_bank_grant request;
  struct enabled_group_slot* group;
  struct group_hart_slot* slot;
  struct group_member_descriptor* member;
  struct group_task_bank_protocol* bank;
  unsigned long hartid;
  unsigned long ret;
  uintptr_t slice_id;

  if (request_len != sizeof(request))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  spin_lock(&encl_lock);
  ret = yxstm_current_member_context_locked(
      eid, &group, &slot, &member, &hartid);
  if (ret)
    goto out;
  if (!range_contains(member->private_epm_base, member->private_epm_size,
                      request_buf, sizeof(request))) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  sbi_memcpy(&request, (void*)request_buf, sizeof(request));
  ret = sm_abi_validate(&request.abi, sizeof(request),
                        KEYSTONE_YXSTM_ABI_FEATURES);
  if (ret)
    goto out;
  if (request.bank_id >= group->yxstm_bank_count ||
      yxstm_task_bank_timeout_locked(group, request.bank_id)) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  bank = &group->task_banks[request.bank_id];
  if (bank->rollback_reason != YXSTM_ROLLBACK_NONE) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  if (!yxstm_task_bank_owner_binding_valid_locked(group, bank)) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  if (request.phase != bank->phase ||
      request.expected_phase_epoch != bank->phase_epoch ||
      request.expected_task_epoch != bank->task_epoch ||
      request.task_digest != bank->task_digest) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  if (bank->phase == YXSTM_PHASE_IDLE) {
    ret = SBI_ERR_SM_YXSTM_PHASE;
    goto out;
  }
  if (member->role == GROUP_ROLE_WORKER) {
    struct group_worker_lane* lane =
        group_lane_for_id_locked(group, member->lane_id);
    if (!lane || lane->active_eid != eid ||
        lane->active_eid_generation != enclaves[eid].generation) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
      goto out;
    }
    if (member->lane_rank != bank->lane_rank) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
      goto out;
    }
  }
  ret = yxstm_validate_member_access_locked(
      group, member, request.slice_mask, request.permissions,
      request.phase);
  if (ret)
    goto out;
  if (!(request.slice_mask & bank->active_worker_mask) ||
      (request.slice_mask & ~bank->active_worker_mask)) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  if (slot->yxstm_acquired || member->yxstm_suspended_acquired) {
    ret = SBI_ERR_SM_YXSTM_ALREADY_ACQUIRED;
    goto out;
  }
  if (member->role == GROUP_ROLE_WORKER &&
      bank->phase == YXSTM_PHASE_DISPATCH &&
      bank->published_sequence != bank->sequence) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    struct group_member_descriptor* owner;
    uint64_t expected_state;

    if (!(request.slice_mask & (1UL << slice_id)))
      continue;
    owner = group_yxstm_slot_member_for_slice_locked(
        group, slice_id, bank->lane_rank);
    if (!owner || bank->commit_epoch == ~(uint64_t)0 ||
        owner->yxstm_slot.batch_id != bank->commit_epoch + 1 ||
        owner->yxstm_slot.task_id != bank->task_epoch ||
        owner->yxstm_slot.sequence != bank->sequence ||
        owner->yxstm_slot.digest != bank->task_digest) {
      ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
      goto out;
    }
    if (member->role == GROUP_ROLE_MASTER)
      expected_state = bank->phase == YXSTM_PHASE_DISPATCH ?
          YXSTM_SLOT_DISPATCHING : YXSTM_SLOT_AGGREGATING;
    else
      expected_state = bank->phase == YXSTM_PHASE_DISPATCH ?
          YXSTM_SLOT_READY : YXSTM_SLOT_COMPUTING;
    if (owner->yxstm_slot.state != expected_state) {
      ret = SBI_ERR_SM_YXSTM_PHASE;
      goto out;
    }
  }
  for (slice_id = 1; slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT;
       slice_id++) {
    if ((request.slice_mask & (1UL << slice_id)) &&
        !yxstm_task_bank_header_valid_locked(
            group, request.bank_id, slice_id)) {
      ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      goto out;
    }
  }
  ret = yxstm_install_task_bank_pmp_locked(
      group, member, request.bank_id, request.slice_mask,
      request.permissions);
  if (ret)
    goto out;
  yxstm_protocol_barrier();
  slot->yxstm_acquired = 1;
  slot->yxstm_owner_eid = eid;
  slot->yxstm_acquired_slice_mask = request.slice_mask;
  slot->yxstm_permissions = request.permissions;
  slot->yxstm_phase = request.phase;
  slot->yxstm_bank_id = request.bank_id;
  slot->pmp_epoch = group->permission_epoch;
  slot->phase_epoch = bank->phase_epoch;
  if (request.permissions & KEYSTONE_YXSTM_PERM_W)
    group_mark_yxstm_bank_dirty_locked(
        group, request.bank_id, request.slice_mask);
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
out:
  (void)hartid;
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long yxstm_task_bank_release(enclave_id eid,
                                      uintptr_t request_buf,
                                      uintptr_t request_len)
{
  struct keystone_yxstm_task_bank_grant request;
  struct enabled_group_slot* group;
  struct group_hart_slot* slot;
  struct group_member_descriptor* member;
  struct group_task_bank_protocol* bank;
  unsigned long hartid;
  unsigned long ret;

  if (request_len != sizeof(request))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  spin_lock(&encl_lock);
  ret = yxstm_current_member_context_locked(
      eid, &group, &slot, &member, &hartid);
  if (ret)
    goto out;
  if (!range_contains(member->private_epm_base, member->private_epm_size,
                      request_buf, sizeof(request))) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  sbi_memcpy(&request, (void*)request_buf, sizeof(request));
  ret = sm_abi_validate(&request.abi, sizeof(request),
                        KEYSTONE_YXSTM_ABI_FEATURES);
  if (ret)
    goto out;
  if (request.bank_id >= group->yxstm_bank_count) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  bank = &group->task_banks[request.bank_id];
  if (!slot->yxstm_acquired) {
    ret = SBI_ERR_SM_YXSTM_NOT_ACQUIRED;
    goto out;
  }
  if (slot->yxstm_owner_eid != eid ||
      slot->yxstm_bank_id != request.bank_id ||
      slot->yxstm_acquired_slice_mask != request.slice_mask ||
      slot->yxstm_permissions != request.permissions ||
      slot->yxstm_phase != request.phase) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  if (request.expected_phase_epoch != bank->phase_epoch ||
      request.expected_task_epoch != bank->task_epoch ||
      request.task_digest != bank->task_digest ||
      request.phase != bank->phase) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  yxstm_protocol_barrier();
  if (group->yxstm_region >= 0 &&
      pmp_set_keystone(group->yxstm_region, PMP_NO_PERM)) {
    ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
    goto out;
  }
  asm volatile("sfence.vma" ::: "memory");
  yxstm_protocol_barrier();
  slot->yxstm_acquired = 0;
  slot->yxstm_owner_eid = ENCL_MAX;
  slot->yxstm_acquired_slice_mask = 0;
  slot->yxstm_permissions = 0;
  slot->yxstm_phase = YXSTM_PHASE_IDLE;
  slot->yxstm_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
  slot->pmp_epoch = group->permission_epoch;
  slot->phase_epoch = bank->phase_epoch;
  if (bank->rollback_reason != YXSTM_ROLLBACK_NONE &&
      !yxstm_task_bank_any_acquired_locked(group, request.bank_id))
    yxstm_task_bank_rollback_locked(
        group, request.bank_id, bank->rollback_reason,
        "task_bank_release_rollback");
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
out:
  (void)hartid;
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long yxstm_task_bank_ack(enclave_id eid, uintptr_t request_buf,
                                   uintptr_t request_len)
{
  struct keystone_yxstm_task_bank_ack request;
  struct enabled_group_slot* group;
  struct group_hart_slot* slot;
  struct group_member_descriptor* member;
  struct group_task_bank_protocol* bank;
  unsigned long hartid;
  unsigned long ret;
  uintptr_t bit;
  uint64_t* bitmap = 0;
  int wake_master_host = 0;

  if (request_len != sizeof(request))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  spin_lock(&encl_lock);
  ret = yxstm_current_member_context_locked(
      eid, &group, &slot, &member, &hartid);
  if (ret)
    goto out;
  if (!range_contains(member->private_epm_base, member->private_epm_size,
                      request_buf, sizeof(request))) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  sbi_memcpy(&request, (void*)request_buf, sizeof(request));
  ret = sm_abi_validate(&request.abi, sizeof(request),
                        KEYSTONE_YXSTM_ABI_FEATURES);
  if (ret)
    goto out;
  if (request.bank_id >= group->yxstm_bank_count ||
      yxstm_task_bank_timeout_locked(group, request.bank_id)) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  bank = &group->task_banks[request.bank_id];
  if (bank->rollback_reason != YXSTM_ROLLBACK_NONE) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  if (!yxstm_task_bank_owner_binding_valid_locked(group, bank)) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  if (request.expected_phase_epoch != bank->phase_epoch ||
      request.expected_task_epoch != bank->task_epoch ||
      request.task_digest != bank->task_digest) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  if (member->role == GROUP_ROLE_WORKER &&
      member->lane_rank == bank->lane_rank &&
      bank->phase == YXSTM_PHASE_COMPUTE &&
      member->yxstm_slot.valid &&
      member->yxstm_slot.state == YXSTM_SLOT_COMPUTING &&
      bank->commit_epoch != ~(uint64_t)0 &&
      member->yxstm_slot.batch_id == bank->commit_epoch + 1 &&
      member->yxstm_slot.task_id == bank->task_epoch &&
      member->yxstm_slot.sequence == bank->sequence &&
      member->yxstm_slot.digest == bank->task_digest &&
      (member->allowed_slice_mask & bank->active_worker_mask) &&
      (request.event == YXSTM_ACK_COMPUTE_EXEC_BEGIN ||
       request.event == YXSTM_ACK_COMPUTE_EXEC_END)) {
    uint64_t now = sbi_timer_value();
    uint64_t runtime = group_member_exec_runtime_now_locked(member, now);

    if (request.event == YXSTM_ACK_COMPUTE_EXEC_BEGIN) {
      if (member->perf_aes_exec_active) {
        ret = SBI_ERR_SM_YXSTM_ALREADY_ACQUIRED;
        goto out;
      }
      member->perf_aes_exec_start = runtime;
      member->perf_aes_phase_epoch = bank->phase_epoch;
      member->perf_aes_exec_active = 1;
    } else {
      if (!member->perf_aes_exec_active ||
          member->perf_aes_phase_epoch != bank->phase_epoch ||
          runtime < member->perf_aes_exec_start) {
        ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
        goto out;
      }
      member->perf_aes_exec_runtime =
          group_scheduler_cfs_saturating_add(
              member->perf_aes_exec_runtime,
              runtime - member->perf_aes_exec_start);
      member->perf_aes_exec_start = 0;
      member->perf_aes_phase_epoch = 0;
      member->perf_aes_exec_active = 0;
    }
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    goto publish;
  }
  if (slot->yxstm_acquired) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  if (member->role == GROUP_ROLE_MASTER) {
    uintptr_t slice_id;

    if (bank->phase != YXSTM_PHASE_DISPATCH ||
        request.event != YXSTM_ACK_DISPATCH_PUBLISHED ||
        bank->published_sequence == bank->sequence) {
      ret = SBI_ERR_SM_YXSTM_PHASE;
      goto out;
    }
    for (slice_id = 1;
         slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT; slice_id++) {
      struct group_member_descriptor* owner;
      struct yxstm_slot* task_slot;

      if (!(bank->active_worker_mask & (1UL << slice_id)))
        continue;
      owner = group_yxstm_slot_member_for_slice_locked(
          group, slice_id, bank->lane_rank);
      if (!owner || !yxstm_task_bank_header_valid_locked(
                        group, request.bank_id, slice_id)) {
        ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
        goto out;
      }
      task_slot = &owner->yxstm_slot;
      if (task_slot->state != YXSTM_SLOT_DISPATCHING ||
          bank->commit_epoch == ~(uint64_t)0 ||
          task_slot->batch_id != bank->commit_epoch + 1 ||
          task_slot->task_id != bank->task_epoch ||
          task_slot->sequence != bank->sequence ||
          task_slot->digest != bank->task_digest) {
        ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
        goto out;
      }
    }
    for (slice_id = 1;
         slice_id < KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT; slice_id++) {
      struct group_member_descriptor* owner;

      if (!(bank->active_worker_mask & (1UL << slice_id)))
        continue;
      owner = group_yxstm_slot_member_for_slice_locked(
          group, slice_id, bank->lane_rank);
      owner->yxstm_slot.state = YXSTM_SLOT_READY;
      owner->yxstm_slot.permissions = KEYSTONE_YXSTM_PERM_R;
    }
    bank->published_sequence = bank->sequence;
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    goto publish;
  }
  if (member->role != GROUP_ROLE_WORKER) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  if (member->lane_rank != bank->lane_rank) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  if (!member->yxstm_slot.valid ||
      bank->commit_epoch == ~(uint64_t)0 ||
      member->yxstm_slot.batch_id != bank->commit_epoch + 1 ||
      member->yxstm_slot.task_id != bank->task_epoch ||
      member->yxstm_slot.sequence != bank->sequence ||
      member->yxstm_slot.digest != bank->task_digest) {
    ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
    goto out;
  }
  bit = member->allowed_slice_mask;
  if (!bit || !(bank->active_worker_mask & bit)) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  if (bank->phase == YXSTM_PHASE_DISPATCH &&
      request.event == YXSTM_ACK_DISPATCH_READY &&
      bank->published_sequence == bank->sequence &&
      member->yxstm_slot.state == YXSTM_SLOT_READY)
    bitmap = &bank->ready_bitmap;
  else if (bank->phase == YXSTM_PHASE_COMPUTE &&
           request.event == YXSTM_ACK_COMPUTE_DONE &&
           member->yxstm_slot.state == YXSTM_SLOT_COMPUTING) {
    member->yxstm_slot.state = YXSTM_SLOT_DONE;
    member->yxstm_slot.permissions = 0;
    bitmap = &bank->done_bitmap;
  } else if (bank->phase == YXSTM_PHASE_AGGREGATE &&
           request.event == YXSTM_ACK_AGGREGATE_READY &&
           member->yxstm_slot.state == YXSTM_SLOT_AGGREGATING)
    bitmap = &bank->ready_bitmap;
  else {
    ret = SBI_ERR_SM_YXSTM_PHASE;
    goto out;
  }
  if (*bitmap & bit) {
    ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
    goto out;
  }
  *bitmap |= bit;
  if (*bitmap == bank->active_worker_mask) {
    enclave_id master_eid = ENCL_MAX;
    size_t member_index;

    for (member_index = 0;
         member_index < group->member_metadata_capacity; member_index++)
      if (group->members[member_index].valid &&
          group->members[member_index].role == GROUP_ROLE_MASTER) {
        master_eid = group->members[member_index].eid;
        break;
      }
    if (master_eid != ENCL_MAX &&
        !group_scheduler_event_enqueue(
            hartid, group->group_id, group->generation,
            master_eid, enclaves[master_eid].generation,
            KEYSTONE_GROUP_EVENT_WORKERS_READY,
             SBI_ERR_SM_ENCLAVE_SUCCESS,
             (bank->phase << 56) |
                 ((request.bank_id & 0xffUL) << 48) |
                 (bank->task_epoch & UINT64_C(0x0000ffffffffffff)))) {
      struct sm_hart_sched* sched = &group_hart_schedulers[hartid];

      /*
       * WORKERS_READY is consumed by the CPU0 driver waitqueue, but its
       * producer is an HSM-leased worker hart.  A deadline alone is ignored
       * deliberately when the exclusive lease has no periodic heartbeat.
       * Request one scheduler-owned host boundary so group_run_hart() can
       * return the queued event to the HSM event bridge.  This is phase-edge
       * notification, not periodic host service.
       */
      sched->host_service_deadline = sbi_timer_value();
      sched->host_service_forced = 1;
      sched->host_service_drop_grant = 1;
      wake_master_host = 1;
    }
  }
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
publish:
  yxstm_protocol_barrier();
  yxstm_protocol_publish_mailboxes_locked(group);
  yxstm_task_bank_wake_waiters_locked(group, request.bank_id,
                                      "task_bank_ack");
out:
  (void)hartid;
  spin_unlock(&encl_lock);
  if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS && wake_master_host) {
#if KEYSTONE_GROUP_TIMER_PREEMPT
    sbi_timer_event_start(sbi_timer_value() + 1);
    csr_set(mie, MIP_MTIP);
#endif
  }
  return ret;
}

unsigned long group_lane_turn(enclave_id eid, uintptr_t request_buf,
                              uintptr_t request_len)
{
  struct keystone_group_lane_turn request;
  struct enabled_group_slot* group;
  struct group_hart_slot* slot;
  struct group_member_descriptor* member;
  struct group_worker_lane* lane;
  unsigned long hartid;
  unsigned long ret;
  size_t i;

  if (request_len != sizeof(request))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  ret = yxstm_current_member_context_locked(
      eid, &group, &slot, &member, &hartid);
  if (ret)
    goto out;
  if (!range_contains(member->private_epm_base, member->private_epm_size,
                      request_buf, sizeof(request))) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto out;
  }
  sbi_memcpy(&request, (void*)request_buf, sizeof(request));
  ret = sm_abi_validate(&request.abi, sizeof(request),
                        KEYSTONE_YXSTM_ABI_FEATURES);
  if (ret)
    goto out;
  if (member->role != GROUP_ROLE_WORKER ||
      member->lane_id == KEYSTONE_GROUP_UNBOUND_LANE ||
      request.lane_id != member->lane_id ||
      request.lane_rank != member->lane_rank) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  lane = group_lane_for_id_locked(group, member->lane_id);
  if (!lane || lane->hart_id != hartid || lane->active_eid != eid ||
      lane->active_eid_generation != enclaves[eid].generation) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out;
  }
  if (slot->yxstm_acquired || member->yxstm_suspended_acquired) {
    ret = SBI_ERR_SM_YXSTM_ALREADY_ACQUIRED;
    goto out;
  }

  request.result = KEYSTONE_GROUP_LANE_TURN_READY;
  if (request.operation == KEYSTONE_GROUP_LANE_TURN_WAIT_BANK) {
    int ready = 0;

    if (member->lane_wait_pending) {
      ret = SBI_ERR_SM_YXSTM_PROTOCOL_INCOMPLETE;
      goto out;
    }
    ret = yxstm_task_bank_wait_status_locked(
        group, member, request.turn_id, request.reserved[0],
        request.sequence, request.reserved[1], &ready);
    if (ret)
      goto out;
    if (!ready) {
      member->lane_wait_sequence = request.sequence;
      member->lane_wait_turn = request.turn_id;
      member->lane_wait_phase = request.reserved[0];
      member->lane_wait_task_epoch = request.reserved[1];
      member->lane_wait_result = SBI_ERR_SM_ENCLAVE_SUCCESS;
      member->lane_wait_started_at = sbi_timer_value();
      member->lane_wait_pending = 1;
      member->lane_wait_task_bank = GROUP_LANE_WAIT_KIND_TASK_BANK;
      member->lane_wait_ready = 0;
      member->lane_wait_context_saved = 0;
      /*
       * Registration and STOP_LANE_WAIT are two consecutive ecalls.  Do not
       * let a timer/IPI preempt the member in between and expose a RUNNABLE
       * context whose wait metadata already says it is blocked.
       */
      group_member_timer_ready[eid] = 0;
      request.result = KEYSTONE_GROUP_LANE_TURN_BLOCK;
      atomic_add_return(&group_perf_lane_wait_block_count, 1);
    }
    goto copy_result;
  }

  if (request.sequence != group->yxstm_sequence ||
      (group->yxstm_phase != YXSTM_PHASE_COMPUTE &&
       group->yxstm_phase != YXSTM_PHASE_AGGREGATE)) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  if (lane->stream_sequence != request.sequence) {
    if (request.operation != KEYSTONE_GROUP_LANE_TURN_WAIT) {
      ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
      goto out;
    }
    lane->stream_sequence = request.sequence;
    lane->stream_turn = 0;
  }

  if (request.operation == KEYSTONE_GROUP_LANE_TURN_WAIT) {
    if (request.turn_id < lane->stream_turn) {
      ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
      goto out;
    }
    if (request.turn_id > lane->stream_turn) {
      member->lane_wait_sequence = request.sequence;
      member->lane_wait_turn = request.turn_id;
      member->lane_wait_phase = 0;
      member->lane_wait_task_epoch = 0;
      member->lane_wait_result = SBI_ERR_SM_ENCLAVE_SUCCESS;
      member->lane_wait_started_at = sbi_timer_value();
      member->lane_wait_pending = 1;
      member->lane_wait_task_bank = GROUP_LANE_WAIT_KIND_TURN;
      member->lane_wait_ready = 0;
      member->lane_wait_context_saved = 0;
      group_member_timer_ready[eid] = 0;
      request.result = KEYSTONE_GROUP_LANE_TURN_BLOCK;
      atomic_add_return(&group_perf_lane_wait_block_count, 1);
    } else {
      group_lane_wait_clear_locked(member);
    }
  } else if (request.operation == KEYSTONE_GROUP_LANE_TURN_ADVANCE) {
    if (request.turn_id != lane->stream_turn || member->lane_wait_pending) {
      ret = SBI_ERR_SM_YXSTM_STALE_EPOCH;
      goto out;
    }
    lane->stream_turn++;
    lane->lane_epoch++;
    if (!lane->lane_epoch)
      lane->lane_epoch = 1;
    for (i = 0; i < group->member_metadata_capacity; i++) {
      struct group_member_descriptor* waiter = &group->members[i];
      if (!waiter->valid || waiter->role != GROUP_ROLE_WORKER ||
          waiter->lane_id != lane->lane_id || !waiter->lane_wait_pending ||
          waiter->lane_wait_task_bank != GROUP_LANE_WAIT_KIND_TURN ||
          waiter->lane_wait_sequence != lane->stream_sequence ||
          waiter->lane_wait_turn != lane->stream_turn)
        continue;
      group_lane_wait_signal_locked(waiter, SBI_ERR_SM_ENCLAVE_SUCCESS,
                                    "lane_turn_advance");
      break;
    }
  } else {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

copy_result:
  sm_abi_fill(&request.abi, sizeof(request), KEYSTONE_YXSTM_ABI_FEATURES);
  sbi_memcpy((void*)request_buf, &request, sizeof(request));
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
out:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long group_set_count(uint64_t group_count)
{
  int i;

  if (group_count == 0 || group_count > KEYSTONE_MAX_ENABLED_GROUPS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++)
    if (enabled_groups[i].valid &&
        enabled_groups[i].lifecycle_state != KEYSTONE_GROUP_STATE_CONFIGURING) {
      spin_unlock(&encl_lock);
      return SBI_ERR_SM_GROUP_BAD_STATE;
    }

  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    if (enabled_groups[i].valid &&
        enabled_groups[i].group_id > group_count &&
        (enabled_groups[i].member_count ||
         enabled_groups[i].epm_refcount ||
         enabled_groups[i].yxstm_refcount)) {
      spin_unlock(&encl_lock);
      return SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    }
  }

  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    if (enabled_groups[i].valid &&
        enabled_groups[i].group_id > group_count) {
      group_metadata_release_locked(&enabled_groups[i]);
      sbi_memset(&enabled_groups[i], 0, sizeof(enabled_groups[i]));
    }
  }

  configured_group_count = group_count;
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    if (enabled_groups[i].valid &&
        enabled_groups[i].group_id <= group_count &&
        enabled_groups[i].member_count == 0 &&
        enabled_groups[i].epm_refcount == 0 &&
        enabled_groups[i].yxstm_refcount == 0) {
      group_metadata_release_locked(&enabled_groups[i]);
      group_configure_hart_slots_locked(&enabled_groups[i], 0);
      enabled_groups[i].permission_epoch++;
    }
  }

  group_recompute_hart_masks_locked();

  sbi_printf("[SM][group] configured group_count=%lu\n",
             (unsigned long)configured_group_count);
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long group_set_hart_count(uint64_t group_id, uint64_t hart_count)
{
  struct enabled_group_slot* group;
  uint64_t old_mask;
  uint64_t old_count;
  uint64_t total;

  if (!group_id || group_id > configured_group_count ||
      group_id > KEYSTONE_MAX_ENABLED_GROUPS ||
      hart_count == 0 ||
      hart_count > KEYSTONE_GROUP_MAX_CONFIGURED_HARTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  if (group_any_active_locked()) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
  }

  group = find_group_locked(group_id);
  if (!group) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
  if (group->lifecycle_state != KEYSTONE_GROUP_STATE_CONFIGURING) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_GROUP_BAD_STATE;
  }
  if (group->member_count || group->epm_refcount || group->yxstm_refcount) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
  }

  old_mask = group->configured_hart_mask;
  old_count = group->hart_count;

  group->hart_count = hart_count;
  total = group_configured_hart_total_locked();
  if (total > KEYSTONE_GROUP_MAX_CONFIGURED_HARTS ||
      !group_recompute_hart_masks_locked()) {
    group_configure_hart_slots_locked(group, old_mask);
    group->hart_count = old_count;
    group_recompute_hart_masks_locked();
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }

  sbi_printf("[SM][group] configured group=%lu hart_count=%lu hart_mask=0x%lx total_harts=%lu\n",
             (unsigned long)group_id,
             (unsigned long)hart_count,
             (unsigned long)group->configured_hart_mask,
             (unsigned long)total);
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long group_query(uintptr_t out_config)
{
  struct keystone_group_config cfg;
  struct enabled_group_slot* group;

  if (!out_config)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (copy_to_sm(&cfg, out_config, sizeof(cfg)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  {
    unsigned long abi_ret = sm_abi_validate(&cfg.abi, sizeof(cfg),
                                            KEYSTONE_GROUP_ABI_FEATURES);
    if (abi_ret)
      return abi_ret;
  }

  spin_lock(&encl_lock);
  cfg.group_count = configured_group_count;
  group = find_group_locked(cfg.group_id ? cfg.group_id : 1);
  if (group) {
    cfg.group_id = group->group_id;
    cfg.hart_count = group->hart_count;
    cfg.hart_mask = group->configured_hart_mask;
    cfg.member_capacity = group->member_capacity;
    cfg.member_count = group->member_count;
    cfg.lifecycle_state = group->lifecycle_state;
    cfg.generation = group->generation;
  } else {
    cfg.hart_count = 0;
    cfg.hart_mask = 0;
    cfg.member_capacity = 0;
    cfg.member_count = 0;
    cfg.lifecycle_state = KEYSTONE_GROUP_STATE_FREE;
    cfg.generation = 0;
  }
  spin_unlock(&encl_lock);
  sm_abi_fill(&cfg.abi, sizeof(cfg), KEYSTONE_GROUP_ABI_FEATURES);

  if (copy_from_sm(out_config, &cfg, sizeof(cfg)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static void group_fill_topology_locked(
    const struct enabled_group_slot* group,
    struct keystone_group_topology* topology)
{
  if (!group || !topology)
    return;
  topology->group_id = group->group_id;
  topology->group_generation = group->generation;
  topology->execution_mode = group->execution_mode;
  topology->housekeeping_cpu = group->housekeeping_cpu;
  topology->housekeeping_hart = group->housekeeping_hart;
  topology->master_hart = group->master_hart;
  topology->worker_hart_mask = group->worker_hart_mask;
  topology->worker_count = group->worker_count;
  topology->configured_hart_mask = group->configured_hart_mask;
  topology->cpu_hart_offset = group->cpu_hart_offset;
  topology->lease_state = group->lease_state;
  topology->flags = group->topology_flags;
  topology->status = SBI_ERR_SM_ENCLAVE_SUCCESS;
  topology->topology_epoch = group->topology_epoch;
  sm_abi_fill(&topology->abi, sizeof(*topology),
              KEYSTONE_GROUP_ABI_FEATURES);
}

unsigned long group_config_topology(uintptr_t inout_topology)
{
  struct keystone_group_topology topology;
  struct enabled_group_slot* group;
  uint64_t execution_mode;
  uint64_t housekeeping_cpu;
  uint64_t housekeeping_hart;
  uint64_t master_hart;
  uint64_t worker_hart_mask;
  uint64_t worker_count;
  uint64_t cpu_hart_offset;
  uint64_t topology_flags;
  uint64_t old_execution_mode;
  uint64_t old_housekeeping_cpu;
  uint64_t old_housekeeping_hart;
  uint64_t old_master_hart;
  uint64_t old_worker_hart_mask;
  uint64_t old_worker_count;
  uint64_t old_cpu_hart_offset;
  uint64_t old_topology_flags;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (!inout_topology ||
      copy_to_sm(&topology, inout_topology, sizeof(topology)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&topology.abi, sizeof(topology),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;

  spin_lock(&encl_lock);
  group = find_group_locked(topology.group_id);
  if (!group || (topology.group_generation &&
                 topology.group_generation != group->generation)) {
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto out;
  }
  if (group->lifecycle_state != KEYSTONE_GROUP_STATE_CONFIGURING ||
      group->member_count || group->registered_member_count ||
      group->pending_create_count || group->epm_refcount ||
      group->yxstm_refcount || group->active_hart_bitmap ||
      group->lease_state != KEYSTONE_GROUP_LEASE_FREE) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }
  if (topology.configured_hart_mask &&
      topology.configured_hart_mask != group->configured_hart_mask) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  execution_mode = topology.execution_mode;
  if (execution_mode != GROUP_MODE_3W_1HM &&
      execution_mode != GROUP_MODE_SATURATION_TEST) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  if (execution_mode == GROUP_MODE_3W_1HM) {
    housekeeping_cpu = KEYSTONE_VF2_HOUSEKEEPING_CPU;
    housekeeping_hart = KEYSTONE_VF2_HOUSEKEEPING_HART;
    master_hart = KEYSTONE_VF2_HOUSEKEEPING_HART;
    worker_hart_mask = KEYSTONE_VF2_WORKER_HART_MASK;
    worker_count = 3;
    cpu_hart_offset = KEYSTONE_VF2_CPU_HART_OFFSET;
    topology_flags = topology.flags |
        KEYSTONE_GROUP_TOPOLOGY_FLAG_EXPLICIT_CPU_HART_MAP |
        KEYSTONE_GROUP_TOPOLOGY_FLAG_REQUIRE_ISOLATION;
    if ((topology.housekeeping_cpu &&
         topology.housekeeping_cpu != housekeeping_cpu) ||
        (topology.housekeeping_hart &&
         topology.housekeeping_hart != housekeeping_hart) ||
        (topology.master_hart && topology.master_hart != master_hart) ||
        (topology.worker_hart_mask &&
         topology.worker_hart_mask != worker_hart_mask) ||
        (topology.worker_count && topology.worker_count != worker_count) ||
        (topology.cpu_hart_offset &&
         topology.cpu_hart_offset != cpu_hart_offset)) {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      goto out;
    }
  } else {
    master_hart = topology.master_hart;
    if (!master_hart)
      master_hart = group_first_hart_in_mask(group->configured_hart_mask);
    housekeeping_hart = topology.housekeeping_hart ?
        topology.housekeeping_hart : master_hart;
    cpu_hart_offset = topology.cpu_hart_offset ?
        topology.cpu_hart_offset : KEYSTONE_VF2_CPU_HART_OFFSET;
    if (housekeeping_hart < cpu_hart_offset) {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      goto out;
    }
    housekeeping_cpu = topology.housekeeping_cpu;
    if (!housekeeping_cpu)
      housekeeping_cpu = housekeeping_hart - cpu_hart_offset;
    worker_hart_mask = topology.worker_hart_mask ?
        topology.worker_hart_mask :
        group->configured_hart_mask & ~group_hart_bit(master_hart);
    worker_count = topology.worker_count ? topology.worker_count :
        group_hart_mask_popcount(worker_hart_mask);
    topology_flags = topology.flags |
        KEYSTONE_GROUP_TOPOLOGY_FLAG_EXPLICIT_CPU_HART_MAP;
  }

  old_execution_mode = group->execution_mode;
  old_housekeeping_cpu = group->housekeeping_cpu;
  old_housekeeping_hart = group->housekeeping_hart;
  old_master_hart = group->master_hart;
  old_worker_hart_mask = group->worker_hart_mask;
  old_worker_count = group->worker_count;
  old_cpu_hart_offset = group->cpu_hart_offset;
  old_topology_flags = group->topology_flags;

  group->execution_mode = execution_mode;
  group->housekeeping_cpu = housekeeping_cpu;
  group->housekeeping_hart = housekeeping_hart;
  group->master_hart = master_hart;
  group->worker_hart_mask = worker_hart_mask;
  group->worker_count = worker_count;
  group->cpu_hart_offset = cpu_hart_offset;
  group->topology_flags = topology_flags;
  if (!group_topology_validate_locked(group) ||
      group_topology_rebuild_lanes_locked(group)) {
    group->execution_mode = old_execution_mode;
    group->housekeeping_cpu = old_housekeeping_cpu;
    group->housekeeping_hart = old_housekeeping_hart;
    group->master_hart = old_master_hart;
    group->worker_hart_mask = old_worker_hart_mask;
    group->worker_count = old_worker_count;
    group->cpu_hart_offset = old_cpu_hart_offset;
    group->topology_flags = old_topology_flags;
    (void)group_topology_rebuild_lanes_locked(group);
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  group->topology_epoch++;
  if (!group->topology_epoch)
    group->topology_epoch = 1;
  sbi_printf("[SM][group] topology: group=%lu generation=%lu mode=%lu housekeeping=cpu%lu/hart%lu master=%lu workers=0x%lx count=%lu epoch=%lu\n",
             (unsigned long)group->group_id,
             (unsigned long)group->generation,
             (unsigned long)group->execution_mode,
             (unsigned long)group->housekeeping_cpu,
             (unsigned long)group->housekeeping_hart,
             (unsigned long)group->master_hart,
             (unsigned long)group->worker_hart_mask,
             (unsigned long)group->worker_count,
             (unsigned long)group->topology_epoch);
out:
  if (group)
    group_fill_topology_locked(group, &topology);
  topology.status = ret;
  spin_unlock(&encl_lock);
  if (copy_from_sm(inout_topology, &topology, sizeof(topology)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return ret;
}

unsigned long group_query_topology(uintptr_t inout_topology)
{
  struct keystone_group_topology topology;
  struct enabled_group_slot* group;
  unsigned long ret;

  if (!inout_topology ||
      copy_to_sm(&topology, inout_topology, sizeof(topology)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&topology.abi, sizeof(topology),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;

  spin_lock(&encl_lock);
  group = find_group_locked(topology.group_id ? topology.group_id : 1);
  if (!group) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  group_fill_topology_locked(group, &topology);
  spin_unlock(&encl_lock);
  if (copy_from_sm(inout_topology, &topology, sizeof(topology)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long group_set_lease_state(uintptr_t inout_lease)
{
  struct keystone_group_lease lease;
  struct enabled_group_slot* group;
  uint64_t requested;
  unsigned long hartid;
  uint64_t kick_mask = 0;
  int valid_transition = 0;
  unsigned long ret;

  if (!inout_lease || copy_to_sm(&lease, inout_lease, sizeof(lease)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&lease.abi, sizeof(lease),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;
  requested = lease.lease_state;

  spin_lock(&encl_lock);
  group = find_group_locked(lease.group_id);
  if (!group || lease.group_generation != group->generation) {
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto lease_out;
  }
  if (group->lifecycle_state != KEYSTONE_GROUP_STATE_ACTIVE ||
      group->execution_mode != GROUP_MODE_3W_1HM ||
      lease.worker_hart_mask != group->worker_hart_mask) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto lease_out;
  }
  if (requested == group->lease_state) {
    valid_transition = 1;
  } else if (group->lease_state == KEYSTONE_GROUP_LEASE_FREE &&
             requested == KEYSTONE_GROUP_LEASE_DRAINING) {
    valid_transition = 1;
  } else if (group->lease_state == KEYSTONE_GROUP_LEASE_DRAINING &&
             requested == KEYSTONE_GROUP_LEASE_LEASED) {
    valid_transition = 1;
  } else if (group->lease_state == KEYSTONE_GROUP_LEASE_DRAINING &&
             requested == KEYSTONE_GROUP_LEASE_FAILED) {
    valid_transition = 1;
  } else if ((group->lease_state == KEYSTONE_GROUP_LEASE_LEASED ||
              group->lease_state == KEYSTONE_GROUP_LEASE_FAILED) &&
             requested == KEYSTONE_GROUP_LEASE_RELEASING) {
    valid_transition = 1;
  } else if (group->lease_state == KEYSTONE_GROUP_LEASE_RELEASING &&
             requested == KEYSTONE_GROUP_LEASE_FREE &&
             !(group->active_hart_bitmap & group->worker_hart_mask)) {
    valid_transition = 1;
  }
  if (!valid_transition) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto lease_out;
  }

  if (lease.flags & ~(KEYSTONE_GROUP_LEASE_FLAG_REQUIRE_ISOLATION |
                      KEYSTONE_GROUP_LEASE_FLAG_TEST_FALLBACK |
                      KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT |
                      KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE |
                      KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE)) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto lease_out;
  }
  if (lease.flags & KEYSTONE_GROUP_LEASE_FLAG_TEST_FALLBACK) {
    if ((lease.flags & (KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE |
                        KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE)) ||
        !(lease.flags & KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT)) {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      goto lease_out;
    }
  } else if (!(lease.flags & KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE) ||
             (lease.flags & KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT)) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto lease_out;
  }

  if (group->lease_state == KEYSTONE_GROUP_LEASE_FREE &&
      requested == KEYSTONE_GROUP_LEASE_DRAINING)
    group->lease_flags = lease.flags;
  else if (requested != KEYSTONE_GROUP_LEASE_FREE &&
           lease.flags != group->lease_flags) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto lease_out;
  }

  if (requested != group->lease_state) {
    group->lease_state = requested;
    group->lease_epoch++;
    if (!group->lease_epoch)
      group->lease_epoch = 1;
  }
  if (requested == KEYSTONE_GROUP_LEASE_LEASED ||
      requested == KEYSTONE_GROUP_LEASE_RELEASING ||
      requested == KEYSTONE_GROUP_LEASE_FREE) {
    for (hartid = 0; hartid < MAX_HARTS; hartid++) {
      struct sm_hart_sched* sched;

      if (!(group->worker_hart_mask & group_hart_bit(hartid)))
        continue;
      sched = &group_hart_schedulers[hartid];
      if (requested == KEYSTONE_GROUP_LEASE_LEASED &&
          (group->lease_flags & KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE))
        kick_mask |= group_hart_bit(hartid);
      if (requested == KEYSTONE_GROUP_LEASE_RELEASING) {
        /*
         * Do not gate release on an active_harts snapshot.  A release can race
         * with the short schedule-out/schedule-in interval where no member is
         * published active even though the runner still owns this hart.  Mark
         * and kick every worker lane so either the current member returns to
         * its saved HOST frame or the next group_run_hart observes RELEASING.
         * The lease boundary drops, rather than suspends, any dynamic grant.
         */
        sched->host_service_forced = 1;
        sched->host_service_drop_grant = 1;
        kick_mask |= group_hart_bit(hartid);
      }
      sched->heartbeat_enabled =
          requested == KEYSTONE_GROUP_LEASE_LEASED &&
          (group->lease_flags &
           KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT) != 0;
      sched->host_service_deadline = 0;
      if (!sched->heartbeat_enabled) {
        sched->heartbeat_state = KEYSTONE_GROUP_HEARTBEAT_STATE_IDLE;
        sched->heartbeat_pending_sources = 0;
        sched->heartbeat_handoff_sources = 0;
        sched->heartbeat_cleared_sources = 0;
      }
      if (requested == KEYSTONE_GROUP_LEASE_FREE)
        group_scheduler_clear_host_service_locked(sched);
    }
  }
  if (requested == KEYSTONE_GROUP_LEASE_FREE)
    group->lease_flags = 0;
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
lease_out:
  lease.group_generation = group ? group->generation : 0;
  lease.worker_hart_mask = group ? group->worker_hart_mask : 0;
  lease.lease_state = group ? group->lease_state : KEYSTONE_GROUP_LEASE_FAILED;
  lease.status = ret;
  lease.lease_epoch = group ? group->lease_epoch : 0;
  sm_abi_fill(&lease.abi, sizeof(lease), KEYSTONE_GROUP_ABI_FEATURES);
  spin_unlock(&encl_lock);
  if (!ret && kick_mask && group_scheduler_ipi_kick((ulong)kick_mask))
    sbi_printf("[SM][sched] lease transition IPI failed: group=%lu mask=0x%lx\n",
               (unsigned long)lease.group_id,
               (unsigned long)kick_mask);
  if (copy_from_sm(inout_lease, &lease, sizeof(lease)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return ret;
}

unsigned long group_test_snapshot(uintptr_t out_snapshot)
{
  struct keystone_group_test_snapshot snapshot;
  struct group_coherence_test_stats ipi_stats;
  struct enabled_group_slot* selected = NULL;
  uintptr_t requested_group_id;
  size_t i;
  size_t j;

  if (!out_snapshot || copy_to_sm(&snapshot, out_snapshot, sizeof(snapshot)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  {
    unsigned long abi_ret = sm_abi_validate(
        &snapshot.abi, sizeof(snapshot), KEYSTONE_GROUP_TEST_ABI_FEATURES);
    if (abi_ret)
      return abi_ret;
  }
  requested_group_id = snapshot.group_id;
  sbi_memset(&snapshot, 0, sizeof(snapshot));
  snapshot.group_id = requested_group_id;

  spin_lock(&encl_lock);
  for (i = 0; i < ENCL_MAX; i++) {
    if (enclaves[i].state < 0)
      continue;
    snapshot.live_enclaves++;
    if (enclaves[i].group_id)
      snapshot.live_group_enclaves++;
  }
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    struct enabled_group_slot* group = &enabled_groups[i];
    if (!group->valid)
      continue;
    snapshot.live_groups++;
    if (snapshot.group_id && snapshot.group_id == group->group_id)
      selected = group;
    for (j = 0; j < group->member_metadata_capacity; j++)
      if (group->members[j].valid)
        snapshot.live_members++;
  }
  if (selected) {
    snapshot.group_generation = selected->generation;
    snapshot.member_capacity = selected->member_capacity;
    snapshot.member_metadata_capacity =
        selected->member_metadata_capacity;
    snapshot.metadata_bytes = selected->metadata_bytes;
    snapshot.max_running_workers = selected->max_running_workers;
    for (i = 0; i < KEYSTONE_GROUP_MAX_WORKER_LANES; i++) {
      struct group_worker_lane* lane = &selected->worker_lanes[i];
      if (!lane->valid)
        continue;
      if (lane->state == GROUP_WORKER_LANE_RUNNING)
        snapshot.running_workers++;
      snapshot.lane_owner_switches += lane->owner_switch_count;
      snapshot.lane_scrubs += lane->scrub_count;
    }
    snapshot.master_non_boundary_entries =
        selected->master_non_boundary_entries;
  }
  snapshot.metadata_free_bytes = group_metadata_free_bytes_locked();
  for (i = 0; i < MAX_HARTS; i++) {
    if (group_active_harts[i].active &&
        (!snapshot.group_id ||
         group_active_harts[i].active_group_id == snapshot.group_id))
      snapshot.active_harts++;
    if (group_hart_schedulers[i].valid &&
        (!snapshot.group_id ||
         group_hart_schedulers[i].active_group_id == snapshot.group_id))
      snapshot.runqueue_entries += group_hart_schedulers[i].runqueue_len;
    if (!snapshot.group_id ||
        (group_hart_schedulers[i].valid &&
         group_hart_schedulers[i].active_group_id == snapshot.group_id)) {
      snapshot.event_queue_entries += group_hart_event_queues[i].count;
      snapshot.event_queue_overflows +=
          group_hart_event_queues[i].overflow_count;
    }
  }
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    struct enabled_group_slot* group = &enabled_groups[i];
    if (!group->valid ||
        (snapshot.group_id && group->group_id != snapshot.group_id))
      continue;
    for (j = 0; j < MAX_HARTS; j++)
      if (group->hart_slots[j].valid && group->hart_slots[j].yxstm_acquired)
        snapshot.acquired_yxstm_harts++;
  }
  snapshot.pmp_regions = pmp_defined_region_count();
  spin_unlock(&encl_lock);

  group_coherence_test_get_stats(&ipi_stats);
  snapshot.ipi_requests = ipi_stats.requests;
  snapshot.ipi_acks = ipi_stats.acks;
  snapshot.ipi_timeouts = ipi_stats.timeouts;
  snapshot.coherence_failures = ipi_stats.failures;
  sm_abi_fill(&snapshot.abi, sizeof(snapshot),
              KEYSTONE_GROUP_TEST_ABI_FEATURES);
  if (copy_from_sm(out_snapshot, &snapshot, sizeof(snapshot)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long group_test_inject(uintptr_t inout_injection)
{
  struct keystone_group_test_injection injection;
  int ret;

  if (!inout_injection ||
      copy_to_sm(&injection, inout_injection, sizeof(injection)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  {
    unsigned long abi_ret = sm_abi_validate(
        &injection.abi, sizeof(injection), KEYSTONE_GROUP_TEST_ABI_FEATURES);
    if (abi_ret)
      return abi_ret;
  }
  if (injection.group_id) {
    spin_lock(&encl_lock);
    ret = find_group_locked(injection.group_id) ? 0 : -1;
    spin_unlock(&encl_lock);
    if (ret)
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  ret = group_coherence_test_inject(injection.operation,
                                    injection.hart_id,
                                    injection.count);
  if (ret)
    return ret == SBI_ENOTSUPP ? SBI_ERR_SM_NOT_IMPLEMENTED :
                                SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  injection.result = 0;
  sm_abi_fill(&injection.abi, sizeof(injection),
              KEYSTONE_GROUP_TEST_ABI_FEATURES);
  if (copy_from_sm(inout_injection, &injection, sizeof(injection)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static void group_perf_reset_counters_locked(void)
{
  atomic_write(&group_perf_acquire_count, 0);
  atomic_write(&group_perf_acquire_cycles, 0);
  atomic_write(&group_perf_release_count, 0);
  atomic_write(&group_perf_release_cycles, 0);
  sbi_memset(group_perf_harts, 0, sizeof(group_perf_harts));
  atomic_write(&group_perf_ocall_count, 0);
  atomic_write(&group_perf_ocall_cycles, 0);
  atomic_write(&group_perf_ocall_handler_count, 0);
  atomic_write(&group_perf_ocall_handler_cycles, 0);
  atomic_write(&group_perf_ocall_wait_count, 0);
  atomic_write(&group_perf_ocall_wait_ticks, 0);
  atomic_write(&group_perf_lane_wait_block_count, 0);
  atomic_write(&group_perf_lane_wait_wake_count, 0);
  atomic_write(&group_perf_lane_wait_ticks, 0);
  atomic_write(&group_perf_heartbeat_count, 0);
  atomic_write(&group_perf_heartbeat_cycles, 0);
  atomic_write(&group_perf_ipi_count, 0);
  atomic_write(&group_perf_ipi_cycles, 0);
  atomic_write(&group_perf_host_service_count, 0);
  atomic_write(&group_perf_host_service_cycles, 0);
  atomic_write(&group_perf_grant_suspend_restore_count, 0);
  atomic_write(&group_perf_grant_suspend_restore_cycles, 0);
  atomic_write(&group_perf_scrub_count, 0);
  atomic_write(&group_perf_scrub_bytes, 0);
  atomic_write(&group_perf_scrub_cycles, 0);
}

unsigned long group_perf_query(uintptr_t inout_snapshot)
{
  struct keystone_group_perf_snapshot snapshot;
  struct enabled_group_slot* group;
  uintptr_t requested_group_id;
  uintptr_t requested_member_query;
  uintptr_t requested_member_eid;
  uintptr_t operation;
  unsigned long pmp_count = 0;
  unsigned long pmp_cycles = 0;
  unsigned long hartid;
  uint64_t now;
  size_t i;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
  int reset_pmp = 0;

  if (!inout_snapshot ||
      copy_to_sm(&snapshot, inout_snapshot, sizeof(snapshot)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(
      &snapshot.abi, sizeof(snapshot), KEYSTONE_GROUP_PERF_ABI_FEATURES);
  if (ret)
    return ret;
  requested_group_id = snapshot.group_id;
  requested_member_query = snapshot.member_query;
  requested_member_eid = snapshot.member_eid;
  operation = snapshot.operation;
  if (operation > KEYSTONE_GROUP_PERF_FREEZE || requested_member_query > 1)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  sbi_memset(&snapshot, 0, sizeof(snapshot));
  snapshot.group_id = requested_group_id;
  snapshot.member_query = requested_member_query;
  snapshot.member_eid = requested_member_eid;
  snapshot.operation = operation;
  snapshot.cycle_source = KEYSTONE_GROUP_PERF_CYCLE_MCYCLE;

  spin_lock(&encl_lock);
  group = requested_group_id ? find_group_locked(requested_group_id) : NULL;
  if (requested_group_id && !group) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out_unlock;
  }
  if (requested_member_query && !group) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out_unlock;
  }
  now = sbi_timer_value();
  if (operation == KEYSTONE_GROUP_PERF_BEGIN) {
    if (!group || group_perf_window_state ==
                      KEYSTONE_GROUP_PERF_WINDOW_ACTIVE) {
      ret = SBI_ERR_SM_GROUP_BAD_STATE;
      goto out_unlock;
    }
    group_perf_reset_counters_locked();
    group_perf_window_epoch++;
    if (!group_perf_window_epoch)
      group_perf_window_epoch = 1;
    group_perf_window_state = KEYSTONE_GROUP_PERF_WINDOW_ACTIVE;
    group_perf_window_group_id = group->group_id;
    group_perf_window_group_generation = group->generation;
    group_perf_window_start_ticks = now;
    group_perf_window_stop_ticks = 0;
    group_perf_window_reset_members_locked(group, now);
    reset_pmp = 1;
  } else if (operation == KEYSTONE_GROUP_PERF_FREEZE) {
    if (!group ||
        group_perf_window_state != KEYSTONE_GROUP_PERF_WINDOW_ACTIVE ||
        group_perf_window_group_id != group->group_id ||
        group_perf_window_group_generation != group->generation ||
        !group_perf_window_freeze_members_locked(group, now)) {
      ret = SBI_ERR_SM_GROUP_BAD_STATE;
      goto out_unlock;
    }
    group_perf_window_stop_ticks = now;
    group_perf_window_state = KEYSTONE_GROUP_PERF_WINDOW_FROZEN;
  } else if (operation == KEYSTONE_GROUP_PERF_RESET) {
    group_perf_reset_counters_locked();
    if (group)
      group_perf_window_reset_members_locked(group, now);
    group_perf_window_state = KEYSTONE_GROUP_PERF_WINDOW_IDLE;
    group_perf_window_group_id = 0;
    group_perf_window_group_generation = 0;
    group_perf_window_start_ticks = 0;
    group_perf_window_stop_ticks = 0;
    reset_pmp = 1;
  }

  if (group)
    snapshot.group_generation = group->generation;
  snapshot.window_state = group_perf_window_state;
  snapshot.window_epoch = group_perf_window_epoch;
  snapshot.window_start_ticks = group_perf_window_start_ticks;
  snapshot.window_stop_ticks = group_perf_window_stop_ticks;
  snapshot.acquire_count =
      (uintptr_t)atomic_read(&group_perf_acquire_count);
  snapshot.acquire_cycles =
      (uintptr_t)atomic_read(&group_perf_acquire_cycles);
  snapshot.release_count =
      (uintptr_t)atomic_read(&group_perf_release_count);
  snapshot.release_cycles =
      (uintptr_t)atomic_read(&group_perf_release_cycles);
  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    struct group_perf_hart_local* perf = &group_perf_harts[hartid];

    snapshot.context_switch_count += perf->context_switch_count;
    snapshot.context_switch_cycles += perf->context_switch_cycles;
    snapshot.context_switch_ticks += perf->context_switch_ticks;
    snapshot.context_gpr_cycles += perf->context_gpr_cycles;
    snapshot.context_smode_csr_cycles += perf->context_smode_csr_cycles;
    snapshot.context_fp_cycles += perf->context_fp_cycles;
    snapshot.context_pmp_cycles += perf->context_pmp_cycles;
    snapshot.context_platform_cycles += perf->context_platform_cycles;
    snapshot.context_scheduler_lock_cycles +=
        perf->context_scheduler_lock_cycles;
    snapshot.pmp_grant_suspend_cycles += perf->pmp_grant_suspend_cycles;
    snapshot.pmp_epm_revoke_cycles += perf->pmp_epm_revoke_cycles;
    snapshot.pmp_epm_install_cycles += perf->pmp_epm_install_cycles;
    snapshot.pmp_yxstm_restore_cycles += perf->pmp_yxstm_restore_cycles;
    snapshot.pmp_fence_cycles += perf->pmp_fence_cycles;
    snapshot.pmp_validation_cycles += perf->pmp_validation_cycles;
    snapshot.pmp_lock_wait_cycles += perf->pmp_lock_wait_cycles;
    snapshot.cfs_pick_count += perf->cfs_pick_count;
    snapshot.cfs_preempt_count += perf->cfs_preempt_count;
    snapshot.cfs_runtime_ticks += perf->cfs_runtime_ticks;
    snapshot.cfs_vruntime_delta += perf->cfs_vruntime_delta;
    snapshot.cfs_slice_ticks += perf->cfs_slice_ticks;
    snapshot.cfs_min_granularity_count += perf->cfs_min_granularity_count;
    if (perf->cfs_dynamic_min_slice_ticks >
        snapshot.cfs_dynamic_min_slice_ticks)
      snapshot.cfs_dynamic_min_slice_ticks =
          perf->cfs_dynamic_min_slice_ticks;
    snapshot.timer_trap_count += perf->timer_trap_count;
    snapshot.timer_trap_cycles += perf->timer_trap_cycles;
  }
  snapshot.ocall_count = (uintptr_t)atomic_read(&group_perf_ocall_count);
  snapshot.ocall_cycles = (uintptr_t)atomic_read(&group_perf_ocall_cycles);
  snapshot.ocall_handler_count =
      (uintptr_t)atomic_read(&group_perf_ocall_handler_count);
  snapshot.ocall_handler_cycles =
      (uintptr_t)atomic_read(&group_perf_ocall_handler_cycles);
  snapshot.ocall_wait_count =
      (uintptr_t)atomic_read(&group_perf_ocall_wait_count);
  snapshot.ocall_wait_ticks =
      (uintptr_t)atomic_read(&group_perf_ocall_wait_ticks);
  snapshot.lane_wait_block_count =
      (uintptr_t)atomic_read(&group_perf_lane_wait_block_count);
  snapshot.lane_wait_wake_count =
      (uintptr_t)atomic_read(&group_perf_lane_wait_wake_count);
  snapshot.lane_wait_ticks =
      (uintptr_t)atomic_read(&group_perf_lane_wait_ticks);
  snapshot.heartbeat_count =
      (uintptr_t)atomic_read(&group_perf_heartbeat_count);
  snapshot.heartbeat_cycles =
      (uintptr_t)atomic_read(&group_perf_heartbeat_cycles);
  snapshot.ipi_shootdown_count =
      (uintptr_t)atomic_read(&group_perf_ipi_count);
  snapshot.ipi_shootdown_cycles =
      (uintptr_t)atomic_read(&group_perf_ipi_cycles);
  snapshot.host_service_count =
      (uintptr_t)atomic_read(&group_perf_host_service_count);
  snapshot.host_service_cycles =
      (uintptr_t)atomic_read(&group_perf_host_service_cycles);
  snapshot.grant_suspend_restore_count =
      (uintptr_t)atomic_read(&group_perf_grant_suspend_restore_count);
  snapshot.grant_suspend_restore_cycles =
      (uintptr_t)atomic_read(&group_perf_grant_suspend_restore_cycles);
  snapshot.scrub_count =
      (uintptr_t)atomic_read(&group_perf_scrub_count);
  snapshot.scrub_bytes =
      (uintptr_t)atomic_read(&group_perf_scrub_bytes);
  snapshot.scrub_cycles =
      (uintptr_t)atomic_read(&group_perf_scrub_cycles);

  if (group && group->members) {
    uint64_t aes_min = ~(uint64_t)0;

    for (i = 0; i < group->member_metadata_capacity; i++) {
      struct group_member_descriptor* member = &group->members[i];
      uint64_t exec_runtime;

      if (!member->valid)
        continue;
      if (group_perf_window_state == KEYSTONE_GROUP_PERF_WINDOW_ACTIVE) {
        uint64_t current = group_member_exec_runtime_now_locked(member, now);
        exec_runtime = current >= member->perf_window_exec_baseline ?
            current - member->perf_window_exec_baseline : 0;
      } else {
        exec_runtime = member->perf_window_exec_runtime;
      }
      if (member->role == GROUP_ROLE_WORKER) {
        snapshot.worker_runtime_members++;
        snapshot.worker_exec_runtime_ticks += exec_runtime;
        snapshot.worker_aes_exec_runtime_ticks +=
            member->perf_aes_exec_runtime;
        if (member->perf_aes_exec_runtime < aes_min)
          aes_min = member->perf_aes_exec_runtime;
        if (member->perf_aes_exec_runtime >
            snapshot.worker_aes_exec_runtime_max)
          snapshot.worker_aes_exec_runtime_max =
              member->perf_aes_exec_runtime;
      }
      if (requested_member_query && member->eid == requested_member_eid) {
        snapshot.member_generation = member->eid_generation;
        snapshot.member_role = member->role;
        snapshot.member_exec_runtime_ticks = exec_runtime;
        snapshot.member_aes_exec_runtime_ticks =
            member->perf_aes_exec_runtime;
      }
    }
    snapshot.worker_aes_exec_runtime_min =
        aes_min == ~(uint64_t)0 ? 0 : aes_min;
    if (requested_member_query && !snapshot.member_generation) {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      goto out_unlock;
    }
  }

out_unlock:
  spin_unlock(&encl_lock);
  if (ret)
    return ret;

  pmp_perf_snapshot(&pmp_count, &pmp_cycles, reset_pmp);
  if (!reset_pmp) {
    snapshot.pmp_update_count = pmp_count;
    snapshot.pmp_update_cycles = pmp_cycles;
  }
  sm_abi_fill(&snapshot.abi, sizeof(snapshot),
              KEYSTONE_GROUP_PERF_ABI_FEATURES);
  if (copy_from_sm(inout_snapshot, &snapshot, sizeof(snapshot)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int group_roles_valid_locked(struct enabled_group_slot* group)
{
  size_t masters = 0;
  int i;

  if (!group)
    return 0;
  for (i = 0; i < (int)group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];
    if (!member->valid)
      continue;
    if (member->group_generation != group->generation ||
        member->eid >= ENCL_MAX ||
        member->eid_generation != enclaves[member->eid].generation)
      return 0;
    if (member->role == GROUP_ROLE_MASTER) {
      masters++;
      if (member->bound_hart != group->master_hart ||
          member->lane_id != KEYSTONE_GROUP_UNBOUND_LANE ||
          member->allowed_slice_mask != KEYSTONE_YXSTM_MASTER_SLICE_MASK)
        return 0;
    } else if (member->role == GROUP_ROLE_WORKER) {
      struct group_worker_lane* lane =
          group_lane_for_id_locked(group, member->lane_id);
      if (!lane || member->bound_hart != lane->hart_id ||
          member->allowed_slice_mask != lane->slice_mask ||
          !member->allowed_slice_mask ||
          (member->allowed_slice_mask & (member->allowed_slice_mask - 1)))
        return 0;
    } else if (member->role == GROUP_ROLE_AUXILIARY) {
      if (group->execution_mode != GROUP_MODE_SATURATION_TEST ||
          member->bound_hart != group->master_hart ||
          member->lane_id != KEYSTONE_GROUP_UNBOUND_LANE ||
          member->allowed_slice_mask)
        return 0;
    } else {
      return 0;
    }
  }
  return masters == 1;
}

static void group_quiesce_members_for_destroy_locked(
    struct enabled_group_slot* group)
{
  size_t quiesced = 0;
  int i;

  if (!group)
    return;

  for (i = 0; i < (int)group->member_metadata_capacity; i++) {
    struct group_member_descriptor* member = &group->members[i];
    enclave_id eid;

    if (!member->valid)
      continue;
    eid = member->eid;
    if (member->group_generation != group->generation ||
        eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
        member->eid_generation != enclaves[eid].generation ||
        enclaves[eid].group_id != group->group_id) {
      sbi_printf("[SM][group] destroy found stale member: group=%lu generation=%lu slot=%d eid=%u\n",
                 (unsigned long)group->group_id,
                 (unsigned long)group->generation, i, eid);
      continue;
    }

    group_control_requests[eid] = 0;
    group_ocall_clear_locked(eid, 0);
    group_release_yxstm_owner_metadata_locked(eid);
    group_member_timer_ready[eid] = 0;
    group_member_saved_mepc_advanced[eid] = 0;
    group_scheduler_set_state_locked(eid, GROUP_SCHED_EXITED);
    group_scheduler_remove_eid_locked(eid);
    enclaves[eid].n_thread = 0;
    enclaves[eid].state = FAULTED;
    quiesced++;
  }

  group_scheduler_event_purge_group(group->group_id, group->generation);
  sbi_printf("[SM][group] quiesced for destroy: group=%lu generation=%lu members=%lu\n",
             (unsigned long)group->group_id,
             (unsigned long)group->generation,
             (unsigned long)quiesced);
}

unsigned long group_create(uintptr_t inout_config)
{
  struct keystone_group_config cfg;
  struct enabled_group_slot* group;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
  int created = 0;

  if (!inout_config || copy_to_sm(&cfg, inout_config, sizeof(cfg)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&cfg.abi, sizeof(cfg),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;
  spin_lock(&encl_lock);
  group = find_group_locked(cfg.group_id);
  if (group && (!cfg.generation || cfg.generation != group->generation)) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }
  if (!group && cfg.generation) {
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto out;
  }
  if (!group) {
    group = find_or_alloc_config_group_locked(cfg.group_id);
    created = group != 0;
  }
  if (!group || group->lifecycle_state != KEYSTONE_GROUP_STATE_CONFIGURING) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }
  if (cfg.member_capacity) {
    if (cfg.member_capacity > KEYSTONE_GROUP_MAX_MEMBERS ||
        (group->member_capacity &&
         group->member_capacity != cfg.member_capacity)) {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      goto out;
    }
    if (!group->members &&
        group_metadata_prepare_locked(group, cfg.member_capacity)) {
      ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
      goto out;
    }
    if (group->member_metadata_capacity != cfg.member_capacity) {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      goto out;
    }
    group->member_capacity = cfg.member_capacity;
  }
  cfg.group_count = configured_group_count;
  cfg.hart_count = group->hart_count;
  cfg.hart_mask = group->configured_hart_mask;
  cfg.member_capacity = group->member_capacity;
  cfg.member_count = group->member_count;
  cfg.lifecycle_state = group->lifecycle_state;
  cfg.generation = group->generation;
  sm_abi_fill(&cfg.abi, sizeof(cfg), KEYSTONE_GROUP_ABI_FEATURES);
out:
  if (ret && created && group && !group->member_count &&
      !group->epm_refcount && !group->yxstm_refcount) {
    group_metadata_release_locked(group);
    sbi_memset(group, 0, sizeof(*group));
  }
  spin_unlock(&encl_lock);
  if (!ret && created)
    group_scheduler_event_purge_group(cfg.group_id, cfg.generation);
  if (!ret && copy_from_sm(inout_config, &cfg, sizeof(cfg))) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    if (created) {
      spin_lock(&encl_lock);
      group = find_group_locked(cfg.group_id);
      if (group && group->generation == cfg.generation &&
          !group->member_count && !group->epm_refcount &&
          !group->yxstm_refcount) {
        group_metadata_release_locked(group);
        sbi_memset(group, 0, sizeof(*group));
      }
      spin_unlock(&encl_lock);
    }
  }
  return ret;
}

unsigned long group_activate(uintptr_t inout_config)
{
  struct keystone_group_config cfg;
  struct enabled_group_slot* group;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (!inout_config || copy_to_sm(&cfg, inout_config, sizeof(cfg)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&cfg.abi, sizeof(cfg),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;
  spin_lock(&encl_lock);
  group = find_group_locked(cfg.group_id);
  if (!group || cfg.generation != group->generation) {
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto out;
  }
  if (group->lifecycle_state == KEYSTONE_GROUP_STATE_ACTIVE)
    goto fill;
  if (!thread_extended_context_supported()) {
    ret = SBI_ERR_SM_GROUP_VECTOR_UNSUPPORTED;
    goto out;
  }
  if (group->lifecycle_state != KEYSTONE_GROUP_STATE_READY ||
      group->pending_create_count || !group->member_count ||
      group->registered_member_count != group->member_count ||
      !group->epm_refcount || !group->yxstm_refcount ||
      !group_topology_validate_locked(group) ||
      !group_roles_valid_locked(group)) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }
  if (group_yxstm_slots_freeze_locked(group)) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }
  group->lifecycle_state = KEYSTONE_GROUP_STATE_ACTIVE;
  sbi_printf("[SM][group] activated: group=%lu generation=%lu members=%lu capacity=%lu resume_pc_fix=1 host_ipi_latch=1\n",
             (unsigned long)group->group_id,
             (unsigned long)group->generation,
             (unsigned long)group->member_count,
             (unsigned long)group->member_capacity);
fill:
  cfg.member_capacity = group->member_capacity;
  cfg.member_count = group->member_count;
  cfg.lifecycle_state = group->lifecycle_state;
  cfg.hart_count = group->hart_count;
  cfg.hart_mask = group->configured_hart_mask;
  sm_abi_fill(&cfg.abi, sizeof(cfg), KEYSTONE_GROUP_ABI_FEATURES);
out:
  spin_unlock(&encl_lock);
  if (!ret && copy_from_sm(inout_config, &cfg, sizeof(cfg)))
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return ret;
}

unsigned long group_destroy(uintptr_t inout_config)
{
  struct keystone_group_config cfg;
  struct enabled_group_slot* group;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (!inout_config || copy_to_sm(&cfg, inout_config, sizeof(cfg)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&cfg.abi, sizeof(cfg),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;
  spin_lock(&encl_lock);
  group = find_group_locked(cfg.group_id);
  if (!group) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  if (cfg.generation != group->generation) {
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto out;
  }
  if (group->active_hart_bitmap || group->pending_create_count ||
      group->coherence_inflight ||
      group->lease_state != KEYSTONE_GROUP_LEASE_FREE) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;
    goto out;
  }
  group->lifecycle_state = KEYSTONE_GROUP_STATE_DRAINING;
  group_quiesce_members_for_destroy_locked(group);
  cfg.lifecycle_state = group->lifecycle_state;
  cfg.member_count = group->member_count;
  sbi_printf("[SM][group] draining: group=%lu generation=%lu members=%lu\n",
             (unsigned long)group->group_id,
             (unsigned long)group->generation,
             (unsigned long)group->member_count);
  maybe_clear_group_locked(group);
  if (!group->valid)
    cfg.lifecycle_state = KEYSTONE_GROUP_STATE_FREE;
  sm_abi_fill(&cfg.abi, sizeof(cfg), KEYSTONE_GROUP_ABI_FEATURES);
out:
  spin_unlock(&encl_lock);
  if (!ret && copy_from_sm(inout_config, &cfg, sizeof(cfg)))
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return ret;
}

unsigned long group_poll_blocked_ocall(uintptr_t out_status)
{
  struct keystone_group_ocall_status status;
  struct enabled_group_slot* group;
  uint64_t requested_hart;
  size_t pending_count = 0;
  int found = 0;
  int h;

  if (!out_status)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (copy_to_sm(&status, out_status, sizeof(status)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  {
    unsigned long abi_ret = sm_abi_validate(&status.abi, sizeof(status),
                                            KEYSTONE_GROUP_ABI_FEATURES);
    if (abi_ret)
      return abi_ret;
  }

  requested_hart = status.hart_id;
  sm_abi_fill(&status.abi, sizeof(status), KEYSTONE_GROUP_ABI_FEATURES);
  status.eid = 0;
  status.pending = 0;
  status.pending_count = 0;
  status.ocall_id = 0;
  status.action = KEYSTONE_GROUP_OCALL_ACTION_NONE;
  status.timeout_cycles = 0;
  status.result = 0;
  status.created_at = 0;
  status.deadline = 0;
  status.host_cookie = 0;
  status.flags = 0;

  spin_lock(&encl_lock);
  group = find_group_locked(status.group_id ? status.group_id : 1);
  if (!group || !group_context_validate_locked(group, "poll_blocked_ocall")) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }
  group_ocall_expire_locked();

  for (h = 0; h < MAX_HARTS; h++) {
    struct sm_hart_sched* sched;
    size_t i;

    if (requested_hart != KEYSTONE_GROUP_OCALL_ANY_HART &&
        requested_hart != (uint64_t)h)
      continue;
    if (!(group->configured_hart_mask & group_hart_bit((unsigned long)h)))
      continue;

    sched = &group_hart_schedulers[h];
    if (!sched->valid)
      continue;
    if (sched->active_group_id && sched->active_group_id != group->group_id)
      continue;

    for (i = 0; i < sched->runqueue_len; i++) {
      enclave_id candidate = sched->runqueue[i].eid;
      if (candidate >= ENCL_MAX || !ENCLAVE_EXISTS(candidate))
        continue;
      if (sched->runqueue[i].eid_generation !=
          enclaves[candidate].generation)
        continue;
      if (enclaves[candidate].group_id != group->group_id)
        continue;
      if (enclaves[candidate].sched_state != GROUP_SCHED_BLOCKED)
        continue;
      if (!group_ocalls[candidate].valid ||
          group_ocalls[candidate].group_generation != group->generation ||
          group_ocalls[candidate].eid_generation !=
              enclaves[candidate].generation)
        continue;

      pending_count++;
      if (!found) {
        status.eid = candidate;
        status.hart_id = (uintptr_t)h;
        status.pending = 1;
        status.ocall_id = group_ocalls[candidate].ocall_id;
        status.created_at = group_ocalls[candidate].created_at;
        status.deadline = group_ocalls[candidate].deadline;
        status.host_cookie = group_ocalls[candidate].host_cookie;
        status.flags = group_ocalls[candidate].flags;
        status.timeout_cycles =
            (int64_t)(group_ocalls[candidate].deadline - sbi_timer_value()) > 0 ?
            group_ocalls[candidate].deadline - sbi_timer_value() : 0;
        found = 1;
      }
    }
  }

  status.group_id = group->group_id;
  status.pending_count = pending_count;
  spin_unlock(&encl_lock);

  if (copy_from_sm(out_status, &status, sizeof(status)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long group_resume_blocked_ocall(uintptr_t inout_status)
{
  struct keystone_group_ocall_status status;
  struct enabled_group_slot* group;
  enclave_id eid;
  uint64_t group_id;
  uint64_t requested_hart;
  unsigned long hartid;
  uint64_t handler_started = csr_read(CSR_MCYCLE);
  int active = 0;
  int defer_host_kick = 0;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (!inout_status)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (copy_to_sm(&status, inout_status, sizeof(status)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&status.abi, sizeof(status),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;

  group_id = status.group_id ? status.group_id : 1;
  requested_hart = status.hart_id;
  eid = (enclave_id)status.eid;
  defer_host_kick =
      !!(status.flags & KEYSTONE_GROUP_OCALL_FLAG_DEFER_HOST_KICK);

  spin_lock(&encl_lock);
  group = find_group_locked(group_id);
  if (!group || !group_context_validate_locked(group, "resume_blocked_ocall")) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  if (eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
      enclaves[eid].group_id != group->group_id) {
    sbi_printf("[SM][ocall] resume rejected: invalid member group=%lu eid=%u\n",
               (unsigned long)group->group_id, eid);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
    goto out;
  }
  if (!group_ocalls[eid].valid ||
      group_ocalls[eid].group_generation != group->generation ||
      group_ocalls[eid].eid_generation != enclaves[eid].generation ||
      (status.ocall_id &&
       status.ocall_id != group_ocalls[eid].ocall_id) ||
      (status.host_cookie &&
       status.host_cookie != group_ocalls[eid].host_cookie)) {
    sbi_printf("[SM][ocall] resume rejected: stale record group=%lu eid=%u requested=%lu valid=%d current=%lu group_gen=%lu/%lu eid_gen=%lu/%lu\n",
               (unsigned long)group->group_id, eid,
               (unsigned long)status.ocall_id,
               group_ocalls[eid].valid,
               (unsigned long)group_ocalls[eid].ocall_id,
               (unsigned long)group_ocalls[eid].group_generation,
               (unsigned long)group->generation,
               (unsigned long)group_ocalls[eid].eid_generation,
               (unsigned long)enclaves[eid].generation);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
    goto out;
  }

  /*
   * The generation-bound OCALL record and BLOCKED scheduler state are the
   * authoritative transaction.  The generic Keystone state/n_thread pair is
   * updated before the member frame is switched back to Linux, but it can
   * still contain the pre-switch RUNNING/1 image when the host return uses
   * the per-hart group frame.  It is safe to normalize that bookkeeping only
   * after proving that no active-hart or scheduler slot still owns this eid.
   */
  for (hartid = 0; hartid < MAX_HARTS; hartid++) {
    if ((group_active_harts[hartid].active &&
         group_active_harts[hartid].eid == eid &&
         group_active_harts[hartid].eid_generation ==
             enclaves[eid].generation) ||
        (group_hart_schedulers[hartid].valid &&
         group_hart_schedulers[hartid].active_eid == eid &&
         group_hart_schedulers[hartid].active_eid_generation ==
             enclaves[eid].generation)) {
      active = 1;
      break;
    }
  }
  if (enclaves[eid].sched_state != GROUP_SCHED_BLOCKED || active) {
    sbi_printf("[SM][ocall] resume rejected: group=%lu eid=%u ocall=%lu sched=%u state=%d threads=%u active=%d\n",
               (unsigned long)group->group_id, eid,
               (unsigned long)group_ocalls[eid].ocall_id,
               (unsigned int)enclaves[eid].sched_state,
               (int)enclaves[eid].state, enclaves[eid].n_thread, active);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
    goto out;
  }
  if (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED) {
    if (enclaves[eid].state != STOPPED || enclaves[eid].n_thread != 0) {
#if KEYSTONE_GROUP_OCALL_TRACE
      sbi_printf("[SM][ocall] normalized stopped state: group=%lu eid=%u ocall=%lu state=%d threads=%u\n",
                 (unsigned long)group->group_id, eid,
                 (unsigned long)group_ocalls[eid].ocall_id,
                 (int)enclaves[eid].state, enclaves[eid].n_thread);
#endif
      enclaves[eid].state = STOPPED;
      enclaves[eid].n_thread = 0;
    }
  } else {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
    goto out;
  }

  if (!enclaves[eid].hart_bound) {
    sbi_printf("[SM][ocall] resume rejected: unbound group=%lu eid=%u\n",
               (unsigned long)group->group_id, eid);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out;
  }

  if (requested_hart != KEYSTONE_GROUP_OCALL_ANY_HART &&
      requested_hart != enclaves[eid].assigned_hart) {
    sbi_printf("[SM][ocall] resume rejected: hart mismatch group=%lu eid=%u requested=%lu assigned=%lu\n",
               (unsigned long)group->group_id, eid,
               (unsigned long)requested_hart,
               (unsigned long)enclaves[eid].assigned_hart);
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  if (!(group->configured_hart_mask &
        group_hart_bit((unsigned long)enclaves[eid].assigned_hart))) {
    sbi_printf("[SM][ocall] resume rejected: hart outside mask group=%lu eid=%u assigned=%lu mask=0x%lx\n",
               (unsigned long)group->group_id, eid,
               (unsigned long)enclaves[eid].assigned_hart,
               (unsigned long)group->configured_hart_mask);
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out;
  }

  /*
   * The host has completed the pending edge call. Make the blocked enclave's
   * saved SBI return value explicit here, not only at the earlier schedule-out
   * point. This is the ownership boundary for BLOCKED -> RUNNABLE and protects
   * the resumed runtime from seeing the host-visible EdgeCallHost status as the
   * return value of sbi_stop_enclave(STOP_EDGE_CALL_HOST).
   */
  if (!status.action)
    status.action = KEYSTONE_GROUP_OCALL_ACTION_RESUME;
  if (status.action == KEYSTONE_GROUP_OCALL_ACTION_CANCEL) {
    uint64_t ocall_id = group_ocalls[eid].ocall_id;
    if (group_scheduler_transition_locked(eid, GROUP_SCHED_EXITED,
                                          "ocall_cancel")) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
      goto out;
    }
    group_ocall_clear_locked(
        eid, csr_read(CSR_MCYCLE) - handler_started);
    yxstm_protocol_member_gone_locked(group, eid,
                                      YXSTM_ROLLBACK_WORKER_GONE);
    group_release_yxstm_owner_metadata_locked(eid);
    enclaves[eid].state = FAULTED;
    enclaves[eid].n_thread = 0;
    (void)group_scheduler_event_enqueue(
        enclaves[eid].assigned_hart, group->group_id, group->generation,
        eid, enclaves[eid].generation, KEYSTONE_GROUP_EVENT_CANCELLED,
        SBI_ERR_SM_GROUP_OCALL_CANCELLED, ocall_id);
    status.result = SBI_ERR_SM_GROUP_OCALL_CANCELLED;
  } else if (status.action == KEYSTONE_GROUP_OCALL_ACTION_ABANDON) {
    uint64_t ocall_id = group_ocalls[eid].ocall_id;
    if (group_scheduler_transition_locked(eid, GROUP_SCHED_FAULTED,
                                          "ocall_abandon")) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
      goto out;
    }
    group_ocall_clear_locked(
        eid, csr_read(CSR_MCYCLE) - handler_started);
    yxstm_protocol_member_gone_locked(group, eid, YXSTM_ROLLBACK_FAULT);
    group_release_yxstm_owner_metadata_locked(eid);
    enclaves[eid].state = FAULTED;
    enclaves[eid].n_thread = 0;
    (void)group_scheduler_event_enqueue(
        enclaves[eid].assigned_hart, group->group_id, group->generation,
        eid, enclaves[eid].generation,
        KEYSTONE_GROUP_EVENT_OCALL_ABANDONED,
        SBI_ERR_SM_GROUP_OCALL_ABANDONED, ocall_id);
    status.result = SBI_ERR_SM_GROUP_OCALL_ABANDONED;
  } else if (status.action == KEYSTONE_GROUP_OCALL_ACTION_RESUME) {
    if (group_scheduler_transition_ex_locked(eid, GROUP_SCHED_RUNNABLE,
                                             "ocall_resume",
                                             defer_host_kick)) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
      goto out;
    }
    enclaves[eid].threads[0].prev_state.a0 = status.result;
    group_ocall_resume_start_cycle[eid] =
        group_ocalls[eid].perf_start_cycle;
    group_ocall_resume_generation[eid] = enclaves[eid].generation;
    group_ocall_clear_locked(
        eid, csr_read(CSR_MCYCLE) - handler_started);
    group_member_timer_ready[eid] = 1;
  } else {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  status.group_id = group->group_id;
  status.hart_id = enclaves[eid].assigned_hart;
  status.pending = 0;
  status.pending_count = 0;
  status.ocall_id = 0;
  status.created_at = 0;
  status.deadline = 0;
  status.host_cookie = 0;
  status.flags = 0;
  sm_abi_fill(&status.abi, sizeof(status), KEYSTONE_GROUP_ABI_FEATURES);

out:
  spin_unlock(&encl_lock);

  if (!ret && copy_from_sm(inout_status, &status, sizeof(status)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return ret;
}

static void group_write_host_event(enclave_id eid, uintptr_t event,
                                   uintptr_t error, uintptr_t value,
                                   int clear_run_status)
{
  unsigned long hartid = csr_read(mhartid);
  uintptr_t run_status;
  struct keystone_group_run_hart status;
  uint64_t group_id;
  uint64_t group_generation = 0;
  uint64_t eid_generation = 0;
  struct enabled_group_slot* group;
  int write_ret;

  if (hartid >= MAX_HARTS || eid >= ENCL_MAX)
    return;

  spin_lock(&encl_lock);
  group_id = enclaves[eid].group_id;
  eid_generation = enclaves[eid].generation;
  group = find_group_locked(group_id);
  if (group) {
    group_generation = group->generation;
    /*
     * STOP_EDGE_CALL_HOST is a request code, not an OCALL identifier.
     * Publish the generation-bound SM record so every master/worker OCALL,
     * including the second and later calls, can be completed unambiguously.
     */
    if (event == KEYSTONE_GROUP_EVENT_OCALL &&
        group_ocalls[eid].valid &&
        group_ocalls[eid].group_generation == group->generation &&
        group_ocalls[eid].eid_generation == eid_generation)
      value = group_ocalls[eid].ocall_id;
  }
  run_status = group_hart_run_status_ptr[hartid];
  spin_unlock(&encl_lock);
  /*
   * A normal run/resume ioctl receives this event directly in its SBI return
   * value.  Only group_run_hart owns an event queue/status buffer; enqueuing
   * normal-run OCALLs would leave duplicate stale events behind.
   */
  if (!run_status)
    return;

  if (event &&
      group_scheduler_event_enqueue(hartid, group_id, group_generation,
                                    eid, eid_generation, event,
                                    error, value))
    return;

  /*
   * run_status was validated when group_run_hart stored it. Do not read it
   * again after restoring the host frame: MPRV address translation and the
   * resumed kernel stack can make that redundant read fail, leaving the event
   * queued while the current ioctl returns event=NONE. Build the result only
   * from SM-owned metadata and commit it directly.
  */
  sbi_memset(&status, 0, sizeof(status));
  if (!group_scheduler_event_dequeue(hartid, group_id,
                                     group_generation, &status))
    return;

  /*
   * COMPUTE_DONE queues WORKERS_READY but deliberately does not interrupt the
   * worker before the runtime records its completed batch.  The worker then
   * reaches STOP_LANE_WAIT or OCALL naturally; an event==NONE call enters this
   * path only to flush that queued phase edge through the existing HSM bridge.
   * Legacy forced-service state is cleared if an older producer left it set.
   */
  if (status.event == KEYSTONE_GROUP_EVENT_WORKERS_READY) {
    spin_lock(&encl_lock);
    if (hartid < MAX_HARTS &&
        group_hart_schedulers[hartid].active_group_id == group_id &&
        group_hart_schedulers[hartid].active_group_generation ==
            group_generation) {
      struct sm_hart_sched* sched = &group_hart_schedulers[hartid];

      if (sched->host_service_pending &&
          sched->host_service_drop_grant &&
          !sched->host_service_grant_suspended &&
          sched->host_service_eid < ENCL_MAX &&
          ENCLAVE_EXISTS(sched->host_service_eid) &&
          sched->host_service_eid_generation ==
              enclaves[sched->host_service_eid].generation) {
        /*
         * Bind the forced phase-edge return to the event actually delivered
         * through group_run_hart. The next worker entry must carry this exact
         * sequence after CPU0 has aggregated/dispatched the slot.
         */
        sched->host_service_event_sequence = status.event_sequence;
      } else if (!sched->host_service_pending) {
        sched->host_service_forced = 0;
        sched->host_service_drop_grant = 0;
        sched->host_service_deadline = 0;
      }
    }
    spin_unlock(&encl_lock);
  }

  write_ret = copy_from_sm(run_status, &status, sizeof(status));
  if (clear_run_status)
    group_hart_run_status_ptr[hartid] = 0;
  if (write_ret)
    return;
}

void group_queue_host_event(enclave_id eid, uintptr_t event,
                            uintptr_t error, uintptr_t value)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group;
  uint64_t group_id;
  uint64_t group_generation = 0;
  uint64_t eid_generation;

  if (hartid >= MAX_HARTS || eid >= ENCL_MAX || !event)
    return;
  spin_lock(&encl_lock);
  group_id = enclaves[eid].group_id;
  eid_generation = enclaves[eid].generation;
  group = find_group_locked(group_id);
  if (group)
    group_generation = group->generation;
  spin_unlock(&encl_lock);
  (void)group_scheduler_event_enqueue(
      hartid, group_id, group_generation, eid, eid_generation,
      event, error, value);
}

void group_record_host_event(enclave_id eid, uintptr_t event,
                             uintptr_t error, uintptr_t value)
{
  group_write_host_event(eid, event, error, value, 1);
}

unsigned long group_fault_return_value(enclave_id eid,
                                       unsigned long fault_code)
{
#if __riscv_xlen == 64
  unsigned long hartid = csr_read(mhartid);

  if (eid < ENCL_MAX &&
      enclaves[eid].group_id != 0 &&
      hartid < MAX_HARTS &&
      group_hart_run_status_ptr[hartid]) {
    return (((unsigned long)eid + 1UL) << 32) |
           (fault_code & 0xffffffffUL);
  }
#endif
  return fault_code;
}

unsigned long group_control_enclave(uintptr_t inout_control)
{
  struct keystone_group_control control;
  struct enabled_group_slot* group;
  struct sm_hart_sched* sched = 0;
  enclave_id eid;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  if (!inout_control ||
      copy_to_sm(&control, inout_control, sizeof(control)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&control.abi, sizeof(control),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;
  eid = (enclave_id)control.eid;
  sm_abi_fill(&control.abi, sizeof(control), KEYSTONE_GROUP_ABI_FEATURES);
  control.status = KEYSTONE_GROUP_CONTROL_APPLIED;
  control.scheduler_epoch = 0;

  spin_lock(&encl_lock);
  group = find_group_locked(control.group_id);
  if (!group || group->generation != control.group_generation ||
      eid >= ENCL_MAX || !ENCLAVE_EXISTS(eid) ||
      enclaves[eid].generation != control.eid_generation ||
      enclaves[eid].group_id != group->group_id) {
    ret = SBI_ERR_SM_ENCLAVE_STALE_GENERATION;
    goto out;
  }
  if (enclaves[eid].hart_bound && enclaves[eid].assigned_hart < MAX_HARTS)
    sched = &group_hart_schedulers[enclaves[eid].assigned_hart];

  if (control.action == KEYSTONE_GROUP_CONTROL_RESUME) {
    if (enclaves[eid].sched_state != GROUP_SCHED_PAUSED ||
        group_scheduler_transition_locked(eid, GROUP_SCHED_RUNNABLE,
                                          "host_resume")) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
      goto out;
    }
    group_member_timer_ready[eid] = 1;
  } else if (control.action == KEYSTONE_GROUP_CONTROL_PAUSE ||
             control.action == KEYSTONE_GROUP_CONTROL_CANCEL) {
    if (enclaves[eid].sched_state == GROUP_SCHED_RUNNING) {
      if (group_control_requests[eid]) {
        ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
        goto out;
      }
      group_control_requests[eid] = control.action;
      control.status = KEYSTONE_GROUP_CONTROL_PENDING;
    } else {
      enum group_sched_state target =
          control.action == KEYSTONE_GROUP_CONTROL_PAUSE ?
          GROUP_SCHED_PAUSED : GROUP_SCHED_EXITED;
      if (control.action == KEYSTONE_GROUP_CONTROL_PAUSE &&
          enclaves[eid].sched_state == GROUP_SCHED_BLOCKED) {
        ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
        goto out;
      }
      if (group_scheduler_transition_locked(eid, target,
                                            "host_control")) {
        ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
        goto out;
      }
      if (control.action == KEYSTONE_GROUP_CONTROL_CANCEL) {
        uint64_t ocall_id = group_ocalls[eid].ocall_id;
        group_ocall_clear_locked(eid, 0);
        yxstm_protocol_member_gone_locked(group, eid,
                                          YXSTM_ROLLBACK_WORKER_GONE);
        group_release_yxstm_owner_metadata_locked(eid);
        enclaves[eid].state = FAULTED;
        enclaves[eid].n_thread = 0;
        if (enclaves[eid].hart_bound)
          (void)group_scheduler_event_enqueue(
              enclaves[eid].assigned_hart, group->group_id,
              group->generation, eid, enclaves[eid].generation,
              KEYSTONE_GROUP_EVENT_CANCELLED,
              SBI_ERR_SM_GROUP_OCALL_CANCELLED, ocall_id);
      } else {
        if (enclaves[eid].state != FRESH)
          enclaves[eid].state = STOPPED;
        enclaves[eid].n_thread = 0;
        if (enclaves[eid].hart_bound)
          (void)group_scheduler_event_enqueue(
              enclaves[eid].assigned_hart, group->group_id,
              group->generation, eid, enclaves[eid].generation,
              KEYSTONE_GROUP_EVENT_PAUSED,
              SBI_ERR_SM_GROUP_PAUSED, 0);
      }
    }
  } else {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }

  if (sched)
    control.scheduler_epoch = sched->sched_epoch;
out:
  spin_unlock(&encl_lock);
  if (!ret && copy_from_sm(inout_control, &control, sizeof(control)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return ret;
}

unsigned long group_pause_master(uintptr_t inout_control)
{
  struct keystone_group_control control;
  struct enabled_group_slot* group;
  struct group_member_descriptor* master = 0;
  struct sm_hart_sched* sched = 0;
  enclave_id eid = ENCL_MAX;
  unsigned long ret;
  int i;

  if (!inout_control ||
      copy_to_sm(&control, inout_control, sizeof(control)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&control.abi, sizeof(control),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;

  spin_lock(&encl_lock);
  group = find_group_locked(control.group_id);
  if (!group || group->generation != control.group_generation) {
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto pause_out;
  }
  if (group->lifecycle_state != KEYSTONE_GROUP_STATE_ACTIVE ||
      group->execution_mode != GROUP_MODE_3W_1HM) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto pause_out;
  }
  for (i = 0; i < (int)group->member_metadata_capacity; i++)
    if (group->members[i].valid &&
        group->members[i].role == GROUP_ROLE_MASTER) {
      master = &group->members[i];
      break;
    }
  if (!master || master->bound_hart != group->master_hart) {
    ret = SBI_ERR_SM_ENCLAVE_INVALID_ID;
    goto pause_out;
  }
  eid = master->eid;
  if (!ENCLAVE_EXISTS(eid) ||
      enclaves[eid].generation != master->eid_generation) {
    ret = SBI_ERR_SM_ENCLAVE_STALE_GENERATION;
    goto pause_out;
  }

  control.eid = eid;
  control.eid_generation = enclaves[eid].generation;
  control.action = KEYSTONE_GROUP_CONTROL_PAUSE;
  control.status = KEYSTONE_GROUP_CONTROL_APPLIED;
  if (enclaves[eid].hart_bound &&
      enclaves[eid].assigned_hart < MAX_HARTS)
    sched = &group_hart_schedulers[enclaves[eid].assigned_hart];
  if (enclaves[eid].sched_state == GROUP_SCHED_RUNNING) {
    if (group_control_requests[eid]) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
      goto pause_out;
    }
    group_control_requests[eid] = KEYSTONE_GROUP_CONTROL_PAUSE;
    control.status = KEYSTONE_GROUP_CONTROL_PENDING;
  } else {
    if (enclaves[eid].sched_state == GROUP_SCHED_BLOCKED ||
        group_scheduler_transition_locked(eid, GROUP_SCHED_PAUSED,
                                          "pause_master")) {
      ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
      goto pause_out;
    }
    group_release_yxstm_owner_metadata_locked(eid);
    if (enclaves[eid].state != FRESH)
      enclaves[eid].state = STOPPED;
    enclaves[eid].n_thread = 0;
    (void)group_scheduler_event_enqueue(
        group->master_hart, group->group_id, group->generation,
        eid, enclaves[eid].generation, KEYSTONE_GROUP_EVENT_PAUSED,
        SBI_ERR_SM_GROUP_PAUSED, 0);
  }
  control.scheduler_epoch = sched ? sched->sched_epoch : 0;
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
pause_out:
  sm_abi_fill(&control.abi, sizeof(control), KEYSTONE_GROUP_ABI_FEATURES);
  spin_unlock(&encl_lock);
  if (copy_from_sm(inout_control, &control, sizeof(control)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return ret;
}

static unsigned long group_run_hart_common(struct sbi_trap_regs* regs,
                                           uintptr_t run_status,
                                           int master_only)
{
  struct keystone_group_run_hart status;
  struct enabled_group_slot* group;
  enclave_id entry = ENCL_MAX;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
  uint64_t group_id;
  uint64_t hartid;
  uint64_t current_hartid;
  uint64_t committed_event_sequence;
  int load_parameters = 0;

  if (!regs || !run_status)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (copy_to_sm(&status, run_status, sizeof(status)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&status.abi, sizeof(status),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;

  group_id = status.group_id ? status.group_id : 1;
  hartid = status.hart_id;
  committed_event_sequence = status.event_sequence;
  current_hartid = csr_read(mhartid);
  sm_abi_fill(&status.abi, sizeof(status), KEYSTONE_GROUP_ABI_FEATURES);
  status.group_id = group_id;
  status.eid = 0;
  status.event = KEYSTONE_GROUP_EVENT_NONE;
  status.error = SBI_ERR_SM_ENCLAVE_SUCCESS;
  status.value = 0;
  status.event_sequence = 0;
  status.scheduler_epoch = 0;
  status.queue_overflows = 0;

  spin_lock(&encl_lock);
  group = find_group_locked(group_id);
  if (current_hartid != hartid ||
      !group || !group_context_validate_locked(group, "group_run_hart") ||
      group->lifecycle_state != KEYSTONE_GROUP_STATE_ACTIVE ||
      status.group_generation != group->generation ||
      !group_hart_allowed_locked(group, hartid) ||
      (master_only && group->execution_mode != GROUP_MODE_3W_1HM) ||
      (master_only && hartid != group->master_hart) ||
      (!master_only &&
       group->execution_mode == GROUP_MODE_3W_1HM &&
       (!(group->worker_hart_mask & group_hart_bit(hartid)) ||
        group->lease_state != KEYSTONE_GROUP_LEASE_LEASED))) {
    if (current_hartid != hartid) {
      sbi_printf("[SM][sched] group_run_hart rejected: requested_hart=%lu current_hart=%lu group=%lu\n",
                 (unsigned long)hartid,
                 (unsigned long)current_hartid,
                 (unsigned long)group_id);
    } else if (group && !master_only &&
               group->execution_mode == GROUP_MODE_3W_1HM &&
               group->lease_state != KEYSTONE_GROUP_LEASE_LEASED) {
      sbi_printf("[SM][lease] group_run_hart rejected: group=%lu hart=%lu lease_state=%lu expected=%u\n",
                 (unsigned long)group_id,
                 (unsigned long)hartid,
                 (unsigned long)group->lease_state,
                 KEYSTONE_GROUP_LEASE_LEASED);
    }
    if (group && status.group_generation != group->generation) {
      ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    } else if (group &&
               (group->lifecycle_state != KEYSTONE_GROUP_STATE_ACTIVE ||
                (master_only &&
                 group->execution_mode != GROUP_MODE_3W_1HM) ||
                (!master_only &&
                 group->execution_mode == GROUP_MODE_3W_1HM &&
                 group->lease_state != KEYSTONE_GROUP_LEASE_LEASED))) {
      ret = SBI_ERR_SM_GROUP_BAD_STATE;
    } else {
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    }
    goto out_locked;
  }

  group_ocall_expire_locked();
  if (!master_only && committed_event_sequence)
    (void)group_scheduler_commit_host_service_locked(
        &group_hart_schedulers[hartid], committed_event_sequence);
  if (!group_scheduler_validate_locked(&group_hart_schedulers[hartid],
                                       "group_run_hart")) {
    ret = SBI_ERR_SM_GROUP_WATCHDOG;
    goto out_locked;
  }
  if (group->coherence_inflight) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out_locked;
  }

  if (group_scheduler_event_dequeue(hartid, group->group_id,
                                    group->generation, &status)) {
    spin_unlock(&encl_lock);
    if (copy_from_sm(run_status, &status, sizeof(status)))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    return status.error;
  }

  entry = group_scheduler_pick_host_entry_locked(hartid, group_id);
  if (entry == ENCL_MAX) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out_locked;
  }

  status.eid = entry;
  status.hart_id = hartid;
  group_hart_run_status_ptr[hartid] = run_status;

  if (enclaves[entry].state == FRESH) {
    enclaves[entry].state = RUNNING;
    enclaves[entry].n_thread++;
    load_parameters = 1;
  } else if (enclaves[entry].state == STOPPED || enclaves[entry].state == RUNNING) {
    enclaves[entry].state = RUNNING;
    enclaves[entry].n_thread++;
  } else {
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    goto out_locked;
  }
  ret = group_active_hart_enter_locked(entry, hartid);
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    if (enclaves[entry].state == RUNNING) {
      if (enclaves[entry].n_thread > 0)
        enclaves[entry].n_thread--;
      if (enclaves[entry].n_thread == 0) {
        enclaves[entry].state = load_parameters ? FRESH : STOPPED;
        (void)group_scheduler_transition_locked(
            entry, GROUP_SCHED_RUNNABLE, "group_run_enter_rollback");
      }
    }
    if (group_hart_run_status_ptr[hartid] == run_status)
      group_hart_run_status_ptr[hartid] = 0;
    goto out_locked;
  }

out_locked:
  if (ret) {
    status.error = ret;
    status.event = KEYSTONE_GROUP_EVENT_NONE;
  }
  spin_unlock(&encl_lock);

  if (copy_from_sm(run_status, &status, sizeof(status)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (ret)
    return ret;

  ret = context_switch_to_enclave(regs, entry, load_parameters);
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    group_context_switch_fail_rollback(entry, load_parameters);
    if (hartid < MAX_HARTS && group_hart_run_status_ptr[hartid] == run_status)
      group_hart_run_status_ptr[hartid] = 0;
    if (hartid < MAX_HARTS) {
      sbi_memset(&group_hart_host_threads[hartid], 0,
                 sizeof(group_hart_host_threads[hartid]));
      group_hart_host_context_valid[hartid] = 0;
    }
  }
  return ret;
}

unsigned long group_run_hart(struct sbi_trap_regs* regs, uintptr_t run_status)
{
  return group_run_hart_common(regs, run_status, 0);
}

unsigned long group_run_master(struct sbi_trap_regs* regs,
                               uintptr_t run_status)
{
  return group_run_hart_common(regs, run_status, 1);
}

unsigned long group_service_host_interrupt(struct sbi_trap_regs* regs,
                                           enclave_id eid,
                                           unsigned long interrupt_cause)
{
  unsigned long hartid = csr_read(mhartid);
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  struct group_hart_slot* slot;
  struct sm_hart_sched* sched;
  int serviceable = 0;
  uint64_t service_start = csr_read(CSR_MCYCLE);
  uint64_t heartbeat_sequence = 0;
  int forced_service = 0;
  int drop_grant = 0;

  if (!regs || eid >= ENCL_MAX || hartid >= MAX_HARTS)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  group = ENCLAVE_EXISTS(eid) ?
      find_group_locked(enclaves[eid].group_id) : 0;
  member = group ? group_member_find_locked(group, eid) : 0;
  slot = group ? &group->hart_slots[hartid] : 0;
  sched = &group_hart_schedulers[hartid];
  forced_service = sched->host_service_forced;
  drop_grant = sched->host_service_drop_grant;
  if (group && member && slot && slot->valid &&
      (!slot->yxstm_acquired || slot->yxstm_owner_eid == eid) &&
      !member->yxstm_suspended_acquired &&
      !sched->host_service_pending &&
      thread_extended_context_supported() &&
      (group_member_timer_ready[eid] || forced_service) &&
      group_hart_run_status_ptr[hartid] &&
      enclaves[eid].state == RUNNING && enclaves[eid].n_thread > 0 &&
      enclaves[eid].sched_state == GROUP_SCHED_RUNNING &&
      enclaves[eid].hart_bound && enclaves[eid].assigned_hart == hartid &&
      group_scheduler_active_matches_locked(sched, eid) &&
      !group_scheduler_transition_locked(eid, GROUP_SCHED_RUNNABLE,
                                         "host_interrupt")) {
    if (slot->yxstm_acquired) {
      uint64_t grant_suspend_start;

      grant_suspend_start = csr_read(CSR_MCYCLE);
      if (!drop_grant) {
        member->yxstm_suspended_acquired = 1;
        member->yxstm_suspended_slice_mask =
            slot->yxstm_acquired_slice_mask;
        member->yxstm_suspended_permissions = slot->yxstm_permissions;
        member->yxstm_suspended_phase = slot->yxstm_phase;
        member->yxstm_suspended_bank_id = slot->yxstm_bank_id;
        member->yxstm_suspended_phase_epoch = slot->phase_epoch;
        member->yxstm_suspended_permission_epoch = slot->pmp_epoch;
        member->yxstm_suspended_task_epoch =
            slot->yxstm_bank_id != KEYSTONE_YXSTM_INVALID_BANK &&
                    slot->yxstm_bank_id < group->yxstm_bank_count ?
                group->task_banks[slot->yxstm_bank_id].task_epoch :
                group->yxstm_task_epoch;
      } else {
        member->yxstm_suspended_acquired = 0;
        member->yxstm_suspended_slice_mask = 0;
        member->yxstm_suspended_permissions = 0;
        member->yxstm_suspended_phase = YXSTM_PHASE_IDLE;
        member->yxstm_suspended_bank_id = KEYSTONE_YXSTM_INVALID_BANK;
        member->yxstm_suspended_phase_epoch = 0;
        member->yxstm_suspended_permission_epoch = 0;
        member->yxstm_suspended_task_epoch = 0;
        member->yxstm_suspended_save_cycles = 0;
      }
      asm volatile("fence rw,rw" ::: "memory");
      if (group->yxstm_region >= 0)
        pmp_set_keystone(group->yxstm_region, PMP_NO_PERM);
      asm volatile("sfence.vma" ::: "memory");
      sched->host_service_grant_suspended = !drop_grant;
      sched->host_service_grant_cycles =
          csr_read(CSR_MCYCLE) - grant_suspend_start;
      if (!drop_grant)
        member->yxstm_suspended_save_cycles =
            sched->host_service_grant_cycles;
    }
    enclaves[eid].n_thread--;
    if (enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
    group_member_timer_ready[eid] = 1;
    sched->host_service_pending = 1;
    sched->host_service_eid = eid;
    sched->host_service_eid_generation = enclaves[eid].generation;
    sched->host_service_group_generation = group->generation;
    sched->host_service_event_sequence = 0;
    sched->host_service_start_cycle = service_start;
    sched->host_service_forced = 0;
    /*
     * Keep the event-only marker until CPU0 commits the sequence returned by
     * group_run_hart. Before that ACK, only exact phase-edge reentry is safe.
     * After the ACK, there is no suspended grant and the saved worker context
     * returns to ordinary CFS competition with READY peers.
     */
    sched->host_service_drop_grant = drop_grant;
    if (sched->heartbeat_enabled) {
      uintptr_t pending = csr_read(mip);

      sched->heartbeat_request_sequence++;
      if (!sched->heartbeat_request_sequence)
        sched->heartbeat_request_sequence++;
      heartbeat_sequence = sched->heartbeat_request_sequence;
      sched->heartbeat_pending_sources =
          KEYSTONE_GROUP_HEARTBEAT_SOURCE_TIMER;
      if (pending & (MIP_MSIP | MIP_SSIP))
        sched->heartbeat_pending_sources |=
            KEYSTONE_GROUP_HEARTBEAT_SOURCE_SOFTWARE;
      if (pending & MIP_SEIP)
        sched->heartbeat_pending_sources |=
            KEYSTONE_GROUP_HEARTBEAT_SOURCE_EXTERNAL;
      sched->heartbeat_cleared_sources = 0;
      sched->heartbeat_handoff_sources = 0;
      sched->heartbeat_state = KEYSTONE_GROUP_HEARTBEAT_STATE_REQUESTED;
      sched->heartbeat_deadline =
          sbi_timer_value() + KEYSTONE_GROUP_HEARTBEAT_TIMEOUT_CYCLES;
    }
    /* group_run_hart's SBI wrapper adds four on every schedule-in. */
    group_member_saved_mepc_advanced[eid] = 1;
    serviceable = 1;
  }
  if (!serviceable) {
    sbi_printf("[SM][sched] host interrupt denied: hart=%lu eid=%u cause=%lu group=%d member=%d slot=%d slot_valid=%d acquired=%lu owner=%u suspended=%lu pending=%d run_frame=%d enclave_state=%u threads=%u sched_state=%u bound=%lu assigned=%lu active_match=%d\n",
               hartid, eid, interrupt_cause, group != 0, member != 0,
               slot != 0, slot ? slot->valid : 0,
               slot ? (unsigned long)slot->yxstm_acquired : 0,
               slot ? slot->yxstm_owner_eid : ENCL_MAX,
               member ? (unsigned long)member->yxstm_suspended_acquired : 0,
               sched->host_service_pending,
               group_hart_run_status_ptr[hartid] != 0,
               (unsigned int)enclaves[eid].state,
               (unsigned int)enclaves[eid].n_thread,
               (unsigned int)enclaves[eid].sched_state,
               (unsigned long)enclaves[eid].hart_bound,
               (unsigned long)enclaves[eid].assigned_hart,
               group_scheduler_active_matches_locked(sched, eid));
  }
  spin_unlock(&encl_lock);

  if (!serviceable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  /*
   * Save the enclave at the exact interrupted PC, revoke its dynamic
   * PMP/YXSTM permissions, and restore the group_run_hart host frame.
   * context_switch_to_host() processes the expired MTIP and exposes STIP to
   * Linux. The comparator may remain level-pending until Linux replaces it,
   * so completion is recorded below instead of inferred from a later mip read.
   */
  context_switch_to_host(regs, eid, 0, 1);
  /*
   * Record completion at the exact M-mode -> host handoff boundary.  Raw mip
   * cannot be used later by the ACK path: MTIP can remain level-pending until
   * Linux programs its comparator, and any bit observed by the later ecall
   * may already belong to a new host interrupt.  context_switch_to_host() has
   * processed the machine timer/IPI and delegated supervisor-visible work, so
   * this sequence-scoped bitmap is the authoritative handoff evidence.
   */
  spin_lock(&encl_lock);
  sched = hartid < MAX_HARTS ? &group_hart_schedulers[hartid] : 0;
  if (sched && sched->host_service_pending &&
      sched->host_service_eid == eid &&
      sched->host_service_eid_generation == enclaves[eid].generation &&
      sched->heartbeat_state == KEYSTONE_GROUP_HEARTBEAT_STATE_REQUESTED &&
      sched->heartbeat_request_sequence == heartbeat_sequence) {
    sched->heartbeat_handoff_sources = sched->heartbeat_pending_sources;
    asm volatile("fence rw,rw" ::: "memory");
  }
  spin_unlock(&encl_lock);
  group_record_host_event(eid, KEYSTONE_GROUP_EVENT_HOST_INTERRUPT,
                          SBI_ERR_SM_ENCLAVE_SUCCESS,
                          heartbeat_sequence ? heartbeat_sequence :
                                               interrupt_cause);
  /*
   * The explicit return code is a second, register-only event channel. The
   * driver normalizes it to HOST_INTERRUPT even if the asynchronous status
   * buffer writeback could not be completed.
   */
  /*
   * This path exits directly through the saved host trap frame, bypassing the
   * normal OpenSBI ecall return mapper. Keep a0 a standard SBI error. The
   * status object is the primary event channel; tagged a1 is a sequence-only
   * fallback for the case where its kernel-stack writeback is no longer
   * addressable after restoring the host context.
   */
  regs->a0 = SBI_EALREADY;
  regs->a1 = KEYSTONE_GROUP_DIRECT_SEQUENCE_ENCODE(heartbeat_sequence);
  regs->mepc += 4;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long group_host_heartbeat_ack(uintptr_t inout_heartbeat)
{
  struct keystone_group_heartbeat heartbeat;
  struct enabled_group_slot* group;
  struct sm_hart_sched* sched;
  unsigned long hartid = csr_read(mhartid);
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
  uint64_t perf_started = 0;
  int perf_accepted = 0;

  if (!inout_heartbeat ||
      copy_to_sm(&heartbeat, inout_heartbeat, sizeof(heartbeat)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = sm_abi_validate(&heartbeat.abi, sizeof(heartbeat),
                        KEYSTONE_GROUP_ABI_FEATURES);
  if (ret)
    return ret;

  spin_lock(&encl_lock);
  group = find_group_locked(heartbeat.group_id);
  sched = hartid < MAX_HARTS ? &group_hart_schedulers[hartid] : 0;
  if (!group || group->generation != heartbeat.group_generation ||
      heartbeat.hart_id != hartid || !sched || !sched->valid ||
      sched->active_group_id != group->group_id ||
      sched->active_group_generation != group->generation) {
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto out;
  }

  /* HOST_INTERRUPT is carried by both the status buffer and a tagged register
   * fallback. A delayed duplicate of an already verified sequence is an
   * idempotent ACK, not a protocol fault. request_sequence still prevents an
   * old ACK from satisfying a newer heartbeat. */
  if (sched->heartbeat_enabled && heartbeat.request_sequence &&
      heartbeat.request_sequence == sched->heartbeat_request_sequence &&
      heartbeat.request_sequence == sched->heartbeat_ack_sequence &&
      (sched->heartbeat_state == KEYSTONE_GROUP_HEARTBEAT_STATE_VERIFIED ||
       (sched->heartbeat_state == KEYSTONE_GROUP_HEARTBEAT_STATE_IDLE &&
        !sched->host_service_pending))) {
    heartbeat.ack_sequence = sched->heartbeat_ack_sequence;
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    goto out;
  }
  if (!sched->heartbeat_enabled || !sched->host_service_pending ||
      sched->heartbeat_state != KEYSTONE_GROUP_HEARTBEAT_STATE_REQUESTED ||
      heartbeat.request_sequence != sched->heartbeat_request_sequence) {
    ret = SBI_ERR_SM_GROUP_HEARTBEAT_SEQUENCE;
    goto out;
  }
  if ((int64_t)(sbi_timer_value() - sched->heartbeat_deadline) >= 0) {
    ret = SBI_ERR_SM_GROUP_COHERENCE_TIMEOUT;
    goto out;
  }

  sched->heartbeat_ack_sequence = heartbeat.request_sequence;
  sched->heartbeat_cleared_sources = heartbeat.cleared_sources;
  sched->heartbeat_state = KEYSTONE_GROUP_HEARTBEAT_STATE_ACKED;
  asm volatile("fence rw,rw" ::: "memory");

  if ((heartbeat.cleared_sources & sched->heartbeat_pending_sources) !=
          sched->heartbeat_pending_sources ||
      (sched->heartbeat_handoff_sources & sched->heartbeat_pending_sources) !=
          sched->heartbeat_pending_sources) {
    /* The ACK was observed before the sequence-scoped M-mode handoff. */
    sched->heartbeat_state = KEYSTONE_GROUP_HEARTBEAT_STATE_REQUESTED;
    ret = SBI_ERR_SM_GROUP_HEARTBEAT_SOURCE_PENDING;
    goto out;
  }

  sched->heartbeat_state = KEYSTONE_GROUP_HEARTBEAT_STATE_VERIFIED;
  heartbeat.ack_sequence = sched->heartbeat_ack_sequence;
  perf_started = sched->host_service_start_cycle;
  perf_accepted = 1;

out:
  heartbeat.group_generation = group ? group->generation : 0;
  heartbeat.hart_id = hartid;
  heartbeat.request_sequence = sched ?
      sched->heartbeat_request_sequence : heartbeat.request_sequence;
  heartbeat.ack_sequence = sched ? sched->heartbeat_ack_sequence : 0;
  heartbeat.pending_sources = sched ? sched->heartbeat_pending_sources : 0;
  heartbeat.cleared_sources = sched ?
      sched->heartbeat_cleared_sources : 0;
  heartbeat.state = sched ? sched->heartbeat_state :
      KEYSTONE_GROUP_HEARTBEAT_STATE_IDLE;
  heartbeat.deadline = sched ? sched->heartbeat_deadline : 0;
  sm_abi_fill(&heartbeat.abi, sizeof(heartbeat),
              KEYSTONE_GROUP_ABI_FEATURES);
  sm_abi_set_result(&heartbeat.abi,
                    ret == SBI_ERR_SM_ENCLAVE_SUCCESS ? 0 : 1, ret);
  spin_unlock(&encl_lock);
  if (perf_accepted) {
    atomic_add_return(&group_perf_heartbeat_count, 1);
    if (perf_started)
      atomic_add_return(&group_perf_heartbeat_cycles,
                        (long)(csr_read(CSR_MCYCLE) - perf_started));
  }
  if (copy_from_sm(inout_heartbeat, &heartbeat, sizeof(heartbeat)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  return ret;
}

unsigned long group_bind_enclave_to_hart(enclave_id eid, uint64_t hart_id,
                                         uint64_t group_generation,
                                         uint64_t eid_generation,
                                         uint64_t priority,
                                         uint64_t quantum_ticks)
{
  struct enabled_group_slot* group;
  struct group_member_descriptor* member;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  spin_lock(&encl_lock);
  if (!ENCLAVE_EXISTS(eid) || enclaves[eid].group_id == 0 ||
      enclaves[eid].generation != eid_generation) {
    ret = SBI_ERR_SM_ENCLAVE_STALE_GENERATION;
    goto out;
  }

  group = find_group_locked(enclaves[eid].group_id);
  if (!group || !group_context_validate_locked(group, "bind_enclave")) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  if (group->generation != group_generation) {
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto out;
  }
  if (group->lifecycle_state != KEYSTONE_GROUP_STATE_ACTIVE) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }

  if (!thread_extended_context_supported()) {
    ret = SBI_ERR_SM_GROUP_VECTOR_UNSUPPORTED;
    goto out;
  }
  if (priority > KEYSTONE_GROUP_SCHED_PRIORITY_MAX ||
      quantum_ticks > KEYSTONE_GROUP_SCHED_QUANTUM_MAX) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  member = group_member_find_locked(group, eid);
  if (!member) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  if (hart_id < MAX_HARTS &&
      group_scheduler_active_matches_locked(
          &group_hart_schedulers[hart_id], eid))
    group_scheduler_cfs_account_current_locked(
        group, &group_hart_schedulers[hart_id], eid, sbi_timer_value());
  member->sched_base_priority = priority;
  member->sched_weight = group_scheduler_cfs_weight(priority);
  member->sched_quantum_ticks = quantum_ticks ? quantum_ticks :
      KEYSTONE_GROUP_SCHED_QUANTUM_DEFAULT;
  member->sched_exec_start_time = 0;

  if (hart_id < MAX_HARTS &&
      group_scheduler_active_matches_locked(
          &group_hart_schedulers[hart_id], eid))
    group_scheduler_cfs_prepare_active_locked(
        group, &group_hart_schedulers[hart_id], member,
        sbi_timer_value());

  if (group_scheduler_bind_locked(group, eid, (unsigned long)hart_id))
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;

out:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long group_enqueue_enclave(enclave_id eid,
                                    uint64_t group_generation,
                                    uint64_t eid_generation)
{
  struct enabled_group_slot* group;
  unsigned long hartid = 0;
  unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  spin_lock(&encl_lock);
  if (!ENCLAVE_EXISTS(eid) || enclaves[eid].group_id == 0 ||
      enclaves[eid].generation != eid_generation) {
    ret = SBI_ERR_SM_ENCLAVE_STALE_GENERATION;
    goto out;
  }

  group = find_group_locked(enclaves[eid].group_id);
  if (!group || !group_context_validate_locked(group, "enqueue_enclave")) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto out;
  }
  if (group->generation != group_generation) {
    ret = SBI_ERR_SM_GROUP_STALE_GENERATION;
    goto out;
  }
  if (group->lifecycle_state != KEYSTONE_GROUP_STATE_ACTIVE) {
    ret = SBI_ERR_SM_GROUP_BAD_STATE;
    goto out;
  }

  if (enclaves[eid].hart_bound) {
    hartid = enclaves[eid].assigned_hart;
  } else if (group_scheduler_choose_hart_locked(group, &hartid)) {
    ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
    goto out;
  }

  if (group_scheduler_bind_locked(group, eid, hartid))
    ret = SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;

out:
  spin_unlock(&encl_lock);
  return ret;
}

int enclave_is_group_enclave(enclave_id eid)
{
  int is_group = 0;

  spin_lock(&encl_lock);
  if (ENCLAVE_EXISTS(eid) && enclaves[eid].group_id != 0)
    is_group = 1;
  spin_unlock(&encl_lock);

  return is_group;
}

static int group_yxstm_release(region_id rid)
{
  int i;
  int should_free = 0;

  spin_lock(&encl_lock);
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    struct enabled_group_slot* group = &enabled_groups[i];
    if (!group->valid || group->yxstm_region != rid)
      continue;

    if (group->yxstm_refcount > 0)
      group->yxstm_refcount--;

    if (group->yxstm_refcount == 0) {
      group_secure_zero_range(group->yxstm_base, group->yxstm_size);
      group_security_rekey_locked(group, YXSTM_ROLLBACK_WORKER_GONE);
      group_region_remove_locked(group,
                                 GROUP_REGION_SHARED,
                                 group->yxstm_base,
                                 group->yxstm_size);
      group->yxstm_region = -1;
      group->yxstm_base = 0;
      group->yxstm_size = 0;
      group->kg_ready = 0;
      should_free = 1;
    }
    maybe_clear_group_locked(group);
    spin_unlock(&encl_lock);

    if (should_free) {
      pmp_unset_global(rid);
      pmp_region_free_atomic(rid);
    }
    return 1;
  }
  spin_unlock(&encl_lock);
  return 0;
}

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/
static inline unsigned long context_switch_to_enclave(
    struct sbi_trap_regs* regs,
    enclave_id eid,
    int load_parameters)
{
  unsigned long hartid = csr_read(mhartid);
  unsigned long ret;
  int group_run_hart_entry = 0;

  group_run_hart_entry = enclaves[eid].group_id != 0 &&
      hartid < MAX_HARTS && group_hart_run_status_ptr[hartid];

  if (group_run_hart_entry) {
    /*
     * group_run_hart owns an independent host frame. Save it directly, then
     * restore the selected member. Do not route either frame through the
     * other one's thread_state: timer switching and host-service re-entry can
     * otherwise leave a third context as the next exchange operand.
     */
    if (group_hart_host_context_valid[hartid]) {
      sbi_printf("[SM][sched] duplicate host frame: hart=%lu eid=%u\n",
                 hartid, eid);
      return SBI_ERR_SM_GROUP_BAD_STATE;
    }
    thread_state_save_exact(&group_hart_host_threads[hartid], regs);
    group_hart_host_context_valid[hartid] = 1;
    group_scheduler_restore_thread_context_exact(
        &enclaves[eid].threads[0], regs);
  } else {
    /* Historical host <-> enclave exchange for the non-group run ABI. */
    swap_prev_state(&enclaves[eid].threads[0], regs, 1);
    swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
    swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);
  }

  uintptr_t interrupts = 0;
  csr_write(mideleg, interrupts);
  if (enclaves[eid].group_id != 0) {
    /*
     * Linux supervisor interrupts stay masked while a group enclave runs.
     * Scheduler-owned MTIP periodically restores the saved group_run_hart
     * frame, after which pending Linux timer/device work is delivered in the
     * normal host context. This avoids the pending-STIP immediate re-entry
     * loop seen with direct S-interrupt service.
    */
    csr_clear(mie, MIP_SSIP | MIP_STIP | MIP_SEIP);
#if KEYSTONE_GROUP_TIMER_PREEMPT
    /*
     * schedule-in programs a future comparator after PMP and saved context
     * are ready. Do not enable an expired machine timer in this earlier
     * context-restore stage.
     */
    csr_clear(mie, MIP_MTIP);
#else
    csr_clear(mie, MIP_MTIP);
#endif
    /* MSIP carries PMP/TLB coherence independently of timer scheduling. */
    csr_set(mie, MIP_MSIP);
  }

  if(load_parameters) {
    uintptr_t yxstm_param_base = enclaves[eid].params.YXSTrusted_base;
    size_t yxstm_param_size = enclaves[eid].params.YXSTrusted_size;

    group_member_saved_mepc_advanced[eid] = 0;

    // passing parameters for a first run
    regs->mepc = (uintptr_t) enclaves[eid].params.dram_base - 4; // regs->mepc will be +4 before sbi_ecall_handler return
    regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
    regs->a0 = SBI_ERR_SM_ENCLAVE_SUCCESS;
    // $a1: (PA) DRAM base,
    regs->a1 = (uintptr_t) enclaves[eid].params.dram_base;
    // $a2: DRAM size,
    regs->a2 = (uintptr_t) enclaves[eid].params.dram_size;
    // $a3: (PA) kernel location,
    regs->a3 = (uintptr_t) enclaves[eid].params.runtime_base;
    // $a4: (PA) user location,
    regs->a4 = (uintptr_t) enclaves[eid].params.user_base;
    // $a5: (PA) freemem location,
    regs->a5 = (uintptr_t) enclaves[eid].params.free_base;
    // $a6: (PA) utm base,
    regs->a6 = (uintptr_t) enclaves[eid].params.untrusted_base;
    // $a7: utm size
    regs->a7 = (uintptr_t) enclaves[eid].params.untrusted_size;
    // $t0: (PA) YXSTM base,
    regs->t0 = (uintptr_t) yxstm_param_base;
    // $t1: YXSTM size
    regs->t1 = (uintptr_t) yxstm_param_size;
    // $t2: (PA) shared UTM base (for Slave Enclave to access Main's UTM)
    regs->t2 = (uintptr_t) enclaves[eid].params.shared_utm_base;
    // $t3: shared UTM size
    regs->t3 = (uintptr_t) enclaves[eid].params.shared_utm_size;
    // $t4: SEC MMIO base
    regs->t4 = (uintptr_t) enclaves[eid].params.sec_base;
    // $t5: SEC MMIO size
    regs->t5 = (uintptr_t) enclaves[eid].params.sec_size;

    // enclave will only have physical addresses in the first run
    csr_write(satp, 0);
    asm volatile("sfence.vma" ::: "memory");
  } else if (enclaves[eid].group_id != 0) {
    group_scheduler_adjust_resume_pc(regs, eid, 1);
  }

  switch_vector_enclave();

  ret = group_scheduler_schedule_in_local(eid, 0);
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    sbi_printf("[SM][sched] schedule-in failed: eid=%u group=%lu\n",
               eid,
               (unsigned long)enclaves[eid].group_id);
    switch_vector_host();
    if (group_run_hart_entry && group_hart_host_context_valid[hartid]) {
      group_scheduler_restore_thread_context_exact(
          &group_hart_host_threads[hartid], regs);
      sbi_memset(&group_hart_host_threads[hartid], 0,
                 sizeof(group_hart_host_threads[hartid]));
      group_hart_host_context_valid[hartid] = 0;
    } else {
      swap_prev_state(&enclaves[eid].threads[0], regs, 1);
      swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
      swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);
    }
    group_restore_host_ipi();
    return ret;
  }

  // Setup any platform specific defenses
  platform_switch_to_enclave(&(enclaves[eid]));
#if KEYSTONE_GROUP_STARTUP_TRACE
  if (enclaves[eid].group_id != 0 && !group_hart_enter_log_seen[eid]) {
    uint64_t active_hart_bitmap = 0;
    uint64_t active_epoch = 0;

    group_hart_enter_log_seen[eid] = 1;
    group_active_hart_snapshot(enclaves[eid].group_id,
                               &active_hart_bitmap,
                               &active_epoch);
    sbi_printf("[SM][group] hart first enter: hart=%lu eid=%u group=%lu active_harts=0x%lx epoch=%lu epm=0x%lx/0x%lx yxstm=0x%lx/0x%lx mepc=0x%lx mstatus=0x%lx\n",
               (unsigned long)csr_read(mhartid),
               eid,
               (unsigned long)enclaves[eid].group_id,
               (unsigned long)active_hart_bitmap,
               (unsigned long)active_epoch,
               (unsigned long)enclaves[eid].params.dram_base,
               (unsigned long)enclaves[eid].params.dram_size,
               (unsigned long)enclaves[eid].params.YXSTrusted_base,
               (unsigned long)enclaves[eid].params.YXSTrusted_size,
               (unsigned long)regs->mepc,
               (unsigned long)regs->mstatus);
  }
#endif
  cpu_enter_enclave_context(eid);
  return ret;
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
    enclave_id eid,
    int return_on_resume,
    int preserve_member_gprs){
  unsigned long hartid = csr_read(mhartid);
  struct thread_state* member_thread = &enclaves[eid].threads[0];
  struct thread_state* host_thread = member_thread;
  int group_run_hart_return = 0;
  unsigned long suspend_ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  /*
   * STOP_EDGE_CALL_HOST is resumable.  An OCALL made while a worker owns its
   * YXSTM COMPUTING slot must revoke the hardware aperture while Linux runs,
   * but must not silently discard the logical grant.  Keep it as suspended
   * SM metadata; schedule-in restores it only after all authority epochs and
   * slot ownership have been revalidated.
   */
  if (return_on_resume && eid < ENCL_MAX && ENCLAVE_EXISTS(eid) &&
      enclaves[eid].group_id != 0) {
    suspend_ret = group_scheduler_suspend_yxstm_grant_local(
        eid, "context_switch_to_host", 0);
    if (suspend_ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
      sbi_printf("[SM][sched] resumable host switch could not suspend YXSTM grant: hart=%lu eid=%u ret=%lu\n",
                 hartid, eid, suspend_ret);
  }

  group_scheduler_schedule_out_local(eid, "context_switch_to_host", 0);
  osm_pmp_set(PMP_ALL_PERM);
  group_active_hart_exit(eid);

#if KEYSTONE_GROUP_STARTUP_TRACE
  if (enclaves[eid].group_id != 0 && !group_hart_exit_log_seen[eid]) {
    uint64_t active_hart_bitmap = 0;
    uint64_t active_epoch = 0;

    group_hart_exit_log_seen[eid] = 1;
    group_active_hart_snapshot(enclaves[eid].group_id,
                               &active_hart_bitmap,
                               &active_epoch);
    sbi_printf("[SM][group] hart first exit: hart=%lu eid=%u group=%lu active_harts=0x%lx epoch=%lu\n",
               (unsigned long)csr_read(mhartid),
               eid,
               (unsigned long)enclaves[eid].group_id,
               (unsigned long)active_hart_bitmap,
               (unsigned long)active_epoch);
  }
#endif

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  csr_write(mideleg, interrupts);
  if (enclaves[eid].group_id != 0) {
    csr_set(mie, MIP_MTIP);
    csr_set(mie, MIP_MSIP);
  }

  if (enclaves[eid].group_id != 0 &&
      hartid < MAX_HARTS &&
      group_hart_run_status_ptr[hartid] &&
      group_hart_host_context_valid[hartid]) {
    host_thread = &group_hart_host_threads[hartid];
    group_run_hart_return = 1;
  }

  /*
   * A group_run_hart return owns two independent contexts: the currently
   * running member and the Linux thread that entered this hart's scheduler.
   * Save the member first. Restoring the per-hart host copy directly would
   * otherwise write the member registers into that temporary copy and then
   * discard them when the copy is cleared.
  */
  if (group_run_hart_return) {
    if (preserve_member_gprs) {
      group_scheduler_save_thread_context_exact(member_thread, regs);
      group_member_saved_mepc_advanced[eid] = 1;
    } else {
      group_scheduler_save_thread_context(member_thread, regs,
                                          return_on_resume);
      /* Synchronous STOP is still at its ecall and needs the wrapper's +4. */
      group_member_saved_mepc_advanced[eid] = 0;
    }
    group_scheduler_restore_thread_context_exact(host_thread, regs);
  } else {
    /* Non-group ABI keeps the original paired exchange semantics. */
    if (preserve_member_gprs)
      swap_prev_state_exact(member_thread, regs);
    else
      swap_prev_state(member_thread, regs, return_on_resume);
    swap_prev_mepc(member_thread, regs, regs->mepc);
    swap_prev_mstatus(member_thread, regs, regs->mstatus);
  }
  if (group_run_hart_return) {
    sbi_memset(host_thread, 0, sizeof(*host_thread));
    group_hart_host_context_valid[hartid] = 0;
  }

  group_restore_host_ipi();
  switch_vector_host();

  uintptr_t pending = csr_read(mip);

  if (pending & MIP_MTIP) {
    /*
     * MTIP is level-triggered by the expired machine timer comparator.
     * Merely clearing mip.MTIP can immediately retrigger before Linux runs.
     * OpenSBI's timer processing disables MTIE and exposes STIP to the host;
     * schedule-in programs the next CFS-lite slice.
     */
    sbi_timer_process();
  }
  if (pending & MIP_MSIP) {
    if (enclaves[eid].group_id != 0)
      sbi_ipi_process();
    else {
      csr_clear(mip, MIP_MSIP);
      csr_set(mip, MIP_SSIP);
    }
  }
  if (pending & MIP_MEIP) {
    csr_clear(mip, MIP_MEIP);
    csr_set(mip, MIP_SEIP);
  }

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();

  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(void){
  enclave_id eid;
  int i=0;

  sbi_memset(enabled_groups, 0, sizeof(enabled_groups));
  sbi_memset(group_metadata_arena, 0, sizeof(group_metadata_arena));
  sbi_memset(group_metadata_bitmap, 0, sizeof(group_metadata_bitmap));
  sbi_memset(group_active_harts, 0, sizeof(group_active_harts));
  group_scheduler_reset_locked();
  group_generation_counter = 0;
  enclave_generation_counter = 0;
  configured_group_count = 0;

  /* Assumes eids are incrementing values, which they are for now */
  for(eid=0; eid < ENCL_MAX; eid++){
    enclaves[eid].state = INVALID;
    enclaves[eid].generation = 0;

    enclaves[eid].engine_id = 0;
    enclaves[eid].group_id = 0;
    enclaves[eid].assigned_hart = 0;
    enclaves[eid].hart_bound = 0;
    enclaves[eid].sched_state = GROUP_SCHED_NONE;
    group_member_timer_ready[eid] = 0;

    // Clear out regions
    for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
      enclaves[eid].regions[i].type = REGION_INVALID;
    }
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[eid]));
  }

}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  sbi_memset((void*)utbase, 0, utsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long clean_enclave_YXST_memory(uintptr_t YXSTbase, uintptr_t YXSTsize)
{
  sbi_memset((void*)YXSTbase, 0, YXSTsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(enclave_id* _eid)
{
  enclave_id eid;

  spin_lock(&encl_lock);

  for(eid=0; eid<ENCL_MAX; eid++)
  {
    if(enclaves[eid].state == INVALID){
      break;
    }
  }
  if(eid != ENCL_MAX) {
    enclaves[eid].state = ALLOCATED;
    enclaves[eid].generation =
      next_nonzero_generation(&enclave_generation_counter);
  }

  spin_unlock(&encl_lock);

  if(eid != ENCL_MAX){
    *_eid = eid;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  else{
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
}

static unsigned long encl_free_eid(enclave_id eid)
{
  spin_lock(&encl_lock);
  enclaves[eid].state = INVALID;
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type){
  size_t i;
  for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == type){
      return i;
    }
  }
  // No such region for this enclave
  return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create_t* dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create_t));

  if (region_overlap)
    return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data from enclave, source must be inside EPM */
static unsigned long copy_enclave_data(struct enclave* enclave,
                                          void* dest, uintptr_t source, size_t size) {

  int illegal = copy_to_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static unsigned long copy_enclave_report(struct enclave* enclave,
                                            uintptr_t dest, struct report* source) {

  int illegal = copy_from_sm(dest, source, sizeof(struct report));

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create_t* args)
{
  uintptr_t epm_start, epm_end;
  uintptr_t group_epm_end;

  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;
  if (args->sec_region.size > 0 &&
      args->sec_region.paddr >= args->sec_region.paddr + args->sec_region.size)
    return 0;
  if (args->YXSTM_region.size > 0 &&
      (!args->yxstm_slice_size || !args->yxstm_bank_count ||
       args->yxstm_bank_count > KEYSTONE_YXSTM_MAX_BANKS ||
       args->yxstm_slice_size >
           (size_t)-1 / KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT /
               args->yxstm_bank_count ||
       args->yxstm_slice_size * KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT *
               args->yxstm_bank_count != args->YXSTM_region.size))
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  if (args->group_epm_region.size > 0) {
    if (args->group_epm_region.paddr >=
        args->group_epm_region.paddr + args->group_epm_region.size)
      return 0;
    group_epm_end = args->group_epm_region.paddr + args->group_epm_region.size;
    if (args->group_epm_region.paddr > epm_start || epm_end > group_epm_end)
      return 0;
  }

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;
  if (args->sec_region.size > 0) {
    uintptr_t sec_end = args->sec_region.paddr + args->sec_region.size;
    if (args->sec_region.paddr < epm_end && epm_start < sec_end)
      return 0;
    if (args->utm_region.size > 0) {
      uintptr_t utm_end = args->utm_region.paddr + args->utm_region.size;
      if (args->sec_region.paddr < utm_end && args->utm_region.paddr < sec_end)
        return 0;
    }
    if (args->YXSTM_region.size > 0) {
      uintptr_t yxstm_end = args->YXSTM_region.paddr + args->YXSTM_region.size;
      if (args->sec_region.paddr < yxstm_end && args->YXSTM_region.paddr < sec_end)
        return 0;
    }
    if (args->shared_utm_region.size > 0) {
      uintptr_t shared_utm_end = args->shared_utm_region.paddr + args->shared_utm_region.size;
      if (args->sec_region.paddr < shared_utm_end && args->shared_utm_region.paddr < sec_end)
        return 0;
    }
  }

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;
  
  return 1;
}

// 初始化从属 enclave 的函数
static void initialize_m_enclave(m_enclave* menclave) {
  menclave->slave_numbers = 0; // 设置从属数量为0
  for (int i = 0; i < MAX_SLAVE_ENCLAVES; i++) {
    menclave->slave_enclave[i] = NULL; // 初始化从属 enclave 指针为 NULL
  }
}

// 初始化 s_enclave 的函数
static void initialize_s_enclave(s_enclave* enclave) {
  enclave->state = 0; // 初始化状态
  enclave->s_id = 0; // 初始化从属 enclave 的 ID
  enclave->data_ptr = 0; // 初始化数据指针
  enclave->size = 0; // 初始化数据大小
  enclave->numbers = 0; // 初始化块id
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create_t create_args)
{
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t group_epm_base = create_args.group_epm_region.paddr;
  size_t group_epm_size = create_args.group_epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;
  uintptr_t YXSTbase = create_args.YXSTM_region.paddr;
  size_t YXSTsize = create_args.YXSTM_region.size;
  /* Shared UTM parameters for dual-enclave parallel encryption */
  uintptr_t shared_utm_base = create_args.shared_utm_region.paddr;
  size_t shared_utm_size = create_args.shared_utm_region.size;
  uintptr_t sec_base = create_args.sec_region.paddr;
  size_t sec_size = create_args.sec_region.size;
  uintptr_t sec_flags = create_args.sec_flags;
  uintptr_t sec_engine_id = create_args.sec_engine_id;
  uint64_t ms_YXSTM = create_args.ms_YXSTM;
  uint64_t engine_id = create_args.engine_id;
  size_t yxstm_bank_slice_size = create_args.yxstm_slice_size;
  uint64_t yxstm_bank_count = create_args.yxstm_bank_count;
  int is_create = 0;
  byte kg[MDSIZE];

  enclave_id eid;
  unsigned long ret;
  int region, shared_region;
  int YXSTM_region = -1;
  int sec_region = -1;
  struct enabled_group_slot* group_slot = 0;
  int group_mode = group_mode_enabled(ms_YXSTM, engine_id);
  int uses_group_epm_region = 0;
  int created_group_epm_region = 0;
  int owns_yxstm_region = 0;
  int uses_yxstm_region = 0;
  int reserved_group_member = 0;
  int registered_group_member_descriptor = 0;
  int owns_sec_region = 0;
  int uses_sec_region = 0;
  int sec_region_slot = 2;
  struct keystone_pmp_budget pmp_budget;

  /*
   * These ownership flags form the create transaction journal. Failure labels
   * unwind in reverse order: member descriptor, SEC, YXSTM, shared regions,
   * group EPM, eid, and finally the reserved membership count.
   */

  /* Debug: Print UTM parameters to verify NAPOT alignment */
  // sbi_printf("[SM] create_enclave: EPM base=0x%lx size=0x%lx\n", base, size);
  // sbi_printf("[SM] create_enclave: UTM base=0x%lx size=0x%lx\n", utbase, utsize);
  // if (utsize > 0) {
  //   int is_power_of_2 = !(utsize & (utsize - 1));
  //   int is_aligned = !(utbase & (utsize - 1));
  //   sbi_printf("[SM] UTM NAPOT check: power_of_2=%d aligned=%d\n", is_power_of_2, is_aligned);
  // }

  ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  /* Validate shared UTM region does not overlap with EPM (Requirement 3.6) */
  if (shared_utm_size > 0) {
    uintptr_t epm_end = base + size;
    uintptr_t shared_utm_end = shared_utm_base + shared_utm_size;
    
    /* Check for overlap: regions overlap if one starts before the other ends */
    if ((shared_utm_base < epm_end) && (base < shared_utm_end)) {
      sbi_printf("[SM] ERROR: Shared UTM region [0x%lx-0x%lx) overlaps with EPM [0x%lx-0x%lx)\n",
                 shared_utm_base, shared_utm_end, base, epm_end);
      return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
    }
    
    sbi_printf("[SM] Shared UTM configured: base=0x%lx size=0x%lx\n", 
               shared_utm_base, (unsigned long)shared_utm_size);
  }

  /* Runtime parameters */
  if(!is_create_args_valid(&create_args))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (group_mode) {
    ret = pmp_group_preflight(group_epm_base, group_epm_size,
                              YXSTbase, YXSTsize,
                              sec_base, sec_size, &pmp_budget);
    if (ret) {
      sbi_printf("[SM][pmp] group preflight rejected: group=%lu epm=0x%lx/0x%lx yxstm=0x%lx/0x%lx sec=0x%lx/0x%lx ret=%lu\n",
                 (unsigned long)engine_id,
                 (unsigned long)group_epm_base,
                 (unsigned long)group_epm_size,
                 (unsigned long)YXSTbase,
                 (unsigned long)YXSTsize,
                 (unsigned long)sec_base,
                 (unsigned long)sec_size, ret);
      return ret;
    }
    sbi_printf("[SM][pmp] group preflight: group=%lu metadata_limit=%d hardware=%u slots={sm:%u epm:%u yxstm:%u sec:%u os_utm:%u reserved:%u} total=%u\n",
               (unsigned long)engine_id, PMP_MAX_N_REGION,
               (unsigned int)pmp_budget.hardware_entries,
               (unsigned int)pmp_budget.sm_entries,
               (unsigned int)pmp_budget.epm_entries,
               (unsigned int)pmp_budget.yxstm_entries,
               (unsigned int)pmp_budget.sec_entries,
               (unsigned int)pmp_budget.os_utm_entries,
               (unsigned int)pmp_budget.reserved_entries,
               (unsigned int)pmp_budget.total_entries);
  }

  /* set params */
  struct runtime_params_t params;
  params.dram_base = base;
  params.dram_size = size;
  params.runtime_base = create_args.runtime_paddr;
  params.user_base = create_args.user_paddr;
  params.free_base = create_args.free_paddr;
  params.untrusted_base = utbase;
  params.untrusted_size = utsize;
  params.YXSTrusted_base = YXSTbase;
  params.YXSTrusted_size = YXSTsize;
  /* Set shared UTM parameters for slave enclave to access owner's UTM */
  params.shared_utm_base = shared_utm_base;
  params.shared_utm_size = shared_utm_size;
  params.sec_base = sec_base;
  params.sec_size = sec_size;
  params.sec_flags = sec_flags;
  params.sec_engine_id = sec_engine_id;

  spin_lock(&encl_lock);
  if (group_mode) {
    if (group_any_active_locked()) {
      spin_unlock(&encl_lock);
      return SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    }
    group_slot = find_or_alloc_group_locked(engine_id, ms_YXSTM);
    if (!group_slot) {
      spin_unlock(&encl_lock);
      return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
    }
    if (!group_slot->pmp_budget_valid) {
      group_slot->pmp_budget = pmp_budget;
      group_slot->pmp_budget_valid = 1;
    }
    if (!group_context_validate_locked(group_slot, "create_reserve")) {
      spin_unlock(&encl_lock);
      ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      reserved_group_member = 1;
      goto free_group_member;
    }
    reserved_group_member = 1;
    if (group_slot->pmp_budget.epm_entries !=
                   pmp_budget.epm_entries ||
               group_slot->pmp_budget.yxstm_entries !=
                   pmp_budget.yxstm_entries ||
               group_slot->pmp_budget.sec_entries !=
                   pmp_budget.sec_entries) {
      spin_unlock(&encl_lock);
      ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
      goto free_group_member;
    }
  } else if (ms_YXSTM != 0 && YXSTM_sm_fleible == 0 && sm_engine_id == 0) {
    YXSTM_sm_fleible = ms_YXSTM;
    sm_engine_id = engine_id;
    YXSTM_sm_init = 0;
  }
  spin_unlock(&encl_lock);

  if (ms_YXSTM == 0) {
    params.YXSTrusted_base = 0;
    params.YXSTrusted_size = 0;
    engine_id = 0;
  }
  params.free_requested = create_args.free_requested;

  if (group_mode &&
      (!group_epm_size ||
       !range_contains(group_epm_base, group_epm_size, base, size))) {
    sbi_printf("[SM][group] member EPM slice outside requested group pool: group=%lu slice=0x%lx/0x%lx pool=0x%lx/0x%lx\n",
               (unsigned long)engine_id,
               (unsigned long)base,
               (unsigned long)size,
               (unsigned long)group_epm_base,
               (unsigned long)group_epm_size);
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto free_group_member;
  }

  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto free_group_member;

  // create or reuse a PMP region bound to the enabled group
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  region = -1;
  if (group_mode) {
    spin_lock(&encl_lock);
    if (group_slot->epm_region >= 0) {
      if (!range_contains(group_slot->epm_base,
                          group_slot->epm_size,
                          base,
                          size) ||
          group_slot->epm_base != group_epm_base ||
          group_slot->epm_size != group_epm_size) {
        sbi_printf("[SM][group] reject member outside active group EPM: group=%lu slice=0x%lx/0x%lx active_pool=0x%lx/0x%lx requested_pool=0x%lx/0x%lx\n",
                   (unsigned long)engine_id,
                   (unsigned long)base,
                   (unsigned long)size,
                   (unsigned long)group_slot->epm_base,
                   (unsigned long)group_slot->epm_size,
                   (unsigned long)group_epm_base,
                   (unsigned long)group_epm_size);
        spin_unlock(&encl_lock);
        ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
        goto free_encl_idx;
      }
      region = group_slot->epm_region;
      group_slot->epm_refcount++;
      uses_group_epm_region = 1;
    }
    spin_unlock(&encl_lock);
  }

  if (region < 0) {
    uintptr_t pmp_base = (group_mode && group_epm_size > 0) ? group_epm_base : base;
    size_t pmp_size = (group_mode && group_epm_size > 0) ? group_epm_size : size;

    ret = group_mode ?
        pmp_region_init_fixed_atomic(pmp_base, pmp_size,
                                     KEYSTONE_PMP_SLOT_GROUP_EPM_LO, 2,
                                     &region, 0) :
        pmp_region_init_atomic(pmp_base, pmp_size, PMP_PRI_ANY,
                               &region, 0);
    if (ret)
      goto free_encl_idx;

    if (group_mode) {
      spin_lock(&encl_lock);
      if (group_slot->epm_region < 0) {
        group_slot->epm_base = pmp_base;
        group_slot->epm_size = pmp_size;
        group_slot->epm_region = region;
        group_slot->epm_refcount = 1;
        uses_group_epm_region = 1;
        created_group_epm_region = 1;
      } else {
        spin_unlock(&encl_lock);
        ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
        goto free_region;
      }
      spin_unlock(&encl_lock);
    }
  }

  // sbi_printf("YXSTM sm testing %s\t, eid:%u, base:%lu ,size:%lu, flexible:%u\n", __func__, eid, base, size, YXSTM_sm_fleible);

  /*
   * JH7110 has eight hardware entries per hart even though the SM maintains
   * 24 software region descriptors. Group descriptors reuse the fixed layout:
   * SM=0, EPM=1-2, YXSTM=3-4, SEC=5-6, OS/UTM=7.
   */

  // create PMP region for shared memory (UTM)
  // Skip UTM PMP allocation if utsize = 0 (Slave Enclave uses shared UTM instead)
  // This saves 2 PMP registers per Slave Enclave
  shared_region = -1;  // Initialize to invalid
  if (utsize > 0) {
    // Use PMP_PRI_BOTTOM to share PMP register 7 with OS region
    // This is the original Keystone design - UTM and OS share the same PMP register
    // PMP_PRI_BOTTOM always uses reg 7 (PMP_N_REG - 1) and allows multiple regions to share it
    // This saves PMP registers compared to PMP_PRI_ANY which would allocate separate registers
    // sbi_printf("[SM] Initializing UTM PMP region with PMP_PRI_BOTTOM...\n");
    int utm_ret = pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0);
    // sbi_printf("[SM] UTM PMP init result: %d, region_id=%d\n", utm_ret, shared_region);
    if(utm_ret) {
      ret = utm_ret;
      goto free_region;
    }
  }

  if (ms_YXSTM) {
    if (group_mode) {
      spin_lock(&encl_lock);
      is_create = (group_slot->yxstm_region < 0);
      if (!is_create) {
        if (group_slot->yxstm_base != YXSTbase ||
            group_slot->yxstm_size != YXSTsize ||
            group_slot->yxstm_bank_slice_size != yxstm_bank_slice_size ||
            group_slot->yxstm_bank_count != yxstm_bank_count) {
          spin_unlock(&encl_lock);
          ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
          goto free_shared_region;
        }
        YXSTM_region = group_slot->yxstm_region;
        group_slot->yxstm_refcount++;
        group_update_yxstm_slices_locked(group_slot);
        if (group_region_add_or_get_locked(group_slot,
                                           GROUP_REGION_SHARED,
                                           YXSTbase,
                                           YXSTsize,
                                           GROUP_REGION_PERM_R |
                                             GROUP_REGION_PERM_W,
                                           0)) {
          group_slot->yxstm_refcount--;
          spin_unlock(&encl_lock);
          ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
          goto free_shared_region;
        }
        uses_yxstm_region = 1;
      }
      spin_unlock(&encl_lock);

      if (is_create) {
        ret = pmp_region_init_fixed_atomic(YXSTbase, YXSTsize,
                                           KEYSTONE_PMP_SLOT_YXSTM_LO, 2,
                                           &YXSTM_region, 0);
        if (ret)
          goto free_shared_region;

        owns_yxstm_region = 1;
        uses_yxstm_region = 1;

        spin_lock(&encl_lock);
        group_slot->yxstm_base = YXSTbase;
        group_slot->yxstm_size = YXSTsize;
        group_slot->yxstm_bank_slice_size = yxstm_bank_slice_size;
        group_slot->yxstm_bank_count = yxstm_bank_count;
        group_slot->yxstm_region = YXSTM_region;
        group_slot->yxstm_refcount = 1;
        group_update_yxstm_slices_locked(group_slot);
        if (group_region_add_or_get_locked(group_slot,
                                           GROUP_REGION_SHARED,
                                           YXSTbase,
                                           YXSTsize,
                                           GROUP_REGION_PERM_R |
                                             GROUP_REGION_PERM_W,
                                           0)) {
          spin_unlock(&encl_lock);
          ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
          goto free_YXSTM_region;
        }
        spin_unlock(&encl_lock);

        ret = pmp_set_global(YXSTM_region, PMP_NO_PERM);
        if(ret)
          goto free_YXSTM_region;
        clean_enclave_YXST_memory(YXSTbase, YXSTsize);
      }
    } else {
      spin_lock(&encl_lock);
      is_create = (YXSTM_sm_init == 0);
      sbi_printf("[SM] YXSTM: ms=%lu engine_id=%lu is_create=%d YXSTM_sm_init=%d sm_engine_id=%d\n",
                 ms_YXSTM, engine_id, is_create, YXSTM_sm_init, sm_engine_id);
      sbi_printf("[SM] YXSTM: YXSTbase=0x%lx YXSTsize=0x%lx\n", YXSTbase, YXSTsize);
      // sbi_printf("is_create:%d ,YXSTM_sm_init:%d, eid:%d\n", is_create, YXSTM_sm_init, eid);
      if (is_create && sm_engine_id != 0) {
        ret = pmp_region_init_atomic(YXSTbase, YXSTsize, PMP_PRI_ANY,
                                     &YXSTM_region, 0);
        if(ret) {
          spin_unlock(&encl_lock);
          goto free_shared_region;
        }
        owns_yxstm_region = 1;
        YXSTM_sm_init = YXSTM_region;
      }

      if (engine_id == sm_engine_id && sm_engine_id != 0) {
        YXSTM_region = YXSTM_sm_init;
      }

      spin_unlock(&encl_lock);
      if (is_create && sm_engine_id != 0) {
        ret = pmp_set_global(YXSTM_region, PMP_NO_PERM);
        if(ret) {
          YXSTM_sm_init = 0;
          goto free_YXSTM_region;
        }
        // 只清除一次，在pmp ipi同步之后，立马对stm memset 0
        clean_enclave_YXST_memory(YXSTbase, YXSTsize);
      }
    }
  }

  if (sec_size > 0) {
    spin_lock(&encl_lock);
    if (SEC_sm_init < 0) {
      ret = group_mode ?
          pmp_region_init_fixed_atomic(sec_base, sec_size,
                                       KEYSTONE_PMP_SLOT_SEC_LO, 2,
                                       &sec_region, 0) :
          pmp_region_init_atomic(sec_base, sec_size, PMP_PRI_ANY,
                                 &sec_region, 0);
      if (ret) {
        spin_unlock(&encl_lock);
        goto free_YXSTM_region;
      }
      SEC_sm_init = sec_region;
      SEC_sm_fleible = 1;
      SEC_sm_base = sec_base;
      SEC_sm_size = sec_size;
      SEC_sm_flags = sec_flags;
      SEC_sm_engine_id = sec_engine_id;
      owns_sec_region = 1;
      uses_sec_region = 1;
    } else {
      if (SEC_sm_base != sec_base || SEC_sm_size != sec_size ||
          SEC_sm_flags != sec_flags || SEC_sm_engine_id != sec_engine_id) {
        spin_unlock(&encl_lock);
        ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
        goto free_YXSTM_region;
      }
      sec_region = SEC_sm_init;
      SEC_sm_fleible++;
      uses_sec_region = 1;
    }
    spin_unlock(&encl_lock);

    if (owns_sec_region) {
      ret = pmp_set_global(sec_region, PMP_NO_PERM);
      if (ret)
        goto free_sec_region;
    }

    sec_region_slot = ms_YXSTM ? 3 : 2;
  }

  // set pmp registers for private region (not shared)
  if(!group_mode || !uses_group_epm_region || created_group_epm_region) {
    ret = pmp_set_global(region, PMP_NO_PERM);
    if (ret)
      goto free_sec_region;
  }

  // sbi_printf("[SM] EPM pmp_set_global completed, cleaning UTM memory...\n");

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);

  // sbi_printf("[SM] UTM memory cleaned, initializing enclave metadata...\n");

  // initialize enclave metadata
  enclaves[eid].eid = eid;
  enclaves[eid].engine_id = engine_id;
  enclaves[eid].group_id = group_mode ? engine_id : 0;
  enclaves[eid].assigned_hart = 0;
  enclaves[eid].hart_bound = 0;
  enclaves[eid].sched_state =
    group_mode ? GROUP_SCHED_RUNNABLE : GROUP_SCHED_NONE;

  // Initialize the master enclave structure for the newly created enclave
  initialize_m_enclave(&enclaves[eid].m);
  // Initialize the slave enclave structure for the newly created enclave
  initialize_s_enclave(&enclaves[eid].s);

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
  if (ms_YXSTM) {
    enclaves[eid].regions[2].pmp_rid = YXSTM_region;
    enclaves[eid].regions[2].type =
      group_mode ? REGION_GROUP_SHARED : REGION_OTHER;
  }
  if (sec_region >= 0) {
    enclaves[eid].regions[sec_region_slot].pmp_rid = sec_region;
    enclaves[eid].regions[sec_region_slot].type = REGION_OTHER;
  }
  
  // UTM (shared memory) should be accessible to Host immediately after creation
  // This allows Host to mmap and access UTM before Enclave starts running
  // NOTE: Since UTM uses PMP_PRI_BOTTOM, it shares PMP register 7 with OS.
  // The OS region already has PMP_ALL_PERM covering the entire RAM, so UTM
  // is already accessible. We should NOT call pmp_set_keystone here because
  // it would overwrite the OS's "entire RAM" configuration with UTM's smaller
  // region, breaking access to other memory areas.
  // 
  // Only set UTM PMP if it's a valid region (not -1)
  // if (shared_region >= 0) {
  //   // Skip pmp_set_keystone for PMP_PRI_BOTTOM regions - they share with OS
  //   // which already has PMP_ALL_PERM for the entire address space
  // }
  
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = params;
  enclaves[eid].ped.sec_mmio_base = sec_base;
  enclaves[eid].ped.sec_mmio_size = sec_size;
  enclaves[eid].ped.sec_engine_id = sec_engine_id;
  enclaves[eid].ped.sec_flags = sec_flags;
  enclaves[eid].ped.sec_owned = 0;

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  if (group_mode) {
    ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
    if (group_member_register(engine_id, eid,
                              base, size, 0,
                              YXSTbase, YXSTsize,
                              utbase, utsize,
                              shared_utm_base, shared_utm_size,
                              sec_base, sec_size))
      goto unset_region;
    registered_group_member_descriptor = 1;

    ret = group_member_validate_initial_view(eid);
    if (ret)
      goto unset_region;
  }

  // sbi_printf("[SM] Calling platform_create_enclave...\n");

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if (ret)
    goto unset_region;

  // sbi_printf("[SM] platform_create_enclave done, validating and hashing...\n");

  /* Validate memory, prepare hash and signature for attestation */
  spin_lock(&encl_lock); // FIXME This should error for second enter.
 
  ret = validate_and_hash_enclave(&enclaves[eid]);

  // sbi_printf("[SM] validate_and_hash_enclave done, ret=%ld\n", ret);

  // spin_unlock(&encl_lock);
  if (ms_YXSTM) {
    // sbi_printf("[SM] Processing YXSTM key generation...\n");
    // if (is_create) {
    //   sbi_printf("kg_ready 1, eid:%d\n", eid);
    //   generate_kg(&enclaves[eid], kg);
    //   sbi_printf("kg_ready 1, eid:%d\n", eid);
    //   sbi_memcpy((void*)(YXSTbase + YXSTsize - sizeof(kg)), (void*)kg, sizeof(kg));
    //   sbi_printf("kg_ready 3, eid:%d\n", eid);
    //   kg_ready = 1;
    //   mb();
    // } else {
    //   sbi_printf("kg_ready 2, eid:%d\n", eid);
    //   sbi_printf("YXSTM_sm_init:%d , eid:%d\n", YXSTM_sm_init, eid);
    //   while (!kg_ready){
    //     mb();
    //   }
    // }
    // spin_lock(&encl_lock);
    if (group_mode && group_slot) {
      if (group_slot->kg_ready == 0) {
        generate_kg(&enclaves[eid], kg);
        sbi_memcpy((void*)(YXSTbase + YXSTsize - sizeof(kg)), (void*)kg, sizeof(kg));
        group_slot->kg_ready = 1;
      }
    } else if (kg_ready == 0) {
      // sbi_printf("[SM] Generating key...\n");
      generate_kg(&enclaves[eid], kg);
      // sbi_printf("kg_ready 1, eid:%d, kg_ready:%d\n", eid, kg_ready);
      sbi_memcpy((void*)(YXSTbase + YXSTsize - sizeof(kg)), (void*)kg, sizeof(kg));
      // sbi_printf("kg_ready 3, eid:%d\n", eid);
      kg_ready = 1;
      // sbi_printf("[SM] Key generation done\n");
    } else {
      // sbi_printf("[SM] Key already generated\n");
      // sbi_printf("kg_ready 2, eid:%d, kg_ready:%d\n", eid, kg_ready);
      // sbi_printf("YXSTM_sm_init:%d , eid:%d\n", YXSTM_sm_init, eid);
    }
    // spin_unlock(&encl_lock);
  }
  // spin_lock(&encl_lock);
  
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret)
    goto unlock;

  if (group_mode) {
    if (!group_slot || group_slot->pending_create_count == 0 ||
        group_slot->lifecycle_state == KEYSTONE_GROUP_STATE_ACTIVE ||
        group_slot->lifecycle_state == KEYSTONE_GROUP_STATE_DRAINING) {
      ret = SBI_ERR_SM_GROUP_BAD_STATE;
      goto unlock;
    }
    group_slot->pending_create_count--;
    if (group_slot->lifecycle_state == KEYSTONE_GROUP_STATE_CONFIGURING)
      group_slot->lifecycle_state = KEYSTONE_GROUP_STATE_READY;
  }

  enclaves[eid].state = FRESH;
  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = ((enclaves[eid].generation & 0xffffffffUL) << 32) | eid;

  // sbi_printf("[SM] create_enclave SUCCESS! eid=%d\n", eid);

  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
  spin_unlock(&encl_lock);
// free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  if (registered_group_member_descriptor) {
    group_member_unregister(engine_id, eid);
    registered_group_member_descriptor = 0;
  }
  if (!(group_mode && uses_group_epm_region) && region >= 0)
    pmp_unset_global(region);
free_sec_region:
  if (uses_sec_region && sec_region >= 0) {
    int free_shared_sec = 0;

    spin_lock(&encl_lock);
    if (SEC_sm_fleible > 0) {
      SEC_sm_fleible--;
      if (SEC_sm_fleible == 0) {
        SEC_sm_init = -1;
        SEC_sm_base = 0;
        SEC_sm_size = 0;
        SEC_sm_flags = 0;
        SEC_sm_engine_id = 0;
        free_shared_sec = 1;
      }
    }
    spin_unlock(&encl_lock);

    if (free_shared_sec) {
      pmp_unset_global(sec_region);
      pmp_region_free_atomic(sec_region);
    }
  }
free_YXSTM_region:
  if (group_mode && uses_yxstm_region && YXSTM_region >= 0) {
    group_yxstm_release(YXSTM_region);
  } else if (owns_yxstm_region && YXSTM_region >= 0) {
    pmp_region_free_atomic(YXSTM_region);
  }
free_shared_region:
  if (shared_region >= 0)
    pmp_region_free_atomic(shared_region);
free_region:
  if (group_mode && uses_group_epm_region && region >= 0) {
    group_epm_release(region);
  } else if (region >= 0) {
    pmp_region_free_atomic(region);
  }
free_encl_idx:
  encl_free_eid(eid);
free_group_member:
  if (reserved_group_member)
    group_member_release(engine_id);
  return ret;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails if the enclave is running or its group still has active harts.
 */
unsigned long destroy_enclave(enclave_id eid)
{
  int destroyable;
  enclave_state previous_state = INVALID;

  spin_lock(&encl_lock);
  destroyable = (ENCLAVE_EXISTS(eid)
                 && (enclaves[eid].state <= STOPPED
                     || enclaves[eid].state == FAULTED));
  if (destroyable && enclaves[eid].group_id != 0) {
    struct enabled_group_slot* group =
      find_group_locked(enclaves[eid].group_id);
    if (group && group_any_active_locked()) {
      sbi_printf("[SM][group] reject member destroy while fixed PMP slots are active: group=%lu eid=%u active_harts=0x%lx\n",
                 (unsigned long)enclaves[eid].group_id,
                 eid,
                 (unsigned long)group->active_hart_bitmap);
      destroyable = 0;
    }
  }
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable) {
    if (enclaves[eid].group_id != 0) {
      struct enabled_group_slot* group =
        find_group_locked(enclaves[eid].group_id);
      if (group_ocalls[eid].valid) {
        uint64_t ocall_id = group_ocalls[eid].ocall_id;
        (void)group_scheduler_event_enqueue(
            enclaves[eid].assigned_hart, enclaves[eid].group_id,
            group ? group->generation : 0, eid, enclaves[eid].generation,
            KEYSTONE_GROUP_EVENT_CANCELLED,
            SBI_ERR_SM_GROUP_OCALL_CANCELLED, ocall_id);
        group_ocall_clear_locked(eid, 0);
      }
      if (group && group->lifecycle_state != KEYSTONE_GROUP_STATE_DRAINING)
        group->lifecycle_state = KEYSTONE_GROUP_STATE_DRAINING;
      yxstm_protocol_member_gone_locked(group, eid,
                                        YXSTM_ROLLBACK_WORKER_GONE);
      group_release_yxstm_owner_metadata_locked(eid);
    }
    previous_state = enclaves[eid].state;
    enclaves[eid].state = DESTROYING;
  }
  spin_unlock(&encl_lock);

  if(!destroyable)
    return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;

  if (enclaves[eid].group_id != 0) {
    group_scheduler_clear_enclave_pmp_local(eid);
    asm volatile("sfence.vma" ::: "memory");
    if (!group_scheduler_verify_host_denies_local(eid, "destroy")) {
      pmp_debug_dump_hart("destroy_revoke_mismatch");
      spin_lock(&encl_lock);
      enclaves[eid].state = previous_state;
      spin_unlock(&encl_lock);
      return SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
    }
  }

  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(&enclaves[eid]);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  int i;
  void* base;
  size_t size;
  region_id rid;
  // spin_lock(&encl_lock);
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == REGION_INVALID ||
       enclaves[eid].regions[i].type == REGION_UTM)
      continue;
    rid = enclaves[eid].regions[i].pmp_rid;

    if (group_yxstm_release(rid))
      continue;

    if (enclaves[eid].group_id != 0 &&
        enclaves[eid].regions[i].type == REGION_EPM)
      sbi_memset((void*)enclaves[eid].params.dram_base,
                 0, enclaves[eid].params.dram_size);

    if (group_epm_release(rid))
      continue;

    //1.a Clear all pages
    if (enclaves[eid].regions[i].type != REGION_OTHER) {
      base = (void*) pmp_region_get_addr(rid);
      size = (size_t) pmp_region_get_size(rid);
      sbi_memset((void*) base, 0, size);
    }
    //1.b free pmp region
    if (YXSTM_sm_init == rid) {
      spin_lock(&encl_lock);
      YXSTM_sm_fleible--;
      unsigned int is_last = (YXSTM_sm_fleible == 0);
      if (is_last) {
        YXSTM_sm_init = 0;
        sm_engine_id = 0;
      }

      spin_unlock(&encl_lock);

      if (is_last) {
        pmp_unset_global(rid);
        pmp_region_free_atomic(rid);
        kg_ready = 0;
      }
      continue;
    }
    if (enclaves[eid].regions[i].type == REGION_OTHER &&
        enclaves[eid].ped.sec_mmio_size > 0) {
      int free_shared_sec = 0;

      spin_lock(&encl_lock);
      if (SEC_sm_init == rid && SEC_sm_fleible > 0) {
        SEC_sm_fleible--;
        if (SEC_sm_fleible == 0) {
          SEC_sm_init = -1;
          SEC_sm_base = 0;
          SEC_sm_size = 0;
          SEC_sm_flags = 0;
          SEC_sm_engine_id = 0;
          free_shared_sec = 1;
        }
      }
      spin_unlock(&encl_lock);

      if (free_shared_sec) {
        pmp_unset_global(rid);
        pmp_region_free_atomic(rid);
      }
      continue;
    }
    pmp_unset_global(rid);
    // sbi_printf("YXSTM testing 2 %s , free region:%d\n", __func__,  rid);
    pmp_region_free_atomic(rid);
    // sbi_printf("YXSTM testing 3 %s , free region:%d\n", __func__,  rid);
  }

  // 2. free pmp region for UTM
  rid = get_enclave_region_index(eid, REGION_UTM);
  if(rid != -1)
    pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

  group_member_unregister(enclaves[eid].group_id, eid);
  group_member_release(enclaves[eid].group_id);
#if KEYSTONE_GROUP_STARTUP_TRACE
  group_hart_enter_log_seen[eid] = 0;
  group_hart_exit_log_seen[eid] = 0;
#endif
  group_member_timer_ready[eid] = 0;
  group_control_requests[eid] = 0;

  enclaves[eid].encl_satp = 0;
  enclaves[eid].n_thread = 0;
  enclaves[eid].assigned_hart = 0;
  enclaves[eid].hart_bound = 0;
  enclaves[eid].sched_state = GROUP_SCHED_NONE;
  enclaves[eid].params = (struct runtime_params_t) {0};
  for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
    enclaves[eid].regions[i].type = REGION_INVALID;
  }

  // 2.5 clean group
  for (int i=0; i<MAX_MS_GROUP; ++i) {
    if(ms_group_list[i].isCreated == 1) {
      if (ms_group_list[i].m != NULL && ms_group_list[i].m == &enclaves[eid].m) {
        if (enclaves[eid].m.slave_numbers != 0) {
          enclaves[eid].m.slave_numbers = 0;
          // sbi_printf("set slave_number\n");
        }
        ms_group_list[i].isCreated = 0;
        break;
      }
    }
  }
  // spin_unlock(&encl_lock);

  // 3. release eid
  encl_free_eid(eid);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int runable;
  unsigned long active_ret;

  spin_lock(&encl_lock);
  runable = (ENCLAVE_EXISTS(eid)
            && enclaves[eid].state == FRESH);
  if(runable) {
    enclaves[eid].state = RUNNING;
    enclaves[eid].n_thread++;
    if (enclaves[eid].group_id != 0 &&
        enclaves[eid].sched_state != GROUP_SCHED_NONE &&
        enclaves[eid].sched_state != GROUP_SCHED_RUNNABLE) {
      enclaves[eid].state = FRESH;
      enclaves[eid].n_thread--;
      runable = 0;
    }
  }
  spin_unlock(&encl_lock);

  if(!runable) {
    return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  }

  active_ret = group_active_hart_enter(eid);
  if (active_ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    spin_lock(&encl_lock);
    if (ENCLAVE_EXISTS(eid) && enclaves[eid].state == RUNNING) {
      if (enclaves[eid].n_thread > 0)
        enclaves[eid].n_thread--;
      if (enclaves[eid].n_thread == 0) {
        enclaves[eid].state = FRESH;
        if (enclaves[eid].group_id != 0)
          (void)group_scheduler_transition_locked(
              eid, GROUP_SCHED_RUNNABLE, "run_enter_rollback");
      }
    }
    spin_unlock(&encl_lock);
    return active_ret;
  }

  // Enclave is OK to run, context switch to it
  active_ret = context_switch_to_enclave(regs, eid, 1);
  if (active_ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
    group_context_switch_fail_rollback(eid, 1);

  return active_ret;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid,
                           int allow_direct_switch)
{
  int exitable;
  unsigned long audit_ret;

  (void)allow_direct_switch;

  spin_lock(&encl_lock);
  exitable = enclaves[eid].state == RUNNING;
  if (exitable && enclaves[eid].group_id != 0 &&
      group_scheduler_transition_locked(eid, GROUP_SCHED_EXITED, "exit"))
    exitable = 0;
  if (exitable) {
    if (enclaves[eid].group_id != 0) {
      struct enabled_group_slot* group =
          find_group_locked(enclaves[eid].group_id);
      struct group_member_descriptor* member =
          group_member_find_locked(group, eid);

      if (member) {
        member->yxstm_completion_pending = 0;
        member->yxstm_completion_epoch = 0;
      }
    }
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0) {
      enclaves[eid].state = STOPPED;
      if (enclaves[eid].group_id != 0) {
        group_control_requests[eid] = 0;
        group_ocall_clear_locked(eid, 0);
        yxstm_protocol_member_gone_locked(
            find_group_locked(enclaves[eid].group_id), eid,
            YXSTM_ROLLBACK_WORKER_GONE);
      }
    }
  }
  spin_unlock(&encl_lock);

  if(!exitable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  audit_ret = group_member_validate_initial_view(eid);
  if (audit_ret)
    return audit_ret;

  /*
   * EXIT is a completion boundary.  Do not splice this synchronous ecall
   * frame into a peer whose context may have been saved asynchronously by
   * the timer path.  In particular, the exiting thread has no continuation
   * to resume, while the peer must be restored from its exact trap frame.
   *
   * Return the EXIT event to the per-hart driver runner instead.  The runner
   * immediately re-enters group_run_hart(), which selects the next runnable
   * member and restores it through the normal host-context entry path.  This
   * keeps timer preemption inside SM and adds a host boundary only when an
   * enclave has actually completed.
   */

  context_switch_to_host(regs, eid, 0, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long fault_enclave(struct sbi_trap_regs *regs, enclave_id eid,
                            unsigned long fault_code,
                            unsigned long fault_cause,
                            unsigned long fault_tval)
{
  int faultable;

  spin_lock(&encl_lock);
  faultable = ENCLAVE_EXISTS(eid) && enclaves[eid].state == RUNNING;
  if (faultable && enclaves[eid].group_id != 0 &&
      group_scheduler_transition_locked(eid, GROUP_SCHED_FAULTED, "fault"))
    faultable = 0;
  if (faultable) {
    if (enclaves[eid].group_id != 0) {
      struct enabled_group_slot* group =
          find_group_locked(enclaves[eid].group_id);
      struct group_member_descriptor* member =
          group_member_find_locked(group, eid);

      if (member) {
        member->yxstm_completion_pending = 0;
        member->yxstm_completion_epoch = 0;
      }
    }
    if (enclaves[eid].n_thread > 0)
      enclaves[eid].n_thread--;
    if (enclaves[eid].n_thread == 0) {
      enclaves[eid].state = FAULTED;
      if (enclaves[eid].group_id != 0) {
        struct enabled_group_slot* group =
            find_group_locked(enclaves[eid].group_id);
        struct group_member_descriptor* member =
            group_member_find_locked(group, eid);
        group_control_requests[eid] = 0;
        group_ocall_clear_locked(eid, 0);
        group_scrub_member_yxstm_locked(group, member, "fault");
        yxstm_protocol_member_gone_locked(
            group, eid, YXSTM_ROLLBACK_FAULT);
        if (group) {
          group->membership_epoch++;
          if (!group->membership_epoch)
            group->membership_epoch = 1;
          if (member)
            member->revoked_epoch = group->membership_epoch;
          group_security_rekey_locked(group, YXSTM_ROLLBACK_FAULT);
        }
      }
    }
  }
  spin_unlock(&encl_lock);

  if (!faultable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  sbi_printf("[SM][fault] enclave fatal fault: eid=%u code=%lu cause=0x%lx tval=0x%lx mepc=0x%lx\n",
             eid,
             fault_code,
             fault_cause,
             fault_tval,
             (unsigned long)regs->mepc);
  if (enclaves[eid].group_id != 0) {
    unsigned long hartid = csr_read(mhartid);

    sbi_printf("[SM][fault] context: hart=%lu ready=%d run_frame=%d host_frame=%d satp=0x%lx sp=0x%lx ra=0x%lx\n",
               hartid,
               group_member_timer_ready[eid],
               hartid < MAX_HARTS && group_hart_run_status_ptr[hartid] != 0,
               hartid < MAX_HARTS && group_hart_host_context_valid[hartid],
               (unsigned long)csr_read(satp),
               (unsigned long)regs->sp,
               (unsigned long)regs->ra);
    sbi_printf("[SM][fault] args: a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx a4=0x%lx a5=0x%lx a6=0x%lx a7=0x%lx\n",
               (unsigned long)regs->a0,
               (unsigned long)regs->a1,
               (unsigned long)regs->a2,
               (unsigned long)regs->a3,
               (unsigned long)regs->a4,
               (unsigned long)regs->a5,
               (unsigned long)regs->a6,
               (unsigned long)regs->a7);
    sbi_printf("[SM][fault] temps: t0=0x%lx t1=0x%lx t2=0x%lx t3=0x%lx t4=0x%lx t5=0x%lx\n",
               (unsigned long)regs->t0,
               (unsigned long)regs->t1,
               (unsigned long)regs->t2,
               (unsigned long)regs->t3,
               (unsigned long)regs->t4,
               (unsigned long)regs->t5);
  }

  context_switch_to_host(regs, eid, 0, 0);
  /*
   * run_status points to driver memory. Write it after restoring the host
   * context, otherwise copy_from_sm may still translate through the enclave
   * page table on a fault path.
   */
  return SBI_ERR_SM_ENCLAVE_FATAL_FAULT;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid)
{
  int stoppable;
  unsigned long current_hart = csr_read(mhartid);
  unsigned long audit_ret;
  uintptr_t control_action = 0;
  enum group_sched_state effective_state = GROUP_SCHED_BLOCKED;
  unsigned long lane_wait_ready_result = SBI_ERR_SM_ENCLAVE_SUCCESS;
  int lane_wait_already_ready = 0;
  int lane_wait_valid = 0;
  unsigned long lane_wait_hart = MAX_HARTS;
  unsigned int lane_wait_enclave_state = INVALID;
  unsigned int lane_wait_sched_state = GROUP_SCHED_NONE;
  unsigned int lane_wait_threads = 0;
  unsigned int lane_wait_pending = 0;
  unsigned int lane_wait_ready = 0;
  unsigned int lane_wait_acquired = 0;
  unsigned int lane_wait_suspended = 0;
  unsigned int lane_wait_active_match = 0;

  spin_lock(&encl_lock);
  if (ENCLAVE_EXISTS(eid)) {
    lane_wait_enclave_state = enclaves[eid].state;
    lane_wait_sched_state = enclaves[eid].sched_state;
    lane_wait_threads = enclaves[eid].n_thread;
  }
  stoppable = ENCLAVE_EXISTS(eid) && enclaves[eid].state == RUNNING;
  if (stoppable && enclaves[eid].group_id != 0) {
    if (request == STOP_EDGE_CALL_HOST) {
      struct enabled_group_slot* completion_group =
          find_group_locked(enclaves[eid].group_id);
      struct group_member_descriptor* completion_member =
          group_member_find_locked(completion_group, eid);

      if (completion_member) {
        completion_member->yxstm_completion_pending = 0;
        completion_member->yxstm_completion_epoch = 0;
      }
    }
    enum group_sched_state next_state =
        request == STOP_YIELD_ENCLAVE ? GROUP_SCHED_RUNNABLE :
        request == STOP_TIMER_INTERRUPT ? GROUP_SCHED_RUNNABLE :
        request == STOP_LANE_WAIT_ENCLAVE ? GROUP_SCHED_BLOCKED :
        request == STOP_EDGE_CALL_HOST ? GROUP_SCHED_BLOCKED :
                                         GROUP_SCHED_BLOCKED;
    control_action = group_control_requests[eid];
    if (control_action == KEYSTONE_GROUP_CONTROL_PAUSE)
      next_state = GROUP_SCHED_PAUSED;
    else if (control_action == KEYSTONE_GROUP_CONTROL_CANCEL)
      next_state = GROUP_SCHED_EXITED;
    effective_state = next_state;
    if (request == STOP_LANE_WAIT_ENCLAVE) {
      struct enabled_group_slot* wait_group =
          find_group_locked(enclaves[eid].group_id);
      struct group_member_descriptor* wait_member =
          group_member_find_locked(wait_group, eid);
      unsigned long wait_hart = enclaves[eid].assigned_hart;
      struct group_hart_slot* wait_slot =
          wait_group && wait_hart < MAX_HARTS ?
              &wait_group->hart_slots[wait_hart] : 0;
      struct sm_hart_sched* wait_sched =
          wait_hart < MAX_HARTS ? &group_hart_schedulers[wait_hart] : 0;

      lane_wait_hart = wait_hart;
      lane_wait_pending = wait_member && wait_member->lane_wait_pending;
      lane_wait_ready = wait_member && wait_member->lane_wait_ready;
      lane_wait_acquired = wait_slot && wait_slot->yxstm_acquired;
      lane_wait_suspended =
          wait_member && wait_member->yxstm_suspended_acquired;
      lane_wait_active_match = wait_sched &&
          group_scheduler_active_matches_locked(wait_sched, eid);
      lane_wait_valid = wait_group && wait_member && wait_slot && wait_sched &&
          wait_member->lane_wait_pending && !wait_slot->yxstm_acquired &&
          !wait_member->yxstm_suspended_acquired &&
          enclaves[eid].hart_bound &&
          enclaves[eid].assigned_hart == current_hart &&
          wait_hart == current_hart && lane_wait_active_match &&
          cpu_is_enclave_context() && cpu_get_enclave_id() == eid;

      if (!control_action && wait_member && wait_member->lane_wait_pending &&
          wait_member->lane_wait_ready) {
        lane_wait_ready_result = wait_member->lane_wait_result;
        group_lane_wait_account_and_clear_locked(wait_member);
        group_member_timer_ready[eid] = 1;
        lane_wait_already_ready = 1;
        stoppable = 0;
      } else if (!lane_wait_valid) {
        stoppable = 0;
      } else if (enclaves[eid].sched_state == GROUP_SCHED_RUNNABLE) {
        /*
         * WAIT_READY disables timer switching before issuing STOP, but an IPI
         * already accepted by the hart can leave the executing member marked
         * RUNNABLE.  Active hart ownership proves that this is the current
         * context, so canonicalize it before the RUNNING -> BLOCKED edge.
         */
        group_scheduler_set_state_locked(eid, GROUP_SCHED_RUNNING);
      }
    }
    if (stoppable &&
        group_scheduler_transition_locked(eid, next_state, "stop"))
      stoppable = 0;
    else if (!control_action && request == STOP_EDGE_CALL_HOST &&
             group_ocall_register_locked(eid, 0)) {
      group_scheduler_set_state_locked(eid, GROUP_SCHED_RUNNING);
      if (enclaves[eid].hart_bound &&
          enclaves[eid].assigned_hart < MAX_HARTS)
        group_scheduler_progress_locked(
            &group_hart_schedulers[enclaves[eid].assigned_hart]);
      stoppable = 0;
    } else if (control_action) {
      struct enabled_group_slot* group =
          find_group_locked(enclaves[eid].group_id);
      group_control_requests[eid] = 0;
      if (control_action == KEYSTONE_GROUP_CONTROL_CANCEL) {
        group_ocall_clear_locked(eid, 0);
        yxstm_protocol_member_gone_locked(group, eid,
                                          YXSTM_ROLLBACK_WORKER_GONE);
        group_release_yxstm_owner_metadata_locked(eid);
      }
    }
  }
  if (stoppable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0) {
      enclaves[eid].state =
          control_action == KEYSTONE_GROUP_CONTROL_CANCEL ? FAULTED : STOPPED;
    }
  }
  spin_unlock(&encl_lock);

  if (lane_wait_already_ready)
    return lane_wait_ready_result;
  if(!stoppable) {
    if (request == STOP_LANE_WAIT_ENCLAVE)
      sbi_printf("[SM][sched] lane wait stop rejected: hart=%lu eid=%u enclave_state=%u sched_state=%u threads=%u pending=%u ready=%u acquired=%u suspended=%u active_match=%u valid=%u\n",
                 lane_wait_hart, eid, lane_wait_enclave_state,
                 lane_wait_sched_state, lane_wait_threads,
                 lane_wait_pending, lane_wait_ready, lane_wait_acquired,
                 lane_wait_suspended, lane_wait_active_match,
                 lane_wait_valid);
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;
  }

  audit_ret = group_member_validate_initial_view(eid);
  if (audit_ret)
    return audit_ret;

  if (enclaves[eid].group_id != 0 &&
      (request == STOP_YIELD_ENCLAVE ||
       request == STOP_EDGE_CALL_HOST ||
       request == STOP_TIMER_INTERRUPT)) {
    spin_lock(&encl_lock);
    group_member_timer_ready[eid] = 1;
    spin_unlock(&encl_lock);
  }

  /*
   * A direct peer switch already writes a successful return into a0. When a
   * lane has no peer, yield/timer-stop returns through HOST and group_run_hart
   * later restores this saved trap frame verbatim. Seed the same return value
   * before saving it; otherwise the original STOP_* request (3 for yield)
   * becomes the runtime syscall result and aborts protocol wait loops.
   */
  if (!control_action &&
      (request == STOP_YIELD_ENCLAVE ||
       request == STOP_LANE_WAIT_ENCLAVE ||
       request == STOP_TIMER_INTERRUPT))
    regs->a0 = SBI_ERR_SM_ENCLAVE_SUCCESS;

  /*
   * OCALL is an unavoidable HOST-service boundary.  Returning through the
   * per-hart runner first publishes the OCALL transaction before that runner
   * immediately re-enters group_run_hart() and selects a runnable peer.
   *
   * Directly switching on STOP_EDGE_CALL_HOST lets two same-lane members both
   * become BLOCKED while their OCALL events and saved host frame are still
   * being unwound.  That ordering can strand the lane after the last direct
   * switch.  Keep direct switching for scheduler-owned yield/timer events,
   * but serialize OCALL publication through HOST.
   */
  if ((request == STOP_YIELD_ENCLAVE ||
       request == STOP_LANE_WAIT_ENCLAVE ||
       request == STOP_TIMER_INTERRUPT) &&
      group_scheduler_direct_switch_from_ecall(
          regs,
          eid,
          effective_state,
          request == STOP_YIELD_ENCLAVE ? "yield" :
          request == STOP_LANE_WAIT_ENCLAVE ? "lane_wait" : "timer_stop",
          1)) {
    if (control_action == KEYSTONE_GROUP_CONTROL_CANCEL)
      return SBI_ERR_SM_GROUP_OCALL_CANCELLED;
    if (control_action == KEYSTONE_GROUP_CONTROL_PAUSE)
      return SBI_ERR_SM_GROUP_PAUSED;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }

  /*
   * A worker with no runnable same-lane peer returns through its saved HOST
   * frame for STOP_TIMER_INTERRUPT/STOP_YIELD_ENCLAVE. That is a resumable
   * scheduler boundary, not an enclave exit: preserve any live slot grant as
   * generation/epoch-bound suspended metadata before schedule-out revokes the
   * hardware aperture. Otherwise the resumed worker continues at the next
   * instruction with its YXSTM mapping present but PMP denied and faults on
   * the first load/store. STOP_LANE_WAIT is deliberately excluded because a
   * blocked waiter must have released its slot before sleeping.
   *
   * Deployment marker: keystone-yxstm-host-fallback-grant-v1
   */
  if (request == STOP_YIELD_ENCLAVE ||
      request == STOP_TIMER_INTERRUPT) {
    unsigned long suspend_ret = group_scheduler_suspend_yxstm_grant_local(
        eid,
        request == STOP_YIELD_ENCLAVE ?
            "yield_to_host" : "timer_stop_to_host",
        0);

    if (suspend_ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
      sbi_printf("[SM][sched] resumable stop could not suspend YXSTM grant: hart=%lu eid=%u request=%lu ret=%lu\n",
                 (unsigned long)csr_read(mhartid), eid,
                 (unsigned long)request, suspend_ret);
      return suspend_ret;
    }
  }

  context_switch_to_host(regs, eid, request == STOP_EDGE_CALL_HOST, 0);
  if (request == STOP_LANE_WAIT_ENCLAVE)
    group_lane_wait_mark_context_saved(eid);

  if (control_action == KEYSTONE_GROUP_CONTROL_CANCEL)
    return SBI_ERR_SM_GROUP_OCALL_CANCELLED;
  if (control_action == KEYSTONE_GROUP_CONTROL_PAUSE)
    return SBI_ERR_SM_GROUP_PAUSED;

  switch(request) {
    case(STOP_TIMER_INTERRUPT):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_EDGE_CALL_HOST):
      return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    case(STOP_YIELD_ENCLAVE):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_LANE_WAIT_ENCLAVE):
      /* Internal scheduler sleep: the HSM runner waits for a lane wakeup. */
      return SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE;
    default:
      return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  }
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int resumable;
  unsigned long active_ret;

  spin_lock(&encl_lock);
  resumable = (ENCLAVE_EXISTS(eid)
               && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED)
               && enclaves[eid].n_thread < MAX_ENCL_THREADS
               && (enclaves[eid].group_id == 0 ||
                   enclaves[eid].sched_state != GROUP_SCHED_BLOCKED));

  if(!resumable) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  } else {
    enclaves[eid].n_thread++;
    enclaves[eid].state = RUNNING;
    if (enclaves[eid].group_id != 0) {
      if (enclaves[eid].sched_state == GROUP_SCHED_PAUSED &&
          group_scheduler_transition_locked(eid, GROUP_SCHED_RUNNABLE,
                                            "resume_prepare")) {
        enclaves[eid].n_thread--;
        enclaves[eid].state = STOPPED;
        spin_unlock(&encl_lock);
        return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
      }
      if (enclaves[eid].sched_state != GROUP_SCHED_RUNNABLE) {
        enclaves[eid].n_thread--;
        enclaves[eid].state = STOPPED;
        spin_unlock(&encl_lock);
        return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
      }
    }
  }
  spin_unlock(&encl_lock);

  active_ret = group_active_hart_enter(eid);
  if (active_ret != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    spin_lock(&encl_lock);
    if (ENCLAVE_EXISTS(eid) && enclaves[eid].state == RUNNING) {
      if (enclaves[eid].n_thread > 0)
        enclaves[eid].n_thread--;
      if (enclaves[eid].n_thread == 0) {
        enclaves[eid].state = STOPPED;
        if (enclaves[eid].group_id != 0)
          (void)group_scheduler_transition_locked(
              eid, GROUP_SCHED_RUNNABLE, "resume_enter_rollback");
      }
    }
    spin_unlock(&encl_lock);
    return active_ret;
  }

  // Enclave is OK to resume, context switch to it
  active_ret = context_switch_to_enclave(regs, eid, 0);
  if (active_ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
    group_context_switch_fail_rollback(eid, 0);

  return active_ret;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid)
{
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  sbi_memset(&report, 0, sizeof(report));
  spin_lock(&encl_lock);
  attestable = (ENCLAVE_EXISTS(eid)
                && (enclaves[eid].state >= FRESH));

  if(!attestable) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
      data, size);
  report.enclave.data_len = size;
  report.enclave.report_version = 1;
  report.enclave.security_policy_version =
      KEYSTONE_GROUP_SECURITY_POLICY_VERSION;
  sbi_memcpy(report.enclave.runtime_hash,
             enclaves[eid].runtime_hash,
             MDSIZE);

  if (enclaves[eid].group_id != 0) {
    struct enabled_group_slot* group =
        find_group_locked(enclaves[eid].group_id);
    struct group_member_descriptor* member =
        group_member_find_locked(group, eid);
    if (group && member) {
      report.enclave.security_policy_version =
          group->security_policy_version;
      report.enclave.group_id = group->group_id;
      report.enclave.group_generation = group->generation;
      report.enclave.group_role = member->role;
      report.enclave.group_hart_mask = group->configured_hart_mask;
      report.enclave.bound_hart = member->bound_hart;
      report.enclave.allowed_slice_mask = member->allowed_slice_mask;
      report.enclave.membership_epoch = member->membership_epoch;
      report.enclave.phase_epoch = group->yxstm_phase_epoch;
      report.enclave.session_epoch = group->session_epoch;
      sbi_memcpy(report.enclave.group_session_hash,
                 group->session_hash,
                 MDSIZE);
    }
  }

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  spin_unlock(&encl_lock); // Don't need to wait while signing, which might take some time

  sbi_memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.hash, sm_hash, MDSIZE);
  sbi_memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  spin_lock(&encl_lock);

  /* copy report to the enclave */
  ret = copy_enclave_report(&enclaves[eid],
      report_ptr,
      &report);

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                                 size_t key_ident_size, enclave_id eid)
{
  struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
  int ret;

  /* derive key */
  ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                              (const unsigned char *)key_ident, key_ident_size,
                              (const unsigned char *)enclaves[eid].hash);
  if (ret)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  /* sign derived key */
  sm_sign((void *)key_struct->signature, (void *)key_struct->key,
          SEALING_KEY_SIZE);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

// 创建从属 enclave 组的函数
unsigned long m_enclave_create_group(uintptr_t identity, uintptr_t size, enclave_id eid) {
  sbi_printf("sm testing %s 1 \n", __func__);
  spin_lock(&encl_lock);
  
  m_enclave* m = &enclaves[eid].m; // 获取指定 enclave 的 m_enclave
  char tempidentity[64+4];
  if (copy_enclave_data(&enclaves[eid], (void*)tempidentity, identity, size)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }
  // 查找未创建的组
  for (int i = 0; i < MAX_MS_GROUP; i++) {
    // sbi_printf("sm testing %s \n", __func__);
    if (ms_group_list[i].isCreated == 0) { // 查找未创建的组
      // sbi_printf("sm testing %s 2 ,size %ld\n", __func__, size);
      // // sbi_memcpy(ms_group_list[i].identity, (char*)identity, size); // 复制身份信息
      // ret = copy_enclave_data(&enclaves[eid], (void*)ms_group_list[i].identity, identity, size); // 复制身份信息
      // if (copy_enclave_data(&enclaves[eid], (void*)ms_group_list[i].identity, identity, size)) { // 复制身份信息
      //   spin_unlock(&encl_lock);
      //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
      // }
      sbi_memcpy(ms_group_list[i].identity, tempidentity, size); // 复制身份信息
      // sbi_printf("sm testing %s 3 id: %s\n", __func__, ms_group_list[i].identity);
      ms_group_list[i].m = m; // 关联 m_enclave
      // sbi_printf("sm testing %s 4 \n", __func__);
      ms_group_list[i].isCreated = 1; // 标记为已创建
      spin_unlock(&encl_lock);
      return SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功
    } else if(ms_group_list[i].isCreated == 1) {
      // 检查组是否已创建 
      // char temp[64+4];
      // if (copy_enclave_data(&enclaves[eid], (void*)temp, identity, size)) { // 复制身份信息
      //   spin_unlock(&encl_lock);
      //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
      // }
      // if (sbi_memcmp(ms_group_list[i].identity, temp, size) == 0) {
      //   spin_unlock(&encl_lock);
      //   return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
      // }

      // if (sbi_memcmp(ms_group_list[i].identity, (char*)identity, size) == 0) {
      //   spin_unlock(&encl_lock);
      //   return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
      // }
      if (sbi_memcmp(ms_group_list[i].identity, tempidentity, size) == 0) {
        spin_unlock(&encl_lock);
        return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
      }
    }
  }
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
}

// 加入从属 enclave 组的函数
unsigned long s_enclave_join_group(uintptr_t identity, uintptr_t size, enclave_id eid) {
  int ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  sbi_printf("sm testing %s\n", __func__);
  spin_lock(&encl_lock);

  char tempidentity[64+4];
  if (copy_enclave_data(&enclaves[eid], (void*)tempidentity, identity, size)) { // 复制身份信息
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err;
  }

  m_enclave* m = NULL; // 初始化 m_enclave 指针
  s_enclave* s = &enclaves[eid].s; // 获取指定 enclave 的 s_enclave
  s->s_id = eid;
  for (int i = 0; i < MAX_MS_GROUP; i++) {
    if (ms_group_list[i].isCreated == 1) { // 检查组是否已创建
      if (sbi_memcmp(ms_group_list[i].identity, tempidentity, size) == 0) { // 匹配身份
        m = ms_group_list[i].m; // 获取 m_enclave
        if (m->slave_numbers < MAX_SLAVE_ENCLAVES) { // 确保不超过最大从属数量
          m->slave_enclave[m->slave_numbers++] = s; // 将 s_enclave 添加到从属数组
          ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功
        } else {
          ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
          goto err;
        }
        break;
      }
    }
  }

err:
  spin_unlock(&encl_lock);
  return ret;
}

// 查找从属 enclave 组的函数
unsigned long s_enclave_find_group(uintptr_t identity, uintptr_t size) {
  for (int i = 0; i < MAX_MS_GROUP; i++) {
    if (ms_group_list[i].isCreated == 1 && sbi_memcmp(ms_group_list[i].identity, (char*)identity, size) == 0) {
      return i; // 返回找到的组索引
    }
  }
  return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
}

// 检查从属 enclave 数据的函数
static int check_m_get_data(m_enclave* m, uint64_t numbers, uint64_t state, uint64_t size, uint64_t s_id) {
  sbi_printf("sm testing %s  1\n", __func__);
  sbi_printf("sm testing %s  s_number=%ld, number=%ld\n", __func__, m->slave_enclave[s_id]->numbers, numbers);
  sbi_printf("sm testing %s  s_state=%ld, state=%ld\n", __func__, m->slave_enclave[s_id]->state, state);
  sbi_printf("sm testing %s  s_size=%ld, size=%ld\n", __func__, m->slave_enclave[s_id]->size, size);
  if (m->slave_enclave[s_id]->numbers == numbers && 
      m->slave_enclave[s_id]->size <= size) {
    return SBI_ERR_SM_ENCLAVE_SUCCESS; // 数据有效
  }
  return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 数据无效
}

static unsigned long copy_sm_to_enclave(struct enclave* enclave,
  uintptr_t dest, void* source, size_t size) {

  int illegal = copy_from_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long copy_slave_enclave_data(struct enclave* enclave,
                                          uintptr_t dest, uintptr_t source, size_t size) {

  sbi_printf("sm testing %s, in 1\n", __func__);
  int illegal = copy_s_to_m(dest, source, size);
  sbi_printf("sm testing %s, in 2\n", __func__);
  if(illegal)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

// 获取从属 enclave 数据的函数
unsigned long main_enclave_get_slave_enclave_data_yx(uintptr_t temp_ptr, uintptr_t dest_ptr, enclave_id eid) {
  int ret;

  unsigned char temp[17] = {0};
  unsigned long *temp_nothing = (unsigned long *)temp;
  unsigned long *temp_size = (unsigned long *)(temp+8);
  unsigned char *temp_state = temp+16;

  // unsigned char yxtest = 67;
  spin_lock(&encl_lock);

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  1\n", __func__, eid, yxtest);

  // if (copy_enclave_data(&enclaves[eid], (void*)&yxtest, dest, 1)) { // 复制身份信息
  //   spin_unlock(&encl_lock);
  //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  // }

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  2\n", __func__, eid, yxtest);

  // yxtest = 65;

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  3\n", __func__, eid, yxtest);

  // if (copy_sm_to_enclave(&enclaves[eid], dest, (void*)&yxtest, 1)) { // 复制身份信息
  //   spin_unlock(&encl_lock);
  //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  // }

  // yxtest = 66;

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  4\n", __func__, eid, yxtest);

  // if (copy_enclave_data(&enclaves[eid], (void*)&yxtest, dest, 1)) { // 复制身份信息
  //   spin_unlock(&encl_lock);
  //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  // }

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  5\n", __func__, eid, yxtest);

  if (copy_enclave_data(&enclaves[eid], (void*)temp, temp_ptr, 17)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  m_enclave* m = &enclaves[eid].m;
  uint64_t s_id = (*temp_nothing) % (m->slave_numbers + 1); // 选择从属 enclave
  sbi_printf("sm testing %s  check_m_get_data 1, sid=%ld, numbers=%ld, m->slave_numbers=%ld, size=%ld\n", __func__, s_id, *temp_nothing, m->slave_numbers, *temp_size);
  if (m->slave_enclave[s_id - 1]->state == 0) {
    // spin_unlock(&encl_lock);
    sbi_printf("sm testing %s  slave_state=%lu, whiling...\n", __func__, m->slave_enclave[s_id - 1]->state);
    *temp_state = 0;
    if (copy_sm_to_enclave(&enclaves[eid], temp_ptr, (void*)temp, 17)) {
      ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回等待
      goto err;
    }
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回等待
    goto err;
    sbi_printf("sm testing %s, waiting spin_lock\n", __func__);
    // spin_lock(&encl_lock);
    sbi_printf("sm testing %s  slave_state=%lu\n", __func__, m->slave_enclave[s_id - 1]->state);
  }
  ret = check_m_get_data(m, *temp_nothing, m->slave_enclave[s_id - 1]->state, *temp_size, s_id - 1); // 检查数据

  // sbi_printf("sm testing %s, copy_slave_enclave_data 2, ret=%d\n", __func__, ret);
  // if (ret) {
  //   ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
  //   goto err;
  // }
  
  sbi_printf("sm testing %s, copy_slave_enclave_data 1\n", __func__);
  *temp_nothing = m->slave_enclave[s_id - 1]->numbers;
  *temp_size = m->slave_enclave[s_id - 1]->size;
  *temp_state = 1;
  ret = copy_sm_to_enclave(&enclaves[eid], temp_ptr, (void*)temp, 17); // 复制
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }
  sbi_printf("sm testing %s, copy_slave_enclave_data 2\n", __func__);

  ret = copy_slave_enclave_data(&enclaves[eid], dest_ptr, m->slave_enclave[s_id - 1]->data_ptr, m->slave_enclave[s_id - 1]->size); // 复制数据
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }

  sbi_printf("sm testing %s, copy_slave_enclave_data done\n", __func__);
  
  m->slave_enclave[s_id - 1]->state = 0; // 重置状态
  
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功

err:  
  spin_unlock(&encl_lock);
  return ret;
}

// 设置从属 enclave 数据指针的函数
unsigned long slave_enclave_set_dataptr_yx(uintptr_t temp_ptr, uintptr_t data_ptr, enclave_id eid) {
  int ret;

  unsigned char temp[17] = {0};
  unsigned long *temp_nothing = (unsigned long *)temp;
  unsigned long *temp_size = (unsigned long *)(temp+8);
  unsigned char *temp_state = temp+16;

  spin_lock(&encl_lock);

  if (copy_enclave_data(&enclaves[eid], (void*)temp, temp_ptr, 17)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  sbi_printf("sm testing %s\n", __func__);
  s_enclave* s = &enclaves[eid].s; // 获取指定 enclave 的 s_enclave
  if (s->state == 0) { // 检查状态
    s->data_ptr = data_ptr; // 设置数据指针
    s->size = *temp_size; // 设置数据大小
    s->numbers = *temp_nothing; // 设置数量
    s->state = 1; // 更新状态
    *temp_state = 0;
  } else {
    *temp_state = 1;
  }

  if (copy_sm_to_enclave(&enclaves[eid], temp_ptr, (void*)temp, 17) ) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回等待
    goto err;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功

  sbi_printf("sm testing %s, slave_eid=%ud, state=%lu, numbers=%lu, size=%lu, *temp_state=%02x \n", __func__, eid, s->state, *temp_nothing, *temp_size, *temp_state);

err:
  spin_unlock(&encl_lock);
  return ret;
}

// 获取从属 enclave 数据的函数
unsigned long main_enclave_get_slave_enclave_data(uintptr_t dest, uintptr_t size, uintptr_t numbers, enclave_id eid) {
  int ret;

  // sbi_printf("\t\t yx sm copy s to m testing %s main_eid=%ud 1\n", __func__, eid);
  // while(1){

  // }
  unsigned char tz = 11;
  unsigned char tz1 = 1;
  unsigned char yxtest = 67;
  spin_lock(&encl_lock);

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  1\n", __func__, eid, yxtest);

  if (copy_enclave_data(&enclaves[eid], (void*)&yxtest, dest, 1)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  2\n", __func__, eid, yxtest);

  yxtest = 65;

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  3\n", __func__, eid, yxtest);

  if (copy_sm_to_enclave(&enclaves[eid], dest, (void*)&yxtest, 1)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  yxtest = 66;

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  4\n", __func__, eid, yxtest);

  if (copy_enclave_data(&enclaves[eid], (void*)&yxtest, dest, 1)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  5\n", __func__, eid, yxtest);

  m_enclave* m = &enclaves[eid].m;
  uint64_t s_id = numbers % (m->slave_numbers + 1); // 选择从属 enclave
  sbi_printf("sm testing %s  check_m_get_data 1, sid=%ld, numbers=%ld, m->slave_numbers=%ld, size=%ld\n", __func__, s_id, numbers, m->slave_numbers, size);
  if (m->slave_enclave[s_id - 1]->state == 0) {
    // spin_unlock(&encl_lock);
    sbi_printf("sm testing %s  slave_state=%lu, whiling...\n", __func__, m->slave_enclave[s_id - 1]->state);
    ret = copy_sm_to_enclave(&enclaves[eid], dest, (void*)&tz1, 1); // 复制
    if (ret) {
      ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回等待
      goto err;
    }
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回等待
    goto err;
    sbi_printf("sm testing %s, waiting spin_lock\n", __func__);
    // spin_lock(&encl_lock);
    sbi_printf("sm testing %s  slave_state=%lu\n", __func__, m->slave_enclave[s_id - 1]->state);
  }
  ret = check_m_get_data(m, numbers, m->slave_enclave[s_id - 1]->state, size, s_id - 1); // 检查数据

  // sbi_printf("sm testing %s, copy_slave_enclave_data 2, ret=%d\n", __func__, ret);
  // if (ret) {
  //   ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
  //   goto err;
  // }
  
  sbi_printf("sm testing %s, copy_slave_enclave_data 1\n", __func__);
  ret = copy_sm_to_enclave(&enclaves[eid], dest+1, (void*)&m->slave_enclave[s_id - 1]->numbers, 8); // 复制number
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }

  sbi_printf("sm testing %s, copy_slave_enclave_data 2\n", __func__);
  ret = copy_sm_to_enclave(&enclaves[eid], dest+9, (void*)&m->slave_enclave[s_id - 1]->size, 8); // 复制size
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }

  sbi_printf("sm testing %s, copy_slave_enclave_data 3\n", __func__);
  ret = copy_slave_enclave_data(&enclaves[eid], dest+17, m->slave_enclave[s_id - 1]->data_ptr, size); // 复制数据
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }

  sbi_printf("sm testing %s, copy_slave_enclave_data done\n", __func__);
  
  m->slave_enclave[s_id - 1]->state = 0; // 重置状态
  ret = copy_sm_to_enclave(&enclaves[eid], dest, (void*)&tz, 1); // 复制

  ret = copy_sm_to_enclave(&enclaves[m->slave_enclave[s_id - 1]->s_id], m->slave_enclave[s_id - 1]->data_ptr-17, (void*)&tz1, 1);
  sbi_printf("sm testing %s, set copy_slave_enclave_data ready\n", __func__);
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }
  
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功

err:  
  spin_unlock(&encl_lock);
  return ret;
}

// 设置从属 enclave 数据指针的函数
unsigned long slave_enclave_set_dataptr(uintptr_t src, uintptr_t size, uintptr_t numbers, enclave_id eid) {
  int ret;
  spin_lock(&encl_lock);

  sbi_printf("sm testing %s\n", __func__);
  s_enclave* s = &enclaves[eid].s; // 获取指定 enclave 的 s_enclave
  if (s->state == 0) { // 检查状态
    s->data_ptr = src; // 设置数据指针
    s->size = size; // 设置数据大小
    s->numbers = numbers; // 设置数量
    s->state = 1; // 更新状态
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功
  } else {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
    goto err;
  }

  sbi_printf("sm testing %s, slave_eid=%ud, state=%lu, numbers=%lu, size=%lu, ret=%d \n", __func__, eid, s->state, numbers, size, ret);

err:
  spin_unlock(&encl_lock);
  return ret;
}


unsigned long slave_enclave_set_numberblock_set_pmp(enclave_id eid){
  (void)eid;
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

unsigned long main_enclave_get_numberblock_set_pmp(enclave_id eid) {
  (void)eid;
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

unsigned long other_enclave_access_stm_test_set_pmp(enclave_id eid){
  (void)eid;
  return SBI_ERR_SM_NOT_IMPLEMENTED;
}

unsigned long s_enclave_attested(enclave_id eid, uintptr_t report, uintptr_t nonce, uintptr_t kg) {

  struct s_attested_report s_report;
  unsigned char s_kg[64];
  int ret;

  ret = copy_enclave_data(&enclaves[eid], s_kg, kg, 64);
  if (ret) {
    return ret;
  }

  s_report.seq = eid;
  s_report.nonce = nonce;
  sbi_memcpy(s_report.s_hash, enclaves[eid].hash, 64);

  generate_s_attested_hash(&s_report, s_kg);

  sm_sign(s_report.signature, &s_report, sizeof(struct s_attested_report) - 64);
  
  ret = copy_from_sm(report, &s_report, sizeof(struct s_attested_report));

  if (ret) {
    return ret;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  return ret;
}

unsigned long m_enclave_attest_s_enclave(enclave_id eid, uintptr_t report, uintptr_t kg, uintptr_t flag) {
  // sbi_printf("func:%s, slave kg and hmac attest start\n", __func__);
  struct s_attested_report s_report;
  unsigned char m_kg[64];
  unsigned char s_hmac[64];
  int ret;
  uint64_t _flag = 0;

  ret = copy_enclave_data(&enclaves[eid], &s_report, report, sizeof(struct s_attested_report));
  if (ret) {
    return ret;
  }

  if (!sm_verify(s_report.signature, &s_report, sizeof(struct s_attested_report) - 64)) {
    _flag = 0;
    ret = copy_from_sm(flag, &_flag, sizeof(_flag));
    if (ret) {
      return ret;
    }
    return 1;
  }

  ret = copy_enclave_data(&enclaves[eid], m_kg, kg, 64);
  if (ret) {
    return ret;
  }

  // 提前备份s的hmac
  sbi_memcpy(s_hmac, s_report.hmac, 64);

  // 使用m_kg重新计算hmac
  generate_s_attested_hash(&s_report, m_kg);

  ret = sbi_memcmp(s_report.hmac, s_hmac, 64);
  if (ret) {
    return ret;
  }

  _flag = 1;
  ret = copy_from_sm(flag, &_flag, sizeof(_flag));
  if (ret) {
    return ret;
  }

  // sbi_printf("func:%s, slave kg and hmac attest match\n", __func__);

  return 0;

}
