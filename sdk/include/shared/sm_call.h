#ifndef __SM_CALL_H__
#define __SM_CALL_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

// BKE (Berkeley Keystone Enclave)
#define SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE 0x08424b45

#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1
#define SBI_CONSOLE_GETCHAR 2

/* 0-1999 are not used (deprecated) */
#define FID_RANGE_DEPRECATED      1999
/* 2000-2999 are called by host */
#define SBI_SM_CREATE_ENCLAVE    2001
#define SBI_SM_DESTROY_ENCLAVE   2002
#define SBI_SM_RUN_ENCLAVE       2003
#define SBI_SM_RESUME_ENCLAVE    2005
#define SBI_SM_GROUP_SET_COUNT   2006
#define SBI_SM_GROUP_SET_HART_COUNT 2007
#define SBI_SM_GROUP_QUERY       2008
#define SBI_SM_GROUP_BIND_ENCLAVE 2009
#define SBI_SM_GROUP_ENQUEUE_ENCLAVE 2010
#define SBI_SM_GROUP_POLL_BLOCKED_OCALL 2011
#define SBI_SM_GROUP_RUN_HART    2012
#define SBI_SM_GROUP_RESUME_BLOCKED_OCALL 2013
#define SBI_SM_GROUP_CREATE      2014
#define SBI_SM_GROUP_ACTIVATE    2015
#define SBI_SM_GROUP_DESTROY     2016
#define SBI_SM_GROUP_CONTROL_ENCLAVE 2017
#define SBI_SM_GROUP_TEST_SNAPSHOT 2018
#define SBI_SM_GROUP_TEST_INJECT   2019
#define SBI_SM_GROUP_PERF_QUERY    2020
#define SBI_SM_GROUP_CONFIG_TOPOLOGY 2021
#define SBI_SM_GROUP_QUERY_TOPOLOGY  2022
#define SBI_SM_GROUP_SET_LEASE_STATE 2023
#define SBI_SM_GROUP_RUN_MASTER      2024
#define SBI_SM_GROUP_PAUSE_MASTER    2025
#define SBI_SM_GROUP_HOST_HEARTBEAT_ACK 2026
#define FID_RANGE_HOST           2999

/* 3000-3999 are called by enclave */
#define SBI_SM_RANDOM            3001
#define SBI_SM_ATTEST_ENCLAVE    3002
#define SBI_SM_GET_SEALING_KEY   3003
#define SBI_SM_STOP_ENCLAVE      3004
#define SBI_SM_EXIT_ENCLAVE      3006
#define SBI_SM_MAIN_ENCLAVE_GET_SLAVE_ENCLAVE_DATA 3007
#define SBI_SM_SLAVE_ENCLAVE_SET_DATAPTR           3008
#define SBI_SM_M_ENCLAVE_CREATE_GROUP              3009
#define SBI_SM_S_ENCLAVE_JOIN_GROUP                3010
#define SBI_SM_M_ENCLAVE_YXSTM_GET_NUMBERBLOCK_PMP 3011
#define SBI_SM_S_ENCLAVE_YXSTM_SET_NUMBERBLOCK_PMP 3012
#define SBI_SM_O_ENCLAVE_ACCESS_STM_TEST_SET_PMP   3013
#define SBI_SM_S_ENCLAVE_ATTESTED                  3014
#define SBI_SM_M_ENCLAVE_ATTEST_S_ENCLAVE          3015
#define SBI_SM_SEC_ACQUIRE                         3016
#define SBI_SM_SEC_RELEASE                         3017
#define SBI_SM_SEC_QUERY                           3018
#define SBI_SM_GROUP_VALIDATE_PAGE_TABLE           3019
#define SBI_SM_YXSTM_QUERY_LAYOUT                  3024
#define SBI_SM_YXSTM_ACQUIRE_SLICE                 3025
#define SBI_SM_YXSTM_RELEASE_SLICE                 3026
#define SBI_SM_YXSTM_ACQUIRE_MASK                  3027
#define SBI_SM_YXSTM_RELEASE_MASK                  3028
#define SBI_SM_YXSTM_QUERY_PROTOCOL                3029
#define SBI_SM_YXSTM_PHASE_TRANSITION              3030
#define SBI_SM_YXSTM_PHASE_ACK                     3031
#define SBI_SM_YXSTM_REGISTER_MAILBOX               3032
#define SBI_SM_YXSTM_TASK_BANK_TRANSITION            3033
#define SBI_SM_YXSTM_TASK_BANK_ACQUIRE               3034
#define SBI_SM_YXSTM_TASK_BANK_RELEASE               3035
#define SBI_SM_YXSTM_TASK_BANK_ACK                   3036
#define SBI_SM_GROUP_LANE_TURN                       3037
#define SBI_SM_YXSTM_QUERY_SLOT                      3038
#define SBI_SM_YXSTM_SLOT_COMMAND                    3039
#define FID_RANGE_ENCLAVE        3999

/* 4000-4999 are experimental */
#define SBI_SM_CALL_PLUGIN        4000
#define FID_RANGE_CUSTOM          4999

/* Plugin IDs and Call IDs */
#define SM_MULTIMEM_PLUGIN_ID   0x01
#define SM_MULTIMEM_CALL_GET_SIZE 0x01
#define SM_MULTIMEM_CALL_GET_ADDR 0x02

/* Enclave stop reasons requested */
#define STOP_TIMER_INTERRUPT  0
#define STOP_EDGE_CALL_HOST   1
#define STOP_EXIT_ENCLAVE     2
#define STOP_YIELD_ENCLAVE    3
#define STOP_LANE_WAIT_ENCLAVE 4

#define KEYSTONE_ABI_VERSION                 20UL
#define KEYSTONE_GROUP_ABI_MARKER            "keystone-group-abi-v20"
#define KEYSTONE_ABI_WORD_SIZE               ((uintptr_t)sizeof(uintptr_t))
#define KEYSTONE_ABI_ALIGN                   ((uintptr_t)sizeof(uintptr_t))
#define KEYSTONE_ABI_FEATURE_GROUP_PMP       (1UL << 0)
#define KEYSTONE_ABI_FEATURE_YXSTM_SLICE     (1UL << 1)
#define KEYSTONE_ABI_FEATURE_YXSTM_PROTOCOL  (1UL << 2)
#define KEYSTONE_ABI_FEATURE_GROUP_EVENTS    (1UL << 3)
#define KEYSTONE_ABI_FEATURE_HOST_CONTROL    (1UL << 4)
#define KEYSTONE_ABI_FEATURE_OCALL_LIFECYCLE (1UL << 5)
#define KEYSTONE_ABI_FEATURE_GROUP_SECURITY  (1UL << 6)
#define KEYSTONE_ABI_FEATURE_GROUP_TEST      (1UL << 7)
#define KEYSTONE_ABI_FEATURE_GROUP_PERF      (1UL << 8)
#define KEYSTONE_ABI_FEATURE_YXSTM_MAILBOX   (1UL << 9)
#define KEYSTONE_ABI_FEATURE_GROUP_TOPOLOGY  (1UL << 10)
#define KEYSTONE_ABI_FEATURE_WORKER_LEASE    (1UL << 11)
#define KEYSTONE_ABI_FEATURE_MASTER_HOST     (1UL << 12)
#define KEYSTONE_ABI_FEATURE_SCHED_QOS       (1UL << 13)
#define KEYSTONE_ABI_FEATURE_HOST_HEARTBEAT  (1UL << 14)
#define KEYSTONE_ABI_FEATURE_STANDARD_ERROR  (1UL << 15)
#define KEYSTONE_ABI_FEATURE_TASK_SCHEDULER  (1UL << 16)
#define KEYSTONE_ABI_FEATURE_YXSTM_BANKS     (1UL << 17)
#define KEYSTONE_ABI_FEATURE_DYNAMIC_GROUP_METADATA (1UL << 18)
#define KEYSTONE_ABI_FEATURE_EXCLUSIVE_LEASE (1UL << 19)
#define KEYSTONE_ABI_FEATURE_HSM_CPU_LEASE   (1UL << 20)
#define KEYSTONE_ABI_FEATURE_LANE_STREAM_WAIT (1UL << 21)
#define KEYSTONE_ABI_FEATURE_CFS_LITE        (1UL << 22)
#define KEYSTONE_ABI_FEATURE_GROUP_PERF_WINDOW (1UL << 23)
#define KEYSTONE_ABI_FEATURE_ADAPTIVE_CFS    (1UL << 24)
#define KEYSTONE_ABI_FEATURE_DIRTY_SCRUB     (1UL << 25)
#define KEYSTONE_ABI_FEATURE_YXSTM_DYNAMIC_SLOTS (1UL << 26)
#define KEYSTONE_ABI_FEATURE_YXSTM_SLOT_PIPELINE (1UL << 27)
#define KEYSTONE_ABI_FEATURE_YXSTM_MAPPING_DIAGNOSTICS (1UL << 28)
#define KEYSTONE_GROUP_ABI_FEATURES \
  (KEYSTONE_ABI_FEATURE_GROUP_PMP | \
   KEYSTONE_ABI_FEATURE_GROUP_EVENTS | \
   KEYSTONE_ABI_FEATURE_HOST_CONTROL | \
   KEYSTONE_ABI_FEATURE_OCALL_LIFECYCLE | \
   KEYSTONE_ABI_FEATURE_GROUP_SECURITY | \
   KEYSTONE_ABI_FEATURE_GROUP_TOPOLOGY | \
   KEYSTONE_ABI_FEATURE_WORKER_LEASE | \
   KEYSTONE_ABI_FEATURE_MASTER_HOST | \
   KEYSTONE_ABI_FEATURE_SCHED_QOS | \
   KEYSTONE_ABI_FEATURE_HOST_HEARTBEAT | \
   KEYSTONE_ABI_FEATURE_STANDARD_ERROR | \
   KEYSTONE_ABI_FEATURE_TASK_SCHEDULER | \
   KEYSTONE_ABI_FEATURE_YXSTM_BANKS | \
   KEYSTONE_ABI_FEATURE_DYNAMIC_GROUP_METADATA | \
   KEYSTONE_ABI_FEATURE_EXCLUSIVE_LEASE | \
  KEYSTONE_ABI_FEATURE_HSM_CPU_LEASE | \
  KEYSTONE_ABI_FEATURE_LANE_STREAM_WAIT | \
  KEYSTONE_ABI_FEATURE_CFS_LITE | \
  KEYSTONE_ABI_FEATURE_ADAPTIVE_CFS | \
  KEYSTONE_ABI_FEATURE_DIRTY_SCRUB | \
  KEYSTONE_ABI_FEATURE_YXSTM_DYNAMIC_SLOTS | \
  KEYSTONE_ABI_FEATURE_YXSTM_SLOT_PIPELINE | \
  KEYSTONE_ABI_FEATURE_YXSTM_MAPPING_DIAGNOSTICS)
#define KEYSTONE_YXSTM_ABI_FEATURES \
  (KEYSTONE_ABI_FEATURE_GROUP_PMP | \
   KEYSTONE_ABI_FEATURE_YXSTM_SLICE | \
   KEYSTONE_ABI_FEATURE_YXSTM_PROTOCOL | \
   KEYSTONE_ABI_FEATURE_YXSTM_MAILBOX | \
   KEYSTONE_ABI_FEATURE_GROUP_SECURITY | \
   KEYSTONE_ABI_FEATURE_TASK_SCHEDULER | \
   KEYSTONE_ABI_FEATURE_YXSTM_BANKS | \
   KEYSTONE_ABI_FEATURE_LANE_STREAM_WAIT | \
   KEYSTONE_ABI_FEATURE_YXSTM_DYNAMIC_SLOTS | \
   KEYSTONE_ABI_FEATURE_YXSTM_SLOT_PIPELINE | \
   KEYSTONE_ABI_FEATURE_YXSTM_MAPPING_DIAGNOSTICS)
#define KEYSTONE_GROUP_TEST_ABI_FEATURES \
  (KEYSTONE_GROUP_ABI_FEATURES | KEYSTONE_ABI_FEATURE_GROUP_TEST)
#define KEYSTONE_GROUP_PERF_ABI_FEATURES \
  (KEYSTONE_GROUP_ABI_FEATURES | KEYSTONE_ABI_FEATURE_GROUP_PERF | \
   KEYSTONE_ABI_FEATURE_GROUP_PERF_WINDOW)

struct keystone_abi_header {
  uintptr_t version;
  uintptr_t struct_size;
  uintptr_t features;
  uintptr_t status;
  uintptr_t detail;
  uintptr_t reserved;
};

#define KEYSTONE_ABI_INIT(obj, feature_mask) do { \
  (obj)->abi.version = KEYSTONE_ABI_VERSION; \
  (obj)->abi.struct_size = sizeof(*(obj)); \
  (obj)->abi.features = (feature_mask); \
  (obj)->abi.status = 0; \
  (obj)->abi.detail = 0; \
  (obj)->abi.reserved = 0; \
} while (0)

struct keystone_sec_query {
  uintptr_t sec_base;
  uintptr_t sec_size;
  uintptr_t sec_flags;
  uintptr_t sec_engine_id;
  uintptr_t owner_eid;
  uintptr_t configured;
  uintptr_t owned_by_caller;
  uintptr_t busy;
};

struct keystone_group_config {
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

#define GROUP_MODE_INVALID          0
#define GROUP_MODE_3W_1HM           1
#define GROUP_MODE_SATURATION_TEST  2

#define KEYSTONE_GROUP_TOPOLOGY_FLAG_EXPLICIT_CPU_HART_MAP (1UL << 0)
#define KEYSTONE_GROUP_TOPOLOGY_FLAG_REQUIRE_ISOLATION      (1UL << 1)

#define KEYSTONE_GROUP_LEASE_FREE       0
#define KEYSTONE_GROUP_LEASE_DRAINING   1
#define KEYSTONE_GROUP_LEASE_LEASED     2
#define KEYSTONE_GROUP_LEASE_RELEASING  3
#define KEYSTONE_GROUP_LEASE_FAILED     4

#define KEYSTONE_GROUP_LEASE_FLAG_REQUIRE_ISOLATION (1UL << 0)
#define KEYSTONE_GROUP_LEASE_FLAG_TEST_FALLBACK     (1UL << 1)
#define KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT    (1UL << 2)
#define KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE        (1UL << 3)
#define KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE         (1UL << 4)

/* VisionFive2 exposes Linux CPU0 as SM hart1. Keep this mapping explicit. */
#define KEYSTONE_VF2_HOUSEKEEPING_CPU 0UL
#define KEYSTONE_VF2_HOUSEKEEPING_HART 1UL
#define KEYSTONE_VF2_CPU_HART_OFFSET 1UL
#define KEYSTONE_VF2_WORKER_HART_MASK \
  ((1UL << 2) | (1UL << 3) | (1UL << 4))

struct keystone_group_topology {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t execution_mode;
  uintptr_t housekeeping_cpu;
  uintptr_t housekeeping_hart;
  uintptr_t master_hart;
  uintptr_t worker_hart_mask;
  uintptr_t worker_count;
  uintptr_t configured_hart_mask;
  uintptr_t cpu_hart_offset;
  uintptr_t lease_state;
  uintptr_t flags;
  uintptr_t status;
  uintptr_t topology_epoch;
};

struct keystone_group_lease {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t worker_hart_mask;
  uintptr_t lease_state;
  uintptr_t flags;
  uintptr_t status;
  uintptr_t lease_epoch;
};

#define KEYSTONE_GROUP_STATE_FREE         0
#define KEYSTONE_GROUP_STATE_CONFIGURING  1
#define KEYSTONE_GROUP_STATE_READY        2
#define KEYSTONE_GROUP_STATE_ACTIVE       3
#define KEYSTONE_GROUP_STATE_DRAINING     4

#define KEYSTONE_GROUP_PT_TRUST_MEASURED_RUNTIME 1
#define KEYSTONE_GROUP_PT_TRUST_SM_MEDIATED      2

struct keystone_group_sched_config {
  struct keystone_abi_header abi;
  uintptr_t eid;
  uintptr_t hart_id;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t eid_generation;
  uintptr_t priority;
  /* CFS-lite minimum-slice multiplier; 1 preserves the default policy. */
  uintptr_t quantum_ticks;
  uintptr_t flags;
  uintptr_t scheduler_epoch;
};

/* Priority 16 is nice-0; larger values receive a larger CFS weight. */
#define KEYSTONE_GROUP_SCHED_PRIORITY_MIN      0UL
#define KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT 16UL
#define KEYSTONE_GROUP_SCHED_PRIORITY_MAX     31UL
#define KEYSTONE_GROUP_SCHED_QUANTUM_DEFAULT   1UL
#define KEYSTONE_GROUP_SCHED_QUANTUM_MAX      64UL
#define KEYSTONE_GROUP_SCHED_POLICY_CFS_LITE   1UL
#define KEYSTONE_GROUP_SCHED_CFS_NICE_0_LOAD   1024UL
#define KEYSTONE_GROUP_SCHED_CFS_LATENCY_US    60000UL
#define KEYSTONE_GROUP_SCHED_CFS_MIN_GRAN_US   12000UL
#define KEYSTONE_GROUP_SCHED_CFS_WAKEUP_GRAN_US 3000UL
#define KEYSTONE_GROUP_SCHED_SWITCH_COST_MULTIPLIER 32UL

#define KEYSTONE_GROUP_OCALL_ANY_HART ((uintptr_t)-1)
#define KEYSTONE_GROUP_OCALL_ACTION_NONE   0
#define KEYSTONE_GROUP_OCALL_ACTION_RESUME 1
#define KEYSTONE_GROUP_OCALL_ACTION_CANCEL 2
#define KEYSTONE_GROUP_OCALL_ACTION_ABANDON 3
#define KEYSTONE_GROUP_OCALL_FLAG_DEFER_HOST_KICK (1UL << 30)

struct keystone_group_ocall_status {
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

#define KEYSTONE_GROUP_EVENT_NONE        0
#define KEYSTONE_GROUP_EVENT_EXIT        1
#define KEYSTONE_GROUP_EVENT_OCALL       2
#define KEYSTONE_GROUP_EVENT_FAULT       3
#define KEYSTONE_GROUP_EVENT_INTERRUPTED 4
#define KEYSTONE_GROUP_EVENT_PAUSED      5
#define KEYSTONE_GROUP_EVENT_CANCELLED   6
#define KEYSTONE_GROUP_EVENT_WATCHDOG    7
#define KEYSTONE_GROUP_EVENT_HOST_INTERRUPT 8
#define KEYSTONE_GROUP_EVENT_WORKERS_READY  9
#define KEYSTONE_GROUP_EVENT_OCALL_ABANDONED 10
#define KEYSTONE_GROUP_EVENT_HEARTBEAT       11

/*
 * A timer-driven group_run_hart return restores a saved Linux trap frame and
 * may be unable to update the original kernel-stack status object afterward.
 * Carry the heartbeat sequence in a1 as a tagged fallback while a0 remains a
 * standard SBI error. The tag makes the value unambiguous from SM detail codes.
 */
#define KEYSTONE_GROUP_DIRECT_SEQUENCE_TAG \
  ((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 1))
#define KEYSTONE_GROUP_DIRECT_SEQUENCE_MASK \
  (~KEYSTONE_GROUP_DIRECT_SEQUENCE_TAG)
#define KEYSTONE_GROUP_DIRECT_SEQUENCE_ENCODE(sequence) \
  (KEYSTONE_GROUP_DIRECT_SEQUENCE_TAG | \
   ((uintptr_t)(sequence) & KEYSTONE_GROUP_DIRECT_SEQUENCE_MASK))
#define KEYSTONE_GROUP_DIRECT_SEQUENCE_VALID(value) \
  ((((uintptr_t)(value)) & KEYSTONE_GROUP_DIRECT_SEQUENCE_TAG) != 0)
#define KEYSTONE_GROUP_DIRECT_SEQUENCE_DECODE(value) \
  (((uintptr_t)(value)) & KEYSTONE_GROUP_DIRECT_SEQUENCE_MASK)

#define KEYSTONE_GROUP_HEARTBEAT_SOURCE_TIMER    (1UL << 0)
#define KEYSTONE_GROUP_HEARTBEAT_SOURCE_SOFTWARE (1UL << 1)
#define KEYSTONE_GROUP_HEARTBEAT_SOURCE_EXTERNAL (1UL << 2)
#define KEYSTONE_GROUP_HEARTBEAT_STATE_IDLE       0
#define KEYSTONE_GROUP_HEARTBEAT_STATE_REQUESTED  1
#define KEYSTONE_GROUP_HEARTBEAT_STATE_ACKED      2
#define KEYSTONE_GROUP_HEARTBEAT_STATE_VERIFIED   3

struct keystone_group_heartbeat {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t hart_id;
  uintptr_t request_sequence;
  uintptr_t ack_sequence;
  uintptr_t pending_sources;
  uintptr_t cleared_sources;
  uintptr_t state;
  uintptr_t flags;
  uintptr_t deadline;
};

#define KEYSTONE_GROUP_CONTROL_PAUSE     1
#define KEYSTONE_GROUP_CONTROL_RESUME    2
#define KEYSTONE_GROUP_CONTROL_CANCEL    3
#define KEYSTONE_GROUP_CONTROL_APPLIED   0
#define KEYSTONE_GROUP_CONTROL_PENDING   1

struct keystone_group_control {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t eid;
  uintptr_t eid_generation;
  uintptr_t action;
  uintptr_t status;
  uintptr_t scheduler_epoch;
};

struct keystone_group_run_hart {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t hart_id;
  uintptr_t eid;
  uintptr_t event;
  uintptr_t error;
  uintptr_t value;
  /*
   * Output: sequence of the event returned by SM.
   * Input: sequence CPU0 has committed before re-entering a worker hart.
   */
  uintptr_t event_sequence;
  uintptr_t scheduler_epoch;
  uintptr_t queue_overflows;
};

#define KEYSTONE_GROUP_EVENT_MASK(event) \
  ((event) < sizeof(uintptr_t) * 8 ? ((uintptr_t)1 << (event)) : 0)

struct keystone_group_wait_event {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t event_mask;
  uintptr_t timeout_ms;
  uintptr_t hart_id;
  uintptr_t eid;
  uintptr_t event;
  uintptr_t error;
  uintptr_t value;
  uintptr_t event_sequence;
  uintptr_t scheduler_epoch;
  uintptr_t queue_overflows;
};

struct keystone_group_test_snapshot {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t live_enclaves;
  uintptr_t live_group_enclaves;
  uintptr_t live_groups;
  uintptr_t live_members;
  uintptr_t pmp_regions;
  uintptr_t active_harts;
  uintptr_t acquired_yxstm_harts;
  uintptr_t runqueue_entries;
  uintptr_t event_queue_entries;
  uintptr_t event_queue_overflows;
  uintptr_t ipi_requests;
  uintptr_t ipi_acks;
  uintptr_t ipi_timeouts;
  uintptr_t coherence_failures;
  uintptr_t member_capacity;
  uintptr_t member_metadata_capacity;
  uintptr_t metadata_bytes;
  uintptr_t metadata_free_bytes;
  uintptr_t running_workers;
  uintptr_t max_running_workers;
  uintptr_t lane_owner_switches;
  uintptr_t lane_scrubs;
  uintptr_t master_non_boundary_entries;
};

#define KEYSTONE_GROUP_TEST_INJECT_NONE             0
#define KEYSTONE_GROUP_TEST_INJECT_DROP_NEXT_IPI    1
#define KEYSTONE_GROUP_TEST_INJECT_FORCE_IPI_TIMEOUT 2
#define KEYSTONE_GROUP_TEST_INJECT_CLEAR            3

struct keystone_group_test_injection {
  struct keystone_abi_header abi;
  uintptr_t operation;
  uintptr_t group_id;
  uintptr_t hart_id;
  uintptr_t eid;
  uintptr_t count;
  uintptr_t flags;
  uintptr_t result;
};

#define KEYSTONE_GROUP_PERF_CYCLE_MCYCLE 1

#define KEYSTONE_GROUP_PERF_QUERY  0
#define KEYSTONE_GROUP_PERF_RESET  1
#define KEYSTONE_GROUP_PERF_BEGIN  2
#define KEYSTONE_GROUP_PERF_FREEZE 3

#define KEYSTONE_GROUP_PERF_WINDOW_IDLE   0
#define KEYSTONE_GROUP_PERF_WINDOW_ACTIVE 1
#define KEYSTONE_GROUP_PERF_WINDOW_FROZEN 2

struct keystone_group_perf_snapshot {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t operation;
  uintptr_t cycle_source;
  uintptr_t acquire_count;
  uintptr_t acquire_cycles;
  uintptr_t release_count;
  uintptr_t release_cycles;
  uintptr_t pmp_update_count;
  uintptr_t pmp_update_cycles;
  uintptr_t context_switch_count;
  uintptr_t context_switch_cycles;
  uintptr_t context_switch_ticks;
  uintptr_t ocall_count;
  uintptr_t ocall_cycles;
  uintptr_t heartbeat_count;
  uintptr_t heartbeat_cycles;
  uintptr_t timer_trap_count;
  uintptr_t timer_trap_cycles;
  uintptr_t ipi_shootdown_count;
  uintptr_t ipi_shootdown_cycles;
  uintptr_t host_service_count;
  uintptr_t host_service_cycles;
  uintptr_t grant_suspend_restore_count;
  uintptr_t grant_suspend_restore_cycles;
  uintptr_t context_gpr_cycles;
  uintptr_t context_smode_csr_cycles;
  uintptr_t context_fp_cycles;
  uintptr_t context_pmp_cycles;
  uintptr_t context_platform_cycles;
  uintptr_t context_scheduler_lock_cycles;
  uintptr_t ocall_handler_count;
  uintptr_t ocall_handler_cycles;
  uintptr_t ocall_wait_count;
  uintptr_t ocall_wait_ticks;
  uintptr_t lane_wait_block_count;
  uintptr_t lane_wait_wake_count;
  uintptr_t lane_wait_ticks;
  uintptr_t cfs_pick_count;
  uintptr_t cfs_preempt_count;
  uintptr_t cfs_runtime_ticks;
  uintptr_t cfs_vruntime_delta;
  uintptr_t cfs_slice_ticks;
  uintptr_t cfs_min_granularity_count;
  uintptr_t cfs_dynamic_min_slice_ticks;
  uintptr_t window_state;
  uintptr_t window_epoch;
  uintptr_t window_start_ticks;
  uintptr_t window_stop_ticks;
  uintptr_t member_query;
  uintptr_t member_eid;
  uintptr_t member_generation;
  uintptr_t member_role;
  uintptr_t member_exec_runtime_ticks;
  uintptr_t member_aes_exec_runtime_ticks;
  uintptr_t worker_exec_runtime_ticks;
  uintptr_t worker_aes_exec_runtime_ticks;
  uintptr_t worker_aes_exec_runtime_min;
  uintptr_t worker_aes_exec_runtime_max;
  uintptr_t worker_runtime_members;
  uintptr_t pmp_grant_suspend_cycles;
  uintptr_t pmp_epm_revoke_cycles;
  uintptr_t pmp_epm_install_cycles;
  uintptr_t pmp_yxstm_restore_cycles;
  uintptr_t pmp_fence_cycles;
  uintptr_t pmp_validation_cycles;
  uintptr_t pmp_lock_wait_cycles;
  uintptr_t scrub_count;
  uintptr_t scrub_bytes;
  uintptr_t scrub_cycles;
};

#define KEYSTONE_YXSTM_PERM_R         0x1
#define KEYSTONE_YXSTM_PERM_W         0x2
#define KEYSTONE_YXSTM_PERM_X         0x4

#define GROUP_ROLE_NONE               0
#define GROUP_ROLE_MASTER             1
#define GROUP_ROLE_WORKER             2
#define GROUP_ROLE_AUXILIARY          3

#define YXSTM_PHASE_IDLE              0
#define YXSTM_PHASE_DISPATCH          1
#define YXSTM_PHASE_COMPUTE           2
#define YXSTM_PHASE_AGGREGATE         3

#define YXSTM_ACK_DISPATCH_READY      1
#define YXSTM_ACK_COMPUTE_DONE        2
#define YXSTM_ACK_AGGREGATE_READY     3
#define YXSTM_ACK_DISPATCH_PUBLISHED  4
#define YXSTM_ACK_COMPUTE_EXEC_BEGIN  5
#define YXSTM_ACK_COMPUTE_EXEC_END    6

#define YXSTM_ROLLBACK_NONE           0
#define YXSTM_ROLLBACK_MASTER_GONE    1
#define YXSTM_ROLLBACK_WORKER_GONE    2
#define YXSTM_ROLLBACK_TIMEOUT         3
#define YXSTM_ROLLBACK_FAULT           4

#define KEYSTONE_YXSTM_CHANNEL_MAGIC   ((uintptr_t)0x595853544d43484eUL)
#define KEYSTONE_YXSTM_CHANNEL_VERSION ((uintptr_t)3)
#define KEYSTONE_YXSTM_MAILBOX_MAGIC    ((uintptr_t)0x59584d41494c424fUL)
#define KEYSTONE_YXSTM_MAILBOX_VERSION  ((uintptr_t)1)
#define KEYSTONE_YXSTM_MAILBOX_PAGE_SIZE ((uintptr_t)4096)
#define KEYSTONE_YXSTM_MAILBOX_FLAG_PERF_QUIET ((uintptr_t)1)
#define KEYSTONE_GROUP_SECURITY_POLICY_VERSION ((uintptr_t)2)

/*
 * Protocol errors are deterministic: stale epoch, phase mismatch, repeated
 * or nested acquire, release without acquire, and incomplete transition map
 * to the corresponding SBI_ERR_SM_YXSTM_* value in sm_err.h. A release mask
 * must exactly match the acquired mask.
 */

#define KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT 4
#define KEYSTONE_YXSTM_MASTER_SLICE_ID     0
#define KEYSTONE_YXSTM_MAX_BANKS           4
#define KEYSTONE_YXSTM_DEFAULT_BANK_COUNT  1
#define KEYSTONE_YXSTM_TASK_BANK_COUNT     2
#define KEYSTONE_YXSTM_STREAM_BANK_COUNT   3
#define KEYSTONE_GROUP_MEMBER_LIMIT        65
#define KEYSTONE_YXSTM_INVALID_BANK        ((uintptr_t)-1)
#define KEYSTONE_YXSTM_INVALID_SLOT         ((uintptr_t)-1)
#define KEYSTONE_YXSTM_WORKER_LANE_COUNT    3
#define KEYSTONE_DECIMAL_MB_BYTES            ((uintptr_t)1000000)
#define KEYSTONE_YXSTM_WORKER_LANE_DATA_SIZE \
  ((uintptr_t)12 * KEYSTONE_DECIMAL_MB_BYTES)
/*
 * Each worker lane carries exactly 12 MB of logical payload. The physical
 * slice remains 16 MiB so page-aligned per-member slots can absorb alignment
 * padding without stealing bytes from the payload contract.
 */
#define KEYSTONE_YXSTM_WORKER_LANE_SIZE      \
  ((uintptr_t)16 * (uintptr_t)1024 * (uintptr_t)1024)
#define KEYSTONE_YXSTM_WORKER_TOTAL_SIZE    \
  (KEYSTONE_YXSTM_WORKER_LANE_COUNT * \
   KEYSTONE_YXSTM_WORKER_LANE_DATA_SIZE)
#define KEYSTONE_YXSTM_WORKER_MAPPED_TOTAL_SIZE \
  (KEYSTONE_YXSTM_WORKER_LANE_COUNT * KEYSTONE_YXSTM_WORKER_LANE_SIZE)
#define KEYSTONE_YXSTM_SLOT_PROTOCOL_METADATA_SIZE ((uintptr_t)0)

static inline uintptr_t
keystone_yxstm_slot_payload_capacity(uintptr_t slot_count)
{
  uintptr_t bytes;

  if (!slot_count)
    return 0;
  bytes = (KEYSTONE_YXSTM_WORKER_LANE_DATA_SIZE + slot_count - 1) /
          slot_count;
  return (bytes + (uintptr_t)15) & ~(uintptr_t)15;
}

static inline uintptr_t
keystone_yxstm_slot_mapping_size(uintptr_t slot_count)
{
  uintptr_t bytes = keystone_yxstm_slot_payload_capacity(slot_count);

  return bytes ? (bytes + (uintptr_t)4095) & ~(uintptr_t)4095 : 0;
}

#define YXSTM_SLOT_FREE                     0
#define YXSTM_SLOT_DISPATCHING              1
#define YXSTM_SLOT_READY                    2
#define YXSTM_SLOT_COMPUTING                3
#define YXSTM_SLOT_DONE                     4
#define YXSTM_SLOT_AGGREGATING              5

#define KEYSTONE_GROUP_TASK_SCHED_FIFO     0
#define KEYSTONE_GROUP_TASK_SCHED_FAIR     1
#define KEYSTONE_GROUP_TASK_SCHED_ROUND_ROBIN 2

#define KEYSTONE_GROUP_TASK_FLAG_BARRIER   (1UL << 0)
#define KEYSTONE_GROUP_TASK_FLAG_RETRYABLE (1UL << 1)
#define KEYSTONE_GROUP_TASK_FLAG_IDEMPOTENT (1UL << 2)
#define KEYSTONE_GROUP_TASK_FLAG_CANCELLED (1UL << 3)
#define KEYSTONE_GROUP_TASK_FLAG_TIMED_OUT (1UL << 4)

#define KEYSTONE_GROUP_TASK_STATE_FREE       0
#define KEYSTONE_GROUP_TASK_STATE_QUEUED     1
#define KEYSTONE_GROUP_TASK_STATE_RUNNING    2
#define KEYSTONE_GROUP_TASK_STATE_SUCCEEDED  3
#define KEYSTONE_GROUP_TASK_STATE_RETRY      4
#define KEYSTONE_GROUP_TASK_STATE_CANCELLED  5
#define KEYSTONE_GROUP_TASK_STATE_FAILED     6
#define KEYSTONE_GROUP_TASK_STATE_STAGED     7

#define KEYSTONE_GROUP_TASK_OPCODE_COPY       1
#define KEYSTONE_GROUP_TASK_OPCODE_AES128_ECB_ENCRYPT 2
#define KEYSTONE_GROUP_TASK_OPCODE_AES128_ECB_DECRYPT 3

/*
 * Canonical enclave virtual address of the YXSTM window. The physical base is
 * group-specific and must never be returned through yxstm_va_base.
 */
#if defined(__riscv_xlen) && (__riscv_xlen == 32)
#define KEYSTONE_YXSTM_ENCLAVE_VA_BASE ((uintptr_t)0xa0000000UL)
#else
#define KEYSTONE_YXSTM_ENCLAVE_VA_BASE ((uintptr_t)0xffffffffa0000000ULL)
#endif

#define KEYSTONE_YXSTM_CACHE_PLATFORM_DEFAULT 1
#define KEYSTONE_YXSTM_TLB_COUNTER_UNAVAILABLE 0

struct keystone_yxstm_layout_info {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t role;
  uintptr_t bound_hart;
  uintptr_t slice_count;
  uintptr_t slice_size;
  uintptr_t allowed_slice_mask;
  uintptr_t master_slice_id;
  uintptr_t worker_slice_id;
  uintptr_t yxstm_va_base; /* canonical enclave VA, never the physical base */
  uintptr_t lane_id;
  uintptr_t task_epoch;
  uintptr_t bank_count;
  uintptr_t bank_size;
  uintptr_t bank_slice_size;
  uintptr_t bank_stride;
  uintptr_t task_queue_capacity;
  uintptr_t worker_lane_count;
  uintptr_t worker_lane_size;
  uintptr_t slot_id;
  uintptr_t slot_count;
  uintptr_t slot_offset;
  uintptr_t slot_size;
  uintptr_t slot_payload_size;
  uintptr_t slot_epoch;
  uintptr_t slot_state;
  uintptr_t lane_reserved_size;
  uintptr_t mapping_pte_flags;
  uintptr_t mapping_leaf_count;
  uintptr_t mapping_min_leaf_size;
  uintptr_t mapping_max_leaf_size;
  uintptr_t mapping_cache_mode;
  uintptr_t mapping_nx;
  uintptr_t mapping_linear;
  uintptr_t mapping_alias_count;
  uintptr_t mapping_page_table_pages;
  uintptr_t mapping_tlb_counter_supported;
  uintptr_t mapping_alignment;
  uintptr_t mapping_hidden_copy_bytes;
};

/*
 * Frozen per-member YXSTM slot. Master may query every worker slot; a worker
 * may query only its own slot. A master request with INVALID_SLOT returns the
 * lane summary in slot_count/slot_size. The master maps the complete 16 MiB
 * physical lane backing, while a worker maps only its owned slot. Exactly
 * 12,000,000 bytes per lane are logical payload; alignment slack is reserved
 * and protocol metadata stays in SM. Physical addresses are omitted.
 */
struct keystone_yxstm_slot_info {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t lane_id;
  uintptr_t slot_id;
  uintptr_t owner_eid;
  uintptr_t slot_count;
  uintptr_t slot_offset;
  uintptr_t slot_size;
  uintptr_t payload_size;
  uintptr_t state;
  uintptr_t batch_id;
  uintptr_t task_id;
  uintptr_t sequence;
  uintptr_t epoch;
  uintptr_t permissions;
  uintptr_t digest;
};

#define KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_ACQUIRE  1
#define KEYSTONE_YXSTM_SLOT_MASTER_DISPATCH_PUBLISH  2
#define KEYSTONE_YXSTM_SLOT_WORKER_WAIT_READY        3
#define KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_ACQUIRE   4
#define KEYSTONE_YXSTM_SLOT_WORKER_COMPUTE_DONE      5
#define KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_ACQUIRE 6
#define KEYSTONE_YXSTM_SLOT_MASTER_AGGREGATE_COMPLETE 7
#define KEYSTONE_YXSTM_SLOT_WORKER_AES_EXEC_BEGIN    8
#define KEYSTONE_YXSTM_SLOT_WORKER_AES_EXEC_END      9
#define KEYSTONE_YXSTM_SLOT_MASTER_FINISH_AND_ACQUIRE 10
#define KEYSTONE_YXSTM_SLOT_WORKER_WAIT_ACQUIRE_BEGIN 11

#define KEYSTONE_YXSTM_SLOT_RESULT_READY 0
#define KEYSTONE_YXSTM_SLOT_RESULT_BLOCK 1

/*
 * Atomic command interface for one frozen worker slot. The caller supplies
 * the expected epoch and task identity on every state-changing operation.
 * A WAIT_READY command may return BLOCK; the runtime then saves the worker
 * context with STOP_LANE_WAIT_ENCLAVE until the master publishes that slot.
 */
struct keystone_yxstm_slot_command {
  struct keystone_abi_header abi;
  uintptr_t operation;
  uintptr_t lane_id;
  uintptr_t slot_id;
  uintptr_t expected_epoch;
  uintptr_t batch_id;
  uintptr_t task_id;
  uintptr_t sequence;
  uintptr_t payload_size;
  uintptr_t permissions;
  uintptr_t digest;
  uintptr_t state;
  uintptr_t result;
  uintptr_t reserved[2];
};

struct keystone_yxstm_task_bank_state {
  uintptr_t bank_id;
  uintptr_t phase;
  uintptr_t phase_epoch;
  uintptr_t task_epoch;
  uintptr_t sequence;
  uintptr_t published_sequence;
  uintptr_t active_worker_mask;
  uintptr_t ready_bitmap;
  uintptr_t done_bitmap;
  uintptr_t payload_length;
  uintptr_t deadline;
  uintptr_t rollback_reason;
  uintptr_t commit_epoch;
  uintptr_t task_digest;
  uintptr_t lane_rank;
};

struct keystone_yxstm_protocol_state {
  struct keystone_abi_header abi;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t security_policy_version;
  uintptr_t phase;
  uintptr_t phase_epoch;
  uintptr_t session_epoch;
  uintptr_t membership_epoch;
  uintptr_t sequence;
  uintptr_t published_sequence;
  uintptr_t active_worker_mask;
  uintptr_t ready_bitmap;
  uintptr_t done_bitmap;
  uintptr_t payload_length;
  uintptr_t deadline;
  uintptr_t rollback_reason;
  uintptr_t channel_version;
  uintptr_t task_epoch;
};

/*
 * The eapp maps this page read-only. SM is the only writer and publishes an
 * even sequence after the protocol snapshot is complete. Readers retry when
 * the sequence is zero, odd, or changes while copying the state.
 */
struct keystone_yxstm_protocol_mailbox {
  uintptr_t publish_sequence;
  uintptr_t magic;
  uintptr_t version;
  uintptr_t flags;
  struct keystone_yxstm_protocol_state state;
  uintptr_t task_bank_count;
  struct keystone_yxstm_task_bank_state task_banks[KEYSTONE_YXSTM_MAX_BANKS];
};

struct keystone_yxstm_mailbox_registration {
  struct keystone_abi_header abi;
  uintptr_t mailbox_va;
  uintptr_t mailbox_size;
  uintptr_t flags;
  uintptr_t reserved;
};

/* Optional scheduler clock in the unused tail of the audited RO EPM mailbox.
 * This is not UTM: only SM may publish it. No SBI is needed at AES boundaries. */
#define KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK ((uintptr_t)2)
/* Requires EXEC_CLOCK; omit unrelated protocol/bank snapshot publications. */
#define KEYSTONE_YXSTM_MAILBOX_FLAG_EXEC_CLOCK_ONLY ((uintptr_t)4)
#define KEYSTONE_EXEC_CLOCK_OFFSET 1024
#define KEYSTONE_EXEC_CLOCK_VERSION ((uintptr_t)1)
#define KEYSTONE_EXEC_CLOCK_MARKER "keystone-member-exec-clock-v1"
struct keystone_member_exec_clock {
  uintptr_t sequence;
  uintptr_t version;
  uintptr_t generation;
  uintptr_t runtime_ticks;
  uintptr_t resume_ticks;
  uintptr_t running;
};

struct keystone_exec_clock_sample {
  uint64_t runtime_ticks;
  uint64_t wall_ticks;
  uintptr_t generation;
};

static inline int keystone_exec_clock_read(
    const volatile struct keystone_member_exec_clock* clock,
    uint64_t (*read_time)(void), struct keystone_exec_clock_sample* sample) {
  unsigned attempt;
  if (!clock || !read_time || !sample)
    return -1;
  for (attempt = 0; attempt < 16; ++attempt) {
    uintptr_t before = clock->sequence;
    uintptr_t version, generation, runtime, resume, running;
    uint64_t now;
    if (!before || (before & 1))
      continue;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    version = clock->version;
    generation = clock->generation;
    runtime = clock->runtime_ticks;
    resume = clock->resume_ticks;
    running = clock->running;
    now = read_time();
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (before != clock->sequence)
      continue;
    if (version != KEYSTONE_EXEC_CLOCK_VERSION || !generation ||
        running != 1 || now < resume ||
        now - resume > ~(uint64_t)0 - runtime)
      return -1;
    sample->runtime_ticks = runtime + now - resume;
    sample->wall_ticks = now;
    sample->generation = generation;
    return 0;
  }
  return -1;
}

struct keystone_yxstm_phase_transition {
  struct keystone_abi_header abi;
  uintptr_t expected_epoch;
  uintptr_t next_phase;
  uintptr_t active_worker_mask;
  uintptr_t sequence;
  uintptr_t payload_length;
  uintptr_t timeout_cycles;
};

struct keystone_group_task_descriptor {
  struct keystone_abi_header abi;
  uintptr_t job_id;
  uintptr_t stage_id;
  uintptr_t task_id;
  uintptr_t attempt_id;
  uintptr_t partition_id;
  uintptr_t input_bank;
  uintptr_t output_bank;
  uintptr_t input_offset;
  uintptr_t output_offset;
  uintptr_t length;
  uintptr_t opcode;
  uintptr_t task_epoch;
  uintptr_t digest;
  uintptr_t deadline;
  uintptr_t preferred_lane_mask;
  uintptr_t active_worker_mask;
  uintptr_t flags;
  uintptr_t weight;
  uintptr_t max_attempts;
  uintptr_t commit_token;
};

struct keystone_group_task_result {
  struct keystone_abi_header abi;
  uintptr_t job_id;
  uintptr_t stage_id;
  uintptr_t task_id;
  uintptr_t attempt_id;
  uintptr_t partition_id;
  uintptr_t lane_id;
  uintptr_t bank_id;
  uintptr_t task_epoch;
  uintptr_t status;
  uintptr_t digest;
  uintptr_t commit_token;
  uintptr_t completed_at;
};

struct keystone_yxstm_task_bank_transition {
  struct keystone_abi_header abi;
  uintptr_t bank_id;
  uintptr_t expected_phase_epoch;
  uintptr_t next_phase;
  uintptr_t active_worker_mask;
  uintptr_t sequence;
  uintptr_t payload_length;
  uintptr_t timeout_cycles;
  uintptr_t task_epoch;
  uintptr_t task_digest;
  uintptr_t flags;
  uintptr_t lane_rank;
};

struct keystone_yxstm_task_bank_grant {
  struct keystone_abi_header abi;
  uintptr_t bank_id;
  uintptr_t slice_mask;
  uintptr_t permissions;
  uintptr_t phase;
  uintptr_t expected_phase_epoch;
  uintptr_t expected_task_epoch;
  uintptr_t task_digest;
};

struct keystone_yxstm_task_bank_ack {
  struct keystone_abi_header abi;
  uintptr_t bank_id;
  uintptr_t expected_phase_epoch;
  uintptr_t expected_task_epoch;
  uintptr_t event;
  uintptr_t task_digest;
};

#define KEYSTONE_GROUP_LANE_TURN_WAIT       1
#define KEYSTONE_GROUP_LANE_TURN_ADVANCE    2
#define KEYSTONE_GROUP_LANE_TURN_WAIT_BANK  3
#define KEYSTONE_GROUP_LANE_TURN_READY      0
#define KEYSTONE_GROUP_LANE_TURN_BLOCK      1

/*
 * Scheduler-owned streaming order for oversubscribed worker lanes.
 * WAIT may return BLOCK, in which case the runtime immediately enters
 * STOP_LANE_WAIT_ENCLAVE. ADVANCE wakes exactly the next turn holder.
 * WAIT_BANK uses turn_id as bank_id and reserved[] as {phase, task_epoch};
 * the SM wakes the member only after that bank state is fully published.
 */
struct keystone_group_lane_turn {
  struct keystone_abi_header abi;
  uintptr_t operation;
  uintptr_t lane_id;
  uintptr_t lane_rank;
  uintptr_t sequence;
  uintptr_t turn_id;
  uintptr_t result;
  uintptr_t reserved[2];
};

struct keystone_yxstm_channel_header {
  uintptr_t magic;
  uintptr_t version;
  uintptr_t header_size;
  uintptr_t group_id;
  uintptr_t group_generation;
  uintptr_t security_policy_version;
  uintptr_t phase_epoch;
  uintptr_t task_epoch;
  uintptr_t session_epoch;
  uintptr_t sequence;
  uintptr_t payload_length;
  uintptr_t slice_id;
  uintptr_t bank_id;
  uintptr_t flags;
};

struct group_private_region_info {
  struct keystone_abi_header abi;
  uintptr_t private_va_base;
  uintptr_t private_size;
};

#define KEYSTONE_ABI_STATIC_ASSERT(name, condition) \
  typedef char keystone_abi_static_assert_##name[(condition) ? 1 : -1]

KEYSTONE_ABI_STATIC_ASSERT(group_member_limit_64,
    KEYSTONE_GROUP_MEMBER_LIMIT == 65);
KEYSTONE_ABI_STATIC_ASSERT(group_config_words,
    sizeof(struct keystone_group_config) == 14 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_topology_words,
    sizeof(struct keystone_group_topology) == 20 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_lease_words,
    sizeof(struct keystone_group_lease) == 13 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_sched_config_words,
    sizeof(struct keystone_group_sched_config) == 15 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_ocall_status_words,
    sizeof(struct keystone_group_ocall_status) == 19 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_run_hart_words,
    sizeof(struct keystone_group_run_hart) == 16 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_wait_event_words,
    sizeof(struct keystone_group_wait_event) == 18 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_test_snapshot_words,
    sizeof(struct keystone_group_test_snapshot) == 31 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_test_injection_words,
    sizeof(struct keystone_group_test_injection) == 13 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_perf_snapshot_words,
    sizeof(struct keystone_group_perf_snapshot) == 76 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_control_words,
    sizeof(struct keystone_group_control) == 13 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_heartbeat_words,
    sizeof(struct keystone_group_heartbeat) == 16 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_worker_total_bytes,
    KEYSTONE_YXSTM_WORKER_TOTAL_SIZE == (uintptr_t)36 * 1000000);
KEYSTONE_ABI_STATIC_ASSERT(yxstm_worker_lane_mapping_page_aligned,
    (KEYSTONE_YXSTM_WORKER_LANE_SIZE & (uintptr_t)4095) == 0);
KEYSTONE_ABI_STATIC_ASSERT(yxstm_worker_lane_mapping_covers_data,
    KEYSTONE_YXSTM_WORKER_LANE_SIZE >=
        KEYSTONE_YXSTM_WORKER_LANE_DATA_SIZE);
KEYSTONE_ABI_STATIC_ASSERT(yxstm_layout_info_words,
    sizeof(struct keystone_yxstm_layout_info) == 44 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_slot_info_words,
    sizeof(struct keystone_yxstm_slot_info) == 21 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_slot_command_words,
    sizeof(struct keystone_yxstm_slot_command) == 20 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_protocol_state_words,
    sizeof(struct keystone_yxstm_protocol_state) == 23 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_protocol_mailbox_words,
    sizeof(struct keystone_yxstm_protocol_mailbox) ==
        88 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(exec_clock_mailbox_tail,
    sizeof(struct keystone_yxstm_protocol_mailbox) <= KEYSTONE_EXEC_CLOCK_OFFSET &&
    KEYSTONE_EXEC_CLOCK_OFFSET + sizeof(struct keystone_member_exec_clock) <=
        KEYSTONE_YXSTM_MAILBOX_PAGE_SIZE);
KEYSTONE_ABI_STATIC_ASSERT(exec_clock_words,
    sizeof(struct keystone_member_exec_clock) == 6 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_mailbox_registration_words,
    sizeof(struct keystone_yxstm_mailbox_registration) ==
        10 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_phase_transition_words,
    sizeof(struct keystone_yxstm_phase_transition) == 12 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_task_descriptor_words,
    sizeof(struct keystone_group_task_descriptor) == 26 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_task_result_words,
    sizeof(struct keystone_group_task_result) == 18 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_task_bank_transition_words,
    sizeof(struct keystone_yxstm_task_bank_transition) ==
        17 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_task_bank_grant_words,
    sizeof(struct keystone_yxstm_task_bank_grant) == 13 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_task_bank_ack_words,
    sizeof(struct keystone_yxstm_task_bank_ack) == 11 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_lane_turn_words,
    sizeof(struct keystone_group_lane_turn) == 14 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(yxstm_channel_header_words,
    sizeof(struct keystone_yxstm_channel_header) == 14 * sizeof(uintptr_t));
KEYSTONE_ABI_STATIC_ASSERT(group_private_region_info_words,
    sizeof(struct group_private_region_info) == 8 * sizeof(uintptr_t));

/* Structs for interfacing into the SM */
struct runtime_params_t {
  uintptr_t dram_base;
  uintptr_t dram_size;
  uintptr_t runtime_base;
  uintptr_t user_base;
  uintptr_t free_base;
  uintptr_t untrusted_base;
  uintptr_t untrusted_size;
  uintptr_t YXSTrusted_base;
  uintptr_t YXSTrusted_size;
  uintptr_t shared_utm_base;  // Shared UTM base address (for slave enclave)
  uintptr_t shared_utm_size;  // Shared UTM size (for slave enclave)
  uintptr_t sec_base;         // SEC MMIO base address
  uintptr_t sec_size;         // SEC MMIO size
  uintptr_t sec_flags;        // SEC access mode flags
  uintptr_t sec_engine_id;    // SEC engine identifier
  uintptr_t free_requested; // for attestation
};

struct keystone_sbi_pregion_t {
  uintptr_t paddr;
  size_t size;
};

struct keystone_sbi_create_t {
  struct keystone_sbi_pregion_t epm_region;
  struct keystone_sbi_pregion_t group_epm_region;
  struct keystone_sbi_pregion_t utm_region;
  struct keystone_sbi_pregion_t YXSTM_region;
  struct keystone_sbi_pregion_t shared_utm_region;  // Shared UTM region for dual-enclave parallel encryption
  struct keystone_sbi_pregion_t sec_region;         // Trusted SEC MMIO region
  uintptr_t ms_YXSTM;
  uintptr_t engine_id;
  uintptr_t yxstm_slice_size;
  uintptr_t yxstm_bank_count;
  uintptr_t sec_flags;
  uintptr_t sec_engine_id;

  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;
  uintptr_t free_requested;
};

#endif  // __SM_CALL_H__
