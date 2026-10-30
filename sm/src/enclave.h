//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires a defined platform to build"
#endif

#include "sm.h"
#include "pmp.h"
#include "thread.h"
#include <crypto.h>

// Special target platform header, set by configure script
#include TARGET_PLATFORM_HEADER

#define ATTEST_DATA_MAXLEN  1024
/* TODO: does not support multithreaded enclave yet */
#define MAX_ENCL_THREADS 1

#define MAX_SLAVE_ENCLAVES (ENCL_MAX - 1)

#define MAX_MS_GROUP 10
#define KEYSTONE_MAX_ENABLED_GROUPS 4

typedef struct {
  uint64_t state;          // 状态
  unsigned int s_id;          // 从属 enclave 的 eID
  uintptr_t data_ptr;     // 数据指针
  uint64_t size;          // 数据大小
  uint64_t numbers;       // 数量
} s_enclave;

typedef struct {
  uint64_t slave_numbers; // 从属数量
  s_enclave* slave_enclave[MAX_SLAVE_ENCLAVES]; // 从属 enclave 数组
} m_enclave;

typedef struct {
  uint64_t isCreated;     // 是否已创建
  char identity[64+4];    // 身份信息
  m_enclave* m;           // 关联的 m_enclave
} ms_group;

typedef enum {
  INVALID = -1,
  DESTROYING = 0,
  ALLOCATED,
  FRESH,
  STOPPED,
  RUNNING,
  FAULTED,
} enclave_state;

enum group_sched_state {
  GROUP_SCHED_NONE = 0,
  GROUP_SCHED_RUNNABLE,
  GROUP_SCHED_RUNNING,
  GROUP_SCHED_BLOCKED,
  GROUP_SCHED_PAUSED,
  GROUP_SCHED_FAULTED,
  GROUP_SCHED_EXITED,
};

/* For now, eid's are a simple unsigned int */
typedef unsigned int enclave_id;

/* Metadata around memory regions associate with this enclave
 * EPM is the 'home' for the enclave, contains runtime code/etc
 * UTM is the untrusted shared pages
 * OTHER is managed by some other component (e.g. platform_)
 * INVALID is an unused index
 */
enum enclave_region_type{
  REGION_INVALID,
  REGION_EPM,
  REGION_UTM,
  REGION_OTHER,
  REGION_GROUP_SHARED,
};

struct enclave_region
{
  region_id pmp_rid;
  enum enclave_region_type type;
};

/* enclave metadata */
struct enclave
{
  //spinlock_t lock; //local enclave lock. we don't need this until we have multithreaded enclave
  enclave_id eid; //enclave id
  uint64_t generation;
  unsigned long encl_satp; // enclave's page table base
  enclave_state state; // global state of the enclave

  /* Physical memory regions associate with this enclave */
  struct enclave_region regions[ENCLAVE_REGIONS_MAX];

  /* measurement */
  byte hash[MDSIZE];
  byte runtime_hash[MDSIZE];
  byte sign[SIGNATURE_SIZE];

  /* parameters */
  struct runtime_params_t params;

  /* enclave execution context */
  unsigned int n_thread;
  struct thread_state threads[MAX_ENCL_THREADS];

  struct platform_enclave_data ped;

  m_enclave m;
  s_enclave s;
  uint64_t engine_id;
  uint64_t group_id;
  uint64_t assigned_hart;
  uint64_t hart_bound;
  enum group_sched_state sched_state;
};

extern struct enclave enclaves[ENCL_MAX];

/* attestation reports */
struct enclave_report
{
  byte hash[MDSIZE];
  uint64_t report_version;
  uint64_t security_policy_version;
  uint64_t group_id;
  uint64_t group_generation;
  uint64_t group_role;
  uint64_t group_hart_mask;
  uint64_t bound_hart;
  uint64_t allowed_slice_mask;
  uint64_t membership_epoch;
  uint64_t phase_epoch;
  uint64_t session_epoch;
  byte runtime_hash[MDSIZE];
  byte group_session_hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};
struct sm_report
{
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};
struct report
{
  struct enclave_report enclave;
  struct sm_report sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

/* sealing key structure */
#define SEALING_KEY_SIZE 128
struct sealing_key
{
  uint8_t key[SEALING_KEY_SIZE];
  uint8_t signature[SIGNATURE_SIZE];
};

struct s_attested_report {
  unsigned int seq;
  unsigned long long nonce;
  unsigned char s_hash[64];
  unsigned char hmac[64];
  unsigned char signature[64];
};

/*** SBI functions & external functions ***/
// callables from the host
unsigned long create_enclave(unsigned long *eid, struct keystone_sbi_create_t create_args);
unsigned long destroy_enclave(enclave_id eid);
unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid);
// callables from the enclave
unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid,
                           int allow_direct_switch);
unsigned long fault_enclave(struct sbi_trap_regs *regs, enclave_id eid,
                            unsigned long fault_code,
                            unsigned long fault_cause,
                            unsigned long fault_tval);
unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid);
unsigned long attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size, enclave_id eid);

// Function to create a group of master enclaves
unsigned long m_enclave_create_group(uintptr_t identity, uintptr_t size, enclave_id eid);

// Function to join a slave enclave to a master enclave group
unsigned long s_enclave_join_group(uintptr_t identity, uintptr_t size, enclave_id eid);

// // Function to find a master enclave group by its identity
// unsigned long s_enclave_find_group(uintptr_t identity, uintptr_t size);

// Function to get data from a slave enclave to the main enclave
unsigned long main_enclave_get_slave_enclave_data(uintptr_t dest, uintptr_t size, uintptr_t numbers, enclave_id eid);

// Function to set the data pointer for a slave enclave
unsigned long slave_enclave_set_dataptr(uintptr_t src, uintptr_t size, uintptr_t numbers, enclave_id eid);

// Function to get data from a slave enclave to the main enclave
unsigned long main_enclave_get_slave_enclave_data_yx(uintptr_t temp_ptr, uintptr_t dest_ptr, enclave_id eid);

// Function to set the data pointer for a slave enclave
unsigned long slave_enclave_set_dataptr_yx(uintptr_t temp_ptr, uintptr_t data_ptr, enclave_id eid);

unsigned long slave_enclave_set_numberblock_set_pmp(enclave_id eid);

unsigned long main_enclave_get_numberblock_set_pmp(enclave_id eid);

unsigned long other_enclave_access_stm_test_set_pmp(enclave_id eid);

unsigned long s_enclave_attested(enclave_id eid, uintptr_t report, uintptr_t nonce, uintptr_t kg);
unsigned long m_enclave_attest_s_enclave(enclave_id eid, uintptr_t report, uintptr_t kg, uintptr_t flag);
unsigned long group_member_register_page_table_root(enclave_id eid, uintptr_t page_table_root);
unsigned long yxstm_query_layout(enclave_id eid, uintptr_t out_buf,
                                 uintptr_t out_len);
unsigned long yxstm_query_slot(enclave_id eid, uintptr_t inout_buf,
                               uintptr_t inout_len);
unsigned long yxstm_slot_command(enclave_id eid, uintptr_t inout_buf,
                                 uintptr_t inout_len);
unsigned long yxstm_acquire_slice(enclave_id eid, uintptr_t slice_id,
                                  uintptr_t flags, uintptr_t phase,
                                  uintptr_t expected_epoch);
unsigned long yxstm_release_slice(enclave_id eid, uintptr_t slice_id,
                                  uintptr_t expected_epoch);
unsigned long yxstm_acquire_mask(enclave_id eid, uintptr_t slice_mask,
                                 uintptr_t flags, uintptr_t phase,
                                 uintptr_t expected_epoch);
unsigned long yxstm_release_mask(enclave_id eid, uintptr_t slice_mask,
                                 uintptr_t expected_epoch);
unsigned long yxstm_query_protocol(enclave_id eid, uintptr_t out_buf,
                                   uintptr_t out_len);
unsigned long yxstm_phase_transition(enclave_id eid, uintptr_t request_buf,
                                     uintptr_t request_len);
unsigned long yxstm_phase_ack(enclave_id eid, uintptr_t expected_epoch,
                              uintptr_t event);
unsigned long yxstm_register_mailbox(enclave_id eid, uintptr_t request_buf,
                                     uintptr_t request_len);
unsigned long yxstm_task_bank_transition(enclave_id eid,
                                         uintptr_t request_buf,
                                         uintptr_t request_len);
unsigned long yxstm_task_bank_acquire(enclave_id eid,
                                      uintptr_t request_buf,
                                      uintptr_t request_len);
unsigned long yxstm_task_bank_release(enclave_id eid,
                                      uintptr_t request_buf,
                                      uintptr_t request_len);
unsigned long yxstm_task_bank_ack(enclave_id eid, uintptr_t request_buf,
                                  uintptr_t request_len);
unsigned long group_lane_turn(enclave_id eid, uintptr_t request_buf,
                              uintptr_t request_len);
unsigned long group_set_count(uint64_t group_count);
unsigned long group_set_hart_count(uint64_t group_id, uint64_t hart_count);
unsigned long group_query(uintptr_t out_config);
unsigned long group_config_topology(uintptr_t inout_topology);
unsigned long group_query_topology(uintptr_t inout_topology);
unsigned long group_set_lease_state(uintptr_t inout_lease);
unsigned long group_test_snapshot(uintptr_t out_snapshot);
unsigned long group_test_inject(uintptr_t inout_injection);
unsigned long group_perf_query(uintptr_t inout_snapshot);
unsigned long group_create(uintptr_t inout_config);
unsigned long group_activate(uintptr_t inout_config);
unsigned long group_destroy(uintptr_t inout_config);
unsigned long group_bind_enclave_to_hart(enclave_id eid, uint64_t hart_id,
                                         uint64_t group_generation,
                                         uint64_t eid_generation,
                                         uint64_t priority,
                                         uint64_t quantum_ticks);
unsigned long group_enqueue_enclave(enclave_id eid,
                                    uint64_t group_generation,
                                    uint64_t eid_generation);
unsigned long group_poll_blocked_ocall(uintptr_t out_status);
unsigned long group_resume_blocked_ocall(uintptr_t inout_status);
unsigned long group_host_heartbeat_ack(uintptr_t inout_heartbeat);
unsigned long group_run_hart(struct sbi_trap_regs* regs, uintptr_t run_status);
unsigned long group_run_master(struct sbi_trap_regs* regs,
                               uintptr_t run_status);
unsigned long group_pause_master(uintptr_t inout_control);
unsigned long group_control_enclave(uintptr_t inout_control);
void group_record_host_event(enclave_id eid, uintptr_t event,
                             uintptr_t error, uintptr_t value);
void group_queue_host_event(enclave_id eid, uintptr_t event,
                            uintptr_t error, uintptr_t value);
unsigned long group_fault_return_value(enclave_id eid,
                                       unsigned long fault_code);
unsigned long group_scheduler_timer_tick(enclave_id eid);
unsigned long group_scheduler_timer_switch(struct sbi_trap_regs* regs,
                                           enclave_id eid);
void group_perf_timer_trap_begin(uint64_t cycle, uint64_t time);
void group_perf_record_timer_trap(uint64_t start_cycle, uint64_t start_time);
unsigned long group_scheduler_ipi_switch(struct sbi_trap_regs* regs,
                                         enclave_id eid);
int group_scheduler_ipi_reschedule_pending(enclave_id eid);
unsigned long group_service_host_interrupt(struct sbi_trap_regs* regs,
                                           enclave_id eid,
                                           unsigned long interrupt_cause);
void group_scheduler_runtime_timer_init(enclave_id eid);
int enclave_is_group_enclave(enclave_id eid);

// attestation
unsigned long validate_and_hash_enclave(struct enclave* enclave);
unsigned long generate_kg(struct enclave* enclave, void* kg);
unsigned long generate_s_attested_hash(struct s_attested_report* s_attested_report, void* kg);
// TODO: These functions are supposed to be internal functions.
void enclave_init_metadata(void);
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create_t* dest);
int get_enclave_region_index(enclave_id eid, enum enclave_region_type type);
uintptr_t get_enclave_region_base(enclave_id eid, int memid);
uintptr_t get_enclave_region_size(enclave_id eid, int memid);
unsigned long get_sealing_key(uintptr_t seal_key, uintptr_t key_ident, size_t key_ident_size, enclave_id eid);
// interrupt handlers
void sbi_trap_handler_keystone_enclave(struct sbi_trap_regs *regs);
#endif
