//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_SBI_
#define _KEYSTONE_SBI_

#include "keystone_user.h"
#include "sm_call.h"
#include "sm_err.h"

#include <asm/sbi.h>

struct sbiret sbi_sm_create_enclave(struct keystone_sbi_create_t* args);
struct sbiret sbi_sm_destroy_enclave(unsigned long eid,
                                     unsigned long eid_generation);
struct sbiret sbi_sm_run_enclave(unsigned long eid);
struct sbiret sbi_sm_resume_enclave(unsigned long eid);
struct sbiret sbi_sm_group_set_count(unsigned long group_count);
struct sbiret sbi_sm_group_set_hart_count(unsigned long group_id,
                                          unsigned long hart_count);
struct sbiret sbi_sm_group_query(struct keystone_group_config* config);
struct sbiret sbi_sm_group_config_topology(
    struct keystone_group_topology* topology);
struct sbiret sbi_sm_group_query_topology(
    struct keystone_group_topology* topology);
struct sbiret sbi_sm_group_set_lease_state(
    struct keystone_group_lease* lease);
struct sbiret sbi_sm_group_create(struct keystone_group_config* config);
struct sbiret sbi_sm_group_activate(struct keystone_group_config* config);
struct sbiret sbi_sm_group_destroy(struct keystone_group_config* config);
struct sbiret sbi_sm_group_bind_enclave(unsigned long eid,
                                        unsigned long hart_id,
                                        unsigned long group_generation,
                                        unsigned long eid_generation,
                                        unsigned long priority,
                                        unsigned long quantum_ticks);
struct sbiret sbi_sm_group_enqueue_enclave(unsigned long eid,
                                           unsigned long group_generation,
                                           unsigned long eid_generation);
struct sbiret sbi_sm_group_poll_blocked_ocall(
    struct keystone_group_ocall_status* status);
struct sbiret sbi_sm_group_resume_blocked_ocall(
    struct keystone_group_ocall_status* status);
struct sbiret sbi_sm_group_run_hart(struct keystone_group_run_hart* run);
struct sbiret sbi_sm_group_run_master(struct keystone_group_run_hart* run);
struct sbiret sbi_sm_group_pause_master(
    struct keystone_group_control* control);
struct sbiret sbi_sm_group_host_heartbeat_ack(
    struct keystone_group_heartbeat* heartbeat);
struct sbiret sbi_sm_group_control_enclave(
    struct keystone_group_control* control);
struct sbiret sbi_sm_group_test_snapshot(
    struct keystone_group_test_snapshot* snapshot);
struct sbiret sbi_sm_group_test_inject(
    struct keystone_group_test_injection* injection);
struct sbiret sbi_sm_group_perf_query(
    struct keystone_group_perf_snapshot* snapshot);

long keystone_sbi_sm_detail(struct sbiret ret);
int keystone_sbi_sm_errno(struct sbiret ret);
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
int keystone_sbi_send_ipi_mask(unsigned long hart_mask);
int keystone_sbi_hsm_hart_status(unsigned long hart_id,
                                 unsigned long *state);
#endif

#endif
