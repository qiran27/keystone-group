#ifndef KEYSTONE_ENCLAVE_STORE_H
#define KEYSTONE_ENCLAVE_STORE_H

#include <stdint.h>
#include "shared/sm_call.h"

#include "../eapp/group-pmp-sqlite-shared.h"
#include "../eapp/group-pmp-sqlite-vfs-shared.h"

#define KEYSTONE_ENCLAVE_STORE_MARKER "keystone-enclave-extent-client-v21"

#ifdef GROUP_PMP_KV_WORKER
#include "../secure-kv/kv-record.h"
void keystone_enclave_store_get_kv_stats(struct kv_bench_stats* stats);
#endif

int keystone_enclave_store_set_exec_clock(
    const volatile struct keystone_member_exec_clock* clock);

int keystone_enclave_store_configure(
    const struct group_pmp_sqlite_vfs_config* config, uint64_t task_bytes);
/* Configure resets this opt-in; non-READSEQ workloads remain unpaired. */
int keystone_enclave_store_set_paired_reads(int enabled);
int keystone_enclave_store_set_intent_lookahead(int enabled);
/* Security-only diagnostic; called before prefill, never from normal runs. */
int keystone_enclave_store_set_security_sentinel(uint64_t nonce);
int keystone_enclave_store_prepare(void);
int keystone_enclave_store_begin_measurement(void);
/* Opt-in real-system diagnostics only; no new I/O or OCALLs. */
int keystone_enclave_store_set_system_trace(int enabled);
int keystone_enclave_store_publish_system_trace(void);
int keystone_enclave_store_execute(
    const struct group_pmp_sqlite_packet_header* header,
    uint64_t* digest);
int keystone_enclave_store_sync(void);
void keystone_enclave_store_get_stats(
    struct group_pmp_sqlite_vfs_stats* stats);
uint64_t keystone_enclave_store_last_error(void);
void keystone_enclave_store_destroy(void);

#endif
