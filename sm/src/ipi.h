#ifndef __PMP_IPI_H__
#define __PMP_IPI_H__

#include <sbi/sbi_scratch.h>
#include <sbi/sbi_hartmask.h>
#include <sbi/sbi_tlb.h>

#define SBI_PMP_IPI_TYPE_SET    0
#define SBI_PMP_IPI_TYPE_UNSET  1
#define SBI_PMP_IPI_TYPE_SFENCE 2

#define SBI_GROUP_IPI_REVOKE_YXSTM 1
#define SBI_GROUP_IPI_REFRESH_PMP  2

struct group_coherence_ipi_request {
  unsigned long sequence;
  unsigned long operation;
  unsigned long group_id;
  unsigned long group_generation;
  unsigned long permission_epoch;
  unsigned long phase_epoch;
  long epm_rid;
  long yxstm_rid;
};

struct sbi_pmp_ipi_info {
  unsigned long type;
  unsigned long __dummy;
  unsigned long rid;
  unsigned long perm;
};

void sbi_pmp_ipi_local_update(struct sbi_tlb_info *info);

#define SBI_PMP_IPI_INFO_SIZE sizeof(struct sbi_pmp_ipi_info)

int sbi_pmp_ipi_init(struct sbi_scratch* scratch, bool cold_boot);

int sbi_pmp_ipi_request(ulong hmask, ulong hbase, struct sbi_pmp_ipi_info* info);

void send_and_sync_pmp_ipi(int region_idx, int type, uint8_t perm);
void send_and_sync_pmp_ipi_mask(ulong mask, int region_idx, int type, uint8_t perm);
int group_coherence_ipi_init(void);
int group_coherence_ipi_target_matches(unsigned long hartid,
                                       unsigned long group_id,
                                       unsigned long group_generation);
int group_coherence_ipi_sync(ulong requested_mask,
                             struct group_coherence_ipi_request* request,
                             unsigned long timeout_cycles,
                             ulong* acked_mask,
                             ulong* offline_mask);
int group_scheduler_ipi_kick(ulong requested_mask);
void group_process_enclave_ipis(void);
void group_restore_host_ipi(void);

struct group_coherence_test_stats {
  unsigned long requests;
  unsigned long acks;
  unsigned long timeouts;
  unsigned long failures;
};

void group_coherence_test_get_stats(struct group_coherence_test_stats* stats);
int group_coherence_test_inject(unsigned long operation,
                                unsigned long hart_id,
                                unsigned long count);
#endif
