#include <sbi/sbi_fifo.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hsm.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_timer.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_barrier.h>
#include "ipi.h"
#include "pmp.h"
#include "cpu.h"

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires a defined platform to build"
#endif
#include TARGET_PLATFORM_HEADER

struct group_coherence_mailbox {
  volatile unsigned long published_sequence;
  volatile unsigned long ack_sequence;
  volatile unsigned long ack_permission_epoch;
  volatile unsigned long ack_phase_epoch;
  volatile long ack_status;
  struct group_coherence_ipi_request request;
};

static struct group_coherence_mailbox group_coherence_mailboxes[MAX_HARTS];
static atomic_t group_coherence_sequence = ATOMIC_INITIALIZER(0);
static u32 group_coherence_event = SBI_IPI_EVENT_MAX;
static u32 group_scheduler_kick_event = SBI_IPI_EVENT_MAX;
static atomic_t group_coherence_request_count = ATOMIC_INITIALIZER(0);
static atomic_t group_coherence_ack_count = ATOMIC_INITIALIZER(0);
static atomic_t group_coherence_timeout_count = ATOMIC_INITIALIZER(0);
static atomic_t group_coherence_failure_count = ATOMIC_INITIALIZER(0);
/* Only the owning hart accesses this latch, with M-mode interrupts disabled. */
static unsigned long group_host_ssip_pending[MAX_HARTS];
#ifndef KEYSTONE_GROUP_TESTING
#define KEYSTONE_GROUP_TESTING 0
#endif
#if KEYSTONE_GROUP_TESTING
static atomic_t group_test_drop_ipi_count = ATOMIC_INITIALIZER(0);
static atomic_t group_test_force_timeout_count = ATOMIC_INITIALIZER(0);
static volatile unsigned long group_test_drop_ipi_hart = (unsigned long)-1;
#endif

void group_process_enclave_ipis(void)
{
  unsigned long hartid = csr_read(mhartid);
  unsigned long runtime_ssip;

  if (hartid >= MAX_HARTS) {
    sbi_ipi_process();
    return;
  }
  /* OpenSBI IPI_SMODE targets HOST, not the currently executing runtime.
   * Separate it from runtime SIP before another member/HOST CSR restore can
   * erase it. Coherence callbacks still finish before any scheduler switch. */
  runtime_ssip = csr_read(mip) & MIP_SSIP;
  csr_clear(mip, MIP_SSIP);
  sbi_ipi_process();
  group_host_ssip_pending[hartid] |= csr_read(mip) & MIP_SSIP;
  csr_clear(mip, MIP_SSIP);
  if (runtime_ssip)
    csr_set(mip, runtime_ssip);
}

void group_restore_host_ipi(void)
{
  unsigned long hartid = csr_read(mhartid);

  /* Call only after restoring HOST CSRs, never on an enclave-to-peer switch. */
  if (hartid < MAX_HARTS && group_host_ssip_pending[hartid]) {
    group_host_ssip_pending[hartid] = 0;
    csr_set(mip, MIP_SSIP);
  }
}

void group_coherence_test_get_stats(struct group_coherence_test_stats* stats)
{
  if (!stats)
    return;
  stats->requests = (unsigned long)atomic_read(&group_coherence_request_count);
  stats->acks = (unsigned long)atomic_read(&group_coherence_ack_count);
  stats->timeouts = (unsigned long)atomic_read(&group_coherence_timeout_count);
  stats->failures = (unsigned long)atomic_read(&group_coherence_failure_count);
}

int group_coherence_test_inject(unsigned long operation,
                                unsigned long hart_id,
                                unsigned long count)
{
#if KEYSTONE_GROUP_TESTING
  if (operation == KEYSTONE_GROUP_TEST_INJECT_CLEAR) {
    atomic_write(&group_test_drop_ipi_count, 0);
    atomic_write(&group_test_force_timeout_count, 0);
    group_test_drop_ipi_hart = (unsigned long)-1;
    return 0;
  }
  if (!count)
    return SBI_EINVAL;
  if (operation == KEYSTONE_GROUP_TEST_INJECT_DROP_NEXT_IPI) {
    group_test_drop_ipi_hart = hart_id;
    atomic_write(&group_test_drop_ipi_count, (long)count);
    return 0;
  }
  if (operation == KEYSTONE_GROUP_TEST_INJECT_FORCE_IPI_TIMEOUT) {
    atomic_write(&group_test_force_timeout_count, (long)count);
    return 0;
  }
#else
  (void)operation;
  (void)hart_id;
  (void)count;
#endif
  return SBI_ENOTSUPP;
}

static int group_coherence_apply_local(
    const struct group_coherence_ipi_request* request)
{
  if (!request ||
      (request->operation != SBI_GROUP_IPI_REVOKE_YXSTM &&
       request->operation != SBI_GROUP_IPI_REFRESH_PMP))
    return SBI_EINVAL;
  smp_mb();
  if (request->operation == SBI_GROUP_IPI_REFRESH_PMP &&
      request->epm_rid >= 0)
    pmp_set_keystone((int)request->epm_rid, PMP_ALL_PERM);
  if ((request->operation == SBI_GROUP_IPI_REVOKE_YXSTM ||
       request->operation == SBI_GROUP_IPI_REFRESH_PMP) &&
      request->yxstm_rid >= 0)
    pmp_set_keystone((int)request->yxstm_rid, PMP_NO_PERM);
  asm volatile("sfence.vma" ::: "memory");
  asm volatile("fence.i" ::: "memory");
  smp_mb();
  return 0;
}

static int group_coherence_ipi_update(struct sbi_scratch* scratch,
                                      struct sbi_scratch* remote_scratch,
                                      u32 remote_hartid,
                                      void* data)
{
  struct group_coherence_mailbox* mailbox;
  struct group_coherence_ipi_request* request = data;

  (void)scratch;
  (void)remote_scratch;
  if (!request || remote_hartid >= MAX_HARTS)
    return SBI_EINVAL;

  mailbox = &group_coherence_mailboxes[remote_hartid];
  mailbox->published_sequence = 0;
  smp_wmb();
  mailbox->request = *request;
  smp_wmb();
  mailbox->published_sequence = request->sequence;
  return 0;
}

static void group_coherence_ipi_process(struct sbi_scratch* scratch)
{
  unsigned long hartid = current_hartid();
  struct group_coherence_mailbox* mailbox;
  struct group_coherence_ipi_request request;
  unsigned long sequence;

  (void)scratch;
  if (hartid >= MAX_HARTS)
    return;

  mailbox = &group_coherence_mailboxes[hartid];
  sequence = __smp_load_acquire(&mailbox->published_sequence);
  if (!sequence || mailbox->ack_sequence == sequence)
    return;

  request = mailbox->request;
  smp_rmb();
  if (request.sequence != sequence)
    return;

#if KEYSTONE_GROUP_TESTING
  if (atomic_read(&group_test_drop_ipi_count) > 0 &&
      (group_test_drop_ipi_hart == (unsigned long)-1 ||
       group_test_drop_ipi_hart == hartid)) {
    atomic_sub_return(&group_test_drop_ipi_count, 1);
    return;
  }
#endif

  /*
   * A target may schedule out after the sender snapshots active_hart_bitmap.
   * schedule-out clears all dynamic PMP slots before it clears active state,
   * so an inactive/mismatched target is already coherent and may ACK without
   * applying the request. Treating it as EINVAL makes the sender wait for a
   * hart that is deliberately quiescent.
   */
  mailbox->ack_status = 0;
  if (group_coherence_ipi_target_matches(
          hartid, request.group_id, request.group_generation))
    mailbox->ack_status = group_coherence_apply_local(&request);
  mailbox->ack_permission_epoch = request.permission_epoch;
  mailbox->ack_phase_epoch = request.phase_epoch;
  __smp_store_release(&mailbox->ack_sequence, sequence);
  atomic_add_return(&group_coherence_ack_count, 1);
}

static struct sbi_ipi_event_ops group_coherence_ipi_ops = {
  .name = "IPI_GROUP_COHERENCE",
  .update = group_coherence_ipi_update,
  .process = group_coherence_ipi_process,
};

static void group_scheduler_kick_process(struct sbi_scratch* scratch)
{
  /*
   * An enclave switches only after trap handling drains every IPI, including
   * PMP coherence. A parked HSM runner has no enclave trap epilogue, however:
   * leave SSIP pending so its S-mode WFI cannot lose this READY notification
   * after OpenSBI consumes MSIP. No Linux interrupt handler runs on that hart.
   */
  (void)scratch;
  smp_mb();
  if (!cpu_is_enclave_context())
    csr_set(mip, MIP_SSIP);
}

static struct sbi_ipi_event_ops group_scheduler_kick_ops = {
  .name = "IPI_GROUP_SCHED_KICK",
  .process = group_scheduler_kick_process,
};

int group_coherence_ipi_init(void)
{
  int event;
  int coherence_created = 0;

  if (group_coherence_event < SBI_IPI_EVENT_MAX &&
      group_scheduler_kick_event < SBI_IPI_EVENT_MAX)
    return 0;

  if (group_coherence_event >= SBI_IPI_EVENT_MAX) {
    sbi_memset(group_coherence_mailboxes, 0,
               sizeof(group_coherence_mailboxes));
    event = sbi_ipi_event_create(&group_coherence_ipi_ops);
    if (event < 0)
      return event;
    group_coherence_event = (u32)event;
    coherence_created = 1;
  }

  if (group_scheduler_kick_event >= SBI_IPI_EVENT_MAX) {
    event = sbi_ipi_event_create(&group_scheduler_kick_ops);
    if (event < 0) {
      if (coherence_created) {
        sbi_ipi_event_destroy(group_coherence_event);
        group_coherence_event = SBI_IPI_EVENT_MAX;
      }
      return event;
    }
    group_scheduler_kick_event = (u32)event;
  }

  return 0;
}

int group_scheduler_ipi_kick(ulong requested_mask)
{
  if (!requested_mask)
    return 0;
  if (group_scheduler_kick_event >= SBI_IPI_EVENT_MAX)
    return SBI_EINVAL;
  smp_wmb();
  return sbi_ipi_send_many(requested_mask, 0,
                           group_scheduler_kick_event, NULL);
}

int group_coherence_ipi_sync(ulong requested_mask,
                             struct group_coherence_ipi_request* request,
                             unsigned long timeout_cycles,
                             ulong* acked_mask,
                             ulong* offline_mask)
{
  ulong interruptible = 0;
  ulong target_mask;
  ulong local_bit;
  ulong remote_mask;
  ulong acked = 0;
  unsigned long hartid;
  unsigned long deadline;
  int ret;

  if (acked_mask)
    *acked_mask = 0;
  if (offline_mask)
    *offline_mask = 0;
  if (!request || group_coherence_event >= SBI_IPI_EVENT_MAX)
    return SBI_EINVAL;
  if (!requested_mask)
    return 0;

  atomic_add_return(&group_coherence_request_count, 1);
#if KEYSTONE_GROUP_TESTING
  if (atomic_read(&group_test_force_timeout_count) > 0) {
    atomic_sub_return(&group_test_force_timeout_count, 1);
    atomic_add_return(&group_coherence_timeout_count, 1);
    return SBI_ETIMEDOUT;
  }
#endif

  hartid = current_hartid();
  local_bit = hartid < BITS_PER_LONG ? (1UL << hartid) : 0;
  ret = sbi_hsm_hart_interruptible_mask(sbi_domain_thishart_ptr(), 0,
                                        &interruptible);
  if (ret)
    return ret;
  interruptible |= local_bit;
  target_mask = requested_mask & interruptible;
  if (offline_mask)
    *offline_mask = requested_mask & ~interruptible;

  request->sequence = (unsigned long)atomic_add_return(
      &group_coherence_sequence, 1);
  if (!request->sequence)
    request->sequence = (unsigned long)atomic_add_return(
        &group_coherence_sequence, 1);

  if (target_mask & local_bit) {
    struct group_coherence_mailbox* mailbox =
        &group_coherence_mailboxes[hartid];
    mailbox->ack_status = 0;
    if (group_coherence_ipi_target_matches(
            hartid, request->group_id, request->group_generation))
      mailbox->ack_status = group_coherence_apply_local(request);
    mailbox->ack_permission_epoch = request->permission_epoch;
    mailbox->ack_phase_epoch = request->phase_epoch;
    __smp_store_release(&mailbox->ack_sequence, request->sequence);
    if (!mailbox->ack_status)
      acked |= local_bit;
  }

  remote_mask = target_mask & ~local_bit;
  if (remote_mask) {
    ret = sbi_ipi_send_many(remote_mask, 0, group_coherence_event, request);
    if (ret)
      atomic_add_return(&group_coherence_failure_count, 1);
    if (ret)
      return ret;
  }

  deadline = sbi_timer_value() + timeout_cycles;
  while ((acked & target_mask) != target_mask) {
    for (hartid = 0; hartid < MAX_HARTS; hartid++) {
      ulong bit = 1UL << hartid;
      struct group_coherence_mailbox* mailbox;

      if (!(target_mask & bit) || (acked & bit))
        continue;
      mailbox = &group_coherence_mailboxes[hartid];
      /*
       * The target left the group after the snapshot. Its schedule-out path
       * has already revoked EPM/YXSTM PMP state. Publish a successful ACK for
       * this exact sequence so a delayed IPI cannot later revoke permissions
       * acquired after the hart re-enters under the new epoch.
       */
      if (!group_coherence_ipi_target_matches(
              hartid, request->group_id, request->group_generation)) {
        mailbox->ack_status = 0;
        mailbox->ack_permission_epoch = request->permission_epoch;
        mailbox->ack_phase_epoch = request->phase_epoch;
        __smp_store_release(&mailbox->ack_sequence, request->sequence);
        acked |= bit;
        continue;
      }
      if (__smp_load_acquire(&mailbox->ack_sequence) ==
          request->sequence &&
          mailbox->ack_permission_epoch == request->permission_epoch &&
          mailbox->ack_phase_epoch == request->phase_epoch &&
          !mailbox->ack_status)
        acked |= bit;
      else if (mailbox->ack_sequence == request->sequence &&
               mailbox->ack_status) {
        if (acked_mask)
          *acked_mask = acked;
        atomic_add_return(&group_coherence_failure_count, 1);
        return SBI_EIO;
      }
    }
    if ((acked & target_mask) == target_mask)
      break;
    if ((long)(sbi_timer_value() - deadline) >= 0) {
      if (acked_mask)
        *acked_mask = acked;
      atomic_add_return(&group_coherence_timeout_count, 1);
      return SBI_ETIMEDOUT;
    }
    cpu_relax();
  }

  if (acked_mask)
    *acked_mask = acked;
  atomic_add_return(&group_coherence_ack_count, 1);
  return 0;
}

void sbi_pmp_ipi_local_update(struct sbi_tlb_info *__info)
{
  struct sbi_pmp_ipi_info* info = (struct sbi_pmp_ipi_info *) __info;
  // sbi_printf("[IPI-LOCAL] hart=%lu processing region=%ld type=%d perm=0x%x\n", 
  //            current_hartid(), info->rid, info->type, info->perm);
  if (info->type == SBI_PMP_IPI_TYPE_SET) {
    pmp_set_keystone(info->rid, (uint8_t) info->perm);
  } else if (info->type == SBI_PMP_IPI_TYPE_UNSET) {
    pmp_unset(info->rid);
  } else if (info->type == SBI_PMP_IPI_TYPE_SFENCE) {
    asm volatile("sfence.vma" ::: "memory");
  }
  // sbi_printf("[IPI-LOCAL] hart=%lu completed\n", current_hartid());
}

void send_and_sync_pmp_ipi_mask(ulong mask, int region_idx, int type, uint8_t perm)
{
  ulong source_hart = current_hartid();
  // sbi_printf("[IPI] send_and_sync_pmp_ipi: hart=%lu region=%d type=%d perm=0x%x\n", 
  //            source_hart, region_idx, type, perm);
  struct sbi_tlb_info tlb_info;
  if (!mask)
    return;
  // sbi_printf("[IPI] hart_mask=0x%lx\n", mask);

  SBI_TLB_INFO_INIT(&tlb_info, type, 0, region_idx, perm,
      sbi_pmp_ipi_local_update, source_hart);
  // sbi_printf("[IPI] Calling sbi_tlb_request...\n");
  sbi_tlb_request(mask, 0, &tlb_info);
  // sbi_printf("[IPI] sbi_tlb_request completed\n");
}

void send_and_sync_pmp_ipi(int region_idx, int type, uint8_t perm)
{
  ulong mask = 0;
  sbi_hsm_hart_interruptible_mask(sbi_domain_thishart_ptr(), 0, &mask);
  send_and_sync_pmp_ipi_mask(mask, region_idx, type, perm);
}
