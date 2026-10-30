// SPDX-License-Identifier: Dual BSD/GPL
#include "keystone.h"
#include "keystone-sbi.h"
#include "keystone_user.h"

#include <linux/cpu.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/irqflags.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
#include <asm/csr.h>
#include <asm/hsm_cpu_lease.h>
#ifndef RISCV_HSM_CPU_LEASE_EVENT_IPI
#error "HSM lease requires the kernel event-IPI hook; update asm/hsm_cpu_lease.h and the kernel"
#endif
#endif

#define KEYSTONE_GROUP_DRIVER_EVENT_DEPTH 256
#define KEYSTONE_GROUP_DRIVER_MAX_WORKERS 3

static const char keystone_group_internal_interrupt_marker[] __used =
    "keystone-group-internal-interrupted-event-v1";
static const char keystone_group_targeted_completion_kick_marker[] __used =
    "keystone-group-targeted-completion-kick-v1";
static const char keystone_group_hsm_event_ipi_marker[] __used =
    "keystone-group-hsm-event-ipi-v1";

struct keystone_group_driver_context;

struct keystone_group_worker_runner {
  struct keystone_group_driver_context *group;
  struct task_struct *task;
  wait_queue_head_t waitq;
  struct completion quiesced;
  atomic_t kick;
  atomic_t in_sm;
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  atomic_t hsm_requested;
  atomic_t hsm_entered;
  atomic_t hsm_run_enabled;
  atomic_t hsm_event_pending;
  atomic_t hsm_wake_sequence;
  atomic_long_t hsm_commit_pending_sequence;
  atomic_long_t hsm_commit_acked_sequence;
  unsigned long hsm_commit_event;
  unsigned long hsm_commit_eid;
  struct keystone_group_run_hart hsm_event;
#endif
  unsigned long hart_id;
  unsigned int cpu_id;
  bool module_ref;
};

struct keystone_group_driver_context {
  struct mutex lock;
  spinlock_t event_lock;
  wait_queue_head_t event_waitq;
  struct keystone_group_topology topology;
  struct keystone_group_worker_runner workers[KEYSTONE_GROUP_DRIVER_MAX_WORKERS];
  struct keystone_group_run_hart events[KEYSTONE_GROUP_DRIVER_EVENT_DEPTH];
  unsigned int event_head;
  unsigned int event_count;
  unsigned long event_overflows;
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  struct work_struct hsm_event_work;
  bool hsm_event_enabled;
#endif
  bool topology_valid;
  bool leased;
  struct file *lease_owner;
  unsigned long lease_flags;
  atomic_t stop_requested;
};

static struct keystone_group_driver_context
    keystone_group_contexts[KEYSTONE_MAX_ENABLED_GROUPS];

#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
static DEFINE_PER_CPU(struct keystone_group_worker_runner *,
                      keystone_hsm_lease_runner);
static struct workqueue_struct *keystone_hsm_event_wq;
#endif

/* Set only after the board isolation script has verified the boot/runtime setup. */
static bool worker_isolation_ready;
module_param(worker_isolation_ready, bool, 0644);
MODULE_PARM_DESC(worker_isolation_ready,
                 "CPU1-3 isolation and housekeeping migration verified");

static unsigned int worker_release_timeout_ms = 5000;
module_param(worker_release_timeout_ms, uint, 0644);
MODULE_PARM_DESC(worker_release_timeout_ms,
                 "Maximum wait for each leased worker to return to HOST");

static void keystone_group_abi_init(struct keystone_abi_header *abi,
                                    size_t size,
                                    unsigned long features)
{
  abi->version = KEYSTONE_ABI_VERSION;
  abi->struct_size = size;
  abi->features = features;
  abi->status = 0;
  abi->detail = 0;
  abi->reserved = 0;
}

static int keystone_group_abi_valid(const struct keystone_abi_header *abi,
                                    size_t size,
                                    unsigned long features)
{
  return abi && abi->version == KEYSTONE_ABI_VERSION &&
         abi->struct_size == size &&
         (abi->features & features) == features && !abi->status &&
         !abi->detail && !abi->reserved;
}

static struct keystone_group_driver_context *
keystone_group_context(unsigned long group_id)
{
  if (!group_id || group_id > KEYSTONE_MAX_ENABLED_GROUPS)
    return NULL;
  return &keystone_group_contexts[group_id - 1];
}

static void keystone_group_reset_events(
    struct keystone_group_driver_context *context)
{
  unsigned long flags;

  spin_lock_irqsave(&context->event_lock, flags);
  context->event_head = 0;
  context->event_count = 0;
  context->event_overflows = 0;
  memset(context->events, 0, sizeof(context->events));
  spin_unlock_irqrestore(&context->event_lock, flags);
}

static void keystone_group_accept_topology(
    struct keystone_group_driver_context *context,
    const struct keystone_group_topology *topology)
{
  if (!context->topology_valid ||
      context->topology.group_generation != topology->group_generation)
    keystone_group_reset_events(context);
  context->topology = *topology;
  context->topology_valid = true;
}

static int keystone_group_sbi_errno(struct sbiret ret)
{
  return keystone_sbi_sm_errno(ret);
}

static int keystone_group_ack_heartbeat(
    struct keystone_group_worker_runner *runner,
    unsigned long request_sequence,
    unsigned long *detail)
{
  struct keystone_group_driver_context *context = runner->group;
  struct keystone_group_heartbeat heartbeat;
  unsigned int attempt;

  if (detail)
    *detail = 0;
  memset(&heartbeat, 0, sizeof(heartbeat));
  for (attempt = 0; attempt < 32; attempt++) {
    struct sbiret ret;
    unsigned long response_detail;
    int error;

    cond_resched();
    memset(&heartbeat, 0, sizeof(heartbeat));
    keystone_group_abi_init(&heartbeat.abi, sizeof(heartbeat),
                            KEYSTONE_GROUP_ABI_FEATURES);
    heartbeat.group_id = context->topology.group_id;
    heartbeat.group_generation = context->topology.group_generation;
    heartbeat.hart_id = runner->hart_id;
    heartbeat.request_sequence = request_sequence;
    heartbeat.cleared_sources =
        KEYSTONE_GROUP_HEARTBEAT_SOURCE_TIMER |
        KEYSTONE_GROUP_HEARTBEAT_SOURCE_SOFTWARE |
        KEYSTONE_GROUP_HEARTBEAT_SOURCE_EXTERNAL;
    ret = sbi_sm_group_host_heartbeat_ack(&heartbeat);
    error = keystone_sbi_sm_errno(ret);
    response_detail = heartbeat.abi.detail ? heartbeat.abi.detail :
                      keystone_sbi_sm_detail(ret);
    if (detail)
      *detail = response_detail;
    if (!error)
      return 0;
    /* Treat a replay of the last completed ACK as success. New SM versions
     * return success directly; this also keeps the driver tolerant of a stale
     * duplicate delivered through the second HOST_INTERRUPT channel. */
    if (heartbeat.ack_sequence == request_sequence &&
        (heartbeat.state == KEYSTONE_GROUP_HEARTBEAT_STATE_VERIFIED ||
         heartbeat.state == KEYSTONE_GROUP_HEARTBEAT_STATE_IDLE) &&
        response_detail == SBI_ERR_SM_GROUP_HEARTBEAT_SEQUENCE)
      return 0;
    if (error != -EAGAIN) {
      pr_err("keystone_enclave: heartbeat ACK rejected: group=%lu generation=%lu hart=%lu request=%lu pending=0x%lx cleared=0x%lx ack=%lu state=%lu detail=%lu error=%d\n",
             context->topology.group_id,
             context->topology.group_generation,
             runner->hart_id,
             request_sequence,
             heartbeat.pending_sources,
             heartbeat.cleared_sources,
             heartbeat.ack_sequence,
             heartbeat.state,
             detail ? *detail : 0,
             error);
      return error;
    }
    usleep_range(100, 250);
  }
  pr_err("keystone_enclave: heartbeat ACK timed out: group=%lu generation=%lu hart=%lu request=%lu pending=0x%lx cleared=0x%lx state=%lu detail=%lu\n",
         context->topology.group_id,
         context->topology.group_generation,
         runner->hart_id,
         request_sequence,
         heartbeat.pending_sources,
         heartbeat.cleared_sources,
         heartbeat.state,
         detail ? *detail : 0);
  return -ETIMEDOUT;
}

static void keystone_group_translate_event(struct keystone_group_run_hart *event)
{
  unsigned int ueid;

  if (!event || !event->event)
    return;
  ueid = enclave_idr_find_by_sm_eid(event->eid);
  if (ueid) {
    event->eid = ueid;
    return;
  }

  /* Never expose an SM-internal eid through a HOST-facing group event. */
  event->eid = 0;
  if (!event->error)
    event->error = SBI_ERR_SM_ENCLAVE_STALE_GENERATION;
}

static bool keystone_group_decode_fault_fallback(
    struct keystone_group_run_hart *event, struct sbiret ret, long detail)
{
  unsigned long packed_eid;

  if (!event || event->event || !ret.error ||
      KEYSTONE_GROUP_DIRECT_SEQUENCE_VALID(ret.value))
    return false;
  packed_eid = ret.value >> 32;
  if (!packed_eid)
    return false;

  event->eid = packed_eid - 1;
  event->event = KEYSTONE_GROUP_EVENT_FAULT;
  event->error = detail ? detail : SBI_ERR_SM_ENCLAVE_FATAL_FAULT;
  event->value = ret.value & 0xffffffffUL;
  return true;
}

static void keystone_group_push_event(
    struct keystone_group_driver_context *context,
    const struct keystone_group_run_hart *event)
{
  unsigned long flags;
  unsigned int tail;

  if (!context || !event || !event->event ||
      event->event == KEYSTONE_GROUP_EVENT_HOST_INTERRUPT ||
      event->event == KEYSTONE_GROUP_EVENT_INTERRUPTED)
    return;
  if (!context->topology_valid ||
      event->group_generation != context->topology.group_generation)
    return;

  spin_lock_irqsave(&context->event_lock, flags);
  if (context->event_count == KEYSTONE_GROUP_DRIVER_EVENT_DEPTH) {
    if (context->event_overflows != ~0UL)
      context->event_overflows++;
    context->event_head =
        (context->event_head + 1) % KEYSTONE_GROUP_DRIVER_EVENT_DEPTH;
    context->event_count--;
  }
  tail = (context->event_head + context->event_count) %
         KEYSTONE_GROUP_DRIVER_EVENT_DEPTH;
  context->events[tail] = *event;
  if (~0UL - context->events[tail].queue_overflows <
      context->event_overflows)
    context->events[tail].queue_overflows = ~0UL;
  else
    context->events[tail].queue_overflows += context->event_overflows;
  context->event_count++;
  spin_unlock_irqrestore(&context->event_lock, flags);
  wake_up_interruptible(&context->event_waitq);
}

static bool keystone_group_event_available(
    struct keystone_group_driver_context *context,
    unsigned long event_mask)
{
  unsigned long flags;
  unsigned int i;
  bool available = false;

  spin_lock_irqsave(&context->event_lock, flags);
  for (i = 0; i < context->event_count; i++) {
    unsigned int index = (context->event_head + i) %
                         KEYSTONE_GROUP_DRIVER_EVENT_DEPTH;
    unsigned long event = context->events[index].event;
    if (!event_mask || (KEYSTONE_GROUP_EVENT_MASK(event) & event_mask)) {
      available = true;
      break;
    }
  }
  spin_unlock_irqrestore(&context->event_lock, flags);
  return available;
}

static bool keystone_group_pop_event(
    struct keystone_group_driver_context *context,
    unsigned long event_mask,
    struct keystone_group_run_hart *event)
{
  unsigned long flags;
  unsigned int i;
  bool found = false;

  spin_lock_irqsave(&context->event_lock, flags);
  for (i = 0; i < context->event_count; i++) {
    unsigned int index = (context->event_head + i) %
                         KEYSTONE_GROUP_DRIVER_EVENT_DEPTH;
    unsigned long value = context->events[index].event;
    unsigned int move;

    if (event_mask && !(KEYSTONE_GROUP_EVENT_MASK(value) & event_mask))
      continue;
    *event = context->events[index];
    for (move = i; move + 1 < context->event_count; move++) {
      unsigned int dst = (context->event_head + move) %
                         KEYSTONE_GROUP_DRIVER_EVENT_DEPTH;
      unsigned int src = (context->event_head + move + 1) %
                         KEYSTONE_GROUP_DRIVER_EVENT_DEPTH;
      context->events[dst] = context->events[src];
    }
    context->event_count--;
    found = true;
    break;
  }
  spin_unlock_irqrestore(&context->event_lock, flags);
  return found;
}

static void keystone_group_host_service_quiescent(void)
{
  /*
   * A leased worker CPU can return to this kthread without another runnable
   * task being available. In that case cond_resched() is not guaranteed to
   * perform a context switch, so explicitly report the ordered heartbeat
   * boundary as a quiescent state to both Tree RCU and Tasks RCU.
   */
#ifndef CONFIG_PREEMPTION
  rcu_all_qs();
#endif
  cond_resched_tasks_rcu_qs();
}

static int keystone_group_worker_thread(void *arg)
{
  struct keystone_group_worker_runner *runner = arg;
  struct keystone_group_driver_context *context = runner->group;

  while (!kthread_should_stop()) {
    wait_event_interruptible(runner->waitq,
                             kthread_should_stop() ||
                             atomic_read(&runner->kick));
    if (kthread_should_stop())
      break;
    atomic_set(&runner->kick, 0);

    while (!kthread_should_stop() &&
           !atomic_read(&context->stop_requested)) {
      struct keystone_group_run_hart run;
      struct sbiret ret;
      long sbi_detail;
      unsigned long irq_flags = 0;
      bool exclusive =
          (READ_ONCE(context->lease_flags) &
           KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE) != 0;

      /*
       * Pair with groupReleaseWorkers(): once in_sm is published, release
       * either kicks this hart out of SM or observes it already quiescent.
       * The second stop check closes the check-then-enter race.
       */
      atomic_set(&runner->in_sm, 1);
      smp_mb__after_atomic();
      if (atomic_read(&context->stop_requested)) {
        atomic_set(&runner->in_sm, 0);
        complete_all(&runner->quiesced);
        break;
      }

      memset(&run, 0, sizeof(run));
      keystone_group_abi_init(&run.abi, sizeof(run),
                              KEYSTONE_GROUP_ABI_FEATURES);
      run.group_id = context->topology.group_id;
      run.group_generation = context->topology.group_generation;
      run.hart_id = runner->hart_id;
      if (exclusive) {
        /* The production kernel owns RCU/context-tracking integration for a
         * leased hart.  External modules must not call unexported RCU idle
         * internals merely to make legacy Buildroot kernels link. */
        cond_resched_tasks_rcu_qs();
        local_irq_save(irq_flags);
      }
      ret = sbi_sm_group_run_hart(&run);
      atomic_set(&runner->in_sm, 0);
      smp_mb__after_atomic();
      if (exclusive && atomic_read(&context->stop_requested)) {
        /*
         * Returning from group_run_hart is the security quiescence boundary:
         * SM has revoked the enclave/YXSTM PMP state and restored this Linux
         * frame.  Publish that boundary before reenabling supervisor
         * interrupts.  A worker lane that finishes last can otherwise spend
         * several seconds draining the timer/RCU/softirq backlog accumulated
         * during an exclusive lease, while groupReleaseWorkers() incorrectly
         * reports that the hart is still inside the enclave.
         */
        complete_all(&runner->quiesced);
        local_irq_restore(irq_flags);
        break;
      }
      if (exclusive)
        local_irq_restore(irq_flags);
      if (!run.event && ret.error &&
          KEYSTONE_GROUP_DIRECT_SEQUENCE_VALID(ret.value)) {
        run.event = KEYSTONE_GROUP_EVENT_HOST_INTERRUPT;
        run.error = SBI_ERR_SM_ENCLAVE_SUCCESS;
        run.value = KEYSTONE_GROUP_DIRECT_SEQUENCE_DECODE(ret.value);
      }
      sbi_detail = keystone_sbi_sm_detail(ret);

      /* RELEASING forces the active enclave back through this SBI frame. */
      if (atomic_read(&context->stop_requested))
        break;

      if (sbi_detail == SBI_ERR_SM_GROUP_HOST_SERVICE ||
          run.event == KEYSTONE_GROUP_EVENT_HOST_INTERRUPT) {
        if (context->lease_flags &
            KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT) {
          unsigned long heartbeat_detail = 0;
          unsigned long request_sequence = run.value;
          int heartbeat_error;

          if (!request_sequence) {
            heartbeat_error = -ESTALE;
            heartbeat_detail = SBI_ERR_SM_GROUP_HEARTBEAT_SEQUENCE;
          } else {
            heartbeat_error = keystone_group_ack_heartbeat(
                runner, request_sequence, &heartbeat_detail);
          }

          if (heartbeat_error) {
            memset(&run, 0, sizeof(run));
            keystone_group_abi_init(&run.abi, sizeof(run),
                                    KEYSTONE_GROUP_ABI_FEATURES);
            run.group_id = context->topology.group_id;
            run.group_generation = context->topology.group_generation;
            run.hart_id = runner->hart_id;
            run.event = KEYSTONE_GROUP_EVENT_HEARTBEAT;
            run.error = heartbeat_detail ? heartbeat_detail :
                        SBI_ERR_SM_GROUP_HEARTBEAT_SOURCE_PENDING;
            run.value = request_sequence;
            keystone_group_push_event(context, &run);
            break;
          }
        }
        keystone_group_host_service_quiescent();
        continue;
      }
      if (sbi_detail == SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE ||
          (!sbi_detail && ret.error &&
           keystone_sbi_sm_errno(ret) == -EAGAIN))
        break;
      (void)keystone_group_decode_fault_fallback(&run, ret, sbi_detail);
      if (run.event) {
        keystone_group_translate_event(&run);
        /*
         * Timer stops and cooperative yields are scheduler boundaries. The
         * worker runner must immediately re-enter group_run_hart(); exposing
         * them to CPU0 fills the bounded event queue at the timer cadence and
         * turns a healthy warmup into a false EnclaveInterrupted failure.
         * Explicit host pause has its own PAUSED event and is unaffected.
         */
        if (run.event == KEYSTONE_GROUP_EVENT_INTERRUPTED)
          continue;
        keystone_group_push_event(context, &run);
        if (run.event == KEYSTONE_GROUP_EVENT_FAULT ||
            run.event == KEYSTONE_GROUP_EVENT_WATCHDOG ||
            run.event == KEYSTONE_GROUP_EVENT_HEARTBEAT)
          break;
        continue;
      }
      if (ret.error) {
        memset(&run, 0, sizeof(run));
        keystone_group_abi_init(&run.abi, sizeof(run),
                                KEYSTONE_GROUP_ABI_FEATURES);
        run.group_id = context->topology.group_id;
        run.group_generation = context->topology.group_generation;
        run.hart_id = runner->hart_id;
        run.eid = ~0UL;
        run.event = KEYSTONE_GROUP_EVENT_FAULT;
        run.error = sbi_detail ? sbi_detail : ret.error;
        keystone_group_translate_event(&run);
        keystone_group_push_event(context, &run);
        break;
      }
      keystone_group_host_service_quiescent();
    }
    if (atomic_read(&context->stop_requested))
      complete_all(&runner->quiesced);
  }
  atomic_set(&runner->in_sm, 0);
  if (atomic_read(&context->stop_requested))
    complete_all(&runner->quiesced);
  return 0;
}

#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
static unsigned int keystone_group_hsm_wake_snapshot(
    struct keystone_group_worker_runner *runner)
{
  smp_rmb();
  return (unsigned int)atomic_read(&runner->hsm_wake_sequence);
}

static void keystone_group_hsm_signal_runner(
    struct keystone_group_worker_runner *runner)
{
  atomic_inc(&runner->hsm_wake_sequence);
  smp_mb__after_atomic();
  (void)keystone_sbi_send_ipi_mask(1UL << runner->hart_id);
}

static void keystone_group_hsm_signal_mask(
    struct keystone_group_driver_context *context,
    unsigned long hart_mask)
{
  unsigned int i;

  for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
    struct keystone_group_worker_runner *runner = &context->workers[i];

    if (!atomic_read(&runner->hsm_requested) ||
        !(hart_mask & (1UL << runner->hart_id)))
      continue;
    atomic_inc(&runner->hsm_wake_sequence);
  }
  smp_mb__after_atomic();
  (void)keystone_sbi_send_ipi_mask(hart_mask);
}

static void keystone_group_hsm_prepare_wait(void)
{
  /*
   * Consume old edges BEFORE inspecting runqueue/mailbox state. HOST ACKs
   * increment hsm_wake_sequence, but SM READY kicks do not: their durable
   * condition is the SM runqueue. Clearing SSIP after group_run_hart reports
   * NOT_RUNNABLE can erase a concurrent READY kick and park the lane forever.
   */
  csr_clear(CSR_STATUS, SR_IE);
  csr_set(CSR_IE, IE_SIE);
  csr_clear(CSR_IP, IE_SIE);
  smp_mb();
}

static void keystone_group_hsm_wait(
    struct keystone_group_worker_runner *runner,
    unsigned int observed_sequence)
{
  if (atomic_read(&runner->group->stop_requested) ||
      keystone_group_hsm_wake_snapshot(runner) != observed_sequence ||
      (csr_read(CSR_IP) & IE_SIE))
    return;
  /* SIE stays globally off; locally enabled SSIP wakes WFI without Linux. */
  __asm__ __volatile__("wfi" ::: "memory");
  smp_mb();
}

static unsigned int keystone_group_hsm_publish_event(
    struct keystone_group_worker_runner *runner,
    const struct keystone_group_run_hart *event)
{
  unsigned int observed_sequence;

  while (atomic_read_acquire(&runner->hsm_event_pending) &&
         !atomic_read(&runner->group->stop_requested)) {
    keystone_group_hsm_prepare_wait();
    observed_sequence = keystone_group_hsm_wake_snapshot(runner);
    if (atomic_read_acquire(&runner->hsm_event_pending))
      keystone_group_hsm_wait(runner, observed_sequence);
  }
  if (atomic_read(&runner->group->stop_requested))
    return keystone_group_hsm_wake_snapshot(runner);
  observed_sequence = keystone_group_hsm_wake_snapshot(runner);
  runner->hsm_event = *event;
  smp_wmb();
  atomic_set(&runner->hsm_event_pending, 1);
  /* Use the kernel's dedicated IPI bit, not Linux's offline-CPU call queue. */
  riscv_hsm_cpu_lease_notify(runner->group->topology.housekeeping_cpu);
  return observed_sequence;
}

static bool keystone_group_hsm_event_needs_host_commit(unsigned long event)
{
  /*
   * These events describe a protocol edge that is not complete when the
   * housekeeping work item merely copies it into the driver queue.
   *
   * WORKERS_READY requires CPU0 to run the master so it can aggregate the
   * completed slot and publish the next READY object.  OCALL requires the
   * host to finish the transaction and issue GROUP_RESUME_BLOCKED_OCALL.
   * Both operations end by calling keystone_group_kick(), which is the only
   * notification that new runnable work has actually been committed.
   */
  return event == KEYSTONE_GROUP_EVENT_WORKERS_READY ||
         event == KEYSTONE_GROUP_EVENT_OCALL;
}

static bool keystone_group_hsm_lease_requested(unsigned int cpu)
{
  struct keystone_group_worker_runner *runner;

  if (cpu >= nr_cpu_ids)
    return false;
  runner = READ_ONCE(per_cpu(keystone_hsm_lease_runner, cpu));
  return runner && atomic_read(&runner->hsm_requested);
}

static void keystone_group_hsm_lease_enter(unsigned int cpu)
{
  struct keystone_group_worker_runner *runner =
      READ_ONCE(per_cpu(keystone_hsm_lease_runner, cpu));
  struct keystone_group_driver_context *context;

  if (!runner || !atomic_read(&runner->hsm_requested))
    return;
  context = runner->group;
  atomic_set(&runner->hsm_entered, 1);
  smp_mb__after_atomic();

  /*
   * CPU hotplug and HSM restart are completed one hart at a time while the
   * group lease is still DRAINING.  Do not enter group_run_hart until CPU0
   * has restarted every worker and committed LEASED in the SM.  Publishing
   * an SBI error during this window used to leave a stale synthetic FAULT in
   * the host event queue before the first enclave warmup.
   */
  while (!atomic_read(&runner->hsm_run_enabled) &&
         !atomic_read(&context->stop_requested)) {
    unsigned int observed_sequence;

    keystone_group_hsm_prepare_wait();
    observed_sequence = keystone_group_hsm_wake_snapshot(runner);

    smp_rmb();
    if (atomic_read(&runner->hsm_run_enabled) ||
        atomic_read(&context->stop_requested))
      break;
    keystone_group_hsm_wait(runner, observed_sequence);
  }
  smp_rmb();

  while (!atomic_read(&context->stop_requested)) {
    struct keystone_group_run_hart run;
    struct sbiret ret;
    unsigned int observed_sequence;
    long detail;

    keystone_group_hsm_prepare_wait();
    observed_sequence = keystone_group_hsm_wake_snapshot(runner);
    memset(&run, 0, sizeof(run));
    keystone_group_abi_init(&run.abi, sizeof(run),
                            KEYSTONE_GROUP_ABI_FEATURES);
    run.group_id = context->topology.group_id;
    run.group_generation = context->topology.group_generation;
    run.hart_id = runner->hart_id;
    run.event_sequence = (unsigned long)atomic_long_xchg(
        &runner->hsm_commit_acked_sequence, 0);
    atomic_set(&runner->in_sm, 1);
    smp_mb__after_atomic();
    ret = sbi_sm_group_run_hart(&run);
    atomic_set(&runner->in_sm, 0);
    smp_mb__after_atomic();
    if (atomic_read(&context->stop_requested))
      break;

    detail = keystone_sbi_sm_detail(ret);
    if (!run.event && ret.error &&
        KEYSTONE_GROUP_DIRECT_SEQUENCE_VALID(ret.value)) {
      run.event = KEYSTONE_GROUP_EVENT_HOST_INTERRUPT;
      run.error = SBI_ERR_SM_ENCLAVE_SUCCESS;
      run.value = KEYSTONE_GROUP_DIRECT_SEQUENCE_DECODE(ret.value);
    }
    /* Keep scheduler-owned timer/yield boundaries on the leased hart. */
    if (run.event == KEYSTONE_GROUP_EVENT_INTERRUPTED)
      continue;
    if (run.event && run.event != KEYSTONE_GROUP_EVENT_HOST_INTERRUPT) {
      observed_sequence = keystone_group_hsm_publish_event(runner, &run);
      if (keystone_group_hsm_event_needs_host_commit(run.event) ||
          run.event == KEYSTONE_GROUP_EVENT_FAULT ||
          run.event == KEYSTONE_GROUP_EVENT_WATCHDOG ||
          run.event == KEYSTONE_GROUP_EVENT_HEARTBEAT)
        keystone_group_hsm_wait(runner, observed_sequence);
      continue;
    }
    if (detail == SBI_ERR_SM_GROUP_HOST_SERVICE ||
        run.event == KEYSTONE_GROUP_EVENT_HOST_INTERRUPT)
      continue;
    if (detail == SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE ||
        (!detail && ret.error && keystone_sbi_sm_errno(ret) == -EAGAIN)) {
      keystone_group_hsm_wait(runner, observed_sequence);
      continue;
    }
    (void)keystone_group_decode_fault_fallback(&run, ret, detail);
    if (run.event) {
      observed_sequence = keystone_group_hsm_publish_event(runner, &run);
      keystone_group_hsm_wait(runner, observed_sequence);
      continue;
    }
    if (ret.error) {
      memset(&run, 0, sizeof(run));
      keystone_group_abi_init(&run.abi, sizeof(run),
                              KEYSTONE_GROUP_ABI_FEATURES);
      run.group_id = context->topology.group_id;
      run.group_generation = context->topology.group_generation;
      run.hart_id = runner->hart_id;
      run.eid = ~0UL;
      run.event = KEYSTONE_GROUP_EVENT_FAULT;
      run.error = detail ? detail : ret.error;
      observed_sequence = keystone_group_hsm_publish_event(runner, &run);
      keystone_group_hsm_wait(runner, observed_sequence);
    }
  }

  atomic_set(&runner->in_sm, 0);
  atomic_set(&runner->hsm_run_enabled, 0);
  atomic_set(&runner->hsm_entered, 0);
  smp_mb__after_atomic();
}

static void keystone_group_hsm_event_ipi(unsigned int cpu)
{
  unsigned int group_index;

  for (group_index = 0; group_index < KEYSTONE_MAX_ENABLED_GROUPS; group_index++) {
    struct keystone_group_driver_context *context =
        &keystone_group_contexts[group_index];
    unsigned long flags;
    unsigned int i;

    spin_lock_irqsave(&context->event_lock, flags);
    if (context->hsm_event_enabled &&
        context->topology.housekeeping_cpu == cpu) {
      for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
        if (!atomic_read(&context->workers[i].hsm_event_pending))
          continue;
        queue_work_on(cpu, keystone_hsm_event_wq, &context->hsm_event_work);
        break;
      }
    }
    spin_unlock_irqrestore(&context->event_lock, flags);
  }
}

static void keystone_group_hsm_disable_events(
    struct keystone_group_driver_context *context)
{
  unsigned long flags;

  /* Serialize the last IPI enqueue with cancellation, including teardown. */
  spin_lock_irqsave(&context->event_lock, flags);
  context->hsm_event_enabled = false;
  spin_unlock_irqrestore(&context->event_lock, flags);
  cancel_work_sync(&context->hsm_event_work);
}

static const struct riscv_hsm_cpu_lease_ops keystone_group_hsm_lease_ops = {
  .requested = keystone_group_hsm_lease_requested,
  .enter = keystone_group_hsm_lease_enter,
  .event = keystone_group_hsm_event_ipi,
};

static void keystone_group_hsm_event_work(struct work_struct *work)
{
  struct keystone_group_driver_context *context = container_of(
      work, struct keystone_group_driver_context,
      hsm_event_work);
  unsigned int i;

  for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
    struct keystone_group_worker_runner *runner = &context->workers[i];
    struct keystone_group_run_hart event;

    if (!atomic_read(&runner->hsm_event_pending))
      continue;
    smp_rmb();
    event = runner->hsm_event;
    keystone_group_translate_event(&event);
    if (keystone_group_hsm_event_needs_host_commit(event.event)) {
      WRITE_ONCE(runner->hsm_commit_event, event.event);
      WRITE_ONCE(runner->hsm_commit_eid, event.eid);
      smp_wmb();
      atomic_long_set(&runner->hsm_commit_pending_sequence,
                      event.event_sequence);
    }
    /*
     * Release the copied mailbox BEFORE making the event visible to HOST.
     * A fast ACK may immediately resume this hart and publish its next event.
     * If the mailbox were still occupied, the producer could sleep after
     * consuming that ACK; clearing it afterwards provides no new commit wake.
     * Do not touch the mailbox after push_event: it may already hold the next
     * event. This release pairs with the producer's acquire before reuse.
     */
    atomic_set_release(&runner->hsm_event_pending, 0);
    keystone_group_push_event(context, &event);
    /*
     * Clearing hsm_event_pending only acknowledges that CPU0 can see the
     * event.  It does not make an enclave runnable.  In particular, waking a
     * WORKERS_READY producer here races ahead of the master: the worker sees
     * NOT_RUNNABLE, consumes this edge, and can sleep forever after the later
     * dispatch. The master/OCALL commit paths publish event_sequence as the
     * durable SM ACK and then issue the wake.
     */
    if (!keystone_group_hsm_event_needs_host_commit(event.event))
      keystone_group_hsm_signal_runner(runner);
  }
}

static int keystone_group_hsm_wait_entered(
    struct keystone_group_worker_runner *runner)
{
  unsigned long deadline = jiffies +
      msecs_to_jiffies(worker_release_timeout_ms ?
                       worker_release_timeout_ms : 1);

  while (!atomic_read(&runner->hsm_entered)) {
    if (time_after_eq(jiffies, deadline))
      return -ETIMEDOUT;
    usleep_range(100, 250);
  }
  return 0;
}

static int keystone_group_hsm_wait_stopped(
    struct keystone_group_worker_runner *runner)
{
  unsigned long deadline = jiffies +
      msecs_to_jiffies(worker_release_timeout_ms ?
                       worker_release_timeout_ms : 1);
  unsigned long state = SBI_HSM_STATE_STARTED;
  int error;

  while (time_before(jiffies, deadline)) {
    error = keystone_sbi_hsm_hart_status(runner->hart_id, &state);
    if (error)
      return error;
    if (state == SBI_HSM_STATE_STOPPED)
      return 0;
    usleep_range(100, 250);
  }
  return -ETIMEDOUT;
}

static int keystone_group_hsm_offline_runner(
    struct keystone_group_worker_runner *runner)
{
  int error;

  if (!try_module_get(THIS_MODULE))
    return -ENODEV;
  runner->module_ref = true;
  atomic_set(&runner->hsm_event_pending, 0);
  atomic_set(&runner->hsm_entered, 0);
  atomic_set(&runner->hsm_run_enabled, 0);
  atomic_set(&runner->hsm_wake_sequence, 0);
  atomic_long_set(&runner->hsm_commit_pending_sequence, 0);
  atomic_long_set(&runner->hsm_commit_acked_sequence, 0);
  WRITE_ONCE(runner->hsm_commit_event, KEYSTONE_GROUP_EVENT_NONE);
  WRITE_ONCE(runner->hsm_commit_eid, 0);
  WRITE_ONCE(per_cpu(keystone_hsm_lease_runner, runner->cpu_id), runner);
  smp_wmb();
  atomic_set(&runner->hsm_requested, 1);
  error = remove_cpu(runner->cpu_id);
  if (error)
    goto fail;
  error = keystone_group_hsm_wait_stopped(runner);
  if (error)
    goto fail;
  error = riscv_hsm_cpu_lease_start(runner->cpu_id);
  if (error)
    goto fail;
  error = keystone_group_hsm_wait_entered(runner);
  if (!error)
    return 0;

fail:
  atomic_set(&runner->group->stop_requested, 1);
  if (atomic_read(&runner->hsm_entered))
    keystone_group_hsm_signal_runner(runner);
  if (!cpu_online(runner->cpu_id)) {
    int cleanup_error = keystone_group_hsm_wait_stopped(runner);

    if (cleanup_error)
      return cleanup_error;
    cleanup_error = add_cpu(runner->cpu_id);
    if (cleanup_error)
      return cleanup_error;
  }
  atomic_set(&runner->hsm_requested, 0);
  smp_wmb();
  WRITE_ONCE(per_cpu(keystone_hsm_lease_runner, runner->cpu_id), NULL);
  module_put(THIS_MODULE);
  runner->module_ref = false;
  return error;
}

static int keystone_group_hsm_release_runner(
    struct keystone_group_worker_runner *runner)
{
  unsigned long deadline;
  int error = 0;
  int online_error;

  if (!atomic_read(&runner->hsm_requested))
    return 0;
  atomic_set(&runner->hsm_run_enabled, 0);
  smp_mb__after_atomic();
  keystone_group_hsm_signal_runner(runner);
  deadline = jiffies + msecs_to_jiffies(
      worker_release_timeout_ms ? worker_release_timeout_ms : 1);
  while (atomic_read(&runner->hsm_entered) &&
         time_before(jiffies, deadline))
    usleep_range(100, 250);
  if (atomic_read(&runner->hsm_entered))
    return -ETIMEDOUT;
  error = keystone_group_hsm_wait_stopped(runner);
  if (error)
    return error;

  online_error = add_cpu(runner->cpu_id);
  if (online_error)
    return online_error;
  atomic_set(&runner->hsm_requested, 0);
  smp_wmb();
  WRITE_ONCE(per_cpu(keystone_hsm_lease_runner, runner->cpu_id), NULL);
  if (runner->module_ref) {
    module_put(THIS_MODULE);
    runner->module_ref = false;
  }
  return error;
}
#endif

static int keystone_group_query_topology_sm(
    unsigned long group_id,
    struct keystone_group_topology *topology)
{
  struct sbiret ret;

  memset(topology, 0, sizeof(*topology));
  keystone_group_abi_init(&topology->abi, sizeof(*topology),
                          KEYSTONE_GROUP_ABI_FEATURES);
  topology->group_id = group_id;
  ret = sbi_sm_group_query_topology(topology);
  return keystone_group_sbi_errno(ret);
}

static int keystone_group_refresh_topology(
    struct keystone_group_driver_context *context,
    unsigned long group_id)
{
  struct keystone_group_topology topology;
  int error = keystone_group_query_topology_sm(group_id, &topology);

  if (!error)
    keystone_group_accept_topology(context, &topology);
  return error;
}

static int keystone_group_set_lease_sm(
    struct keystone_group_driver_context *context,
    unsigned long state,
    unsigned long flags,
    struct keystone_group_lease *lease)
{
  struct sbiret ret;

  memset(lease, 0, sizeof(*lease));
  keystone_group_abi_init(&lease->abi, sizeof(*lease),
                          KEYSTONE_GROUP_ABI_FEATURES);
  lease->group_id = context->topology.group_id;
  lease->group_generation = context->topology.group_generation;
  lease->worker_hart_mask = context->topology.worker_hart_mask;
  lease->lease_state = state;
  lease->flags = flags;
  ret = sbi_sm_group_set_lease_state(lease);
  return keystone_group_sbi_errno(ret);
}

int keystone_group_config_topology_ioctl(unsigned long data)
{
  struct keystone_ioctl_group_topology *cfg =
      (struct keystone_ioctl_group_topology *)data;
  struct keystone_group_driver_context *context;
  struct sbiret ret;
  int error;

  if (!keystone_group_abi_valid(&cfg->topology.abi,
                                sizeof(cfg->topology),
                                KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  context = keystone_group_context(cfg->topology.group_id);
  if (!context)
    return -EINVAL;

  mutex_lock(&context->lock);
  if (context->leased) {
    error = -EBUSY;
    goto out;
  }
  ret = sbi_sm_group_config_topology(&cfg->topology);
  error = keystone_group_sbi_errno(ret);
  if (!error)
    keystone_group_accept_topology(context, &cfg->topology);
out:
  mutex_unlock(&context->lock);
  return error;
}

int keystone_group_query_topology_ioctl(unsigned long data)
{
  struct keystone_ioctl_group_topology *cfg =
      (struct keystone_ioctl_group_topology *)data;
  struct keystone_group_driver_context *context;
  int error;

  if (!keystone_group_abi_valid(&cfg->topology.abi,
                                sizeof(cfg->topology),
                                KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  context = keystone_group_context(cfg->topology.group_id);
  if (!context)
    return -EINVAL;
  mutex_lock(&context->lock);
  error = keystone_group_query_topology_sm(cfg->topology.group_id,
                                           &cfg->topology);
  if (!error)
    keystone_group_accept_topology(context, &cfg->topology);
  mutex_unlock(&context->lock);
  return error;
}

int keystone_group_lease_workers_ioctl(struct file *filep,
                                       unsigned long data)
{
  struct keystone_ioctl_group_lease *cfg =
      (struct keystone_ioctl_group_lease *)data;
  struct keystone_group_driver_context *context;
  struct keystone_group_lease lease;
  unsigned long worker_mask;
  unsigned long hart;
  unsigned int runner_index = 0;
  int error = 0;
  int cleanup_error = 0;

  if (!keystone_group_abi_valid(&cfg->lease.abi, sizeof(cfg->lease),
                                KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  context = keystone_group_context(cfg->lease.group_id);
  if (!context)
    return -EINVAL;
  mutex_lock(&context->lock);

  error = keystone_group_refresh_topology(context, cfg->lease.group_id);
  if (error)
    goto out;
  if (context->leased) {
    error = -EALREADY;
    goto out;
  }
  if (context->topology.execution_mode != GROUP_MODE_3W_1HM) {
    error = -EOPNOTSUPP;
    goto out;
  }
#if !IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  if (cfg->lease.flags & KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE) {
    error = -EOPNOTSUPP;
    goto out;
  }
#endif
  if (cfg->lease.flags & KEYSTONE_GROUP_LEASE_FLAG_TEST_FALLBACK) {
    /* The non-isolated diagnostic path remains heartbeat-driven. */
    cfg->lease.flags &= ~KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE;
    cfg->lease.flags |= KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT;
  } else {
    /* Production leases first complete Linux CPU hotplug, then remotely
     * restart each HSM-stopped hart at the dedicated lease trampoline. */
    cfg->lease.flags &= ~KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT;
    cfg->lease.flags |= KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE;
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
    cfg->lease.flags |= KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
#endif
  }
  atomic_set(&context->stop_requested, 0);
  if ((context->topology.flags &
       KEYSTONE_GROUP_TOPOLOGY_FLAG_REQUIRE_ISOLATION) &&
      !worker_isolation_ready &&
      !(cfg->lease.flags & KEYSTONE_GROUP_LEASE_FLAG_TEST_FALLBACK)) {
    error = -EBUSY;
    goto out;
  }
  if (context->topology.housekeeping_cpu >= nr_cpu_ids ||
      !cpu_online(context->topology.housekeeping_cpu) ||
      !context->topology.worker_count ||
      context->topology.worker_count > KEYSTONE_GROUP_DRIVER_MAX_WORKERS) {
    error = -EINVAL;
    goto out;
  }

#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  if (cfg->lease.flags & KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE) {
    /* Check the notification transport before taking any CPU offline. */
    error = riscv_hsm_cpu_lease_notify(context->topology.housekeeping_cpu);
    if (error)
      goto out;
  }
#endif
  /* A lease is a new event-consumption session, even within one generation. */
  keystone_group_reset_events(context);
  error = keystone_group_set_lease_sm(
      context, KEYSTONE_GROUP_LEASE_DRAINING, cfg->lease.flags, &lease);
  if (error)
    goto out;
  synchronize_rcu();

  worker_mask = context->topology.worker_hart_mask;
  for (hart = 0; hart < sizeof(worker_mask) * 8; hart++) {
    struct keystone_group_worker_runner *runner;
    unsigned long cpu;

    if (!(worker_mask & (1UL << hart)))
      continue;
    if (hart < context->topology.cpu_hart_offset) {
      error = -EINVAL;
      goto fail;
    }
    cpu = hart - context->topology.cpu_hart_offset;
    if (cpu >= nr_cpu_ids || !cpu_online(cpu) ||
        cpu == context->topology.housekeeping_cpu ||
        runner_index >= KEYSTONE_GROUP_DRIVER_MAX_WORKERS) {
      error = -EINVAL;
      goto fail;
    }
    runner = &context->workers[runner_index++];
    runner->group = context;
    runner->hart_id = hart;
    runner->cpu_id = cpu;
    reinit_completion(&runner->quiesced);
    atomic_set(&runner->kick, 0);
    atomic_set(&runner->in_sm, 0);
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
    if (cfg->lease.flags & KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE) {
      error = keystone_group_hsm_offline_runner(runner);
      if (error)
        goto fail;
      continue;
    }
#endif
    if (!try_module_get(THIS_MODULE)) {
      error = -ENODEV;
      goto fail;
    }
    runner->module_ref = true;
    runner->task = kthread_create(keystone_group_worker_thread, runner,
                                  "keystone-g%lu-h%lu",
                                  context->topology.group_id, hart);
    if (IS_ERR(runner->task)) {
      error = PTR_ERR(runner->task);
      runner->task = NULL;
      module_put(THIS_MODULE);
      runner->module_ref = false;
      goto fail;
    }
    kthread_bind(runner->task, cpu);
    wake_up_process(runner->task);
  }

  error = keystone_group_set_lease_sm(
      context, KEYSTONE_GROUP_LEASE_LEASED, cfg->lease.flags, &lease);
  if (error)
    goto fail;
  context->leased = true;
  context->lease_owner = filep;
  context->lease_flags = cfg->lease.flags;
  context->topology.lease_state = lease.lease_state;
  cfg->lease = lease;
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  if (cfg->lease.flags & KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE) {
    unsigned long event_flags;

    spin_lock_irqsave(&context->event_lock, event_flags);
    context->hsm_event_enabled = true;
    spin_unlock_irqrestore(&context->event_lock, event_flags);
    for (runner_index = 0;
         runner_index < KEYSTONE_GROUP_DRIVER_MAX_WORKERS;
         runner_index++) {
      if (!atomic_read(&context->workers[runner_index].hsm_requested))
        continue;
      atomic_set(&context->workers[runner_index].hsm_run_enabled, 1);
    }
    smp_wmb();
    keystone_group_hsm_signal_mask(
        context, context->topology.worker_hart_mask);
  }
#endif
  for (runner_index = 0;
       runner_index < KEYSTONE_GROUP_DRIVER_MAX_WORKERS;
       runner_index++) {
    if (!context->workers[runner_index].task)
      continue;
    atomic_set(&context->workers[runner_index].kick, 1);
    wake_up_interruptible(&context->workers[runner_index].waitq);
  }
  goto out;

fail:
  atomic_set(&context->stop_requested, 1);
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  for (runner_index = 0;
       runner_index < KEYSTONE_GROUP_DRIVER_MAX_WORKERS;
       runner_index++)
    atomic_set(&context->workers[runner_index].hsm_run_enabled, 0);
  smp_mb__after_atomic();
#endif
  (void)keystone_group_set_lease_sm(
      context, KEYSTONE_GROUP_LEASE_FAILED, cfg->lease.flags, &lease);
  (void)keystone_group_set_lease_sm(
      context, KEYSTONE_GROUP_LEASE_RELEASING, cfg->lease.flags, &lease);
  for (runner_index = 0;
       runner_index < KEYSTONE_GROUP_DRIVER_MAX_WORKERS;
       runner_index++) {
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
    if (atomic_read(&context->workers[runner_index].hsm_requested)) {
      int release_error = keystone_group_hsm_release_runner(
          &context->workers[runner_index]);
      if (!cleanup_error && release_error)
        cleanup_error = release_error;
      continue;
    }
#endif
    if (context->workers[runner_index].task) {
      kthread_stop(context->workers[runner_index].task);
      context->workers[runner_index].task = NULL;
    }
    if (context->workers[runner_index].module_ref) {
      module_put(THIS_MODULE);
      context->workers[runner_index].module_ref = false;
    }
  }
  if (!cleanup_error) {
    (void)keystone_group_set_lease_sm(
        context, KEYSTONE_GROUP_LEASE_FREE, cfg->lease.flags, &lease);
    context->topology.lease_state = lease.lease_state;
  } else {
    context->leased = true;
    context->lease_owner = filep;
    context->lease_flags = cfg->lease.flags;
    context->topology.lease_state = KEYSTONE_GROUP_LEASE_RELEASING;
    error = cleanup_error;
  }
out:
  mutex_unlock(&context->lock);
  return error;
}

int keystone_group_release_workers_ioctl(unsigned long data)
{
  struct keystone_ioctl_group_lease *cfg =
      (struct keystone_ioctl_group_lease *)data;
  struct keystone_group_driver_context *context;
  struct keystone_group_lease lease;
  unsigned int i;
  int error;

  if (!keystone_group_abi_valid(&cfg->lease.abi, sizeof(cfg->lease),
                                KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  context = keystone_group_context(cfg->lease.group_id);
  if (!context)
    return -EINVAL;
  mutex_lock(&context->lock);
  if (!context->leased) {
    error = 0;
    goto out;
  }
  if (cfg->lease.flags) {
    unsigned long normalized_flags = cfg->lease.flags;

    if (context->lease_flags & KEYSTONE_GROUP_LEASE_FLAG_TEST_FALLBACK) {
      normalized_flags &= ~(KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE |
                            KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE);
      normalized_flags |= KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT;
    } else {
      normalized_flags &= ~KEYSTONE_GROUP_LEASE_FLAG_HOST_HEARTBEAT;
      normalized_flags |= KEYSTONE_GROUP_LEASE_FLAG_EXCLUSIVE;
      if (context->lease_flags & KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE)
        normalized_flags |= KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE;
    }
    if (normalized_flags != context->lease_flags) {
      error = -EINVAL;
      goto out;
    }
  }
  cfg->lease.flags = context->lease_flags;
  atomic_set(&context->stop_requested, 1);
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++)
    atomic_set(&context->workers[i].hsm_run_enabled, 0);
  smp_mb__after_atomic();
#endif
  error = keystone_group_set_lease_sm(
      context, KEYSTONE_GROUP_LEASE_RELEASING, cfg->lease.flags, &lease);
  if (error)
    goto reset_stop;
  context->topology.lease_state = lease.lease_state;
  cfg->lease = lease;
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  if (cfg->lease.flags & KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE) {
    int release_error = 0;

    keystone_group_hsm_signal_mask(
        context, context->topology.worker_hart_mask);
    keystone_group_hsm_disable_events(context);
    for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
      int runner_error = keystone_group_hsm_release_runner(
          &context->workers[i]);
      if (!release_error && runner_error)
        release_error = runner_error;
    }
    if (release_error) {
      error = release_error;
      goto out;
    }
    goto lease_runners_released;
  }
#endif
  for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
    if (!context->workers[i].task)
      continue;
    atomic_set(&context->workers[i].kick, 1);
    wake_up_interruptible(&context->workers[i].waitq);
    if (!atomic_read(&context->workers[i].in_sm))
      complete_all(&context->workers[i].quiesced);
  }
  for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
    unsigned long timeout;

    if (!context->workers[i].task)
      continue;
    timeout = msecs_to_jiffies(worker_release_timeout_ms ?
                              worker_release_timeout_ms : 1);
    if (!wait_for_completion_timeout(&context->workers[i].quiesced,
                                     timeout)) {
      pr_err("keystone_enclave: worker lease release timed out: group=%lu hart=%lu cpu=%u in_sm=%d stop=%d\n",
             context->topology.group_id,
             context->workers[i].hart_id,
             context->workers[i].cpu_id,
             atomic_read(&context->workers[i].in_sm),
             atomic_read(&context->stop_requested));
      error = -ETIMEDOUT;
      goto out;
    }
  }
  for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
    if (!context->workers[i].task)
      continue;
    kthread_stop(context->workers[i].task);
    context->workers[i].task = NULL;
    if (context->workers[i].module_ref) {
      module_put(THIS_MODULE);
      context->workers[i].module_ref = false;
    }
  }
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
lease_runners_released:
#endif
  error = keystone_group_set_lease_sm(
      context, KEYSTONE_GROUP_LEASE_FREE, cfg->lease.flags, &lease);
  if (!error) {
    context->leased = false;
    context->lease_owner = NULL;
    context->lease_flags = 0;
    context->topology.lease_state = lease.lease_state;
    cfg->lease = lease;
  }
  goto out;
reset_stop:
  atomic_set(&context->stop_requested, 0);
out:
  mutex_unlock(&context->lock);
  return error;
}

int keystone_group_run_master_ioctl(unsigned long data)
{
  struct keystone_ioctl_group_run_hart *cfg =
      (struct keystone_ioctl_group_run_hart *)data;
  struct keystone_group_driver_context *context;
  struct keystone_group_run_hart run;
  struct sbiret ret;

  if (!keystone_group_abi_valid(&cfg->abi, sizeof(*cfg),
                                KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  context = keystone_group_context(cfg->group_id);
  if (!context)
    return -EINVAL;
  mutex_lock(&context->lock);
  if (keystone_group_refresh_topology(context, cfg->group_id)) {
    mutex_unlock(&context->lock);
    return -ESTALE;
  }
  if (context->topology.execution_mode != GROUP_MODE_3W_1HM) {
    mutex_unlock(&context->lock);
    return -EOPNOTSUPP;
  }
  migrate_disable();
  if (raw_smp_processor_id() != context->topology.housekeeping_cpu) {
    migrate_enable();
    mutex_unlock(&context->lock);
    return -EXDEV;
  }
  memset(&run, 0, sizeof(run));
  keystone_group_abi_init(&run.abi, sizeof(run),
                          KEYSTONE_GROUP_ABI_FEATURES);
  run.group_id = context->topology.group_id;
  run.group_generation = context->topology.group_generation;
  run.hart_id = context->topology.master_hart;
  mutex_unlock(&context->lock);

  ret = sbi_sm_group_run_master(&run);
  migrate_enable();

  /*
   * A master transition can make worker members runnable without going
   * through enqueue or OCALL-resume.  In particular, IDLE publication wakes
   * workers waiting to observe the task-complete boundary.  A runner that
   * previously received NOT_RUNNABLE is asleep on its waitqueue, so propagate
   * every master return as an explicit lane-state notification.  The kick is
   * harmless for a runner that is still executing in SM and avoids polling or
   * a periodic heartbeat for this protocol edge.
   */
  keystone_group_commit_event(
      run.group_id, KEYSTONE_GROUP_EVENT_WORKERS_READY, 0, 0);
  keystone_group_kick(run.group_id);

  if (keystone_sbi_sm_detail(ret) == SBI_ERR_SM_GROUP_HOST_SERVICE &&
      !run.event) {
    run.event = KEYSTONE_GROUP_EVENT_HOST_INTERRUPT;
    run.error = SBI_ERR_SM_ENCLAVE_SUCCESS;
    run.value = ret.value;
  } else if (!run.event && ret.error) {
    long detail = keystone_sbi_sm_detail(ret);
    run.error = detail ? detail : ret.error;
  }
  keystone_group_translate_event(&run);
  memcpy(cfg, &run, sizeof(*cfg));
  return 0;
}

int keystone_group_wait_event_ioctl(unsigned long data)
{
  struct keystone_ioctl_group_wait_event *cfg =
      (struct keystone_ioctl_group_wait_event *)data;
  struct keystone_group_driver_context *context;
  struct keystone_group_run_hart event;
  unsigned long generation;
  long waited;
  int error;

  if (!keystone_group_abi_valid(&cfg->wait.abi, sizeof(cfg->wait),
                                KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  context = keystone_group_context(cfg->wait.group_id);
  if (!context)
    return -EINVAL;

  mutex_lock(&context->lock);
  error = keystone_group_refresh_topology(context, cfg->wait.group_id);
  if (error) {
    mutex_unlock(&context->lock);
    return error;
  }
  generation = context->topology.group_generation;
  if (cfg->wait.group_generation &&
      cfg->wait.group_generation != generation) {
    mutex_unlock(&context->lock);
    return -ESTALE;
  }
  cfg->wait.group_generation = generation;
  mutex_unlock(&context->lock);

  if (!keystone_group_event_available(context, cfg->wait.event_mask)) {
    if (!cfg->wait.timeout_ms)
      return -EAGAIN;
    waited = wait_event_interruptible_timeout(
        context->event_waitq,
        keystone_group_event_available(context, cfg->wait.event_mask),
        msecs_to_jiffies(cfg->wait.timeout_ms));
    if (waited < 0)
      return waited;
    if (!waited)
      return -ETIMEDOUT;
  }
  if (!keystone_group_pop_event(context, cfg->wait.event_mask, &event))
    return -EAGAIN;
  if (event.group_generation != generation)
    return -ESTALE;

  cfg->wait.group_id = event.group_id;
  cfg->wait.group_generation = event.group_generation;
  cfg->wait.hart_id = event.hart_id;
  cfg->wait.eid = event.eid;
  cfg->wait.event = event.event;
  cfg->wait.error = event.error;
  cfg->wait.value = event.value;
  cfg->wait.event_sequence = event.event_sequence;
  cfg->wait.scheduler_epoch = event.scheduler_epoch;
  cfg->wait.queue_overflows = event.queue_overflows;
  keystone_group_abi_init(&cfg->wait.abi, sizeof(cfg->wait),
                          KEYSTONE_GROUP_ABI_FEATURES);
  return 0;
}

int keystone_group_pause_master_ioctl(unsigned long data)
{
  struct keystone_ioctl_group_control *cfg =
      (struct keystone_ioctl_group_control *)data;
  struct keystone_group_driver_context *context;
  struct keystone_group_control control;
  struct sbiret ret;

  if (!keystone_group_abi_valid(&cfg->abi, sizeof(*cfg),
                                KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  context = keystone_group_context(cfg->group_id);
  if (!context)
    return -EINVAL;
  mutex_lock(&context->lock);
  if (keystone_group_refresh_topology(context, cfg->group_id)) {
    mutex_unlock(&context->lock);
    return -ESTALE;
  }
  if (context->topology.execution_mode != GROUP_MODE_3W_1HM) {
    mutex_unlock(&context->lock);
    return -EOPNOTSUPP;
  }
  memset(&control, 0, sizeof(control));
  keystone_group_abi_init(&control.abi, sizeof(control),
                          KEYSTONE_GROUP_ABI_FEATURES);
  control.group_id = context->topology.group_id;
  control.group_generation = context->topology.group_generation;
  control.action = KEYSTONE_GROUP_CONTROL_PAUSE;
  mutex_unlock(&context->lock);
  ret = sbi_sm_group_pause_master(&control);
  if (ret.error)
    return keystone_group_sbi_errno(ret);
  cfg->group_id = control.group_id;
  cfg->group_generation = control.group_generation;
  cfg->eid = control.eid;
  cfg->eid_generation = control.eid_generation;
  cfg->action = control.action;
  cfg->status = control.status;
  cfg->scheduler_epoch = control.scheduler_epoch;
  if (cfg->eid) {
    unsigned int ueid = enclave_idr_find_by_sm_eid(cfg->eid);
    if (ueid)
      cfg->eid = ueid;
  }
  keystone_group_abi_init(&cfg->abi, sizeof(*cfg),
                          KEYSTONE_GROUP_ABI_FEATURES);
  return 0;
}

int keystone_group_heartbeat_ack_ioctl(unsigned long data)
{
  struct keystone_ioctl_group_heartbeat *cfg =
      (struct keystone_ioctl_group_heartbeat *)data;
  struct sbiret ret;

  if (!keystone_group_abi_valid(&cfg->heartbeat.abi,
                                sizeof(cfg->heartbeat),
                                KEYSTONE_GROUP_ABI_FEATURES))
    return -EINVAL;
  migrate_disable();
  ret = sbi_sm_group_host_heartbeat_ack(&cfg->heartbeat);
  migrate_enable();
  return keystone_group_sbi_errno(ret);
}

void keystone_group_kick(unsigned long group_id)
{
  struct keystone_group_driver_context *context =
      keystone_group_context(group_id);
  unsigned int i;

  if (!context || !READ_ONCE(context->leased))
    return;
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  if (READ_ONCE(context->lease_flags) &
      KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE) {
    keystone_group_hsm_signal_mask(
        context, READ_ONCE(context->topology.worker_hart_mask));
    return;
  }
#endif
  for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
    if (!READ_ONCE(context->workers[i].task))
      continue;
    atomic_set(&context->workers[i].kick, 1);
    wake_up_interruptible(&context->workers[i].waitq);
  }
}

void keystone_group_kick_hart(unsigned long group_id,
                              unsigned long hart_id)
{
  struct keystone_group_driver_context *context =
      keystone_group_context(group_id);
  unsigned int i;

  if (!context || !READ_ONCE(context->leased))
    return;
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  if (READ_ONCE(context->lease_flags) &
      KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE) {
    if (hart_id < BITS_PER_LONG)
      keystone_group_hsm_signal_mask(context, BIT(hart_id));
    return;
  }
#endif
  for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
    struct keystone_group_worker_runner *runner = &context->workers[i];

    if (!READ_ONCE(runner->task) ||
        READ_ONCE(runner->hart_id) != hart_id)
      continue;
    atomic_set(&runner->kick, 1);
    wake_up_interruptible(&runner->waitq);
    return;
  }
}

void keystone_group_commit_event(unsigned long group_id,
                                 unsigned long event,
                                 unsigned long hart_id,
                                 unsigned long eid)
{
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  struct keystone_group_driver_context *context =
      keystone_group_context(group_id);
  unsigned int i;

  if (!context || !READ_ONCE(context->leased) ||
      !(READ_ONCE(context->lease_flags) &
        KEYSTONE_GROUP_LEASE_FLAG_HSM_REMOTE))
    return;

  for (i = 0; i < KEYSTONE_GROUP_DRIVER_MAX_WORKERS; i++) {
    struct keystone_group_worker_runner *runner = &context->workers[i];
    unsigned long sequence =
        (unsigned long)atomic_long_read(
            &runner->hsm_commit_pending_sequence);

    if (!sequence || READ_ONCE(runner->hsm_commit_event) != event ||
        (hart_id && runner->hart_id != hart_id) ||
        (eid && READ_ONCE(runner->hsm_commit_eid) != eid))
      continue;
    smp_rmb();
    if ((unsigned long)atomic_long_cmpxchg(
            &runner->hsm_commit_pending_sequence, sequence, 0) != sequence)
      continue;
    atomic_long_set(&runner->hsm_commit_acked_sequence, sequence);
    smp_mb__after_atomic();
  }
#else
  (void)group_id;
  (void)event;
  (void)hart_id;
  (void)eid;
#endif
}

bool keystone_group_worker_is_leased(unsigned long group_id,
                                     unsigned long hart_id)
{
  struct keystone_group_driver_context *context =
      keystone_group_context(group_id);

  return hart_id < sizeof(unsigned long) * 8 && context &&
         READ_ONCE(context->leased) &&
         (READ_ONCE(context->topology.worker_hart_mask) & (1UL << hart_id));
}

int keystone_group_release_for_destroy(unsigned long group_id)
{
  struct keystone_ioctl_group_lease cfg;
  struct keystone_group_driver_context *context =
      keystone_group_context(group_id);

  if (!context || !READ_ONCE(context->leased))
    return 0;
  memset(&cfg, 0, sizeof(cfg));
  keystone_group_abi_init(&cfg.lease.abi, sizeof(cfg.lease),
                          KEYSTONE_GROUP_ABI_FEATURES);
  cfg.lease.group_id = group_id;
  cfg.lease.flags = READ_ONCE(context->lease_flags);
  return keystone_group_release_workers_ioctl((unsigned long)&cfg);
}

int keystone_group_release_for_file(struct file *filep)
{
  unsigned int group_index;
  int error = 0;

  if (!filep)
    return -EINVAL;
  for (group_index = 0;
       group_index < KEYSTONE_MAX_ENABLED_GROUPS;
       group_index++) {
    struct keystone_group_driver_context *context =
        &keystone_group_contexts[group_index];
    int release_error;

    if (READ_ONCE(context->lease_owner) != filep)
      continue;
    pr_info("keystone_enclave: releasing worker lease on control-fd close: group=%u\n",
            group_index + 1);
    release_error = keystone_group_release_for_destroy(group_index + 1);
    if (!error && release_error)
      error = release_error;
    if (READ_ONCE(context->lease_owner) == filep)
      WRITE_ONCE(context->lease_owner, NULL);
  }
  return error;
}

int keystone_group_driver_init(void)
{
  unsigned int group_index;
  unsigned int worker_index;
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  int error;

  keystone_hsm_event_wq = alloc_workqueue("keystone-hsm-event",
                                         WQ_HIGHPRI | WQ_MEM_RECLAIM, 0);
  if (!keystone_hsm_event_wq)
    return -ENOMEM;
#endif

  for (group_index = 0;
       group_index < KEYSTONE_MAX_ENABLED_GROUPS;
       group_index++) {
    struct keystone_group_driver_context *context =
        &keystone_group_contexts[group_index];
    mutex_init(&context->lock);
    spin_lock_init(&context->event_lock);
    init_waitqueue_head(&context->event_waitq);
    atomic_set(&context->stop_requested, 0);
    context->lease_owner = NULL;
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
    INIT_WORK(&context->hsm_event_work,
                      keystone_group_hsm_event_work);
    context->hsm_event_enabled = false;
#endif
    for (worker_index = 0;
         worker_index < KEYSTONE_GROUP_DRIVER_MAX_WORKERS;
         worker_index++) {
      init_waitqueue_head(&context->workers[worker_index].waitq);
      init_completion(&context->workers[worker_index].quiesced);
      atomic_set(&context->workers[worker_index].kick, 0);
      atomic_set(&context->workers[worker_index].in_sm, 0);
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
      atomic_set(&context->workers[worker_index].hsm_requested, 0);
      atomic_set(&context->workers[worker_index].hsm_entered, 0);
      atomic_set(&context->workers[worker_index].hsm_run_enabled, 0);
      atomic_set(&context->workers[worker_index].hsm_event_pending, 0);
      atomic_set(&context->workers[worker_index].hsm_wake_sequence, 0);
      atomic_long_set(
          &context->workers[worker_index].hsm_commit_pending_sequence, 0);
      atomic_long_set(
          &context->workers[worker_index].hsm_commit_acked_sequence, 0);
      context->workers[worker_index].hsm_commit_event =
          KEYSTONE_GROUP_EVENT_NONE;
      context->workers[worker_index].hsm_commit_eid = 0;
#endif
      context->workers[worker_index].module_ref = false;
    }
  }
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  error = riscv_hsm_cpu_lease_register(&keystone_group_hsm_lease_ops);
  if (error) {
    destroy_workqueue(keystone_hsm_event_wq);
    return error;
  }
#endif
  return 0;
}

void keystone_group_driver_exit(void)
{
  unsigned int group_index;

  for (group_index = 0;
       group_index < KEYSTONE_MAX_ENABLED_GROUPS;
       group_index++)
    (void)keystone_group_release_for_destroy(group_index + 1);
#if IS_ENABLED(CONFIG_RISCV_HSM_CPU_LEASE)
  riscv_hsm_cpu_lease_unregister(&keystone_group_hsm_lease_ops);
  for (group_index = 0; group_index < KEYSTONE_MAX_ENABLED_GROUPS; group_index++)
    keystone_group_hsm_disable_events(&keystone_group_contexts[group_index]);
  destroy_workqueue(keystone_hsm_event_wq);
#endif
}
