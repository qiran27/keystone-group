#include "enclave.h"
#include "cpu.h"
#include "sm-sbi.h"
#include "ipi.h"
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_illegal_insn.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_misaligned_ldst.h>
#include <sbi/sbi_timer.h>
#include <sbi/sbi_trap.h>

#ifndef SBI_SET_TIMER
#define SBI_SET_TIMER 0
#endif

static void sbi_trap_error(const char *msg, int rc,
				      ulong mcause, ulong mtval, ulong mtval2,
				      ulong mtinst, struct sbi_trap_regs *regs)
{
	u32 hartid = current_hartid();

	sbi_printf("%s: hart%d: %s (error %d)\n", __func__, hartid, msg, rc);
	sbi_printf("%s: hart%d: mcause=0x%" PRILX " mtval=0x%" PRILX "\n",
		   __func__, hartid, mcause, mtval);
	if (misa_extension('H')) {
		sbi_printf("%s: hart%d: mtval2=0x%" PRILX
			   " mtinst=0x%" PRILX "\n",
			   __func__, hartid, mtval2, mtinst);
	}
	sbi_printf("%s: hart%d: mepc=0x%" PRILX " mstatus=0x%" PRILX "\n",
		   __func__, hartid, regs->mepc, regs->mstatus);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "ra", regs->ra, "sp", regs->sp);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "gp", regs->gp, "tp", regs->tp);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s0", regs->s0, "s1", regs->s1);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a0", regs->a0, "a1", regs->a1);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a2", regs->a2, "a3", regs->a3);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a4", regs->a4, "a5", regs->a5);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "a6", regs->a6, "a7", regs->a7);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s2", regs->s2, "s3", regs->s3);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s4", regs->s4, "s5", regs->s5);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s6", regs->s6, "s7", regs->s7);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s8", regs->s8, "s9", regs->s9);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "s10", regs->s10, "s11", regs->s11);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "t0", regs->t0, "t1", regs->t1);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "t2", regs->t2, "t3", regs->t3);
	sbi_printf("%s: hart%d: %s=0x%" PRILX " %s=0x%" PRILX "\n", __func__,
		   hartid, "t4", regs->t4, "t5", regs->t5);
	sbi_printf("%s: hart%d: %s=0x%" PRILX "\n", __func__, hartid, "t6",
		   regs->t6);

  sbi_sm_fault_enclave(regs, rc, mcause, mtval);
}


/**
 * Handle trap/interrupt
 *
 * This function is called by firmware linked to OpenSBI
 * library for handling trap/interrupt. It expects the
 * following:
 * 1. The 'mscratch' CSR is pointing to sbi_scratch of current HART
 * 2. The 'mcause' CSR is having exception/interrupt cause
 * 3. The 'mtval' CSR is having additional trap information
 * 4. The 'mtval2' CSR is having additional trap information
 * 5. The 'mtinst' CSR is having decoded trap instruction
 * 6. Stack pointer (SP) is setup for current HART
 * 7. Interrupts are disabled in MSTATUS CSR
 *
 * @param regs pointer to register state
 */
void sbi_trap_handler_keystone_enclave(struct sbi_trap_regs *regs)
{
	int rc = SBI_ENOTSUPP;
	const char *msg = "trap handler failed";
	ulong mcause = csr_read(CSR_MCAUSE);
	ulong mtval = csr_read(CSR_MTVAL), mtval2 = 0, mtinst = 0;
	struct sbi_trap_info trap;

	if (misa_extension('H')) {
		mtval2 = csr_read(CSR_MTVAL2);
		mtinst = csr_read(CSR_MTINST);
	}

	if (mcause & (1UL << (__riscv_xlen - 1))) {
		mcause &= ~(1UL << (__riscv_xlen - 1));
		switch (mcause) {
		case IRQ_M_TIMER: {
      if (cpu_is_enclave_context() &&
          enclave_is_group_enclave(cpu_get_enclave_id())) {
        uint64_t perf_cycle_start = csr_read(CSR_MCYCLE);
        uint64_t perf_time_start = sbi_timer_value();
        /*
         * MTIP is owned by the SM scheduler. It either switches to a runnable
         * peer or restores the saved group_run_hart host frame for periodic
         * Linux service. The interrupted enclave PC/GPR state is preserved
         * exactly, and any dynamic YXSTM grant is suspended and revoked before
         * host execution.
         */
        group_perf_timer_trap_begin(perf_cycle_start, perf_time_start);
        group_scheduler_timer_switch(regs, cpu_get_enclave_id());
        group_perf_record_timer_trap(perf_cycle_start, perf_time_start);
        csr_clear(mip, MIP_MTIP);
        return;
      }
      regs->mepc -= 4;
      sbi_sm_stop_enclave(regs, STOP_TIMER_INTERRUPT);
			break;
                      }
	case IRQ_M_SOFT: {
      /*
       * A lease-release kick can race with the final enclave EXIT.  EXIT
       * clears cpu_is_enclave_context() before the group_run_hart SBI frame
       * has finished returning to its bound Linux kthread.  In that window
       * the pending MSIP belongs to OpenSBI/SM IPI delivery, not to an
       * enclave STOP request.  Treating the host frame as an enclave corrupts
       * the return path and leaves the driver waiting forever for quiesced.
       */
      if (!cpu_is_enclave_context()) {
        sbi_ipi_process();
        return;
      }
      if (cpu_is_enclave_context() &&
          enclave_is_group_enclave(cpu_get_enclave_id())) {
        /*
         * PMP/TLB coherence uses OpenSBI IPI events. Processing the event is
         * mandatory before returning to the interrupted group enclave; treating
         * MSIP as a scheduler tick would leave the sender waiting forever.
         */
        group_process_enclave_ipis();
        if (group_scheduler_ipi_reschedule_pending(
                cpu_get_enclave_id()))
          group_scheduler_ipi_switch(regs, cpu_get_enclave_id());
        return;
      }
      regs->mepc -= 4;
      sbi_sm_stop_enclave(regs, STOP_TIMER_INTERRUPT);
			break;
                     }
	case IRQ_S_SOFT:
	case IRQ_S_TIMER:
	case IRQ_S_EXT: {
      if (cpu_is_enclave_context() &&
          enclave_is_group_enclave(cpu_get_enclave_id())) {
        /*
         * Supervisor interrupts are not scheduler triggers. Keep the pending
         * bit for Linux, mask the corresponding enable while the enclave is
         * active, and let the next scheduler-owned MTIP restore the saved
         * group_run_hart host frame.
         */
        if (mcause == IRQ_S_SOFT)
          csr_clear(mie, MIP_SSIP);
        else if (mcause == IRQ_S_TIMER)
          csr_clear(mie, MIP_STIP);
        else
          csr_clear(mie, MIP_SEIP);
        return;
      }
      msg = "unhandled host-service interrupt";
      goto trap_error;
                    }
	default:
			msg = "unhandled external interrupt";
			goto trap_error;
		};
		return;
	}

	if (cpu_is_enclave_context() &&
	    enclave_is_group_enclave(cpu_get_enclave_id()) &&
	    mcause != CAUSE_SUPERVISOR_ECALL &&
	    mcause != CAUSE_MACHINE_ECALL) {
		if (mcause == CAUSE_ILLEGAL_INSTRUCTION) {
			/*
			 * Some platforms, including VisionFive2/JH7110, trap S-mode
			 * counter/time CSR reads to M-mode for OpenSBI emulation. Group
			 * runtimes call get_cycles64() during init_timer(), so do not
			 * classify every illegal instruction as a fatal enclave fault
			 * before OpenSBI has a chance to emulate CSR_CYCLE/CSR_TIME.
			 */
			rc = sbi_illegal_insn_handler(mtval, regs);
			if (!rc)
				return;
		}
		sbi_printf("[SM][fault] group trap: hart=%lu eid=%u cause=0x%lx tval=0x%lx mepc=0x%lx\n",
			   (unsigned long)current_hartid(),
			   cpu_get_enclave_id(),
			   (unsigned long)mcause,
			   (unsigned long)mtval,
			   (unsigned long)regs->mepc);
		sbi_sm_fault_enclave(regs, mcause, mcause, mtval);
		return;
	}

	switch (mcause) {
	case CAUSE_ILLEGAL_INSTRUCTION:
		rc  = sbi_illegal_insn_handler(mtval, regs);
		msg = "illegal instruction handler failed";
		break;
	case CAUSE_MISALIGNED_LOAD:
		rc = sbi_misaligned_load_handler(mtval, mtval2, mtinst, regs);
		msg = "misaligned load handler failed";
		break;
	case CAUSE_MISALIGNED_STORE:
		rc  = sbi_misaligned_store_handler(mtval, mtval2, mtinst, regs);
		msg = "misaligned store handler failed";
		break;
	case CAUSE_SUPERVISOR_ECALL:
	case CAUSE_MACHINE_ECALL:
		if (cpu_is_enclave_context() &&
		    enclave_is_group_enclave(cpu_get_enclave_id()) &&
		    regs->a7 == SBI_SET_TIMER) {
			/*
			 * Group enclaves use SM-owned timer preemption. Eyrie may still
			 * call legacy SBI_SET_TIMER from init_timer()/handle_timer_interrupt();
			 * accepting it here prevents the runtime from overwriting the
			 * scheduler's per-hart machine timer deadline.
			 */
			group_scheduler_runtime_timer_init(cpu_get_enclave_id());
			regs->a0 = 0;
			regs->mepc += 4;
			return;
		}
		rc  = sbi_ecall_handler(regs);
		msg = "ecall handler failed";
		break;
	default:
		/* If the trap came from S or U mode, redirect it there */
		trap.epc = regs->mepc;
		trap.cause = mcause;
		trap.tval = mtval;
		trap.tval2 = mtval2;
		trap.tinst = mtinst;
		rc = sbi_trap_redirect(regs, &trap);
		break;
	};

trap_error:
	if (rc)
		sbi_trap_error(msg, rc, mcause, mtval, mtval2, mtinst, regs);
}
