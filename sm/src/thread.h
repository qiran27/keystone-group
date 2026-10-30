//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __THREAD_H__
#define __THREAD_H__

#include <sbi/sbi_types.h>
#include <sbi/sbi_trap.h>
struct ctx
{
  uintptr_t slot;
  uintptr_t ra;
  uintptr_t sp;
  uintptr_t gp;
  uintptr_t tp;
  uintptr_t t0;
  uintptr_t t1;
  uintptr_t t2;
  uintptr_t s0;
  uintptr_t s1;
  uintptr_t a0;
  uintptr_t a1;
  uintptr_t a2;
  uintptr_t a3;
  uintptr_t a4;
  uintptr_t a5;
  uintptr_t a6;
  uintptr_t a7;
  uintptr_t s2;
  uintptr_t s3;
  uintptr_t s4;
  uintptr_t s5;
  uintptr_t s6;
  uintptr_t s7;
  uintptr_t s8;
  uintptr_t s9;
  uintptr_t s10;
  uintptr_t s11;
  uintptr_t t3;
  uintptr_t t4;
  uintptr_t t5;
  uintptr_t t6;
} __packed;

typedef char thread_ctx_must_match_32_gprs[
    sizeof(struct ctx) == 32 * sizeof(uintptr_t) ? 1 : -1];

struct csrs
{
  /*
   * Per-enclave S-mode visible CSR image.
   *
   * G-stage audit against Coffer:
   * - Coffer's Context saves GPRs plus mstatus/mepc and selected M-mode
   *   control CSRs such as mideleg/medeleg/mcounteren.
   * - Keystone's enclave runtime executes in S-mode, so the per-enclave state
   *   that must move with a group scheduler switch is the S-mode CSR set below.
   * - sbadaddr is the toolchain name used here for stval.
   * - PMP entries are not saved here; group schedule-in reconstructs the
   *   current private EPM/YXSTM permissions.
   * - RV64 F/D registers and fcsr are saved in fp_state when the SM is built
   *   with a 64-bit floating-point register file.
   * - Vector register state is variable length and is not represented here;
   *   the group scheduler therefore rejects direct switching when V is present.
   * - mcounteren is SM-owned policy; scounteren is part of this S-mode image.
   */
  uintptr_t sstatus;    //Supervisor status register.
  uintptr_t sedeleg;    //Supervisor exception delegation register.
  uintptr_t sideleg;    //Supervisor interrupt delegation register.
  uintptr_t sie;        //Supervisor interrupt-enable register.
  uintptr_t stvec;      //Supervisor trap handler base address.
  uintptr_t scounteren; //Supervisor counter enable

  /*  Supervisor Trap Handling */
  uintptr_t sscratch;   //Scratch register for supervisor trap handlers.
  uintptr_t sepc;       //Supervisor exception program counter.
  uintptr_t scause;     //Supervisor trap cause.
  // NOTE: This is stval in the privileged spec; sbadaddr is the local toolchain name.
  uintptr_t sbadaddr;   //Supervisor bad address.
  uintptr_t sip;        //Supervisor interrupt pending.

  /*  Supervisor Protection and Translation */
  uintptr_t satp;     //Page-table base register.

};

#if defined(__riscv_flen) && __riscv_flen == 64
struct fp_state
{
  uint64_t regs[32];
  uintptr_t fcsr;
};
#endif

/* enclave thread state */
struct thread_state
{
  int prev_mpp;
  uintptr_t prev_mepc;
  uintptr_t prev_mstatus;
  struct csrs prev_csrs;
  struct ctx prev_state;
#if defined(__riscv_flen) && __riscv_flen == 64
  struct fp_state prev_fp_state;
#endif
};

struct thread_state_profile
{
  uint64_t gpr_cycles;
  uint64_t smode_csr_cycles;
  uint64_t fp_cycles;
};

/* swap previous and current thread states */
void swap_prev_state(struct thread_state* state, struct sbi_trap_regs* regs, int return_on_resume);
void swap_prev_state_exact(struct thread_state* state,
                           struct sbi_trap_regs* regs);
void swap_prev_mepc(struct thread_state* state, struct sbi_trap_regs* regs, uintptr_t mepc);
void swap_prev_mstatus(struct thread_state* state, struct sbi_trap_regs* regs, uintptr_t mstatus);
void swap_prev_smode_csrs(struct thread_state* thread);
void swap_prev_fp_state(struct thread_state* thread);

/*
 * One-way context operations for the group scheduler.
 *
 * Keystone's historical helpers exchange a trap frame with thread_state,
 * which is appropriate for a host <-> enclave pair.  A per-hart scheduler
 * has three independent owners (HOST, current member, next member), so it
 * must save and restore explicitly instead of carrying an unrelated frame
 * through the next member's storage.
 */
void thread_state_save_exact(struct thread_state* state,
                             const struct sbi_trap_regs* regs);
void thread_state_restore_exact(const struct thread_state* state,
                                struct sbi_trap_regs* regs);
void thread_state_save_exact_profiled(struct thread_state* state,
                                      const struct sbi_trap_regs* regs,
                                      struct thread_state_profile* profile);
void thread_state_restore_exact_profiled(
    const struct thread_state* state, struct sbi_trap_regs* regs,
    struct thread_state_profile* profile);
int thread_extended_context_supported(void);

void switch_vector_enclave(void);
void switch_vector_host(void);
extern void trap_vector_enclave(void);
extern void _trap_handler(void);

/* Clean state generation */
void clean_state(struct thread_state* state);
void clean_smode_csrs(struct thread_state* state);
#endif /* thread */
