//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include "thread.h"

#if defined(__riscv_flen) && __riscv_flen == 64
#define FP_STORE(n, offset) "fsd f" #n ", " #offset "(%0)\n"
#define FP_LOAD(n, offset)  "fld f" #n ", " #offset "(%0)\n"

static void fp_save(uint64_t* regs, uintptr_t* fcsr)
{
  asm volatile(
      FP_STORE(0, 0) FP_STORE(1, 8) FP_STORE(2, 16) FP_STORE(3, 24)
      FP_STORE(4, 32) FP_STORE(5, 40) FP_STORE(6, 48) FP_STORE(7, 56)
      FP_STORE(8, 64) FP_STORE(9, 72) FP_STORE(10, 80) FP_STORE(11, 88)
      FP_STORE(12, 96) FP_STORE(13, 104) FP_STORE(14, 112) FP_STORE(15, 120)
      FP_STORE(16, 128) FP_STORE(17, 136) FP_STORE(18, 144) FP_STORE(19, 152)
      FP_STORE(20, 160) FP_STORE(21, 168) FP_STORE(22, 176) FP_STORE(23, 184)
      FP_STORE(24, 192) FP_STORE(25, 200) FP_STORE(26, 208) FP_STORE(27, 216)
      FP_STORE(28, 224) FP_STORE(29, 232) FP_STORE(30, 240) FP_STORE(31, 248)
      : : "r"(regs) : "memory");
  asm volatile("frcsr %0" : "=r"(*fcsr));
}

static void fp_restore(const uint64_t* regs, uintptr_t fcsr)
{
  asm volatile(
      FP_LOAD(0, 0) FP_LOAD(1, 8) FP_LOAD(2, 16) FP_LOAD(3, 24)
      FP_LOAD(4, 32) FP_LOAD(5, 40) FP_LOAD(6, 48) FP_LOAD(7, 56)
      FP_LOAD(8, 64) FP_LOAD(9, 72) FP_LOAD(10, 80) FP_LOAD(11, 88)
      FP_LOAD(12, 96) FP_LOAD(13, 104) FP_LOAD(14, 112) FP_LOAD(15, 120)
      FP_LOAD(16, 128) FP_LOAD(17, 136) FP_LOAD(18, 144) FP_LOAD(19, 152)
      FP_LOAD(20, 160) FP_LOAD(21, 168) FP_LOAD(22, 176) FP_LOAD(23, 184)
      FP_LOAD(24, 192) FP_LOAD(25, 200) FP_LOAD(26, 208) FP_LOAD(27, 216)
      FP_LOAD(28, 224) FP_LOAD(29, 232) FP_LOAD(30, 240) FP_LOAD(31, 248)
      : : "r"(regs) : "memory");
  asm volatile("fscsr %0" : : "r"(fcsr) : "memory");
}

#undef FP_STORE
#undef FP_LOAD
#endif

void swap_prev_fp_state(struct thread_state* thread)
{
#if defined(__riscv_flen) && __riscv_flen == 64
  struct fp_state current;
  uintptr_t mstatus = csr_read(CSR_MSTATUS);

  /* This image stores every FP register with fsd/fld. */
  if (!misa_extension('D'))
    return;
  csr_set(CSR_MSTATUS, MSTATUS_FS);
  fp_save(current.regs, &current.fcsr);
  fp_restore(thread->prev_fp_state.regs, thread->prev_fp_state.fcsr);
  thread->prev_fp_state = current;
  csr_write(CSR_MSTATUS, mstatus);
#else
  (void)thread;
#endif
}

static void save_fp_state(struct thread_state* thread)
{
#if defined(__riscv_flen) && __riscv_flen == 64
  uintptr_t mstatus = csr_read(CSR_MSTATUS);

  if (!misa_extension('D'))
    return;
  csr_set(CSR_MSTATUS, MSTATUS_FS);
  fp_save(thread->prev_fp_state.regs, &thread->prev_fp_state.fcsr);
  csr_write(CSR_MSTATUS, mstatus);
#else
  (void)thread;
#endif
}

static void restore_fp_state(const struct thread_state* thread)
{
#if defined(__riscv_flen) && __riscv_flen == 64
  uintptr_t mstatus = csr_read(CSR_MSTATUS);

  if (!misa_extension('D'))
    return;
  csr_set(CSR_MSTATUS, MSTATUS_FS);
  fp_restore(thread->prev_fp_state.regs, thread->prev_fp_state.fcsr);
  csr_write(CSR_MSTATUS, mstatus);
#else
  (void)thread;
#endif
}

int thread_extended_context_supported(void)
{
  /* Variable-length V register state is not part of thread_state yet. */
  if (misa_extension('V'))
    return 0;
  /* The current fixed-width image requires D; do not half-save F-only state. */
  if (misa_extension('F') && !misa_extension('D'))
    return 0;
#if !defined(__riscv_flen) || __riscv_flen != 64
  if (misa_extension('D') || misa_extension('F'))
    return 0;
#endif
  return 1;
}

void switch_vector_enclave(void){
  csr_write(mtvec, &trap_vector_enclave);
}

void switch_vector_host(void){
  csr_write(mtvec, &_trap_handler);
}

void swap_prev_mstatus(struct thread_state* thread, struct sbi_trap_regs* regs, uintptr_t current_mstatus) {
  //Time interrupts can occur in either user mode or supervisor mode
  uintptr_t mstatus_mask = MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_SPP |
                            MSTATUS_MPP | MSTATUS_FS | MSTATUS_SUM |
                            MSTATUS_MXR;

  uintptr_t tmp = thread->prev_mstatus;
  /*
   * Keep machine-wide policy bits from the currently executing SM/host
   * context. Only the explicitly audited enclave-visible return and S-mode
   * control bits travel with a scheduled enclave.
   */
  thread->prev_mstatus = current_mstatus;
  regs->mstatus = (current_mstatus & ~mstatus_mask) |
                  (tmp & mstatus_mask);
}

static void swap_prev_state_common(struct thread_state* thread,
                                   struct sbi_trap_regs* regs,
                                   int rewrite_resume_slot,
                                   int return_on_resume)
{
  int i;

  uintptr_t* prev = (uintptr_t*) &thread->prev_state;
  for(i=0; i<32; i++)
  {
    /* swap state */
    uintptr_t tmp = prev[i];
    prev[i] = ((unsigned long *)regs)[i];
    ((unsigned long *)regs)[i] = tmp;
  }

  if (rewrite_resume_slot)
    prev[0] = !return_on_resume;

  swap_prev_smode_csrs(thread);
  swap_prev_fp_state(thread);
}

/* Swaps state for the synchronous Keystone SBI stop/resume convention. */
void swap_prev_state(struct thread_state* thread, struct sbi_trap_regs* regs,
                     int return_on_resume)
{
  swap_prev_state_common(thread, regs, 1, return_on_resume);
}

/* Swaps an asynchronously interrupted context without changing any GPR. */
void swap_prev_state_exact(struct thread_state* thread,
                           struct sbi_trap_regs* regs)
{
  swap_prev_state_common(thread, regs, 0, 0);

  /* slot is the trap-frame image of architectural x0 and must stay zero. */
  thread->prev_state.slot = 0;
  regs->zero = 0;
}

/* Swaps all s-mode csrs defined in 1.10 standard */
/* TODO: Right now we are only handling the ones that our test
   platforms support. Realistically we should have these behind
   defines for extensions (ex: N extension)*/
void swap_prev_smode_csrs(struct thread_state*
thread){

  uintptr_t tmp;

#define LOCAL_SWAP_CSR(csrname) \
  tmp = thread->prev_csrs.csrname;                 \
  thread->prev_csrs.csrname = csr_read(csrname);   \
  csr_write(csrname, tmp);

  LOCAL_SWAP_CSR(sstatus);
  // These only exist with N extension.
  //LOCAL_SWAP_CSR(sedeleg);
  //LOCAL_SWAP_CSR(sideleg);
  LOCAL_SWAP_CSR(sie);
  LOCAL_SWAP_CSR(stvec);
  LOCAL_SWAP_CSR(scounteren);
  LOCAL_SWAP_CSR(sscratch);
  LOCAL_SWAP_CSR(sepc);
  LOCAL_SWAP_CSR(scause);
  LOCAL_SWAP_CSR(sbadaddr);
  LOCAL_SWAP_CSR(sip);
  LOCAL_SWAP_CSR(satp);

  /*
   * Group members use distinct page-table roots but currently share ASID 0.
   * A SATP write alone does not invalidate translations associated with the
   * old root.  Flush after every SATP exchange so a resumed member cannot use
   * another member's stale private-EPM translation (and so the host cannot
   * inherit an enclave translation on a scheduler service boundary).
   */
  asm volatile("sfence.vma" ::: "memory");

#undef LOCAL_SWAP_CSR
}

static void save_smode_csrs(struct thread_state* thread)
{
  thread->prev_csrs.sstatus = csr_read(sstatus);
  thread->prev_csrs.sie = csr_read(sie);
  thread->prev_csrs.stvec = csr_read(stvec);
  thread->prev_csrs.scounteren = csr_read(scounteren);
  thread->prev_csrs.sscratch = csr_read(sscratch);
  thread->prev_csrs.sepc = csr_read(sepc);
  thread->prev_csrs.scause = csr_read(scause);
  thread->prev_csrs.sbadaddr = csr_read(sbadaddr);
  thread->prev_csrs.sip = csr_read(sip);
  thread->prev_csrs.satp = csr_read(satp);
}

static void restore_smode_csrs(const struct thread_state* thread)
{
  csr_write(sstatus, thread->prev_csrs.sstatus);
  csr_write(sie, thread->prev_csrs.sie);
  csr_write(stvec, thread->prev_csrs.stvec);
  csr_write(scounteren, thread->prev_csrs.scounteren);
  csr_write(sscratch, thread->prev_csrs.sscratch);
  csr_write(sepc, thread->prev_csrs.sepc);
  csr_write(scause, thread->prev_csrs.scause);
  csr_write(sbadaddr, thread->prev_csrs.sbadaddr);
  csr_write(sip, thread->prev_csrs.sip);
  csr_write(satp, thread->prev_csrs.satp);
  asm volatile("sfence.vma" ::: "memory");
}

void thread_state_save_exact_profiled(struct thread_state* thread,
                                      const struct sbi_trap_regs* regs,
                                      struct thread_state_profile* profile)
{
  uintptr_t* saved = (uintptr_t*)&thread->prev_state;
  const uintptr_t* current = (const uintptr_t*)regs;
  uint64_t started = 0;
  int i;

  if (profile) {
    profile->gpr_cycles = 0;
    profile->smode_csr_cycles = 0;
    profile->fp_cycles = 0;
    started = csr_read(CSR_MCYCLE);
  }
  for (i = 0; i < 32; i++)
    saved[i] = current[i];
  thread->prev_state.slot = 0;
  thread->prev_mepc = regs->mepc;
  thread->prev_mstatus = regs->mstatus;
  if (profile) {
    profile->gpr_cycles += csr_read(CSR_MCYCLE) - started;
    started = csr_read(CSR_MCYCLE);
  }
  save_smode_csrs(thread);
  if (profile) {
    profile->smode_csr_cycles += csr_read(CSR_MCYCLE) - started;
    started = csr_read(CSR_MCYCLE);
  }
  save_fp_state(thread);
  if (profile)
    profile->fp_cycles += csr_read(CSR_MCYCLE) - started;
  asm volatile("fence rw,rw" ::: "memory");
}

void thread_state_restore_exact_profiled(
    const struct thread_state* thread, struct sbi_trap_regs* regs,
    struct thread_state_profile* profile)
{
  const uintptr_t* saved = (const uintptr_t*)&thread->prev_state;
  uintptr_t* current = (uintptr_t*)regs;
  uintptr_t mstatus_mask = MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_SPP |
                           MSTATUS_MPP | MSTATUS_FS | MSTATUS_SUM |
                           MSTATUS_MXR;
  uintptr_t machine_mstatus = regs->mstatus;
  uint64_t started = 0;
  int i;

  if (profile) {
    profile->gpr_cycles = 0;
    profile->smode_csr_cycles = 0;
    profile->fp_cycles = 0;
    started = csr_read(CSR_MCYCLE);
  }
  asm volatile("fence rw,rw" ::: "memory");
  for (i = 0; i < 32; i++)
    current[i] = saved[i];
  regs->zero = 0;
  if (profile) {
    profile->gpr_cycles += csr_read(CSR_MCYCLE) - started;
    started = csr_read(CSR_MCYCLE);
  }
  restore_smode_csrs(thread);
  if (profile) {
    profile->smode_csr_cycles += csr_read(CSR_MCYCLE) - started;
    started = csr_read(CSR_MCYCLE);
  }
  restore_fp_state(thread);
  if (profile)
    profile->fp_cycles += csr_read(CSR_MCYCLE) - started;
  regs->mepc = thread->prev_mepc;
  regs->mstatus = (machine_mstatus & ~mstatus_mask) |
                  (thread->prev_mstatus & mstatus_mask);
}

void thread_state_save_exact(struct thread_state* thread,
                             const struct sbi_trap_regs* regs)
{
  thread_state_save_exact_profiled(thread, regs, 0);
}

void thread_state_restore_exact(const struct thread_state* thread,
                                struct sbi_trap_regs* regs)
{
  thread_state_restore_exact_profiled(thread, regs, 0);
}

void swap_prev_mepc(struct thread_state* thread, struct sbi_trap_regs* regs, uintptr_t current_mepc)
{
  uintptr_t tmp = thread->prev_mepc;
  thread->prev_mepc = current_mepc;
  regs->mepc = tmp;
}


void clean_state(struct thread_state* state){
  int i;
  uintptr_t* prev = (uintptr_t*) &state->prev_state;
  for(i=0; i<32; i++)
  {
    prev[i] = 0;
  }

  state->prev_mpp = -1; // 0x800;
  state->prev_mepc = 0;
  state->prev_mstatus = 0;
#if defined(__riscv_flen) && __riscv_flen == 64
  for (i = 0; i < 32; i++)
    state->prev_fp_state.regs[i] = 0;
  state->prev_fp_state.fcsr = 0;
#endif
  clean_smode_csrs(state);
}

void clean_smode_csrs(struct thread_state* state){

  state->prev_csrs.sstatus = 0;

  // We can't read these or set these from M-mode?
  state->prev_csrs.sedeleg = 0;
  state->prev_csrs.sideleg = 0;

  state->prev_csrs.sie = 0;
  state->prev_csrs.stvec = 0;
  // For now we take whatever the OS was doing
  state->prev_csrs.scounteren = csr_read(scounteren);
  state->prev_csrs.sscratch = 0;
  state->prev_csrs.sepc = 0;
  state->prev_csrs.scause = 0;
  state->prev_csrs.sbadaddr = 0;
  state->prev_csrs.sip = 0;
  state->prev_csrs.satp = 0;

}
