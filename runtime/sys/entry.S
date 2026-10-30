#include <asm/csr.h>
#include "util/asm_helpers.h"

.text
//entry point to the runtime!
.altmacro
.macro SAVE_ALL_BUT_SP
  addi sp, sp, -ENCL_CONTEXT_SIZE
  STORE ra, 1*REGBYTES(sp)
  STORE gp, 3*REGBYTES(sp)
  STORE tp, 4*REGBYTES(sp)
  STORE t0, 5*REGBYTES(sp)
  STORE t1, 6*REGBYTES(sp)
  STORE t2, 7*REGBYTES(sp)
  STORE s0, 8*REGBYTES(sp)
  STORE s1, 9*REGBYTES(sp)
  STORE a0, 10*REGBYTES(sp)
  STORE a1, 11*REGBYTES(sp)
  STORE a2, 12*REGBYTES(sp)
  STORE a3, 13*REGBYTES(sp)
  STORE a4, 14*REGBYTES(sp)
  STORE a5, 15*REGBYTES(sp)
  STORE a6, 16*REGBYTES(sp)
  STORE a7, 17*REGBYTES(sp)
  STORE s2, 18*REGBYTES(sp)
  STORE s3, 19*REGBYTES(sp)
  STORE s4, 20*REGBYTES(sp)
  STORE s5, 21*REGBYTES(sp)
  STORE s6, 22*REGBYTES(sp)
  STORE s7, 23*REGBYTES(sp)
  STORE s8, 24*REGBYTES(sp)
  STORE s9, 25*REGBYTES(sp)
  STORE s10, 26*REGBYTES(sp)
  STORE s11, 27*REGBYTES(sp)
  STORE t3, 28*REGBYTES(sp)
  STORE t4, 29*REGBYTES(sp)
  STORE t5, 30*REGBYTES(sp)
  STORE t6, 31*REGBYTES(sp)
.endm

.macro CLEAR_ALL_BUT_SP
  mv ra, x0
  mv gp, x0
  mv tp, x0
  mv t0, x0
  mv t1, x0
  mv t2, x0
  mv s0, x0
  mv s1, x0
  mv a0, x0
  mv a1, x0
  mv a2, x0
  mv a3, x0
  mv a4, x0
  mv a5, x0
  mv a6, x0
  mv a7, x0
  mv s2, x0
  mv s3, x0
  mv s4, x0
  mv s5, x0
  mv s6, x0
  mv s7, x0
  mv s8, x0
  mv s9, x0
  mv s10, x0
  mv s11, x0
  mv t3, x0
  mv t4, x0
  mv t5, x0
  mv t6, x0
.endm

.macro RESTORE_ALL_BUT_SP

  // restore context
  LOAD ra, 1*REGBYTES(sp)
  LOAD gp, 3*REGBYTES(sp)
  LOAD tp, 4*REGBYTES(sp)
  LOAD t0, 5*REGBYTES(sp)
  LOAD t1, 6*REGBYTES(sp)
  LOAD t2, 7*REGBYTES(sp)
  LOAD s0, 8*REGBYTES(sp)
  LOAD s1, 9*REGBYTES(sp)
  LOAD a0, 10*REGBYTES(sp)
  LOAD a1, 11*REGBYTES(sp)
  LOAD a2, 12*REGBYTES(sp)
  LOAD a3, 13*REGBYTES(sp)
  LOAD a4, 14*REGBYTES(sp)
  LOAD a5, 15*REGBYTES(sp)
  LOAD a6, 16*REGBYTES(sp)
  LOAD a7, 17*REGBYTES(sp)
  LOAD s2, 18*REGBYTES(sp)
  LOAD s3, 19*REGBYTES(sp)
  LOAD s4, 20*REGBYTES(sp)
  LOAD s5, 21*REGBYTES(sp)
  LOAD s6, 22*REGBYTES(sp)
  LOAD s7, 23*REGBYTES(sp)
  LOAD s8, 24*REGBYTES(sp)
  LOAD s9, 25*REGBYTES(sp)
  LOAD s10, 26*REGBYTES(sp)
  LOAD s11, 27*REGBYTES(sp)
  LOAD t3, 28*REGBYTES(sp)
  LOAD t4, 29*REGBYTES(sp)
  LOAD t5, 30*REGBYTES(sp)
  LOAD t6, 31*REGBYTES(sp)
  addi sp, sp, ENCL_CONTEXT_SIZE
.endm

_start:
  /* set up runtime stack */
  la sp, kernel_stack_end

  /* set sscratch zero so that the trap handler can
   * notice that the trap is from S-mode */
  csrw sscratch, x0

  sfence.vma
  
  //===========================================================================
  // Save ALL parameters for yx_eyrie_boot (a0-a7, t0-t5)
  // RISC-V calling convention: a0-a7 are caller-saved, so we must save them
  // before calling any function (like debug_print_entry_shared_utm_params)
  //
  // Parameters from SM:
  //   a0: dummy (return value from SBI)
  //   a1: dram_base
  //   a2: dram_size
  //   a3: runtime_paddr
  //   a4: user_paddr
  //   a5: free_paddr
  //   a6: utm_vaddr
  //   a7: utm_size
  //   t0: YXSTM_ptr
  //   t1: YXSTM_size
  //   t2: shared_utm_paddr (for Slave Enclave)
  //   t3: shared_utm_size
  //   t4: sec_mmio_paddr
  //   t5: sec_mmio_size
  //===========================================================================
  addi sp, sp, -(REGBYTES*14)
  STORE a0, 0*REGBYTES(sp)
  STORE a1, 1*REGBYTES(sp)
  STORE a2, 2*REGBYTES(sp)
  STORE a3, 3*REGBYTES(sp)
  STORE a4, 4*REGBYTES(sp)
  STORE a5, 5*REGBYTES(sp)
  STORE a6, 6*REGBYTES(sp)
  STORE a7, 7*REGBYTES(sp)
  STORE t0, 8*REGBYTES(sp)
  STORE t1, 9*REGBYTES(sp)
  STORE t2, 10*REGBYTES(sp)
  STORE t3, 11*REGBYTES(sp)
  STORE t4, 12*REGBYTES(sp)
  STORE t5, 13*REGBYTES(sp)
  
  //===========================================================================
  // DEBUG: Print shared UTM parameters before calling yx_eyrie_boot
  // t2 = shared_utm_paddr, t3 = shared_utm_size
  //===========================================================================
  mv a0, t2                    // a0 = shared_utm_paddr
  mv a1, t3                    // a1 = shared_utm_size
  jal debug_print_entry_shared_utm_params
  
  //===========================================================================
  // Restore ALL parameters from stack
  //===========================================================================
  LOAD a0, 0*REGBYTES(sp)
  LOAD a1, 1*REGBYTES(sp)
  LOAD a2, 2*REGBYTES(sp)
  LOAD a3, 3*REGBYTES(sp)
  LOAD a4, 4*REGBYTES(sp)
  LOAD a5, 5*REGBYTES(sp)
  LOAD a6, 6*REGBYTES(sp)
  LOAD a7, 7*REGBYTES(sp)
  LOAD t0, 8*REGBYTES(sp)
  LOAD t1, 9*REGBYTES(sp)
  LOAD t2, 10*REGBYTES(sp)
  LOAD t3, 11*REGBYTES(sp)
  LOAD t4, 12*REGBYTES(sp)
  LOAD t5, 13*REGBYTES(sp)
  
  //===========================================================================
  // Call yx_eyrie_boot with 14 parameters
  // RISC-V calling convention: a0-a7 for first 8 args, stack for rest
  // 
  // Parameters in registers (restored above):
  //   a0: dummy (return value from SBI)
  //   a1: dram_base
  //   a2: dram_size
  //   a3: runtime_paddr
  //   a4: user_paddr
  //   a5: free_paddr
  //   a6: utm_vaddr
  //   a7: utm_size
  //
  // Parameters 9-14 need to be passed on stack:
  //   stack[0]: YXSTM_vaddr (t0)
  //   stack[1]: YXSTM_size (t1)
  //   stack[2]: shared_utm_paddr (t2)
  //   stack[3]: shared_utm_size (t3)
  //   stack[4]: sec_mmio_paddr (t4)
  //   stack[5]: sec_mmio_size (t5)
  //
  // Adjust stack pointer to set up stack arguments
  //===========================================================================
  // First, deallocate the 14-register save area
  addi sp, sp, (REGBYTES*14)
  // Now allocate space for 6 stack arguments
  addi sp, sp, -(REGBYTES*6)
  STORE t0, 0*REGBYTES(sp)
  STORE t1, 1*REGBYTES(sp)
  STORE t2, 2*REGBYTES(sp)
  STORE t3, 3*REGBYTES(sp)
  STORE t4, 4*REGBYTES(sp)
  STORE t5, 5*REGBYTES(sp)
  
  jal yx_eyrie_boot
  addi sp, sp, (REGBYTES*6)
  sfence.vma

  /* set spp to user */
  li t0, 0x100
  csrrc x0, sstatus, t0

  /* start running enclave */
  csrrw sp, sscratch, sp
  li a0, 0 // passed as rtld_fini to entry point/ __libc_start_main
  sret

.align 6
encl_trap_handler:
  .global encl_trap_handler

/* TODO we may want to explicitly disable the FPU here ala linux */

  csrrw sp, sscratch, sp
  bnez sp, __save_context
  /* if trap is from kernel, restore sp */
  csrr sp, sscratch

__save_context:
  /* save previous context */
  SAVE_ALL_BUT_SP

  csrrw t0, sscratch, x0           # t0 <- previous sp
  STORE t0, 2*REGBYTES(sp)         # previous sp

  csrr t0, sepc
  STORE t0, (sp)

  csrr t0, sstatus
  STORE t0, 32*REGBYTES(sp)

  csrr t0, sbadaddr
  STORE t0, 33*REGBYTES(sp)

  csrr s2, scause

  bge s2, zero, 1f

  /* handle interrupts */

  /* clear the MSB */
  slli s2, s2, 1
  srli s2, s2, 1
  STORE s2, 34*REGBYTES(sp)

  /* clear enclave context */
  CLEAR_ALL_BUT_SP

  mv a0, sp

  la t0, handle_interrupts
  jalr t0

  j return_to_encl
1:
  /* handle exceptions */
  STORE s2, 34*REGBYTES(sp)

  /* SR_SUM (0x40000): allow S-mode to access U-mapped pages (YXSTM, user stack).
   * Required when runtime touches YXSTM during syscall handling. */
  li t0, 0x40000
  csrs sstatus, t0

  la t0, rt_trap_table
  sll t1, s2, LOG_REGBYTES
  add t1, t0, t1
  LOAD t1, 0(t1)

  mv a0, sp

  jalr t1

return_to_encl:
  LOAD t0, (sp)
  csrw sepc, t0


  // restore user stack
  LOAD t0, 2*REGBYTES(sp)
  csrw sscratch, t0

  RESTORE_ALL_BUT_SP

  csrrw sp, sscratch, sp
  sret

not_implemented:
  csrr a0, scause
  li a7, 1111
  ecall

  .section ".data"
rt_trap_table:
  .global rt_trap_table
  .align 6
  WORD not_implemented_fatal //0
  WORD not_implemented_fatal //1
  WORD not_implemented_fatal //2
  WORD not_implemented_fatal //3
  WORD not_implemented_fatal //4
  WORD not_implemented_fatal //5
  WORD not_implemented_fatal //6
  WORD not_implemented_fatal //7
  WORD handle_syscall //8
  WORD not_implemented_fatal //9
  WORD not_implemented_fatal //10
  WORD not_implemented_fatal //11
  WORD rt_page_fault //12: fetch page fault - non-executable/unmapped code
  WORD rt_page_fault //13: load page fault - stack/heap access
  WORD not_implemented_fatal //14
  WORD rt_page_fault //15: store page fault - stack/heap access
