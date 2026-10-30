#define __PREPROCESSING__
#include "mm/vm_defs.h"
#include <asm/csr.h>
#include "util/asm_helpers.h"

.section .text
_start:
  // a1: dram_base
  // a2: dram_size
  // a3: runtime_base
  // a4: user_base
  // a5: free_base
  // a6: untrusted_ptr
  // a7: untrusted_size
  // t0: YXSTM_ptr
  // t1: YXSTM_size
  // t2: shared_utm_paddr (for Slave Enclave)
  // t3: shared_utm_size
  // t4: sec_mmio_paddr
  // t5: sec_mmio_size

  // use designated stack
  la sp, _estack

  //===========================================================================
  // FIRST: Save ALL parameters to stack BEFORE calling any debug function
  // This is critical because a0-a7 and t0-t6 are caller-saved registers
  // and will be clobbered by any function call.
  //===========================================================================
  addi sp, sp, -(REGBYTES*13)
  STORE a1, 0(sp)
  STORE a2, 1*REGBYTES(sp)
  STORE a3, 2*REGBYTES(sp)
  STORE a4, 3*REGBYTES(sp)
  STORE a5, 4*REGBYTES(sp)
  STORE a6, 5*REGBYTES(sp)
  STORE a7, 6*REGBYTES(sp)
  STORE t0, 7*REGBYTES(sp)
  STORE t1, 8*REGBYTES(sp)
  STORE t2, 9*REGBYTES(sp)
  STORE t3, 10*REGBYTES(sp)
  STORE t4, 11*REGBYTES(sp)
  STORE t5, 12*REGBYTES(sp)

  //===========================================================================
  // DEBUG: Print ALL parameters received from SM (including a6/a7)
  // a6 = untrusted_ptr (own UTM), a7 = untrusted_size
  // t2 = shared_utm_paddr, t3 = shared_utm_size
  //===========================================================================
  mv a0, a6                    // a0 = untrusted_ptr (own UTM)
  mv a1, a7                    // a1 = untrusted_size
  mv a2, t2                    // a2 = shared_utm_paddr
  mv a3, t3                    // a3 = shared_utm_size
  call debug_print_all_utm_params
  
  //===========================================================================
  // Restore parameters from stack for yx_load_runtime call
  // Note: a0 is not used by SM, so we set it to 0 (dummy)
  //===========================================================================
  li a0, 0                     // dummy parameter
  LOAD a1, 0(sp)
  LOAD a2, 1*REGBYTES(sp)
  LOAD a3, 2*REGBYTES(sp)
  LOAD a4, 3*REGBYTES(sp)
  LOAD a5, 4*REGBYTES(sp)
  LOAD a6, 5*REGBYTES(sp)
  LOAD a7, 6*REGBYTES(sp)
  LOAD t0, 7*REGBYTES(sp)
  LOAD t1, 8*REGBYTES(sp)
  LOAD t2, 9*REGBYTES(sp)
  LOAD t3, 10*REGBYTES(sp)
  LOAD t4, 11*REGBYTES(sp)
  LOAD t5, 12*REGBYTES(sp)

  //===========================================================================
  // Set up stack arguments for yx_load_runtime (parameters 9-14)
  // RISC-V calling convention: a0-a7 for first 8 args, stack for rest
  //
  // IMPORTANT: We need to preserve the 11-register save area for later use
  // by yx_eyrie_boot. So we allocate the 4-register stack arg area BELOW
  // the existing save area.
  //
  // Stack layout after this allocation:
  //   sp[0]  = YXSTM_ptr (stack arg for yx_load_runtime)
  //   sp[1]  = YXSTM_size
  //   sp[2]  = shared_utm_paddr
  //   sp[3]  = shared_utm_size
  //   sp[4]  = sec_mmio_paddr
  //   sp[5]  = sec_mmio_size
  //   sp[6]  = a1 (saved dram_base)      <- 13-register save area starts here
  //   sp[5]  = a2 (saved dram_size)
  //   ...
  //   sp[18] = t5 (saved sec_mmio_size)
  //===========================================================================
  addi sp, sp, -(REGBYTES*6)
  STORE t0, 0*REGBYTES(sp)     // YXSTM_ptr
  STORE t1, 1*REGBYTES(sp)     // YXSTM_size
  STORE t2, 2*REGBYTES(sp)     // shared_utm_paddr
  STORE t3, 3*REGBYTES(sp)     // shared_utm_size
  STORE t4, 4*REGBYTES(sp)     // sec_mmio_paddr
  STORE t5, 5*REGBYTES(sp)     // sec_mmio_size

  // call yx_load_runtime
  call yx_load_runtime

  // Restore stack pointer (remove stack arguments for yx_load_runtime)
  // Now sp points back to the 11-register save area
  addi sp, sp, (REGBYTES*6)

  // exit if errors
  bne a0, zero, exit

  // switch to va and jump to runtime code 
  li t0, RUNTIME_VA_START
  csrw stvec, t0  // store runtime start addresss in stvec 

  // construct new satp
  // below assembly and fences work on CVA6, for satp specifically.
  // FIXME: declutter if possible according to more testing
  la a0, root_page_table_storage  
  li a1, RISCV_PAGE_BITS
  li a2, SATP_MODE
  srl a0, a0, a1
  or a0, a0, a2

  // flush TLB's just in case
  fence.i
  sfence.vma

  //===========================================================================
  // Set up arguments for yx_eyrie_boot (including shared UTM params)
  // Restore from the saved area on stack (sp still points to the 11-register save area)
  // Note: sp[0] = a1 (dram_base), sp[5] = a6 (untrusted_ptr), etc.
  //===========================================================================
  LOAD a1, 0*REGBYTES(sp)      // dram_base
  LOAD a2, 1*REGBYTES(sp)      // dram_size
  LOAD a3, 2*REGBYTES(sp)      // runtime_base
  LOAD a4, 3*REGBYTES(sp)      // user_base
  LOAD a5, free_base_final     // free_base (updated by yx_load_runtime)
  LOAD a6, 5*REGBYTES(sp)      // untrusted_ptr
  LOAD a7, 6*REGBYTES(sp)      // untrusted_size
  LOAD t0, 7*REGBYTES(sp)      // YXSTM_ptr
  LOAD t1, 8*REGBYTES(sp)      // YXSTM_size
  LOAD t2, 9*REGBYTES(sp)      // shared_utm_paddr
  LOAD t3, 10*REGBYTES(sp)     // shared_utm_size
  LOAD t4, 11*REGBYTES(sp)     // sec_mmio_paddr
  LOAD t5, 12*REGBYTES(sp)     // sec_mmio_size
  
  // Deallocate the 13-register save area
  addi sp, sp, (REGBYTES*13)

  // flush TLB's just in case
  fence.i
  sfence.vma

  csrw satp, a0 // switch to virtual addresssing 
  sfence.vma

exit:
  call error_and_exit
