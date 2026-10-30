#include <asm/csr.h>

#include "util/printf.h"
#include "sys/interrupt.h"
#include "call/syscall.h"
#include "mm/vm.h"
#include "util/string.h"
#include "call/sbi.h"
#include "mm/freemem.h"
#include "mm/mm.h"
#include "sys/env.h"
#include "mm/paging.h"
#include "loader/elf.h"
#include "loader/loader.h"

/* defined in vm.h */
extern uintptr_t shared_buffer;
extern uintptr_t shared_buffer_size;

extern uintptr_t YXS_trusted_memory;
extern uintptr_t YXS_trusted_memory_size;
extern uintptr_t sec_mmio_base;
extern uintptr_t sec_mmio_size;

extern unsigned char kg[64];

/* initial memory layout */
uintptr_t utm_base;
size_t utm_size;

/* defined in entry.S */
extern void* encl_trap_handler;

static inline void enable_runtime_user_memory_access(void)
{
  /*
   * YXSTM is mapped with PTE_U for eapp direct access. Runtime (S-mode) must
   * set SR_SUM to access U-mapped regions (YXSTM, user stack). Also set in
   * entry.S trap handler before dispatching to syscall handlers.
   */
  csr_write(sstatus, csr_read(sstatus) | SR_SUM);
}

static inline uintptr_t current_satp_root_pa(void)
{
#if __riscv_xlen == 64
  return (csr_read(satp) & MASK(44)) << RISCV_PAGE_BITS;
#else
  return (csr_read(satp) & MASK(22)) << RISCV_PAGE_BITS;
#endif
}

static void validate_group_page_table_or_exit(void)
{
  uintptr_t ret = sbi_group_validate_page_table(current_satp_root_pa());
  if (ret != 0) {
    printf("[runtime] SM group page-table validation failed: 0x%lx\n", ret);
    sbi_exit_enclave(-1);
  }
  group_page_table_policy_enable();
}

/*
 * Debug function to print shared UTM parameters in entry.S before calling yx_eyrie_boot
 * Called from entry.S
 */
void debug_print_entry_shared_utm_params(uintptr_t shared_utm_paddr, uintptr_t shared_utm_size) {
  // printf("[entry.S] DEBUG: Before yx_eyrie_boot - shared UTM params:\n");
  // printf("[entry.S]   t2 (shared_utm_paddr) = 0x%lx\n", shared_utm_paddr);
  // printf("[entry.S]   t3 (shared_utm_size)  = %lu (0x%lx)\n", shared_utm_size, shared_utm_size);
}

int verify_and_load_elf_file(uintptr_t ptr, size_t file_size, bool is_eapp) {
  int ret = 0;
  // validate elf
  if (((void*) ptr == NULL) || (file_size <= 0)) {
    return -1;
  }

  // create elf struct
  elf_t elf_file;
  ret = elf_newFile((void*) ptr, file_size, &elf_file);
  if (ret < 0) {
    return ret;
  }

  // parse and load elf file
  ret = loadElf(&elf_file, 1);

  if (is_eapp) { // setup entry point
    uintptr_t entry = elf_getEntryPoint(&elf_file);
    csr_write(sepc, entry);
  }
  return ret;
}

/* initialize free memory with a simple page allocator*/
void
init_freemem()
{
  spa_init(freemem_va_start, freemem_size);
}

/* initialize user stack */
void
init_user_stack_and_env(ELF(Ehdr) *hdr)
{
  void* user_sp = (void*) EYRIE_USER_STACK_START;
  size_t count;
  uintptr_t stack_end = EYRIE_USER_STACK_END;
  size_t stack_count = EYRIE_USER_STACK_SIZE >> RISCV_PAGE_BITS;

  // allocated stack pages right below the runtime
  count = alloc_pages(vpn(stack_end), stack_count,
      PTE_R | PTE_W | PTE_D | PTE_A | PTE_U);

  assert(count == stack_count);

  // setup user stack env/aux
  user_sp = setup_start(user_sp, hdr);

  // prepare user sp
  csr_write(sscratch, user_sp);
}

void
eyrie_boot(uintptr_t dummy, // $a0 contains the return value from the SBI
           uintptr_t dram_base,
           uintptr_t dram_size,
           uintptr_t runtime_paddr,
           uintptr_t user_paddr,
           uintptr_t free_paddr,
           uintptr_t utm_vaddr,
           uintptr_t utm_size)
{
  /* set initial values */
  load_pa_start = dram_base;
  private_region_va_start = EYRIE_LOAD_START;
  private_region_size = dram_size;
  root_page_table = (pte*) __va(csr_read(satp) << RISCV_PAGE_BITS);
  enable_runtime_user_memory_access();
  shared_buffer = EYRIE_UNTRUSTED_START;
  shared_buffer_size = utm_size;
  runtime_va_start = (uintptr_t) &rt_base;
  kernel_offset = runtime_va_start - runtime_paddr;

  debug("ROOT PAGE TABLE: 0x%lx", root_page_table);
  debug("UTM : 0x%lx-0x%lx (%u KB)", utm_vaddr, utm_vaddr+utm_size, utm_size/1024);
  debug("DRAM: 0x%lx-0x%lx (%u KB)", dram_base, dram_base + dram_size, dram_size/1024);
  debug("USER: 0x%lx-0x%lx (%u KB)", user_paddr, free_paddr, (free_paddr-user_paddr)/1024);

  /* set trap vector */
  csr_write(stvec, &encl_trap_handler);
  freemem_va_start = __va(free_paddr);
  freemem_size = dram_base + dram_size - free_paddr;

  debug("FREE: 0x%lx-0x%lx (%u KB), va 0x%lx", free_paddr, dram_base + dram_size, freemem_size/1024, freemem_va_start);

  /* initialize free memory */
  init_freemem();

  /* load eapp elf */
  assert(!verify_and_load_elf_file(__va(user_paddr), free_paddr-user_paddr, true));

  /* free leaking memory */
  // TODO: clean up after loader -- entire file no longer needed
  // TODO: load elf file doesn't map some pages; those can be re-used. runtime and eapp.

  //TODO: This should be set by walking the userspace vm and finding
  //highest used addr. Instead we start partway through the anon space
  set_program_break(EYRIE_ANON_REGION_START + (1024 * 1024 * 1024));

  #ifdef USE_PAGING
  init_paging(user_paddr, free_paddr);
  #endif /* USE_PAGING */

  /* initialize user stack */
  init_user_stack_and_env((ELF(Ehdr) *) __va(user_paddr));

  /* prepare edge & system calls */
  init_edge_internals();

  /* set timer */
  init_timer();

  validate_group_page_table_or_exit();

  /* Keep SR_SUM enabled and turn on the FPU before entering user mode */
  csr_write(sstatus, csr_read(sstatus) | 0x6000 | SR_SUM);

  debug("eyrie boot finished. drop to the user land ...");
  /* booting all finished, droping to the user land */
  return;
}

void
yx_eyrie_boot(uintptr_t dummy, // $a0 contains the return value from the SBI
              uintptr_t dram_base,
              uintptr_t dram_size,
              uintptr_t runtime_paddr,
              uintptr_t user_paddr,
              uintptr_t free_paddr,
              uintptr_t utm_vaddr,
              uintptr_t utm_size,
              uintptr_t YXSTM_vaddr,
              uintptr_t YXSTM_size,
              uintptr_t shared_utm_paddr,  // $t2: shared UTM physical address (for Slave Enclave)
              uintptr_t shared_utm_size_param,   // $t3: shared UTM size
              uintptr_t sec_paddr,
              uintptr_t sec_size_param)
{
  (void)sec_paddr;
  //===========================================================================
  // DEBUG: Print shared UTM parameters received from entry.S
  //===========================================================================
  // printf("[yx_eyrie_boot] DEBUG: Function entry - shared UTM params:\n");
  // printf("[yx_eyrie_boot]   shared_utm_paddr      = 0x%lx\n", shared_utm_paddr);
  // printf("[yx_eyrie_boot]   shared_utm_size_param = %lu (0x%lx)\n", shared_utm_size_param, shared_utm_size_param);
  // printf("[yx_eyrie_boot]   utm_vaddr (own UTM)   = 0x%lx\n", utm_vaddr);
  // printf("[yx_eyrie_boot]   utm_size (own UTM)    = %lu\n", utm_size);
  // printf("[yx_eyrie_boot]   YXSTM_vaddr           = 0x%lx\n", YXSTM_vaddr);
  // printf("[yx_eyrie_boot]   YXSTM_size            = %lu\n", YXSTM_size);
  //===========================================================================

  /* set initial values */
  load_pa_start = dram_base;
  private_region_va_start = EYRIE_LOAD_START;
  private_region_size = dram_size;
  root_page_table = (pte*) __va(csr_read(satp) << RISCV_PAGE_BITS);
  enable_runtime_user_memory_access();

  /*
   * Shared UTM Support for Dual Enclave Parallel Encryption
   * ========================================================
   *
   * If shared_utm_size_param > 0, this is a Slave Enclave that should use
   * the Main Enclave's UTM (shared UTM) instead of its own small UTM.
   *
   * The shared UTM physical address is passed from SM via $t2 register.
   * We map it to EYRIE_SHARED_UTM_START virtual address and use it as
   * the shared_buffer for edge calls (copy_from_shared, copy_to_shared).
   *
   * This allows Slave Enclave to directly access Main's 64MB UTM instead
   * of being limited to its own 1MB UTM.
   *
   * CRITICAL: OCALL communication always uses the enclave's own UTM
   * ===============================================================
   *
   * The ocall_buffer always points to EYRIE_UNTRUSTED_START (enclave's own UTM).
   * This is because:
   * 1. Host writes edge_call structures to the enclave's own UTM
   * 2. Runtime reads edge_call from own UTM and writes response to own UTM
   * 3. shared_buffer is only for data transfer (copy_from_shared, copy_to_shared)
   *
   * In shared UTM mode:
   *   - ocall_buffer = EYRIE_UNTRUSTED_START (own 1MB UTM) - for OCALL
   *   - shared_buffer = EYRIE_SHARED_UTM_START (Main's 64MB UTM) - for data
   *
   * In regular mode:
   *   - ocall_buffer = shared_buffer = EYRIE_UNTRUSTED_START (own UTM)
   */

  /* OCALL buffer always points to enclave's own UTM */
  ocall_buffer = EYRIE_UNTRUSTED_START;
  ocall_buffer_size = utm_size;

  if (shared_utm_size_param > 0) {
    /* Slave Enclave: use shared UTM from Main Enclave for data transfer */
    shared_buffer = EYRIE_SHARED_UTM_START;
    shared_buffer_size = shared_utm_size_param;
    // printf("[yx_eyrie_boot] DEBUG: Slave Enclave mode - using shared UTM\n");
    // printf("[yx_eyrie_boot]   shared_buffer      = 0x%lx (EYRIE_SHARED_UTM_START)\n", shared_buffer);
    // printf("[yx_eyrie_boot]   shared_buffer_size = %lu KB\n", shared_buffer_size/1024);
    // printf("[yx_eyrie_boot]   ocall_buffer       = 0x%lx (EYRIE_UNTRUSTED_START)\n", ocall_buffer);
    // printf("[yx_eyrie_boot]   ocall_buffer_size  = %lu KB\n", ocall_buffer_size/1024);
    debug("[Runtime] Shared UTM mode: paddr=0x%lx size=%lu KB", shared_utm_paddr, shared_utm_size_param/1024);
  } else {
    /* Main Enclave or regular Enclave: use own UTM */
    shared_buffer = EYRIE_UNTRUSTED_START;
    shared_buffer_size = utm_size;
    // printf("[yx_eyrie_boot] DEBUG: Main/Regular Enclave mode - using own UTM\n");
    // printf("[yx_eyrie_boot]   shared_buffer      = 0x%lx (EYRIE_UNTRUSTED_START)\n", shared_buffer);
    // printf("[yx_eyrie_boot]   shared_buffer_size = %lu KB\n", shared_buffer_size/1024);
  }

  YXS_trusted_memory = KEYSTONE_YXSTM_ENCLAVE_VA_BASE;
  YXS_trusted_memory_size = YXSTM_size;
  sec_mmio_base = sec_size_param > 0 ? EYRIE_SEC_MMIO_START : 0;
  sec_mmio_size = sec_size_param;
  runtime_va_start = (uintptr_t) &rt_base;
  kernel_offset = runtime_va_start - runtime_paddr;

  /*
   * YXSTM is no longer a boot-time always-open mapping. Group enclaves must
   * acquire it explicitly at the API that needs shared state. Reading kg here
   * touches the YXSTM slice before the eapp starts and before the scheduler has
   * reached a cooperative point, so keep boot independent from YXSTM.
   */
  
  /* test other enclave access epm */
  test_other_enclave_access_epm = dram_base;
  // // morenzhixuyao8B
  // test_other_enclave_access_epm_size;

  // if (YXSTM_vaddr == YXSTM_size || YXSTM_size == 0) {
  //   printf("[runtime] YXSTM testing 3 %s, YXSTM_vaddr:%lu, YXSTM_size:%lu, YXS_trusted_memory:%lu\n", __func__, YXSTM_vaddr, YXSTM_size, YXS_trusted_memory);
  // } else {
  //   printf("[runtime] YXSTM testing 3 %s, YXSTM_vaddr:%lu, YXSTM_size:%lu, YXS_trusted_memory:%lu\n", __func__, YXSTM_vaddr, YXSTM_size, YXS_trusted_memory);
  //   printf("YXSTM : 0x%lx-0x%lx (%u KB)", YXSTM_vaddr, YXSTM_vaddr+YXSTM_size, YXSTM_size/1024);
  //   printf("[runtime] YXSTM testing 3.1 %s, shared_buffer:%lu\n", __func__, shared_buffer);
  //   printf("UTM : 0x%lx-0x%lx (%u KB)", utm_vaddr, utm_vaddr+utm_size, utm_size/1024);
  // }

  debug("ROOT PAGE TABLE: 0x%lx", root_page_table);
  debug("UTM : 0x%lx-0x%lx (%u KB)", utm_vaddr, utm_vaddr+utm_size, utm_size/1024);
  debug("YXSTM : 0x%lx-0x%lx (%u KB)", YXSTM_vaddr, YXSTM_vaddr+YXSTM_size, YXSTM_size/1024);
  debug("DRAM: 0x%lx-0x%lx (%u KB)", dram_base, dram_base + dram_size, dram_size/1024);
  debug("USER: 0x%lx-0x%lx (%u KB)", user_paddr, free_paddr, (free_paddr-user_paddr)/1024);

  /* set trap vector */
  csr_write(stvec, &encl_trap_handler);
  freemem_va_start = __va(free_paddr);
  freemem_size = dram_base + dram_size - free_paddr;

  debug("FREE: 0x%lx-0x%lx (%u KB), va 0x%lx", free_paddr, dram_base + dram_size, freemem_size/1024, freemem_va_start);

  /* initialize free memory */
  init_freemem();

  /* load eapp elf */
  assert(!verify_and_load_elf_file(__va(user_paddr), free_paddr-user_paddr, true));

  /* free leaking memory */
  // TODO: clean up after loader -- entire file no longer needed
  // TODO: load elf file doesn't map some pages; those can be re-used. runtime and eapp.

  //TODO: This should be set by walking the userspace vm and finding
  //highest used addr. Instead we start partway through the anon space
  set_program_break(EYRIE_ANON_REGION_START + (1024 * 1024 * 1024));

  #ifdef USE_PAGING
  init_paging(user_paddr, free_paddr);
  #endif /* USE_PAGING */

  /* initialize user stack */
  init_user_stack_and_env((ELF(Ehdr) *) __va(user_paddr));

  /* prepare edge & system calls */
  init_edge_internals();

  validate_group_page_table_or_exit();

  /* Keep SR_SUM enabled and turn on the FPU before entering user mode */
  csr_write(sstatus, csr_read(sstatus) | 0x6000 | SR_SUM);

  /*
   * Arm scheduler-owned preemption only after page-table construction,
   * policy validation, edge setup and architectural initialization finish.
   * The first host-service boundary must not suspend a partial Eyrie boot.
   */
  init_timer();

  debug("eyrie boot finished. drop to the user land ...");
  /* booting all finished, droping to the user land */
  return;
}
