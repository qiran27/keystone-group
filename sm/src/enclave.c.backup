//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/riscv_barrier.h>

struct enclave enclaves[ENCL_MAX];

ms_group ms_group_list[MAX_MS_GROUP]; // 从属 enclave 组列表

static volatile int YXSTM_sm_init = 0;
static volatile int YXSTM_sm_fleible = 0;
static volatile int sm_engine_id = 0;
static volatile int kg_ready = 0;

typedef struct {
  volatile int YXSTM_sm_init;
  volatile int YXSTM_sm_fleible;
  volatile int sm_engine_id;
}sm_ms;

// Enclave IDs are unsigned ints, so we do not need to check if eid is
// greater than or equal to 0
#define ENCLAVE_EXISTS(eid) (eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/
static inline void context_switch_to_enclave(struct sbi_trap_regs* regs,
                                                enclave_id eid,
                                                int load_parameters){
  /* save host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, 1);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  uintptr_t interrupts = 0;
  csr_write(mideleg, interrupts);

  if(load_parameters) {
    // passing parameters for a first run
    regs->mepc = (uintptr_t) enclaves[eid].params.dram_base - 4; // regs->mepc will be +4 before sbi_ecall_handler return
    regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
    // $a1: (PA) DRAM base,
    regs->a1 = (uintptr_t) enclaves[eid].params.dram_base;
    // $a2: DRAM size,
    regs->a2 = (uintptr_t) enclaves[eid].params.dram_size;
    // $a3: (PA) kernel location,
    regs->a3 = (uintptr_t) enclaves[eid].params.runtime_base;
    // $a4: (PA) user location,
    regs->a4 = (uintptr_t) enclaves[eid].params.user_base;
    // $a5: (PA) freemem location,
    regs->a5 = (uintptr_t) enclaves[eid].params.free_base;
    // $a6: (PA) utm base,
    regs->a6 = (uintptr_t) enclaves[eid].params.untrusted_base;
    // $a7: utm size
    regs->a7 = (uintptr_t) enclaves[eid].params.untrusted_size;
    // $t0: (PA) YXSTM base,
    regs->t0 = (uintptr_t) enclaves[eid].params.YXSTrusted_base;
    // $01: YXSTM size
    regs->t1 = (uintptr_t) enclaves[eid].params.YXSTrusted_size;

    // enclave will only have physical addresses in the first run
    csr_write(satp, 0);
  }

  switch_vector_enclave();

  // set PMP
  osm_pmp_set(PMP_NO_PERM);
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
    }
  }

  // sbi_printf("pmp testing start\n");
  // if(load_parameters) {
  //   osm_pmp_set(PMP_NO_PERM);
  //   int memid;
  //   for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
  //     if(enclaves[eid].regions[memid].type != REGION_INVALID) {
  //       pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
  //     }
  //   }
  // } else {
  //   osm_pmp_set(PMP_NO_PERM);
  //   int memid;
  //   for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
  //     if(enclaves[eid].regions[memid].type != REGION_INVALID) {
  //       pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
  //     }
  //   }
  // }
  // sbi_printf("pmp testing end\n");

  // sbi_printf("pmp testing start\n");
  // osm_pmp_set(PMP_NO_PERM);
  // int memid;
  // for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
  //   if(enclaves[eid].regions[memid].type != REGION_INVALID) {
  //     pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
  //   }
  // }
  // sbi_printf("pmp testing end\n");


  // Setup any platform specific defenses
  platform_switch_to_enclave(&(enclaves[eid]));
  cpu_enter_enclave_context(eid);
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
    enclave_id eid,
    int return_on_resume){

  // set PMP
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }
  }
  osm_pmp_set(PMP_ALL_PERM);

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  csr_write(mideleg, interrupts);

  /* restore host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, return_on_resume);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  switch_vector_host();

  uintptr_t pending = csr_read(mip);

  if (pending & MIP_MTIP) {
    csr_clear(mip, MIP_MTIP);
    csr_set(mip, MIP_STIP);
  }
  if (pending & MIP_MSIP) {
    csr_clear(mip, MIP_MSIP);
    csr_set(mip, MIP_SSIP);
  }
  if (pending & MIP_MEIP) {
    csr_clear(mip, MIP_MEIP);
    csr_set(mip, MIP_SEIP);
  }

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();

  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(void){
  enclave_id eid;
  int i=0;

  /* Assumes eids are incrementing values, which they are for now */
  for(eid=0; eid < ENCL_MAX; eid++){
    enclaves[eid].state = INVALID;

    enclaves[eid].engine_id = 0;

    // Clear out regions
    for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
      enclaves[eid].regions[i].type = REGION_INVALID;
    }
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[eid]));
  }

}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  sbi_memset((void*)utbase, 0, utsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long clean_enclave_YXST_memory(uintptr_t YXSTbase, uintptr_t YXSTsize)
{
  sbi_memset((void*)YXSTbase, 0, YXSTsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(enclave_id* _eid)
{
  enclave_id eid;

  spin_lock(&encl_lock);

  for(eid=0; eid<ENCL_MAX; eid++)
  {
    if(enclaves[eid].state == INVALID){
      break;
    }
  }
  if(eid != ENCL_MAX)
    enclaves[eid].state = ALLOCATED;

  spin_unlock(&encl_lock);

  if(eid != ENCL_MAX){
    *_eid = eid;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  else{
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
}

static unsigned long encl_free_eid(enclave_id eid)
{
  spin_lock(&encl_lock);
  enclaves[eid].state = INVALID;
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type){
  size_t i;
  for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == type){
      return i;
    }
  }
  // No such region for this enclave
  return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create_t* dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create_t));

  if (region_overlap)
    return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data from enclave, source must be inside EPM */
static unsigned long copy_enclave_data(struct enclave* enclave,
                                          void* dest, uintptr_t source, size_t size) {

  int illegal = copy_to_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static unsigned long copy_enclave_report(struct enclave* enclave,
                                            uintptr_t dest, struct report* source) {

  int illegal = copy_from_sm(dest, source, sizeof(struct report));

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create_t* args)
{
  uintptr_t epm_start, epm_end;

  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;
  
  return 1;
}

// 初始化从属 enclave 的函数
static void initialize_m_enclave(m_enclave* menclave) {
  menclave->slave_numbers = 0; // 设置从属数量为0
  for (int i = 0; i < MAX_SLAVE_ENCLAVES; i++) {
    menclave->slave_enclave[i] = NULL; // 初始化从属 enclave 指针为 NULL
  }
}

// 初始化 s_enclave 的函数
static void initialize_s_enclave(s_enclave* enclave) {
  enclave->state = 0; // 初始化状态
  enclave->s_id = 0; // 初始化从属 enclave 的 ID
  enclave->data_ptr = 0; // 初始化数据指针
  enclave->size = 0; // 初始化数据大小
  enclave->numbers = 0; // 初始化块id
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create_t create_args)
{
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;
  uintptr_t YXSTbase = create_args.YXSTM_region.paddr;
  size_t YXSTsize = create_args.YXSTM_region.size;
  uint64_t ms_YXSTM = create_args.ms_YXSTM;
  uint64_t engine_id = create_args.engine_id;
  int is_create = 0;
  byte kg[MDSIZE];

  enclave_id eid;
  unsigned long ret;
  int region, shared_region;
  int YXSTM_region;

  /* Runtime parameters */
  if(!is_create_args_valid(&create_args))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /* set params */
  struct runtime_params_t params;
  params.dram_base = base;
  params.dram_size = size;
  params.runtime_base = create_args.runtime_paddr;
  params.user_base = create_args.user_paddr;
  params.free_base = create_args.free_paddr;
  params.untrusted_base = utbase;
  params.untrusted_size = utsize;
  params.YXSTrusted_base = YXSTbase;
  params.YXSTrusted_size = YXSTsize;

  spin_lock(&encl_lock);
  if (ms_YXSTM != 0 && YXSTM_sm_fleible == 0 && sm_engine_id == 0) {
    YXSTM_sm_fleible = ms_YXSTM;
    sm_engine_id = engine_id;
    YXSTM_sm_init = 0;
  }
  spin_unlock(&encl_lock);

  if (ms_YXSTM == 0) {
    params.YXSTrusted_base = 0;
    params.YXSTrusted_size = 0;
    engine_id = 0;
  }
  params.free_requested = create_args.free_requested;


  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto error;

  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // sbi_printf("YXSTM sm testing %s\t, eid:%u, base:%lu ,size:%lu, flexible:%u\n", __func__, eid, base, size, YXSTM_sm_fleible);

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  if (ms_YXSTM) {
    spin_lock(&encl_lock);
    is_create = (YXSTM_sm_init == 0);
    // sbi_printf("is_create:%d ,YXSTM_sm_init:%d, eid:%d\n", is_create, YXSTM_sm_init, eid);
    if (is_create && sm_engine_id != 0) {
      if(pmp_region_init_atomic(YXSTbase, YXSTsize, PMP_PRI_ANY, &YXSTM_region, 0)) {
        spin_unlock(&encl_lock);
        goto free_shared_region;
      }
      YXSTM_sm_init = YXSTM_region;
    }

    if (engine_id == sm_engine_id && sm_engine_id != 0) {
      YXSTM_region = YXSTM_sm_init;
    }

    spin_unlock(&encl_lock);
    if (is_create && sm_engine_id != 0) {
      if(pmp_set_global(YXSTM_region, PMP_NO_PERM)) {
        YXSTM_sm_init = YXSTM_region = 0;
        goto free_YXSTM_region;
      }
      // 只清除一次，在pmp ipi同步之后，立马对stm memset 0
      clean_enclave_YXST_memory(YXSTbase, YXSTsize);
    }
  }

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM))
    goto free_YXSTM_region;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);

  // initialize enclave metadata
  enclaves[eid].eid = eid;
  enclaves[eid].engine_id = engine_id;

  // Initialize the master enclave structure for the newly created enclave
  initialize_m_enclave(&enclaves[eid].m);
  // Initialize the slave enclave structure for the newly created enclave
  initialize_s_enclave(&enclaves[eid].s);

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
  if (ms_YXSTM) {
    enclaves[eid].regions[2].pmp_rid = YXSTM_region;
    enclaves[eid].regions[2].type = REGION_EPM;
  }
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = params;

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if (ret)
    goto unset_region;

  /* Validate memory, prepare hash and signature for attestation */
  spin_lock(&encl_lock); // FIXME This should error for second enter.
 
  ret = validate_and_hash_enclave(&enclaves[eid]);

  // spin_unlock(&encl_lock);
  if (ms_YXSTM) {
    // if (is_create) {
    //   sbi_printf("kg_ready 1, eid:%d\n", eid);
    //   generate_kg(&enclaves[eid], kg);
    //   sbi_printf("kg_ready 1, eid:%d\n", eid);
    //   sbi_memcpy((void*)(YXSTbase + YXSTsize - sizeof(kg)), (void*)kg, sizeof(kg));
    //   sbi_printf("kg_ready 3, eid:%d\n", eid);
    //   kg_ready = 1;
    //   mb();
    // } else {
    //   sbi_printf("kg_ready 2, eid:%d\n", eid);
    //   sbi_printf("YXSTM_sm_init:%d , eid:%d\n", YXSTM_sm_init, eid);
    //   while (!kg_ready){
    //     mb();
    //   }
    // }
    // spin_lock(&encl_lock);
    if (kg_ready == 0) {
      generate_kg(&enclaves[eid], kg);
      // sbi_printf("kg_ready 1, eid:%d, kg_ready:%d\n", eid, kg_ready);
      sbi_memcpy((void*)(YXSTbase + YXSTsize - sizeof(kg)), (void*)kg, sizeof(kg));
      // sbi_printf("kg_ready 3, eid:%d\n", eid);
      kg_ready = 1;
    } else {
      // sbi_printf("kg_ready 2, eid:%d, kg_ready:%d\n", eid, kg_ready);
      // sbi_printf("YXSTM_sm_init:%d , eid:%d\n", YXSTM_sm_init, eid);
    }
    // spin_unlock(&encl_lock);
  }
  // spin_lock(&encl_lock);
  
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret)
    goto unlock;

  enclaves[eid].state = FRESH;
  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = eid;

  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
  spin_unlock(&encl_lock);
// free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_YXSTM_region:
  pmp_region_free_atomic(YXSTM_region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
unsigned long destroy_enclave(enclave_id eid)
{
  int destroyable;

  spin_lock(&encl_lock);
  destroyable = (ENCLAVE_EXISTS(eid)
                 && enclaves[eid].state <= STOPPED);
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable)
    enclaves[eid].state = DESTROYING;
  spin_unlock(&encl_lock);

  if(!destroyable)
    return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;


  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(&enclaves[eid]);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  int i;
  void* base;
  size_t size;
  region_id rid;
  // spin_lock(&encl_lock);
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == REGION_INVALID ||
       enclaves[eid].regions[i].type == REGION_UTM)
      continue;
    //1.a Clear all pages
    rid = enclaves[eid].regions[i].pmp_rid;
    base = (void*) pmp_region_get_addr(rid);
    size = (size_t) pmp_region_get_size(rid);
    sbi_memset((void*) base, 0, size);
    // sbi_printf("YXSTM testing 1 %s , free region:%d\n", __func__, rid);

    //1.b free pmp region
    // if (YXSTM_sm_init == rid) {
    //   spin_lock(&encl_lock);
    //   YXSTM_sm_fleible--;
    //   if (YXSTM_sm_fleible == 0) {
    //     YXSTM_sm_init = 0;
    //     sbi_printf("sm pmp testing free YXSTM pmp, %s\n", __func__);
    //     spin_unlock(&encl_lock);
    //     pmp_unset_global(rid);
    //     pmp_region_free_atomic(rid);
    //   } else {
    //     spin_unlock(&encl_lock);
    //   }
    //   continue;
    // }
    if (YXSTM_sm_init == rid) {
      spin_lock(&encl_lock);
      YXSTM_sm_fleible--;
      unsigned int is_last = (YXSTM_sm_fleible == 0);
      if (is_last) {
        YXSTM_sm_init = 0;
        sm_engine_id = 0;
      }

      spin_unlock(&encl_lock);

      if (is_last) {
        // sbi_printf("sm pmp testing free YXSTM pmp, %s\n", __func__);
        pmp_unset_global(rid);
        pmp_region_free_atomic(rid);
        kg_ready = 0;
      }
      continue;
    }
    pmp_unset_global(rid);
    // sbi_printf("YXSTM testing 2 %s , free region:%d\n", __func__,  rid);
    pmp_region_free_atomic(rid);
    // sbi_printf("YXSTM testing 3 %s , free region:%d\n", __func__,  rid);
  }

  // 2. free pmp region for UTM
  rid = get_enclave_region_index(eid, REGION_UTM);
  if(rid != -1)
    pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

  enclaves[eid].encl_satp = 0;
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = (struct runtime_params_t) {0};
  for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
    enclaves[eid].regions[i].type = REGION_INVALID;
  }

  // 2.5 clean group
  for (int i=0; i<MAX_MS_GROUP; ++i) {
    if(ms_group_list[i].isCreated == 1) {
      if (ms_group_list[i].m != NULL && ms_group_list[i].m == &enclaves[eid].m) {
        if (enclaves[eid].m.slave_numbers != 0) {
          enclaves[eid].m.slave_numbers = 0;
          // sbi_printf("set slave_number\n");
        }
        ms_group_list[i].isCreated = 0;
        break;
      }
    }
  }
  // spin_unlock(&encl_lock);

  // 3. release eid
  encl_free_eid(eid);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int runable;

  spin_lock(&encl_lock);
  runable = (ENCLAVE_EXISTS(eid)
            && enclaves[eid].state == FRESH);
  if(runable) {
    enclaves[eid].state = RUNNING;
    enclaves[eid].n_thread++;
  }
  spin_unlock(&encl_lock);

  if(!runable) {
    return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  }

  // Enclave is OK to run, context switch to it
  context_switch_to_enclave(regs, eid, 1);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int exitable;

  spin_lock(&encl_lock);
  exitable = enclaves[eid].state == RUNNING;
  if (exitable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!exitable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid)
{
  int stoppable;

  spin_lock(&encl_lock);
  stoppable = enclaves[eid].state == RUNNING;
  if (stoppable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!stoppable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, request == STOP_EDGE_CALL_HOST);

  switch(request) {
    case(STOP_TIMER_INTERRUPT):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_EDGE_CALL_HOST):
      return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    default:
      return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  }
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int resumable;

  spin_lock(&encl_lock);
  resumable = (ENCLAVE_EXISTS(eid)
               && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED)
               && enclaves[eid].n_thread < MAX_ENCL_THREADS);

  if(!resumable) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  } else {
    enclaves[eid].n_thread++;
    enclaves[eid].state = RUNNING;
  }
  spin_unlock(&encl_lock);

  // Enclave is OK to resume, context switch to it
  context_switch_to_enclave(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid)
{
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  attestable = (ENCLAVE_EXISTS(eid)
                && (enclaves[eid].state >= FRESH));

  if(!attestable) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
      data, size);
  report.enclave.data_len = size;

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  spin_unlock(&encl_lock); // Don't need to wait while signing, which might take some time

  sbi_memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.hash, sm_hash, MDSIZE);
  sbi_memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  spin_lock(&encl_lock);

  /* copy report to the enclave */
  ret = copy_enclave_report(&enclaves[eid],
      report_ptr,
      &report);

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                                 size_t key_ident_size, enclave_id eid)
{
  struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
  int ret;

  /* derive key */
  ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                              (const unsigned char *)key_ident, key_ident_size,
                              (const unsigned char *)enclaves[eid].hash);
  if (ret)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  /* sign derived key */
  sm_sign((void *)key_struct->signature, (void *)key_struct->key,
          SEALING_KEY_SIZE);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

// 创建从属 enclave 组的函数
unsigned long m_enclave_create_group(uintptr_t identity, uintptr_t size, enclave_id eid) {
  sbi_printf("sm testing %s 1 \n", __func__);
  spin_lock(&encl_lock);
  
  m_enclave* m = &enclaves[eid].m; // 获取指定 enclave 的 m_enclave
  char tempidentity[64+4];
  if (copy_enclave_data(&enclaves[eid], (void*)tempidentity, identity, size)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }
  // 查找未创建的组
  for (int i = 0; i < MAX_MS_GROUP; i++) {
    // sbi_printf("sm testing %s \n", __func__);
    if (ms_group_list[i].isCreated == 0) { // 查找未创建的组
      // sbi_printf("sm testing %s 2 ,size %ld\n", __func__, size);
      // // sbi_memcpy(ms_group_list[i].identity, (char*)identity, size); // 复制身份信息
      // ret = copy_enclave_data(&enclaves[eid], (void*)ms_group_list[i].identity, identity, size); // 复制身份信息
      // if (copy_enclave_data(&enclaves[eid], (void*)ms_group_list[i].identity, identity, size)) { // 复制身份信息
      //   spin_unlock(&encl_lock);
      //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
      // }
      sbi_memcpy(ms_group_list[i].identity, tempidentity, size); // 复制身份信息
      // sbi_printf("sm testing %s 3 id: %s\n", __func__, ms_group_list[i].identity);
      ms_group_list[i].m = m; // 关联 m_enclave
      // sbi_printf("sm testing %s 4 \n", __func__);
      ms_group_list[i].isCreated = 1; // 标记为已创建
      spin_unlock(&encl_lock);
      return SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功
    } else if(ms_group_list[i].isCreated == 1) {
      // 检查组是否已创建 
      // char temp[64+4];
      // if (copy_enclave_data(&enclaves[eid], (void*)temp, identity, size)) { // 复制身份信息
      //   spin_unlock(&encl_lock);
      //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
      // }
      // if (sbi_memcmp(ms_group_list[i].identity, temp, size) == 0) {
      //   spin_unlock(&encl_lock);
      //   return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
      // }

      // if (sbi_memcmp(ms_group_list[i].identity, (char*)identity, size) == 0) {
      //   spin_unlock(&encl_lock);
      //   return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
      // }
      if (sbi_memcmp(ms_group_list[i].identity, tempidentity, size) == 0) {
        spin_unlock(&encl_lock);
        return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
      }
    }
  }
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
}

// 加入从属 enclave 组的函数
unsigned long s_enclave_join_group(uintptr_t identity, uintptr_t size, enclave_id eid) {
  int ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  sbi_printf("sm testing %s\n", __func__);
  spin_lock(&encl_lock);

  char tempidentity[64+4];
  if (copy_enclave_data(&enclaves[eid], (void*)tempidentity, identity, size)) { // 复制身份信息
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err;
  }

  m_enclave* m = NULL; // 初始化 m_enclave 指针
  s_enclave* s = &enclaves[eid].s; // 获取指定 enclave 的 s_enclave
  s->s_id = eid;
  for (int i = 0; i < MAX_MS_GROUP; i++) {
    if (ms_group_list[i].isCreated == 1) { // 检查组是否已创建
      if (sbi_memcmp(ms_group_list[i].identity, tempidentity, size) == 0) { // 匹配身份
        m = ms_group_list[i].m; // 获取 m_enclave
        if (m->slave_numbers < MAX_SLAVE_ENCLAVES) { // 确保不超过最大从属数量
          m->slave_enclave[m->slave_numbers++] = s; // 将 s_enclave 添加到从属数组
          ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功
        } else {
          ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
          goto err;
        }
        break;
      }
    }
  }

err:
  spin_unlock(&encl_lock);
  return ret;
}

// 查找从属 enclave 组的函数
unsigned long s_enclave_find_group(uintptr_t identity, uintptr_t size) {
  for (int i = 0; i < MAX_MS_GROUP; i++) {
    if (ms_group_list[i].isCreated == 1 && sbi_memcmp(ms_group_list[i].identity, (char*)identity, size) == 0) {
      return i; // 返回找到的组索引
    }
  }
  return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
}

// 检查从属 enclave 数据的函数
static int check_m_get_data(m_enclave* m, uint64_t numbers, uint64_t state, uint64_t size, uint64_t s_id) {
  sbi_printf("sm testing %s  1\n", __func__);
  sbi_printf("sm testing %s  s_number=%ld, number=%ld\n", __func__, m->slave_enclave[s_id]->numbers, numbers);
  sbi_printf("sm testing %s  s_state=%ld, state=%ld\n", __func__, m->slave_enclave[s_id]->state, state);
  sbi_printf("sm testing %s  s_size=%ld, size=%ld\n", __func__, m->slave_enclave[s_id]->size, size);
  if (m->slave_enclave[s_id]->numbers == numbers && 
      m->slave_enclave[s_id]->size <= size) {
    return SBI_ERR_SM_ENCLAVE_SUCCESS; // 数据有效
  }
  return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 数据无效
}

static unsigned long copy_sm_to_enclave(struct enclave* enclave,
  uintptr_t dest, void* source, size_t size) {

  int illegal = copy_from_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long copy_slave_enclave_data(struct enclave* enclave,
                                          uintptr_t dest, uintptr_t source, size_t size) {

  sbi_printf("sm testing %s, in 1\n", __func__);
  int illegal = copy_s_to_m(dest, source, size);
  sbi_printf("sm testing %s, in 2\n", __func__);
  if(illegal)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

// 获取从属 enclave 数据的函数
unsigned long main_enclave_get_slave_enclave_data_yx(uintptr_t temp_ptr, uintptr_t dest_ptr, enclave_id eid) {
  int ret;

  unsigned char temp[17] = {0};
  unsigned long *temp_nothing = (unsigned long *)temp;
  unsigned long *temp_size = (unsigned long *)(temp+8);
  unsigned char *temp_state = temp+16;

  // unsigned char yxtest = 67;
  spin_lock(&encl_lock);

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  1\n", __func__, eid, yxtest);

  // if (copy_enclave_data(&enclaves[eid], (void*)&yxtest, dest, 1)) { // 复制身份信息
  //   spin_unlock(&encl_lock);
  //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  // }

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  2\n", __func__, eid, yxtest);

  // yxtest = 65;

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  3\n", __func__, eid, yxtest);

  // if (copy_sm_to_enclave(&enclaves[eid], dest, (void*)&yxtest, 1)) { // 复制身份信息
  //   spin_unlock(&encl_lock);
  //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  // }

  // yxtest = 66;

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  4\n", __func__, eid, yxtest);

  // if (copy_enclave_data(&enclaves[eid], (void*)&yxtest, dest, 1)) { // 复制身份信息
  //   spin_unlock(&encl_lock);
  //   return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  // }

  // sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  5\n", __func__, eid, yxtest);

  if (copy_enclave_data(&enclaves[eid], (void*)temp, temp_ptr, 17)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  m_enclave* m = &enclaves[eid].m;
  uint64_t s_id = (*temp_nothing) % (m->slave_numbers + 1); // 选择从属 enclave
  sbi_printf("sm testing %s  check_m_get_data 1, sid=%ld, numbers=%ld, m->slave_numbers=%ld, size=%ld\n", __func__, s_id, *temp_nothing, m->slave_numbers, *temp_size);
  if (m->slave_enclave[s_id - 1]->state == 0) {
    // spin_unlock(&encl_lock);
    sbi_printf("sm testing %s  slave_state=%lu, whiling...\n", __func__, m->slave_enclave[s_id - 1]->state);
    *temp_state = 0;
    if (copy_sm_to_enclave(&enclaves[eid], temp_ptr, (void*)temp, 17)) {
      ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回等待
      goto err;
    }
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回等待
    goto err;
    sbi_printf("sm testing %s, waiting spin_lock\n", __func__);
    // spin_lock(&encl_lock);
    sbi_printf("sm testing %s  slave_state=%lu\n", __func__, m->slave_enclave[s_id - 1]->state);
  }
  ret = check_m_get_data(m, *temp_nothing, m->slave_enclave[s_id - 1]->state, *temp_size, s_id - 1); // 检查数据

  // sbi_printf("sm testing %s, copy_slave_enclave_data 2, ret=%d\n", __func__, ret);
  // if (ret) {
  //   ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
  //   goto err;
  // }
  
  sbi_printf("sm testing %s, copy_slave_enclave_data 1\n", __func__);
  *temp_nothing = m->slave_enclave[s_id - 1]->numbers;
  *temp_size = m->slave_enclave[s_id - 1]->size;
  *temp_state = 1;
  ret = copy_sm_to_enclave(&enclaves[eid], temp_ptr, (void*)temp, 17); // 复制
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }
  sbi_printf("sm testing %s, copy_slave_enclave_data 2\n", __func__);

  ret = copy_slave_enclave_data(&enclaves[eid], dest_ptr, m->slave_enclave[s_id - 1]->data_ptr, m->slave_enclave[s_id - 1]->size); // 复制数据
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }

  sbi_printf("sm testing %s, copy_slave_enclave_data done\n", __func__);
  
  m->slave_enclave[s_id - 1]->state = 0; // 重置状态
  
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功

err:  
  spin_unlock(&encl_lock);
  return ret;
}

// 设置从属 enclave 数据指针的函数
unsigned long slave_enclave_set_dataptr_yx(uintptr_t temp_ptr, uintptr_t data_ptr, enclave_id eid) {
  int ret;

  unsigned char temp[17] = {0};
  unsigned long *temp_nothing = (unsigned long *)temp;
  unsigned long *temp_size = (unsigned long *)(temp+8);
  unsigned char *temp_state = temp+16;

  spin_lock(&encl_lock);

  if (copy_enclave_data(&enclaves[eid], (void*)temp, temp_ptr, 17)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  sbi_printf("sm testing %s\n", __func__);
  s_enclave* s = &enclaves[eid].s; // 获取指定 enclave 的 s_enclave
  if (s->state == 0) { // 检查状态
    s->data_ptr = data_ptr; // 设置数据指针
    s->size = *temp_size; // 设置数据大小
    s->numbers = *temp_nothing; // 设置数量
    s->state = 1; // 更新状态
    *temp_state = 0;
  } else {
    *temp_state = 1;
  }

  if (copy_sm_to_enclave(&enclaves[eid], temp_ptr, (void*)temp, 17) ) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回等待
    goto err;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功

  sbi_printf("sm testing %s, slave_eid=%ud, state=%lu, numbers=%lu, size=%lu, *temp_state=%02x \n", __func__, eid, s->state, *temp_nothing, *temp_size, *temp_state);

err:
  spin_unlock(&encl_lock);
  return ret;
}

// 获取从属 enclave 数据的函数
unsigned long main_enclave_get_slave_enclave_data(uintptr_t dest, uintptr_t size, uintptr_t numbers, enclave_id eid) {
  int ret;

  // sbi_printf("\t\t yx sm copy s to m testing %s main_eid=%ud 1\n", __func__, eid);
  // while(1){

  // }
  unsigned char tz = 11;
  unsigned char tz1 = 1;
  unsigned char yxtest = 67;
  spin_lock(&encl_lock);

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  1\n", __func__, eid, yxtest);

  if (copy_enclave_data(&enclaves[eid], (void*)&yxtest, dest, 1)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  2\n", __func__, eid, yxtest);

  yxtest = 65;

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  3\n", __func__, eid, yxtest);

  if (copy_sm_to_enclave(&enclaves[eid], dest, (void*)&yxtest, 1)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  yxtest = 66;

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  4\n", __func__, eid, yxtest);

  if (copy_enclave_data(&enclaves[eid], (void*)&yxtest, dest, 1)) { // 复制身份信息
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
  }

  sbi_printf("sm testing %s main_eid=%ud yxtest=%02x  5\n", __func__, eid, yxtest);

  m_enclave* m = &enclaves[eid].m;
  uint64_t s_id = numbers % (m->slave_numbers + 1); // 选择从属 enclave
  sbi_printf("sm testing %s  check_m_get_data 1, sid=%ld, numbers=%ld, m->slave_numbers=%ld, size=%ld\n", __func__, s_id, numbers, m->slave_numbers, size);
  if (m->slave_enclave[s_id - 1]->state == 0) {
    // spin_unlock(&encl_lock);
    sbi_printf("sm testing %s  slave_state=%lu, whiling...\n", __func__, m->slave_enclave[s_id - 1]->state);
    ret = copy_sm_to_enclave(&enclaves[eid], dest, (void*)&tz1, 1); // 复制
    if (ret) {
      ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回等待
      goto err;
    }
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回等待
    goto err;
    sbi_printf("sm testing %s, waiting spin_lock\n", __func__);
    // spin_lock(&encl_lock);
    sbi_printf("sm testing %s  slave_state=%lu\n", __func__, m->slave_enclave[s_id - 1]->state);
  }
  ret = check_m_get_data(m, numbers, m->slave_enclave[s_id - 1]->state, size, s_id - 1); // 检查数据

  // sbi_printf("sm testing %s, copy_slave_enclave_data 2, ret=%d\n", __func__, ret);
  // if (ret) {
  //   ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
  //   goto err;
  // }
  
  sbi_printf("sm testing %s, copy_slave_enclave_data 1\n", __func__);
  ret = copy_sm_to_enclave(&enclaves[eid], dest+1, (void*)&m->slave_enclave[s_id - 1]->numbers, 8); // 复制number
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }

  sbi_printf("sm testing %s, copy_slave_enclave_data 2\n", __func__);
  ret = copy_sm_to_enclave(&enclaves[eid], dest+9, (void*)&m->slave_enclave[s_id - 1]->size, 8); // 复制size
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }

  sbi_printf("sm testing %s, copy_slave_enclave_data 3\n", __func__);
  ret = copy_slave_enclave_data(&enclaves[eid], dest+17, m->slave_enclave[s_id - 1]->data_ptr, size); // 复制数据
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }

  sbi_printf("sm testing %s, copy_slave_enclave_data done\n", __func__);
  
  m->slave_enclave[s_id - 1]->state = 0; // 重置状态
  ret = copy_sm_to_enclave(&enclaves[eid], dest, (void*)&tz, 1); // 复制

  ret = copy_sm_to_enclave(&enclaves[m->slave_enclave[s_id - 1]->s_id], m->slave_enclave[s_id - 1]->data_ptr-17, (void*)&tz1, 1);
  sbi_printf("sm testing %s, set copy_slave_enclave_data ready\n", __func__);
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回错误
    goto err;
  }
  
  ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功

err:  
  spin_unlock(&encl_lock);
  return ret;
}

// 设置从属 enclave 数据指针的函数
unsigned long slave_enclave_set_dataptr(uintptr_t src, uintptr_t size, uintptr_t numbers, enclave_id eid) {
  int ret;
  spin_lock(&encl_lock);

  sbi_printf("sm testing %s\n", __func__);
  s_enclave* s = &enclaves[eid].s; // 获取指定 enclave 的 s_enclave
  if (s->state == 0) { // 检查状态
    s->data_ptr = src; // 设置数据指针
    s->size = size; // 设置数据大小
    s->numbers = numbers; // 设置数量
    s->state = 1; // 更新状态
    ret = SBI_ERR_SM_ENCLAVE_SUCCESS; // 返回成功
  } else {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR; // 返回未知错误
    goto err;
  }

  sbi_printf("sm testing %s, slave_eid=%ud, state=%lu, numbers=%lu, size=%lu, ret=%d \n", __func__, eid, s->state, numbers, size, ret);

err:
  spin_unlock(&encl_lock);
  return ret;
}


unsigned long slave_enclave_set_numberblock_set_pmp(enclave_id eid){
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      if (enclaves[eid].regions[memid].pmp_rid == YXSTM_sm_init && YXSTM_sm_init != 0) {
        pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
      }
    }
  }
  return 0;
}

unsigned long main_enclave_get_numberblock_set_pmp(enclave_id eid) {
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      if (enclaves[eid].regions[memid].pmp_rid == YXSTM_sm_init && YXSTM_sm_init != 0) {
        pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
      }
    }
  }
  return 0;
}

unsigned long other_enclave_access_stm_test_set_pmp(enclave_id eid){
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      if (enclaves[eid].regions[memid].pmp_rid == YXSTM_sm_init && YXSTM_sm_init != 0) {
        pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
      }
    }
  }
  return 0;
}

unsigned long s_enclave_attested(enclave_id eid, uintptr_t report, uintptr_t nonce, uintptr_t kg) {

  struct s_attested_report s_report;
  unsigned char s_kg[64];
  int ret;

  ret = copy_enclave_data(&enclaves[eid], s_kg, kg, 64);
  if (ret) {
    return ret;
  }

  s_report.seq = eid;
  s_report.nonce = nonce;
  sbi_memcpy(s_report.s_hash, enclaves[eid].hash, 64);

  generate_s_attested_hash(&s_report, s_kg);

  sm_sign(s_report.signature, &s_report, sizeof(struct s_attested_report) - 64);
  
  ret = copy_from_sm(report, &s_report, sizeof(struct s_attested_report));

  if (ret) {
    return ret;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  return ret;
}

unsigned long m_enclave_attest_s_enclave(enclave_id eid, uintptr_t report, uintptr_t kg, uintptr_t flag) {
  // sbi_printf("func:%s, slave kg and hmac attest start\n", __func__);
  struct s_attested_report s_report;
  unsigned char m_kg[64];
  unsigned char s_hmac[64];
  int ret;
  uint64_t _flag = 0;

  ret = copy_enclave_data(&enclaves[eid], &s_report, report, sizeof(struct s_attested_report));
  if (ret) {
    return ret;
  }

  if (sm_verify(s_report.signature, &s_report, sizeof(struct s_attested_report) - 64)) {
    _flag = 0;
    ret = copy_from_sm(flag, &_flag, sizeof(_flag));
    if (ret) {
      return ret;
    }
  }

  ret = copy_enclave_data(&enclaves[eid], m_kg, kg, 64);
  if (ret) {
    return ret;
  }

  // 提前备份s的hmac
  sbi_memcpy(s_hmac, s_report.hmac, 64);

  // 使用m_kg重新计算hmac
  generate_s_attested_hash(&s_report, m_kg);

  ret = sbi_memcmp(s_report.hmac, s_hmac, 64);
  if (ret) {
    return ret;
  }

  _flag = 1;
  ret = copy_from_sm(flag, &_flag, sizeof(_flag));
  if (ret) {
    return ret;
  }

  // sbi_printf("func:%s, slave kg and hmac attest match\n", __func__);

  return 0;

}
