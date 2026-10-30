//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include <crypto.h>
#include "page.h"
#include <sbi/sbi_console.h>

/* This will hash the loader and the runtime + eapp elf files. */
static int validate_and_hash_epm(hash_ctx* ctx, struct enclave* encl)
{
  uintptr_t loader = encl->params.dram_base; // also base
  uintptr_t runtime = encl->params.runtime_base;
  uintptr_t eapp = encl->params.user_base;
  uintptr_t free = encl->params.free_base;
  hash_ctx runtime_ctx;

  // ensure pointers don't point to middle of correct files
  uintptr_t sizes[3] = {runtime - loader, eapp - runtime, free - eapp};
  hash_extend(ctx, (void*) sizes, sizeof(sizes));
  hash_init(&runtime_ctx);
  hash_extend(&runtime_ctx, (void*) &sizes[1], sizeof(sizes[1]));

  // using pointers to ensure that they themselves are correct
  // TODO(Evgeny): can extend by entire file instead of page at a time?
  for (uintptr_t page = loader; page < runtime; page += RISCV_PGSIZE) {
    hash_extend_page(ctx, (void*) page);
  }
  for (uintptr_t page = runtime; page < eapp; page += RISCV_PGSIZE) {
    hash_extend_page(ctx, (void*) page);
    hash_extend_page(&runtime_ctx, (void*) page);
  }
  for (uintptr_t page = eapp; page < free; page += RISCV_PGSIZE) {
    hash_extend_page(ctx, (void*) page);
  }
  hash_finalize(encl->runtime_hash, &runtime_ctx);
  return 0;
}

unsigned long validate_and_hash_enclave(struct enclave* enclave){
  hash_ctx ctx;
  hash_init(&ctx);

  // TODO: ensure untrusted and free sizes

  // hash the epm contents
  int valid = validate_and_hash_epm(&ctx, enclave);

  if(valid == -1){
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE;
  }

  hash_finalize(enclave->hash, &ctx);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long generate_kg(struct enclave* enclave, void* kg) {
  unsigned long kgRandom = sbi_sm_random();
  hash_ctx ctx;
  hash_init(&ctx);

  // seq
  hash_extend(&ctx, (void*)&enclave->eid, sizeof(enclave->eid));
  // engine id
  hash_extend(&ctx, (void*)&enclave->engine_id, sizeof(enclave->engine_id));
  // random
  hash_extend(&ctx, (void*)&kgRandom, sizeof(kgRandom));
  // hash 
  hash_extend(&ctx, (void*)enclave->hash, sizeof(enclave->hash));

  hash_finalize(kg, &ctx);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long generate_s_attested_hash(struct s_attested_report* s_report, void* kg) {
  unsigned char temp_hash[64];
  unsigned char k_ipad[64];
  unsigned char k_opad[64];
  unsigned char *s_kg = (unsigned char*)kg;

  for (int i = 0; i < 64; ++i) {
    k_ipad[i] = s_kg[i] ^ 0x36;
    k_opad[i] = s_kg[i] ^ 0x5c;
  }

  hash_ctx temp_ctx;
  hash_init(&temp_ctx);

  // hmac ipad
  hash_extend(&temp_ctx, (void*)k_ipad, 64);
  // seq
  hash_extend(&temp_ctx, (void*)&s_report->seq, sizeof(s_report->seq));
  // nonce
  hash_extend(&temp_ctx, (void*)&s_report->nonce, sizeof(s_report->nonce));
  // s_hash
  hash_extend(&temp_ctx, (void*)s_report->s_hash, 64);
  hash_finalize((void*)temp_hash, &temp_ctx);

  hash_ctx hmac_ctx;
  hash_init(&hmac_ctx);
  // hmac opad
  hash_extend(&hmac_ctx, (void*)k_opad, 64);
  // temp_hash
  hash_extend(&hmac_ctx, (void*)temp_hash, 64);
 
  // hmac
  hash_finalize((void*)s_report->hmac, &hmac_ctx);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}
