#include "core.h"
#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"
#include "../eapp/aes_core.h"
#include <string.h>

_Static_assert(sizeof(struct mot_header) == 64, "wire header changed");
static const volatile char marker[] __attribute__((used)) = MOT_MARKER;
static struct { struct mot_header header; uint8_t data[MOT_BLOCK]; } snapshot;
static uint8_t plain[MOT_BLOCK];
static uint64_t expected[MOT_MAX_BLOCKS];
static mbedtls_gcm_context gcm;
static void* ecb_encrypt;
static void* ecb_decrypt;
/* Public benchmark fixture key; never copied to UTM. Not production key provisioning. */
static const uint8_t key[16] = {0x71,0x24,0x8c,0x13,0xa9,0x55,0x06,0xfe,
                               0x63,0x90,0x2a,0x44,0x18,0x7d,0xb1,0x3e};
static uint64_t hash(const uint8_t* p, size_t n) {
  uint64_t h = UINT64_C(1469598103934665603);
  for (size_t i = 0; i < n; ++i) h = (h ^ p[i]) * UINT64_C(1099511628211);
  return h;
}
static void generate(uint64_t block, size_t n) {
  uint64_t x = UINT64_C(0x6d6f746976617431) ^ (block + 1);
  for (size_t i = 0; i < n; ++i) {
    x ^= x << 13; x ^= x >> 7; x ^= x << 17; plain[i] = (uint8_t)x;
  }
}
static void header(struct mot_header* h, const struct mot_config* c, uint64_t b) {
  uint32_t index = (uint32_t)b;
  memset(h, 0, sizeof(*h));
  h->magic=MOT_MAGIC; h->object=c->object; h->block=b; h->length=mot_block_length(c,b);
  memcpy(h->nonce,&c->object,8); memcpy(h->nonce+8,&index,4);
  h->reserved[0]=(uint8_t)c->cipher;
  h->reserved[1]=(uint8_t)(mot_block_bytes(c)/1024);
}
static int exchange(const struct mot_api* a, struct mot_call* c, struct mot_reply* r) {
  memset(r,0,sizeof(*r)); return a->exchange(c,r) || r->status ? -1 : 0;
}
static int process(const struct mot_api* a, const struct mot_config* cfg, unsigned slot,
                   uint64_t block, uint64_t* digest, struct mot_call* stages) {
  struct mot_header wanted;
  size_t n = mot_block_length(cfg,block);
  if (a->capture(&snapshot,mot_data(slot),mot_wire_bytes(cfg,block))) return -1;
  if (stages) stages->capture_end=a->ticks();
  header(&wanted,cfg,block);
  /* Identity and nonce are checked against trusted task state, before AEAD. */
  if (memcmp(&snapshot.header,&wanted,44) ||
      memcmp(snapshot.header.reserved,wanted.reserved,4)) return -1;
  if(cfg->cipher==MOT_CIPHER_ECB) {
    if(memcmp(snapshot.header.tag,wanted.tag,16) || !ecb_decrypt) return -1;
    aes_decrypt_blocks(ecb_decrypt,snapshot.data,plain,mot_payload_bytes(cfg,block)/16);
    for(size_t i=n;i<mot_payload_bytes(cfg,block);++i) if(plain[i]) return -1;
  } else {
    int rc = mbedtls_gcm_auth_decrypt(&gcm,n,snapshot.header.nonce,12,
        (const uint8_t*)&wanted,32,snapshot.header.tag,16,snapshot.data,plain);
    if (rc) { mbedtls_platform_zeroize(plain,sizeof(plain)); return -1; }
  }
  if (stages) stages->decrypt_end=a->ticks();
  *digest = hash(plain,n);
  if (*digest != expected[block]) return -1;
  return 0;
}
static int execute(const struct mot_api* a, const struct mot_task_api* task) {
  struct mot_call c = {0}; struct mot_reply r;
  if (marker[0]!='k' || exchange(a,&c,&r)) return 10;
  struct mot_config cfg = r.config;
  if (!cfg.input_bytes || cfg.input_bytes > UINT64_C(500000000) || !mot_valid_geometry(&cfg)) return 11;
  uint64_t count = cfg.limit_block-cfg.first_block;
  if (cfg.magic!=MOT_MAGIC || !cfg.object || cfg.first_block>=cfg.limit_block ||
      cfg.limit_block>mot_count(&cfg) || cfg.limit_block>MOT_MAX_BLOCKS ||
      (cfg.mode==MOT_PREPARE && (cfg.first_block || cfg.limit_block!=mot_count(&cfg))) ||
      cfg.mode>MOT_ASYNC || cfg.cipher>MOT_CIPHER_ECB || cfg.timebase_hz<1000) return 11;
  if(cfg.cipher==MOT_CIPHER_ECB) {
    /* The production core has one static context per direction. Release its
     * known-answer selftest before allocating the actual fixture context. */
    static const uint8_t test_key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    static const uint8_t test_plain[16]={0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    static const uint8_t expected_cipher[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    uint8_t test_cipher[16],test_out[16];
    void* enc=aes_encrypt_init(test_key,16);void* dec=aes_decrypt_init(test_key,16);
    if(!enc || !dec) {if(enc) aes_encrypt_deinit(enc);if(dec) aes_decrypt_deinit(dec);return 12;}
    aes_encrypt(enc,test_plain,test_cipher);aes_decrypt(dec,test_cipher,test_out);
    aes_encrypt_deinit(enc);aes_decrypt_deinit(dec);
    if(memcmp(test_plain,test_out,16) || memcmp(test_cipher,expected_cipher,16)) return 12;
    if(cfg.mode==MOT_PREPARE) ecb_encrypt=aes_encrypt_init(key,16);
    else ecb_decrypt=aes_decrypt_init(key,16);
    if(!ecb_encrypt && !ecb_decrypt) return 13;
  } else {
    if (mbedtls_gcm_self_test(0)) return 12;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm,MBEDTLS_CIPHER_ID_AES,key,128)) return 13;
  }
  uint64_t wanted_digest=0;
  for (uint64_t b=cfg.first_block;b<cfg.limit_block;++b) {
    size_t n=mot_block_length(&cfg,b); generate(b,n);
    expected[b]=hash(plain,n); wanted_digest ^= expected[b] + b * UINT64_C(0x9e3779b97f4a7c15);
    if (cfg.mode==MOT_PREPARE) {
      header(&snapshot.header,&cfg,b);
      if(cfg.cipher==MOT_CIPHER_ECB) {
        memset(plain+n,0,mot_payload_bytes(&cfg,b)-n);
        aes_encrypt_blocks(ecb_encrypt,plain,snapshot.data,mot_payload_bytes(&cfg,b)/16);
      } else if(mbedtls_gcm_crypt_and_tag(&gcm,MBEDTLS_GCM_ENCRYPT,n,snapshot.header.nonce,12,
          (const uint8_t*)&snapshot.header,32,plain,snapshot.data,16,snapshot.header.tag)) return 14;
      if(a->publish(mot_data(0),&snapshot,mot_wire_bytes(&cfg,b))) return 14;
      memset(&c,0,sizeof(c)); c.op=MOT_PUT; c.block=b; c.bytes=mot_wire_bytes(&cfg,b);
      if (exchange(a,&c,&r)) return 15;
    }
  }
  if (cfg.mode==MOT_PREPARE) {
    memset(&c,0,sizeof(c)); c.op=MOT_PREPARED; c.digest=wanted_digest;
    return exchange(a,&c,&r) ? 16 : 0;
  }
  /* Real file read and decrypt warmup, followed by Host cache preparation. */
  memset(&c,0,sizeof(c)); c.op=MOT_WARM;
  uint64_t warm_digest=0;
  if (exchange(a,&c,&r) || process(a,&cfg,0,cfg.first_block,&warm_digest,0)) return 17;
  memset(&c,0,sizeof(c)); c.op=MOT_START;
  if (exchange(a,&c,&r)) return 18;
  if (task && (!task->acquire || !task->complete || task->acquire(&cfg))) return 31;
  const uint64_t start=a->ticks();
  uint64_t next=cfg.first_block,done=0,processed=0,digest=0,waits=0,early=0,reordered=0;
  uint64_t generation[2]={0,0}, block[2]={0,0}, returned[2]={0,0};
  unsigned owned[2]={0,0};
  while (done<count) {
    for (unsigned s=0;s<2 && next<cfg.limit_block;++s) {
      if (owned[s] || (cfg.mode==MOT_SYNC && (s || owned[0]))) continue;
      memset(&c,0,sizeof(c)); c.op=MOT_SUBMIT; c.slot=s; c.block=next;
      c.generation=++generation[s]; c.bytes=mot_wire_bytes(&cfg,next);
      if (exchange(a,&c,&r)) return 20;
      returned[s]=a->ticks(); block[s]=next++; owned[s]=1;
    }
    int selected=-1; struct mot_completion ready={0};
    for (unsigned s=0;s<2;++s) if (owned[s]) {
      struct mot_completion item;
      if (a->capture(&item,mot_meta(s),sizeof(item))) return 21;
      if (!item.ready) continue;
      __sync_synchronize();
      if (a->capture(&item,mot_meta(s),sizeof(item)) || item.ready!=1 ||
          item.block!=block[s] || item.generation!=generation[s] || item.error ||
          item.bytes!=mot_wire_bytes(&cfg,block[s])) return 22;
      if (selected<0 || item.io_done_ticks<ready.io_done_ticks) { selected=(int)s; ready=item; }
    }
    if (selected<0) {
      if (cfg.mode==MOT_SYNC) return 30; // blocking read OCALL must already publish
      if (!owned[0] && !owned[1]) return 23;
      memset(&c,0,sizeof(c)); c.op=MOT_WAIT_ANY;
      if (exchange(a,&c,&r)) return 24;
      ++waits; continue;
    }
    unsigned s=(unsigned)selected; uint64_t begin=a->ticks(),value=0;
    struct mot_call stages={0};
    if (process(a,&cfg,s,block[s],&value,cfg.diagnostic?&stages:0)) return 25;
    uint64_t end=a->ticks();
    if (owned[1-s] && block[1-s]<block[s]) ++reordered;
    if (returned[s]<ready.io_done_ticks) ++early;
    digest ^= value + block[s]*UINT64_C(0x9e3779b97f4a7c15);
    processed+=mot_block_length(&cfg,block[s]); ++done;
    const unsigned refill=next<cfg.limit_block;
    memset(&c,0,sizeof(c)); c.op=refill?MOT_RELEASE_SUBMIT:MOT_RELEASE; c.slot=s; c.block=block[s];
    c.generation=generation[s]; c.submit_return=returned[s]; c.compute_begin=begin; c.compute_end=end;
    c.capture_end=stages.capture_end; c.decrypt_end=stages.decrypt_end;
    if (refill) {
      if (generation[s]==UINT64_MAX) return 26;
      c.next_block=next; c.next_generation=generation[s]+1; c.next_bytes=mot_wire_bytes(&cfg,next);
    }
    if (exchange(a,&c,&r)) return 26;
    if (refill) {
      returned[s]=a->ticks(); block[s]=next++; ++generation[s];
    } else owned[s]=0;
  }
  if (processed!=mot_range_bytes(&cfg) || next!=cfg.limit_block || owned[0] || owned[1] || digest!=wanted_digest ||
      (cfg.mode==MOT_SYNC && (waits || early))) return 27;
  uint64_t elapsed=a->ticks()-start;
  if (!elapsed || elapsed>UINT64_MAX/2) return 28;
  memset(&c,0,sizeof(c)); c.op=MOT_DONE; c.elapsed_ticks=elapsed; c.processed=processed;
  c.blocks=done; c.digest=digest; c.waits=waits; c.early_returns=early; c.out_of_order=reordered;
  if (task && task->complete(&cfg,&c)) return 32;
  return exchange(a,&c,&r) ? 29 : 0;
}
int mot_run(const struct mot_api* a) {
  return mot_run_task(a,0);
}
int mot_run_task(const struct mot_api* a, const struct mot_task_api* task) {
  int rc=execute(a,task);
  mbedtls_gcm_free(&gcm);
  if(ecb_encrypt) aes_encrypt_deinit(ecb_encrypt);
  if(ecb_decrypt) aes_decrypt_deinit(ecb_decrypt);
  ecb_encrypt=ecb_decrypt=0;
  mbedtls_platform_zeroize(plain,sizeof(plain));
  mbedtls_platform_zeroize(&snapshot,sizeof(snapshot));
  mbedtls_platform_zeroize(expected,sizeof(expected));
  return rc;
}
