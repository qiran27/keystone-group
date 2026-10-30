#ifndef MOTIVATION_PROTOCOL_H
#define MOTIVATION_PROTOCOL_H
#include <stdint.h>
#include <stddef.h>
#define MOT_MARKER "keystone-worker-overlap-v7"
#define MOT_MAGIC UINT64_C(0x4d4f544956415432)
#define MOT_OCALL 8
#define MOT_BLOCK 65536u
#define MOT_MAX_BLOCKS 122071u
#define MOT_META_OFFSET 4096u
#define MOT_DATA_OFFSET 8192u
#define MOT_STRIDE 69632u
#define MOT_UTM_BYTES (MOT_DATA_OFFSET + 2u * MOT_STRIDE)
enum mot_op { MOT_CONFIG, MOT_PUT, MOT_PREPARED, MOT_WARM, MOT_START,
              MOT_SUBMIT, MOT_WAIT_ANY, MOT_RELEASE, MOT_DONE,
              MOT_RELEASE_SUBMIT=13 }; /* 9..12 are protected Master control operations. */
enum mot_mode { MOT_PREPARE, MOT_SYNC, MOT_ASYNC };
enum mot_cipher { MOT_CIPHER_GCM, MOT_CIPHER_ECB };
struct mot_header {
  uint64_t magic, object, block, length;
  uint8_t nonce[12], tag[16], reserved[4];
};
struct mot_completion {
  uint64_t ready, block, generation, bytes, io_done_ticks;
  int64_t error;
};
struct mot_config { uint64_t magic, input_bytes, object, mode, timebase_hz, first_block, limit_block, cipher, block_bytes, diagnostic; };
struct mot_call {
  uint64_t op, slot, block, generation, bytes;
  uint64_t submit_return, compute_begin, compute_end, digest;
  uint64_t elapsed_ticks, processed, blocks, waits, early_returns, out_of_order;
  uint64_t capture_end, decrypt_end;
  uint64_t next_block, next_generation, next_bytes;
};
struct mot_reply { int64_t status; struct mot_config config; };
static inline uint64_t mot_blocks(uint64_t bytes) { return (bytes + MOT_BLOCK - 1) / MOT_BLOCK; }
/* Zero retains the default for in-tree API callers; scripts always send an explicit size. */
static inline uint64_t mot_block_bytes(const struct mot_config* c) { return c->block_bytes ? c->block_bytes : MOT_BLOCK; }
static inline int mot_valid_geometry(const struct mot_config* c) {
  uint64_t n=mot_block_bytes(c);
  return (n==4096 || n==16384 || n==65536) && c->diagnostic<=1;
}
static inline uint64_t mot_count(const struct mot_config* c) {
  return (c->input_bytes + mot_block_bytes(c) - 1) / mot_block_bytes(c);
}
static inline uint64_t mot_initial_reads(const struct mot_config* c) {
  uint64_t count=c->limit_block-c->first_block;
  uint64_t slots=c->mode==MOT_SYNC?1:2;
  return count<slots?count:slots;
}
static inline int mot_partition(struct mot_config* c, unsigned worker, unsigned workers) {
  if (!mot_valid_geometry(c) || !workers || worker>=workers || mot_count(c)<workers) return -1;
  c->first_block=mot_count(c)*worker/workers;
  c->limit_block=mot_count(c)*(worker+1)/workers;
  return 0;
}
static inline uint64_t mot_range_bytes(const struct mot_config* c) {
  uint64_t end=c->limit_block*mot_block_bytes(c);
  if (end>c->input_bytes) end=c->input_bytes;
  return end-c->first_block*mot_block_bytes(c);
}
static inline size_t mot_length(uint64_t bytes, uint64_t block) {
  uint64_t left = bytes - block * MOT_BLOCK;
  return (size_t)(left < MOT_BLOCK ? left : MOT_BLOCK);
}
static inline size_t mot_block_length(const struct mot_config* c,uint64_t block) {
  uint64_t left=c->input_bytes-block*mot_block_bytes(c);
  return (size_t)(left<mot_block_bytes(c)?left:mot_block_bytes(c));
}
static inline size_t mot_payload_bytes(const struct mot_config* c,uint64_t block) {
  size_t n=mot_block_length(c,block);
  return c->cipher==MOT_CIPHER_ECB ? (n+15u)&~(size_t)15u : n;
}
static inline size_t mot_wire_bytes(const struct mot_config* c,uint64_t block) {
  return sizeof(struct mot_header)+mot_payload_bytes(c,block);
}
static inline uint64_t mot_file_bytes(const struct mot_config* c) {
  uint64_t last=mot_count(c)-1;
  return last*(mot_block_bytes(c)+sizeof(struct mot_header))+mot_wire_bytes(c,last);
}
static inline const char* mot_cipher_name(uint64_t cipher) {
  return cipher==MOT_CIPHER_ECB?"aes-128-ecb":"aes-128-gcm";
}
static inline size_t mot_data(unsigned slot) { return MOT_DATA_OFFSET + slot * MOT_STRIDE; }
static inline size_t mot_meta(unsigned slot) { return MOT_META_OFFSET + slot * sizeof(struct mot_completion); }
#endif
