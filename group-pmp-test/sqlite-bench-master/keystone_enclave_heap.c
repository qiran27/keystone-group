#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "keystone_enclave_heap.h"

#define KEYSTONE_SQLITE_HEAP_BYTES (UINT64_C(12) * UINT64_C(1000000))
#define KEYSTONE_HEAP_ALIGNMENT ((size_t)16)
#define KEYSTONE_HEAP_FREE UINT64_C(0x4652454548454150)
#define KEYSTONE_HEAP_USED UINT64_C(0x5553454448454150)

static const char sqlite_epm_heap_artifact_marker[] __attribute__((used)) =
    "keystone-sqlite-epm-heap-v2";

struct keystone_heap_block {
  size_t size;
  struct keystone_heap_block* next;
  uint64_t state;
  uint64_t reserved;
};

static unsigned char heap_storage[KEYSTONE_SQLITE_HEAP_BYTES]
    __attribute__((aligned(4096)));
static struct keystone_heap_block* heap_head;

static int align_size(size_t size, size_t* aligned) {
  if (!aligned || size > SIZE_MAX - (KEYSTONE_HEAP_ALIGNMENT - 1))
    return -1;
  *aligned = (size + KEYSTONE_HEAP_ALIGNMENT - 1) &
      ~(KEYSTONE_HEAP_ALIGNMENT - 1);
  return 0;
}

static void heap_init(void) {
  if (heap_head)
    return;
  heap_head = (struct keystone_heap_block*)(void*)heap_storage;
  heap_head->size = sizeof(heap_storage) - sizeof(*heap_head);
  heap_head->next = NULL;
  heap_head->state = KEYSTONE_HEAP_FREE;
  heap_head->reserved = 0;
}

static void split_block(struct keystone_heap_block* block, size_t size) {
  struct keystone_heap_block* remainder;
  if (block->size < size + sizeof(*block) + KEYSTONE_HEAP_ALIGNMENT)
    return;
  remainder = (struct keystone_heap_block*)(void*)(
      (unsigned char*)(block + 1) + size);
  remainder->size = block->size - size - sizeof(*block);
  remainder->next = block->next;
  remainder->state = KEYSTONE_HEAP_FREE;
  remainder->reserved = 0;
  block->size = size;
  block->next = remainder;
}

static struct keystone_heap_block* find_block(const void* pointer) {
  struct keystone_heap_block* block;
  if (!pointer || (const unsigned char*)pointer < heap_storage ||
      (const unsigned char*)pointer >= heap_storage + sizeof(heap_storage))
    return NULL;
  for (block = heap_head; block; block = block->next)
    if ((const void*)(block + 1) == pointer)
      return block;
  return NULL;
}

static void coalesce_free_blocks(void) {
  struct keystone_heap_block* block = heap_head;
  while (block && block->next) {
    struct keystone_heap_block* next = block->next;
    unsigned char* expected = (unsigned char*)(block + 1) + block->size;
    if (block->state == KEYSTONE_HEAP_FREE &&
        next->state == KEYSTONE_HEAP_FREE &&
        expected == (unsigned char*)next) {
      block->size += sizeof(*next) + next->size;
      block->next = next->next;
      continue;
    }
    block = next;
  }
}

void* malloc(size_t size) {
  struct keystone_heap_block* block;
  size_t aligned;
  if (!size || align_size(size, &aligned) != 0)
    return NULL;
  heap_init();
  for (block = heap_head; block; block = block->next) {
    if (block->state != KEYSTONE_HEAP_FREE || block->size < aligned)
      continue;
    split_block(block, aligned);
    block->state = KEYSTONE_HEAP_USED;
    return block + 1;
  }
  return NULL;
}

void free(void* pointer) {
  struct keystone_heap_block* block = find_block(pointer);
  if (!block || block->state != KEYSTONE_HEAP_USED)
    return;
  block->state = KEYSTONE_HEAP_FREE;
  coalesce_free_blocks();
}

void* calloc(size_t count, size_t size) {
  void* pointer;
  size_t bytes;
  if (count && size > SIZE_MAX / count)
    return NULL;
  bytes = count * size;
  pointer = malloc(bytes);
  if (pointer)
    memset(pointer, 0, bytes);
  return pointer;
}

void* realloc(void* pointer, size_t size) {
  struct keystone_heap_block* block;
  size_t aligned;
  void* replacement;
  size_t copy_size;
  if (!pointer)
    return malloc(size);
  if (!size) {
    free(pointer);
    return NULL;
  }
  if (align_size(size, &aligned) != 0)
    return NULL;
  block = find_block(pointer);
  if (!block || block->state != KEYSTONE_HEAP_USED)
    return NULL;
  if (block->size >= aligned) {
    split_block(block, aligned);
    return pointer;
  }
  if (block->next && block->next->state == KEYSTONE_HEAP_FREE &&
      (unsigned char*)(block + 1) + block->size ==
          (unsigned char*)block->next &&
      block->size + sizeof(*block->next) + block->next->size >= aligned) {
    block->size += sizeof(*block->next) + block->next->size;
    block->next = block->next->next;
    split_block(block, aligned);
    return pointer;
  }
  replacement = malloc(size);
  if (!replacement)
    return NULL;
  copy_size = block->size < size ? block->size : size;
  memcpy(replacement, pointer, copy_size);
  free(pointer);
  return replacement;
}

void keystone_enclave_heap_reset(void) {
  volatile unsigned char* byte = heap_storage;
  size_t index;
  for (index = 0; index < sizeof(heap_storage); ++index)
    byte[index] = 0;
  heap_head = NULL;
}
