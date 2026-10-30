#ifndef GROUP_PMP_MEDIABENCH_JM_MEMORY_VFS_H
#define GROUP_PMP_MEDIABENCH_JM_MEMORY_VFS_H

#include <stddef.h>
#include <stdint.h>

/* Register JM's named inputs and outputs in enclave-private memory before
 * invoking its encoder or decoder. No unregistered name is opened. */
void group_pmp_jm_memory_reset(void);
int group_pmp_jm_memory_input(const char* name, const uint8_t* data,
                              size_t bytes);
int group_pmp_jm_memory_output(const char* name, uint8_t* data,
                               size_t capacity);
int group_pmp_jm_memory_size(const char* name, size_t* bytes);

#endif
