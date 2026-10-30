#ifndef STORE_NATIVE_BOUNDARY_H
#define STORE_NATIVE_BOUNDARY_H
#include <stddef.h>
#include <stdint.h>
#include "shared/eyrie_call.h"
#include "shared/sm_call.h"
/* Replace only the RISC-V syscall assembly for native object compilation. */
#define __SYSCALL_H__
int ocall(unsigned long, void*, size_t, void*, size_t);
int copy_to_shared_utm(uintptr_t, const void*, size_t);
uintptr_t utm_query_direct(struct keystone_utm_direct_info*, size_t);
#endif
