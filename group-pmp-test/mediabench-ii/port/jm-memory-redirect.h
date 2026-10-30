#ifndef GROUP_PMP_MEDIABENCH_JM_MEMORY_REDIRECT_H
#define GROUP_PMP_MEDIABENCH_JM_MEMORY_REDIRECT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

FILE* group_pmp_jm_fopen(const char* name, const char* mode);
int group_pmp_jm_open(const char* name, int flags, ...);
ssize_t group_pmp_jm_read(int fd, void* output, size_t bytes);
ssize_t group_pmp_jm_write(int fd, const void* input, size_t bytes);
off_t group_pmp_jm_lseek(int fd, off_t offset, int whence);
int group_pmp_jm_close(int fd);

/* Include this only while compiling the pinned JM sources. Standard headers
 * above must be parsed before the redirects are defined. */
#define fopen group_pmp_jm_fopen
#define open group_pmp_jm_open
#define read group_pmp_jm_read
#define write group_pmp_jm_write
#define lseek group_pmp_jm_lseek
#define close group_pmp_jm_close

#endif
