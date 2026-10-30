#ifndef KEYSTONE_ENCLAVE_VFS_H
#define KEYSTONE_ENCLAVE_VFS_H

#include "sqlite3.h"

#include "group-pmp-sqlite-vfs-shared.h"

#define KEYSTONE_ENCLAVE_VFS_NAME "keystone_enclave_async_aes128"
#define KEYSTONE_SQLITE_VFS_PERF_WINDOW_MARKER \
  "keystone-sqlite-vfs-perf-window-v1"

int keystone_enclave_vfs_configure(
    const struct group_pmp_sqlite_vfs_config* config);
int keystone_enclave_vfs_reset(void);
int keystone_enclave_vfs_reset_stats(void);
int keystone_enclave_vfs_sync(void);
sqlite3_int64 keystone_enclave_vfs_bytes(void);
void keystone_enclave_vfs_get_stats(
    struct group_pmp_sqlite_vfs_stats* stats);
uint64_t keystone_enclave_vfs_last_error(void);

#endif
