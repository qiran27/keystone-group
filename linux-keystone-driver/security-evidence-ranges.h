#ifndef KEYSTONE_SECURITY_EVIDENCE_RANGES_H
#define KEYSTONE_SECURITY_EVIDENCE_RANGES_H
#include <linux/types.h>
/* ABI shared with the optional test observer; no protected-memory contents. */
struct ke_range { __u64 start, size, group, epoch, type, permissions; };
int keystone_security_protected_ranges(struct ke_range *out, unsigned int capacity);
#endif
