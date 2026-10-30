#ifndef KEYSTONE_EVIDENCE_UAPI_H
#define KEYSTONE_EVIDENCE_UAPI_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define KE_PAGE_BYTES 4096
#define KE_RANGE_MAX 64
struct ke_range { __u64 start, size, group, epoch, type, permissions; };
struct ke_ranges { __u64 count; struct ke_range ranges[KE_RANGE_MAX]; };
struct ke_page {
  __s32 fd, pid;
  __u64 index, address, pfn, timestamp_ns, inode, offset;
  __u32 length, kind;
  __s32 status;
  __u32 reserved;
  __u8 data[KE_PAGE_BYTES];
};
/* No arbitrary kernel/physical address read command is provided. */
#define KE_FILE_PAGE _IOWR('E', 1, struct ke_page)
#define KE_RING_PAGE _IOWR('E', 2, struct ke_page)
#define KE_CONTROL _IOWR('E', 3, struct ke_page)
#define KE_PROTECTED _IOR('E', 4, struct ke_ranges)
#define KE_BIO_NEXT _IOWR('E', 5, struct ke_page)
#define KE_REGISTER_FILE _IOW('E', 6, struct ke_page)
#define KE_RESET _IO('E', 7)
#define KE_STATS _IOR('E', 8, struct ke_page)
#endif
