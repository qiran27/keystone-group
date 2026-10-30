// SPDX-License-Identifier: GPL-2.0
/* Test observer, NOT a trusted production component. Linux 5.15 interface. */
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/bio.h>
#include <linux/tracepoint.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include "evidence-uapi.h"
#define KE_BIO_CAP 256
static bool controls;
module_param(controls, bool, 0600);
static struct page *control_page;
static struct file *files[KE_RANGE_MAX];
static struct ke_page *queue;
static unsigned int head, tail, file_count;
static u64 lost, observed, bounce_events;
static DEFINE_SPINLOCK(queue_lock);
static DEFINE_MUTEX(command_lock);
static struct tracepoint *bio_queue;
static struct tracepoint *bio_bounce;
/* Supplied by the Keystone driver; metadata only, no EPM/TSR reads. */
extern int keystone_security_protected_ranges(struct ke_range *, unsigned int);
static int protected_ranges(struct ke_ranges *r)
{
  int (*provider)(struct ke_range *, unsigned int);
  int n;
  provider = symbol_get(keystone_security_protected_ranges);
  if (!provider) return -ENODEV;
  n = provider(r->ranges, KE_RANGE_MAX);
  symbol_put(keystone_security_protected_ranges);
  if (n < 0) return n;
  r->count = n;
  return 0;
}
static int export_page(struct page *page, struct ke_page *out, bool lock)
{
  void *mapped;
  if (lock && !trylock_page(page)) return -EBUSY;
  out->pfn = page_to_pfn(page);
  out->timestamp_ns = ktime_get_ns();
  mapped = kmap_local_page(page);
  memcpy(out->data, mapped, PAGE_SIZE);
  kunmap_local(mapped);
  if (lock) unlock_page(page);
  out->length = PAGE_SIZE;
  return 0;
}
static void observe_bio(void *ignore, struct bio *bio)
{
  struct bio_vec bvec;
  struct bvec_iter iter;
  unsigned long flags;
  unsigned int i;
  u64 event_time = ktime_get_ns();
  (void)ignore;
  bio_for_each_segment(bvec, bio, iter) {
    struct address_space *mapping = page_mapping(bvec.bv_page);
    bool match = false;
    spin_lock_irqsave(&queue_lock, flags);
    for (i = 0; i < file_count; ++i)
      if (mapping == files[i]->f_mapping) { match = true; break; }
    if (match) {
      unsigned int next = (head + 1) % KE_BIO_CAP;
      ++observed;
      if (next == tail) ++lost;
      else {
        struct ke_page *out = &queue[head];
        /* bio owns the page during this callback; no released-page dereference.
         * This is a sampled pre-submit image, not an atomic device snapshot. */
        memset(out, 0, sizeof(*out));
        out->kind = 3;
        out->inode = mapping->host->i_ino;
        out->index = compound_head(bvec.bv_page)->index +
          page_to_pfn(bvec.bv_page) - page_to_pfn(compound_head(bvec.bv_page));
        out->offset = bvec.bv_offset;
        export_page(bvec.bv_page, out, false);
        out->timestamp_ns = event_time;
        head = next;
      }
    }
    spin_unlock_irqrestore(&queue_lock, flags);
  }
}
static void find_tracepoint(struct tracepoint *tp, void *unused)
{
  (void)unused;
  if (!strcmp(tp->name, "block_bio_queue")) bio_queue = tp;
  if (!strcmp(tp->name, "block_bio_bounce")) bio_bounce = tp;
}
static void observe_bounce(void *ignore, struct bio *bio)
{
  unsigned long flags;
  (void)ignore; (void)bio;
  /* Bounce pages may lose their file association. Do not pretend that the
   * file-page filter covers them: record any event while a test file is live. */
  spin_lock_irqsave(&queue_lock, flags);
  if(file_count) ++bounce_events;
  spin_unlock_irqrestore(&queue_lock, flags);
}
static void reset_files(void)
{
  struct file *old[KE_RANGE_MAX];
  unsigned int n, i;
  unsigned long flags;
  spin_lock_irqsave(&queue_lock, flags);
  n = file_count;
  memcpy(old, files, sizeof(old));
  file_count = head = tail = 0;
  lost = observed = bounce_events = 0;
  spin_unlock_irqrestore(&queue_lock, flags);
  for (i = 0; i < n; ++i) fput(old[i]);
  if (control_page) {
    void *p = kmap_local_page(control_page);
    memzero_explicit(p, PAGE_SIZE);
    kunmap_local(p);
  }
}
static int capture_ring(struct ke_page *out)
{
  struct task_struct *task;
  struct pid *pid;
  struct mm_struct *mm;
  struct vm_area_struct *vma;
  const char *special;
  struct page *page = NULL;
  int rc = -EACCES, locked = 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
  unsigned long pfn;
#endif
  if (out->address > ULONG_MAX - PAGE_SIZE) return -EINVAL;
  pid = find_get_pid(out->pid);
  task = pid ? get_pid_task(pid, PIDTYPE_PID) : NULL;
  if (pid) put_pid(pid);
  if (!task) return -ESRCH;
  /* Test device is root-only and remote VMA capture additionally requires
   * CAP_SYS_PTRACE; do not depend on the non-exported ptrace_may_access helper. */
  if (!capable(CAP_SYS_PTRACE)) goto put_task;
  mm = get_task_mm(task);
  if (!mm) goto put_task;
  mmap_read_lock(mm);
  vma = find_vma(mm, out->address);
  if (!vma || out->address < vma->vm_start || out->address + PAGE_SIZE > vma->vm_end) goto unlock;
  special = vma->vm_ops && vma->vm_ops->name ? vma->vm_ops->name(vma) : NULL;
  if ((!vma->vm_file || !strstr(vma->vm_file->f_path.dentry->d_name.name, "io_uring")) &&
      (!special || (strcmp(special,"[vvar]") && strcmp(special,"[vdso]")))) goto unlock;
  /* Only the live io_uring VMA is eligible. mmap lock retains its lifetime.
   * Never follow an arbitrary device/PMP-protected mapping. */
  if (vma->vm_flags & (VM_PFNMAP|VM_IO)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    rc = follow_pfn(vma, out->address, &pfn);
    if (!rc && pfn_valid(pfn)) {
      page = pfn_to_page(pfn);
      if (!get_page_unless_zero(compound_head(page))) page = NULL;
    }
#else
    rc = -EOPNOTSUPP;
#endif
  } else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    rc = get_user_pages_remote(mm, out->address, 1, 0, &page, NULL, &locked);
#else
    rc = get_user_pages_remote(mm, out->address, 1, 0, &page, &locked);
#endif
    if (rc != 1) page = NULL;
  }
  if (page) { rc = export_page(page, out, false); put_page(page); }
  else if (rc >= 0) rc = -EFAULT;
unlock:
  if (locked) mmap_read_unlock(mm);
  mmput(mm);
put_task:
  put_task_struct(task);
  return rc;
}
static long evidence_ioctl(struct file *unused, unsigned int cmd, unsigned long arg)
{
  struct ke_page *out;
  int rc = 0;
  (void)unused;
  if (!capable(CAP_SYS_ADMIN)) return -EPERM;
  if (cmd == KE_PROTECTED) {
    struct ke_ranges *ranges = kzalloc(sizeof(*ranges), GFP_KERNEL);
    if (!ranges) return -ENOMEM;
    rc = protected_ranges(ranges);
    if (!rc && copy_to_user((void __user *)arg, ranges, sizeof(*ranges))) rc = -EFAULT;
    kfree(ranges);
    return rc;
  }
  mutex_lock(&command_lock);
  if (cmd == KE_RESET) { reset_files(); goto unlock; }
  out = kzalloc(sizeof(*out), GFP_KERNEL);
  if (!out) { rc = -ENOMEM; goto unlock; }
  if (copy_from_user(out, (void __user *)arg, sizeof(*out))) { rc = -EFAULT; goto free_out; }
  out->length = 0;
  if (cmd == KE_FILE_PAGE || cmd == KE_REGISTER_FILE) {
    struct file *f = fget(out->fd);
    if (!f) rc = -EBADF;
    else if (!S_ISREG(file_inode(f)->i_mode)) { rc = -EINVAL; fput(f); }
    else if (cmd == KE_REGISTER_FILE) {
      unsigned long flags;
      unsigned int i;
      bool added = false;
      spin_lock_irqsave(&queue_lock, flags);
      for (i = 0; i < file_count; ++i) if (files[i]->f_mapping == f->f_mapping) break;
      if (i == file_count && file_count < KE_RANGE_MAX) { files[file_count++] = f; added = true; }
      else if (i == file_count) rc = -ENOSPC;
      spin_unlock_irqrestore(&queue_lock, flags);
      if (!added) fput(f);
    } else {
      struct page *page = find_get_page(f->f_mapping, out->index);
      out->inode = file_inode(f)->i_ino;
      out->kind = 1;
      if (!page) rc = -ENOENT; /* not allocated in this sampled page cache */
      else { out->pfn = page_to_pfn(page); rc = export_page(page, out, true); put_page(page); }
      fput(f);
    }
  } else if (cmd == KE_RING_PAGE) { out->kind = 2; rc = capture_ring(out); }
  else if (cmd == KE_CONTROL) {
    if (!controls) rc = -EPERM;
    else {
      if (out->reserved == 1) {
        void *p = kmap_local_page(control_page);
        memset(p, 0, PAGE_SIZE); memcpy(p + 128, out->data, 64); kunmap_local(p);
      }
      out->kind = 4; rc = export_page(control_page, out, true);
    }
  } else if (cmd == KE_STATS) {
    unsigned long flags;
    spin_lock_irqsave(&queue_lock, flags);
    out->index = observed; out->pfn = lost; out->offset = bounce_events;
    out->reserved = (bio_queue != NULL) | ((bio_bounce != NULL) << 1);
    spin_unlock_irqrestore(&queue_lock, flags);
  } else if (cmd == KE_BIO_NEXT) {
    unsigned long flags;
    spin_lock_irqsave(&queue_lock, flags);
    if (tail == head) rc = -EAGAIN;
    else { memcpy(out, &queue[tail], sizeof(*out)); tail = (tail + 1) % KE_BIO_CAP; }
    spin_unlock_irqrestore(&queue_lock, flags);
  } else rc = -ENOTTY;
  out->status = rc;
  /* Errors also return an object/status record; ioctl errors never become zeros. */
  if (copy_to_user((void __user *)arg, out, sizeof(*out))) rc = -EFAULT;
free_out:
  kfree(out);
unlock:
  mutex_unlock(&command_lock);
  return rc;
}
static const struct file_operations evidence_ops = {
  .owner = THIS_MODULE, .unlocked_ioctl = evidence_ioctl,
};
static struct miscdevice evidence_device = {
  .minor = MISC_DYNAMIC_MINOR, .name = "keystone-evidence", .fops = &evidence_ops, .mode = 0600,
};
static int __init evidence_init(void)
{
  int rc;
  BUILD_BUG_ON(PAGE_SIZE != KE_PAGE_BYTES);
  queue = vzalloc(sizeof(*queue) * KE_BIO_CAP);
  control_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
  if (!queue || !control_page) { rc = -ENOMEM; goto fail; }
  for_each_kernel_tracepoint(find_tracepoint, NULL);
  if (bio_queue && tracepoint_probe_register(bio_queue, observe_bio, NULL)) bio_queue = NULL;
  if (bio_bounce && tracepoint_probe_register(bio_bounce, observe_bounce, NULL)) bio_bounce = NULL;
  rc = misc_register(&evidence_device);
  if (!rc) return 0;
  if (bio_queue) { tracepoint_probe_unregister(bio_queue, observe_bio, NULL); tracepoint_synchronize_unregister(); }
  if (bio_bounce) { tracepoint_probe_unregister(bio_bounce, observe_bounce, NULL); tracepoint_synchronize_unregister(); }
fail:
  if (control_page) __free_page(control_page);
  vfree(queue);
  return rc;
}
static void __exit evidence_exit(void)
{
  misc_deregister(&evidence_device);
  if (bio_queue) { tracepoint_probe_unregister(bio_queue, observe_bio, NULL); tracepoint_synchronize_unregister(); }
  if (bio_bounce) { tracepoint_probe_unregister(bio_bounce, observe_bounce, NULL); tracepoint_synchronize_unregister(); }
  reset_files();
  __free_page(control_page);
  vfree(queue);
}
module_init(evidence_init);
module_exit(evidence_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded Keystone test evidence: file pages, io_uring VMAs, matching BIO pages");
MODULE_VERSION("1");
