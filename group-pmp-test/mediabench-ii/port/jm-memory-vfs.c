#define _GNU_SOURCE 1
#include "jm-memory-vfs.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define JM_MEMORY_FILES 24
#define JM_MEMORY_HANDLES 32
#define JM_MEMORY_NAME 128

struct memory_file {
  char name[JM_MEMORY_NAME];
  uint8_t* data;
  size_t length;
  size_t capacity;
  int writable;
};

struct memory_handle {
  struct memory_file* file;
  size_t offset;
  int readable;
  int writable;
  int append;
  int in_use;
};

static struct memory_file files[JM_MEMORY_FILES];
static struct memory_handle handles[JM_MEMORY_HANDLES];
static size_t file_count;

void group_pmp_jm_memory_reset(void) {
  memset(files, 0, sizeof(files));
  memset(handles, 0, sizeof(handles));
  file_count = 0;
}

static struct memory_file* find_file(const char* name) {
  size_t i;
  if (!name) return NULL;
  for (i = 0; i < file_count; ++i)
    if (strcmp(files[i].name, name) == 0) return &files[i];
  return NULL;
}

static int add_file(const char* name, uint8_t* data, size_t bytes,
                    size_t capacity, int writable) {
  struct memory_file* file;
  size_t length;
  if (!name || !*name || !data || !capacity || bytes > capacity ||
      file_count == JM_MEMORY_FILES || find_file(name)) return -1;
  length = strlen(name);
  if (length >= JM_MEMORY_NAME) return -1;
  file = &files[file_count++];
  memcpy(file->name, name, length + 1);
  file->data = data;
  file->length = bytes;
  file->capacity = capacity;
  file->writable = writable;
  return 0;
}

int group_pmp_jm_memory_input(const char* name, const uint8_t* data,
                              size_t bytes) {
  return add_file(name, (uint8_t*)data, bytes, bytes, 0);
}

int group_pmp_jm_memory_output(const char* name, uint8_t* data,
                               size_t capacity) {
  return add_file(name, data, 0, capacity, 1);
}

int group_pmp_jm_memory_size(const char* name, size_t* bytes) {
  struct memory_file* file = find_file(name);
  if (!file || !bytes) return -1;
  *bytes = file->length;
  return 0;
}

static struct memory_handle* allocate_handle(struct memory_file* file,
                                              int readable, int writable,
                                              int append, int truncate) {
  size_t i;
  if (!file || (writable && !file->writable)) {
    errno = EACCES;
    return NULL;
  }
  for (i = 0; i < JM_MEMORY_HANDLES; ++i) {
    struct memory_handle* handle = &handles[i];
    if (handle->in_use) continue;
    memset(handle, 0, sizeof(*handle));
    handle->file = file;
    handle->readable = readable;
    handle->writable = writable;
    handle->append = append;
    handle->offset = append ? file->length : 0;
    handle->in_use = 1;
    if (truncate) file->length = 0;
    return handle;
  }
  errno = EMFILE;
  return NULL;
}

static ssize_t memory_read(struct memory_handle* handle, void* output,
                           size_t bytes) {
  size_t available;
  if (!handle || !handle->in_use || !handle->readable || !output) {
    errno = EBADF;
    return -1;
  }
  available = handle->offset < handle->file->length ?
      handle->file->length - handle->offset : 0;
  if (bytes > available) bytes = available;
  memcpy(output, handle->file->data + handle->offset, bytes);
  handle->offset += bytes;
  return (ssize_t)bytes;
}

static ssize_t memory_write(struct memory_handle* handle, const void* input,
                            size_t bytes) {
  size_t available;
  if (!handle || !handle->in_use || !handle->writable || !input) {
    errno = EBADF;
    return -1;
  }
  if (handle->append) handle->offset = handle->file->length;
  available = handle->file->capacity - handle->offset;
  if (bytes > available) {
    errno = ENOSPC;
    return -1;
  }
  if (handle->offset > handle->file->length)
    memset(handle->file->data + handle->file->length, 0,
           handle->offset - handle->file->length);
  memcpy(handle->file->data + handle->offset, input, bytes);
  handle->offset += bytes;
  if (handle->offset > handle->file->length)
    handle->file->length = handle->offset;
  return (ssize_t)bytes;
}

static int seek_handle(struct memory_handle* handle, int64_t offset,
                       int whence, size_t* result) {
  uint64_t base;
  uint64_t position;
  if (!handle || !handle->in_use) return -1;
  switch (whence) {
    case SEEK_SET: base = 0; break;
    case SEEK_CUR: base = handle->offset; break;
    case SEEK_END: base = handle->file->length; break;
    default: return -1;
  }
  if (offset < 0) {
    if ((uint64_t)(-(offset + 1)) + 1 > base) return -1;
    position = base - ((uint64_t)(-(offset + 1)) + 1);
  } else {
    if ((uint64_t)offset > UINT64_MAX - base) return -1;
    position = base + (uint64_t)offset;
  }
  if (position > handle->file->capacity) return -1;
  handle->offset = (size_t)position;
  *result = handle->offset;
  return 0;
}

static ssize_t cookie_read(void* cookie, char* output, size_t bytes) {
  return memory_read(cookie, output, bytes);
}
static ssize_t cookie_write(void* cookie, const char* input, size_t bytes) {
  return memory_write(cookie, input, bytes);
}
static int cookie_seek(void* cookie, off64_t* offset, int whence) {
  size_t result;
  if (seek_handle(cookie, *offset, whence, &result) != 0 ||
      result > INT64_MAX) return -1;
  *offset = (off64_t)result;
  return 0;
}
static int cookie_close(void* cookie) {
  ((struct memory_handle*)cookie)->in_use = 0;
  return 0;
}

FILE* group_pmp_jm_fopen(const char* name, const char* mode) {
  struct memory_handle* handle;
  cookie_io_functions_t functions = {cookie_read, cookie_write,
                                     cookie_seek, cookie_close};
  int write_mode;
  if (!mode || !*mode) return NULL;
  write_mode = mode[0] == 'w' || mode[0] == 'a';
  if (mode[0] != 'r' && !write_mode) return NULL;
  handle = allocate_handle(find_file(name), mode[0] == 'r' ||
                            strchr(mode, '+') != NULL, write_mode ||
                            strchr(mode, '+') != NULL, mode[0] == 'a',
                            mode[0] == 'w');
  if (!handle) return NULL;
  {
    FILE* stream = fopencookie(handle, mode, functions);
    if (!stream) handle->in_use = 0;
    return stream;
  }
}

int group_pmp_jm_open(const char* name, int flags, ...) {
  struct memory_handle* handle = allocate_handle(
      find_file(name), (flags & O_ACCMODE) != O_WRONLY,
      (flags & O_ACCMODE) != O_RDONLY, (flags & O_APPEND) != 0,
      (flags & O_TRUNC) != 0);
  if (!handle) return -1;
  return (int)(handle - handles) + 1000;
}

static struct memory_handle* fd_handle(int fd) {
  int index = fd - 1000;
  return index >= 0 && index < JM_MEMORY_HANDLES && handles[index].in_use ?
      &handles[index] : NULL;
}

ssize_t group_pmp_jm_read(int fd, void* output, size_t bytes) {
  return memory_read(fd_handle(fd), output, bytes);
}
ssize_t group_pmp_jm_write(int fd, const void* input, size_t bytes) {
  return memory_write(fd_handle(fd), input, bytes);
}
off_t group_pmp_jm_lseek(int fd, off_t offset, int whence) {
  size_t result;
  if (seek_handle(fd_handle(fd), offset, whence, &result) != 0 ||
      result > INT64_MAX) {
    errno = EINVAL;
    return -1;
  }
  return (off_t)result;
}
int group_pmp_jm_close(int fd) {
  struct memory_handle* handle = fd_handle(fd);
  if (!handle) {
    errno = EBADF;
    return -1;
  }
  handle->in_use = 0;
  return 0;
}
