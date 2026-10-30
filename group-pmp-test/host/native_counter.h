#ifndef KEYSTONE_NATIVE_COUNTER_H
#define KEYSTONE_NATIVE_COUNTER_H

#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define KEYSTONE_NATIVE_COUNTER_MARKER "keystone-native-counter-perf-v1"

static int native_counter_fd = -1;
static int native_counter_initialized;
static const char* native_counter_name = "uninitialized";

static void native_counter_initialize(void)
{
  struct perf_event_attr attributes;

  if (native_counter_initialized) {
    return;
  }
  native_counter_initialized = 1;
  memset(&attributes, 0, sizeof(attributes));
  attributes.type = PERF_TYPE_HARDWARE;
  attributes.size = sizeof(attributes);
  attributes.config = PERF_COUNT_HW_CPU_CYCLES;
  attributes.exclude_kernel = 1;
  attributes.exclude_hv = 1;
  native_counter_fd = (int)syscall(SYS_perf_event_open, &attributes,
                                    0, -1, -1, 0);
  if (native_counter_fd >= 0) {
    native_counter_name = "perf-cpu-cycles";
    return;
  }
  native_counter_name = "monotonic-raw-ns";
}

static uint64_t native_counter_read(void)
{
  uint64_t value;

  native_counter_initialize();
  if (native_counter_fd >= 0) {
    ssize_t length = read(native_counter_fd, &value, sizeof(value));
    if (length != (ssize_t)sizeof(value)) {
      fprintf(stderr, "[CRYPTO-NATIVE] perf counter read failed: %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
    return value;
  }
  {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0) {
      fprintf(stderr, "[CRYPTO-NATIVE] monotonic counter read failed: %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
           (uint64_t)now.tv_nsec;
  }
}

static const char* native_counter_source(void)
{
  native_counter_initialize();
  return native_counter_name;
}

static void native_counter_destroy(void)
{
  if (native_counter_fd >= 0) {
    close(native_counter_fd);
    native_counter_fd = -1;
  }
}

#endif
