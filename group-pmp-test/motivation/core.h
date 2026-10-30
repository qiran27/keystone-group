#ifndef MOTIVATION_CORE_H
#define MOTIVATION_CORE_H
#include "protocol.h"
struct mot_api {
  int (*exchange)(const struct mot_call*, struct mot_reply*);
  int (*capture)(void*, size_t, size_t);
  int (*publish)(size_t, const void*, size_t);
  uint64_t (*ticks)(void);
};
struct mot_task_api {
  int (*acquire)(struct mot_config*);
  int (*complete)(const struct mot_config*, const struct mot_call*);
};
/* All cryptographic buffers and expected results reside in enclave private RAM. */
#ifdef __cplusplus
extern "C" {
#endif
int mot_run(const struct mot_api* api);
int mot_run_task(const struct mot_api* api, const struct mot_task_api* task);
#ifdef __cplusplus
}
#endif
#endif
