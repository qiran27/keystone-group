#ifndef KEYSTONE_GROUP_TASK_H
#define KEYSTONE_GROUP_TASK_H

#include <stddef.h>
#include <stdint.h>

#include "shared/sm_call.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEYSTONE_GROUP_TASK_QUEUE_CAPACITY 512
#define KEYSTONE_GROUP_TASK_MAX_STAGES     16
#define KEYSTONE_GROUP_TASK_MAX_JOBS       8
#define KEYSTONE_GROUP_TASK_MAX_LANES      3
#define KEYSTONE_GROUP_TASK_MAX_WEIGHT     1024
#define KEYSTONE_GROUP_TASK_NO_LANE        ((uint64_t)-1)

#define KEYSTONE_GROUP_STAGE_FLAG_BARRIER  (1UL << 0)

#define KEYSTONE_GROUP_STAGE_PENDING        0
#define KEYSTONE_GROUP_STAGE_RUNNABLE       1
#define KEYSTONE_GROUP_STAGE_RUNNING        2
#define KEYSTONE_GROUP_STAGE_SUCCEEDED      3
#define KEYSTONE_GROUP_STAGE_FAILED         4
#define KEYSTONE_GROUP_STAGE_CANCELLED      5

#define KEYSTONE_GROUP_TASK_OK               0
#define KEYSTONE_GROUP_TASK_ERR_ARGUMENT    -1
#define KEYSTONE_GROUP_TASK_ERR_FULL        -2
#define KEYSTONE_GROUP_TASK_ERR_NOT_FOUND   -3
#define KEYSTONE_GROUP_TASK_ERR_STATE       -4
#define KEYSTONE_GROUP_TASK_ERR_STALE       -5
#define KEYSTONE_GROUP_TASK_ERR_COMMIT      -6
#define KEYSTONE_GROUP_TASK_ERR_BARRIER     -7

struct keystone_group_stage_descriptor {
  uint64_t job_id;
  uint64_t stage_id;
  uint64_t dependency_mask;
  uint64_t required_workers;
  uint64_t flags;
};

struct keystone_group_task_slot {
  struct keystone_group_task_descriptor descriptor;
  uint64_t state;
  uint64_t assigned_lane;
  uint64_t submit_sequence;
  uint64_t retry_count;
  uint64_t result_digest;
  uint64_t committed_token;
};

struct keystone_group_stage_slot {
  struct keystone_group_stage_descriptor descriptor;
  uint64_t state;
};

struct keystone_group_task_lane {
  uint64_t lane_id;
  uint64_t busy;
  uint64_t task_index;
  uint64_t prefetched_task_index;
  uint64_t resident_bank;
  uint64_t completed_tasks;
};

struct keystone_group_task_job_fairness {
  uint64_t valid;
  uint64_t job_id;
  uint64_t weight;
  uint64_t service_units;
};

struct keystone_group_task_scheduler {
  uint64_t mode;
  uint64_t active_worker_mask;
  uint64_t submit_sequence;
  uint64_t dispatch_sequence;
  uint64_t rr_job_cursor;
  uint64_t queued_count;
  uint64_t running_count;
  uint64_t staged_count;
  uint64_t completed_count;
  uint64_t cancelled_count;
  uint64_t failed_count;
  uint64_t deadline_expired_count;
  uint64_t now;
  struct keystone_group_task_slot tasks[KEYSTONE_GROUP_TASK_QUEUE_CAPACITY];
  struct keystone_group_stage_slot stages[KEYSTONE_GROUP_TASK_MAX_STAGES];
  struct keystone_group_task_lane lanes[KEYSTONE_GROUP_TASK_MAX_LANES];
  struct keystone_group_task_job_fairness jobs[KEYSTONE_GROUP_TASK_MAX_JOBS];
};

void keystone_group_task_scheduler_init(
    struct keystone_group_task_scheduler* scheduler,
    uint64_t mode, uint64_t active_worker_mask);

int keystone_group_task_add_stage(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_stage_descriptor* stage);

int keystone_group_task_submit(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_descriptor* task);

int keystone_group_task_dispatch(
    struct keystone_group_task_scheduler* scheduler,
    struct keystone_group_task_descriptor* tasks,
    uint64_t* lane_ids, size_t capacity);

int keystone_group_task_prefetch(
    struct keystone_group_task_scheduler* scheduler,
    struct keystone_group_task_descriptor* tasks,
    uint64_t* lane_ids, size_t capacity);

int keystone_group_task_activate_prefetched(
    struct keystone_group_task_scheduler* scheduler, uint64_t bank_id,
    struct keystone_group_task_descriptor* tasks,
    uint64_t* lane_ids, size_t capacity);

int keystone_group_task_complete(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_result* result);

int keystone_group_task_fail(
    struct keystone_group_task_scheduler* scheduler,
    const struct keystone_group_task_result* result);

int keystone_group_task_cancel(
    struct keystone_group_task_scheduler* scheduler,
    uint64_t job_id, uint64_t stage_id, uint64_t task_id);

int keystone_group_task_advance_time(
    struct keystone_group_task_scheduler* scheduler, uint64_t now);

int keystone_group_task_stage_state(
    const struct keystone_group_task_scheduler* scheduler,
    uint64_t job_id, uint64_t stage_id, uint64_t* state);

int keystone_group_task_idle(
    const struct keystone_group_task_scheduler* scheduler);

#ifdef __cplusplus
}
#endif

#endif
